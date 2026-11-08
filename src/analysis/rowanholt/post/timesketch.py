"""A processed case into Timesketch (elrond.py --Timesketch): one sketch per case, named after it,
and one timeline per host holding every timed record of the host's tables, the Plaso timeline
among them, with the hostname, artefact and ATT&CK technique fields Elastic's documents carry.

Timesketch is where analysts annotate, so an export never deletes: a host whose timeline is
already in the case's sketch is left as it is and said so; delete that timeline in Timesketch to
send it again. Records with no time can't be on a timeline and are counted, not sent.

Through Timesketch's own web API (as its import client does: the login form's CSRF token, then
multipart uploads of JSON Lines, in 100 MiB chunks). Settings from the environment (.env):
TIMESKETCH_URL, TIMESKETCH_USERNAME, TIMESKETCH_PASSWORD, TIMESKETCH_CA, TIMESKETCH_VERIFY.
"""

import http.cookiejar
import json
import logging
import math
import os
import re
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional, Tuple

from rowanholt.core.records import ENVELOPE
from rowanholt.post.elastic.ingest import host_tables, table_records, to_document
from rowanholt.post.siem import siem_hosts

logger = logging.getLogger(__name__)

CHUNK = 100 * 1024 * 1024  # the import client's: under Timesketch's 200 MB form limit
MESSAGE_FIELDS = 6
MESSAGE_LENGTH = 500
# Timesketch's own event fields: a record's field of the same name keeps its value as record_<name>
RESERVED = ("datetime", "timestamp", "timestamp_desc", "message", "tag", "label")


class TimesketchError(RuntimeError):
    """Timesketch refused the export, or isn't configured."""


@dataclass(frozen=True)
class TimesketchTarget:
    """Where and how to reach Timesketch."""

    url: str
    username: str
    password: str
    ca: str = ""
    verify: bool = True

    @classmethod
    def from_env(cls, env: Optional[Dict[str, str]] = None) -> "TimesketchTarget":
        """The target .env describes; TimesketchError without TIMESKETCH_URL and a user."""
        env = os.environ if env is None else env
        url = env.get("TIMESKETCH_URL", "").rstrip("/")
        if not url or not env.get("TIMESKETCH_USERNAME"):
            raise TimesketchError("TIMESKETCH_URL and TIMESKETCH_USERNAME aren't set (.env)")
        return cls(url=url, username=env["TIMESKETCH_USERNAME"], password=env.get("TIMESKETCH_PASSWORD", ""),
                   ca=env.get("TIMESKETCH_CA", ""),
                   verify=env.get("TIMESKETCH_VERIFY", "true").strip().lower() not in ("false", "0", "no"))


def _scalar(value: Any) -> Any:
    """Every value as a string (lists and objects as JSON): one timeline holds every artefact, and
    a field that's a number in one and text in another gets events refused, as it did in Elastic."""
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str, ensure_ascii=False)
    return str(value)


def _message(doc: Dict[str, Any], artefact: str) -> str:
    """The line Timesketch lists: Plaso's own message, else the artefact and its first fields."""
    if isinstance(doc.get("message"), str) and doc["message"]:
        return doc["message"][:MESSAGE_LENGTH]
    skip = set(ENVELOPE) | {"hostname", "artefact", "@timestamp"} | {k for k in doc if k.startswith("mitre_")}
    parts = [f"{k}={_scalar(v)}" for k, v in doc.items() if k not in skip and v not in (None, "", [], {})]
    return f"{artefact}: {' | '.join(parts[:MESSAGE_FIELDS])}"[:MESSAGE_LENGTH]


def to_event(record: Dict[str, Any], host: str, artefact: str) -> Optional[Dict[str, Any]]:
    """A record as a Timesketch event, or None when it has no time."""
    doc = to_document(record, host, artefact)
    stamp = doc.get("@timestamp")
    if not stamp:
        return None
    event: Dict[str, Any] = {
        "datetime": stamp if re.search(r"(Z|[+-]\d\d:?\d\d)$", stamp) else f"{stamp}Z",
        "timestamp_desc": artefact,
        "message": _message(doc, artefact),
    }
    for key, value in doc.items():
        if key == "@timestamp" or key.startswith("_"):  # Timesketch's own, as in its import client
            continue
        event[f"record_{key}" if key in RESERVED else key] = _scalar(value)
    return event


def host_events(host_dir: str, host: str) -> Iterator[Optional[Dict[str, Any]]]:
    """Each record of the host's tables as an event (None for one with no time)."""
    for path, artefact in host_tables(host_dir):
        try:
            for record in table_records(path):
                yield to_event(record, host, artefact)
        except (OSError, ValueError) as error:
            logger.warning("Timesketch: couldn't read %s: %s", path, error)


def write_timeline(host_dir: str, host: str, out) -> Tuple[int, int]:
    """The host's events as JSON Lines into ``out``; (events written, records with no time)."""
    written = untimed = 0
    for event in host_events(host_dir, host):
        if event is None:
            untimed += 1
            continue
        out.write(json.dumps(event, ensure_ascii=False).encode("utf-8") + b"\n")
        written += 1
    return written, untimed


def _multipart(fields: Dict[str, str], filename: str, content: bytes) -> Tuple[bytes, str]:
    boundary = uuid.uuid4().hex
    parts: List[bytes] = []
    for name, value in fields.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
    parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                  "Content-Type: application/octet-stream\r\n\r\n").encode())
    parts.append(content)
    parts.append(f"\r\n--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


class TimesketchClient:
    """A signed-in session with Timesketch's web API."""

    def __init__(self, target: TimesketchTarget, opener: Optional[urllib.request.OpenerDirector] = None) -> None:
        self.target = target
        self.api = f"{target.url}/api/v1"
        if opener is None:
            handlers: List[Any] = [urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())]
            if target.url.startswith("https"):
                context = ssl.create_default_context(cafile=target.ca or None)
                if not target.verify:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                handlers.append(urllib.request.HTTPSHandler(context=context))
            opener = urllib.request.build_opener(*handlers)
        self.opener = opener
        self.csrf = ""

    def _open(self, method: str, url: str, body: Optional[bytes] = None,
              content_type: str = "") -> Tuple[int, bytes, str]:
        request = urllib.request.Request(url, data=body, method=method)
        if content_type:
            request.add_header("Content-Type", content_type)
        if self.csrf:
            request.add_header("X-CSRFToken", self.csrf)
            request.add_header("Referer", self.target.url)
        try:
            with self.opener.open(request, timeout=300) as response:
                return response.status, response.read(), response.geturl()
        except urllib.error.HTTPError as error:
            return error.code, error.read(), url

    def login(self) -> None:
        """Sign in with the login form, as Timesketch's API client does for a user and password."""
        url = f"{self.target.url}/login/?local_auth=1"
        status, page, _ = self._open("GET", url)
        text = page.decode("utf-8", errors="replace")
        match = (re.search(r'id="csrf_token"[^>]*value="([^"]+)"', text)
                 or re.search(r'value="([^"]+)"[^>]*id="csrf_token"', text)
                 or re.search(r'name="csrf-token"[^>]*content="([^"]+)"', text))
        if status >= 300 or not match:
            raise TimesketchError(f"Timesketch's sign-in page at {self.target.url} gave no CSRF token ({status})")
        self.csrf = match.group(1)
        form = urllib.parse.urlencode({"username": self.target.username, "password": self.target.password,
                                       "csrf_token": self.csrf}).encode()
        status, _, final = self._open("POST", url, form, "application/x-www-form-urlencoded")
        if status == 401 or status >= 400 or final.split("?")[0].rstrip("/").endswith("/login"):
            raise TimesketchError(f"Timesketch refused the sign-in for '{self.target.username}'")

    def _json(self, method: str, path: str, value: Optional[Dict] = None) -> Dict[str, Any]:
        body = json.dumps(value).encode() if value is not None else None
        status, reply, _ = self._open(method, f"{self.api}/{path}", body, "application/json" if body else "")
        if status >= 300:
            raise TimesketchError(f"Timesketch {method} /api/v1/{path} failed ({status}): {reply[:200]!r}")
        return json.loads(reply or b"{}")

    def sketch(self, name: str) -> Tuple[int, List[str]]:
        """The id of the sketch with this name, made if there's none, and its timelines' names."""
        for sketch in self._json("GET", "sketches/").get("objects") or []:
            if isinstance(sketch, dict) and sketch.get("name") == name and sketch.get("status", "") != "deleted":
                found = self._json("GET", f"sketches/{sketch['id']}/").get("objects") or [{}]
                return int(sketch["id"]), [t.get("name", "") for t in found[0].get("timelines") or []]
        made = self._json("POST", "sketches/", {"name": name, "description": f"Rowanholt case {name}"})
        return int(made["objects"][0]["id"]), []

    def upload(self, sketch_id: int, name: str, path: str) -> None:
        """Upload a JSON Lines file as a timeline, in chunks of 100 MiB."""
        size = os.path.getsize(path)
        fields = {"name": name, "sketch_id": str(sketch_id), "total_file_size": str(size),
                  "provider": "Rowanholt", "data_label": "jsonl"}
        total = max(1, math.ceil(size / CHUNK))
        if total > 1:
            fields.update(chunk_total_chunks=str(total), chunk_index_name=uuid.uuid4().hex)
        with open(path, "rb") as fh:
            for index in range(total):
                if total > 1:
                    fields.update(chunk_index=str(index), chunk_byte_offset=str(index * CHUNK))
                body, content_type = _multipart(fields, f"{name}.jsonl", fh.read(CHUNK))
                status, reply, _ = self._open("POST", f"{self.api}/upload/", body, content_type)
                if status >= 300:
                    raise TimesketchError(f"Timesketch refused timeline '{name}' ({status}): {reply[:200]!r}")


def export_case(output_directory: str, case: str, allimgs: Dict[str, str],
                target: Optional[TimesketchTarget] = None,
                client: Optional[TimesketchClient] = None) -> Dict[str, Tuple[int, int]]:
    """A timeline per processed host in the case's sketch; (events, records with no time) per host
    sent. Hosts already in the sketch are skipped."""
    client = client or TimesketchClient(target or TimesketchTarget.from_env())
    client.login()
    sketch_id, existing = client.sketch(case)
    print(f"     Timesketch sketch '{case}': {client.target.url}/sketch/{sketch_id}/")
    sent: Dict[str, Tuple[int, int]] = {}
    for host, _ in siem_hosts(allimgs):
        if host in sent:
            continue
        if host in existing:
            print(f"     '{host}' is already a timeline in the sketch; left as it is (delete it there to send it again)")
            continue
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as out:
            path = out.name
            written, untimed = write_timeline(os.path.join(output_directory, host), host, out)
        try:
            if written:
                client.upload(sketch_id, host, path)
        finally:
            os.unlink(path)
        sent[host] = (written, untimed)
        print(f"     Sent {written} events for '{host}' to Timesketch ({untimed} records have no time)")
    return sent
