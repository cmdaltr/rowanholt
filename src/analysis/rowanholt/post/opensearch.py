"""A processed case into OpenSearch, or into Wazuh's indexer, which is OpenSearch (elrond.py --OpenSearch).

The same documents as Elastic's (post/elastic/ingest.py: field names, @timestamp, the technique
fields), into one index per case, ``<OPENSEARCH_INDEX_PREFIX><case>``, replaced on every export so
a case indexed again isn't indexed twice. With OPENSEARCH_DASHBOARDS_URL, an index pattern for it
in OpenSearch Dashboards (or the Wazuh dashboard).

Settings come from the environment (.env): OPENSEARCH_URL, OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD,
OPENSEARCH_CA (a CA bundle for a private certificate, such as Wazuh's), OPENSEARCH_VERIFY (false
skips certificate checks), OPENSEARCH_INDEX_PREFIX (rowanholt-) and OPENSEARCH_DASHBOARDS_URL.
"""

import base64
import json
import logging
import os
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from rowanholt.post.elastic.ingest import INDEX_MAPPING, ingest_host_tables
from rowanholt.post.siem import siem_hosts

logger = logging.getLogger(__name__)


class OpenSearchError(RuntimeError):
    """OpenSearch refused the export, or isn't configured."""


@dataclass(frozen=True)
class OpenSearchTarget:
    """Where and how to reach OpenSearch (or Wazuh's indexer)."""

    url: str
    username: str = ""
    password: str = ""
    ca: str = ""
    verify: bool = True
    prefix: str = "rowanholt-"
    dashboards_url: str = ""

    @classmethod
    def from_env(cls, env: Optional[Dict[str, str]] = None) -> "OpenSearchTarget":
        """The target .env describes; OpenSearchError without OPENSEARCH_URL."""
        env = os.environ if env is None else env
        url = env.get("OPENSEARCH_URL", "").rstrip("/")
        if not url:
            raise OpenSearchError("OPENSEARCH_URL isn't set (.env): the OpenSearch or Wazuh indexer to export to")
        return cls(
            url=url,
            username=env.get("OPENSEARCH_USERNAME", ""),
            password=env.get("OPENSEARCH_PASSWORD", ""),
            ca=env.get("OPENSEARCH_CA", ""),
            verify=env.get("OPENSEARCH_VERIFY", "true").strip().lower() not in ("false", "0", "no"),
            prefix=env.get("OPENSEARCH_INDEX_PREFIX", "rowanholt-").lower(),
            dashboards_url=env.get("OPENSEARCH_DASHBOARDS_URL", "").rstrip("/"),
        )

    def index(self, case: str) -> str:
        """The case's index name (OpenSearch's are lower case)."""
        return f"{self.prefix}{case}".lower()

    def context(self) -> Optional[ssl.SSLContext]:
        """The TLS context: verified (against OPENSEARCH_CA when given) unless OPENSEARCH_VERIFY=false."""
        if not self.url.startswith("https") and not self.dashboards_url.startswith("https"):
            return None
        context = ssl.create_default_context(cafile=self.ca or None)
        if not self.verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context


Request = Callable[[str, str, Optional[bytes], Dict[str, str]], Tuple[int, bytes]]


def http_request(target: OpenSearchTarget) -> Request:
    """A request function for ``target``: (method, url, body, headers) -> (status, body)."""
    context = target.context()
    auth = ""
    if target.username:
        auth = "Basic " + base64.b64encode(f"{target.username}:{target.password}".encode()).decode()

    def request(method: str, url: str, body: Optional[bytes], headers: Dict[str, str]) -> Tuple[int, bytes]:
        req = urllib.request.Request(url, data=body, method=method)
        for name, value in headers.items():
            req.add_header(name, value)
        if auth:
            req.add_header("Authorization", auth)
        try:
            with urllib.request.urlopen(req, context=context, timeout=120) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    return request


def _json(value: Dict) -> bytes:
    return json.dumps(value).encode("utf-8")


def replace_index(target: OpenSearchTarget, case: str, request: Request) -> str:
    """Delete the case's index and create it afresh with Elastic's mapping; "replaced" or "new"."""
    url = f"{target.url}/{target.index(case)}"
    status, body = request("DELETE", url, None, {})
    if status >= 300 and status != 404:
        raise OpenSearchError(f"OpenSearch wouldn't delete index '{target.index(case)}' ({status}): {body[:200]!r}")
    mapping = dict(INDEX_MAPPING, settings={"index.mapping.total_fields.limit": 1000000})
    created, body = request("PUT", url, _json(mapping), {"Content-Type": "application/json"})
    if created >= 300:
        raise OpenSearchError(f"OpenSearch wouldn't create index '{target.index(case)}' ({created}): {body[:200]!r}")
    return "new" if status == 404 else "replaced"


def bulk_sender(target: OpenSearchTarget, request: Request) -> Callable[[List[str]], bool]:
    """send(batch) for ingest_host_tables: False when the request, or any document in it, is refused."""

    def send(batch: List[str]) -> bool:
        if not batch:
            return True
        body = ("\n".join(batch) + "\n").encode("utf-8")
        try:
            status, reply = request("POST", f"{target.url}/_bulk", body, {"Content-Type": "application/x-ndjson"})
        except OSError as error:
            logger.warning("OpenSearch bulk request failed: %s", error)
            return False
        if status >= 300:
            return False
        try:
            return not json.loads(reply).get("errors")  # accepted as a whole even with documents refused
        except (ValueError, AttributeError):
            return True

    return send


def index_pattern(target: OpenSearchTarget, case: str, request: Request) -> Optional[str]:
    """An index pattern for the case's index in OpenSearch Dashboards (or the Wazuh dashboard), on
    @timestamp; what happened, or None without OPENSEARCH_DASHBOARDS_URL."""
    if not target.dashboards_url:
        return None
    index = target.index(case)
    body = _json({"attributes": {"title": index, "timeFieldName": "@timestamp"}})
    url = f"{target.dashboards_url}/api/saved_objects/index-pattern/{index}?overwrite=true"
    status, reply = request("POST", url, body, {"Content-Type": "application/json", "osd-xsrf": "true"})
    if status >= 300:
        raise OpenSearchError(f"OpenSearch Dashboards wouldn't save index pattern '{index}' ({status}): {reply[:200]!r}")
    return index


def export_case(output_directory: str, case: str, allimgs: Dict[str, str],
                target: Optional[OpenSearchTarget] = None, request: Optional[Request] = None) -> Dict[str, int]:
    """Index every processed host of the case into its own OpenSearch index, replacing the last
    export; records sent per host. OpenSearchError if the index can't be made or any table was
    refused in part (the rest is still sent)."""
    target = target or OpenSearchTarget.from_env()
    request = request or http_request(target)
    index = target.index(case)
    outcome = replace_index(target, case, request)
    print(f"     {'Replaced' if outcome == 'replaced' else 'Created'} OpenSearch index '{index}'")
    send = bulk_sender(target, request)
    sent: Dict[str, int] = {}
    refused: List[str] = []
    for host, _ in siem_hosts(allimgs):
        if host in sent:
            continue
        results = ingest_host_tables(os.path.join(output_directory, host), host, index, send)
        sent[host] = sum(records for _, records, _ in results)
        refused += [f"{host}/{artefact}" for artefact, _, ok in results if not ok]
        print(f"     Indexed {sent[host]} records for '{host}' into OpenSearch")
    pattern = index_pattern(target, case, request)
    if pattern:
        print(f"     Index pattern '{pattern}' saved in OpenSearch Dashboards")
    if refused:
        raise OpenSearchError(f"OpenSearch refused records of {len(refused)} table(s): {', '.join(refused[:10])}")
    return sent
