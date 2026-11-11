"""Webhooks: Rowanholt POSTs JSON to URLs an admin registers when something happens (automation).

Events
    job.completed      an analysis finished:          {job_id, case_number, status, images}
    job.failed         an analysis stopped:           {job_id, case_number, status, images, error}
    finding.confirmed  an analyst confirmed a finding: {job_id, case_number, finding_id, host, technique}
    report.ready       a case report was built:       {job_id, case_number, format, findings, confirmed}

Bodies carry ids, the case number, a host and counts, never artefact contents: a webhook leaves the
installation, the case's evidence doesn't. The one free text, a failed job's error, has its file paths
taken out (they name evidence and where it's kept).

Each delivery is {"event", "sent_at", "data"}, with X-Rowanholt-Event and, when the webhook has a
secret, X-Rowanholt-Signature: sha256=<hex HMAC-SHA256 of the raw body>, so the receiver can check it
came from this server (Shikari's design, shikari/webhooks.py). Deliveries run on a background thread,
three tries with backoff; the last 20 are kept per webhook for the admin page. Webhooks (with their
secrets) live in webhooks.json beside users.json (or the path in ROWANHOLT_WEBHOOKS), which the
backend and the worker both see, and which `rowanholt server backup` keeps.

Sending is the automation feature (Pro and Services), checked at delivery: registering, listing and
editing stay open on every edition, so a Free installation keeps its webhooks and the admin page says
they aren't sending and why.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    from . import licence
except ImportError:
    import licence

logger = logging.getLogger(__name__)

EVENTS = ("job.completed", "job.failed", "finding.confirmed", "report.ready")
# an absolute path (/mnt/..., C:\cases\...), not a slash inside a word ("and/or", "3/4")
PATH = re.compile(r"(?<![\w/\\])(?:[A-Za-z]:[\\/]|/)[^\s'\"]+")
KEEP_DELIVERIES = 20
TRIES = 3
TIMEOUT = 10
BACKGROUND = True  # deliver on a thread; tests deliver inline
_lock = threading.Lock()


def store_path() -> Path:
    explicit = os.environ.get("ROWANHOLT_WEBHOOKS")
    if explicit:
        return Path(explicit)
    return Path(os.environ.get("USERS_FILE", "/app/data/users.json")).parent / "webhooks.json"


def _load() -> List[Dict]:
    try:
        hooks = json.loads(store_path().read_text())
        return hooks if isinstance(hooks, list) else []
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as exc:
        logger.error("Ignoring the webhook store at %s: %s", store_path(), exc)
        return []


def _save(hooks: List[Dict]) -> None:
    path = store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    # the secrets are in it: readable by the backend's user only, like users.json
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(hooks, fh, indent=2)
    os.replace(tmp, path)


def public(hook: Dict) -> Dict:
    """A webhook as the API shows it: the secret only as whether there is one."""
    return {**{k: v for k, v in hook.items() if k != "secret"}, "has_secret": bool(hook.get("secret"))}


def hooks() -> List[Dict]:
    return _load()


def _private_host(host: str) -> bool:
    """localhost, or a loopback or RFC 1918 address: a homelab SOAR may not have a certificate."""
    if host in ("localhost", "localhost.localdomain") or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    if address.is_loopback:
        return True
    return address.version == 4 and any(address in ipaddress.ip_network(n)
                                        for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def validate(url: str, events: List[str]) -> Optional[str]:
    """Why a webhook can't be saved, or None."""
    parsed = urlparse(url or "")
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return "The URL must be https://"
    if parsed.username or parsed.password:
        return "Put credentials in the webhook's secret, not the URL"
    if parsed.scheme == "http" and not _private_host(parsed.hostname):
        return "The URL must be https:// (http:// is allowed only for localhost and private 10/172.16/192.168 addresses)"
    unknown = set(events or []) - set(EVENTS)
    if not events or unknown:
        return f"Choose events from {', '.join(EVENTS)}"
    return None


def add(url: str, events: List[str], secret: Optional[str] = None, description: str = "") -> Dict:
    hook = {"id": secrets.token_hex(6), "url": url.strip(), "events": sorted(set(events)),
            "secret": secret if secret is not None else secrets.token_urlsafe(24),
            "description": description.strip()[:200], "enabled": True, "created": time.time(), "deliveries": []}
    with _lock:
        stored = _load()
        stored.append(hook)
        _save(stored)
    return hook


def update(hook_id: str, **fields) -> Optional[Dict]:
    with _lock:
        stored = _load()
        for hook in stored:
            if hook["id"] == hook_id:
                hook.update({k: v for k, v in fields.items()
                             if k in ("url", "events", "enabled", "description") and v is not None})
                _save(stored)
                return hook
    return None


def remove(hook_id: str) -> bool:
    with _lock:
        stored = _load()
        kept = [h for h in stored if h["id"] != hook_id]
        _save(kept)
    return len(kept) != len(stored)


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def sending(standing: Optional[licence.Standing] = None) -> Tuple[bool, str]:
    """Whether webhooks are delivered now, and why not when they aren't."""
    st = standing or licence.current()
    if st.has(licence.AUTOMATION):
        return True, ""
    if st.state == "lapsed":
        return False, "The licence has run out, so this is the Free edition: webhooks are kept but not sent."
    if st.state == "pending":
        return False, "The licence hasn't started yet: webhooks are sent from its first day."
    return False, (f"Webhooks are part of the Pro and Services editions; this is the {st.edition.value.title()} "
                   "edition. They're kept, and sent once a Pro or Services licence is installed.")


def _record(hook_id: str, delivery: Dict) -> None:
    with _lock:
        stored = _load()
        for hook in stored:
            if hook["id"] == hook_id:
                hook["deliveries"] = ([delivery] + hook.get("deliveries", []))[:KEEP_DELIVERIES]
                _save(stored)
                return


def _post(url: str, body: bytes, headers: Dict) -> int:
    import httpx  # in the backend and the worker images; only needed once something is sent

    # Redirects aren't followed: the admin registered this URL, not wherever it points next
    return httpx.post(url, content=body, headers=headers, timeout=TIMEOUT, follow_redirects=False).status_code


def deliver(hook: Dict, event: str, data: Dict, tries: int = TRIES, backoff: float = 2.0) -> Dict:
    """POST one event to one webhook; returns the delivery record (also kept on the webhook)."""
    body = json.dumps({"event": event, "sent_at": time.time(), "data": data}, default=str).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "Rowanholt-Webhook/1", "X-Rowanholt-Event": event}
    if hook.get("secret"):
        headers["X-Rowanholt-Signature"] = sign(hook["secret"], body)
    result = {"event": event, "at": time.time(), "ok": False, "status": None, "error": None, "tries": 0}
    for attempt in range(tries):
        result["tries"] = attempt + 1
        try:
            code = _post(hook["url"], body, headers)
            result["status"] = code
            if code < 300:
                result.update(ok=True, error=None)
                break
            result["error"] = f"HTTP {code}"
            if code < 500 and code != 429:
                break  # the receiver refused it; trying again won't change that
        except Exception as exc:  # noqa: BLE001 - any transport failure is a failed try, recorded
            result["error"] = str(exc)[:200]
        if attempt < tries - 1:
            time.sleep(backoff * (attempt + 1))
    _record(hook["id"], result)
    return result


def emit(event: str, data: Dict, background: Optional[bool] = None) -> int:
    """Send an event to every enabled webhook that wants it, if this edition sends webhooks.
    Returns how many were sent (0 when automation is off). Never raises: a webhook mustn't break the
    job, finding or report that set it off."""
    try:
        if event not in EVENTS or not sending()[0]:
            return 0
        targets = [h for h in _load() if h.get("enabled") and event in h.get("events", [])]
        for hook in targets:
            if BACKGROUND if background is None else background:
                threading.Thread(target=deliver, args=(hook, event, data), daemon=True,
                                 name=f"webhook-{hook['id']}").start()
            else:
                deliver(hook, event, data)
        return len(targets)
    except Exception:  # noqa: BLE001
        logger.exception("Webhook %s not sent", event)
        return 0


def emit_job(job) -> int:
    """A job's end, as job.completed or job.failed (storage.save_job calls this on the change)."""
    status = getattr(job.status, "value", job.status)
    data = {"job_id": job.id, "case_number": job.case_number, "status": status,
            "images": len(job.source_paths or [])}
    if status == "failed":
        data["error"] = PATH.sub("<path>", job.error or "")[:200]
        return emit("job.failed", data)
    return emit("job.completed", data)
