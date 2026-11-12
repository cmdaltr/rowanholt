"""
A completed job's manual SIEM export (`POST /api/jobs/{id}/export-siem`), shared by the backend,
which queues it, and the worker, which runs it.

The export is Elrond's own `--Index` (rowanholt/post/index_only.py), run in the worker beside the
analysis task: the worker image has Elrond, the network to Splunk and Elastic, and their
credentials; the backend image has none of these, which is why the export once ran there and
indexed nothing (bc1a979). Nothing is reimplemented here: this module holds the export's state, the
command, and what Elrond's output says happened.

The state lives in Redis (db 1, beside job_liveness's keys), never in the job's row, so it can't
overwrite the worker-owned columns:

- the record, `rowanholt:siem_export:<job>`: JSON with the task, its targets, who asked, its state
  (queued, running, succeeded or failed), the phase it's in and, at the end, each target's outcome.
  The backend writes it when it queues the task; from then on only that task writes it. It's kept
  for RECORD_TTL after its last write, so the job page can show the last export's outcome.
- a heartbeat, `rowanholt:siem_export_alive:<job>`, refreshed by the task (job_liveness.Heartbeat)
  while it runs. It's what `/api/busy` counts, and what tells a running export from one whose
  worker died: the record can't say so itself, since nobody is left to write it.

A queued export isn't busy, for the same reason a pending job isn't (job_liveness): its message
waits out a rebuild in Redis's queue and runs on the new worker.
"""

import json
import logging
import re
import threading
import time
from collections.abc import Callable, Iterable
from datetime import datetime

logger = logging.getLogger(__name__)

# The job option, Elrond's flag and the name Elrond prints for each target, in the order --Index
# runs them (index_case: Splunk, Elastic, then OpenSearch and Timesketch, then the Navigator)
TARGETS = (
    ("splunk", "--Splunk", "Splunk"),
    ("elastic", "--Elastic", "Elastic"),
    ("opensearch", "--OpenSearch", "OpenSearch"),
    ("timesketch", "--Timesketch", "Timesketch"),
    ("navigator", "--Navigator", "Navigator"),
)

QUEUED, RUNNING, SUCCEEDED, FAILED, INTERRUPTED = "queued", "running", "succeeded", "failed", "interrupted"
ACTIVE = (QUEUED, RUNNING)

# Long enough to see the last export's outcome on the job page days later; short enough that a
# deleted job's record doesn't stay for ever
RECORD_TTL = 30 * 24 * 3600
LOG_FILE = "rowanholt_siem_export.log"

INTERRUPTED_REASON = ("Interrupted: the worker running this export stopped before it finished (killed, or its "
                      "container or the host restarted). Export again to run it afresh.")
LOST_REASON = ("Interrupted: the export was queued, but its task is no longer in the queue and no worker "
               "picked it up (the worker or Redis restarted first). Export again.")


def record_key(job_id: str) -> str:
    """Redis key of the job's last export."""
    return f"rowanholt:siem_export:{job_id}"


def heartbeat_key(job_id: str) -> str:
    """Redis key that exists while a worker is running the job's export."""
    return f"rowanholt:siem_export_alive:{job_id}"


HEARTBEAT_MATCH = heartbeat_key("*")


def _redis():
    try:
        from . import job_liveness
    except ImportError:
        import job_liveness
    return job_liveness._redis()


def _queued_task_ids(task_ids: Iterable[str]) -> set:
    try:
        from . import job_liveness
    except ImportError:
        import job_liveness
    return job_liveness.queued_task_ids(task_ids)


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def targets(options) -> list[str]:
    """The SIEM targets a job's options name, in Elrond's order (names as Elrond prints them)."""
    return [name for option, _, name in TARGETS if getattr(options, option, False)]


def index_command(elrond_script: str, case: str, case_dir: str, names: Iterable[str]) -> list[str]:
    """Elrond's --Index of a processed case into the named targets: the command a run with these
    options ends with, without processing anything again."""
    flags = {name: flag for _, flag, name in TARGETS}
    return ["python3", elrond_script, case, case_dir, "--Index", *(flags[name] for name in names)]


def read(job_id: str, client=None) -> dict | None:
    """The job's last export record, or None."""
    raw = (client or _redis()).get(record_key(job_id))
    if not raw:
        return None
    return json.loads(raw.decode() if isinstance(raw, bytes) else raw)


def _write(job_id: str, record: dict, client=None) -> None:
    (client or _redis()).set(record_key(job_id), json.dumps(record), ex=RECORD_TTL)


def status(job_id: str, client=None, queued_ids: Callable[[Iterable[str]], set] | None = None,
           clock: Callable[[], float] = time.time, queued_grace: float = 120) -> dict:
    """What the job's last export is doing, or did: its record, with `state` read against the
    signals of life. A queued export whose message has left the queue with no worker beating for it,
    or a running one whose heartbeat has lapsed, is `interrupted`; nothing rewrites the record for
    that, so the next export simply replaces it."""
    client = client or _redis()
    record = read(job_id, client)
    if record is None:
        return {"state": "none"}
    state = record.get("state")
    if state in ACTIVE and not client.exists(heartbeat_key(job_id)):
        if state == RUNNING:
            record.update(state=INTERRUPTED, error=INTERRUPTED_REASON)
        elif (clock() - record.get("queued_epoch", 0) > queued_grace
              and record.get("task_id") not in (queued_ids or _queued_task_ids)([record.get("task_id")])):
            record.update(state=INTERRUPTED, error=LOST_REASON)
    record.pop("queued_epoch", None)
    return record


# The backend is one uvicorn process, so a lock here makes claiming one step: two requests can't
# both find no export and both queue one
_claim_lock = threading.Lock()


def claim(job_id: str, task_id: str, names: list[str], requested_by: str, client=None,
          **status_options) -> dict | None:
    """Record a new export of the job as queued, unless one is queued or running already (then
    None). Called just before the task is queued, so there's no moment it's queued unrecorded."""
    client = client or _redis()
    with _claim_lock:
        if status(job_id, client, **status_options)["state"] in ACTIVE:
            return None
        record = {"task_id": task_id, "state": QUEUED, "targets": names, "requested_by": requested_by,
                  "queued_at": _now(), "queued_epoch": time.time(), "phase": None, "hosts": [],
                  "results": {}, "error": None}
        _write(job_id, record, client)
    return record


def drop(job_id: str, task_id: str, client=None) -> None:
    """Forget a claim whose task couldn't be queued, if it's still that one."""
    client = client or _redis()
    record = read(job_id, client)
    if record and record.get("task_id") == task_id:
        client.delete(record_key(job_id))


def update(job_id: str, task_id: str, client=None, **fields) -> bool:
    """The worker's write to its own export's record: refused (False) once another export has
    replaced it, so a stray task can't overwrite a newer export's state."""
    client = client or _redis()
    record = read(job_id, client)
    if not record or record.get("task_id") != task_id:
        return False
    record.update(fields)
    _write(job_id, record, client)
    return True


def running(client=None) -> bool:
    """Whether a worker is running any job's export: one heartbeat is enough, so the scan stops
    at the first."""
    for _ in (client or _redis()).scan_iter(match=HEARTBEAT_MATCH, count=100):
        return True
    return False


ANSI = re.compile(r"\x1b\[[0-9;]*m")
_PHASE = re.compile(r"^-> Commencing (\w+) Phase")
_HOSTS = re.compile(r"^Indexing (\d+) processed host\(s\): (.*)$")
_TARGET_FAILED = re.compile(r"^ERROR: (\w+) (?:indexing|export|layer) failed: (.*)$")
_ERROR = re.compile(r"^Error: (.*)$")
_OPENSEARCH = re.compile(r"^Indexed (\d+) records for '(.+)' into OpenSearch")
_TIMESKETCH = re.compile(r"^Sent (\d+) events for '(.+)' to Timesketch")
_LAYER = re.compile(r"layer: (\d+) techniques$")
# Worth a line in the job's log; everything else Elrond prints goes to LOG_FILE only. The job's
# log is rewritten whole on every save, so a line per artefact per host would cost a write each
_NOTABLE = re.compile(r"^(-> Commencing|-> Completed|Indexing \d+ processed|Replaced |No platform recorded|"
                      r".* is a local install|ERROR|Error|WARNING|Warning|Indexed \d+ records|Sent \d+ events|"
                      r".*layer: \d+ techniques|Data inputs configured|Splunk restart|Generated \d+ dashboards)")


class Progress:
    """What Elrond's --Index output says: the phase it's in, the hosts, and each target's outcome.
    Fed one line at a time; `feed` returns the line for the job's log, or None."""

    def __init__(self, names: list[str]) -> None:
        self.names = list(names)
        self.phase: str | None = None
        self.hosts: list[str] = []
        self.failures: dict[str, str] = {}
        self.counts: dict[str, dict[str, int]] = {}
        self.error: str | None = None

    def feed(self, raw: str) -> str | None:
        line = ANSI.sub("", raw).strip()
        if not line or set(line) <= {"-"}:
            return None
        match = _PHASE.match(line)
        if match:
            self.phase = match.group(1)
        match = _HOSTS.match(line)
        if match:
            self.hosts = [host.strip() for host in match.group(2).split(",") if host.strip()]
        # index_case's own wording: "ERROR: Splunk indexing failed", "OpenSearch export failed",
        # "Navigator layer failed"
        match = _TARGET_FAILED.match(line)
        if match:
            self.failures[match.group(1)] = match.group(2)
        match = _ERROR.match(line)
        if match:
            self.error = match.group(1)
        for name, pattern, unit in (("OpenSearch", _OPENSEARCH, "records"), ("Timesketch", _TIMESKETCH, "events")):
            match = pattern.match(line)
            if match:
                self.counts.setdefault(name, {})[match.group(2)] = int(match.group(1))
        match = _LAYER.search(line)
        if match:
            self.counts.setdefault("Navigator", {})["techniques"] = \
                self.counts.get("Navigator", {}).get("techniques", 0) + int(match.group(1))
        return line if _NOTABLE.match(line) else None

    def step(self) -> dict:
        """Where the export is, for the record: the target being indexed and its place in the run."""
        index = self.names.index(self.phase) + 1 if self.phase in self.names else 0
        return {"phase": self.phase, "step": index, "steps": len(self.names)}

    def results(self, returncode: int) -> dict[str, dict]:
        """Each target's outcome. A run that stopped before indexing (Elrond's own Error: a SIEM
        unreachable, no processed hosts) failed every target with that reason."""
        out: dict[str, dict] = {}
        for name in self.names:
            if name in self.failures:
                out[name] = {"ok": False, "error": self.failures[name]}
            elif returncode != 0 and not self.failures:
                out[name] = {"ok": False, "error": self.error or f"Elrond exited with status {returncode}"}
            else:
                out[name] = {"ok": True}
            totals = self.counts.get(name)
            if totals and name == "Navigator":
                out[name]["techniques"] = totals["techniques"]
            elif totals:
                out[name]["by_host"] = totals
                out[name]["total"] = sum(totals.values())
        return out


def elastic_count(case: str, environ: dict | None = None, opener=None) -> int | None:
    """How many documents the case's Elasticsearch index holds now (refreshed first, so the last
    bulk request is counted), or None when Elastic is a local install or doesn't say. Elrond's
    Elastic ingest prints no total of its own."""
    import base64
    import os
    import urllib.request

    env = environ if environ is not None else os.environ
    host = env.get("ELASTICSEARCH_HOST")
    if not host:
        return None
    base = f"http://{host}:{env.get('ELASTICSEARCH_PORT', '9200')}/{case.lower()}"
    auth = base64.b64encode(f"{env.get('ELASTIC_USERNAME', 'elastic')}:{env.get('ELASTIC_PASSWORD', '')}".encode())
    opener = opener or urllib.request.urlopen

    def call(path: str, method: str) -> dict:
        request = urllib.request.Request(f"{base}/{path}", method=method)
        request.add_header("Authorization", f"Basic {auth.decode()}")
        with opener(request, timeout=30) as response:
            return json.loads(response.read() or b"{}")

    try:
        call("_refresh", "POST")
        return int(call("_count", "GET")["count"])
    except Exception as exc:  # noqa: BLE001 - the count is a nicety; the export's outcome stands
        logger.warning("Elastic count for %s not read: %s", case, exc)
        return None


def summary(record: dict) -> str:
    """One line for the job's log and the web app: what the export did."""
    results = record.get("results") or {}
    done = [name for name, result in results.items() if result.get("ok")]
    failed = [name for name, result in results.items() if not result.get("ok")]
    if record.get("state") == SUCCEEDED:
        counts = []
        for name in done:
            result = results[name]
            if "total" in result:
                counts.append(f"{name} {result['total']:,}")
            elif "techniques" in result:
                counts.append(f"Navigator {result['techniques']} techniques")
        tail = f" ({', '.join(counts)})" if counts else ""
        return f"SIEM export finished: indexed into {', '.join(done)}{tail}"
    reasons = "; ".join(f"{name}: {results[name].get('error')}" for name in failed if results[name].get("error"))
    return f"SIEM export failed: {reasons or record.get('error') or 'see ' + LOG_FILE}"
