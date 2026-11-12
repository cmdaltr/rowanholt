"""
Whether Rowanholt is in the middle of work a restart would interrupt.

`homelab pull` and `homelab update` ask `GET /api/busy` before rebuilding (the backend, worker and
frontend recreated; Redis, and the job queue in it, left running) and hold off while it says
`{"busy": true}`. Each kind of work that a rebuild would cut off registers a named check here.
The endpoint is unauthenticated, so the names go to the log only: the answer says busy or not, never what or whose.

The contract counts anything but `{"busy": true}` as idle (an error, a timeout after 5 seconds),
so every check must be cheap, and a check that raises counts as busy: a check that can't tell
must not let a rebuild through by accident.
"""

import logging
import threading
import time
from contextlib import contextmanager
from typing import Callable, Dict, Iterator, List

logger = logging.getLogger(__name__)

BusyCheck = Callable[[], bool]
_checks: Dict[str, BusyCheck] = {}


def register(name: str, check: BusyCheck) -> None:
    """Add (or replace) the check called `name`."""
    _checks[name] = check


def unregister(name: str) -> None:
    """Remove the check called `name`, if there is one."""
    _checks.pop(name, None)


def busy_reasons() -> List[str]:
    """Names of the checks that currently say busy. A check that raises counts as busy."""
    reasons = []
    for name, check in list(_checks.items()):
        try:
            if check():
                reasons.append(name)
        except Exception:  # noqa: BLE001 - unsure is busy, by the contract
            logger.exception("busy check %s failed; treating as busy", name)
            reasons.append(name)
    return reasons


class Counter:
    """How many of something are in flight in this process, for work that leaves no record of its
    own (a request being handled, a download in a background task). The backend runs as a single
    uvicorn process, so a count in memory is the whole picture."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._count = 0

    @contextmanager
    def working(self) -> Iterator[None]:
        """Count the enclosed work as in flight until it ends, however it ends."""
        with self._lock:
            self._count += 1
        try:
            yield
        finally:
            with self._lock:
                self._count -= 1

    def __call__(self) -> bool:
        return self._count > 0


class QueuedTasks:
    """Celery tasks the backend queued that have no job record (a sample fetch, a symbol table
    build), checked by their result in Redis. A result read is one Redis GET; asking the workers
    (`inspect().active()`) waits out its timeout on every call, too slow for this.

    A task whose result never arrives (its worker lost, Redis flushed) would hold every rebuild,
    so each is forgotten after `max_age` seconds, longer than any of them is allowed to run."""

    def __init__(self, result_of: Callable[[str], object], max_age: float = 6 * 3600) -> None:
        self._result_of = result_of
        self._max_age = max_age
        self._lock = threading.Lock()
        self._queued: Dict[str, float] = {}

    def add(self, task_id: str) -> None:
        """Track a task just queued."""
        with self._lock:
            self._queued[task_id] = time.monotonic()

    def __call__(self) -> bool:
        now = time.monotonic()
        with self._lock:
            queued = dict(self._queued)
        for task_id, since in queued.items():
            if now - since > self._max_age:
                logger.warning("busy: forgetting task %s, queued %.0f s ago with no result",
                               task_id, now - since)
                self._forget(task_id)
            elif self._result_of(task_id).ready():
                self._forget(task_id)
        with self._lock:
            return bool(self._queued)

    def _forget(self, task_id: str) -> None:
        with self._lock:
            self._queued.pop(task_id, None)


def _celery_result(task_id: str) -> object:
    try:
        from .tasks_docker import celery_app
    except ImportError:
        from tasks_docker import celery_app
    return celery_app.AsyncResult(task_id)


# Mutating API requests being handled: uploads (evidence helpers, threat intelligence, symbol
# tables, logos) stream for as long as the file takes. (A manual SIEM export runs in the worker
# and registers its own check, siem-exports, in main.py.)
requests_in_flight = Counter()
# Mordor dataset downloads, which run in a background task after their request has answered
downloads = Counter()
# Worker tasks with no job record
side_tasks = QueuedTasks(_celery_result)

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


async def middleware(request, call_next):
    """Count each mutating /api request while it's handled. Reads aren't counted: the web app
    polls, and a rebuild held off by a poll would wait on nothing."""
    if request.method in SAFE_METHODS or not request.url.path.startswith("/api"):
        return await call_next(request)
    with requests_in_flight.working():
        return await call_next(request)


register("requests", requests_in_flight)
register("downloads", downloads)
register("side-tasks", side_tasks)
