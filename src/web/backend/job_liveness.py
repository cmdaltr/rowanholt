"""
Whether a job the database calls pending, running or paused is still being worked on.

The jobs table only says what the last writer saved. A worker killed mid-job (the container
recreated, the host restarted, the OOM killer) never saves again, so its job stays `running` for
ever, and every `GET /api/busy` after it says busy. This module gives each job a signal that ends
on its own when nobody is working on it, and fails the jobs whose signal has gone.

Only running and paused jobs count as busy. A pending job is a message in Celery's queue, and the
queue is in Redis, which a rebuild doesn't recreate (`docker compose up --build` leaves an
unchanged service alone, and `redis_data` keeps its snapshots if it ever is): the job waits out the
rebuild and runs on the new worker. Counting pending jobs held updates for as long as the queue was,
hours behind a long one (Ben, 12 November 2026). Pending jobs are still checked here, so one whose
message Redis did lose is failed with a reason rather than left pending for ever.

The signals, all in Redis (db 1, beside the image locks):

- A heartbeat for a job a worker has picked up: `Heartbeat`, from the moment `start_analysis`
  starts (so a job still `pending` while it waits for its images' locks has one too) until its
  final save. A thread of its own refreshes it, so a silent Volatility or Plaso step that writes
  nothing for hours, or a paused job (Elrond SIGSTOPped, the task's thread waiting on its pipe),
  keeps it. The key expires HEARTBEAT_TTL seconds after the last refresh: a dead worker stops
  refreshing, and the key is gone without anybody deleting it.
- A queued marker, set just before the backend queues a task (`mark_queued`), for the moment
  between queuing and the worker's first beat, when neither the queue nor a heartbeat may show it.
- The task's message in Celery's queue in the broker (or in kombu's `unacked` hash, delivered to
  a worker but not yet started): a pending job waiting its turn behind others for hours.

A job with none of these isn't failed at once: Redis restarting loses every key while workers are
alive and beating, and the queue's message moves between list and hash between two reads. Only a
job seen without a signal for STALE_GRACE seconds is failed, with a reason in its log and error,
so whoever started it sees what happened and can restart it. Nothing is deleted.
"""

import json
import logging
import os
import socket
import threading
import time
from datetime import datetime
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

# The worker refreshes every 15 seconds and the key lives 60: four refreshes would have to be missed
# in a row before a live job looks dead, and the thread doing it is idle between refreshes, so only
# a frozen process misses them. Volatility, Plaso and the rest run as Elrond's subprocesses, never
# in that process, so however long one step takes the beat goes on.
HEARTBEAT_INTERVAL = 15
HEARTBEAT_TTL = 60
# Queuing to the worker's first beat: the broker round trip and a free worker process. Long enough
# for that, short enough that a job whose queue was lost stops counting soon after.
QUEUED_GRACE = 120
# Seen with no signal for this long before it's failed: a Redis restart is recovered by the next
# refresh (15 seconds), so this is six refreshes' worth.
STALE_GRACE = 90
# How often the backend looks for dead jobs between busy checks
RECONCILE_INTERVAL = 30

# Celery's default queue, and kombu's Redis transport's names for its priority lists and for
# messages delivered to a worker but not acknowledged (kombu/transport/redis.py)
CELERY_QUEUE = "celery"
PRIORITY_SEP = "\x06\x16"
PRIORITY_STEPS = (3, 6, 9)
UNACKED_KEY = "unacked"

RUNNING_REASON = ("Interrupted: the worker running this job stopped without finishing it (killed, or "
                  "its container or the host restarted). Its output so far is kept; restart the job "
                  "to run it again.")
PENDING_REASON = ("Interrupted: this job was queued, but its task is no longer in the queue and no "
                  "worker picked it up (the worker or Redis restarted first). Restart the job to run it.")

_client = None
_broker = None


def _quick() -> dict:
    """Short timeouts and no retries. The busy check must answer within its caller's five seconds,
    and redis-py's default retries with backoff take nearly four seconds to give up on a Redis
    that's down: past five, the homelab reads the timeout as idle and rebuilds. Failing fast is an
    error, which counts as busy. The worker's heartbeat doesn't need retries either: the next
    refresh is never far off."""
    from redis.backoff import NoBackoff
    from redis.retry import Retry

    return {"socket_timeout": 1, "socket_connect_timeout": 1, "retry": Retry(NoBackoff(), 0)}


def _redis():
    """Redis db 1, as tasks_docker's image locks and backup_secrets use."""
    global _client
    if _client is None:
        import redis

        _client = redis.Redis(host=os.environ.get("REDIS_HOST", "redis"),
                              port=int(os.environ.get("REDIS_PORT", 6379)), db=1, **_quick())
    return _client


def _broker_client():
    """The Celery broker's Redis (db 0 by default)."""
    global _broker
    if _broker is None:
        import redis

        try:
            from .config import settings
        except ImportError:
            from config import settings
        _broker = redis.Redis.from_url(settings.celery_broker_url, **_quick())
    return _broker


def heartbeat_key(job_id: str) -> str:
    """Redis key that exists while a worker is working on the job."""
    return f"rowanholt:job_alive:{job_id}"


def queued_key(job_id: str) -> str:
    """Redis key that exists for QUEUED_GRACE seconds after the job's task was queued."""
    return f"rowanholt:job_queued:{job_id}"


def _now() -> str:
    return datetime.now().isoformat().replace("T", " ")


class Heartbeat:
    """The worker's proof that it's working on a job: a Redis key refreshed from a thread of its
    own until `stop`. Refresh failures are logged, never raised: a Redis blip mustn't fail the job,
    and a key that lapses for a moment comes back on the next refresh, well inside STALE_GRACE."""

    def __init__(self, job_id: str, client=None, interval: float = HEARTBEAT_INTERVAL,
                 ttl: int = HEARTBEAT_TTL, key: str | None = None) -> None:
        self.job_id = job_id
        # Another key for work on a job that isn't its run (siem_export's), so it never reads as
        # the job's own heartbeat
        self.key = key or heartbeat_key(job_id)
        self._client = client
        self.interval = interval
        self.ttl = ttl
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        # Who holds it, for whoever looks in Redis by hand; never shown through the API
        self._value = json.dumps({"host": socket.gethostname(), "pid": os.getpid()})

    def beat(self) -> bool:
        """Set the key afresh (SET, not EXPIRE, so a key lost with a Redis restart comes back)."""
        try:
            (self._client or _redis()).set(self.key, self._value, ex=self.ttl)
            return True
        except Exception as exc:  # noqa: BLE001 - see the class docstring
            logger.warning("Job %s: heartbeat not refreshed: %s", self.job_id, exc)
            return False

    def start(self) -> "Heartbeat":
        """Beat now, then every `interval` seconds until `stop`."""
        self.beat()

        def run() -> None:
            while not self._stop.wait(self.interval):
                self.beat()

        self._thread = threading.Thread(target=run, name=f"job-heartbeat-{self.job_id}", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        """Stop beating and remove the key: the job's final status is saved by now."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        try:
            (self._client or _redis()).delete(self.key)
        except Exception as exc:  # noqa: BLE001 - it expires by itself within HEARTBEAT_TTL
            logger.warning("Job %s: heartbeat not removed: %s", self.job_id, exc)


def mark_queued(job_id: str, client=None) -> None:
    """Record that the job's task is about to be queued. Called before `.delay()`, so there's no
    moment when the job is pending with no signal at all."""
    try:
        (client or _redis()).set(queued_key(job_id), _now(), ex=QUEUED_GRACE)
    except Exception as exc:  # noqa: BLE001 - the queue itself still shows the task
        logger.warning("Job %s: queued marker not set: %s", job_id, exc)


def queued_task_ids(task_ids: Iterable[str], broker=None) -> set:
    """Which of these Celery task IDs have a message waiting in the broker: in the queue (any
    priority) or delivered but not started. The messages are kombu's JSON with the task ID in
    their headers; matching the ID as text avoids depending on the rest of their shape, and a
    UUID doesn't turn up by accident."""
    wanted = {task_id for task_id in task_ids if task_id}
    if not wanted:
        return set()
    broker = broker or _broker_client()
    pipe = broker.pipeline()
    for name in (CELERY_QUEUE, *(f"{CELERY_QUEUE}{PRIORITY_SEP}{step}" for step in PRIORITY_STEPS)):
        pipe.lrange(name, 0, -1)
    pipe.hvals(UNACKED_KEY)
    found = set()
    for messages in pipe.execute():
        for raw in messages or []:
            text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
            found.update(task_id for task_id in wanted if task_id in text)
    return found


# (job ID, status value, Celery task ID)
ActiveJob = Tuple[str, str, Optional[str]]


class Liveness:
    """Which active jobs are live, and failing the ones that have been dead for STALE_GRACE.

    One pass is one indexed query, and with any active jobs one Redis round trip, plus one to the
    broker for pending jobs with neither a heartbeat nor a queued marker: well under a second."""

    def __init__(self, storage, statuses: Sequence, client_factory: Callable = _redis,
                 broker_factory: Callable = _broker_client, clock: Callable[[], float] = time.monotonic,
                 grace: float = STALE_GRACE) -> None:
        self.storage = storage
        self.statuses = tuple(statuses)
        self._client = client_factory
        self._broker = broker_factory
        self._clock = clock
        self.grace = grace
        self._missing: Dict[str, float] = {}  # job ID -> when it was first seen with no signal
        self._lock = threading.Lock()

    def _signals(self, jobs: List[ActiveJob]) -> Dict[str, bool]:
        pipe = self._client().pipeline()
        for job_id, _, _ in jobs:
            pipe.exists(heartbeat_key(job_id))
            pipe.exists(queued_key(job_id))
        answers = pipe.execute()
        live = {}
        for index, (job_id, _, _) in enumerate(jobs):
            live[job_id] = bool(answers[2 * index]) or bool(answers[2 * index + 1])
        # A pending job can also be waiting its turn in the queue, for hours, with no worker yet
        waiting = {task_id: job_id for job_id, status, task_id in jobs
                   if status == "pending" and task_id and not live[job_id]}
        for task_id in queued_task_ids(waiting, self._broker()) if waiting else ():
            live[waiting[task_id]] = True
        return live

    def check(self) -> bool:
        """One pass: fail the jobs dead for longer than the grace, and say whether any running or
        paused job is left that's live, or not yet dead long enough to tell. Pending jobs are
        reconciled but never busy (the module docstring says why). Raises when the database or
        Redis can't be read, which the busy check counts as busy."""
        with self._lock:
            jobs = self.storage.active_jobs(self.statuses)
            if not jobs:
                self._missing.clear()
                return False
            live = self._signals(jobs)
            now = self._clock()
            busy = False
            for job_id, status, _ in jobs:
                counts = status != "pending"
                if live[job_id]:
                    self._missing.pop(job_id, None)
                    busy = busy or counts
                    continue
                # A running job's heartbeat can vanish with a Redis restart while its worker
                # carries on, so it stays busy through the grace, until the next refresh
                since = self._missing.setdefault(job_id, now)
                if now - since < self.grace:
                    busy = busy or counts
                    continue
                self._interrupt(job_id, status)
            for job_id in set(self._missing) - {job_id for job_id, _, _ in jobs}:
                del self._missing[job_id]
            return busy

    def _interrupt(self, job_id: str, status: str) -> None:
        reason = PENDING_REASON if status == "pending" else RUNNING_REASON
        job = self.storage.interrupt_job(job_id, self.statuses, reason)
        self._missing.pop(job_id, None)
        if job is None:  # it moved on (finished, cancelled) between the read and the write
            return
        logger.warning("Job %s was %s with no worker for %.0f s: marked failed", job_id, status, self.grace)
        # The dead job's image locks would otherwise hold its images from other jobs for up to an
        # hour (tasks_docker.IMAGE_LOCK_TTL), and its process record would point at nothing
        try:
            try:
                from . import tasks_docker
            except ImportError:
                import tasks_docker
            tasks_docker.release_image_locks_for_job(job_id, job.source_paths)
            tasks_docker._clear_job_process(job_id)
        except Exception as exc:  # noqa: BLE001 - the locks expire on their own
            logger.warning("Job %s: image locks not released: %s", job_id, exc)

    def reconcile(self) -> None:
        """A pass for the background loop: errors are logged, and the next pass tries again."""
        try:
            self.check()
        except Exception:  # noqa: BLE001
            logger.exception("Job liveness pass failed")

    def start(self, interval: float = RECONCILE_INTERVAL) -> threading.Event:
        """Reconcile now (the backend's start-up, after a crash or a host restart) and every
        `interval` seconds, in a daemon thread. Returns the event that stops it."""
        stop = threading.Event()

        def run() -> None:
            self.reconcile()
            while not stop.wait(interval):
                self.reconcile()

        threading.Thread(target=run, name="job-liveness", daemon=True).start()
        return stop
