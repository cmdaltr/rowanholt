"""
Celery Tasks - Dockerized Version

Background tasks for running Elrond analysis in Docker containers.
This version runs Elrond directly in the same container environment.
"""

import shutil
import subprocess
import sys
import os
import tempfile
import re
import json
import time
import hashlib
import signal
import threading
from datetime import datetime
from pathlib import Path

from celery import Celery
from celery.utils.log import get_task_logger
from celery.worker.control import control_command
import redis

from config import settings
from storage import JobStorage
from models.job import JobStatus, PendingAction
import backup_secrets

# Initialize Celery
celery_app = Celery(
    "elrond",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)
# Jobs run for hours. Redis re-delivers any unacked (prefetched) message after
# visibility_timeout (default 1 h), which re-ran the same job back to back.
celery_app.conf.broker_transport_options = {"visibility_timeout": 86400}
celery_app.conf.worker_prefetch_multiplier = 1

logger = get_task_logger(__name__)
job_storage = JobStorage()

# Redis client for image locking
_redis_client = None


def output_stats(root: Path) -> tuple:
    """(files, bytes) under root in one scandir walk: one stat per file, not rglob's
    is_file() and stat() on every path (E15: 33 min on a full Windows case).
    macOS resource forks (._*) are skipped; they can raise permission errors."""
    files = size = 0
    stack = [str(root)]
    while stack:
        try:
            with os.scandir(stack.pop()) as entries:
                for entry in entries:
                    if entry.name.startswith("._"):
                        continue
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            files += 1
                            size += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        pass
        except OSError:
            pass
    return files, size

def get_redis_client():
    """Get or create Redis client for image locking."""
    global _redis_client
    if _redis_client is None:
        redis_host = os.environ.get("REDIS_HOST", "redis")
        redis_port = int(os.environ.get("REDIS_PORT", 6379))
        _redis_client = redis.Redis(host=redis_host, port=redis_port, db=1)  # Use db=1 for locks
    return _redis_client


def _get_image_lock_key(image_path: str) -> str:
    """Generate a Redis key for an image lock."""
    # Normalize the path and create a hash for consistent key naming
    normalized = os.path.normpath(image_path).lower()
    path_hash = hashlib.md5(normalized.encode()).hexdigest()[:16]
    return f"rowanholt:image_lock:{path_hash}"


def acquire_image_locks(job_id: str, image_paths: list, timeout: int = 3600, retry_interval: int = 10) -> bool:
    """
    Acquire locks on all image paths. Waits if any image is in use.

    Args:
        job_id: Job ID (used as lock value for identification)
        image_paths: List of image paths to lock
        timeout: Lock timeout in seconds (default 1 hour)
        retry_interval: Seconds between retry attempts

    Returns:
        True if all locks acquired, False if failed
    """
    redis_client = get_redis_client()
    acquired_locks = []

    try:
        for image_path in image_paths:
            lock_key = _get_image_lock_key(image_path)
            image_name = os.path.basename(image_path)

            while True:
                # Try to acquire the lock using SETNX (set if not exists)
                # The lock value contains job_id for debugging
                lock_acquired = redis_client.set(
                    lock_key,
                    f"{job_id}:{datetime.now().isoformat()}",
                    nx=True,  # Only set if not exists
                    ex=timeout  # Expire after timeout
                )

                if lock_acquired:
                    acquired_locks.append(lock_key)
                    logger.info(f"Job {job_id}: Acquired lock on '{image_name}'")
                    break
                else:
                    # Lock exists - another job is using this image
                    existing_lock = redis_client.get(lock_key)
                    if existing_lock:
                        existing_job = existing_lock.decode().split(":")[0]
                        logger.info(f"Job {job_id}: Waiting for '{image_name}' (in use by job {existing_job})")

                        # Update job status to show waiting
                        job = job_storage.get_job(job_id)
                        if job:
                            job.log.append(
                                f"[{datetime.now().isoformat().replace('T', ' ')}] -> Waiting for '{image_name}' (in use by another job)"
                            )
                            job_storage.save_job(job)

                    # Wait and retry
                    time.sleep(retry_interval)

                    # Check if our job was cancelled while waiting
                    job = job_storage.get_job(job_id)
                    if job and job.status == JobStatus.CANCELLED:
                        logger.info(f"Job {job_id}: Cancelled while waiting for image lock")
                        release_image_locks(acquired_locks)
                        return False

        return True

    except Exception as e:
        logger.error(f"Job {job_id}: Error acquiring image locks: {e}")
        # Release any locks we acquired
        release_image_locks(acquired_locks)
        return False


def release_image_locks(lock_keys: list):
    """Release image locks."""
    if not lock_keys:
        return

    redis_client = get_redis_client()
    for lock_key in lock_keys:
        try:
            redis_client.delete(lock_key)
            logger.debug(f"Released lock: {lock_key}")
        except Exception as e:
            logger.warning(f"Error releasing lock {lock_key}: {e}")


def release_image_locks_for_job(job_id: str, source_paths: list):
    """
    Release image locks held by a specific job.
    Only releases locks if they are actually held by this job.
    """
    if not source_paths:
        return

    redis_client = get_redis_client()
    for image_path in source_paths:
        lock_key = _get_image_lock_key(image_path)
        try:
            # Check if this job holds the lock
            lock_value = redis_client.get(lock_key)
            if lock_value:
                lock_str = lock_value.decode() if isinstance(lock_value, bytes) else str(lock_value)
                if lock_str.startswith(f"{job_id}:"):
                    redis_client.delete(lock_key)
                    logger.info(f"Released image lock for job {job_id}: {os.path.basename(image_path)}")
        except Exception as e:
            logger.warning(f"Error releasing lock for {image_path}: {e}")



# =====================================================
# PAUSE / RESUME / KILL OF THE ELROND PROCESS GROUP
# =====================================================
# Elrond runs in its own session (start_new_session=True), so one killpg
# reaches it and every tool it spawns (yara, foremost, log2timeline...).
# The FUSE daemons (ewfmount, vshadowmount, ntfs-3g) setsid themselves and
# are not in the group, so the mounts stay serviceable while it is stopped.
#
# The backend runs in a different container (separate PID namespace), so it
# cannot signal Elrond itself. It broadcasts the rowanholt_signal_job control
# command to the worker that owns the job; that runs in the worker's main
# process, which shares Elrond's PID namespace.

_JOB_SIGNALS = {
    "pause": signal.SIGSTOP,
    "resume": signal.SIGCONT,
    "kill": signal.SIGKILL,
}


def _job_process_key(job_id: str) -> str:
    """Redis key holding the worker hostname and Elrond PGID for a job."""
    return f"rowanholt:job_process:{job_id}"


def _job_events_key(job_id: str) -> str:
    """Redis list of pause/resume events waiting for the task to record."""
    return f"rowanholt:job_events:{job_id}"


def _register_job_process(job_id: str, hostname: str, pgid: int) -> None:
    get_redis_client().set(_job_process_key(job_id), json.dumps({"hostname": hostname, "pgid": pgid}))


def _clear_job_process(job_id: str) -> None:
    get_redis_client().delete(_job_process_key(job_id), _job_events_key(job_id))


def _get_job_process(job_id: str) -> dict | None:
    raw = get_redis_client().get(_job_process_key(job_id))
    return json.loads(raw) if raw else None


def _drain_job_events(job) -> None:
    """
    Apply pause/resume events recorded by the control command to the task's
    in-memory job, so its next save does not overwrite PAUSED with RUNNING.
    Events carry their own timestamps, so the log shows when the pause
    actually happened even if Elrond was silent afterwards.
    """
    redis_client = get_redis_client()
    while True:
        raw = redis_client.lpop(_job_events_key(job.id))
        if raw is None:
            return
        event = json.loads(raw)
        if event["action"] == "pause":
            job.status = JobStatus.PAUSED
            job.log.append(f"[{event['at']}] -> Job paused")
        elif event["action"] == "resume":
            job.status = JobStatus.RUNNING
            job.log.append(f"[{event['at']}] -> Job resumed")


@control_command(
    args=[("job_id", str), ("action", str)],
    signature="<job_id> <pause|resume|kill>",
)
def rowanholt_signal_job(state, job_id: str, action: str) -> dict:
    """Celery remote control command: signal a job's Elrond process group."""
    if action not in _JOB_SIGNALS:
        return {"ok": False, "error": f"unknown action '{action}'"}

    process = _get_job_process(job_id)
    if not process:
        return {"ok": False, "error": "job has no running Elrond process"}
    # Guard against PID reuse across containers: a PGID is only meaningful
    # in the namespace of the worker that started it.
    if process["hostname"] != state.consumer.hostname:
        return {"ok": False, "error": f"job belongs to {process['hostname']}"}

    pgid = process["pgid"]
    try:
        os.killpg(pgid, _JOB_SIGNALS[action])
    except ProcessLookupError:
        _clear_job_process(job_id)
        return {"ok": False, "error": "Elrond process group no longer exists"}
    except PermissionError as e:
        return {"ok": False, "error": f"cannot signal process group {pgid}: {e}"}

    if action in ("pause", "resume"):
        get_redis_client().rpush(
            _job_events_key(job_id),
            json.dumps({"action": action, "at": datetime.now().isoformat().replace("T", " ")}),
        )
    logger.info(f"Job {job_id}: sent {_JOB_SIGNALS[action].name} to process group {pgid}")
    return {"ok": True, "pgid": pgid}


def send_job_signal(job_id: str, action: str, timeout: float = 5.0) -> dict:
    """
    Ask the worker that owns a job to pause, resume or kill its Elrond
    process group. Called from the backend.

    Returns:
        {"ok": True, "pgid": ...} or {"ok": False, "error": ...}
    """
    process = _get_job_process(job_id)
    if not process:
        return {"ok": False, "error": "job has no running Elrond process"}

    replies = celery_app.control.broadcast(
        "rowanholt_signal_job",
        arguments={"job_id": job_id, "action": action},
        destination=[process["hostname"]],
        reply=True,
        limit=1,
        timeout=timeout,
    )
    for reply in replies or []:
        for _, result in reply.items():
            return result
    return {"ok": False, "error": f"worker {process['hostname']} did not reply within {timeout}s"}

def _request_sudo_confirmation(job, target_path: str, reason: str):
    """Set job to awaiting confirmation status for sudo directory removal."""
    from models.job import PendingAction

    job.status = JobStatus.AWAITING_CONFIRMATION
    job.pending_action = PendingAction(
        action_type="sudo_remove_directory",
        target_path=target_path,
        message=f"Failed to remove directory: {reason}. Use sudo to force removal?"
    )
    job_storage.save_job(job)
    logger.info(f"Job {job.id} awaiting sudo confirmation for: {target_path}")


def confirm_sudo_action(job_id: str) -> bool:
    """
    Execute the pending sudo action for a job.
    Returns True if successful, False otherwise.
    """
    job = job_storage.get_job(job_id)
    if not job or job.status != JobStatus.AWAITING_CONFIRMATION:
        return False

    if not job.pending_action or job.pending_action.action_type != "sudo_remove_directory":
        return False

    target_path = job.pending_action.target_path

    job.log.append(
        f"[{datetime.now().isoformat().replace('T', ' ')}] -> User confirmed sudo removal of: {target_path}"
    )
    job_storage.save_job(job)

    try:
        # Use rm -rf (container runs as root, no sudo needed)
        result = subprocess.run(
            ["rm", "-rf", target_path],
            capture_output=True,
            timeout=300  # 5 minute timeout
        )

        if result.returncode == 0:
            job.log.append(
                f"[{datetime.now().isoformat().replace('T', ' ')}] -> Successfully removed directory"
            )
            job.status = JobStatus.PENDING  # Reset to pending so it can be restarted
            job.pending_action = None
            job_storage.save_job(job)
            return True
        else:
            stderr = result.stderr.decode() if result.stderr else "Unknown error"
            job.log.append(
                f"[{datetime.now().isoformat().replace('T', ' ')}] -> Removal failed: {stderr}"
            )
            job.status = JobStatus.FAILED
            job.error = f"Directory removal failed: {stderr}"
            job.pending_action = None
            job.completed_at = datetime.now()
            job_storage.save_job(job)
            return False

    except subprocess.TimeoutExpired:
        job.log.append(
            f"[{datetime.now().isoformat().replace('T', ' ')}] -> Directory removal timed out"
        )
        job.status = JobStatus.FAILED
        job.error = "Directory removal timed out after 5 minutes"
        job.pending_action = None
        job.completed_at = datetime.now()
        job_storage.save_job(job)
        return False
    except Exception as e:
        job.log.append(
            f"[{datetime.now().isoformat().replace('T', ' ')}] -> Directory removal error: {e}"
        )
        job.status = JobStatus.FAILED
        job.error = f"Directory removal error: {e}"
        job.pending_action = None
        job.completed_at = datetime.now()
        job_storage.save_job(job)
        return False


def cancel_sudo_action(job_id: str) -> bool:
    """Cancel the pending sudo action and fail the job."""
    job = job_storage.get_job(job_id)
    if not job or job.status != JobStatus.AWAITING_CONFIRMATION:
        return False

    job.log.append(
        f"[{datetime.now().isoformat().replace('T', ' ')}] -> User cancelled sudo removal"
    )
    job.status = JobStatus.FAILED
    job.error = "Directory removal cancelled by user"
    job.pending_action = None
    job.completed_at = datetime.now()
    job_storage.save_job(job)
    return True


def translate_path_for_worker(path_str: str) -> str:
    """
    Translate paths from backend container perspective to celery-worker perspective.

    Both containers mount:
      - elrond_uploads volume -> /tmp/elrond/uploads (SAME in both containers)
      - /tmp/rowanholt (host) -> /tmp/elrond/output (worker) or /host/tmp/rowanholt (backend)

    Args:
        path_str: Path from backend perspective

    Returns:
        Path translated for celery worker
    """
    path_str = str(path_str)

    # Paths in /tmp/elrond/uploads are the SAME in both containers (shared volume)
    if path_str.startswith("/tmp/elrond/uploads/"):
        return path_str

    # Backend uses /host/tmp/rowanholt for output, worker uses /tmp/elrond/output
    if path_str.startswith("/host/tmp/rowanholt"):
        return path_str.replace("/host/tmp/rowanholt", "/tmp/elrond/output")

    # Backend uses /tmp/elrond/output, worker uses same
    if path_str.startswith("/tmp/elrond/output"):
        return path_str

    # Default: return as-is
    return path_str


def _resolve_destination(job) -> Path:
    """
    Resolve the destination directory using the same logic as job creation.
    Uses case number as the output directory name instead of image name.
    """
    if job.destination_path:
        return Path(job.destination_path)

    if job.source_paths:
        first_source = Path(job.source_paths[0])
        if first_source.is_file() or getattr(job.options, "gandalf", False):
            # Use case number instead of image name for output directory; beside a Gandalf
            # acquisitions folder, not in it (--Gandalf reads every folder there as a host)
            return first_source.parent / job.case_number
        return first_source / job.case_number

    return Path(settings.output_dir) / job.case_number


# The job row is rewritten on every save, log included, so keep only the tail of
# the log there and spool the full log to the job's output directory. Saving the
# whole log every 10 lines grew win_full's row past 7 MB and the jobs table to
# 126 GB, until Postgres stalled and the job failed.
JOB_LOG_KEEP = 5000
JOB_SAVE_INTERVAL = 10.0  # seconds between progress saves
IMAGE_LOCK_TTL = 3600  # refreshed while the job runs, so long jobs keep their locks


class JobLogSpool:
    """Writes every job.log line to a file and trims job.log to its tail."""

    def __init__(self, path):
        self.path = path
        self.index = 0
        self.dropped = 0
        try:
            self.file = open(path, "a", buffering=1)
        except OSError as e:
            logger.warning(f"Can't open job log file {path}: {e}")
            self.file = None

    def sync(self, job):
        if self.file:
            try:
                self.file.write("".join(f"{line}\n" for line in job.log[self.index:]))
            except OSError as e:
                logger.warning(f"Job log write failed: {e}")
        if len(job.log) > JOB_LOG_KEEP + 1:
            body = job.log[1:] if self.dropped else job.log
            self.dropped += len(body) - JOB_LOG_KEEP
            marker = f"[... {self.dropped:,} earlier lines are in {self.path}]"
            job.log = [marker] + body[-JOB_LOG_KEEP:]
        self.index = len(job.log)

    def close(self):
        if self.file:
            self.file.close()


def _safe_save(job):
    """Save without letting a transient database error kill a running job."""
    try:
        job_storage.save_job(job)
        return True
    except Exception as e:
        logger.warning(f"Job {job.id}: progress save failed, will retry: {e}")
        return False


def _start_lock_heartbeat(lock_keys, interval=300):
    """
    Keep image locks alive on a timer. Progress saves can't do it alone: a
    paused job (or a silent stage) writes no output, and the locks would
    expire under it. Returns the event that stops the heartbeat.
    """
    stop = threading.Event()

    def beat():
        while not stop.wait(interval):
            _refresh_image_locks(lock_keys)

    threading.Thread(target=beat, name="image-lock-heartbeat", daemon=True).start()
    return stop


def _refresh_image_locks(lock_keys):
    try:
        client = get_redis_client()
        for key in lock_keys:
            client.expire(key, IMAGE_LOCK_TTL)
    except Exception as e:
        logger.warning(f"Could not refresh image locks: {e}")


def _stop_process_group(process, grace=30):
    """SIGTERM Elrond's process group, then SIGKILL whatever is left."""
    if process is None or process.poll() is not None:
        return
    try:
        pgid = os.getpgid(process.pid)
        os.killpg(pgid, signal.SIGTERM)
        # A paused (SIGSTOPped) job only acts on SIGTERM once it is continued.
        os.killpg(pgid, signal.SIGCONT)
        try:
            process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            os.killpg(pgid, signal.SIGKILL)
            process.wait(timeout=10)
    except ProcessLookupError:
        pass
    except Exception as e:
        logger.warning(f"Could not stop Elrond (pid {process.pid}): {e}")
        process.kill()


SYMBOLS_INCOMING = Path("/opt/rowanholt/symbols/incoming")


@celery_app.task(bind=True)
def add_symbol_table(self, args: list, folder: str) -> dict:
    """An administrator's upload from Aragorn made a symbol table: `rowanholt symbols add` with
    the uploaded files (symbol_routes.py), which are removed afterwards."""
    work = Path(folder).resolve()
    if work.parent != SYMBOLS_INCOMING:
        return {"ok": False, "output": f"Not an upload folder: {folder}"}
    env = {**os.environ, "PYTHONPATH": "/opt/elrond-src"}
    try:
        proc = subprocess.run([sys.executable, "-m", "rowanholt.memory.symbols", "add", *args],
                              capture_output=True, text=True, env=env, timeout=3600)
        return {"ok": proc.returncode == 0, "output": (proc.stdout + proc.stderr).strip()[-4000:]}
    except subprocess.TimeoutExpired:
        return {"ok": False, "output": "Building the table took over an hour"}
    finally:
        shutil.rmtree(work, ignore_errors=True)


@celery_app.task(bind=True)
def start_analysis(self, job_id: str):
    """
    Start Elrond analysis task in dockerized environment.

    Runs the full forensics engine directly in the container.
    Uses Redis-based locking to ensure only one job can process a given image at a time.

    Args:
        job_id: Job ID
    """
    job = job_storage.get_job(job_id)

    if not job:
        logger.error(f"Job {job_id} not found")
        return

    # Track acquired locks for cleanup
    acquired_lock_keys = []
    process = None
    spool = None
    lock_heartbeat = None

    try:
        # Acquire locks on all source images before starting
        # This ensures jobs using the same image wait for each other
        if job.source_paths:
            job.log.append(f"[{datetime.now().isoformat().replace('T', ' ')}] -> Checking image availability...")
            job_storage.save_job(job)

            # Build list of lock keys we need to acquire
            for image_path in job.source_paths:
                acquired_lock_keys.append(_get_image_lock_key(image_path))

            # Try to acquire all locks (will wait if images are in use)
            if not acquire_image_locks(job_id, job.source_paths, timeout=7200, retry_interval=10):
                # Failed to acquire locks (job was cancelled while waiting)
                job.status = JobStatus.CANCELLED
                job.log.append(f"[{datetime.now().isoformat().replace('T', ' ')}] -> Job cancelled while waiting for images")
                job.completed_at = datetime.now()
                job_storage.save_job(job)
                return

            lock_heartbeat = _start_lock_heartbeat(acquired_lock_keys)

        # Update job status
        job.status = JobStatus.RUNNING
        job.started_at = datetime.now()
        job.log.append(f"[{datetime.now().isoformat().replace('T', ' ')}] -> Starting rowanholt...")
        job_storage.save_job(job)

        # Build elrond command
        cmd = build_elrond_command(job)

        logger.info(f"Running command: {' '.join(cmd)}")

        # Set destination directory - must translate to worker perspective
        dest_dir_backend = _resolve_destination(job)
        dest_dir_str = translate_path_for_worker(str(dest_dir_backend))
        dest_dir = Path(dest_dir_str)

        # Check if force_overwrite is set and directory exists
        if getattr(job.options, "force_overwrite", False):
            if dest_dir.exists():
                import shutil

                logger.info(f"Force overwrite enabled, removing existing directory: {dest_dir_str}")

                job.log.append(
                    f"[{datetime.now().isoformat().replace('T', ' ')}] -> Removing existing directory: {dest_dir_str} - stand by..."
                )
                job_storage.save_job(job)

                # Use rm -rf with progress monitoring for large directories
                start_time = datetime.now()
                try:
                    # Start rm -rf in background
                    rm_process = subprocess.Popen(
                        ["rm", "-rf", dest_dir_str],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )

                    # Monitor with periodic updates every 10 seconds
                    last_update = datetime.now()
                    while rm_process.poll() is None:
                        time.sleep(1)
                        elapsed = (datetime.now() - start_time).total_seconds()

                        # Update every 10 seconds
                        if (datetime.now() - last_update).total_seconds() >= 10:
                            job.log.append(
                                f"[{datetime.now().isoformat().replace('T', ' ')}] -> Still removing directory... ({int(elapsed)}s elapsed)"
                            )
                            job_storage.save_job(job)
                            last_update = datetime.now()

                        # Timeout after 5 minutes
                        if elapsed > 300:
                            rm_process.kill()
                            raise subprocess.TimeoutExpired(
                                cmd=["rm", "-rf", dest_dir_str], timeout=300
                            )

                    # Check exit code
                    if rm_process.returncode != 0:
                        raise subprocess.CalledProcessError(
                            rm_process.returncode, ["rm", "-rf", dest_dir_str]
                        )

                    elapsed = (datetime.now() - start_time).total_seconds()
                    logger.info(f"Successfully removed directory: {dest_dir_str} in {elapsed:.1f}s")
                    job.log.append(
                        f"[{datetime.now().isoformat().replace('T', ' ')}] -> Successfully removed directory in {elapsed:.1f}s"
                    )
                except subprocess.TimeoutExpired:
                    logger.error(f"Timeout removing directory: {dest_dir_str}")
                    job.log.append(
                        f"[{datetime.now().isoformat().replace('T', ' ')}] -> Timeout removing directory - requesting sudo confirmation"
                    )
                    _request_sudo_confirmation(job, dest_dir_str, "Timeout after 5 minutes")
                    return
                except subprocess.CalledProcessError as e:
                    logger.error(f"Error removing directory (exit code {e.returncode})")
                    job.log.append(f"[{datetime.now().isoformat().replace('T', ' ')}] -> Error removing directory - requesting sudo confirmation")
                    _request_sudo_confirmation(job, dest_dir_str, f"Permission denied (exit code {e.returncode})")
                    return
                except Exception as e:
                    logger.error(f"Error removing directory: {e}")
                    job.log.append(
                        f"[{datetime.now().isoformat().replace('T', ' ')}] -> Error removing directory - requesting sudo confirmation"
                    )
                    _request_sudo_confirmation(job, dest_dir_str, str(e))
                    return
                job_storage.save_job(job)

        # Create the output directory if it doesn't exist
        dest_dir.mkdir(parents=True, exist_ok=True)

        # Run elrond directly in container
        # Since we're already in the forensics container, we can run it directly
        elrond_path = os.environ.get("ELROND_HOME", "/opt/elrond")
        elrond_script = Path(elrond_path) / "elrond.py"

        if not elrond_script.exists():
            # Elrond not installed - create placeholder error
            raise FileNotFoundError(
                f"Elrond script not found at {elrond_script}. "
                f"Please install Elrond or set ELROND_HOME environment variable to point to Elrond installation."
            )

        # Prepend python3 and elrond script path to command
        cmd.insert(0, str(elrond_script))
        cmd.insert(0, "python3")

        # An encrypted phone backup's password: taken from Redis (and removed there), written to
        # Elrond's standard input below, never on its command line or in the job
        backup_password = backup_secrets.take(job_id) if getattr(job.options, "mobile", False) else None
        if backup_password:
            cmd.append("--backupPasswordStdin")

        logger.info(f"Executing: {' '.join(cmd)}")

        # Run elrond with proper environment
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{elrond_path}:{env.get('PYTHONPATH', '')}"
        env["ELROND_HOME"] = elrond_path
        env["ELROND_OUTPUT"] = str(settings.output_dir)
        env["ELROND_NONINTERACTIVE"] = "1"  # Signal non-interactive mode
        env["PYTHONUNBUFFERED"] = "1"  # Disable Python output buffering for real-time logs

        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if backup_password else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1,  # Line buffering to get output in real-time
            cwd=dest_dir_str,
            env=env,
            # Own process group, so pause/resume/cancel can signal Elrond and its
            # tools together without touching the Celery worker, and a failed task
            # can stop them.
            start_new_session=True,
        )
        if backup_password:
            process.stdin.write(backup_password + "\n")
            process.stdin.close()
            backup_password = None
        _register_job_process(job_id, self.request.hostname, process.pid)
        spool = JobLogSpool(os.path.join(dest_dir_str, "rowanholt_job.log"))
        last_save = time.monotonic()

        # Monitor progress
        progress_count = 0
        last_log_message = None  # Track last message for deduplication
        seen_phases = set()  # Track seen phase transitions to prevent duplicates
        seen_filepaths = set()  # Track seen filepaths to prevent duplicates

        # Phase-based progress tracking
        # Rowanholt processes ALL images through each phase before moving to the next:
        # 1. Identification (mount all): 0-15%
        # 2. Collection (all images): 15-35%
        # 3. Processing (all artefacts): 35-70%
        # 4. Analysis: 70-95%
        total_images = max(1, len(job.source_paths))
        current_phase = "identification"  # Track current phase
        images_collected = 0  # Track how many images have completed collection
        images_processed = 0  # Track how many images have completed processing

        # Counter for repeated patterns (like IE index.dat)
        ie_indexdat_count = 0
        ie_indexdat_logged = False

        # Verbose logging - write all output to verbose.log when debug is enabled
        debug_enabled = getattr(job.options, "debug", False)
        verbose_log_file = None
        if debug_enabled:
            verbose_log_path = os.path.join(dest_dir_str, "verbose.log")
            try:
                verbose_log_file = open(verbose_log_path, "w")
                logger.info(f"Verbose logging enabled, writing to: {verbose_log_path}")
            except Exception as e:
                logger.warning(f"Failed to open verbose log file: {e}")

        # Track phase completion for validation
        phases_completed = {
            "collection": False,
            "processing": False,
            "analysis": False,
        }
        analysis_phase_started = False

        for line in iter(process.stdout.readline, ""):
            _drain_job_events(job)
            line = line.strip()
            if line:
                # Strip ANSI color codes
                line = re.sub(r"\x1b\[[0-9;]*m", "", line)

                # Write ALL output to verbose.log when debug is enabled (before any filtering)
                if verbose_log_file:
                    try:
                        verbose_log_file.write(line + "\n")
                        verbose_log_file.flush()
                    except Exception:
                        pass

                # Exclude verbose messages (MITRE enrichment, verbose command output) unless debug is enabled
                if not debug_enabled:
                    excluded_keywords = ["mitre", "extracting mitre", "mitre enrichment"]
                    excluded_patterns = [
                        r"-> Command:",  # Exclude verbose command line output
                    ]
                    has_excluded = any(kw in line.lower() for kw in excluded_keywords)
                    # Check excluded patterns
                    if not has_excluded:
                        for pattern in excluded_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                has_excluded = True
                                break
                    if has_excluded:
                        continue

                # Special handling for IE index.dat messages - aggregate into count
                if re.search(r"processing (small|large) IE index\.dat", line, re.IGNORECASE):
                    ie_indexdat_count += 1
                    if not ie_indexdat_logged:
                        # Log the first one with a placeholder for count
                        ie_indexdat_logged = True
                        line = f"[{datetime.now().isoformat().replace('T', ' ')}] -> processing IE index.dat files..."
                        job.log.append(line)
                        job_storage.save_job(job)
                    continue  # Skip individual IE index.dat entries

                # Only include lines with ' -> ' (audit log format) OR phase messages OR errors/tracebacks
                # When debug is enabled, show ALL lines
                if not debug_enabled:
                    has_arrow = " -> " in line
                    is_phase_line = ("commencing" in line.lower() and "phase" in line.lower()) or \
                                    ("completed" in line.lower() and "phase" in line.lower())
                    # Also show Python tracebacks, errors, and DEBUG output
                    is_error_line = line.startswith("Traceback") or line.startswith("  File ") or \
                                   "Error:" in line or "Exception:" in line or \
                                   "DEBUG" in line or line.startswith("    ")  # Indented traceback lines
                    if not has_arrow and not is_phase_line and not is_error_line:
                        continue

                # Skip lines that are just separator dashes (e.g., "----------------------------------------")
                if re.match(r'^\[.*\]\s*-+\s*$', line) or re.match(r'^-+$', line.strip()):
                    continue

                # Skip redundant "X phase complete." messages (we show "Completed X Phase" instead)
                if re.search(r'(collect|process|analysis)\s+phase\s+complete\.?$', line, re.IGNORECASE):
                    continue

                # Clean up duplicate slashes in file paths (e.g., //$ -> /$)
                line = re.sub(r"/+", "/", line)

                # Fix timestamp format: convert "-> YYYY-MM-DD HH:MM:SS.ffffff -> message" to "[YYYY-MM-DD HH:MM:SS.ffffff] -> message"
                timestamp_pattern = (
                    r"^->\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+->\s+(.+)$"
                )
                timestamp_match = re.match(timestamp_pattern, line)
                if timestamp_match:
                    timestamp = timestamp_match.group(1)
                    message = timestamp_match.group(2)
                    line = f"[{timestamp}] -> {message}"

                # Format phase headers (Commencing/Completed) with visual separators BEFORE deduplication
                original_line = line
                is_phase_message = False
                phase_key = None  # Used for deduplicating phase messages
                if "commencing" in line.lower() and "phase" in line.lower():
                    # Extract the phase name (e.g., "Collection", "Processing", "Analysis")
                    phase_match = re.search(r"commencing\s+(.*?)\s*phase", line, re.IGNORECASE)
                    if phase_match:
                        phase_name = phase_match.group(1).strip().title()
                        # Simplify "Att&Ck® Navigator" to just "Navigator"
                        phase_name = re.sub(r"Att&Ck®\s*", "", phase_name, flags=re.IGNORECASE)
                        phase_key = f"commencing_{phase_name.lower()}"
                        line = f"========== Commencing {phase_name} Phase =========="
                        is_phase_message = True
                        # Track analysis phase start
                        if "analysis" in phase_name.lower():
                            analysis_phase_started = True
                elif "completed" in line.lower() and "phase" in line.lower():
                    # Extract just the phase name, ignoring "for 'image'" suffixes
                    # Match: "Completed X Phase" or "Completed X Phase for 'image'"
                    phase_match = re.search(r"completed\s+(.*?)\s*phase", line, re.IGNORECASE)
                    if phase_match:
                        phase_name = phase_match.group(1).strip().title()
                        # Simplify "Att&Ck® Navigator" to just "Navigator"
                        phase_name = re.sub(r"Att&Ck®\s*", "", phase_name, flags=re.IGNORECASE)

                        # Check if this is a per-image completion ("for 'image'") or overall completion
                        # Per-image completions should NOT be formatted as major phase transitions
                        is_per_image = " for " in line.lower() or "for '" in line.lower()

                        if is_per_image:
                            # Per-image completion - don't format as major phase transition
                            # Just skip these entirely since they're redundant with overall phase completion
                            continue
                        else:
                            # Overall phase completion - format as major separator
                            phase_key = f"completed_{phase_name.lower()}"
                            line = f"========== Completed {phase_name} Phase =========="
                            is_phase_message = True
                            # Track phase completions for validation
                            phase_name_lower = phase_name.lower()
                            if "collection" in phase_name_lower:
                                phases_completed["collection"] = True
                            elif "processing" in phase_name_lower:
                                phases_completed["processing"] = True
                            elif "analysis" in phase_name_lower:
                                phases_completed["analysis"] = True

                # Deduplicate phase messages: only show each phase transition once
                if is_phase_message and phase_key:
                    if phase_key in seen_phases:
                        continue  # Skip duplicate phase message
                    seen_phases.add(phase_key)

                # Deduplicate: Skip if this exact action+filepath was already logged
                # Normalize message for comparison (remove extra quotes and whitespace)
                normalized_current = re.sub(r"'{2,}", "'", original_line).strip()

                # Extract action and filepath from the message for deduplication
                # Different actions (collecting, processing, analysing) on the same file should all be shown
                action = "unknown"
                action_match = re.search(r"->\s*(collecting|processing|analysing|scanning|tagging|extracting)", normalized_current, re.IGNORECASE)
                if action_match:
                    action = action_match.group(1).lower()

                # Matches patterns like: '/path/to/file.ext' or "/path/to/file.ext" or 'filename'
                filepath_match = re.search(r"['\"]([^'\"]+)['\"]", normalized_current)
                # Only deduplicate if BOTH action and filepath are found
                # Messages without a clear filepath should always be shown
                if filepath_match and action != "unknown":
                    filepath = filepath_match.group(1).lower()
                    dedup_key = f"{action}:{filepath}"
                    if dedup_key in seen_filepaths:
                        continue  # Skip duplicate action+filepath message
                    seen_filepaths.add(dedup_key)

                last_log_message = original_line

                # Fix double single quotes (e.g., ''image_name'' -> 'image_name')
                line = re.sub(r"'{2,}", "'", line)

                # Add IE index.dat summary BEFORE the "Completed Processing Phase" message
                # Check original_line to detect phase completion, add summary before appending the phase line
                if "completed processing phase" in original_line.lower() and " for " not in original_line.lower():
                    if ie_indexdat_count > 0:
                        job.log.append(
                            f"[{datetime.now().isoformat().replace('T', ' ')}] -> processed {ie_indexdat_count} IE index.dat files"
                        )

                # Update log - only add timestamp if line doesn't already have one
                # Check if line starts with a timestamp (YYYY-MM-DD format or contains ' -> ')
                if re.match(r"^\d{4}-\d{2}-\d{2}", line) or " -> " in line:
                    # Line already has timestamp, don't add another
                    job.log.append(line)
                else:
                    # No timestamp, add one
                    log_entry = f"[{datetime.now().isoformat().replace('T', ' ')}] {line}"
                    job.log.append(log_entry)

                # Update progress based on phase transitions (more accurate than counting)
                progress_count += 1
                line_lower = line.lower()
                # Use original_line for phase detection since 'line' may have been reformatted
                original_lower = original_line.lower()

                # Phase-based progress calculation
                # Rowanholt phases: Identification (0-15%) -> Collection (15-35%) -> Processing (35-70%) -> Analysis (70-95%)
                new_progress = job.progress  # Start with current progress

                # Detect phase transitions
                # Note: Rowanholt outputs "Completed X Phase for 'image'" for EACH image
                # We only want to advance major progress on OVERALL phase completion (no "for" suffix)
                # Use original_lower since the reformatting strips " for 'image'" from messages
                if "commencing identification phase" in original_lower and " for " not in original_lower:
                    current_phase = "identification"
                    new_progress = max(new_progress, 2)
                elif "commencing collection phase" in original_lower and " for " not in original_lower:
                    current_phase = "collection"
                    new_progress = max(new_progress, 15)
                elif "commencing processing phase" in original_lower and " for " not in original_lower:
                    current_phase = "processing"
                    new_progress = max(new_progress, 35)
                elif "commencing analysis phase" in original_lower and " for " not in original_lower:
                    current_phase = "analysis"
                    new_progress = max(new_progress, 70)
                # Only trigger phase completion for OVERALL completion (no "for 'image'" suffix)
                elif "completed identification phase" in original_lower and " for " not in original_lower:
                    new_progress = max(new_progress, 15)
                elif "completed collection phase" in original_lower and " for " not in original_lower:
                    new_progress = max(new_progress, 35)
                elif "completed processing phase" in original_lower and " for " not in original_lower:
                    new_progress = max(new_progress, 70)
                elif "completed analysis phase" in original_lower and " for " not in original_lower:
                    new_progress = max(new_progress, 95)
                elif any(keyword in original_lower for keyword in ["splunk phase", "elastic phase", "navigator phase"]):
                    new_progress = max(new_progress, 92)
                elif "rowanholt completed" in original_lower or "analysis finished" in original_lower:
                    new_progress = 95

                # Sub-progress within each phase
                # Scale progress increments by number of images (more images = more work = slower increment per line)
                scale_factor = max(1, total_images)

                # Separate if-chain for sub-progress within phases
                if current_phase == "identification":
                    # Identification: 0-15%
                    if "scanning for forensic images" in line_lower:
                        new_progress = max(new_progress, 3)
                    elif "found forensic image" in line_lower:
                        new_progress = max(new_progress, 5)
                    elif "mounting" in line_lower:
                        # Scale mounting progress by number of images
                        new_progress = max(new_progress, 7 + min(progress_count // (5 * scale_factor), 5))
                    elif "identified platform" in line_lower:
                        new_progress = max(new_progress, 12 + min(progress_count // (10 * scale_factor), 3))
                    elif "not mounted" in line_lower:
                        pass  # Don't advance progress for failed mounts

                elif current_phase == "collection":
                    # Collection: 15-35% (20% range)
                    # Track per-image collection completion
                    if "collection completed for" in line_lower:
                        images_collected += 1
                        # Each image completion advances within collection phase
                        per_image_progress = min(18, 18 * images_collected // scale_factor)
                        new_progress = max(new_progress, 15 + per_image_progress)
                    elif "collecting artefacts for" in line_lower:
                        # Scale by number of images
                        new_progress = max(new_progress, 16 + min(progress_count // (50 * scale_factor), 15))
                    elif any(kw in line_lower for kw in ["collecting", "copying", "configuration file", "crontab", "bash", "plist", "keyring"]):
                        new_progress = max(new_progress, 17 + min(progress_count // (30 * scale_factor), 16))

                elif current_phase == "processing":
                    # Processing: 35-70% (35% range)
                    if "processing completed for" in line_lower:
                        images_processed += 1
                        per_image_progress = min(30, 30 * images_processed // scale_factor)
                        new_progress = max(new_progress, 35 + per_image_progress)
                    elif any(kw in line_lower for kw in ["processing", "parsing", "extracting"]):
                        new_progress = max(new_progress, 36 + min(progress_count // (20 * scale_factor), 30))

                elif current_phase == "analysis":
                    # Analysis: 70-95% (25% range)
                    if any(kw in line_lower for kw in ["analyzing", "scanning", "tagging"]):
                        new_progress = max(new_progress, 71 + min(progress_count // (15 * scale_factor), 20))

                # Only update if progress increases (never go backwards)
                job.progress = max(job.progress, min(new_progress, 95))

                # Save on a timer, not per N lines: chatty stages (IOC extraction)
                # emit thousands of lines a minute.
                if time.monotonic() - last_save >= JOB_SAVE_INTERVAL:
                    spool.sync(job)
                    _safe_save(job)
                    last_save = time.monotonic()

                logger.info(line)

        # Wait for completion
        return_code = process.wait()
        _drain_job_events(job)

        # Close verbose log file if it was opened
        if verbose_log_file:
            try:
                verbose_log_file.close()
                logger.info("Verbose log file closed")
            except Exception as e:
                logger.warning(f"Failed to close verbose log file: {e}")

        # Validate that required phases completed
        # If analysis was requested (started), it must also complete
        analysis_requested = getattr(job.options, "analysis", False)
        phases_ok = True
        incomplete_reason = None

        # Check if analysis was started but not completed
        if analysis_phase_started and not phases_completed["analysis"]:
            phases_ok = False
            incomplete_reason = "Analysis phase started but did not complete"
        # If analysis was explicitly requested but never even started
        elif analysis_requested and not analysis_phase_started:
            phases_ok = False
            incomplete_reason = "Analysis was requested but phase never started"

        if return_code == 0 and phases_ok:
            # Success - process completed AND all phases finished
            job.status = JobStatus.COMPLETED
            job.progress = 100

            job.log.append(
                f"[{datetime.now().isoformat().replace('T', ' ')}] -> rowanholt completed successfully"
            )
        elif return_code == 0 and not phases_ok:
            # Process exited cleanly but required phases didn't complete - this is a FAILURE
            job.status = JobStatus.FAILED
            job.error = incomplete_reason
            job.log.append(
                f"[{datetime.now().isoformat().replace('T', ' ')}] -> Analysis incomplete: {incomplete_reason}"
            )
            # Log which phases were seen
            completed_phases = [k for k, v in phases_completed.items() if v]
            if completed_phases:
                job.log.append(
                    f"[{datetime.now().isoformat().replace('T', ' ')}] -> Completed phases: {', '.join(completed_phases)}"
                )
            else:
                job.log.append(
                    f"[{datetime.now().isoformat().replace('T', ' ')}] -> No phases completed successfully"
                )

        # Collect results information for success/incomplete cases
        if return_code == 0:
            result_info = {
                "output_directory": dest_dir_str,
                "return_code": return_code,
                "analysis_duration": str(datetime.now() - job.started_at),
                "phases_completed": phases_completed,
            }

            # Check for generated files
            output_path = dest_dir
            if output_path.exists():
                try:
                    result_info["output_files"], result_info["output_size"] = output_stats(output_path)
                except (FileNotFoundError, PermissionError, OSError) as e:
                    # Handle cases where paths don't exist or are inaccessible
                    logger.warning(f"Error calculating output stats: {e}")
                    result_info["output_files"] = 0
                    result_info["output_size"] = 0

            job.result = result_info

            # Save template if requested
            if getattr(job.options, "save_template", False):
                try:
                    template_data = {}
                    # Extract all processing options (exclude mode selections and save_template itself)
                    mode_keys = {'brisk', 'exhaustive', 'custom', 'template', 'save_template', 'collect', 'process'}
                    for key, value in vars(job.options).items():
                        if not key.startswith('_') and key not in mode_keys and isinstance(value, bool):
                            template_data[key] = value

                    # Generate filename with timestamp
                    timestamp = datetime.now().strftime("%Y-%m-%d-%H:%M")
                    template_filename = f"{timestamp}_Template.json"
                    template_path = dest_dir / template_filename

                    with open(template_path, "w") as f:
                        json.dump(template_data, f, indent=2)

                    job.log.append(
                        f"[{datetime.now().isoformat().replace('T', ' ')}] -> Template saved: {template_filename}"
                    )
                except Exception as e:
                    logger.warning(f"Failed to save template: {e}")
                    job.log.append(
                        f"[{datetime.now().isoformat().replace('T', ' ')}] -> Warning: Failed to save template: {e}"
                    )

        if return_code != 0:
            # Failed
            job.status = JobStatus.FAILED
            job.error = f"Process exited with code {return_code}"
            job.log.append(f"[{datetime.now().isoformat().replace('T', ' ')}] -> Analysis failed: {job.error}")

    except Exception as e:
        logger.exception(f"Error running analysis for job {job_id}")
        job.status = JobStatus.FAILED
        job.error = str(e)
        job.log.append(f"[{datetime.now().isoformat().replace('T', ' ')}] -> Error: {str(e)}")
        # Nothing reads Elrond's stdout any more; left running it blocks on the
        # full pipe forever with the image mounted.
        if process is not None and process.poll() is None:
            job.log.append(f"[{datetime.now().isoformat().replace('T', ' ')}] -> Stopping Elrond (pid {process.pid}) after the error")
            _stop_process_group(process)

    finally:
        if lock_heartbeat:
            lock_heartbeat.set()
        try:
            _clear_job_process(job_id)
        except Exception as e:
            logger.warning(f"Job {job_id}: could not clear its process record: {e}")

        # Release image locks
        if acquired_lock_keys:
            release_image_locks(acquired_lock_keys)
            logger.info(f"Job {job_id}: Released {len(acquired_lock_keys)} image lock(s)")

        job.completed_at = datetime.now()
        if spool:
            spool.sync(job)
            spool.close()
        for attempt in range(5):  # the final status must land even after a DB blip
            if _safe_save(job):
                break
            time.sleep(10 * (attempt + 1))


def export_threat_intel(job_id: str) -> str:
    """The stored threat intelligence as the CSV Elrond's --threatIntel reads, in the worker's
    temp directory; '' when there's none or the package isn't in this image."""
    from threat_intel_store import ThreatIntelStore, ThreatIntelUnavailable, threat_intel
    path = os.path.join(tempfile.gettempdir(), f"rowanholt-threat-intel-{job_id}.csv")
    try:
        threat_intel()
        stored = ThreatIntelStore(job_storage.Session)
        count = stored.export_csv(path)
        expired = stored.expired_count()
    except (ThreatIntelUnavailable, OSError) as e:
        logger.warning(f"Threat intelligence not exported for job {job_id}: {e}")
        return ""
    if not count:
        logger.info(f"Threat intelligence asked for on job {job_id}, but none is stored"
                    + (f" that hasn't expired ({expired} expired)" if expired else ""))
        return ""
    logger.info(f"Exported {count} threat intelligence indicators for job {job_id}"
                + (f"; {expired} expired ones left out" if expired else ""))
    return path


def build_elrond_command(job):
    """
    Build elrond command from job options.

    Args:
        job: Job object

    Returns:
        Command list for subprocess
    """
    cmd = []

    # Case number
    cmd.append(job.case_number)

    # Source paths (translate from backend to worker perspective)
    translated_sources = [translate_path_for_worker(p) for p in job.source_paths]
    cmd.extend(translated_sources)

    # Destination path (mirror job creation logic and translate to worker perspective)
    dest_path = str(_resolve_destination(job))
    translated_dest = translate_path_for_worker(dest_path)
    cmd.append(translated_dest)

    opts = job.options

    # Primary mode flags
    # Process is ALWAYS invoked
    cmd.append("--Process")

    # Note: elrond.py already runs in auto mode by default (auto = True)
    # No --Auto flag needed

    # Collection mode (mutually exclusive)
    if getattr(opts, "network", False):
        # Network mode: PCAPs, Zeek logs and NetFlow exports (nothing to collect from)
        cmd.append("--Network")
    elif getattr(opts, "mobile", False):
        # Phones' backups and extractions: already collected, nothing to mount (core/mobile.py)
        cmd.append("--Mobile")
    elif opts.gandalf:
        # Gandalf mode: process pre-collected artifacts (no collection)
        cmd.append("--Gandalf")
    else:
        # Default/Local mode: collect from disk image
        cmd.append("--Collect")

    # Analysis options
    analysis_requested = getattr(opts, "analysis", False)
    magic_bytes_requested = analysis_requested or getattr(opts, "magic_bytes", False)

    if analysis_requested:
        cmd.append("--Analysis")
    if magic_bytes_requested:
        cmd.append("--magicBytes")
    if opts.extract_iocs:
        cmd.append("--extractIocs")
    if opts.iocs_file:
        cmd.extend(["--iocsFile", opts.iocs_file])
    if getattr(opts, "threat_intel", False):
        exported = export_threat_intel(job.id)
        if exported:
            cmd.extend(["--threatIntel", exported])
    if opts.misplaced_binaries:
        cmd.append("--misplacedBinaries")
    if opts.masquerading:
        cmd.append("--masquerading")
    if opts.clamav:
        cmd.append("--ClamAV")
    if opts.keywords_file:
        cmd.extend(["--Keywords", opts.keywords_file])
    if opts.yara_dir:
        cmd.extend(["--Yara", opts.yara_dir])

    # Collection options
    # Build file selection string for elrond (matches select.py file_selection letters)
    # A=All, H=Hidden, B=Binaries, D=Documents, R=Archives, S=Scripts,
    # L=LNK, W=Web, M=Mail, V=Virtual, U=Unallocated
    file_selection = ""

    if opts.collect_files_all:
        file_selection = "A"  # All includes everything + carving
    else:
        if opts.collect_files_hidden:
            file_selection += "H"
        if opts.collect_files_bin:
            file_selection += "B"
        if opts.collect_files_docs:
            file_selection += "D"
        if opts.collect_files_archive:
            file_selection += "R"
        if opts.collect_files_scripts:
            file_selection += "S"
        if opts.collect_files_lnk:
            file_selection += "L"
        if opts.collect_files_web:
            file_selection += "W"
        if opts.collect_files_mail:
            file_selection += "M"
        if opts.collect_files_virtual:
            file_selection += "V"
        if opts.collect_files_unalloc:
            file_selection += "U"  # Unallocated = carving only

    if file_selection:
        # Pass file selection to elrond via --collectFiles with selection string
        cmd.extend(["--collectFiles", file_selection])
    elif opts.collectFiles:
        if opts.collectFiles_filter:
            cmd.extend(["--collectFiles", opts.collectFiles_filter])
        else:
            cmd.append("--collectFiles")

    if opts.vss:
        cmd.append("--vss")
    if opts.userprofiles:
        cmd.append("--Userprofiles")

    # Processing options
    if opts.timeline:
        cmd.append("--Timeline")
    if opts.memory:
        cmd.append("--Memory")
    if opts.memory_timeline:
        cmd.append("--memorytimeline")

    # Output options
    if opts.splunk:
        cmd.append("--Splunk")
    if opts.elastic:
        cmd.append("--Elastic")
    if opts.opensearch:
        cmd.append("--OpenSearch")
    if opts.timesketch:
        cmd.append("--Timesketch")
    if opts.navigator:
        cmd.append("--Navigator")

    # Speed/Quality modes
    if opts.brisk:
        cmd.append("--Brisk")
    if opts.mordor:
        cmd.append("--Mordor")

    # Hash comparison
    if opts.nsrl:
        cmd.append("--nsrl")
    if opts.hash_collected:
        cmd.append("--hashCollected")

    # Post-processing
    if opts.delete:
        cmd.append("--Delete")
    if opts.archive:
        cmd.append("--Ziparchive")

    return cmd
