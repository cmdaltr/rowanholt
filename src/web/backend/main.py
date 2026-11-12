"""
Rowanholt Web Backend

FastAPI backend for the Rowanholt web interface; drives Elrond analysis jobs.
"""

import os
import uuid
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

try:
    from .config import settings
    from . import busy  # GET /api/busy, the homelab's question before a rebuild
    from . import job_liveness  # Whether a pending, running or paused job has a worker
    from . import siem_export  # A completed job's manual SIEM export, run in the worker
    from .auth import access
    from .auth.users import load_users
    from .auth.routes_simple import router as auth_router  # Simple file-based auth
    from .ai_routes import router as ai_router  # AI assistant routes
    from .mordor_routes import router as mordor_router  # Mordor dataset management
    from .anduril_routes import router as anduril_router  # Anduril Docker administration
    from .lab_routes import router as lab_router  # Test lab, via the host's lab agent
    from .symbol_routes import router as symbol_router  # Volatility symbol tables (Aragorn)
    from .sample_routes import router as sample_router  # Sample data as ready cases (Aragorn)
    from .threat_intel_routes import router as threat_intel_router  # Threat intelligence indicators
    from . import threat_intel_store
    from . import case_routes  # The case browser, findings, notes and assignments
    from . import smith_offline
    from . import backup_secrets  # Phone backup passwords, job form to worker
    from . import output_removal  # Where a job may write, and removing its old output
    from . import removal_routes  # Confirming or giving up a failed removal
    from . import licence  # The licence: edition, seats and features
    from .licence_routes import router as licence_router
    from . import branding_routes  # Report brands (report-branding, brand-library)
    from .webhook_routes import router as webhook_router  # Signed webhooks (automation)
    from .models.job import (
        Job,
        JobCreate,
        JobListResponse,
        JobStatus,
        JobUpdate,
        FileSystemItem,
    )
    from .storage import JobStorage
    from .tasks import start_analysis
except ImportError:
    # Fallback for standalone execution
    from config import settings
    import busy  # GET /api/busy, the homelab's question before a rebuild
    import job_liveness  # Whether a pending, running or paused job has a worker
    import siem_export  # A completed job's manual SIEM export, run in the worker
    from auth import access
    from auth.users import load_users
    from auth.routes_simple import router as auth_router  # Simple file-based auth
    from ai_routes import router as ai_router  # AI assistant routes
    from mordor_routes import router as mordor_router  # Mordor dataset management
    from anduril_routes import router as anduril_router  # Anduril Docker administration
    from lab_routes import router as lab_router  # Test lab, via the host's lab agent
    from symbol_routes import router as symbol_router  # Volatility symbol tables (Aragorn)
    from sample_routes import router as sample_router  # Sample data as ready cases (Aragorn)
    from threat_intel_routes import router as threat_intel_router  # Threat intelligence indicators
    import threat_intel_store
    import case_routes  # The case browser, findings, notes and assignments
    import smith_offline
    import backup_secrets  # Phone backup passwords, job form to worker
    import output_removal  # Where a job may write, and removing its old output
    import removal_routes  # Confirming or giving up a failed removal
    import licence  # The licence: edition, seats and features
    from licence_routes import router as licence_router
    import branding_routes  # Report brands (report-branding, brand-library)
    from webhook_routes import router as webhook_router  # Signed webhooks (automation)
    from models.job import (
        Job,
        JobCreate,
        JobListResponse,
        JobStatus,
        JobUpdate,
        FileSystemItem,
        FileSystemBrowseResponse,
    )
    from storage import JobStorage
    from tasks_docker import start_analysis

# Temporary replacement for security_utils (paths: output_removal.contained)
def sanitize_case_number(case_number: str) -> str:
    """Basic sanitization of case number."""
    return case_number.replace("/", "_").replace("\\", "_").replace("..", "")

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    debug=settings.debug,
)

# Added before access's middleware, so inside it: only requests access let through are counted,
# and nobody without an account can hold a rebuild back by sending requests
app.middleware("http")(busy.middleware)

# Who is calling; in server mode this also enforces sign-in, admin areas and job
# access for every /api route (auth/access.py). Added before CORS so CORS wraps it.
app.middleware("http")(access.middleware)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize storage
job_storage = JobStorage()
access.configure(job_storage)
threat_intel_store.configure(job_storage)
case_routes.configure(job_storage)
licence.configure(job_storage)
branding_routes.configure(job_storage)
removal_routes.configure(job_storage)
smith_offline.FINDINGS = case_routes.findings_for_case

# Jobs a rebuild would cut off: running, or paused (Elrond stopped with SIGSTOP in the worker,
# killed with it). Pending jobs are checked too but aren't busy: Celery's queue lives in Redis,
# which a rebuild leaves running (its container is unchanged, and `redis_data` holds its
# snapshots), so a queued job waits out the rebuild and runs on the new worker. The jobs table says
# which jobs claim one of these; job_liveness says whether a worker is still on each (a heartbeat
# in Redis, or for a pending job the task in the queue), and fails the ones dead for longer than
# its grace, so a job left `running` by a crash doesn't hold every rebuild for ever, nor one Redis
# lost stay pending. Asking Celery's workers instead would wait out a broadcast timeout each time.
# Awaiting confirmation isn't busy: the task has returned and the job waits on a person, in the
# database, which a rebuild doesn't touch.
ACTIVE_JOB_STATUSES = (JobStatus.PENDING, JobStatus.RUNNING, JobStatus.PAUSED)
job_liveness_check = job_liveness.Liveness(job_storage, ACTIVE_JOB_STATUSES)
busy.register("jobs", job_liveness_check.check)


def queue_job(job: Job) -> None:
    """Queue a saved, pending job's analysis task. The queued marker goes first, so the job
    is never pending with no signal of life; only the task ID is saved afterwards, because the
    worker may already be saving the whole row. A task that can't be queued (Redis down) fails
    the job there and then rather than leaving it pending with nothing to run it."""
    job_liveness.mark_queued(job.id)
    try:
        task = start_analysis.delay(job.id)
    except Exception as exc:
        job_storage.interrupt_job(job.id, (JobStatus.PENDING,), f"Not queued: {exc}. Restart the job to try again.")
        raise
    job.celery_task_id = task.id
    job_storage.set_celery_task_id(job.id, task.id)


class SharingUpdate(BaseModel):
    """Who a job is shared with (usernames)."""
    usernames: List[str]


def _job_for(request: Request, job_id: str) -> Optional[Job]:
    """A job the caller may see, or None (for bulk actions over a list of IDs)."""
    if not access.can_access_job(access.current_user(request), job_id):
        return None
    return job_storage.get_job(job_id)


# Deleting, archiving and restarting with fresh output lose the owner's work, so the people a job
# is shared with can't (as they can't change its sharing); a plain restart, which keeps it, they can
NOT_THEIRS = "Only the job's owner or an admin can {}"
# A job these can't be deleted or archived: it's being worked on (a removal among them)
BUSY_JOB_STATUSES = (JobStatus.PENDING, JobStatus.RUNNING, JobStatus.PAUSED, JobStatus.REMOVING)


def _awaiting_refusal(job: Job, action: str) -> Optional[str]:
    """Why an awaiting_confirmation job mustn't be deleted or archived, or None. Removing its old
    output failed part way and it waits on a decision: deleted, the pending removal would lose its
    job; archived, it would hide from the page that offers the decision."""
    if job.status != JobStatus.AWAITING_CONFIRMATION:
        return None
    return (f"Cannot {action} a job awaiting confirmation: removing its old output failed, and it's "
            "waiting for its owner or an admin to try the removal again or give up (confirm-removal "
            "or cancel-removal)")


def _export_refusal(job_id: str) -> str | None:
    """Why the job's output mustn't be replaced or removed now, or None: a SIEM export of it is
    queued or running, and Elrond's --Index would read (and Splunk monitor) a folder going away. If
    Redis can't say, the action goes ahead: an export can't be running unrecorded, and refusing every
    restart, archive and delete while Redis is down would be worse than the race it guards."""
    try:
        state = siem_export.status(job_id)["state"]
    except Exception as exc:  # noqa: BLE001 - see the docstring
        logger.warning("Job %s: SIEM export state unreadable (%s); not refusing", job_id, exc)
        return None
    if state in siem_export.ACTIVE:
        return f"A SIEM export is {state} for this job; wait for it to finish"
    return None


def _manager_refusal(request: Request, job_id: str, action: str) -> Optional[str]:
    """Why the caller may not do this to the job (they can see it but don't own it), or None."""
    if access.can_manage_job(access.current_user(request), job_id):
        return None
    return NOT_THEIRS.format(action)


def _client_ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


def _replaceable_output(request: Request, folder: str, jobs: List[Job]) -> str:
    """The job whose output an existing folder is, when the caller may replace it (its owner or
    an admin) and it isn't still going; HTTPException otherwise. A folder that isn't Rowanholt's
    output (no marker, and not recorded as an older job's) is never removed: whoever put it there
    removes it, or the job writes somewhere else."""
    owner = output_removal.folder_owner(folder, jobs)
    if owner is None:
        raise HTTPException(status_code=409, detail=(
            f"{folder} is there already and isn't a Rowanholt output folder, so it won't be replaced: "
            "choose another destination or case number, or move it away first"))
    previous = next((job for job in jobs if job.id == owner), None)
    user = access.current_user(request)
    if previous is None:
        # Its job was deleted: nobody owns it any more, so only an admin may replace it
        if not access.is_admin(user) and access.server_mode():
            raise HTTPException(status_code=403, detail=f"Only an admin can replace {folder}: its job was deleted")
    else:
        if not access.can_manage_job(user, previous.id):
            raise HTTPException(status_code=403, detail=(
                f"{folder} is the output of case {previous.case_number}: only its owner or an admin can replace it"))
        if previous.status.value in output_removal.ACTIVE_STATUSES:
            raise HTTPException(status_code=409, detail=(
                f"{folder} is the output of case {previous.case_number}, which is {previous.status.value}"))
    return owner


def _fresh_restart_refusal(request: Request, job: Job) -> Optional[str]:
    """Why the job mustn't restart with fresh output (its old output removed), or None: the owner
    or an admin only, and only into a destination that's still allowed (one recorded before the
    checks may be an allowed folder itself)."""
    refusal = _manager_refusal(request, job.id, "restart it with fresh output (fresh=false re-runs into it)")
    if refusal:
        return refusal
    if job.destination_path:
        try:
            output_removal.contained(job.destination_path, settings.allowed_paths + [str(settings.output_dir)])
        except output_removal.PathRefused as exc:
            return f"Its output folder can't be removed: {exc}"
    return None


def _with_access(jobs: List[Job], request: Request) -> List[Job]:
    """Fill in each job's owner, who it's shared with, and whether the caller may manage it."""
    records = job_storage.all_access() if jobs else {}
    user = access.current_user(request)
    for job in jobs:
        record = records.get(job.id)
        job.owner = (record or {}).get("owner_username")
        job.shared_with = (record or {}).get("shared_with") or []
        job.can_manage = access.manages(user, record)
    return jobs


# Startup event
@app.on_event("startup")
async def on_startup():
    """Run startup tasks."""
    # Jobs left pending, running or paused by a crash or a host restart are failed within a few
    # minutes of start-up, and any that die later within a few minutes of dying (job_liveness)
    app.state.stop_liveness = job_liveness_check.start()


@app.on_event("shutdown")
async def on_shutdown():
    """Stop the background passes."""
    stop = getattr(app.state, "stop_liveness", None)
    if stop is not None:
        stop.set()


# Include authentication routes
app.include_router(auth_router)

# Include AI assistant routes
app.include_router(ai_router)

# Include Mordor dataset management routes
app.include_router(mordor_router)
app.include_router(lab_router)
app.include_router(symbol_router)
app.include_router(sample_router)
app.include_router(threat_intel_router)
app.include_router(case_routes.router)
app.include_router(licence_router)
app.include_router(branding_routes.router)
app.include_router(branding_routes.case_router)
app.include_router(webhook_router)
app.include_router(removal_routes.router)

# Include Anduril (Docker administration) routes; /api/aragorn is the name before the rename
app.include_router(anduril_router, prefix="/api/anduril")
app.include_router(anduril_router, prefix="/api/aragorn", include_in_schema=False)


@app.get("/")
async def root():
    _index = Path(__file__).parent.parent / "frontend" / "build" / "index.html"
    if _index.exists():
        return FileResponse(str(_index))
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "running",
    }


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.get("/api/busy")
def busy_status() -> dict:
    """The homelab contract: `{"busy": true}` holds back a rebuild. No sign-in, so the answer is the
    one bit: which checks said busy goes to the log. A plain def, so the jobs query runs in the
    thread pool and a slow database doesn't stall other requests."""
    reasons = busy.busy_reasons()
    if reasons:
        logger.info("busy: %s", ", ".join(reasons))
    return {"busy": bool(reasons)}


# File System API
@app.get("/api/fs/browse", response_model=FileSystemBrowseResponse)
async def browse_filesystem(path: str = Query("/", description="Path to browse")):
    """
    Browse filesystem to select disk/memory images.

    Args:
        path: Directory path to browse

    Returns:
        FileSystemBrowseResponse with items, current path, and any permission warnings
    """
    try:
        # The check job paths get (output_removal.contained), not a string prefix, which let
        # /tmp/rowanholtX through as inside /tmp/rowanholt and followed links planted below an
        # allowed folder. An allowed folder itself may be listed, as a source may be one.
        try:
            path_obj = output_removal.contained(path, settings.allowed_paths, allow_root=True)
        except output_removal.PathRefused as exc:
            raise HTTPException(status_code=403, detail=f"Access denied: {exc}")

        if not path_obj.exists():
            raise HTTPException(status_code=404, detail="Path not found")

        if not path_obj.is_dir():
            raise HTTPException(status_code=400, detail="Path is not a directory")

        items = []
        skipped_count = 0
        permission_warning = None

        # Add parent directory link if not at root
        if path != "/" and str(path_obj.parent) != str(path_obj):
            items.append(
                FileSystemItem(
                    name="..",
                    path=str(path_obj.parent),
                    is_directory=True,
                )
            )

        # List directory contents - collect readable items first
        readable_items = []
        for item in path_obj.iterdir():
            try:
                # Skip macOS metadata files (._* files) and hidden files
                if item.name.startswith("._") or item.name == ".DS_Store":
                    continue
                # Test if we can access this item
                is_dir = item.is_dir()
                readable_items.append((item, is_dir))
            except (PermissionError, OSError) as e:
                # Track permission errors for external volumes
                skipped_count += 1
                if "Operation not permitted" in str(e) and not permission_warning:
                    permission_warning = (
                        "Some files could not be accessed. On macOS, Docker may need "
                        "Full Disk Access permission. Go to System Settings > Privacy & Security > "
                        "Full Disk Access and add Docker Desktop."
                    )
                continue

        # Sort: directories first, then by name
        readable_items.sort(key=lambda x: (not x[1], x[0].name))

        for item, is_dir in readable_items:
            try:
                stat = item.stat()

                # Check if file is a disk/memory image
                is_image = False
                if not is_dir:
                    ext = item.suffix.lower()
                    is_image = ext in [
                        ".e01", ".ex01", ".raw", ".dd", ".img", ".bin",
                        ".vmdk", ".vhd", ".vhdx", ".mem", ".dmp", ".lime"
                    ]

                items.append(
                    FileSystemItem(
                        name=item.name,
                        path=str(item),
                        is_directory=is_dir,
                        size=stat.st_size if not is_dir else None,
                        modified=datetime.fromtimestamp(stat.st_mtime),
                        is_image=is_image,
                    )
                )
            except (PermissionError, OSError) as e:
                skipped_count += 1
                if "Operation not permitted" in str(e) and not permission_warning:
                    permission_warning = (
                        "Some files could not be accessed. On macOS, Docker may need "
                        "Full Disk Access permission. Go to System Settings > Privacy & Security > "
                        "Full Disk Access and add Docker Desktop."
                    )
                continue

        return FileSystemBrowseResponse(
            items=items,
            current_path=str(path_obj),
            permission_warning=permission_warning,
            skipped_count=skipped_count,
        )

    except HTTPException:
        raise
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Path not found")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Job Management API
@app.post("/api/jobs", response_model=Job)
async def create_job(job_request: JobCreate, request: Request):
    """
    Create a new analysis job.

    Args:
        job_request: Job creation request

    Returns:
        Created job
    """
    try:
        # Sanitize case number
        case_number = sanitize_case_number(job_request.case_number)

        # Validate case number length
        if len(case_number) < 6:
            raise HTTPException(
                status_code=400,
                detail=f"Case number must be at least 6 characters (got {len(case_number)})",
            )
        if len(case_number) > 30:
            raise HTTPException(
                status_code=400,
                detail=f"Case number must be no longer than 30 characters (got {len(case_number)})",
            )

        if job_request.backup_password and not job_request.options.mobile:
            raise HTTPException(status_code=400, detail="A backup password is only for Mobile jobs (phone backups)")

        roots = settings.allowed_paths
        # Validate and sanitize source paths: inside an allowed folder (a whole one may be read)
        sanitized_source_paths = []
        for path in job_request.source_paths:
            try:
                sanitized = str(output_removal.contained(path, roots, allow_root=True))
            except output_removal.PathRefused as exc:
                raise HTTPException(status_code=403, detail=f"Access denied to path: {exc}")
            if not Path(sanitized).exists():
                raise HTTPException(
                    status_code=400,
                    detail=f"Source path does not exist: {path}",
                )
            sanitized_source_paths.append(sanitized)

        # Generate job ID
        job_id = str(uuid.uuid4())

        # Set destination path - if not specified, use case number as directory name
        destination_path = job_request.destination_path
        if not destination_path and sanitized_source_paths:
            first_source = Path(sanitized_source_paths[0])
            # Create output directory using case number (e.g., /tmp/rowanholt/mfttesting/)
            # Beside a Gandalf acquisitions folder, not in it: --Gandalf reads every folder there as a host
            if first_source.is_file() or job_request.options.gandalf:
                destination_path = str(first_source.parent / case_number)
            else:
                destination_path = str(first_source / case_number)
        if destination_path:
            # Inside an allowed folder, never one of them or above one: a fresh run removes it
            try:
                destination_path = str(output_removal.contained(destination_path, roots))
            except output_removal.PathRefused as exc:
                raise HTTPException(status_code=403, detail=f"Access denied to destination path: {exc}")
        else:
            destination_path = str(Path(settings.output_dir) / case_number)

        # Never over evidence, nor at, in or around another job's output while that job is going
        others = job_storage.list_jobs(limit=1_000_000)
        refusal = output_removal.destination_refusal(destination_path, None, sanitized_source_paths, others)
        if refusal:
            raise HTTPException(status_code=409, detail=refusal)

        # What the worker may remove is decided here and only here, whatever the request said
        options = job_request.options
        options.replaces_output_of = None
        options.output_marker = True
        user = access.current_user(request)
        dest_path = Path(destination_path)
        if dest_path.is_dir():
            # Check if destination directory already exists (unless force_overwrite is set)
            if not options.force_overwrite:
                raise HTTPException(
                    status_code=400,
                    detail=f"[Errno 17] File exists: '{destination_path}'",
                )
            options.replaces_output_of = _replaceable_output(request, destination_path, others)
            job_storage.audit("output.removal_requested", user, _client_ip(request), resource_id=job_id,
                              path=destination_path, replaces=options.replaces_output_of, case=case_number)

        # An encrypted phone backup's password goes to the worker through Redis (expiring), never
        # the job: stashed before the job is saved, so a Redis failure leaves no job behind
        password = job_request.backup_password.get_secret_value() if job_request.backup_password else ""
        if password:
            backup_secrets.stash(job_id, password)

        # Create job
        job = Job(
            id=job_id,
            case_number=case_number,
            source_paths=sanitized_source_paths,
            destination_path=destination_path,
            options=options,
            status=JobStatus.PENDING,
            created_at=datetime.now(),
        )

        # Save job, and who it belongs to
        job_storage.save_job(job)
        owner = user
        job_storage.set_owner(job.id, owner["id"], owner["username"])
        job.owner = owner["username"]
        job.can_manage = True

        # Start analysis task and store Celery task ID
        queue_job(job)

        return job

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        logger.error(f"Error creating job: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/jobs", response_model=JobListResponse)
async def list_jobs(
    request: Request,
    status: Optional[JobStatus] = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    log_limit: int = Query(10, description="Max log entries per job"),
):
    """
    List all analysis jobs.

    Args:
        status: Filter by job status
        limit: Maximum number of jobs to return
        offset: Offset for pagination
        log_limit: Maximum log entries per job (default: 10, 0 for all)

    Returns:
        List of jobs
    """
    try:
        visible = access.visible_job_ids(access.current_user(request))
        jobs = _with_access(job_storage.list_jobs(status=status, limit=limit, offset=offset, job_ids=visible), request)
        total = job_storage.count_jobs(status=status, job_ids=visible)

        # Truncate logs to avoid sending massive payloads
        if log_limit > 0:
            for job in jobs:
                if len(job.log) > log_limit:
                    job.log = job.log[-log_limit:]

        return JobListResponse(jobs=jobs, total=total)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/validate/case-id/{case_id}")
async def validate_case_id(case_id: str, request: Request):
    """
    Check if a case ID already exists.

    Args:
        case_id: Case ID to check

    Returns:
        {"exists": bool, "jobs": [list of matching job IDs]}
    """
    try:
        # Case numbers name output directories, so a clash is reported whoever owns
        # the other job; only the caller's own jobs are listed
        all_jobs = job_storage.list_jobs(limit=100000)
        visible = access.visible_job_ids(access.current_user(request))
        clashes = [job for job in all_jobs if job.case_number == case_id]
        matching_jobs = [
            {"id": job.id, "status": job.status, "created_at": job.created_at}
            for job in clashes
            if visible is None or job.id in visible
        ]

        return {
            "exists": len(clashes) > 0,
            "case_id": case_id,
            "jobs": matching_jobs
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/jobs/{job_id}", response_model=Job)
async def get_job(job_id: str, request: Request,
                  log_limit: int = Query(100, description="Max log entries to return")):
    """
    Get job details.

    Args:
        job_id: Job ID
        log_limit: Maximum number of recent log entries to return (default: 100, 0 for all)

    Returns:
        Job details
    """
    try:
        job = job_storage.get_job(job_id)

        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        # Truncate log to most recent entries to avoid sending massive payloads
        # Jobs can accumulate 60k+ log entries (7+ MB), causing API timeouts
        if log_limit > 0 and len(job.log) > log_limit:
            job.log = job.log[-log_limit:]

        return _with_access([job], request)[0]

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.patch("/api/jobs/{job_id}", response_model=Job)
async def update_job(job_id: str, update: JobUpdate, request: Request):
    """
    Add a note to a job's log: its owner or an admin, as for deleting or archiving it.

    Nothing else is changed here. The status, progress, result and error are the worker's, and a
    status set here would skip what the job's own routes do (killing the process group, releasing
    image locks, auditing a removal): `JobUpdate` refuses them with 422. The note goes in with
    `JobStorage.transition` on the status the job has, so it neither overwrites the worker's latest
    log and progress (as a full save would) nor lands on a job that moved on meanwhile (409).

    Args:
        job_id: Job ID
        update: The note
        request: The caller

    Returns:
        The job, with the note in its log
    """
    job = job_storage.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    refusal = _manager_refusal(request, job_id, "add to its log")
    if refusal:
        raise HTTPException(status_code=403, detail=refusal)
    user = access.current_user(request)
    # One line: a newline in the note could pass for an entry of the job's own
    note = " ".join(update.log_message.split())
    saved = job_storage.transition(job_id, (job.status,), job.status,
                                   log_line=f"Note from {user.get('username')}: {note}")
    if saved is None:
        raise HTTPException(status_code=409, detail="The job changed while the note was added; try again")
    job_storage.audit("job.note_added", {"id": user.get("id"), "username": user.get("username")},
                      _client_ip(request), resource_id=job_id)
    return _with_access([saved], request)[0]


@app.delete("/api/jobs/{job_id}")
async def delete_job(job_id: str, request: Request):
    """
    Delete a job.

    Args:
        job_id: Job ID

    Returns:
        Success message
    """
    try:
        job = job_storage.get_job(job_id)

        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        refusal = _manager_refusal(request, job_id, "delete it")
        if refusal:
            raise HTTPException(status_code=403, detail=refusal)

        # Only allow deleting completed/failed/cancelled jobs
        if job.status in BUSY_JOB_STATUSES:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete running or pending job",
            )
        refusal = _awaiting_refusal(job, "delete")
        if refusal:
            raise HTTPException(status_code=400, detail=refusal)
        refusal = _export_refusal(job_id)
        if refusal:
            raise HTTPException(status_code=409, detail=refusal)

        _delete_job(request, job)

        return {"message": "Job deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _delete_job(request: Request, job: Job, bulk: bool = False) -> None:
    """Delete the job and its case's rows (storage.delete_job), never anything on disk, and say so
    in the security log, which keeps it: the case's own activity record goes with the job."""
    removed = job_storage.delete_job(job.id)
    user = access.current_user(request)
    job_storage.audit("job.deleted", {"id": user.get("id"), "username": user.get("username")},
                      _client_ip(request), resource_id=job.id, case=job.case_number, bulk=bulk, removed=removed)


# A job these can be cancelled from (a removal can't: it runs to the end, or fails)
CANCELLABLE_STATUSES = (JobStatus.PENDING, JobStatus.RUNNING, JobStatus.PAUSED)


def _stop_job(job: Job) -> None:
    """Stop a job's work: SIGKILL its Elrond process group, revoke its Celery task and release its
    image locks, in that order."""
    _kill_job_process_group(job.id)
    if job.celery_task_id:
        from celery import current_app
        current_app.control.revoke(job.celery_task_id, terminate=True, signal='SIGKILL')
    try:
        from tasks_docker import release_image_locks_for_job
        release_image_locks_for_job(job.id, job.source_paths)
    except Exception as e:
        logger.warning(f"Failed to release image locks for job {job.id}: {e}")


def _mark_cancelled(job_id: str, log_line: str) -> Optional[Job]:
    """Set a job cancelled, with its completion time and a log line, if it's still pending, running
    or paused: the job as saved, or None when it had already finished or failed. One conditional
    UPDATE, not a save of the row the route read: the worker writes log lines and progress until
    it's killed, and a full save would put back the stale ones.

    It comes before the job is stopped (_stop_job). Killed first, the worker would see Elrond die
    and save the job failed (exit code -9) before the cancel was recorded, and a cancel that worked
    would be reported as a conflict. Marked first, the worker's later saves keep the cancel
    (JobStorage.save_worker_job), and a job that ended before the cancel isn't touched at all."""
    return job_storage.transition(job_id, CANCELLABLE_STATUSES, JobStatus.CANCELLED,
                                  log_line=log_line, completed_at=datetime.now())


# =====================================================
# BULK OPERATIONS - Must be defined BEFORE {job_id} routes
# to prevent FastAPI from matching "bulk" as a job_id
# =====================================================

@app.post("/api/jobs/bulk/cancel")
async def bulk_cancel_jobs(job_ids: list[str], request: Request):
    """
    Cancel multiple jobs at once.

    Args:
        job_ids: List of job IDs to cancel

    Returns:
        Results for each job
    """
    try:
        results = []

        for job_id in job_ids:
            job = _job_for(request, job_id)

            if not job:
                results.append({"job_id": job_id, "success": False, "error": "Job not found"})
                continue

            refusal = _manager_refusal(request, job_id, "cancel it")
            if refusal:
                results.append({"job_id": job_id, "success": False, "error": refusal})
                continue

            if job.status not in CANCELLABLE_STATUSES:
                results.append({"job_id": job_id, "success": False, "error": f"Job already {job.status.value}"})
                continue

            cancelled = _mark_cancelled(job_id, "Job cancelled by user (bulk operation)")
            if cancelled is None:
                current = job_storage.get_job(job_id)
                results.append({"job_id": job_id, "success": False, "error": (
                    f"Job already {current.status.value if current else 'deleted'}: it ended before the cancel")})
                continue
            _stop_job(cancelled)
            results.append({"job_id": job_id, "success": True})

        return {"results": results}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/jobs/bulk/delete")
async def bulk_delete_jobs(job_ids: list[str], request: Request):
    """
    Delete multiple completed/failed/cancelled jobs at once.

    Args:
        job_ids: List of job IDs to delete

    Returns:
        Results for each job
    """
    try:
        results = []

        for job_id in job_ids:
            job = _job_for(request, job_id)

            if not job:
                results.append({"job_id": job_id, "success": False, "error": "Job not found"})
                continue

            refusal = _manager_refusal(request, job_id, "delete it")
            if refusal:
                results.append({"job_id": job_id, "success": False, "error": refusal})
                continue

            if job.status in BUSY_JOB_STATUSES:
                results.append({"job_id": job_id, "success": False, "error": "Cannot delete running job"})
                continue
            refusal = _awaiting_refusal(job, "delete") or _export_refusal(job_id)
            if refusal:
                results.append({"job_id": job_id, "success": False, "error": refusal})
                continue

            _delete_job(request, job, bulk=True)
            results.append({"job_id": job_id, "success": True})

        return {"results": results}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/jobs/bulk/archive")
async def bulk_archive_jobs(job_ids: list[str], request: Request):
    """
    Archive multiple jobs at once.

    Args:
        job_ids: List of job IDs to archive

    Returns:
        Results for each job
    """
    try:
        results = []

        for job_id in job_ids:
            job = _job_for(request, job_id)

            if not job:
                results.append({"job_id": job_id, "success": False, "error": "Job not found"})
                continue

            refusal = _manager_refusal(request, job_id, "archive it")
            if refusal:
                results.append({"job_id": job_id, "success": False, "error": refusal})
                continue

            if job.status in BUSY_JOB_STATUSES:
                results.append({"job_id": job_id, "success": False, "error": "Cannot archive running job"})
                continue
            refusal = _awaiting_refusal(job, "archive") or _export_refusal(job_id)
            if refusal:
                results.append({"job_id": job_id, "success": False, "error": refusal})
                continue

            if job.status == JobStatus.ARCHIVED:
                results.append({"job_id": job_id, "success": False, "error": "Already archived"})
                continue

            _archive(job, "Job archived by user (bulk operation)")
            job_storage.save_job(job)
            results.append({"job_id": job_id, "success": True})

        return {"results": results}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _archive(job: Job, log_line: str) -> None:
    """Archive the job (the caller saves it), keeping when, and the status to restore."""
    job.archived_from = job.status
    job.archived_at = datetime.now()
    job.status = JobStatus.ARCHIVED
    job.log.append(f"[{datetime.now().isoformat()}] {log_line}")


def _unarchived_status(job: Job) -> JobStatus:
    """The status an archived job goes back to: the one it had when it was archived. A job
    archived before that was kept (migration a6d3f9b2c418) has none, so its status is read from
    what it holds: an error means it failed, a completion time that it finished. A cancel sets a
    completion time too, so such a cancelled job comes back as completed."""
    if job.archived_from and job.archived_from != JobStatus.ARCHIVED:
        return job.archived_from
    if job.error:
        return JobStatus.FAILED
    if job.completed_at:
        return JobStatus.COMPLETED
    return JobStatus.CANCELLED


def _unarchive(job: Job, log_line: str) -> None:
    """Restore the job from the archive (the caller saves it), with its archive state cleared."""
    job.status = _unarchived_status(job)
    job.archived_at = None
    job.archived_from = None
    job.log.append(f"[{datetime.now().isoformat()}] {log_line}")


@app.post("/api/jobs/bulk/unarchive")
async def bulk_unarchive_jobs(job_ids: list[str], request: Request):
    """
    Restore multiple archived jobs to the job list at once.

    Args:
        job_ids: List of job IDs to restore

    Returns:
        Results for each job
    """
    try:
        results = []

        for job_id in job_ids:
            job = _job_for(request, job_id)

            if not job:
                results.append({"job_id": job_id, "success": False, "error": "Job not found"})
                continue

            refusal = _manager_refusal(request, job_id, "restore it from the archive")
            if refusal:
                results.append({"job_id": job_id, "success": False, "error": refusal})
                continue

            if job.status != JobStatus.ARCHIVED:
                results.append({"job_id": job_id, "success": False, "error": "Job is not archived"})
                continue

            _unarchive(job, "Job unarchived by user (bulk operation)")
            job_storage.save_job(job)
            results.append({"job_id": job_id, "success": True, "status": job.status.value})

        return {"results": results}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/jobs/bulk/restart")
async def bulk_restart_jobs(job_ids: list[str], request: Request, fresh: Optional[bool] = None,
                           confirm: bool = False):
    """
    Restart multiple failed, cancelled, or completed jobs at once.

    Args:
        job_ids: List of job IDs to restart
        fresh: Remove each job's previous output before it runs again, so a failed
            run's partial output doesn't mix with the new one (default: completed jobs only)
        confirm: Restart jobs that have findings too (without it they're skipped)

    Returns:
        Results for each job
    """
    try:
        results = []

        for job_id in job_ids:
            job = _job_for(request, job_id)

            if not job:
                results.append({"job_id": job_id, "success": False, "error": "Job not found"})
                continue

            if job.status not in [JobStatus.FAILED, JobStatus.CANCELLED, JobStatus.COMPLETED]:
                results.append({"job_id": job_id, "success": False, "error": "Can only restart failed, cancelled, or completed jobs"})
                continue
            refusal = _export_refusal(job_id)
            if refusal:
                results.append({"job_id": job_id, "success": False, "error": refusal})
                continue

            refusal = case_routes.restart_refusal(job_id, confirm)
            if refusal:
                results.append({"job_id": job_id, "success": False, "error": refusal["message"],
                                "findings": refusal["findings"]})
                continue

            clean = _restarts_fresh(job, fresh)
            refusal = _fresh_restart_refusal(request, job) if clean else None
            if refusal:
                results.append({"job_id": job_id, "success": False, "error": refusal})
                continue
            # Reset job state
            job.status = JobStatus.PENDING
            job.progress = 0
            job.error = None
            job.started_at = None
            job.completed_at = None
            # Each restart decides afresh: a wipe isn't kept for the next one
            job.options.force_overwrite = clean
            job.log.append(f"[{datetime.now().isoformat()}] Job restarted by user (bulk operation{', fresh output' if clean else ''})")
            job_storage.save_job(job)

            # Start new analysis task
            queue_job(job)

            results.append({"job_id": job_id, "success": True})

        return {"results": results}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =====================================================
# SINGLE JOB OPERATIONS
# =====================================================

@app.post("/api/jobs/{job_id}/cancel")
async def cancel_job(job_id: str, request: Request):
    """
    Cancel a running job.

    Args:
        job_id: Job ID

    Returns:
        Updated job
    """
    try:
        job = job_storage.get_job(job_id)

        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        refusal = _manager_refusal(request, job_id, "cancel it")
        if refusal:
            raise HTTPException(status_code=403, detail=refusal)

        if job.status not in CANCELLABLE_STATUSES:
            raise HTTPException(
                status_code=400,
                detail=f"Job already {job.status.value} - can only cancel pending, running or paused jobs",
            )

        cancelled = _mark_cancelled(job_id, "Job cancelled by user")
        if cancelled is None:
            current = job_storage.get_job(job_id)
            raise HTTPException(status_code=409, detail=(
                f"The job is already {current.status.value if current else 'deleted'}: it ended before the cancel"))
        _stop_job(cancelled)
        return _with_access([cancelled], request)[0]

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _kill_job_process_group(job_id: str) -> None:
    """Best-effort SIGKILL of a job's Elrond process group before revoking it."""
    try:
        from tasks_docker import send_job_signal, _clear_job_process
        result = send_job_signal(job_id, "kill")
        if result.get("ok"):
            _clear_job_process(job_id)
        else:
            logger.info(f"Job {job_id}: no process group killed ({result.get('error')})")
    except Exception as e:
        logger.warning(f"Failed to kill process group for job {job_id}: {e}")


def _signal_job(request: Request, job_id: str, action: str, required: JobStatus, new_status: JobStatus):
    job = job_storage.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    # Pausing or resuming someone else's job stalls or restarts their work without them: the
    # people a job is shared with can watch it, its owner (or an admin) runs it
    refusal = _manager_refusal(request, job_id, f"{action} it")
    if refusal:
        raise HTTPException(status_code=403, detail=refusal)
    if job.status != required:
        raise HTTPException(
            status_code=400,
            detail=f"Job is {job.status.value} - can only {action} a {required.value} job",
        )

    from tasks_docker import send_job_signal
    result = send_job_signal(job_id, action)
    if not result.get("ok"):
        raise HTTPException(status_code=409, detail=f"Could not {action} job: {result.get('error')}")

    # The worker records the event in the job log itself (see
    # tasks_docker._drain_job_events); only the status is written here.
    job_storage.set_status(job_id, new_status)
    return job_storage.get_job(job_id)


@app.post("/api/jobs/{job_id}/pause")
async def pause_job(job_id: str, request: Request):
    """
    Pause a running job by sending SIGSTOP to its Elrond process group.

    Image mounts stay up and the image lock stays held. Wall-clock timeouts
    inside Elrond keep counting while it is stopped, so a tool call paused
    for longer than its timeout fails on resume.

    Args:
        job_id: Job ID

    Returns:
        Updated job
    """
    return _signal_job(request, job_id, "pause", JobStatus.RUNNING, JobStatus.PAUSED)


@app.post("/api/jobs/{job_id}/resume")
async def resume_job(job_id: str, request: Request):
    """
    Resume a paused job by sending SIGCONT to its Elrond process group.

    Args:
        job_id: Job ID

    Returns:
        Updated job
    """
    return _signal_job(request, job_id, "resume", JobStatus.PAUSED, JobStatus.RUNNING)


def _restarts_fresh(job, fresh: Optional[bool]) -> bool:
    """Whether a restart removes the job's output first. A completed job's always would by default:
    Elrond skips any artefact whose cooked file is already there (registry hives among them), so a
    re-run into the old output would leave it as it was. A failed or cancelled one keeps its output
    unless asked."""
    return job.status == JobStatus.COMPLETED if fresh is None else fresh


@app.post("/api/jobs/{job_id}/restart")
async def restart_job(job_id: str, request: Request, confirm: bool = False, fresh: Optional[bool] = None):
    """
    Restart a failed, cancelled or completed job.

    Args:
        job_id: Job ID
        confirm: Restart even though the job has findings (409 without it)
        fresh: Remove the job's output before it runs again (default: completed jobs only)

    Returns:
        Updated job
    """
    try:
        job = job_storage.get_job(job_id)

        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        if job.status not in [JobStatus.FAILED, JobStatus.CANCELLED, JobStatus.COMPLETED]:
            raise HTTPException(
                status_code=400,
                detail="Can only restart failed, cancelled, or completed jobs",
            )
        refusal = _export_refusal(job_id)
        if refusal:
            raise HTTPException(status_code=409, detail=refusal)

        refusal = case_routes.restart_refusal(job_id, confirm)
        if refusal:
            raise HTTPException(status_code=409, detail=refusal)

        clean = _restarts_fresh(job, fresh)
        refusal = _fresh_restart_refusal(request, job) if clean else None
        if refusal:
            raise HTTPException(status_code=403, detail=refusal)
        # Reset job state
        job.status = JobStatus.PENDING
        job.progress = 0
        job.error = None
        job.started_at = None
        job.completed_at = None
        # Each restart decides afresh: a wipe isn't kept for the next one
        job.options.force_overwrite = clean
        job.log.append(f"[{datetime.now().isoformat()}] Job restarted by user{' (fresh output)' if clean else ''}")

        job_storage.save_job(job)

        # Start new analysis task
        queue_job(job)

        return job

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Confirming or giving up a failed removal of a job's old output (confirm-removal, cancel-removal,
# and the old confirm-sudo and cancel-sudo): removal_routes.py

@app.post("/api/jobs/{job_id}/archive")
async def archive_job(job_id: str, request: Request):
    """
    Archive a completed, failed, or cancelled job.

    Args:
        job_id: Job ID

    Returns:
        Updated job
    """
    try:
        job = job_storage.get_job(job_id)

        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        refusal = _manager_refusal(request, job_id, "archive it")
        if refusal:
            raise HTTPException(status_code=403, detail=refusal)

        if job.status in BUSY_JOB_STATUSES:
            raise HTTPException(
                status_code=400,
                detail="Cannot archive pending or running jobs",
            )
        refusal = _awaiting_refusal(job, "archive")
        if refusal:
            raise HTTPException(status_code=400, detail=refusal)
        refusal = _export_refusal(job_id)
        if refusal:
            raise HTTPException(status_code=409, detail=refusal)

        if job.status == JobStatus.ARCHIVED:
            raise HTTPException(
                status_code=400,
                detail="Job is already archived",
            )

        _archive(job, "Job archived by user")

        job_storage.save_job(job)

        return job

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/jobs/{job_id}/unarchive")
async def unarchive_job(job_id: str, request: Request):
    """
    Unarchive a job, restoring it to its previous status.

    Args:
        job_id: Job ID

    Returns:
        Updated job
    """
    try:
        job = job_storage.get_job(job_id)

        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        # Archiving is the owner's or an admin's, so taking it back out is too
        refusal = _manager_refusal(request, job_id, "restore it from the archive")
        if refusal:
            raise HTTPException(status_code=403, detail=refusal)

        if job.status != JobStatus.ARCHIVED:
            raise HTTPException(
                status_code=400,
                detail="Job is not archived",
            )

        _unarchive(job, "Job unarchived by user")

        job_storage.save_job(job)

        return _with_access([job], request)[0]

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# An export a worker is running: its heartbeat (siem_export). A queued one isn't busy: like a
# pending job, it waits out a rebuild in Redis's queue
busy.register("siem-exports", siem_export.running)


def _export_folder(job: Job) -> Path:
    """The completed job's output folder, which --Index reads; HTTPException when it's unknown or gone."""
    if job.destination_path:
        folder = Path(job.destination_path)
    elif job.result and job.result.get("output_directory"):
        folder = Path(job.result["output_directory"])
    else:
        raise HTTPException(status_code=400, detail="Cannot determine output directory for job")
    if not folder.exists():
        raise HTTPException(status_code=400, detail=f"Output directory does not exist: {folder}")
    return folder


@app.post("/api/jobs/{job_id}/export-siem", status_code=202)
async def trigger_siem_export(job_id: str, request: Request) -> dict:
    """
    Queue the SIEM export of a completed job: Elrond's --Index of its output into the targets its
    options name, in the worker, which has Elrond and the SIEMs' network and credentials. Answers
    at once with the task; GET this path for its progress and outcome.

    Args:
        job_id: Job ID to export
        request: The caller (whoever can see the job; the access middleware has checked)

    Returns:
        The queued export's record
    """
    # The house pattern: a package import under the tests' and tools' `backend.main`, a top-level
    # one under `uvicorn main:app`, as the image runs it
    try:
        from .tasks_docker import export_siem
    except ImportError:
        from tasks_docker import export_siem

    job = job_storage.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != JobStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Can only export SIEM data for completed jobs")
    names = siem_export.targets(job.options)
    if not names:
        raise HTTPException(status_code=400, detail="Job does not have SIEM export enabled")
    _export_folder(job)

    user = access.current_user(request)
    task_id = str(uuid.uuid4())
    try:
        record = siem_export.claim(job_id, task_id, names, user.get("username") or "local")
    except Exception as exc:  # noqa: BLE001 - Redis down: nothing is queued, so say so rather than pretend
        raise HTTPException(status_code=503, detail=f"Can't record the export (Redis): {exc}")
    if record is None:
        raise HTTPException(status_code=409, detail="A SIEM export is already queued or running for this job")
    try:
        export_siem.apply_async(args=[job_id], task_id=task_id)
    except Exception as exc:  # noqa: BLE001 - the broker down: forget the claim and say so
        siem_export.drop(job_id, task_id)
        raise HTTPException(status_code=503, detail=f"Can't queue the export: {exc}")
    # A conditional append, not a full save: the row's other columns stay as the worker left them
    job_storage.transition(job_id, (JobStatus.COMPLETED,), JobStatus.COMPLETED,
                           log_line=f"SIEM export into {', '.join(names)} queued by {user.get('username') or 'local'}")
    job_storage.audit("job.siem_export", {"id": user.get("id"), "username": user.get("username")},
                      _client_ip(request), resource_id=job_id, targets=names)
    return siem_export.status(job_id)


@app.get("/api/jobs/{job_id}/export-siem")
async def siem_export_status(job_id: str) -> dict:
    """
    The job's last SIEM export: `state` none, queued, running (with the target it's on), succeeded
    or failed (with each target's outcome and counts), or interrupted (its worker died).

    Args:
        job_id: Job ID

    Returns:
        The export's record
    """
    if not job_storage.get_job(job_id):
        raise HTTPException(status_code=404, detail="Job not found")
    try:
        return siem_export.status(job_id)
    except Exception as exc:  # noqa: BLE001 - Redis down: the state is unknown, not "none"
        raise HTTPException(status_code=503, detail=f"Can't read the export's state (Redis): {exc}")


@app.get("/api/jobs/{job_id}/navigator")
async def get_navigator_json(job_id: str, domain: Optional[str] = Query(None, pattern="^(enterprise|mobile)-attack$")):
    """
    Get the MITRE ATT&CK Navigator JSON file for a job: its Enterprise layer
    (<case>_navigator.json) or Mobile layer (<case>_mobile_navigator.json); with no domain
    given, Enterprise when the case has one.
    """
    from pathlib import Path
    from fastapi.responses import FileResponse

    try:
        job = job_storage.get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        # Get output directory
        if job.result and "output_directory" in job.result:
            output_dir = Path(job.result["output_directory"])
        elif job.destination_path:
            output_dir = Path(job.destination_path)
        else:
            raise HTTPException(status_code=404, detail="Job output directory not found")

        # Search for navigator JSON files, one per ATT&CK domain the case has
        navigator_files = sorted(output_dir.rglob("*_navigator.json"))
        mobile = [f for f in navigator_files if f.name.endswith("_mobile_navigator.json")]
        enterprise = [f for f in navigator_files if f not in mobile]
        if domain == "mobile-attack":
            navigator_files = mobile
        elif domain == "enterprise-attack":
            navigator_files = enterprise
        else:
            navigator_files = enterprise or mobile

        if not navigator_files:
            raise HTTPException(status_code=404, detail="Navigator JSON file not found")

        nav_file = navigator_files[0]
        return FileResponse(
            path=str(nav_file),
            media_type="application/json",
            filename=nav_file.name
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# File requirements for advanced processing options
FILE_REQUIREMENTS = {
    'keywords': 'keywords.txt',
    'yara': 'yara.yar',
    'collectFiles': 'files.txt',
}

# Default directory for required files (OS-aware)
import platform
if platform.system() == 'Darwin' or platform.system() == 'Linux':
    REQUIRED_FILES_DIR = '/tmp/rowanholt'
else:
    REQUIRED_FILES_DIR = os.path.join(os.environ.get('TEMP', 'C:\\Temp'), 'rowanholt')


@app.get("/api/jobs/{job_id}/sharing")
async def get_job_sharing(job_id: str, request: Request):
    """Who owns a job, who it's shared with, and whether the caller may change that."""
    if not job_storage.get_job(job_id):
        raise HTTPException(status_code=404, detail="Job not found")
    record = job_storage.get_access(job_id) or {}
    return {
        "owner": record.get("owner_username"),
        "shared_with": record.get("shared_with") or [],
        "can_manage": access.can_manage_job(access.current_user(request), job_id),
    }


@app.put("/api/jobs/{job_id}/sharing")
async def set_job_sharing(job_id: str, update: SharingUpdate, request: Request):
    """Share a job with other users (its owner or an admin), replacing the list."""
    if not job_storage.get_job(job_id):
        raise HTTPException(status_code=404, detail="Job not found")
    if not access.can_manage_job(access.current_user(request), job_id):
        raise HTTPException(status_code=403, detail="Only the job's owner or an admin can share it")
    known = {u["username"] for u in load_users().values() if u.get("is_active", True)}
    unknown = sorted(set(update.usernames) - known)
    if unknown:
        raise HTTPException(status_code=400, detail=f"No such user: {', '.join(unknown)}")
    record = job_storage.set_shared(job_id, update.usernames)
    return {"owner": record.get("owner_username"), "shared_with": record["shared_with"], "can_manage": True}


@app.post("/api/check-required-files")
async def check_required_files(request: dict):
    """
    Check if required files exist in the default location.

    Args:
        request: {"options": ["keywords", "yara", "collectFiles"]}

    Returns:
        {"missing": ["keywords", "yara"], "found": ["collectFiles"]}
    """
    try:
        options = request.get('options', [])
        missing = []
        found = []

        # Ensure directory exists
        os.makedirs(REQUIRED_FILES_DIR, exist_ok=True)

        for opt in options:
            if opt in FILE_REQUIREMENTS:
                filename = FILE_REQUIREMENTS[opt]
                filepath = os.path.join(REQUIRED_FILES_DIR, filename)

                if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
                    found.append(opt)
                else:
                    missing.append(opt)

        return {"missing": missing, "found": found, "directory": REQUIRED_FILES_DIR}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


from fastapi import File, UploadFile

@app.post("/api/upload-required-files")
async def upload_required_files_impl(
    keywords: Optional[UploadFile] = File(None),
    yara: Optional[UploadFile] = File(None),
    collectFiles: Optional[UploadFile] = File(None),
):
    """
    Upload required files for advanced processing options.
    """
    try:
        # Ensure directory exists
        os.makedirs(REQUIRED_FILES_DIR, exist_ok=True)

        uploaded = []

        file_mapping = {
            'keywords': (keywords, 'keywords.txt'),
            'yara': (yara, 'yara.yar'),
            'collectFiles': (collectFiles, 'files.txt'),
        }

        for key, (upload_file, target_filename) in file_mapping.items():
            if upload_file and upload_file.filename:
                content = await upload_file.read()
                target_path = os.path.join(REQUIRED_FILES_DIR, target_filename)

                with open(target_path, 'wb') as f:
                    f.write(content)

                uploaded.append({
                    'option': key,
                    'filename': target_filename,
                    'path': target_path,
                    'size': len(content)
                })

        return {"success": True, "uploaded": uploaded, "directory": REQUIRED_FILES_DIR}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Serve React frontend build
_BUILD_DIR = Path(__file__).parent.parent / "frontend" / "build"
if _BUILD_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_BUILD_DIR / "static")), name="react-static")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        # Serve known root-level build assets directly
        candidate = _BUILD_DIR / full_path
        if candidate.is_file():
            return FileResponse(str(candidate))
        return FileResponse(str(_BUILD_DIR / "index.html"))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
