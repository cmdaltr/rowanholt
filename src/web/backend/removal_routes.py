"""
Confirming, or giving up, a failed removal of a job's old output.

A fresh run removes the job's old output folder first (output_removal.py, in the worker). When
that fails (a busy file, permissions) the job waits, `awaiting_confirmation`, for its owner or an
admin to try again or give up. Trying again moves the job to `removing` in one conditional update,
so of two confirmations one wins and the other gets 409, records who asked in the audit log, and
queues the worker's `remove_output` task: 202, and the job page follows the job from there. The
worker re-derives the folder from the job record and checks it all again; nothing a request or the
pending action says is ever deleted.

Nothing was ever escalated: the routes were `confirm-sudo` and `cancel-sudo` until 12 November
2026, and those paths still answer, for clients that call them.
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

try:
    from . import busy
    from . import job_liveness
    from .auth import access
    from .models.job import JobStatus
except ImportError:
    import busy
    import job_liveness
    from auth import access
    from models.job import JobStatus

logger = logging.getLogger(__name__)

router = APIRouter(tags=["jobs"])

NOT_AWAITING = "Job is not awaiting confirmation"
INTERRUPTED = ("Interrupted: the worker removing this job's old output stopped before it finished "
               "(killed, or its container or the host restarted). Part of the old output may be gone; "
               "restart the job with fresh output to remove the rest and run it again.")

_storage = None
_liveness: Optional[job_liveness.Liveness] = None


class _RemovalRows:
    """The job store as job_liveness sees it, for jobs being removed: a removal waiting in the
    queue behind other tasks counts as alive as a pending job's does (the queue is checked for its
    task), and one whose worker died is failed with a reason of its own."""

    def __init__(self, storage) -> None:
        self.storage = storage

    def active_jobs(self, statuses):
        return [(job_id, "pending", task_id) for job_id, _, task_id in self.storage.active_jobs(statuses)]

    def interrupt_job(self, job_id, statuses, reason):
        return self.storage.interrupt_job(job_id, statuses, INTERRUPTED)


def configure(storage) -> None:
    """Give the routes the backend's JobStorage. A removal a rebuild would cut off holds
    `GET /api/busy`, through its own liveness check: registered here, so busy.py and
    job_liveness.py need nothing new."""
    global _storage, _liveness
    _storage = storage
    _liveness = job_liveness.Liveness(_RemovalRows(storage), (JobStatus.REMOVING,))
    busy.register("removals", _liveness.check)


# Some FastAPI versions run an included router's handlers twice (its own and the app's copy):
# one background pass is enough, so starting is a no-op once started
@router.on_event("startup")
def _start_liveness() -> None:
    if _liveness is not None and getattr(router, "stop_liveness", None) is None:
        router.stop_liveness = _liveness.start()


@router.on_event("shutdown")
def _stop_liveness() -> None:
    stop = getattr(router, "stop_liveness", None)
    if stop is not None:
        stop.set()
        router.stop_liveness = None


def _ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


def _actor(request: Request) -> dict:
    user = access.current_user(request)
    return {"id": user.get("id"), "username": user.get("username")}


def _job_or_refusal(request: Request, job_id: str, action: str):
    job = _storage.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    # It's the owner's output and the owner's job: the people it's shared with can't
    if not access.can_manage_job(access.current_user(request), job_id):
        raise HTTPException(status_code=403, detail=f"Only the job's owner or an admin can {action}")
    return job


@router.post("/api/jobs/{job_id}/confirm-removal", status_code=202)
@router.post("/api/jobs/{job_id}/confirm-sudo", status_code=202, include_in_schema=False)
def confirm_removal(job_id: str, request: Request):
    """Try removing the job's old output again: 202 with the job, now `removing`; 409 when it
    isn't awaiting confirmation (another confirmation won). The worker removes it, checks it's
    gone, and queues the job's run; or fails the job, with the reason."""
    _job_or_refusal(request, job_id, "confirm removing its output")
    actor = _actor(request)
    job = _storage.transition(job_id, (JobStatus.AWAITING_CONFIRMATION,), JobStatus.REMOVING,
                              log_line=f"{actor['username']} confirmed removing the old output again")
    if job is None:
        raise HTTPException(status_code=409, detail=NOT_AWAITING)
    path = job.pending_action.target_path if job.pending_action else job.destination_path
    _storage.audit("output.removal_confirmed", actor, _ip(request), resource_id=job_id, path=path)

    try:
        from tasks_docker import remove_output
    except ImportError:  # no Celery here: the job can't be removed, so it isn't left removing
        remove_output = None
    try:
        if remove_output is None:
            raise RuntimeError("the worker's task queue isn't available")
        job_liveness.mark_queued(job_id)
        task = remove_output.delay(job_id, actor, _ip(request))
    except Exception as exc:  # noqa: BLE001 - whatever stopped the queue, the job mustn't wait for ever
        logger.error("Job %s: removal not queued: %s", job_id, exc)
        _storage.transition(job_id, (JobStatus.REMOVING,), JobStatus.FAILED, log_line=f"Not queued: {exc}",
                            error=f"Not queued: {exc}. Restart the job with fresh output to try again.",
                            pending_action=None, completed_at=datetime.now())
        raise HTTPException(status_code=503, detail=f"The removal couldn't be queued: {exc}")
    _storage.set_celery_task_id(job_id, task.id)
    job.celery_task_id = task.id
    return JSONResponse(status_code=202, content=jsonable_encoder(job))


@router.post("/api/jobs/{job_id}/cancel-removal")
@router.post("/api/jobs/{job_id}/cancel-sudo", include_in_schema=False)
def cancel_removal(job_id: str, request: Request):
    """Give up removing the job's old output: the job fails, with that as the reason, and its old
    output stays as it is. 409 when it isn't awaiting confirmation."""
    _job_or_refusal(request, job_id, "give up removing its output")
    actor = _actor(request)
    job = _storage.transition(job_id, (JobStatus.AWAITING_CONFIRMATION,), JobStatus.FAILED,
                              log_line=f"{actor['username']} gave up removing the old output",
                              error="Removing the old output was given up; it's kept as it was",
                              pending_action=None, completed_at=datetime.now())
    if job is None:
        raise HTTPException(status_code=409, detail=NOT_AWAITING)
    _storage.audit("output.removal_cancelled", actor, _ip(request), resource_id=job_id, path=job.destination_path)
    return job
