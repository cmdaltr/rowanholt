"""
Sample data (Aragorn): the public forensic images Rowanholt imports as ready cases, what's
downloaded, and fetching one. Admin-only: a fetch downloads gigabytes from the internet.

The catalogue and the downloads are Elrond's rowanholt/samples (also `rowanholt samples`), in
ROWANHOLT_SAMPLES_DIR. A fetch runs in the worker; importing one is an ordinary job, which the
web app starts through /api/jobs with the sources and options listed here.
"""

import importlib.util
import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

try:
    from .auth.access import require_admin
    from .case_files import _elrond_sources
except ImportError:
    from auth.access import require_admin
    from case_files import _elrond_sources

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/samples", tags=["samples"])
_samples = None


def samples_module():
    """Elrond's rowanholt/samples/samples.py, loaded by path as case_files does."""
    global _samples
    if _samples is None:
        for src in _elrond_sources():
            path = Path(src, "rowanholt", "samples", "samples.py")
            if path.is_file():
                spec = importlib.util.spec_from_file_location("rowanholt_samples", path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                _samples = module
                break
        else:
            raise HTTPException(status_code=503, detail="rowanholt/samples isn't mounted in the backend")
    return _samples


@router.get("")
async def list_samples(_: dict = Depends(require_admin)) -> dict:
    """The catalogue, each sample with its files' state and, once fetched, the job to start."""
    samples = samples_module()
    root = samples.samples_dir()
    listed = []
    for s in samples.catalogue():
        state = samples.status(s, root)
        found = [Path(p) for p in state["images"]]
        job = samples.job_request(s, found) if found else None
        if job:
            job.pop("backup_password", None)  # sent by the import itself, not listed
        listed.append({**{k: s.get(k, "") for k in ("id", "title", "covers", "os", "publisher", "page",
                                                       "answers", "terms", "catches")},
                       "files": state["files"], "images": state["images"], "job": job,
                       "has_backup_password": bool(s.get("backup_password"))})
    return {"dir": str(root), "samples": listed}


@router.post("/{sample_id}/import")
async def import_body(sample_id: str, _: dict = Depends(require_admin)) -> dict:
    """The job request for a fetched sample, backup password included, for the web app to POST
    to /api/jobs as the analyst (so the job is theirs, as any other)."""
    samples = samples_module()
    try:
        s = samples.sample(sample_id)
    except samples.SampleError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    found = samples.images(s, samples.samples_dir())
    if not found:
        raise HTTPException(status_code=409, detail=f"{sample_id} isn't fetched yet")
    return samples.job_request(s, found)


@router.post("/{sample_id}/fetch")
async def fetch_sample(sample_id: str, user: dict = Depends(require_admin)) -> dict:
    """Download, check and unpack a sample in the worker."""
    samples = samples_module()
    try:
        samples.sample(sample_id)
    except samples.SampleError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    try:
        from tasks_docker import fetch_sample as task
    except ImportError:
        raise HTTPException(status_code=503, detail="The worker's task queue isn't available")
    queued = task.delay(sample_id)
    logger.info("Sample %s fetch by %s queued as %s", sample_id, user.get("username"), queued.id)
    return {"task_id": queued.id}


@router.get("/tasks/{task_id}")
async def sample_task(task_id: str, _: dict = Depends(require_admin)) -> dict:
    """A fetch: its progress while it runs, then the outcome."""
    from tasks_docker import celery_app

    result = celery_app.AsyncResult(task_id)
    if not result.ready():
        return {"state": "running", **(result.info if isinstance(result.info, dict) else {})}
    value = result.result if isinstance(result.result, dict) else {"ok": False, "output": str(result.result)}
    return {"state": "done", **value}
