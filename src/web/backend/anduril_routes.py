"""
Anduril routes: administer Dernvale's Docker containers and images.

The backend never holds the Docker socket. These admin-only endpoints proxy
to the Anduril service over the internal dernvale-anduril network, and
Anduril enforces the Dernvale-only scope. Disabled until the JWT secret has
been changed from its default, since a default secret lets anyone mint an
admin token.
"""

import logging
import os
from pathlib import Path
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

try:
    from .auth.routes_simple import load_users
    from .auth.security import verify_token
    from .config import settings
    from .models.job import JobStatus
    from .storage import JobStorage
except ImportError:
    from auth.routes_simple import load_users
    from auth.security import verify_token
    from config import settings
    from models.job import JobStatus
    from storage import JobStorage

logger = logging.getLogger(__name__)

# Served at /api/anduril, and at /api/aragorn for clients from before the rename (main.py)
router = APIRouter(tags=["anduril"])

ANDURIL_URL = os.environ.get("ANDURIL_URL") or os.environ.get("ARAGORN_URL") or "http://anduril:5690"
ANDURIL_TOKEN_PATH = Path(os.environ.get("ANDURIL_TOKEN_PATH", "/run/anduril/token"))
DEFAULT_SECRET = "your-secret-key-change-in-production"
ENABLE_COMMAND = "dernvale anduril enable"
# Services whose restart interrupts a running job (see anduril/scope.py).
JOB_SENSITIVE_SERVICES = {"celery-worker", "dernvale-celery-worker", "postgres", "dernvale-postgres", "redis", "dernvale-redis"}

_bearer = HTTPBearer(auto_error=False)


class ActionRequest(BaseModel):
    force: bool = False


class PullRequest(BaseModel):
    ref: str


class RemoveImageRequest(BaseModel):
    id: str


def _secret_configured() -> bool:
    return bool(settings.secret_key) and settings.secret_key != DEFAULT_SECRET


def _read_token() -> Optional[str]:
    try:
        token = ANDURIL_TOKEN_PATH.read_text().strip()
    except OSError:
        return None
    return token or None


async def require_anduril_admin(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    session_token: Optional[str] = Cookie(None, alias="session_token"),
) -> dict:
    """Admin role from a valid token, confirmed against the user store."""
    if not _secret_configured():
        raise HTTPException(
            status_code=503,
            detail="Anduril is disabled until SECRET_KEY is set for the backend (the default JWT secret lets anyone forge an admin token)",
        )
    token = credentials.credentials if credentials else session_token
    payload = verify_token(token) if token else None
    if not payload:
        raise HTTPException(status_code=401, detail="Authentication required")
    user = load_users().get(payload.get("sub", ""))
    if not user or not user.get("is_active", True) or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


async def _call(method: str, path: str, json: Any = None, params: Optional[dict] = None, timeout: float = 30.0) -> Any:
    token = _read_token()
    if not token:
        raise HTTPException(status_code=503, detail=f"Anduril is not enabled. On the host, run: {ENABLE_COMMAND}")
    try:
        async with httpx.AsyncClient(base_url=ANDURIL_URL, timeout=timeout) as client:
            resp = await client.request(method, path, json=json, params=params, headers={"X-Anduril-Token": token})
    except httpx.HTTPError as exc:
        logger.warning("Anduril unreachable at %s: %s", ANDURIL_URL, exc)
        raise HTTPException(status_code=503, detail=f"Anduril is not running. On the host, run: {ENABLE_COMMAND}")
    try:
        data = resp.json()
    except ValueError:
        data = {"detail": resp.text}
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=data.get("detail", data) if isinstance(data, dict) else data)
    return data


def _active_jobs() -> list[str]:
    try:
        jobs = JobStorage().list_jobs(status=JobStatus.RUNNING, limit=50)
    except Exception:  # noqa: BLE001 - an unreachable database must not hide the guard
        logger.exception("Could not list running jobs for the Anduril guard")
        return []
    return [j.case_number for j in jobs]


@router.get("/status")
async def anduril_status(request: Request) -> dict:
    """Whether Anduril can be used, and what to do if not. Safe to call unauthenticated."""
    status = {
        "enabled": False,
        "secret_configured": _secret_configured(),
        "token_present": _read_token() is not None,
        "reachable": False,
        "enable_command": ENABLE_COMMAND,
        "reason": None,
    }
    if not status["secret_configured"]:
        status["reason"] = "secret_key"
        return status
    if not status["token_present"]:
        status["reason"] = "not_enabled"
        return status
    try:
        health = await _call("GET", "/health", timeout=5)
        status.update(reachable=True, enabled=True, socket=health.get("socket"), project=health.get("project"))
    except HTTPException as exc:
        status["reason"] = "unreachable" if exc.status_code == 503 else "error"
        status["detail"] = exc.detail
    return status


@router.get("/containers")
async def list_containers(_: dict = Depends(require_anduril_admin)) -> Any:
    return await _call("GET", "/containers")


@router.get("/images")
async def list_images(_: dict = Depends(require_anduril_admin)) -> Any:
    return await _call("GET", "/images")


@router.get("/containers/{name}/logs")
async def container_logs(name: str, tail: int = 200, _: dict = Depends(require_anduril_admin)) -> Any:
    return await _call("GET", f"/containers/{name}/logs", params={"tail": max(1, min(tail, 5000))})


@router.get("/containers/{name}/stats")
async def container_stats(name: str, _: dict = Depends(require_anduril_admin)) -> Any:
    return await _call("GET", f"/containers/{name}/stats")


@router.post("/containers/{name}/{action}", status_code=202)
async def container_action(name: str, action: str, body: ActionRequest, user: dict = Depends(require_anduril_admin)) -> Any:
    if action not in ("start", "stop", "restart", "update", "recreate"):
        raise HTTPException(status_code=404, detail="Unknown action")
    if action != "start" and name in JOB_SENSITIVE_SERVICES and not body.force:
        running = _active_jobs()
        if running:
            raise HTTPException(
                status_code=409,
                detail={"message": f"Refusing to {action} {name} while jobs are running: {', '.join(running)}", "busy": True},
            )
    logger.info("Anduril: %s requested %s on %s (force=%s)", user.get("username"), action, name, body.force)
    return await _call("POST", f"/containers/{name}/{action}", json={"force": body.force})


@router.post("/images/pull", status_code=202)
async def pull_image(body: PullRequest, user: dict = Depends(require_anduril_admin)) -> Any:
    logger.info("Anduril: %s requested pull of %s", user.get("username"), body.ref)
    return await _call("POST", "/images/pull", json={"ref": body.ref})


@router.post("/images/remove", status_code=202)
async def remove_image(body: RemoveImageRequest, user: dict = Depends(require_anduril_admin)) -> Any:
    logger.info("Anduril: %s requested removal of image %s", user.get("username"), body.id)
    return await _call("POST", "/images/remove", json={"id": body.id})


@router.post("/images/prune", status_code=202)
async def prune_images(user: dict = Depends(require_anduril_admin)) -> Any:
    logger.info("Anduril: %s requested image prune", user.get("username"))
    return await _call("POST", "/images/prune", json={})


@router.get("/ops")
async def list_ops(_: dict = Depends(require_anduril_admin)) -> Any:
    return await _call("GET", "/ops")


@router.get("/ops/{op_id}")
async def get_op(op_id: str, _: dict = Depends(require_anduril_admin)) -> Any:
    return await _call("GET", f"/ops/{op_id}")
