"""
Lab routes: configure and run the Rowanholt test lab (lab/) from the web UI.

The lab's containers and VMs run on the host, so the backend can't drive them
itself. These admin-only endpoints proxy to the lab agent (lab/agent/lab_agent.py),
which the person starts on the host with `./lab.sh agent start`; the agent
allowlists the lab commands and validates their arguments.
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import httpx
from fastapi import APIRouter, Cookie, Depends, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

try:
    from .auth.routes_simple import load_users
    from .auth.security import verify_token
    from .config import settings
except ImportError:
    from auth.routes_simple import load_users
    from auth.security import verify_token
    from config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/lab", tags=["lab"])

LAB_AGENT_URL = os.environ.get("LAB_AGENT_URL", "http://host.docker.internal:5691")
LAB_AGENT_TOKEN_PATH = Path(os.environ.get("LAB_AGENT_TOKEN_PATH", "/tmp/rowanholt/.lab-agent/token"))
DEFAULT_SECRET = "your-secret-key-change-in-production"
START_COMMAND = "./lab.sh agent start"

_bearer = HTTPBearer(auto_error=False)


class RunRequest(BaseModel):
    command: str
    args: List[str] = []


class ConfigRequest(BaseModel):
    settings: Dict[str, Union[str, int]]


class PasswordRequest(BaseModel):
    password: str


def _read_token() -> Optional[str]:
    try:
        token = LAB_AGENT_TOKEN_PATH.read_text().strip()
    except OSError:
        return None
    return token or None


async def require_lab_admin(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    session_token: Optional[str] = Cookie(None, alias="session_token"),
) -> dict:
    """Admin role from a valid token, confirmed against the user store."""
    if not settings.secret_key or settings.secret_key == DEFAULT_SECRET:
        raise HTTPException(
            status_code=503,
            detail="The lab is disabled until SECRET_KEY is set for the backend (the default JWT secret lets anyone forge an admin token)",
        )
    token = credentials.credentials if credentials else session_token
    payload = verify_token(token) if token else None
    if not payload:
        raise HTTPException(status_code=401, detail="Authentication required")
    user = load_users().get(payload.get("sub", ""))
    if not user or not user.get("is_active", True) or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


async def _agent(method: str, path: str, json: Optional[dict] = None, params: Optional[dict] = None) -> Any:
    token = _read_token()
    if not token:
        raise HTTPException(status_code=503, detail=f"The lab agent isn't running. On the host, run: {START_COMMAND}")
    try:
        async with httpx.AsyncClient(timeout=90.0) as client:
            resp = await client.request(method, f"{LAB_AGENT_URL}{path}", json=json, params=params,
                                        headers={"X-Lab-Token": token})
    except httpx.HTTPError as exc:
        logger.warning(f"Lab agent unreachable at {LAB_AGENT_URL}: {exc}")
        raise HTTPException(status_code=503, detail=f"The lab agent isn't reachable. On the host, run: {START_COMMAND}")
    if resp.status_code == 401:
        raise HTTPException(status_code=503, detail=f"The lab agent rejected the token; restart it: ./lab.sh agent stop && {START_COMMAND}")
    body = resp.json()
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=body.get("error") or body.get("output") or "Lab agent error")
    return body


@router.get("/status")
async def lab_status() -> dict:
    """Whether the lab agent is reachable (no auth: says nothing about the host)."""
    if not _read_token():
        return {"available": False, "reason": "agent_not_running", "start_command": START_COMMAND}
    try:
        await _agent("GET", "/health")
    except HTTPException as exc:
        return {"available": False, "reason": "agent_unreachable", "detail": exc.detail, "start_command": START_COMMAND}
    return {"available": True}


@router.get("/state")
async def lab_state(_: dict = Depends(require_lab_admin)) -> dict:
    """Host profile, lab settings, whether the lab password is stored, and any running command."""
    return await _agent("GET", "/state")


@router.put("/config")
async def lab_config(req: ConfigRequest, user: dict = Depends(require_lab_admin)) -> dict:
    """Change lab settings (lab.conf on the host)."""
    logger.info(f"Lab config change by {user.get('username')}: {sorted(req.settings)}")
    return await _agent("POST", "/config", json={"settings": req.settings})


@router.put("/password")
async def lab_password(req: PasswordRequest, user: dict = Depends(require_lab_admin)) -> dict:
    """Store the lab password (for the gandalf user on lab targets) in the host's keyring."""
    logger.info(f"Lab password set by {user.get('username')}")
    return await _agent("POST", "/password", json={"password": req.password})


@router.post("/run")
async def lab_run(req: RunRequest, user: dict = Depends(require_lab_admin)) -> dict:
    """Start a lab command; poll /runs/{id} for its output."""
    logger.info(f"Lab command by {user.get('username')}: {req.command} {' '.join(req.args)}")
    return await _agent("POST", "/run", json={"command": req.command, "args": req.args})


@router.get("/runs")
async def lab_runs(_: dict = Depends(require_lab_admin)) -> list:
    return await _agent("GET", "/runs")


@router.get("/runs/{run_id}")
async def lab_run_detail(run_id: str, offset: int = Query(0, ge=0), _: dict = Depends(require_lab_admin)) -> dict:
    """A run's status and its output from byte `offset` on."""
    if not run_id.isalnum():
        raise HTTPException(status_code=400, detail="Bad run id")
    return await _agent("GET", f"/runs/{run_id}", params={"offset": offset})


@router.post("/runs/{run_id}/cancel")
async def lab_run_cancel(run_id: str, user: dict = Depends(require_lab_admin)) -> dict:
    if not run_id.isalnum():
        raise HTTPException(status_code=400, detail="Bad run id")
    logger.info(f"Lab run {run_id} cancelled by {user.get('username')}")
    return await _agent("POST", f"/runs/{run_id}/cancel")
