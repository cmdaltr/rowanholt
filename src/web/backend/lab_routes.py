"""
Lab routes: configure and run the Rowanholt test lab (lab/) from the web UI.

The lab's containers and VMs run on the host, so the backend can't drive them
itself. These admin-only endpoints proxy to the lab agent (lab/agent/lab_agent.py),
which the person starts on the host with `./lab.sh agent start`; the agent
allowlists the lab commands and validates their arguments.

Consoles (FR-04): /consoles/{engine}/{name}/ws relays a VM's screen to noVNC in the browser. The
HTTP middleware doesn't see a websocket, so the route checks the caller itself, as
require_lab_admin does (a signed-in admin, locally too), before anything reaches the agent, and
again while it's open. It then asks the agent for a tunnel to that VM by name: the agent looks up
the VM's own VNC port and connects to it on the host's loopback, so nothing sent here can point
the relay at another host or port.
"""

import asyncio
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlsplit

import anyio
import httpx
from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from starlette.requests import HTTPConnection

try:
    from .auth import access
    from .auth.routes_simple import load_users
    from .auth.security import verify_token
    from .config import settings
except ImportError:
    from auth import access
    from auth.routes_simple import load_users
    from auth.security import verify_token
    from config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/lab", tags=["lab"])

LAB_AGENT_URL = os.environ.get("LAB_AGENT_URL", "http://host.docker.internal:5691")
LAB_AGENT_TOKEN_PATH = Path(os.environ.get("LAB_AGENT_TOKEN_PATH", "/tmp/rowanholt/.lab-agent/token"))
DEFAULT_SECRET = "your-secret-key-change-in-production"
START_COMMAND = "./lab.sh agent start"
RESTART_COMMAND = f"./lab.sh agent stop && {START_COMMAND}"

CONSOLE_ENGINES = ("tart", "utm")
CONSOLE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")  # lab_agent.NAME
CONSOLE_UPGRADE = "rowanholt-vnc"  # lab_agent.CONSOLE_UPGRADE
CONSOLE_RECHECK_SECONDS = 30
CONSOLE_CHUNK = 65536

_bearer = HTTPBearer(auto_error=False)


class RunRequest(BaseModel):
    command: str
    args: List[str] = []


class ConfigRequest(BaseModel):
    settings: Dict[str, Union[str, int]]


class PasswordRequest(BaseModel):
    password: str


class ConsoleUnavailable(Exception):
    """The lab agent wouldn't, or couldn't, open a tunnel to a VM's console."""


def _read_token() -> Optional[str]:
    try:
        token = LAB_AGENT_TOKEN_PATH.read_text().strip()
    except OSError:
        return None
    return token or None


def lab_admin(token: Optional[str]) -> dict:
    """The admin a sign-in token belongs to, confirmed against the user store, else HTTPException.
    Locally as on a server: the lab drives the host, so the local analyst's open API isn't enough."""
    if not settings.secret_key or settings.secret_key == DEFAULT_SECRET:
        raise HTTPException(
            status_code=503,
            detail="The lab is disabled until SECRET_KEY is set for the backend (the default JWT secret lets anyone forge an admin token)",
        )
    payload = verify_token(token) if token else None
    if not payload:
        raise HTTPException(status_code=401, detail="Authentication required")
    user = load_users().get(payload.get("sub", ""))
    if not user or not user.get("is_active", True) or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


async def require_lab_admin(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    session_token: Optional[str] = Cookie(None, alias="session_token"),
) -> dict:
    """FastAPI dependency: lab_admin() from the bearer token, else the session cookie."""
    return lab_admin(credentials.credentials if credentials else session_token)


def console_admin(websocket: HTTPConnection) -> Optional[dict]:
    """The admin opening a console websocket, or None. access.websocket_user first (the origin
    check, API token scopes, sign-in and admin areas in server mode), then lab_admin() on the same
    token, so a console needs a signed-in admin locally as well as on a server."""
    if access.websocket_user(websocket) is None:
        return None
    header = websocket.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else websocket.cookies.get("session_token")
    try:
        return lab_admin(token)
    except HTTPException:
        return None


def valid_console(engine: str, name: str) -> bool:
    """A console is named by its engine and VM name only, in the agent's own name format."""
    return engine in CONSOLE_ENGINES and bool(CONSOLE_NAME.match(name))


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
        raise HTTPException(status_code=503, detail=f"The lab agent rejected the token; restart it: {RESTART_COMMAND}")
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


@router.get("/consoles")
async def lab_consoles(_: dict = Depends(require_lab_admin)) -> dict:
    """The running VMs with a console (a VNC server on the host's loopback), passwords left out."""
    try:
        found = await _agent("GET", "/consoles")
    except HTTPException as exc:
        if exc.status_code == 404:  # an agent from before consoles
            return {"consoles": [], "detail": f"Restart the lab agent for consoles: {RESTART_COMMAND}"}
        raise
    return {"consoles": [{k: c.get(k) for k in ("engine", "name", "port", "auth")} for c in found]}


@router.get("/consoles/{engine}/{name}")
async def lab_console(engine: str, name: str, _: dict = Depends(require_lab_admin)) -> dict:
    """One VM's console, with the VNC password noVNC answers with (Tart's, new each run; UTM's is none)."""
    if not valid_console(engine, name):
        raise HTTPException(status_code=400, detail="Bad engine or VM name")
    for c in await _agent("GET", "/consoles"):
        if c.get("engine") == engine and c.get("name") == name:
            return {k: c.get(k) for k in ("engine", "name", "port", "auth", "password")}
    raise HTTPException(status_code=404, detail=f"{name} has no console. Start it from this page (one started before "
                                                "consoles existed needs a stop and a start); see lab/README.md")


def _agent_error(status: bytes, body: str) -> str:
    """What to tell the admin when the agent answered a tunnel request with something other than 101."""
    if status == b"401":
        return f"The lab agent rejected the token; restart it: {RESTART_COMMAND}"
    try:
        detail = json.loads(body).get("error") or ""
    except (ValueError, AttributeError):
        detail = ""
    if status == b"404" and detail == "not found":  # an agent from before consoles
        return f"This lab agent has no consoles; restart it: {RESTART_COMMAND}"
    return detail or f"The lab agent refused the console ({status.decode(errors='replace')})"


async def open_tunnel(engine: str, name: str) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """A raw byte tunnel to a VM's VNC server, through the lab agent's /consoles/<engine>/<name>/connect.
    engine and name have passed valid_console(); the agent finds the port and connects on loopback.
    The connection goes to the agent's own address (LAB_AGENT_URL) and nowhere else."""
    token = _read_token()
    if not token:
        raise ConsoleUnavailable(f"The lab agent isn't running. On the host, run: {START_COMMAND}")
    url = urlsplit(LAB_AGENT_URL)
    host, port = url.hostname or "", url.port or 80
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
    except (OSError, asyncio.TimeoutError) as exc:
        logger.warning(f"Lab agent unreachable at {LAB_AGENT_URL} for a console: {exc}")
        raise ConsoleUnavailable(f"The lab agent isn't reachable. On the host, run: {START_COMMAND}")
    request = (f"GET /consoles/{engine}/{name}/connect HTTP/1.1\r\nHost: {host}:{port}\r\n"
               f"X-Lab-Token: {token}\r\nConnection: Upgrade\r\nUpgrade: {CONSOLE_UPGRADE}\r\n\r\n")
    try:
        writer.write(request.encode())
        await writer.drain()
        # The agent lists the host's VMs before it answers: tart list, utmctl list
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 60)
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
        writer.close()
        raise ConsoleUnavailable(f"The lab agent didn't open the console: {exc!r}")
    status_line = head.split(b"\r\n", 1)[0].split()
    status = status_line[1] if len(status_line) > 1 else b""
    if status != b"101":
        try:
            body = (await asyncio.wait_for(reader.read(4096), 5)).decode("utf-8", "replace")
        except (OSError, asyncio.TimeoutError):
            body = ""
        writer.close()
        raise ConsoleUnavailable(_agent_error(status, body))
    return reader, writer


@router.websocket("/consoles/{engine}/{name}/ws")
async def lab_console_socket(websocket: WebSocket, engine: str, name: str) -> None:
    """A VM's VNC stream for noVNC: binary frames each way, relayed through the lab agent.

    Refused at the handshake, before the agent hears of it, unless the caller is a signed-in admin
    (console_admin) and the VM is named in the agent's format; checked again every
    CONSOLE_RECHECK_SECONDS while open, so a sign-out, an expired session or a demotion ends it.
    """
    user = console_admin(websocket)
    if user is None or not valid_console(engine, name):
        await websocket.close(code=1008)
        return
    who = user.get("username")
    try:
        reader, writer = await open_tunnel(engine, name)
    except ConsoleUnavailable as exc:
        # An admin: say why, in the close reason (a websocket's is at most 123 bytes)
        await websocket.accept()
        await websocket.close(code=1011, reason=str(exc).encode()[:120].decode(errors="ignore"))
        return
    offered = websocket.scope.get("subprotocols") or []
    await websocket.accept(subprotocol="binary" if "binary" in offered else None)
    logger.info(f"Lab console {engine}/{name} opened by {who}")

    async def browser_to_vm() -> None:
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                return
            if message.get("bytes"):
                writer.write(message["bytes"])
                await writer.drain()

    async def vm_to_browser() -> None:
        while True:
            data = await reader.read(CONSOLE_CHUNK)
            if not data:
                return
            await websocket.send_bytes(data)

    async def still_admin() -> None:
        while True:
            await asyncio.sleep(CONSOLE_RECHECK_SECONDS)
            if console_admin(websocket) is None:
                logger.info(f"Lab console {engine}/{name}: {who} is no longer a signed-in admin; closing")
                return

    # Whichever ends first (the browser leaves, the VM's server closes, the caller stops being an
    # admin) ends the other two; anyio, which Starlette runs on, so cancellation stays its own
    try:
        async with anyio.create_task_group() as group:
            async def until_done(step) -> None:
                try:
                    await step()
                except (OSError, WebSocketDisconnect, RuntimeError):
                    pass
                group.cancel_scope.cancel()

            for step in (browser_to_vm, vm_to_browser, still_admin):
                group.start_soon(until_done, step)
    finally:
        writer.close()
        try:
            await websocket.close()
        except (RuntimeError, WebSocketDisconnect):
            pass  # the browser closed it first
        logger.info(f"Lab console {engine}/{name} closed ({who})")
