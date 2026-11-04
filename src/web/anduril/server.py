"""Anduril: Rowanholt's Docker administration service.

The only Rowanholt container that holds the Docker socket. It serves a small
JSON API on the internal admin network to the backend, which authenticates
with a token this process generates at start-up and writes to a volume only
the backend mounts. Every request goes through the ``anduril`` package's scope rules,
so the backend (and anything that compromises it) can act on Rowanholt
containers and images and nothing else.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import queue
import re
import secrets
import threading
import time
import uuid
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlparse

from anduril import BusyError, DockerAdmin, EngineError, EngineUnavailable, ScopeError
from anduril.scope import check_action, container_service

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("rowanholt.anduril")

TOKEN_PATH = Path(os.environ.get("ANDURIL_TOKEN_PATH", "/run/anduril/token"))
PORT = int(os.environ.get("ANDURIL_PORT", "5690"))
BIND = os.environ.get("ANDURIL_BIND", "0.0.0.0")
MAX_BODY = 64 * 1024
MAX_OPS = 50
CONTAINER_ACTIONS = ("start", "stop", "restart", "update", "recreate")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class Op:
    """A queued mutating operation; the UI polls it by id."""

    def __init__(self, action: str, target: str, fn: Callable[[Callable[[str], None]], Any]) -> None:
        self.id = uuid.uuid4().hex[:12]
        self.action = action
        self.target = target
        self.fn = fn
        self.state = "queued"
        self.result: Any = None
        self.error: Optional[str] = None
        self.log: list[str] = []
        self.created = time.time()
        self.finished: Optional[float] = None

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "action": self.action,
            "target": self.target,
            "state": self.state,
            "result": self.result,
            "error": self.error,
            "log": self.log[-200:],
            "created": self.created,
            "finished": self.finished,
        }


class OpRunner:
    """Runs mutating operations one at a time so they cannot race each other."""

    def __init__(self) -> None:
        self.ops: "OrderedDict[str, Op]" = OrderedDict()
        self.queue: "queue.Queue[Op]" = queue.Queue()
        self.lock = threading.Lock()
        threading.Thread(target=self._loop, daemon=True).start()

    def submit(self, op: Op) -> Op:
        with self.lock:
            self.ops[op.id] = op
            while len(self.ops) > MAX_OPS:
                oldest = next(iter(self.ops))
                if self.ops[oldest].state in ("queued", "running"):
                    break
                self.ops.pop(oldest)
        self.queue.put(op)
        return op

    def get(self, op_id: str) -> Optional[Op]:
        return self.ops.get(op_id)

    def _loop(self) -> None:
        while True:
            op = self.queue.get()
            op.state = "running"
            logger.info("op %s: %s %s", op.id, op.action, op.target)
            try:
                op.result = op.fn(op.log.append)
                op.state = "done"
            except (ScopeError, BusyError, EngineError) as exc:
                op.error = str(exc)
                op.state = "failed"
            except Exception as exc:  # noqa: BLE001 - surface anything to the UI
                logger.exception("op %s failed", op.id)
                op.error = f"{type(exc).__name__}: {exc}"
                op.state = "failed"
            op.finished = time.time()


def write_token() -> str:
    token = secrets.token_urlsafe(32)
    TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = TOKEN_PATH.with_suffix(".tmp")
    tmp.write_text(token)
    tmp.chmod(0o640)
    tmp.replace(TOKEN_PATH)
    return token


TOKEN = ""
RUNNER: Optional[OpRunner] = None


def admin() -> DockerAdmin:
    return DockerAdmin()


class Handler(BaseHTTPRequestHandler):
    server_version = "rowanholt-anduril"

    def log_message(self, fmt: str, *args: Any) -> None:
        logger.info("%s %s", self.address_string(), fmt % args)

    # --- plumbing -----------------------------------------------------------

    def _send(self, status: int, payload: Any) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorised(self) -> bool:
        supplied = self.headers.get("X-Anduril-Token", "")
        return bool(TOKEN) and hmac.compare_digest(supplied.encode(), TOKEN.encode())

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise ValueError("Request body too large")
        raw = self.rfile.read(length) if length else b""
        data = json.loads(raw) if raw.strip() else {}
        if not isinstance(data, dict):
            raise ValueError("Body must be a JSON object")
        return data

    def _dispatch(self, method: str) -> None:
        if not self._authorised():
            self._send(401, {"detail": "Invalid Anduril token"})
            return
        url = urlparse(self.path)
        parts = [p for p in url.path.split("/") if p]
        query = {k: v[-1] for k, v in parse_qs(url.query).items()}
        try:
            status, payload = self._route(method, parts, query)
        except ScopeError as exc:
            status, payload = 403, {"detail": str(exc)}
        except BusyError as exc:
            status, payload = 409, {"detail": str(exc), "busy": True}
        except EngineUnavailable as exc:
            status, payload = 503, {"detail": str(exc)}
        except EngineError as exc:
            status, payload = (404 if exc.status == 404 else 502), {"detail": str(exc)}
        except (ValueError, KeyError) as exc:
            status, payload = 400, {"detail": f"Bad request: {exc}"}
        self._send(status, payload)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    # --- routes -------------------------------------------------------------

    def _route(self, method: str, parts: list[str], query: dict) -> tuple[int, Any]:
        if method == "GET":
            if parts == ["health"]:
                a = admin()
                return 200, {"ok": True, "socket": a.engine.socket_path, "project": a.project}
            if parts == ["containers"]:
                return 200, admin().list_containers()
            if parts == ["images"]:
                return 200, admin().list_images()
            if parts == ["ops"]:
                return 200, [op.as_dict() for op in reversed(RUNNER.ops.values())]
            if len(parts) == 2 and parts[0] == "ops":
                op = RUNNER.get(parts[1])
                return (200, op.as_dict()) if op else (404, {"detail": "Unknown operation"})
            if len(parts) == 3 and parts[0] == "containers" and parts[2] in ("logs", "stats"):
                name = _name(parts[1])
                if parts[2] == "logs":
                    return 200, {"name": name, "logs": admin().logs(name, int(query.get("tail", 200)))}
                return 200, admin().stats(name)
            return 404, {"detail": "Not found"}

        body = self._body()
        if len(parts) == 3 and parts[0] == "containers" and parts[2] in CONTAINER_ACTIONS:
            name, action, force = _name(parts[1]), parts[2], bool(body.get("force"))
            a = admin()
            target = a.resolve(name)  # refuse out-of-scope names before queueing
            check_action(container_service(target), action, [] if action == "start" else a.job_processes(), force)
            fns = {
                "start": lambda log: admin().start(name),
                "stop": lambda log: admin().stop(name, force=force),
                "restart": lambda log: admin().restart(name, force=force),
                "update": lambda log: admin().update(name, force=force, progress=log),
                "recreate": lambda log: admin().recreate(name, force=force, progress=log),
            }
            return 202, RUNNER.submit(Op(action, name, fns[action])).as_dict()
        if parts == ["images", "pull"]:
            ref = admin().validate_pull(str(body["ref"]))
            return 202, RUNNER.submit(Op("pull", ref, lambda log: admin().pull(ref, progress=log))).as_dict()
        if parts == ["images", "remove"]:
            image_id = str(body["id"])
            admin().validate_remove(image_id)
            return 202, RUNNER.submit(Op("remove-image", image_id, lambda log: admin().remove_image(image_id))).as_dict()
        if parts == ["images", "prune"]:
            return 202, RUNNER.submit(Op("prune", "rowanholt images", lambda log: admin().prune())).as_dict()
        return 404, {"detail": "Not found"}


def _name(raw: str) -> str:
    if not NAME_RE.match(raw):
        raise ValueError("Invalid container name")
    return raw


def main() -> None:
    global TOKEN, RUNNER
    TOKEN = write_token()
    RUNNER = OpRunner()
    try:
        logger.info("Docker engine at %s", admin().engine.socket_path)
    except EngineUnavailable as exc:
        logger.error("%s - is /var/run/docker.sock mounted?", exc)
    server = ThreadingHTTPServer((BIND, PORT), Handler)
    logger.info("Anduril listening on %s:%d", BIND, PORT)
    server.serve_forever()


if __name__ == "__main__":
    main()
