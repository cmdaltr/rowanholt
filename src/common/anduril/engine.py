"""Minimal Docker Engine API client over a unix socket (stdlib only).

Docker Desktop and OrbStack both expose the same Engine API, so nothing here
is runtime-specific. Kept dependency-free so the Anduril image stays small and
the host CLI runs without extra packages.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import struct
from pathlib import Path
from typing import Any, Iterator, Optional
from urllib.parse import quote, urlencode


class EngineError(Exception):
    """The Engine API returned an error or could not be reached."""

    def __init__(self, message: str, status: int = 0) -> None:
        super().__init__(message)
        self.status = status


class EngineUnavailable(EngineError):
    """No Docker socket was found or it could not be opened."""

    def __init__(self, message: str, socket_path: Optional[str] = None, permission: bool = False) -> None:
        super().__init__(message)
        self.socket_path = socket_path
        self.permission = permission


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.socket_path)
        self.sock = sock


def candidate_sockets() -> list[str]:
    """Socket paths to try, in order: DOCKER_HOST, OrbStack, Docker Desktop, default."""
    paths = []
    docker_host = os.environ.get("DOCKER_HOST", "")
    if docker_host.startswith("unix://"):
        paths.append(docker_host[len("unix://"):])
    home = Path.home()
    paths += [
        str(home / ".orbstack" / "run" / "docker.sock"),
        str(home / ".docker" / "run" / "docker.sock"),
        "/var/run/docker.sock",
    ]
    seen = []
    for p in paths:
        if p not in seen:
            seen.append(p)
    return seen


def reachable_sockets() -> list[str]:
    """Every candidate socket that currently accepts a connection."""
    found = []
    for path in candidate_sockets():
        if not os.path.exists(path):
            continue
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(2)
            sock.connect(path)
            found.append(os.path.realpath(path))
        except OSError:
            continue
        finally:
            sock.close()
    return list(dict.fromkeys(found))


def find_socket(explicit: Optional[str] = None) -> str:
    """Return the first socket that accepts a connection.

    Raises EngineUnavailable with ``permission=True`` when a socket exists but
    the current user may not open it, so callers can prompt for access.
    """
    candidates = [explicit] if explicit else candidate_sockets()
    denied = None
    for path in candidates:
        if not os.path.exists(path):
            continue
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(2)
            sock.connect(path)
            return path
        except PermissionError:
            denied = path
        except OSError:
            continue
        finally:
            sock.close()
    if denied:
        raise EngineUnavailable(f"Permission denied opening {denied}", socket_path=denied, permission=True)
    raise EngineUnavailable("No running Docker engine found (tried: " + ", ".join(candidates) + ")")


class Engine:
    """Thin wrapper over the Engine API endpoints Rowanholt needs."""

    def __init__(self, socket_path: Optional[str] = None, timeout: float = 30.0) -> None:
        self.socket_path = find_socket(socket_path)
        self.timeout = timeout

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[dict] = None,
        body: Any = None,
        timeout: Optional[float] = None,
    ) -> http.client.HTTPResponse:
        if params:
            path = f"{path}?{urlencode(params)}"
        conn = _UnixHTTPConnection(self.socket_path, timeout or self.timeout)
        headers = {"Host": "docker"}
        payload = None
        if body is not None:
            payload = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        try:
            conn.request(method, path, body=payload, headers=headers)
            resp = conn.getresponse()
        except PermissionError as exc:
            raise EngineUnavailable(str(exc), socket_path=self.socket_path, permission=True) from exc
        except OSError as exc:
            raise EngineError(f"Docker engine request failed: {exc}") from exc
        if resp.status >= 400:
            raw = resp.read()
            try:
                message = json.loads(raw).get("message", raw.decode(errors="replace"))
            except ValueError:
                message = raw.decode(errors="replace")
            conn.close()
            raise EngineError(message.strip(), status=resp.status)
        return resp

    def json(self, method: str, path: str, **kwargs: Any) -> Any:
        resp = self._request(method, path, **kwargs)
        raw = resp.read()
        return json.loads(raw) if raw.strip() else None

    def stream_json(self, method: str, path: str, **kwargs: Any) -> Iterator[dict]:
        """Yield each JSON object of a progress stream (pull, build)."""
        resp = self._request(method, path, **kwargs)
        buf = b""
        while True:
            chunk = resp.read1(65536) if hasattr(resp, "read1") else resp.read(65536)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if line.strip():
                    yield json.loads(line)
        if buf.strip():
            yield json.loads(buf)

    # --- containers ---------------------------------------------------------

    def containers(self) -> list[dict]:
        return self.json("GET", "/containers/json", params={"all": "1"})

    def inspect_container(self, cid: str) -> dict:
        return self.json("GET", f"/containers/{quote(cid)}/json")

    def top(self, cid: str) -> dict:
        return self.json("GET", f"/containers/{quote(cid)}/top", params={"ps_args": "-eo pid,args"})

    def start(self, cid: str) -> None:
        self.json("POST", f"/containers/{quote(cid)}/start")

    def stop(self, cid: str, timeout: int = 30) -> None:
        self.json("POST", f"/containers/{quote(cid)}/stop", params={"t": str(timeout)}, timeout=timeout + 30)

    def restart(self, cid: str, timeout: int = 30) -> None:
        self.json("POST", f"/containers/{quote(cid)}/restart", params={"t": str(timeout)}, timeout=timeout + 60)

    def rename(self, cid: str, name: str) -> None:
        self.json("POST", f"/containers/{quote(cid)}/rename", params={"name": name})

    def remove_container(self, cid: str) -> None:
        self.json("DELETE", f"/containers/{quote(cid)}")

    def create_container(self, name: str, body: dict) -> str:
        return self.json("POST", "/containers/create", params={"name": name}, body=body)["Id"]

    def connect_network(self, network: str, cid: str, endpoint: dict) -> None:
        self.json("POST", f"/networks/{quote(network)}/connect", body={"Container": cid, "EndpointConfig": endpoint})

    def stats(self, cid: str) -> dict:
        return self.json("GET", f"/containers/{quote(cid)}/stats", params={"stream": "false"}, timeout=20)

    def logs(self, cid: str, tail: int = 200, tty: bool = False) -> str:
        resp = self._request(
            "GET",
            f"/containers/{quote(cid)}/logs",
            params={"stdout": "1", "stderr": "1", "timestamps": "1", "tail": str(tail)},
        )
        raw = resp.read()
        if tty:
            return raw.decode(errors="replace")
        # Non-TTY logs are multiplexed: 8-byte header (stream, 0, 0, 0, uint32 size).
        out, i = [], 0
        while i + 8 <= len(raw):
            size = struct.unpack(">I", raw[i + 4 : i + 8])[0]
            out.append(raw[i + 8 : i + 8 + size])
            i += 8 + size
        return b"".join(out).decode(errors="replace")

    # --- images -------------------------------------------------------------

    def images(self) -> list[dict]:
        return self.json("GET", "/images/json")

    def dangling_images(self) -> list[dict]:
        return self.json("GET", "/images/json", params={"filters": json.dumps({"dangling": ["true"]})})

    def inspect_image(self, ref: str) -> dict:
        return self.json("GET", f"/images/{quote(ref, safe='')}/json")

    def pull(self, image: str, tag: str) -> Iterator[dict]:
        return self.stream_json("POST", "/images/create", params={"fromImage": image, "tag": tag}, timeout=3600)

    def remove_image(self, image_id: str) -> list[dict]:
        # Never force: the engine refuses to remove an image a container still uses.
        return self.json("DELETE", f"/images/{quote(image_id, safe='')}")
