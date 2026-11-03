#!/usr/bin/env python3
"""Dernvale lab agent: lets the Dernvale web UI drive ./lab.sh on this machine.

The lab's containers and VMs live on the host (Vagrant, VirtualBox, Tart and the
Keychain can't be reached from inside Dernvale's containers), so the backend
calls this small HTTP service instead. It accepts only the lab commands in
COMMANDS, with validated arguments, and runs them one at a time through lab.sh
with no terminal attached.

Authentication: a random token, written to TOKEN_FILE (inside /tmp/dernvale,
which the backend already mounts read-only) and required in X-Lab-Token. The
agent binds to the address lab.sh passes (loopback on macOS), so only this
machine and its containers can reach it.

Standard library only; started by `./lab.sh agent start`.
"""
from __future__ import annotations

import argparse
import hmac
import json
import logging
import os
import re
import secrets
import signal
import subprocess
import threading
import time
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import mordor_api  # the Mordor page's lab (src/mordor/lab, ported from Archer)

LAB_ROOT = Path(__file__).resolve().parent.parent
LAB_SH = LAB_ROOT / "lab.sh"
DEFAULT_TOKEN_FILE = Path("/tmp/dernvale/.lab-agent/token")
RUN_DIR = Path.home() / ".config" / "dernvale-lab" / "run" / "agent-runs"
KEEP_RUNS = 30
VERSION = "1"

log = logging.getLogger("lab_agent")

NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
DATASET = re.compile(r"^[a-z0-9_]+(/[a-z0-9_]+)*$")


def _one_of(*choices: str):
    def check(args: list[str]) -> list[str]:
        if len(args) != 1 or args[0] not in choices:
            raise ValueError(f"expected one of: {', '.join(choices)}")
        return args
    return check


def _none(args: list[str]) -> list[str]:
    if args:
        raise ValueError("takes no arguments")
    return args


def _collect(args: list[str]) -> list[str]:
    if not args or args[0] not in ("bash", "python", "powershell", "all"):
        raise ValueError("first argument: bash, python, powershell or all")
    targets = args[1:]
    if not all(NAME.match(t) for t in targets):
        raise ValueError("target names may only use letters, digits, _ . -")
    # lab.sh takes the targets as one space-separated argument.
    return [args[0], " ".join(targets)] if targets else [args[0]]


def _datasets(args: list[str]) -> list[str]:
    if not all(DATASET.match(a) for a in args):
        raise ValueError("dataset paths look like apt29/day1")
    return args


def _capture(args: list[str]) -> list[str]:
    if len(args) == 1 and NAME.match(args[0]):
        return args
    if len(args) == 3 and args[0] == "custom" and NAME.match(args[1]):
        techs = args[2].split(",")
        if techs and all(TECHNIQUE.match(t) for t in techs):
            return args
    raise ValueError("a preset name, or: custom <name> <T1059.001,T1003,...>")


def _record(args: list[str]) -> list[str]:
    """As _capture, with an optional run name after the techniques (Deploy names its runs)."""
    if len(args) == 4 and args[0] == "custom" and NAME.match(args[3]):
        return _capture(args[:3]) + [args[3]]
    return _capture(args)


def _run_name(args: list[str]) -> list[str]:
    if len(args) == 1 and NAME.match(args[0]):
        return args
    raise ValueError("a recording's run name")


VM_ACTIONS = ("create", "start", "stop", "delete", "status")

# command -> (argument validator, long-running). Everything else is refused:
# install and configure need a person at a terminal (sudo, licence prompts).
COMMANDS = {
    "check": (_none, False),
    "status": (_none, False),
    "dernvale-env": (_none, False),
    "linux-targets": (_one_of("up", "down", "reset", "status"), True),
    "linux-vm": (_one_of(*VM_ACTIONS), True),
    "macos-vm": (_one_of(*VM_ACTIONS), True),
    "windows-vm": (_one_of("create", "adopt", "start", "stop", "provision", "delete", "status"), True),
    "gandalf-collect": (_collect, True),
    "mordor-download": (_datasets, True),
    "mordor-sensor": (_none, True),
    "mordor-capture": (_capture, True),
    "mordor-record": (_record, True),
    "mordor-dataset": (_run_name, True),
    "teardown": (_none, True),
}
# Commands that change or destroy something; the UI confirms these first.
DESTRUCTIVE = {"teardown", ("linux-targets", "reset"), ("linux-vm", "delete"),
               ("macos-vm", "delete"), ("windows-vm", "delete")}


def lab_env() -> dict[str, str]:
    env = dict(os.environ)
    # The UI has already asked the person; lab.sh must never wait on a prompt.
    env.update(LAB_YES="1", LAB_FORCE="1", LAB_HEADLESS="1", LAB_KEEP_PASSWORD="1", TERM="dumb")
    # LAB_FORCE would also say yes to the Gandalf workarounds; the UI tests Gandalf as shipped.
    env.setdefault("GANDALF_WORKAROUNDS", "0")
    env.pop("LAB_PASSWORD", None)
    return env


def run_lab(args: list[str], stdin: str | None = None, timeout: int = 60) -> tuple[int, str]:
    proc = subprocess.run(["bash", str(LAB_SH), *args], input=stdin, capture_output=True,
                          text=True, env=lab_env(), cwd=LAB_ROOT, timeout=timeout,
                          stdin=None if stdin is not None else subprocess.DEVNULL)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


class Runner:
    """Runs lab commands one at a time; output goes to a log file per run."""

    def __init__(self) -> None:
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.runs: dict[str, dict] = {}
        self.current: tuple[str, subprocess.Popen] | None = None

    def busy(self) -> dict | None:
        with self.lock:
            return self.runs[self.current[0]] if self.current else None

    def start(self, command: str, args: list[str]) -> dict:
        with self.lock:
            if self.current:
                raise RuntimeError(f"'{self.runs[self.current[0]]['label']}' is still running")
            run_id = uuid.uuid4().hex[:12]
            logfile = RUN_DIR / f"{run_id}.log"
            run = {"id": run_id, "command": command, "args": args,
                   "label": " ".join([command, *args]), "status": "running",
                   "exit_code": None, "started": time.time(), "finished": None}
            out = logfile.open("wb")
            proc = subprocess.Popen(["bash", str(LAB_SH), command, *args], stdin=subprocess.DEVNULL,
                                    stdout=out, stderr=subprocess.STDOUT, env=lab_env(),
                                    cwd=LAB_ROOT, start_new_session=True)
            out.close()
            self.runs[run_id] = run
            self.current = (run_id, proc)
            self._trim()
        threading.Thread(target=self._wait, args=(run_id, proc), daemon=True).start()
        log.info("run %s: %s", run_id, run["label"])
        return run

    def start_python(self, label: str, fn) -> dict:
        """A Mordor-page job (src.mordor.lab): fn(say) in a thread, its lines in the run's log."""
        with self.lock:
            if self.current:
                raise RuntimeError(f"'{self.runs[self.current[0]]['label']}' is still running")
            run_id = uuid.uuid4().hex[:12]
            run = {"id": run_id, "command": "mordor", "args": [], "label": label, "status": "running",
                   "exit_code": None, "started": time.time(), "finished": None}
            self.runs[run_id] = run
            self.current = (run_id, None)
            self._trim()
        logfile = RUN_DIR / f"{run_id}.log"

        def say(line: str) -> None:
            with logfile.open("a", encoding="utf-8") as fh:
                fh.write(f"{time.strftime('%H:%M:%S')}  {line}\n")

        def work() -> None:
            code = 0
            try:
                fn(say)
                say("Done")
            except Exception as exc:  # noqa: BLE001 — a job must never take the agent down
                code = 1
                say(f"Failed: {getattr(exc, 'message', None) or exc}")
                if getattr(exc, "detail", ""):
                    say(exc.detail[:500])
            with self.lock:
                run.update(exit_code=code, finished=time.time(),
                           status="succeeded" if code == 0 else "failed")
                self.current = None
            log.info("run %s finished: %s", run_id, run["status"])

        say(label)
        threading.Thread(target=work, daemon=True).start()
        log.info("run %s: %s", run_id, label)
        return run

    def _wait(self, run_id: str, proc: subprocess.Popen) -> None:
        code = proc.wait()
        with self.lock:
            run = self.runs[run_id]
            run["exit_code"] = code
            run["finished"] = time.time()
            if run["status"] == "running":
                run["status"] = "succeeded" if code == 0 else "failed"
            self.current = None
        log.info("run %s finished: %s (%s)", run_id, run["status"], code)

    def cancel(self, run_id: str) -> dict:
        with self.lock:
            if not self.current or self.current[0] != run_id:
                raise KeyError(run_id)
            proc = self.current[1]
            if proc is None:
                raise KeyError(run_id)  # a Mordor-page job runs in-process; it can't be cancelled
            self.runs[run_id]["status"] = "cancelled"
        # The whole group: lab.sh, docker, vagrant, ssh relays.
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        threading.Timer(20, self._kill, args=(proc,)).start()
        return self.runs[run_id]

    @staticmethod
    def _kill(proc: subprocess.Popen) -> None:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def get(self, run_id: str, offset: int = 0) -> dict:
        with self.lock:
            run = dict(self.runs[run_id])
        logfile = RUN_DIR / f"{run_id}.log"
        with logfile.open("rb") as fh:
            fh.seek(offset)
            data = fh.read(256 * 1024)
        run["output"] = data.decode("utf-8", "replace")
        run["offset"] = offset + len(data)
        return run

    def list(self) -> list[dict]:
        with self.lock:
            return sorted(self.runs.values(), key=lambda r: r["started"], reverse=True)

    def _trim(self) -> None:
        done = sorted((r for r in self.runs.values() if r["status"] != "running"), key=lambda r: r["started"])
        for run in done[:max(0, len(self.runs) - KEEP_RUNS)]:
            self.runs.pop(run["id"], None)
            (RUN_DIR / f"{run['id']}.log").unlink(missing_ok=True)


def parse_state(text: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line and not line.startswith("["))


class Handler(BaseHTTPRequestHandler):
    server_version = "DernvaleLabAgent/" + VERSION
    token: str = ""
    runner: Runner

    def log_message(self, fmt: str, *args) -> None:
        log.debug("%s %s", self.address_string(), fmt % args)

    def _send(self, status: int, body: dict | list) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    @staticmethod
    def _lab_config() -> dict:
        code, out = run_lab(["state"])
        return {k: v for k, v in parse_state(out).items() if k.isupper()} if code == 0 else {}

    def _authorised(self) -> bool:
        given = self.headers.get("X-Lab-Token", "")
        if given and hmac.compare_digest(given, self.token):
            return True
        self._send(HTTPStatus.UNAUTHORIZED, {"error": "missing or wrong X-Lab-Token"})
        return False

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length > 64 * 1024:
            raise ValueError("request too large")
        data = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(data, dict):
            raise ValueError("expected a JSON object")
        return data

    def do_GET(self) -> None:
        if not self._authorised():
            return
        url = urlparse(self.path)
        parts = [p for p in url.path.split("/") if p]
        if parts == ["health"]:
            return self._send(200, {"ok": True, "version": VERSION})
        if parts == ["state"]:
            code, out = run_lab(["state"])
            if code:
                return self._send(500, {"error": out})
            state = parse_state(out)
            busy = self.runner.busy()
            return self._send(200, {
                "host": {k: state.get(k) for k in ("profile", "label", "os_version", "ram_gb", "docker", "vm_tool", "repo_root")},
                "password_set": state.get("password_set") == "yes",
                "password_default": state.get("password_default") == "yes",
                "default_password": state.get("default_password", ""),
                "linux_containers": state.get("linux_containers", "").split(),
                "mordor_presets": state.get("mordor_presets", "").split(),
                "config": {k: v for k, v in state.items() if k.isupper()},
                "commands": {name: {"long_running": lr} for name, (_, lr) in COMMANDS.items()},
                "destructive": sorted(" ".join(d) if isinstance(d, tuple) else d for d in DESTRUCTIVE),
                "busy": busy,
            })
        if parts == ["runs"]:
            return self._send(200, self.runner.list())
        if parts and parts[0] == "mordor":
            mordor_api.configure(self._lab_config)
            return self._send(*mordor_api.handle_get(parts[1:], parse_qs(url.query), self.runner.busy()))
        if len(parts) == 2 and parts[0] == "runs":
            try:
                offset = int(parse_qs(url.query).get("offset", ["0"])[0])
                return self._send(200, self.runner.get(parts[1], max(0, offset)))
            except (KeyError, FileNotFoundError):
                return self._send(404, {"error": "no such run"})
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        if not self._authorised():
            return
        parts = [p for p in urlparse(self.path).path.split("/") if p]
        try:
            body = self._body()
        except (ValueError, json.JSONDecodeError) as exc:
            return self._send(400, {"error": str(exc)})

        if parts == ["config"]:
            settings = body.get("settings")
            if not isinstance(settings, dict) or not settings:
                return self._send(400, {"error": "settings: {KEY: value}"})
            if not all(isinstance(k, str) and isinstance(v, (str, int)) and "\n" not in str(v) for k, v in settings.items()):
                return self._send(400, {"error": "settings must be strings or numbers on one line"})
            code, out = run_lab(["set-config", *(f"{k}={v}" for k, v in settings.items())])
            return self._send(200 if code == 0 else 400, {"ok": code == 0, "output": out})

        if parts == ["password"]:
            password = body.get("password")
            if not isinstance(password, str) or "\n" in password:
                return self._send(400, {"error": "password: string"})
            code, out = run_lab(["set-password"], stdin=password + "\n")
            return self._send(200 if code == 0 else 400, {"ok": code == 0, "output": out})

        if parts == ["run"]:
            command = body.get("command")
            args = body.get("args") or []
            if command not in COMMANDS:
                return self._send(400, {"error": f"command must be one of: {', '.join(COMMANDS)}"})
            if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
                return self._send(400, {"error": "args: list of strings"})
            try:
                args = COMMANDS[command][0](args)
            except ValueError as exc:
                return self._send(400, {"error": f"{command}: {exc}"})
            try:
                return self._send(202, self.runner.start(command, args))
            except RuntimeError as exc:
                return self._send(409, {"error": str(exc)})

        if parts and parts[0] == "mordor":
            mordor_api.configure(self._lab_config)
            return self._send(*mordor_api.handle_post(parts[1:], body, self.runner))

        if len(parts) == 3 and parts[0] == "runs" and parts[2] == "cancel":
            try:
                return self._send(200, self.runner.cancel(parts[1]))
            except KeyError:
                return self._send(409, {"error": "that run isn't running"})

        self._send(404, {"error": "not found"})


def write_token(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    token = secrets.token_urlsafe(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(token)
    return token


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5691)
    parser.add_argument("--token-file", type=Path, default=DEFAULT_TOKEN_FILE)
    opts = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    Handler.token = write_token(opts.token_file)
    Handler.runner = Runner()
    server = ThreadingHTTPServer((opts.bind, opts.port), Handler)
    log.info("lab agent on %s:%s (token in %s)", opts.bind, opts.port, opts.token_file)
    # `./lab.sh agent stop` sends SIGTERM; exit through finally so the token goes too.
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        opts.token_file.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
