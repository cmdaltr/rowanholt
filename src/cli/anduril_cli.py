"""
dernvale anduril - administer Dernvale's Docker containers and images.

Runs on the host against the Docker Desktop or OrbStack socket, applying the
same Dernvale-only scope as the Anduril service behind the web UI. Rebuilds
and enabling Anduril itself happen here because they need the compose files
on the host.
"""

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, List, Optional

# dernvale.py puts src/analysis first on sys.path, and its platform/ package
# shadows the stdlib module, so this file uses sys.platform instead.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))

from anduril import BusyError, DockerAdmin, EngineError, EngineUnavailable, ScopeError, find_socket  # noqa: E402
from anduril.scope import (  # noqa: E402
    ANDURIL_SERVICE,
    check_action,
    NAME_PREFIX,
    PROJECT,
    container_in_scope,
    container_service,
    image_is_built,
)

DEFAULT_SECRET = "your-secret-key-change-in-production"
CONFIG_FILES_LABEL = "com.docker.compose.project.config_files"
WORKING_DIR_LABEL = "com.docker.compose.project.working_dir"


class Aborted(Exception):
    """The user declined a prompt."""


# --- prompts and output --------------------------------------------------------


def confirm(question: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print(f"[!] {question} - refusing without --yes (no terminal to prompt on)")
        return False
    answer = input(f"[?] {question} [y/N] ").strip().lower()
    return answer in ("y", "yes")


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def table(rows: List[List[str]], headers: List[str]) -> None:
    try:
        from tabulate import tabulate

        print(tabulate(rows, headers=headers, tablefmt="simple"))
        return
    except ImportError:
        pass
    widths = [max(len(str(x)) for x in col) for col in zip(headers, *rows)] if rows else [len(h) for h in headers]
    print("  ".join(h.ljust(w) for h, w in zip(headers, widths)))
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print("  ".join(str(x).ljust(w) for x, w in zip(r, widths)))


# --- engine access (prompts for permissions) ---------------------------------------


def _start_runtime() -> Optional[List[str]]:
    """Command that starts a Docker runtime on this host, if one is installed."""
    if sys.platform == "darwin":
        if Path("/Applications/OrbStack.app").exists():
            return ["open", "-a", "OrbStack"]
        if Path("/Applications/Docker.app").exists():
            return ["open", "-a", "Docker"]
        return None
    if shutil.which("systemctl"):
        return ["sudo", "systemctl", "start", "docker"]
    return None


def get_admin(assume_yes: bool, socket_path: Optional[str] = None) -> DockerAdmin:
    """Connect to the engine hosting Dernvale, prompting to start it or to grant socket access."""
    try:
        return DockerAdmin.locate(socket_path)
    except EngineUnavailable as exc:
        if exc.permission:
            user = os.environ.get("USER", "your user")
            print(f"[!] Dernvale needs access to the Docker socket ({exc.socket_path}), and {user} cannot open it.")
            if sys.platform.startswith("linux") and shutil.which("usermod"):
                cmd = ["sudo", "usermod", "-aG", "docker", user]
                if confirm(f"Grant access by adding {user} to the docker group ({' '.join(cmd)})?", assume_yes):
                    subprocess.run(cmd, check=True)
                    print("[+] Done. Log out and back in (or run `newgrp docker`), then re-run this command.")
                raise Aborted()
            print("    Check the runtime's settings (Docker Desktop: Advanced > allow the default Docker socket; "
                  "OrbStack: Settings > System) or run with sudo.")
            raise Aborted()
        print(f"[!] {exc}")
        cmd = _start_runtime()
        if not cmd or not confirm(f"No Docker engine is running. Start it now ({' '.join(cmd)})?", assume_yes):
            raise Aborted()
        subprocess.run(cmd, check=True)
        print("[*] Waiting for the Docker engine", end="", flush=True)
        for _ in range(60):
            time.sleep(2)
            print(".", end="", flush=True)
            try:
                find_socket()
                print()
                return DockerAdmin.locate(socket_path)
            except EngineUnavailable:
                continue
        print()
        print("[!] The engine did not come up within two minutes.")
        raise Aborted()


def run_guarded(action: Callable[[bool], str], what: str, assume_yes: bool) -> None:
    """Run an action; if it would interrupt a job, ask before forcing it."""
    try:
        print(f"[+] {action(False)}")
    except BusyError as exc:
        print(f"[!] {exc}")
        # Never auto-confirmed by --yes: interrupting a job needs a person at the terminal.
        if not confirm(f"{what} anyway? The running job will be orphaned or killed", False):
            raise Aborted()
        print(f"[+] {action(True)}")


# --- compose (rebuild / enable / disable) -----------------------------------------


def compose_base(admin: DockerAdmin) -> List[str]:
    """`docker compose` with the files and directory the project was last brought up with.

    Re-using them keeps local overrides (such as the worker's concurrency=1
    file) in place; a plain `docker compose up` would drop them.
    """
    for c in admin.engine.containers():
        if not container_in_scope(c, admin.project):
            continue
        labels = c.get("Labels") or {}
        files = [f for f in labels.get(CONFIG_FILES_LABEL, "").split(",") if f]
        workdir = labels.get(WORKING_DIR_LABEL)
        if files and workdir:
            missing = [f for f in files if not Path(f).exists()]
            if missing:
                raise ScopeError(f"Compose files used to start Dernvale are missing: {', '.join(missing)}")
            cmd = ["docker", "compose", "-p", admin.project, "--project-directory", workdir]
            for f in files:
                cmd += ["-f", f]
            return cmd
    raise ScopeError("No Dernvale containers found to read the compose configuration from; start the stack first")


def compose(admin: DockerAdmin, *args: str) -> None:
    cmd = compose_base(admin) + list(args)
    print(f"[*] {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


def backend_secret_is_default(admin: DockerAdmin) -> bool:
    try:
        info = admin.engine.inspect_container(admin.resolve("backend")["Id"])
    except (ScopeError, EngineError):
        return True
    env = dict(e.split("=", 1) for e in info["Config"].get("Env") or [] if "=" in e)
    return env.get("SECRET_KEY", DEFAULT_SECRET) in ("", DEFAULT_SECRET)


def backend_has_anduril(admin: DockerAdmin) -> bool:
    try:
        info = admin.engine.inspect_container(admin.resolve("backend")["Id"])
    except (ScopeError, EngineError):
        return False
    return "dernvale-anduril" in ((info.get("NetworkSettings") or {}).get("Networks") or {})


# --- commands ------------------------------------------------------------------------


def cmd_status(admin: DockerAdmin, args: argparse.Namespace) -> None:
    rows = []
    for c in admin.list_containers():
        note = "job running" if c["job_processes"] else ("Anduril" if c["protected"] else "")
        rows.append([c["name"], c["service"], c["state"], c["status"], ", ".join(c["ports"]), note])
    print(f"Docker engine: {admin.engine.socket_path}  (project '{admin.project}', containers named {NAME_PREFIX}*)\n")
    table(rows, ["CONTAINER", "SERVICE", "STATE", "STATUS", "PORTS", "NOTE"])
    for c in admin.list_containers():
        for p in c["job_processes"]:
            print(f"\n[!] Elrond running in {c['name']}: {p}")
    enabled = any(c["service"] == ANDURIL_SERVICE and c["state"] == "running" for c in admin.list_containers())
    print(f"\nAnduril (web UI administration): {'enabled' if enabled else 'not enabled - run: dernvale anduril enable'}")


def cmd_images(admin: DockerAdmin, args: argparse.Namespace) -> None:
    rows = [
        [i["short_id"], ", ".join(i["tags"]) or "<none>", human_bytes(i["size"]), "built" if i["built"] else "upstream",
         ", ".join(i["used_by"]) or "-", ", ".join(i["shared_with"]) or "-"]
        for i in admin.list_images()
    ]
    table(rows, ["IMAGE", "TAGS", "SIZE", "SOURCE", "USED BY", "ALSO USED OUTSIDE DERNVALE"])


def cmd_logs(admin: DockerAdmin, args: argparse.Namespace) -> None:
    sys.stdout.write(admin.logs(args.name, args.tail))


def cmd_stats(admin: DockerAdmin, args: argparse.Namespace) -> None:
    names = args.names or [c["name"] for c in admin.list_containers() if c["state"] == "running"]
    rows = []
    for n in names:
        s = admin.stats(n)
        if not s.get("running"):
            rows.append([s["name"], "-", "-", "-", "-", "-"])
            continue
        rows.append([
            s["name"], f"{s['cpu_percent']}%",
            f"{human_bytes(s['memory_bytes'])} / {human_bytes(s['memory_limit'])}",
            str(s["pids"]),
            f"{human_bytes(s['net_rx'])} / {human_bytes(s['net_tx'])}",
            f"{human_bytes(s['block_read'])} / {human_bytes(s['block_write'])}",
        ])
    table(rows, ["CONTAINER", "CPU", "MEMORY", "PIDS", "NET RX/TX", "BLOCK R/W"])


def cmd_lifecycle(admin: DockerAdmin, args: argparse.Namespace) -> None:
    allow_self = True  # the host CLI may manage Anduril itself
    if args.command_name == "start":
        print(f"[+] {admin.start(args.name, allow_self=allow_self)}")
        return
    if args.command_name in ("stop", "restart") and not confirm(f"{args.command_name.title()} {args.name}?", args.yes):
        raise Aborted()
    fn = getattr(admin, args.command_name)
    run_guarded(lambda force: fn(args.name, force=force or args.force, allow_self=allow_self),
                args.command_name.title(), args.yes)


def cmd_update(admin: DockerAdmin, args: argparse.Namespace) -> None:
    if not confirm(f"Pull the latest image for {args.name} and recreate it if it changed?", args.yes):
        raise Aborted()
    run_guarded(lambda force: admin.update(args.name, force=force or args.force, progress=lambda m: print(f"    {m}")),
                "Update", args.yes)


def cmd_pull(admin: DockerAdmin, args: argparse.Namespace) -> None:
    image_id = admin.pull(args.ref, progress=lambda m: print(f"    {m}"))
    print(f"[+] Pulled {args.ref} ({image_id.split(':')[-1][:12]}). Run `dernvale anduril update <service>` to use it.")


def cmd_rmi(admin: DockerAdmin, args: argparse.Namespace) -> None:
    if not confirm(f"Remove image {args.image}?", args.yes):
        raise Aborted()
    print(f"[+] {admin.remove_image(args.image)}")


def cmd_prune(admin: DockerAdmin, args: argparse.Namespace) -> None:
    if not confirm("Remove dangling images built for Dernvale?", args.yes):
        raise Aborted()
    r = admin.prune()
    print(f"[+] Removed {len(r['removed'])} image(s), freed {human_bytes(r['freed_bytes'])}")
    for s in r["skipped"]:
        print(f"    skipped {s}")


def cmd_rebuild(admin: DockerAdmin, args: argparse.Namespace) -> None:
    c = admin.resolve(args.service)
    service = container_service(c)
    image = next((i for i in admin.engine.images() if i["Id"] == c.get("ImageID")), {})
    if not image_is_built(image, admin.project):
        raise ScopeError(f"{service} uses an upstream image; use `dernvale anduril update {service}` instead")
    try:
        check_action(service, "rebuild", admin.job_processes(), args.force, allow_self=True)
    except BusyError as exc:
        print(f"[!] {exc}")
        if not confirm("Rebuild anyway? The running job will be killed", False):
            raise Aborted()
    if service == "celery-worker":
        print("[!] The worker image build is heavy; don't run it while a large job and the SIEM profile are up.")
    if not confirm(f"Rebuild and recreate {service}?", args.yes):
        raise Aborted()
    compose(admin, "build", *(["--no-cache"] if args.no_cache else []), service)
    compose(admin, "up", "-d", "--no-deps", service)
    print(f"[+] Rebuilt {service}")


def cmd_enable(admin: DockerAdmin, args: argparse.Namespace) -> None:
    print(
        "Anduril lets admin users of the Dernvale web UI start, stop, restart, update and remove\n"
        "Dernvale's own containers and images. To do that it needs:\n\n"
        "  - the Docker socket (/var/run/docker.sock) mounted into the dernvale-anduril container.\n"
        "    Socket access is root-equivalent on the Docker VM, so Anduril is the only container\n"
        "    that holds it, it is reachable only from the backend on an internal network, and it\n"
        f"    refuses anything not labelled com.docker.compose.project={admin.project} and named {NAME_PREFIX}*.\n"
        "  - the backend recreated so it joins that network and can read Anduril's token.\n"
    )
    if backend_secret_is_default(admin):
        print(
            "[!] The backend is using the default JWT secret, so anyone could forge an admin token.\n"
            "    The web UI keeps Anduril disabled until you set SECRET_KEY (in your shell or a .env\n"
            "    file next to docker-compose.yml) and re-run `dernvale anduril enable`.\n"
        )
    if not confirm("Grant Docker socket access to Anduril and enable it?", args.yes):
        raise Aborted()
    compose(admin, "--profile", "anduril", "up", "-d", "--build", "--no-deps", ANDURIL_SERVICE)
    if not backend_has_anduril(admin) or args.recreate_backend:
        compose(admin, "up", "-d", "--no-deps", "backend")
    print("[+] Anduril enabled. Admin users will see it on Aragorn → Settings in the web UI.")


def cmd_disable(admin: DockerAdmin, args: argparse.Namespace) -> None:
    if not confirm("Stop Anduril and remove its Docker socket access?", args.yes):
        raise Aborted()
    compose(admin, "--profile", "anduril", "rm", "--stop", "--force", ANDURIL_SERVICE)
    print("[+] Anduril disabled. The web UI will show it as not enabled.")


# --- argument parsing ------------------------------------------------------------


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    """Register `dernvale anduril ...` on the main CLI."""
    p = subparsers.add_parser("anduril", aliases=["aragorn"],
                              help="Administer Dernvale Docker containers and images (Anduril)")
    p.add_argument("-y", "--yes", action="store_true", help="Answer yes to confirmation prompts (never to interrupting a job)")
    p.add_argument("--socket", help="Docker socket to use (default: the engine running Dernvale)")
    sub = p.add_subparsers(dest="anduril_command", metavar="COMMAND")

    sub.add_parser("status", help="Dernvale containers and their state").set_defaults(anduril_func=cmd_status)
    sub.add_parser("images", help="Dernvale images").set_defaults(anduril_func=cmd_images)

    s = sub.add_parser("logs", help="Tail a container's logs")
    s.add_argument("name")
    s.add_argument("-n", "--tail", type=int, default=200)
    s.set_defaults(anduril_func=cmd_logs)

    s = sub.add_parser("stats", help="CPU, memory, network and disk usage")
    s.add_argument("names", nargs="*")
    s.set_defaults(anduril_func=cmd_stats)

    for name in ("start", "stop", "restart"):
        s = sub.add_parser(name, help=f"{name.title()} a Dernvale container")
        s.add_argument("name", help="Container or service name, e.g. dernvale-backend or backend")
        s.add_argument("--force", action="store_true", help="Proceed even if Elrond is running")
        s.set_defaults(anduril_func=cmd_lifecycle, command_name=name)

    s = sub.add_parser("update", help="Pull a container's upstream image and recreate it if newer")
    s.add_argument("name")
    s.add_argument("--force", action="store_true")
    s.set_defaults(anduril_func=cmd_update)

    s = sub.add_parser("pull", help="Pull a new version of an upstream image Dernvale uses")
    s.add_argument("ref", help="e.g. postgres:16-alpine")
    s.set_defaults(anduril_func=cmd_pull)

    s = sub.add_parser("rebuild", help="Rebuild a Dernvale-built image and recreate its container")
    s.add_argument("service", help="backend, celery-worker, frontend or anduril")
    s.add_argument("--no-cache", action="store_true")
    s.add_argument("--force", action="store_true")
    s.set_defaults(anduril_func=cmd_rebuild)

    s = sub.add_parser("rmi", help="Remove an unused Dernvale image")
    s.add_argument("image", help="Image ID (at least 12 characters)")
    s.set_defaults(anduril_func=cmd_rmi)

    sub.add_parser("prune", help="Remove dangling images built for Dernvale").set_defaults(anduril_func=cmd_prune)

    s = sub.add_parser("enable", help="Enable Anduril for the web UI (grants it Docker socket access)")
    s.add_argument("--recreate-backend", action="store_true", help="Recreate the backend even if already connected")
    s.set_defaults(anduril_func=cmd_enable)
    sub.add_parser("disable", help="Stop Anduril and remove its socket access").set_defaults(anduril_func=cmd_disable)

    p.set_defaults(func=run, anduril_parser=p)


def run(args: argparse.Namespace) -> int:
    if not getattr(args, "anduril_func", None):
        args.anduril_parser.print_help()
        return 0
    try:
        admin = get_admin(args.yes, args.socket)
        args.anduril_func(admin, args)
        return 0
    except Aborted:
        print("[-] Cancelled.")
        return 1
    except (ScopeError, BusyError) as exc:
        print(f"[!] {exc}")
        return 2
    except EngineError as exc:
        print(f"[!] Docker: {exc}")
        return 3
    except subprocess.CalledProcessError as exc:
        print(f"[!] Command failed ({exc.returncode}): {' '.join(exc.cmd)}")
        return exc.returncode or 1
