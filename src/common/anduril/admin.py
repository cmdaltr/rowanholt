"""Administration operations on Dernvale containers and images.

Used by the Anduril service (for the web UI) and by `dernvale anduril` on the
host, so both apply the same scope rules.
"""

from __future__ import annotations

import logging
import time
from typing import Callable, Optional

from .engine import Engine, EngineError, reachable_sockets
from .scope import (
    ANDURIL_SERVICE,
    PROJECT,
    BusyError,
    ScopeError,
    check_action,
    check_image_removable,
    container_in_scope,
    container_name,
    container_service,
    find_job_processes,
    image_in_scope,
    image_is_built,
    image_users,
    split_image_ref,
)

logger = logging.getLogger("dernvale.anduril")

Progress = Callable[[str], None]

# Inspect fields that describe the running endpoint rather than its configuration.
_ENDPOINT_KEEP = ("IPAMConfig", "Links", "Aliases", "DriverOpts")


class DockerAdmin:
    """Scoped operations; every public method re-resolves its target."""

    def __init__(self, engine: Optional[Engine] = None, project: str = PROJECT) -> None:
        self.engine = engine or Engine()
        self.project = project

    @classmethod
    def locate(cls, preferred: Optional[str] = None, project: str = PROJECT) -> "DockerAdmin":
        """Connect to the engine that hosts Dernvale.

        Docker Desktop and OrbStack can both be running, and starting OrbStack
        makes it the current context, so the first reachable socket is not
        necessarily the one with Dernvale on it.
        """
        if preferred:
            return cls(Engine(preferred), project)
        sockets = reachable_sockets()
        if not sockets:
            return cls(Engine(), project)  # raises EngineUnavailable with the paths tried
        for path in sockets:
            admin = cls(Engine(path), project)
            try:
                if admin._scoped_containers():
                    return admin
            except EngineError:
                continue
        return cls(Engine(sockets[0]), project)

    # --- lookup -------------------------------------------------------------

    def _all_containers(self) -> list[dict]:
        return self.engine.containers()

    def _scoped_containers(self) -> list[dict]:
        return [c for c in self._all_containers() if container_in_scope(c, self.project)]

    def resolve(self, name: str) -> dict:
        """Find a Dernvale container by container name or compose service name."""
        name = name.strip().lstrip("/")
        for c in self._scoped_containers():
            if name in (container_name(c), container_service(c)):
                return c
        raise ScopeError(f"'{name}' is not a Dernvale container")

    def _worker(self) -> Optional[dict]:
        for c in self._scoped_containers():
            if container_service(c) == "celery-worker":
                return c
        return None

    def job_processes(self) -> list[str]:
        """Elrond processes running in the worker, if it is up."""
        worker = self._worker()
        if not worker or worker.get("State") != "running":
            return []
        try:
            return find_job_processes(self.engine.top(worker["Id"]))
        except EngineError:
            return []

    # --- read-only ----------------------------------------------------------

    def list_containers(self) -> list[dict]:
        busy = self.job_processes()
        out = []
        for c in sorted(self._scoped_containers(), key=container_name):
            service = container_service(c)
            out.append({
                "id": c["Id"][:12],
                "name": container_name(c),
                "service": service,
                "image": c.get("Image", ""),
                "image_id": c.get("ImageID", ""),
                "state": c.get("State", ""),
                "status": c.get("Status", ""),
                "created": c.get("Created"),
                "ports": sorted({f"{p['PublicPort']}->{p['PrivatePort']}" for p in c.get("Ports") or [] if p.get("PublicPort")}),
                "protected": service == ANDURIL_SERVICE,
                "job_processes": busy if service == "celery-worker" else [],
            })
        return out

    def list_images(self) -> list[dict]:
        containers = self._all_containers()
        scoped_ids = {c.get("ImageID") for c in containers if container_in_scope(c, self.project)}
        out = []
        for img in self.engine.images():
            if not image_in_scope(img, scoped_ids, self.project):
                continue
            ours, others = image_users(img["Id"], containers, self.project)
            out.append({
                "id": img["Id"],
                "short_id": img["Id"].split(":")[-1][:12],
                "tags": [t for t in (img.get("RepoTags") or []) if t != "<none>:<none>"],
                "size": img.get("Size", 0),
                "created": img.get("Created"),
                "built": image_is_built(img, self.project),
                "used_by": ours,
                "shared_with": others,
            })
        return sorted(out, key=lambda i: (not i["built"], i["tags"][0] if i["tags"] else "~"))

    def logs(self, name: str, tail: int = 200) -> str:
        c = self.resolve(name)
        info = self.engine.inspect_container(c["Id"])
        return self.engine.logs(c["Id"], tail=max(1, min(tail, 5000)), tty=bool(info["Config"].get("Tty")))

    def stats(self, name: str) -> dict:
        c = self.resolve(name)
        if c.get("State") != "running":
            return {"name": container_name(c), "running": False}
        s = self.engine.stats(c["Id"])
        cpu, pre = s.get("cpu_stats", {}), s.get("precpu_stats", {})
        cpu_delta = cpu.get("cpu_usage", {}).get("total_usage", 0) - pre.get("cpu_usage", {}).get("total_usage", 0)
        sys_delta = cpu.get("system_cpu_usage", 0) - pre.get("system_cpu_usage", 0)
        ncpu = cpu.get("online_cpus") or len(cpu.get("cpu_usage", {}).get("percpu_usage") or []) or 1
        mem = s.get("memory_stats", {})
        cache = (mem.get("stats") or {}).get("inactive_file", 0)
        net = s.get("networks") or {}
        blk = (s.get("blkio_stats") or {}).get("io_service_bytes_recursive") or []
        return {
            "name": container_name(c),
            "running": True,
            "cpu_percent": round(cpu_delta / sys_delta * ncpu * 100, 1) if sys_delta > 0 else 0.0,
            "memory_bytes": max(0, mem.get("usage", 0) - cache),
            "memory_limit": mem.get("limit", 0),
            "pids": (s.get("pids_stats") or {}).get("current", 0),
            "net_rx": sum(n.get("rx_bytes", 0) for n in net.values()),
            "net_tx": sum(n.get("tx_bytes", 0) for n in net.values()),
            "block_read": sum(b.get("value", 0) for b in blk if b.get("op", "").lower() == "read"),
            "block_write": sum(b.get("value", 0) for b in blk if b.get("op", "").lower() == "write"),
        }

    # --- lifecycle ----------------------------------------------------------

    def _guard(self, c: dict, action: str, force: bool, allow_self: bool) -> None:
        check_action(container_service(c), action, self.job_processes(), force, allow_self)

    def start(self, name: str, allow_self: bool = False) -> str:
        c = self.resolve(name)
        self._guard(c, "start", True, allow_self)
        self.engine.start(c["Id"])
        logger.info("Started %s", container_name(c))
        return f"Started {container_name(c)}"

    def stop(self, name: str, force: bool = False, allow_self: bool = False) -> str:
        c = self.resolve(name)
        self._guard(c, "stop", force, allow_self)
        self.engine.stop(c["Id"])
        logger.info("Stopped %s", container_name(c))
        return f"Stopped {container_name(c)}"

    def restart(self, name: str, force: bool = False, allow_self: bool = False) -> str:
        c = self.resolve(name)
        self._guard(c, "restart", force, allow_self)
        self.engine.restart(c["Id"])
        logger.info("Restarted %s", container_name(c))
        return f"Restarted {container_name(c)}"

    # --- images -------------------------------------------------------------

    def _scoped_refs(self) -> set[str]:
        refs = {c.get("Image", "") for c in self._scoped_containers()}
        for img in self.list_images():
            refs.update(img["tags"])
        return {r for r in refs if r and not r.startswith("sha256:")}

    def validate_pull(self, ref: str) -> str:
        """Raise ScopeError unless ref is an upstream image Dernvale uses."""
        ref = ref.strip()
        if ref not in self._scoped_refs():
            raise ScopeError(f"'{ref}' is not an image used by Dernvale")
        if any(ref in i["tags"] and i["built"] for i in self.list_images()):
            raise ScopeError(f"'{ref}' is built locally; rebuild it from the host CLI (dernvale anduril rebuild)")
        return ref

    def pull(self, ref: str, progress: Optional[Progress] = None) -> str:
        """Pull a new version of an image a Dernvale container uses."""
        ref = self.validate_pull(ref)
        repo, tag = split_image_ref(ref)
        last = ""
        for event in self.engine.pull(repo, tag):
            if "error" in event:
                raise EngineError(event["error"])
            status = event.get("status", "")
            if progress and status and status != last and "progress" not in event:
                progress(f"{event.get('id', '')} {status}".strip())
                last = status
        image_id = self.engine.inspect_image(ref)["Id"]
        logger.info("Pulled %s (%s)", ref, image_id[:19])
        return image_id

    def validate_remove(self, image_id: str) -> dict:
        """Return the image if it may be removed; raise ScopeError otherwise."""
        image_id = image_id.strip()
        bare = image_id.split(":")[-1]
        containers = self._all_containers()
        scoped_ids = {c.get("ImageID") for c in containers if container_in_scope(c, self.project)}
        matches = [i for i in self.engine.images() if len(bare) >= 12 and i["Id"].split(":")[-1].startswith(bare)]
        if len(matches) != 1:
            raise ScopeError(f"No unique Dernvale image matches '{image_id}'")
        img = matches[0]
        check_image_removable(img, containers, scoped_ids, self.project)
        return img

    def remove_image(self, image_id: str) -> str:
        img = self.validate_remove(image_id)
        self.engine.remove_image(img["Id"])
        logger.info("Removed image %s", img["Id"][:19])
        return f"Removed {', '.join(img.get('RepoTags') or [img['Id'][:19]])}"

    def prune(self) -> dict:
        """Remove dangling images that compose built for Dernvale."""
        removed, freed, skipped = [], 0, []
        containers = self._all_containers()
        for img in self.engine.dangling_images():
            if not image_is_built(img, self.project):
                continue
            ours, others = image_users(img["Id"], containers, self.project)
            if ours or others:
                skipped.append(img["Id"][:19])
                continue
            try:
                self.engine.remove_image(img["Id"])
                removed.append(img["Id"][:19])
                freed += img.get("Size", 0)
            except EngineError as exc:
                skipped.append(f"{img['Id'][:19]} ({exc})")
        logger.info("Pruned %d Dernvale images, %d bytes", len(removed), freed)
        return {"removed": removed, "freed_bytes": freed, "skipped": skipped}

    # --- update -------------------------------------------------------------

    def update(self, name: str, force: bool = False, progress: Optional[Progress] = None) -> str:
        """Pull the container's image and recreate it if a newer one arrived."""
        c = self.resolve(name)
        self._guard(c, "update", force, False)
        info = self.engine.inspect_container(c["Id"])
        ref = info["Config"]["Image"]
        new_id = self.pull(ref, progress)
        if new_id == info["Image"]:
            return f"{container_name(c)} is already on the latest {ref}"
        return self.recreate(name, force=force, progress=progress)

    def recreate(self, name: str, force: bool = False, allow_self: bool = False, progress: Optional[Progress] = None) -> str:
        """Replace a container with one from its image's current version.

        Copies the existing container's configuration, so compose overrides
        (such as the worker's --concurrency=1 command) survive. Image-derived
        defaults are dropped so the new image's own values apply.
        """
        say = progress or (lambda _m: None)
        c = self.resolve(name)
        self._guard(c, "recreate", force, allow_self)
        info = self.engine.inspect_container(c["Id"])
        cname = info["Name"].lstrip("/")
        ref = info["Config"]["Image"]
        new_image = self.engine.inspect_image(ref)
        try:
            old_cfg = (self.engine.inspect_image(info["Image"]).get("Config") or {})
        except EngineError:
            old_cfg = {}
        body = self._clone_config(info, old_cfg, new_image)

        networks = dict((info.get("NetworkSettings") or {}).get("Networks") or {})
        endpoints = {n: self._clean_endpoint(ep, info["Id"]) for n, ep in networks.items()}
        first = next(iter(endpoints), None)
        if first:
            body["NetworkingConfig"] = {"EndpointsConfig": {first: endpoints[first]}}

        was_running = info["State"].get("Running", False)
        backup = f"{cname}-old-{int(time.time())}"
        if was_running:
            say(f"Stopping {cname}")
            self.engine.stop(info["Id"])
        self.engine.rename(info["Id"], backup)
        new_cid = None
        try:
            say(f"Creating {cname} from {ref}")
            new_cid = self.engine.create_container(cname, body)
            for net, ep in endpoints.items():
                if net != first:
                    self.engine.connect_network(net, new_cid, ep)
            if was_running:
                self.engine.start(new_cid)
        except EngineError:
            logger.exception("Recreate of %s failed; restoring the old container", cname)
            if new_cid:
                try:
                    self.engine.remove_container(new_cid)
                except EngineError:
                    pass
            self.engine.rename(info["Id"], cname)
            if was_running:
                self.engine.start(info["Id"])
            raise
        # Volumes are kept: the old container is removed without v=1.
        self.engine.remove_container(info["Id"])
        logger.info("Recreated %s on %s", cname, new_image["Id"][:19])
        return f"Recreated {cname} on {ref} ({new_image['Id'].split(':')[-1][:12]})"

    @staticmethod
    def _clone_config(info: dict, old_cfg: dict, new_image: dict) -> dict:
        cfg = dict(info["Config"])
        if cfg.get("Hostname") == info["Id"][:12]:
            cfg.pop("Hostname", None)
        for key in ("Cmd", "Entrypoint", "WorkingDir", "User", "StopSignal", "Healthcheck"):
            if key in cfg and cfg.get(key) == old_cfg.get(key):
                cfg.pop(key)
        old_env = set(old_cfg.get("Env") or [])
        cfg["Env"] = [e for e in cfg.get("Env") or [] if e not in old_env]
        for key in ("ExposedPorts", "Volumes"):
            old = old_cfg.get(key) or {}
            kept = {k: v for k, v in (cfg.get(key) or {}).items() if k not in old}
            cfg[key] = kept or None
        old_labels = old_cfg.get("Labels") or {}
        labels = {k: v for k, v in (cfg.get("Labels") or {}).items() if old_labels.get(k) != v}
        if "com.docker.compose.image" in labels:
            labels["com.docker.compose.image"] = new_image["Id"]
        cfg["Labels"] = labels

        host = dict(info["HostConfig"])
        # Keep anonymous volumes (image VOLUMEs with no compose mount) attached.
        targets = {b.split(":")[1] for b in host.get("Binds") or [] if ":" in b}
        targets |= {m.get("Target") for m in host.get("Mounts") or []}
        extra = [
            {"Type": "volume", "Source": m["Name"], "Target": m["Destination"]}
            for m in info.get("Mounts") or []
            if m.get("Type") == "volume" and m.get("Destination") not in targets and m.get("Name")
        ]
        if extra:
            host["Mounts"] = list(host.get("Mounts") or []) + extra
        cfg["HostConfig"] = host
        return cfg

    @staticmethod
    def _clean_endpoint(ep: dict, old_id: str) -> dict:
        out = {k: ep[k] for k in _ENDPOINT_KEEP if ep.get(k)}
        if out.get("Aliases"):
            out["Aliases"] = [a for a in out["Aliases"] if a != old_id[:12]] or None
        return out


__all__ = ["DockerAdmin", "ScopeError", "BusyError", "EngineError"]
