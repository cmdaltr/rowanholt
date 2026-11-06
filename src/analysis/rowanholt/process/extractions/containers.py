"""Docker and Kubernetes node artefacts, as collected into raw/linux/ (process/linux_artefacts.py
routes them here).

- /var/lib/docker/containers/<id>/config.v2.json, with hostconfig.json beside it: one row per
  container, flagged when it can reach the host (privileged, the Docker socket, the host's
  namespaces, sensitive host paths, dangerous capabilities)
- /var/lib/docker/containers/<id>/<id>-json.log and /var/log/pods/.../<n>.log: container output
- gandalf+container_changes.csv: Gandalf's listing of each container's writable layer, which is
  everything that changed since the container's image
- /etc/kubernetes/manifests/*.yaml: static pods, which the kubelet runs with no API server involved
- /var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db: containerd's own record of every
  container (a Kubernetes node's, through the CRI, or ctr's), read with the stdlib bbolt reader
  into the same docker_containers rows, Runtime "containerd"
- /var/lib/containers/storage/db.sql (Podman 4.8 on, SQLite) or libpod/bolt_state.db (bbolt, before):
  Podman's record of its containers, with the same OCI spec inside, Runtime "podman"
- raw/live_containers/<runtime>/<id>/top.txt (Gandalf -l/-L only, with inspect.json and export.tar
  beside it): the processes running in each container when it was collected; inspect.json gives the
  container's docker_containers row, Runtime "docker (live)", where the case has no config.v2.json
  for it (a Windows host's Docker Desktop keeps that in its WSL VM)

Every function returns rows; techniques are decided from the rows by the *_techniques functions,
only where a row justifies one.
"""

import csv
import json
import os
import re
import shutil
import sqlite3
import struct
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from rowanholt.process.extractions.bbolt import Bolt, Bucket

# Host paths a container has no business mounting
SENSITIVE_MOUNTS = ("/", "/etc", "/root", "/proc", "/sys", "/dev", "/boot", "/var/lib/docker", "/var/lib/kubelet",
                    "/var/lib/containerd", "/home", "/usr", "/lib", "/var/log")
DOCKER_SOCKETS = ("/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock",
                  "/var/run/containerd/containerd.sock", "/var/run/crio/crio.sock", "/run/crio/crio.sock",
                  "/run/podman/podman.sock", "/var/run/podman/podman.sock")
# What a runtime mounts read-only into every container for name resolution: not a lead
RESOLVER_FILES = ("/etc/hosts", "/etc/resolv.conf", "/etc/hostname")
ESCAPE_CAPABILITIES = {"ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "SYS_RAWIO", "BPF"}
# Kubernetes' own static pods; anything else in the manifests directory was put there by someone
CONTROL_PLANE_PODS = re.compile(r"^(?:kube-apiserver|kube-controller-manager|kube-scheduler|etcd|kube-vip|haproxy|"
                                r"keepalived)(?:-|$)")
TEMP_PATHS = re.compile(r"^/(?:tmp|var/tmp|dev/shm|run)/|/\.[^/]+$")
# Files whose change inside a container is persistence or access, with the technique it implies
PERSISTENCE_FILES = (
    (re.compile(r"^/etc/(?:cron\.(?:d|daily|hourly|weekly|monthly)/|crontab$)|^/var/spool/cron/"), "cron", "T1053.003"),
    (re.compile(r"/\.ssh/authorized_keys2?$"), "SSH authorized keys", "T1098.004"),
    (re.compile(r"^/etc/ld\.so\.preload$"), "ld.so.preload", "T1574.006"),
    (re.compile(r"^/etc/(?:passwd|shadow)$"), "accounts", "T1136.001"),
    (re.compile(r"^/etc/(?:profile|bash\.bashrc|bashrc)$|^/etc/profile\.d/|/\.(?:bashrc|profile|bash_profile)$"),
     "shell startup", "T1546.004"),
)

HEADERS = {
    "docker_containers": ["Container", "Name", "Image", "Command", "Created", "Started", "Finished", "Running",
                              "User", "Privileged", "PidMode", "NetworkMode", "IpcMode", "CapAdd", "SecurityOpt",
                              "Mounts", "Runtime", "Flag"],
    "container_logs": ["Runtime", "Container", "Pod", "Namespace", "Stream", "LastWriteTime", "Message"],
    "container_changes": ["Container", "Path", "Size", "Mode", "Kind", "SHA256", "LastWriteTime", "Flag"],
    "static_pods": ["Source", "Name", "Namespace", "Images", "Command", "Flag"],
    "container_processes": ["Runtime", "Container", "Name", "Image", "PID", "PPID", "User", "Elapsed", "Command",
                                "Flag"],
}


def _load_json(path: str) -> Dict:
    with open(path, encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    return data if isinstance(data, dict) else {}


def _sensitive(source: str) -> bool:
    source = source.rstrip("/") or "/"
    return source in SENSITIVE_MOUNTS or source.startswith(("/etc/", "/root/", "/proc/", "/sys/", "/dev/"))


def container_flags(privileged: bool, mounts: List[Dict[str, str]], pid_mode: str, network_mode: str,
                    ipc_mode: str, cap_add: List[str], security_opt: List[str]) -> List[str]:
    """Why a container could reach its host, or nothing for one that can't."""
    flags = []
    if privileged:
        flags.append("privileged")
    for mount in mounts:
        source = mount.get("Source", "")
        if source in DOCKER_SOCKETS:
            flags.append(f"container runtime socket mounted ({source})")
        elif source in RESOLVER_FILES and not mount.get("RW"):
            continue
        elif _sensitive(source):
            flags.append(f"host path mounted {'read-write' if mount.get('RW') else 'read-only'} ({source})")
    if pid_mode == "host":
        flags.append("host PID namespace")
    if network_mode == "host":
        flags.append("host network")
    if ipc_mode == "host":
        flags.append("host IPC namespace")
    dangerous = sorted(c.upper().replace("CAP_", "") for c in cap_add
                       if c.upper().replace("CAP_", "") in ESCAPE_CAPABILITIES)
    if dangerous:
        flags.append("capabilities " + ", ".join(dangerous))
    if any(opt.replace("=", ":").lower() in ("seccomp:unconfined", "apparmor:unconfined") for opt in security_opt):
        flags.append("seccomp or AppArmor disabled")
    return flags


def docker_container_row(path: str, hostconfig: Optional[str] = None) -> Optional[Dict[str, str]]:
    """One container from its config.v2.json, and the hostconfig.json beside it when there is one."""
    config = _load_json(path)
    if not config.get("ID"):
        return None
    host = _load_json(hostconfig) if hostconfig and os.path.isfile(hostconfig) else {}
    return _docker_row(config, host)


def docker_inspect_row(path: str) -> Optional[Dict[str, str]]:
    """One container from `docker inspect` (Gandalf's live capture, raw/live_containers/docker/<id>/inspect.json):
    the only record of a container's settings from a Windows host, whose Docker Desktop keeps
    config.v2.json inside its WSL VM. The same fields as config.v2.json and hostconfig.json, shaped
    differently: Id for ID, a Mounts list for MountPoints, HostConfig inline."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    inspect = data[0] if isinstance(data, list) and data else data
    if not isinstance(inspect, dict) or not inspect.get("Id"):
        return None
    config = dict(inspect, ID=inspect["Id"],
                  MountPoints={str(n): m for n, m in enumerate(inspect.get("Mounts") or []) if isinstance(m, dict)})
    row = _docker_row(config, inspect.get("HostConfig") or {})
    row["Runtime"] = "docker (live)"
    return row


def _docker_row(config: Dict, host: Dict) -> Dict[str, str]:
    state = config.get("State") or {}
    settings = config.get("Config") or {}
    mounts = [{"Source": m.get("Source", ""), "Destination": m.get("Destination", ""), "RW": bool(m.get("RW"))}
              for m in (config.get("MountPoints") or {}).values()]
    for bind in host.get("Binds") or []:  # source:destination[:options]
        parts = bind.split(":")
        if len(parts) >= 2 and not any(m["Source"] == parts[0] for m in mounts):
            mounts.append({"Source": parts[0], "Destination": parts[1],
                           "RW": not (len(parts) > 2 and "ro" in parts[2].split(","))})
    cap_add = host.get("CapAdd") or []
    security_opt = host.get("SecurityOpt") or []
    flags = container_flags(bool(host.get("Privileged")), mounts, host.get("PidMode") or "",
                            host.get("NetworkMode") or "", host.get("IpcMode") or "", cap_add, security_opt)
    command = " ".join([config.get("Path") or ""] + [str(a) for a in config.get("Args") or []]).strip()
    return {
        "Container": config["ID"][:12], "Name": (config.get("Name") or "").lstrip("/"),
        "Image": settings.get("Image") or config.get("Image", ""), "Command": command,
        "Created": config.get("Created", ""), "Started": state.get("StartedAt", ""),
        "Finished": state.get("FinishedAt", ""), "Running": str(bool(state.get("Running"))),
        "User": settings.get("User") or "root", "Privileged": str(bool(host.get("Privileged"))),
        "PidMode": host.get("PidMode") or "", "NetworkMode": host.get("NetworkMode") or "",
        "IpcMode": host.get("IpcMode") or "", "CapAdd": ", ".join(cap_add), "SecurityOpt": ", ".join(security_opt),
        "Mounts": "; ".join(f"{m['Source']}:{m['Destination']}{'' if m['RW'] else ':ro'}" for m in mounts),
        "Runtime": "docker", "Flag": "; ".join(flags),
    }


# containerd's namespaces: Docker's own containers are in moby, and come from config.v2.json instead
CONTAINERD_SKIP = ("moby",)
GO_EPOCH = datetime(1, 1, 1, tzinfo=timezone.utc)
HEX_ID = re.compile(r"^[0-9a-f]{64}$")


def _varint(data: bytes, at: int) -> Tuple[int, int]:
    value = shift = 0
    while at < len(data):
        byte = data[at]
        at += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, at
        shift += 7
    raise ValueError("truncated varint")


def any_value(data: bytes) -> Tuple[str, bytes]:
    """(type URL, value) of a protobuf google.protobuf.Any: fields 1 and 2, both length-delimited."""
    type_url, value, at = "", b"", 0
    while at < len(data):
        key, at = _varint(data, at)
        if key & 7 != 2:
            raise ValueError("not an Any")
        length, at = _varint(data, at)
        chunk = data[at:at + length]
        at += length
        if key >> 3 == 1:
            type_url = chunk.decode("utf-8", errors="replace")
        elif key >> 3 == 2:
            value = chunk
    return type_url, value


def go_time(data: Optional[bytes]) -> str:
    """Go's time.MarshalBinary (version 1 or 2: seconds since year 1, nanoseconds, zone) as ISO UTC."""
    if not data or len(data) < 15 or data[0] not in (1, 2):
        return ""
    seconds, nanos = struct.unpack(">qi", data[1:13])
    try:
        when = GO_EPOCH + timedelta(seconds=seconds, microseconds=nanos // 1000)
    except OverflowError:
        return ""
    return when.isoformat().replace("+00:00", "Z")


def _host_namespace(namespaces: List[Dict], kind: str) -> bool:
    """No namespace of this kind in the spec, or joining PID 1's: the container shares the host's."""
    for namespace in namespaces:
        if namespace.get("type") == kind:
            return (namespace.get("path") or "").startswith("/proc/1/ns/")
    return True


def oci_spec_fields(spec: Dict, privileged: Optional[bool] = None) -> Dict[str, str]:
    """The docker_containers fields an OCI runtime spec decides, flagged as Docker's are.
    `privileged` when the runtime records it (Podman); otherwise read from the spec."""
    process = spec.get("process") or {}
    linux = spec.get("linux") or {}
    namespaces = linux.get("namespaces") or []
    effective = [c.replace("CAP_", "") for c in (process.get("capabilities") or {}).get("effective") or []]
    devices = (linux.get("resources") or {}).get("devices") or []
    # What a privileged container gets: every device, and CAP_SYS_ADMIN with the rest
    if privileged is None:
        privileged = "SYS_ADMIN" in effective and any(d.get("allow") and not d.get("type") and not d.get("major")
                                                      for d in devices)
    mounts = [{"Source": m.get("source", ""), "Destination": m.get("destination", ""),
               "RW": "ro" not in (m.get("options") or [])}
              for m in spec.get("mounts") or [] if m.get("type") == "bind" or "bind" in (m.get("options") or []) or
              "rbind" in (m.get("options") or [])]
    pid_mode = "host" if spec and _host_namespace(namespaces, "pid") else ""
    network_mode = "host" if spec and _host_namespace(namespaces, "network") else ""
    ipc_mode = "host" if spec and _host_namespace(namespaces, "ipc") else ""
    profile = process.get("apparmorProfile") or ""
    security_opt = ["apparmor=unconfined"] if profile == "unconfined" else []
    flags = container_flags(privileged, mounts, pid_mode, network_mode, ipc_mode, effective, security_opt)
    user = process.get("user") or {}
    return {
        "Command": " ".join(str(a) for a in process.get("args") or []),
        "User": "root" if user.get("uid", 0) == 0 else str(user.get("uid")),
        "Privileged": str(privileged), "PidMode": pid_mode, "NetworkMode": network_mode, "IpcMode": ipc_mode,
        "CapAdd": ", ".join(effective), "SecurityOpt": ", ".join(security_opt),
        "Mounts": "; ".join(f"{m['Source']}:{m['Destination']}{'' if m['RW'] else ':ro'}" for m in mounts),
        "Flag": "; ".join(flags),
    }


def _short(container_id: str) -> str:
    return container_id[:12] if HEX_ID.match(container_id) else container_id


def containerd_container_row(namespace: str, container_id: str, container: Bucket) -> Dict[str, str]:
    """One container from containerd's metadata (v1/<namespace>/containers/<id>): its OCI spec
    says what it was allowed, as hostconfig.json does for Docker."""
    values = container.values()
    labels = {k.decode("utf-8", "replace"): v.decode("utf-8", "replace")
              for k, v in (container.bucket(b"labels").items() if container.bucket(b"labels") else [])}
    spec: Dict = {}
    if values.get(b"spec"):
        try:
            spec = json.loads(any_value(values[b"spec"])[1] or b"{}")
        except ValueError:
            spec = {}
    name = labels.get("io.kubernetes.container.name")
    pod = labels.get("io.kubernetes.pod.name")
    shown = f"{labels.get('io.kubernetes.pod.namespace', '')}/{pod}/{name}" if pod and name else container_id
    return {"Container": _short(container_id), "Name": f"{namespace}: {shown}",
            "Image": values.get(b"image", b"").decode("utf-8", "replace"),
            "Created": go_time(values.get(b"createdat")), "Started": "", "Finished": "", "Running": "",
            **oci_spec_fields(spec), "Runtime": "containerd"}


# libpod's ContainerStatus: 3 is running
PODMAN_RUNNING = 3
PODMAN_UNSET_TIME = "0001-01-01T00:00:00Z"


def podman_container_row(config: Dict, state: Optional[Dict] = None) -> Dict[str, str]:
    """One container from Podman's state database: its config (with the OCI spec Podman generated
    at create) and its state."""
    state = state or {}
    def when(value) -> str:
        return "" if not value or value == PODMAN_UNSET_TIME else str(value)
    return {"Container": _short(config.get("id") or ""), "Name": config.get("name") or "",
            "Image": config.get("rootfsImageName") or config.get("RawImageName") or "",
            "Created": when(config.get("createdTime")), "Started": when(state.get("startedTime")),
            "Finished": when(state.get("finishedTime")),
            "Running": str(state.get("state") == PODMAN_RUNNING) if state else "",
            **oci_spec_fields(config.get("spec") or {}, bool(config.get("privileged"))), "Runtime": "podman"}


def _json(raw) -> Dict:
    try:
        value = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def podman_bolt_rows(path: str) -> List[Dict[str, str]]:
    """Podman's libpod/bolt_state.db: ctr/<id>/config and state."""
    listed = Bolt(path).root().bucket(b"ctr")
    rows = []
    for _, container in (listed.buckets() if listed else []):
        config = _json(container.get(b"config"))
        if config.get("id"):
            rows.append(podman_container_row(config, _json(container.get(b"state"))))
    return rows


def podman_sqlite_rows(path: str) -> List[Dict[str, str]]:
    """Podman's db.sql (ContainerConfig and ContainerState), from a copy with its -wal beside it:
    SQLite in WAL mode keeps the latest writes there, and opening the case's own copy could write to it."""
    with tempfile.TemporaryDirectory(prefix="rowanholt-podman-") as folder:
        copy = os.path.join(folder, "db.sql")
        shutil.copyfile(path, copy)
        if os.path.isfile(path + "-wal"):
            shutil.copyfile(path + "-wal", copy + "-wal")
        connection = sqlite3.connect(copy)
        try:
            states = {i: _json(j) for i, j in connection.execute("SELECT ID, JSON FROM ContainerState")}
            configs = [_json(j) for (j,) in connection.execute("SELECT JSON FROM ContainerConfig")]
        finally:
            connection.close()
    return [podman_container_row(c, states.get(c.get("id"))) for c in configs if c.get("id")]


def containerd_rows(path: str) -> List[Dict[str, str]]:
    """Every container in containerd's meta.db, in every namespace but Docker's."""
    root = Bolt(path).root().bucket(b"v1")
    rows = []
    for namespace, bucket in (root.buckets() if root else []):
        name = namespace.decode("utf-8", "replace")
        listed = bucket.bucket(b"containers")
        if name in CONTAINERD_SKIP or listed is None:
            continue
        for container_id, container in listed.buckets():
            rows.append(containerd_container_row(name, container_id.decode("utf-8", "replace"), container))
    return rows


def container_techniques(rows: List[Dict[str, str]]) -> List[str]:
    """T1611 when a container could reach its host; T1610 as well when it was also told to run a shell
    or fetch something, which is how such containers are deployed for an escape."""
    techniques = []
    if any(r["Flag"] for r in rows):
        techniques.append("T1611")
        if any(r["Flag"] and re.search(r"\b(?:sh|bash|nsenter|chroot|curl|wget|nc)\b", r["Command"]) for r in rows):
            techniques.append("T1610")
    return techniques


def docker_log_rows(path: str, container: str) -> List[Dict[str, str]]:
    """Docker's json-file log driver: one JSON object per line."""
    rows = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            rows.append({"Runtime": "docker", "Container": container[:12], "Pod": "", "Namespace": "",
                         "Stream": entry.get("stream", ""), "LastWriteTime": entry.get("time", ""),
                         "Message": (entry.get("log") or "").rstrip("\n")})
    return rows


CRI_LINE = re.compile(r"^(\S+) (stdout|stderr) [FP] ?(.*)$")


def live_process_rows(path: str, runtime: str, container: str, suspicious: "re.Pattern") -> List[Dict[str, str]]:
    """Gandalf's `<runtime> top` of one running container (PID PPID USER ELAPSED COMMAND), named from
    the inspect.json beside it; a command `suspicious` matches is flagged."""
    name = image = ""
    try:
        with open(os.path.join(os.path.dirname(path), "inspect.json"), encoding="utf-8", errors="replace") as fh:
            inspected = json.load(fh)
        first = inspected[0] if isinstance(inspected, list) and inspected else {}
        name = str(first.get("Name") or "").lstrip("/")
        image = str((first.get("Config") or {}).get("Image") or first.get("ImageName") or "")
    except (OSError, ValueError, AttributeError):
        pass
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = [line.rstrip("\n") for line in fh if line.strip()]
    if not lines:
        return []
    columns = len(lines[0].split())
    rows = []
    for line in lines[1:]:
        fields = line.split(None, columns - 1)
        if len(fields) < columns or columns < 5:
            continue
        pid, ppid, user, elapsed, command = fields[:5]
        rows.append({"Runtime": runtime, "Container": container, "Name": name, "Image": image, "PID": pid,
                     "PPID": ppid, "User": user, "Elapsed": elapsed, "Command": command,
                     "Flag": "suspicious command" if suspicious.search(command) else ""})
    return rows


def cri_log_rows(path: str, pod_dir: str, container: str) -> List[Dict[str, str]]:
    """The CRI log format the kubelet writes under /var/log/pods/<namespace>_<pod>_<uid>/<container>/."""
    namespace, _, rest = pod_dir.partition("_")
    pod = rest.rpartition("_")[0] or rest
    rows = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            match = CRI_LINE.match(line.rstrip("\n"))
            if match:
                rows.append({"Runtime": "cri", "Container": container, "Pod": pod, "Namespace": namespace,
                             "Stream": match.group(2), "LastWriteTime": match.group(1), "Message": match.group(3)})
    return rows


def container_change_rows(path: str) -> List[Dict[str, str]]:
    """Gandalf's listing of each container's writable layer, flagged where a change is a lead."""
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        rows = list(csv.DictReader(fh))
    for row in rows:
        flags = []
        inside = row.get("Path", "")
        if row.get("Kind") and TEMP_PATHS.search(inside):
            flags.append("executable in a temporary or hidden path")
        elif row.get("Kind") == "elf":
            flags.append("binary added or changed since the image")
        for pattern, what, _ in PERSISTENCE_FILES:
            if pattern.search(inside):
                flags.append(f"{what} changed")
        row["LastWriteTime"] = _epoch(row.get("MTime") or row.get("LastWriteTime"))
        row["Flag"] = "; ".join(flags)
    return rows


def change_techniques(rows: List[Dict[str, str]]) -> List[str]:
    techniques = set()
    for row in rows:
        if "executable" in row["Flag"] or "binary" in row["Flag"]:
            techniques.add("T1105")
        for pattern, _, technique in PERSISTENCE_FILES:
            if pattern.search(row.get("Path", "")):
                techniques.add(technique)
    return sorted(techniques)


def static_pod_row(path: str, source: str) -> Optional[Dict[str, str]]:
    """A static pod manifest, read without a YAML parser: the fields that matter are one line each."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read(1 << 20)
    if not re.search(r"^kind:\s*Pod\b", text, re.M):
        return None
    name = re.search(r"^\s+name:\s*['\"]?([\w.-]+)", text, re.M)
    namespace = re.search(r"^\s+namespace:\s*['\"]?([\w.-]+)", text, re.M)
    images = re.findall(r"^\s*-?\s*image:\s*['\"]?([^\s'\"]+)", text, re.M)
    command = " ".join(re.findall(r"^\s*-?\s*command:\s*(\[.*\]|.+)$", text, re.M))
    pod = name.group(1) if name else os.path.basename(source)
    flags = []
    if not CONTROL_PLANE_PODS.match(pod):
        flags.append("not a control-plane pod")
    if re.search(r"^\s*privileged:\s*true", text, re.M):
        flags.append("privileged")
    for key, what in (("hostPID", "host PID namespace"), ("hostNetwork", "host network"), ("hostIPC", "host IPC")):
        if re.search(rf"^\s*{key}:\s*true", text, re.M):
            flags.append(what)
    for host_path in re.findall(r"^\s*hostPath:\s*\n\s*path:\s*['\"]?([^\s'\"]+)", text, re.M):
        if _sensitive(host_path) or host_path in DOCKER_SOCKETS:
            flags.append(f"host path {host_path}")
    return {"Source": source, "Name": pod, "Namespace": namespace.group(1) if namespace else "",
            "Images": ", ".join(images), "Command": command, "Flag": "; ".join(flags)}


def static_pod_techniques(rows: List[Dict[str, str]]) -> List[str]:
    """T1543.005 for a static pod Kubernetes didn't put there; T1611 when it can reach the host."""
    techniques = []
    unexpected = [r for r in rows if "not a control-plane pod" in r["Flag"]]
    if unexpected:
        techniques.append("T1543.005")
        if any(r["Flag"] != "not a control-plane pod" for r in unexpected):
            techniques.append("T1611")
    return techniques


def _epoch(seconds) -> str:
    try:
        seconds = int(float(seconds))
        if seconds <= 0:
            return ""
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError, OSError):
        return ""
