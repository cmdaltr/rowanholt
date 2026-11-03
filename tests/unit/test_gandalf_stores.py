"""Gandalf's container writable-layer copies and macOS stores (G17): gandalf.py's collector,
Elrond's image collection and the staged-file route that reads what they copy."""
import csv
import importlib.machinery
import importlib.util
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Appended, not prepended: src/analysis/platform would shadow the stdlib module.
sys.path.append(str(ROOT / "src" / "analysis"))

from rivendell.collect import linux as collect  # noqa: E402
from rivendell.process import extra_artefacts as ex  # noqa: E402

CID = "4f1c9e2ab3d7" + "0" * 52


def collector():
    path = str(ROOT / "src" / "acquisition" / "python" / "collect_artefacts-py")
    loader = importlib.machinery.SourceFileLoader("gandalf_collector", path)
    spec = importlib.util.spec_from_loader("gandalf_collector", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def docker_root(tmp_path):
    mnt = tmp_path / "mnt"
    docker = mnt / "var" / "lib" / "docker"
    (docker / "containers" / CID).mkdir(parents=True)
    (docker / "image" / "overlay2" / "layerdb" / "mounts" / CID).mkdir(parents=True)
    (docker / "image" / "overlay2" / "layerdb" / "mounts" / CID / "mount-id").write_text("abc123\n")
    upper = docker / "overlay2" / "abc123" / "diff"
    (upper / "tmp" / ".x").mkdir(parents=True)
    (upper / "tmp" / ".x" / "miner").write_bytes(b"\x7fELF" + b"\0" * 60)
    (upper / "etc").mkdir()
    (upper / "etc" / "motd").write_text("hi\n")
    return mnt


def test_gandalf_copies_container_executables(tmp_path):
    gc = collector()
    mnt = docker_root(tmp_path)
    host = tmp_path / "HOST"
    host.mkdir()
    gc._container_layers = lambda root="", real=gc._container_layers: real(str(mnt))
    gc.collect_container_layers(str(host / "artefacts"), str(host))
    copied = sorted(p.relative_to(host / "artefacts").as_posix() for p in (host / "artefacts").rglob("*") if p.is_file())
    assert copied == [f"container_layer/{CID[:12]}/tmp+.x+miner"]
    assert "/tmp/.x/miner" in (host / "log.audit").read_text()


def test_elrond_copies_container_executables_from_an_image(tmp_path):
    mnt = docker_root(tmp_path)
    out = tmp_path / "out"
    raw = out / "HOST" / "artefacts" / "raw"
    raw.mkdir(parents=True)
    collect.collect_linux_extras(str(mnt), str(raw) + "/", "HOST::Linux", str(out) + "/", "collecting", 0)
    assert [p.name for p in (raw / "container_layer" / CID[:12]).iterdir()] == ["tmp+.x+miner"]


def test_container_layer_files_are_staged_files(tmp_path):
    out = str(tmp_path / "out") + "/"
    layer = tmp_path / "out" / "HOST" / "artefacts" / "raw" / "container_layer" / CID[:12]
    layer.mkdir(parents=True)
    (layer / "tmp+.x+miner").write_bytes(b"\x7fELF" + b"\0" * 60)
    artefact = str(layer / "tmp+.x+miner")
    assert ex.is_extra_artefact(artefact)
    assert ex.process_extra_artefact("", "'HOST'", out, "HOST::Linux", "/", "processing", artefact)
    with open(tmp_path / "out" / "HOST" / "artefacts" / "cooked" / "staged_files.csv", newline="") as fh:
        [row] = list(csv.DictReader(fh))
    assert row["Source"] == f"container {CID[:12]}:/tmp/.x/miner"
    assert row["Hidden"] == "yes" and "executable" in row["Flag"]


def test_macos_stores_keep_layout_and_respect_the_cap(tmp_path, monkeypatch):
    gc = collector()
    db = tmp_path / "db"
    (db / "uuidtext" / "AB").mkdir(parents=True)
    (db / "uuidtext" / "AB" / "CDEF").write_bytes(b"u" * 100)
    (db / "diagnostics" / "Persist").mkdir(parents=True)
    old, new = db / "diagnostics" / "Persist" / "0001.tracev3", db / "diagnostics" / "Persist" / "0002.tracev3"
    old.write_bytes(b"o" * 400)
    new.write_bytes(b"n" * 400)
    os.utime(old, (1_700_000_000, 1_700_000_000))
    spot = tmp_path / "spot" / "Store-V2" / "UUID"
    spot.mkdir(parents=True)
    (spot / "store.db").write_bytes(b"s" * 50)
    (spot / "journalAttr.1").write_bytes(b"j" * 50)
    gc.MACOS_LOG_STORES = ((str(db / "diagnostics"), "diagnostics"), (str(db / "uuidtext"), "uuidtext"))
    gc.MACOS_SPOTLIGHT_ROOTS = (str(tmp_path / "spot"),)
    monkeypatch.setenv("GANDALF_UNIFIED_LOG_STORE_MAX", "600")
    host = tmp_path / "HOST"
    host.mkdir()
    gc.collect_macos_stores(str(host / "artefacts"), str(host))
    got = sorted(p.relative_to(host / "artefacts").as_posix() for p in (host / "artefacts").rglob("*") if p.is_file())
    # uuidtext first, then the newest tracev3 that fits; the older one is over the budget
    assert got == ["spotlight/Store-V2+UUID+store.db", "unified_log_store/diagnostics/Persist/0002.tracev3",
                   "unified_log_store/uuidtext/AB/CDEF"]


def test_container_and_store_paths_agree():
    """gandalf.sh, gandalf.py and Elrond's image collection take the same container metadata."""
    bash = (ROOT / "src" / "acquisition" / "bash" / "gandalf.sh").read_text()
    python = (ROOT / "src" / "acquisition" / "python" / "collect_artefacts-py").read_text()
    for path in ("/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db",
                 "/var/lib/containers/storage/overlay-containers/containers.json",
                 "/var/lib/containers/storage/db.sql", "/var/lib/containers/storage/db.sql-wal",
                 "/var/lib/containers/storage/libpod/bolt_state.db"):
        assert path in collect.LINUX_EXTRA_FILES and f'"{path}"' in python and path in bash
    assert "collect_container_layers \"$acq_dir\"" in bash and "collect_macos_stores \"$acq_dir\"" in bash
