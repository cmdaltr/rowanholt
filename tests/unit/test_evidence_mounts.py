"""The evidence folders setup mounts (docker-compose.local.yml): the backend's read-only, the worker's
writable, and Splunk's read-only, since Splunk reads a case's files itself at the worker's paths."""

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def test_the_linux_launcher_mounts_evidence_into_splunk(tmp_path):
    launcher = (REPO / "desktop" / "linux" / "rowanholt-app.sh").read_text()
    pieces = [re.search(r"^LOCAL_HEADER=.*$", launcher, re.M).group(0)]
    for name in ("json_quote", "write_evidence"):
        pieces.append(re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", launcher, re.S | re.M).group(0))
    script = "\n".join(pieces) + '\nsay() { :; }\nwrite_evidence "$1" /srv/evidence'
    subprocess.run(["bash", "-c", script, "bash", str(tmp_path)], check=True)
    services = re.split(r"^  (\S+):\n", (tmp_path / "docker-compose.local.yml").read_text(), flags=re.M)[1:]
    mounts = dict(zip(services[::2], services[1::2]))
    assert set(mounts) == {"backend", "celery-worker", "splunk"}
    for service, writable in (("backend", False), ("celery-worker", True), ("splunk", False)):
        assert 'target: "/srv/evidence"' in mounts[service]
        assert ("read_only: true" not in mounts[service]) == writable


def test_the_mac_and_windows_setups_do_too():
    swift = (REPO / "desktop" / "macos" / "Setup.swift").read_text()
    assert '("backend", true), ("celery-worker", false), ("splunk", true)' in swift
    ps1 = (REPO / "desktop" / "windows" / "Rowanholt.ps1").read_text()
    assert "foreach ($service in 'backend', 'celery-worker', 'splunk')" in ps1
    assert "if ($service -ne 'celery-worker') { $lines += '        read_only: true' }" in ps1
