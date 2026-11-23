"""scripts/install-suite.sh and .ps1 against fake GitHub trees: each product's own installer, fetched from
its latest release's tag and run with that tag. The same file is in Ostraka, Rowanholt and Shikari."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from pathlib import Path

import pytest

# The repository this copy is in: the same file is in all three, at different depths
ROOT = next(p for p in Path(__file__).resolve().parents if (p / "scripts" / "install-suite.sh").is_file())

SH = ROOT / "scripts" / "install-suite.sh"
PS1 = ROOT / "scripts" / "install-suite.ps1"
TAGS = {"ostraka": "v0.2.0", "rowanholt": "v2.1.1", "shikari": "v2.1.0"}


def github(tmp_path: Path, *, missing: str = "", failing: str = "") -> tuple[dict[str, str], Path]:
    """A releases API and a raw tree; each installer writes its name and arguments to the log."""
    log = tmp_path / "log"
    for product, tag in TAGS.items():
        if product != missing:
            latest = tmp_path / "api" / "repos" / "cmdaltr" / product / "releases" / "latest"
            latest.parent.mkdir(parents=True)
            latest.write_text(json.dumps({"tag_name": tag, "name": f"{product} {tag}"}, indent=2))
        desktop = tmp_path / "raw" / "cmdaltr" / product / tag / "desktop"
        desktop.mkdir(parents=True)
        code = 3 if product == failing else 0
        (desktop / "install.sh").write_text(f'#!/bin/sh\necho "{product} $*" >> "{log}"\nexit {code}\n')
        (desktop / "install.ps1").write_text(
            f'param([string]$Version, [switch]$Launch)\n'
            f'Add-Content -Path "{log}" -Value "{product} -Version $Version$(if ($Launch) {{ \' -Launch\' }})"\n'
            f"exit {code}\n"
        )
    env = {
        **os.environ,
        "SUITE_GITHUB_API": (tmp_path / "api").as_uri(),
        "SUITE_GITHUB_RAW": (tmp_path / "raw").as_uri(),
        "GH_TOKEN": "",
        "GITHUB_TOKEN": "",
        "PATH": "/usr/bin:/bin",  # no gh
    }
    return env, log


def run_sh(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(["sh", str(SH), *args], env=env, capture_output=True, text=True, timeout=60)


def lines(log: Path) -> list[str]:
    return log.read_text().splitlines() if log.exists() else []


def test_installs_all_three_each_with_its_own_latest_tag(tmp_path):
    env, log = github(tmp_path)
    r = run_sh([], env)
    assert r.returncode == 0, r.stderr
    assert lines(log) == ["ostraka --version v0.2.0", "rowanholt --version v2.1.1", "shikari --version v2.1.0"]
    assert "Installed: Ostraka Rowanholt Shikari" in r.stdout


def test_only_skip_and_launch(tmp_path):
    env, log = github(tmp_path)
    assert run_sh(["--only", "ostraka,shikari", "--skip", "shikari", "--launch"], env).returncode == 0
    assert lines(log) == ["ostraka --version v0.2.0 --launch"]


def test_an_unknown_product_is_refused_before_anything_runs(tmp_path):
    env, log = github(tmp_path)
    r = run_sh(["--only", "ostraka,vectr"], env)
    assert r.returncode == 1 and "no vectr in the suite" in r.stderr and lines(log) == []


def test_a_dry_run_installs_nothing(tmp_path):
    env, log = github(tmp_path)
    r = run_sh(["--dry-run"], env)
    assert r.returncode == 0 and lines(log) == []
    assert "/cmdaltr/shikari/v2.1.0/desktop/install.sh --version v2.1.0" in r.stdout


def test_one_failure_doesnt_stop_the_others_but_fails_the_run(tmp_path):
    env, log = github(tmp_path, missing="rowanholt", failing="shikari")
    r = run_sh([], env)
    assert r.returncode == 1
    assert lines(log) == ["ostraka --version v0.2.0", "shikari --version v2.1.0"]
    assert "Not installed: Rowanholt Shikari" in r.stderr


def test_the_scripts_and_diagrams_are_the_same_in_every_repository():
    for sibling in {"ostraka", "rowanholt", "shikari"} - {ROOT.name}:
        other = ROOT.parent / sibling
        if not (other / "scripts").is_dir():
            pytest.skip(f"{sibling} isn't checked out beside {ROOT.name}")
        for name in ("scripts/install-suite.sh", "scripts/install-suite.ps1", "docs/suite/draw.py"):
            assert (other / name).read_bytes() == (ROOT / name).read_bytes(), f"{sibling}/{name}"


IMAGE = (
    "mcr.microsoft.com/powershell:7.5-azurelinux-3.0-arm64"
    if platform.machine() in ("arm64", "aarch64")
    else "mcr.microsoft.com/powershell:latest"
)
USE_DOCKER = os.environ.get("OSTRAKA_TEST_PWSH_DOCKER") == "1" and bool(shutil.which("docker"))


@pytest.mark.skipif(not shutil.which("pwsh") and not USE_DOCKER, reason="needs pwsh, or OSTRAKA_TEST_PWSH_DOCKER=1")
def test_the_powershell_twin_does_the_same(tmp_path):
    env, log = github(tmp_path, missing="rowanholt")
    args = ["-NoProfile", "-File", str(PS1), "-Skip", "shikari", "-Launch"]
    suite = {k: env[k] for k in ("SUITE_GITHUB_API", "SUITE_GITHUB_RAW")}
    if shutil.which("pwsh"):
        cmd, environ = ["pwsh", *args], {**os.environ, **suite, "GH_TOKEN": "", "GITHUB_TOKEN": ""}
    else:  # the same paths inside the container, so the file:// trees and the log line up
        cmd = ["docker", "run", "--rm", "-v", f"{tmp_path}:{tmp_path}", "-v", f"{PS1.parent}:{PS1.parent}:ro"]
        for key, value in suite.items():
            cmd += ["-e", f"{key}={value}"]
        cmd, environ = [*cmd, IMAGE, "pwsh", *args], None
    r = subprocess.run(cmd, env=environ, capture_output=True, text=True, timeout=300)  # noqa: S603
    assert r.returncode == 1, r.stdout + r.stderr
    assert lines(log) == ["ostraka -Version v0.2.0 -Launch"], r.stdout + r.stderr
    assert "Not installed: Rowanholt" in r.stdout
