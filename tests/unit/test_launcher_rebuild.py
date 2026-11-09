"""The launcher's rebuild decision (prepare_app_copy): an app copy by its version file, a
server's git checkout by commit, a desktop checkout never."""

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def decide(root: Path, server: bool) -> str:
    """BUILD_FLAG and BUILT_VERSION after prepare_app_copy, run on its own against root."""
    launcher = (REPO / "rowanholt").read_text()
    function = re.search(r"^prepare_app_copy\(\) \{\n.*?^\}\n", launcher, re.S | re.M).group(0)
    script = f'{function}\nROOT="$1"; SERVER={"true" if server else "false"}\nprepare_app_copy >/dev/null\necho "$BUILD_FLAG|$BUILT_VERSION"'
    return subprocess.run(["bash", "-c", script, "bash", str(root)], capture_output=True, text=True, check=True).stdout.strip()


def checkout(root: Path) -> str:
    """A git repository with one commit; its HEAD."""
    run = lambda *a: subprocess.run(["git", "-C", str(root), *a], capture_output=True, text=True, check=True).stdout.strip()
    run("init", "-q")
    (root / "f").write_text("x")
    run("add", "f")
    run("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "one")
    return run("rev-parse", "HEAD")


def test_a_server_checkout_rebuilds_until_its_commit_is_built(tmp_path):
    head = checkout(tmp_path)
    assert decide(tmp_path, server=True) == f"--build|{head}"
    (tmp_path / ".rowanholt-built").write_text(head + "\n")
    assert decide(tmp_path, server=True) == f"|{head}"


def test_a_desktop_checkout_is_left_to_rebuild_when_it_chooses(tmp_path):
    checkout(tmp_path)
    assert decide(tmp_path, server=False) == "|"


def test_an_app_copy_rebuilds_by_its_version_file(tmp_path):
    (tmp_path / ".rowanholt-version").write_text("2.1.0\n")
    assert decide(tmp_path, server=False) == "--build|2.1.0"
    (tmp_path / ".rowanholt-built").write_text("2.1.0\n")
    assert decide(tmp_path, server=False) == "|2.1.0"
