"""An update unpacks over the copy already there: the files a release dropped go (the tarball's
.rowanholt-removed), local state and anything outside the copy stay."""

import re
import shutil
import subprocess
import tarfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                          capture_output=True, text=True, check=True).stdout


def release(tmp_path: Path) -> Path:
    """A repository whose history dropped App.js (renamed to App.jsx) and an once-tracked data file now
    ignored, and its source tarball"""
    repo = tmp_path / "repo"
    (repo / "desktop").mkdir(parents=True)
    shutil.copy(REPO / "desktop" / "source-tarball.sh", repo / "desktop")
    (repo / "src").mkdir()
    (repo / "src" / "App.js").write_text("old")
    (repo / "data").mkdir()
    (repo / "data" / "users.json").write_text("{}")
    git(repo, "init", "-q")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "one")
    git(repo, "mv", "src/App.js", "src/App.jsx")
    git(repo, "rm", "-q", "--cached", "data/users.json")
    (repo / ".gitignore").write_text("data/\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "two")
    out = tmp_path / "r.tar.gz"
    subprocess.run(["bash", str(repo / "desktop" / "source-tarball.sh"), str(out), "9.9.9"], check=True)
    return out


def test_the_tarball_lists_dropped_files_but_not_local_state(tmp_path):
    with tarfile.open(release(tmp_path)) as tar:
        listed = tar.extractfile("rowanholt-9.9.9/.rowanholt-removed").read().decode().split()
    assert listed == ["src/App.js"]


def test_the_linux_launcher_removes_them_and_nothing_else(tmp_path):
    tarball = release(tmp_path)
    # A hostile list can't reach outside the copy
    staged = tmp_path / "staged"
    with tarfile.open(tarball) as tar:
        tar.extractall(staged, filter="data")
    with open(staged / "rowanholt-9.9.9" / ".rowanholt-removed", "a") as f:
        f.write("../outside\n/etc/hosts\n")
    with tarfile.open(tarball, "w:gz") as tar:
        tar.add(staged / "rowanholt-9.9.9", "rowanholt-9.9.9")

    copy = tmp_path / "copy"
    (copy / "src").mkdir(parents=True)
    (copy / "src" / "App.js").write_text("old")
    (copy / "data").mkdir()
    (copy / "data" / "users.json").write_text("{}")
    (copy / ".env").write_text("k")
    (tmp_path / "outside").write_text("keep")

    launcher = (REPO / "desktop" / "linux" / "rowanholt-app.sh").read_text()
    function = re.search(r"^unpack_to\(\) \{\n.*?^\}\n", launcher, re.S | re.M).group(0)
    script = f'{function}\napp_version() {{ echo 9.9.9; }}\nBUNDLED="$1"\nunpack_to "$2"'
    subprocess.run(["bash", "-c", script, "bash", str(tarball), str(copy)], check=True)

    assert not (copy / "src" / "App.js").exists()
    assert (copy / "src" / "App.jsx").read_text() == "old"
    assert (copy / "data" / "users.json").exists() and (copy / ".env").exists()
    assert (tmp_path / "outside").read_text() == "keep"
