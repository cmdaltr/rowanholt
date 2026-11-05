"""rowanholt server backup: the database dump (read back before it counts), the user store and the
settings into a dated, owner-only folder, the newest N kept. Run against a copy of the script in a
temporary tree with a stand-in docker on PATH."""
import os
import shutil
import stat
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# docker ps: the database is up unless NO_DB; exec pg_dump: a dump; exec -i pg_restore --list: reads it
# back, failing on BAD_DUMP
FAKE_DOCKER = """#!/bin/sh
case "$1" in
  ps) [ -z "$NO_DB" ] && echo 4f1c9e2ab3d7 ;;
  exec)
    case "$*" in
      *pg_dump*) printf 'PGDMP fake dump' ;;
      *pg_restore*) cat > /dev/null; [ -z "$BAD_DUMP" ] ;;
      *users.json*) echo '{"via": "backend"}' ;;
    esac ;;
esac
"""


def tree(tmp_path: Path) -> tuple:
    root = tmp_path / "rowanholt"
    (root / "scripts" / "server").mkdir(parents=True)
    shutil.copy(REPO / "scripts" / "server" / "server-backup.sh", root / "scripts" / "server")
    (root / ".env").write_text("SECRET_KEY=x\n")
    (root / "src" / "web" / "backend" / "data").mkdir(parents=True)
    (root / "src" / "web" / "backend" / "data" / "users.json").write_text("{}")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text(FAKE_DOCKER)
    (bin_dir / "docker").chmod(0o755)
    return root, {**os.environ, "PATH": f"{bin_dir}:/usr/bin:/bin:/usr/sbin"}


def backup(root: Path, env: dict, dest: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(root / "scripts" / "server" / "server-backup.sh"), str(dest), *args],
                          env=env, capture_output=True, text=True)


def test_state_backed_up_owner_only(tmp_path):
    root, env = tree(tmp_path)
    done = backup(root, env, tmp_path / "backups")
    assert done.returncode == 0, done.stderr
    [out] = (tmp_path / "backups").iterdir()
    assert sorted(p.name for p in out.iterdir()) == [".env", "rowanholt.pgdump", "users.json"]
    assert (out / "rowanholt.pgdump").read_text().startswith("PGDMP")
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    assert stat.S_IMODE((out / ".env").stat().st_mode) == 0o600


def test_root_owned_user_store_read_through_the_backend(tmp_path):
    """The backend writes users.json as root, mode 600: the Mini's nightly run, as the server's user,
    couldn't read it (5 November 2026)."""
    root, env = tree(tmp_path)
    users = root / "src" / "web" / "backend" / "data" / "users.json"
    users.chmod(0)
    try:
        done = backup(root, env, tmp_path / "backups")
    finally:
        users.chmod(0o600)
    assert done.returncode == 0, done.stderr
    [out] = (tmp_path / "backups").iterdir()
    assert (out / "users.json").read_text().strip() == '{"via": "backend"}'


def test_newest_kept(tmp_path):
    root, env = tree(tmp_path)
    dest = tmp_path / "backups"
    dest.mkdir()
    for stamp in ("20261101-030000", "20261102-030000", "20261103-030000"):
        (dest / f"rowanholt-{stamp}").mkdir()
    (dest / "notes").mkdir()  # not a backup: left alone
    assert backup(root, env, dest, "--keep", "2").returncode == 0
    kept = sorted(p.name for p in dest.iterdir())
    assert kept[0] == "notes" and kept[1] == "rowanholt-20261103-030000" and len(kept) == 3


def test_unreadable_dump_is_not_a_backup(tmp_path):
    root, env = tree(tmp_path)
    done = backup(root, {**env, "BAD_DUMP": "1"}, tmp_path / "backups")
    assert done.returncode == 1 and "doesn't read back" in done.stderr
    assert list((tmp_path / "backups").iterdir()) == []


def test_needs_the_database_running(tmp_path):
    root, env = tree(tmp_path)
    done = backup(root, {**env, "NO_DB": "1"}, tmp_path / "backups")
    assert done.returncode == 1 and "isn't running" in done.stderr
