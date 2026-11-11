"""Collecting from a macOS Data volume (apfs-fuse's, macOS 10.15 and later): /etc and /var are only
under /private, and apfs-fuse is case-sensitive (Library/Keychains, not keychains)."""
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.collect import mac  # noqa: E402


def collect(root: Path, dest: Path, out: Path, relative: str) -> None:
    mac.collect_mac_artefacts(str(dest) + "/", "disk.img::macOS", str(root) + relative, str(root), str(out),
                              False, "collecting", "", False, 0, False, "", "")


def data_volume(tmp_path):
    root, dest, out = tmp_path / "root", tmp_path / "raw", tmp_path / "out"
    (root / "private" / "etc").mkdir(parents=True)
    (root / "private" / "etc" / "hosts").write_text("127.0.0.1 localhost\n")
    (root / "private" / "var" / "log").mkdir(parents=True)
    (root / "private" / "var" / "log" / "install.log").write_text("installed\n")
    dest.mkdir()
    out.mkdir()
    return root, dest, out


def test_private_etc_and_var_log_are_collected(tmp_path):
    root, dest, out = data_volume(tmp_path)
    collect(root, dest, out, "/private/etc/hosts")
    collect(root, dest, out, "/private/var/log")
    assert (dest / "hosts").read_text().startswith("127.0.0.1")
    assert (dest / "logs" / "var+install.log").exists()


def test_private_etc_collects_the_extras(tmp_path, monkeypatch):
    root, dest, out = data_volume(tmp_path)
    seen = []
    monkeypatch.setattr(mac, "collect_macos_extras", lambda mnt, *rest: seen.append(mnt))
    collect(root, dest, out, "/private/etc")
    assert seen == [str(root)]


def test_a_users_keychain_is_collected(tmp_path):
    root, dest, out = data_volume(tmp_path)
    keychains = root / "Users" / "admin" / "Library" / "Keychains"
    keychains.mkdir(parents=True)
    (keychains / "login.keychain-db").write_bytes(b"kych")
    collect(root, dest, out, "/Users/")
    assert (dest / "admin+login.keychain-db").exists()
