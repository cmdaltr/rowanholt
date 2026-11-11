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


def test_the_crontabs_are_collected_with_the_extras(tmp_path):
    root, dest, out = data_volume(tmp_path)
    (root / "private" / "var" / "at" / "tabs").mkdir(parents=True)
    (root / "private" / "var" / "at" / "tabs" / "root").write_text("* * * * * /tmp/evil.sh\n")
    mac.collect_macos_extras(str(root), str(dest) + "/", "disk.img::macOS", str(out), "collecting", 0)
    assert (dest / "cron" / "root+crontab").read_text() == "* * * * * /tmp/evil.sh\n"


def test_zsh_files_and_terminal_sessions_are_collected(tmp_path):
    root, dest, out = data_volume(tmp_path)
    home = root / "Users" / "admin"
    (home / ".zsh_sessions").mkdir(parents=True)
    (home / ".zshrc").write_text("set +o history\n")
    (home / ".zsh_sessions" / "037A40EC.history").write_text("whoami\n")
    (home / ".zsh_sessions" / "037A40EC.session").write_text("not history\n")
    collect(root, dest, out, "/Users/")
    assert (dest / "admin+zshrc").read_text() == "set +o history\n"
    assert (dest / "admin+zsh_sessions+037A40EC_history+zsh_history").read_text() == "whoami\n"
    assert not list(dest.glob("*session+*"))
