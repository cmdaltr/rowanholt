"""Loop-device teardown (mount.release_loop_devices, E9): kpartx mappings go before losetup."""
import sys
from pathlib import Path

# Appended, not prepended, as it always was (src/analysis/platform shadowed the stdlib module until it became platform_adapters).
sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt import mount  # noqa: E402


def test_kpartx_mappings_are_removed_before_losetup(monkeypatch):
    calls = []

    def run(cmd):
        calls.append(cmd)
        return (0, "/dev/loop9: []: (/x.img)\n") if cmd == ["losetup", "-a"] else (0, "")

    monkeypatch.setattr(mount.glob, "glob", lambda _: ["/dev/mapper/loop3p1", "/dev/mapper/loop3p2"])
    monkeypatch.setattr(mount, "_run_quietly", run)
    monkeypatch.setattr(mount.os.path, "exists", lambda _: False)
    left = mount.release_loop_devices()
    assert calls.index(["kpartx", "-d", "/dev/loop3"]) < calls.index(["losetup", "-D"])
    assert ["umount", "/dev/mapper/loop3p2"] in calls
    assert calls.count(["kpartx", "-d", "/dev/loop3"]) == 1
    assert left == ["/dev/loop9"]


def test_missing_tools_are_not_an_error(monkeypatch):
    monkeypatch.setattr(mount.glob, "glob", lambda _: [])
    monkeypatch.setattr(mount.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError()))
    assert mount.release_loop_devices() == []
