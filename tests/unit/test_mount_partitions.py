"""kpartx mounts every partition of a disk at the one mount point: it stops at the OS volume
rather than mounting the next partition over it, and a volume without Windows/ isn't Windows."""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt import mount  # noqa: E402
from rowanholt.core import identify  # noqa: E402

KPARTX = "".join(f"add map loop0p{n} (253:{n}): 0 8 linear /dev/loop0 {n}\n" for n in (1, 2, 3, 4))


def test_the_os_volume_is_kept_and_nothing_mounted_over_it(monkeypatch):
    calls, mounted = [], []

    def run(cmd, **_):
        calls.append(cmd)
        if cmd[0] == "mount" and cmd[-2] == "/dev/mapper/loop0p1" and cmd[2] != "exfat":
            return SimpleNamespace(returncode=32, stdout="", stderr="")  # the EFI partition: only "exfat" takes it
        if cmd[0] == "mount":
            mounted.append(cmd[-2])
        return SimpleNamespace(returncode=0, stdout=KPARTX if cmd[0] == "kpartx" else "", stderr="")

    found = {"/dev/mapper/loop0p1": "disk.dd", "/dev/mapper/loop0p2": "disk.dd::Windows10"}
    monkeypatch.setattr(mount.subprocess, "run", run)
    monkeypatch.setattr(mount, "identify_disk_image", lambda *a: found[mounted[-1]])
    allimgs, partitions = {}, []
    assert mount._mount_with_kpartx("/x/disk.dd", "/mnt/elrond_mount00", "disk.dd", allimgs, partitions, 0, "/out/")
    assert mounted == ["/dev/mapper/loop0p1", "/dev/mapper/loop0p2"]  # loop0p3 and loop0p4 never mounted over it
    assert ["umount", "/mnt/elrond_mount00"] in calls  # the EFI volume taken off again first
    assert allimgs == {"/mnt/elrond_mount00": "disk.dd::Windows10"}


def test_ntfs_without_a_windows_folder_is_not_identified(tmp_path, monkeypatch):
    monkeypatch.setattr(identify, "print_identification", lambda *a: None)
    for name in ("$Boot", "$LogFile", "$MFTMirr"):
        (tmp_path / name).write_text("")
    (tmp_path / "Recovery").mkdir()
    assert identify.identify_disk_image(0, "/out/", "disk.dd", str(tmp_path)) == "disk.dd"
    (tmp_path / "Windows" / "BrowserCore").mkdir(parents=True)
    assert identify.identify_disk_image(0, "/out/", "disk.dd", str(tmp_path)).startswith("disk.dd::Windows")
