"""Memory profile identification (memory/memory.py): the kernel banner decides Linux and macOS,
so an image without a particular process running isn't called Windows."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.memory import memory  # noqa: E402

LINUX_BANNER = ("Offset\tBanner\n0x97bcb88\tLinux version 6.8.0-147-generic (buildd@lcy02-amd64-081) "
                "#147-Ubuntu SMP PREEMPT_DYNAMIC (Ubuntu 6.8.0-147.147-generic 6.8.12)")


def identify(monkeypatch, tmp_path, outputs: dict) -> str:
    monkeypatch.setattr(memory, "vol3_check_os", lambda artefact, memext, plugin: outputs.get(plugin, ""))
    monkeypatch.setattr(memory, "dump_vol3_ziphex", lambda *args: None)
    return memory.identify_memory_profile(str(tmp_path) + "/", "0", str(tmp_path) + "/", "x.mem",
                                          str(tmp_path / "x.mem"), "3")


def test_a_linux_image_without_sudo_running_is_linux(monkeypatch, tmp_path) -> None:
    assert identify(monkeypatch, tmp_path, {"banners.Banners": LINUX_BANNER}) == "Linux"


def test_a_darwin_banner_is_macos(monkeypatch, tmp_path) -> None:
    banner = "Offset\tBanner\n0x1000\tDarwin Kernel Version 23.6.0: Mon Jul 29 21:14:30 PDT 2024"
    assert identify(monkeypatch, tmp_path, {"banners.Banners": banner}) == "macOS"


def test_windows_still_wins_first(monkeypatch, tmp_path) -> None:
    info = "Kernel Base\t0xf80002a5c000\nWindows\tntkrnlmp.pdb\nwindows 7"
    assert identify(monkeypatch, tmp_path, {"windows.info.Info": info, "banners.Banners": LINUX_BANNER}) == "Windows"


def test_five_level_paging_is_read_from_vmcoreinfo(tmp_path) -> None:
    on, off = tmp_path / "on.mem", tmp_path / "off.mem"
    on.write_bytes(b"\0" * 4096 + b"OSRELEASE=6.8.0-147-generic\nNUMBER(pgtable_l5_enabled)=1\n" + b"\0" * 4096)
    off.write_bytes(b"\0" * 4096 + b"NUMBER(pgtable_l5_enabled)=0\n")
    assert memory.five_level_paging(str(on))
    assert not memory.five_level_paging(str(off))
    assert not memory.five_level_paging(str(tmp_path / "missing.mem"))
