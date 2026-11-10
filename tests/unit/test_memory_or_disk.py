"""Which images Elrond treats as memory outright, and which it mounts first (main.is_memory_image)."""
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.main import is_memory_image  # noqa: E402


def test_memory_extensions_and_formats_are_memory():
    for name in ("memory.mem", "host.vmem", "MEMORY.DMP", "box.lime", "x.aff4", "host-memdump.raw"):
        assert is_memory_image(name, "data"), name
    assert is_memory_image("hiberfil.sys", "MS Windows hibernation data")


def test_raw_disks_are_mounted_first():
    # disk.img is the lab's macOS sample, a raw APFS disk: once taken for memory, it was never mounted
    for name in ("disk.img", "image.001", "disk.dd", "disk.raw"):
        assert not is_memory_image(name, "DOS/MBR boot sector"), name
