"""Carving reads EWF images' raw media, not the E01 container (E8)."""
import sys
from pathlib import Path

# Appended, not prepended: src/analysis/platform would shadow the stdlib module.
sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt import mount  # noqa: E402
from rowanholt.collect.files.carve import carve_source  # noqa: E402


def test_raw_images_are_carved_as_they_are():
    assert carve_source("/evidence/disk.dd") == "/evidence/disk.dd"


def test_ewf_images_are_carved_from_ewfmount_raw(tmp_path, monkeypatch):
    raw = tmp_path / "ewf_mount00" / "ewf1"
    raw.parent.mkdir()
    raw.write_bytes(b"\0" * 512)
    monkeypatch.setattr(mount, "EWF_RAW", {str(tmp_path / "case" / "sub" / "WIN.E01"): str(raw)})
    # carve names the image from the source root; it was mounted from a subdirectory
    assert carve_source(str(tmp_path / "case" / "WIN.E01")) == str(raw)


def test_unmounted_ewf_is_skipped_not_carved_as_a_container(monkeypatch):
    monkeypatch.setattr(mount, "EWF_RAW", {})
    assert carve_source("/evidence/WIN.Ex01") is None
