"""Elrond's file-signature (magic-byte) check and the Artemis status.log reader."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.analysis.analysis import _analyse_artemis_mft_from_status_log, signature_mismatch  # noqa: E402


def test_executables_are_any_mz_or_windows_delta() -> None:
    for header in (b"MZ\x90\x00", b"MZP\x00", b"MZ\x80\x00", b"DCN\x01\x00", b"PA30\x00"):
        assert not signature_mismatch("x.dll", header)
    assert signature_mismatch("invoice.exe", b"%PDF-1.7")


def test_extension_case_does_not_matter() -> None:
    assert signature_mismatch("REPORT.DOCX", b"MZ\x90\x00")
    assert not signature_mismatch("REPORT.DOCX", b"PK\x03\x04")


def test_images_under_another_image_extension_are_not_reported() -> None:
    assert not signature_mismatch("cached.png", b"\xff\xd8\xff\xe0")
    assert signature_mismatch("photo.jpg", b"MZ\x90\x00")


def test_pdf_header_may_follow_leading_bytes() -> None:
    assert not signature_mismatch("a.pdf", b"\r\n" * 10 + b"%PDF-1.4")
    assert signature_mismatch("a.pdf", b"PK\x03\x04")


def test_renamed_rtf_doc_is_reported_and_unknown_types_are_not() -> None:
    assert signature_mismatch("cv.doc", b"{\\rtf1\\ansi")
    assert not signature_mismatch("cv.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
    assert not signature_mismatch("notes.txt", b"MZ")
    assert not signature_mismatch("empty.exe", b"")


def test_status_log_analyses_only_the_mft_it_names(tmp_path) -> None:
    (tmp_path / "status.log").write_text("prefetch:aaa.jsonl\nmft:bbb.jsonl\nrawfiles:missing.jsonl\n")
    for name in ("aaa.jsonl", "bbb.jsonl"):
        (tmp_path / name).write_text("{}\n")
    seen = []
    found = _analyse_artemis_mft_from_status_log(str(tmp_path), "status.log", "", "", "", "", "",
                                                lambda *a: seen.append(Path(a[2]).name))
    assert found and seen == ["bbb.jsonl"]


def test_status_log_without_an_mft_is_not_a_check(tmp_path) -> None:
    (tmp_path / "status.log").write_text("prefetch:aaa.jsonl\nmft:missing.jsonl\n")
    (tmp_path / "aaa.jsonl").write_text("{}\n")
    seen = []
    assert not _analyse_artemis_mft_from_status_log(str(tmp_path), "status.log", "", "", "", "", "",
                                                    lambda *a: seen.append(a))
    assert seen == []


def test_by_design_mismatches_are_exempt() -> None:
    from rowanholt.analysis.analysis import SIGNATURE_EXEMPT
    for path in ("/hiberfil.sys", "/pagefile.sys", "/$Recycle.Bin/S-1-5-21-1-1105/$II3DF3L.zip",
                 "/Windows/Installer/{397F4DE2-3C5A-415C-9A36-1D8C2B30B92D}/ARPPRODUCTICON.exe"):
        assert SIGNATURE_EXEMPT.match(path)
    for path in ("/$Recycle.Bin/S-1-5-21-1-1105/$RI3DF3L.zip", "/Users/a/hiberfil.sys", "/Users/a/Pictures/shield.jpg"):
        assert not SIGNATURE_EXEMPT.match(path)
    # A COM program has no header
    assert not signature_mismatch("etfsboot.com", b"\xfa\x33\xc0\x8e\xd0\xbc\x00\x7c")
