"""Plaso timeline: psteal runs unattended over every partition, and an empty run fails (E12)."""
import os
import sys
from pathlib import Path

# Appended, not prepended: src/analysis/platform would shadow the stdlib module.
sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.process import timeline  # noqa: E402


class FakePsteal:
    def __init__(self, cmd, writes, code):
        self.cmd, self.returncode = cmd, code
        with open("plaso_timeline.csvtmp", "w") as out:  # psteal runs in .plaso/
            out.write(writes)

    def communicate(self):
        return None, None


def run(tmp_path, monkeypatch, writes, code=0):
    calls = []
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "disk.raw").write_bytes(b"\0")
    (tmp_path / "out" / "disk.raw" / "artefacts").mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(timeline, "find_psteal", lambda: "/usr/local/bin/psteal")
    monkeypatch.setattr(timeline.time, "sleep", lambda _: None)
    monkeypatch.setattr(timeline.subprocess, "Popen",
                        lambda cmd, **kw: calls.append(cmd) or FakePsteal(cmd, writes, code))
    ok = timeline.create_plaso_timeline("", str(tmp_path / "out") + "/", "timeline", "disk.raw::Linux",
                                        str(tmp_path / "src"), "disk.raw")
    return ok, calls[0]


def test_psteal_answers_its_own_prompts(tmp_path, monkeypatch):
    header = "datetime,timestamp_desc,source,source_long,message,parser,display_name,tag\n"
    ok, cmd = run(tmp_path, monkeypatch, header + "2020-01-01T00:00:00,a,b,c,d,e,f,g\n")
    assert ok
    for flag in ("--partitions", "--volumes", "--unattended"):
        assert flag in cmd
    assert cmd[cmd.index("--partitions") + 1] == "all"


def test_an_empty_timeline_is_a_failure(tmp_path, monkeypatch):
    ok, _ = run(tmp_path, monkeypatch, "")
    assert not ok
    assert not os.path.exists(tmp_path / "out" / "disk.raw" / "artefacts" / "plaso_timeline.csv")


def test_a_failed_psteal_is_a_failure(tmp_path, monkeypatch):
    ok, _ = run(tmp_path, monkeypatch, "partial", code=1)
    assert not ok
