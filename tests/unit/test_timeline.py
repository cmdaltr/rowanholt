"""Plaso timeline: psteal runs unattended over every partition, and an empty run fails (E12);
its json_line events become artefacts/plaso_timeline.jsonl."""
import json
import os
import sys
from pathlib import Path

# Appended, not prepended: src/analysis/platform would shadow the stdlib module.
sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.core.records import check_file, read_records  # noqa: E402
from rowanholt.process import timeline  # noqa: E402


class FakePsteal:
    def __init__(self, cmd, writes, code):
        self.cmd, self.returncode = cmd, code
        with open(timeline.PSTEAL_OUTPUT, "w") as out:  # psteal runs in .plaso/
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
    events = [
        {"__container_type__": "event", "timestamp": 1793990000000000, "timestamp_desc": "Last Written Time",
         "message": "C:\\Users\\bob\\a,b.txt", "parser": "filestat", "display_name": "OS:/a,b.txt"},
        {"__container_type__": "event", "timestamp": 0, "message": "no time"},
    ]
    ok, cmd = run(tmp_path, monkeypatch, "".join(json.dumps(e) + "\n" for e in events))
    assert ok
    assert cmd[cmd.index("-o") + 1] == "json_line"
    path = tmp_path / "out" / "disk.raw" / "artefacts" / "plaso_timeline.jsonl"
    assert check_file(path) == []
    [(_, event)] = read_records(path)  # the event without a time is left out, commas and all kept
    assert event["timestamp"] == "2026-11-06T18:33:20Z" and event["message"] == events[0]["message"]
    assert event["host"] == "disk.raw" and "__container_type__" not in event
    for flag in ("--partitions", "--volumes", "--unattended"):
        assert flag in cmd
    assert cmd[cmd.index("--partitions") + 1] == "all"


def test_an_empty_timeline_is_a_failure(tmp_path, monkeypatch):
    ok, _ = run(tmp_path, monkeypatch, "")
    assert not ok
    assert not os.path.exists(tmp_path / "out" / "disk.raw" / "artefacts" / "plaso_timeline.jsonl")


def test_a_failed_psteal_is_a_failure(tmp_path, monkeypatch):
    ok, _ = run(tmp_path, monkeypatch, "partial", code=1)
    assert not ok
