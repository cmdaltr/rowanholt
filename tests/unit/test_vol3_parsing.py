"""Volatility 3's JSON, decoded as memory/extract.py now reads it, parses whole: paths keep single
backslashes, and a non-ASCII name or mixed quotes no longer lose the plugin's output."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.memory.volatility3.plugins.vol3_lin import linux_vol3  # noqa: E402
from rowanholt.memory.volatility3.plugins.vol3_win import windows_vol3  # noqa: E402


def as_extract_reads(rows) -> list:
    stdout = ("Volatility 3 Framework 2.28.2\n" + json.dumps(rows, ensure_ascii=False) + "\n").encode()
    return stdout.decode("utf-8", "replace").split("\n")


def test_windows_rows_survive_backslashes_unicode_and_quotes(tmp_path) -> None:
    rows = [{"PID": 4, "Path": "C:\\Windows\\System32\\a.exe"}, {"PID": 5, "Path": "C:\\Users\\Zoë\\b.exe"},
            {"PID": 6, "Args": "say \"hi\" it's"}]
    out = windows_vol3(str(tmp_path) + "/", "m", "3", "Win10", "VolatilitySymbolTable", "windows.pslist.PsList",
                       as_extract_reads(rows), {}, [])
    parsed = [json.loads(r) for r in out]
    assert [p["PID"] for p in parsed] == [4, 5, 6]
    assert parsed[0]["Path"] == "C:\\Windows\\System32\\a.exe"
    assert parsed[1]["Path"].endswith("Zoë\\b.exe") and parsed[2]["Args"] == "say \"hi\" it's"


def test_linux_rows_survive_unicode() -> None:
    out = linux_vol3("3", "linux", "VolatilitySymbolTable", "linux.pslist.PsList",
                     as_extract_reads([{"PID": 1, "COMM": "systemd"}, {"PID": 2, "COMM": "café"}]), {}, [])
    assert [json.loads(r)["PID"] for r in out] == [1, 2]
