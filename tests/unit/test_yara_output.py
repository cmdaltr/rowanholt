"""yara -s output as Elrond reads it: every match gets a row, string or not."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.post.yara import yara_rows  # noqa: E402

OUTPUT = """Suspicious_PowerShell_Command /mnt/x/ProgramData/Lab/sync.ps1
0x1a:$enc: -EncodedCommand
0x40:$iwr: Invoke-WebRequest http://c2:8080/a
Big_Unsigned_PE /mnt/x/Users/a/Downloads/setup file.exe
Persistence_Registry_Keys /mnt/x/Windows/System32/config/SOFTWARE
0x99:$run: CurrentVersion\\Run
"""


def test_every_match_gets_a_row() -> None:
    rows, matched = yara_rows(OUTPUT)
    assert [(r[0], r[3]) for r in rows] == [("Suspicious_PowerShell_Command", "enc"),
                                             ("Suspicious_PowerShell_Command", "iwr"),
                                             ("Big_Unsigned_PE", "-"), ("Persistence_Registry_Keys", "run")]
    assert rows[1][4] == "Invoke-WebRequest http://c2:8080/a"  # the data's own colons kept
    assert ("Big_Unsigned_PE", "/mnt/x/Users/a/Downloads/setup file.exe") in matched


def test_a_condition_only_match_at_the_end_is_kept() -> None:
    rows, _ = yara_rows("Big_Unsigned_PE /mnt/x/a.exe\n")
    assert rows == [("Big_Unsigned_PE", "/mnt/x/a.exe", "-", "-", "-")]
