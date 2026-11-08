"""Browser history, setupapi's USB installs and Volatility's plugins as JSON Lines with the
envelope (they were JSON arrays, the USB one patched together from strings), times in UTC."""
import json
import sqlite3
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.append(str(REPO / "src" / "analysis"))

from rowanholt.core.records import check_file, read_records  # noqa: E402
from rowanholt.memory import extract  # noqa: E402
from rowanholt.process import browser  # noqa: E402
from rowanholt.process.extractions.usb import extract_usb  # noqa: E402


def table(path):
    assert check_file(path) == []
    return [r for _, r in read_records(path)]


def test_chrome_history_and_downloads(tmp_path):
    out = str(tmp_path / "out") + "/"
    raw = tmp_path / "out" / "HOST" / "artefacts" / "raw" / "browsers" / "bob" / "chrome"
    raw.mkdir(parents=True)
    db = sqlite3.connect(raw / "History")
    db.executescript("""
        CREATE TABLE urls (id INTEGER, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);
        CREATE TABLE visits (id INTEGER, from_visit INTEGER);
        CREATE TABLE downloads (url TEXT, full_path TEXT, start_time INTEGER, end_time INTEGER,
                                received_bytes INTEGER, total_bytes INTEGER);""")
    # 2026-10-29 14:03:11 UTC in Chrome's microseconds since 1601
    chrome = (1793282591 + 11644473600) * 1000000
    db.execute("INSERT INTO urls VALUES (1, 'http://198.51.100.23/a,b', 'a \"b\"', 2, ?)", (chrome,))
    db.execute("INSERT INTO downloads VALUES ('http://198.51.100.23/x.exe', 'C:\\Users\\bob\\x.exe', ?, ?, 10, 10)",
               (chrome, chrome))
    db.commit()
    db.close()
    browser.process_browser("", "'HOST'", out, "HOST::Windows", "/", "processing", str(raw / "History"))
    cooked = tmp_path / "out" / "HOST" / "artefacts" / "cooked" / "browsers" / "chrome"
    [visit] = table(cooked / "bob+History.jsonl")
    assert visit["timestamp"] == "2026-10-29T14:03:11Z" and visit["url"] == "http://198.51.100.23/a,b"
    assert visit["host"] == "HOST" and visit["artefact"] == "browsers/chrome/bob+History"
    assert visit["techniques"] == [browser.BROWSER_MITRE_MAPPING["browser_history"]["technique_id"]]
    [download] = table(cooked / "bob+History_downloads.jsonl")
    assert download["timestamp"] == "2026-10-29T14:03:11Z" and download["file_path"] == "C:/Users/bob/x.exe"
    # a second run replaces the table rather than adding to it
    browser.process_browser("", "'HOST'", out, "HOST::Windows", "/", "processing", str(raw / "History"))
    assert len(table(cooked / "bob+History.jsonl")) == 1


SETUPAPI = """[Device Install Log]
     OS Version = 10.0.19045
     Service Pack = 0.0

[BeginLog]

[Boot Session: 2026/10/29 09:00:01.500]

>>>  [Device Install (Hardware initiated) - USB\\VID_0781&PID_5583\\4C530001]
>>>  Section start 2026/10/29 14:03:11.123
     ump: Creating Install Process: DrvInst.exe 14:03:11.130
<<<  Section end 2026/10/29 14:03:12.456
<<<  [Exit status: SUCCESS]

"""


def test_usb_installs(tmp_path):
    out = str(tmp_path / "out") + "/"
    (tmp_path / "out" / "HOST" / "artefacts" / "cooked").mkdir(parents=True)
    extract_usb(out, "HOST::Windows", "/", {}, [], SETUPAPI,
                str(tmp_path / "out" / "HOST" / "artefacts" / "raw" / "setupapi.dev.log"))
    rows = table(tmp_path / "out" / "HOST" / "artefacts" / "cooked" / "usb.log.jsonl")
    [install] = [r for r in rows if "VID_0781" in r.get("Artefact", "")]
    assert install["timestamp"] == "2026-10-29T14:03:11.123Z"
    assert install["source_path"] == "artefacts/raw/setupapi.dev.log"


class FakeVol:
    def __init__(self, rows):
        self.stdout = ("Volatility 3 Framework 2.28.2\n" + json.dumps(rows)).encode()

    def communicate(self):
        return self.stdout, b""


def test_volatility_plugin(tmp_path, monkeypatch):
    out = str(tmp_path / "out") + "/"
    (tmp_path / "out" / "HOST").mkdir(parents=True)
    rows = [{"PID": 4, "ImageFileName": "System", "CreateTime": "2026-10-29T14:03:11+00:00", "__children": []},
            {"PID": 812, "ImageFileName": "upd.exe", "CreateTime": None, "__children": []}]
    monkeypatch.setattr(extract.subprocess, "Popen", lambda *a, **kw: FakeVol(rows))
    extract.use_plugins(out, "", "'HOST'", "/evidence/mem", "3", ".raw", "HOST/", "Win10", "windows.pslist.PsList")
    path = tmp_path / "out" / "HOST" / "memory_windows.pslist.PsList.jsonl"
    found = table(path)
    assert [(r["PID"], r["timestamp"]) for r in found] == [(4, "2026-10-29T14:03:11Z"), (812, None)]
    assert found[0]["host"] == "HOST" and found[0]["artefact"] == "memory_windows.pslist.PsList"
    assert found[0]["source_path"] == "mem.raw" and "__children" not in found[0]
    # already there: the plugin isn't run again
    monkeypatch.setattr(extract.subprocess, "Popen", lambda *a, **kw: (_ for _ in ()).throw(AssertionError))
    extract.use_plugins(out, "", "'HOST'", "/evidence/mem", "3", ".raw", "HOST/", "Win10", "windows.pslist.PsList")


def test_journal_records_decode_binary_fields():
    from rowanholt.process.linux import journal_records
    output = (json.dumps({"__REALTIME_TIMESTAMP": "1793282591000000", "MESSAGE": [104, 105]}) + "\nnot json\n").encode()
    assert list(journal_records(output)) == [{"__REALTIME_TIMESTAMP": "1793282591000000", "MESSAGE": "hi"}]
