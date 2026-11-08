"""Phones (--Mobile): evidence found and registered (core/mobile.py), ADB backups opened and laid
out (process/extractions/android_backup.py), device management read (mobile_config.py), and
iLEAPP/ALEAPP's reports cooked (process/mobile.py).

The LEAPP tools aren't run: a stand-in writes a report shaped like theirs (v2026.4.x): the
report folder named by --custom_output_folder, '_TSV Exports/<artefact>.tsv' as UTF-8 with a BOM,
tab-separated, a header row, and the header again wherever an artefact appended a second time.

Run: python3 -m unittest tests/unit/test_mobile.py
"""

import hashlib
import io
import json
import os
import plistlib
import sqlite3
import sys
import tarfile
import tempfile
import unittest
import zipfile
import zlib
from datetime import datetime
from pathlib import Path
from unittest import mock

# Appended, not prepended: src/analysis/platform would shadow the stdlib module.
sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.core import mobile as core_mobile  # noqa: E402
from rowanholt.core.records import read_records  # noqa: E402
from rowanholt.process import mobile  # noqa: E402
from rowanholt.process.extractions import android_backup, mobile_config  # noqa: E402

PASSWORD = "Correct-Horse-7"


# ---- synthetic evidence ------------------------------------------------------------------

def tar_bytes(members):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tar:
        for name, body in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))
    return out.getvalue()


AB_MEMBERS = {
    "apps/com.example.chat/_manifest": b"manifest",
    "apps/com.example.chat/db/messages.db": b"SQLite format 3\x00rest",
    "apps/com.example.chat/sp/settings.xml": b"<map/>",
    "apps/com.example.chat/f/../../../../escape.txt": b"nope",
    "shared/0/DCIM/Camera/IMG_0001.jpg": b"\xff\xd8\xff",
}


def _pad(data):
    n = 16 - len(data) % 16
    return data + bytes([n]) * n


def write_ab(path, members=AB_MEMBERS, password=None, version=5):
    payload = zlib.compress(tar_bytes(members))
    if password is None:
        path.write_bytes(b"ANDROID BACKUP\n%d\n1\nnone\n" % version + payload)
        return
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    user_salt, ck_salt, rounds = os.urandom(64), os.urandom(64), 1000
    user_iv, master_iv, master_key = os.urandom(16), os.urandom(16), os.urandom(32)
    checksum = hashlib.pbkdf2_hmac("sha1", android_backup._java_password_bytes(master_key, version), ck_salt, rounds, 32)
    blob = bytes([16]) + master_iv + bytes([32]) + master_key + bytes([32]) + checksum
    user_key = hashlib.pbkdf2_hmac("sha1", password.encode(), user_salt, rounds, 32)
    enc = Cipher(algorithms.AES(user_key), modes.CBC(user_iv)).encryptor()
    blob_enc = enc.update(_pad(blob)) + enc.finalize()
    enc = Cipher(algorithms.AES(master_key), modes.CBC(master_iv)).encryptor()
    body = enc.update(_pad(payload)) + enc.finalize()
    header = "ANDROID BACKUP\n{}\n1\nAES-256\n{}\n{}\n{}\n{}\n{}\n".format(
        version, user_salt.hex().upper(), ck_salt.hex().upper(), rounds, user_iv.hex().upper(), blob_enc.hex().upper())
    path.write_bytes(header.encode() + body)


MDM_PROFILE = {
    "PayloadDisplayName": "Corp Device Management", "PayloadIdentifier": "com.corp.mdm",
    "PayloadOrganization": "Corp Ltd", "PayloadType": "Configuration",
    "PayloadContent": [{"PayloadType": "com.apple.mdm", "ServerURL": "https://mdm.corp.example/server"},
                       {"PayloadType": "com.apple.security.root"}],
    "InstallDate": datetime(2026, 10, 30, 9, 15, 0),
}
WIFI_PROFILE = {"PayloadDisplayName": "Office Wi-Fi", "PayloadIdentifier": "com.corp.wifi",
                "PayloadContent": [{"PayloadType": "com.apple.wifi.managed"}]}
DEVICE_POLICIES = b"""<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<policies setup-complete="true">
<admin name="com.spy.app/com.spy.app.AdminReceiver">
<policies flags="17" />
<disable-camera value="true" />
</admin>
</policies>"""
DEVICE_OWNER = b"""<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<root><device-owner package="com.corp.dpc" name="" component="com.corp.dpc/.DeviceAdmin" /></root>"""


def ios_filesystem(root):
    profiles = root / "filesystem1/private/var/containers/Shared/SystemGroup/ABCD/Library/ConfigurationProfiles"
    profiles.mkdir(parents=True)
    (profiles / "profile-1a2b.stub").write_bytes(plistlib.dumps(MDM_PROFILE))
    # A signed .mobileconfig: CMS around the XML plist
    (profiles / "profile-3c4d.stub").write_bytes(b"0\x82\x05\x00junk" + plistlib.dumps(WIFI_PROFILE) + b"\x00sig")
    (profiles / "MDM.plist").write_bytes(plistlib.dumps({"ServerURL": "https://mdm.corp.example/server",
                                                         "Topic": "com.apple.mgmt.External.x"}))
    (root / "filesystem1/private/var/mobile/Library/SMS").mkdir(parents=True)
    (root / "filesystem1/private/var/mobile/Library/SMS/sms.db").write_bytes(b"SQLite format 3\x00")
    return root


def itunes_backup(root, encrypted=False, profile=True):
    root.mkdir(parents=True)
    (root / "Info.plist").write_bytes(plistlib.dumps({"Device Name": "Ben's iPhone", "Product Type": "iPhone15,2",
                                                      "Serial Number": "F2LXXXXX"}))
    (root / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": encrypted}))
    con = sqlite3.connect(root / "Manifest.db")
    con.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
    if profile:
        file_id = "ab" + "0" * 38
        con.execute("INSERT INTO Files VALUES (?,?,?,1,NULL)", (
            file_id, "SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles",
            "Library/ConfigurationProfiles/profile-9f.stub"))
        (root / file_id[:2]).mkdir()
        (root / file_id[:2] / file_id).write_bytes(plistlib.dumps(MDM_PROFILE))
    con.commit()
    con.close()
    return root


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rowanholt-mobile-"))
        core_mobile.set_backup_password(None)
        self.addCleanup(core_mobile.set_backup_password, None)


# ---- ADB backups --------------------------------------------------------------------------

class AndroidBackupTest(Tmp):
    def test_unencrypted_backup_laid_out_as_the_phone_had_it(self):
        ab = self.tmp / "pixel.ab"
        write_ab(ab)
        header = android_backup.read_header(ab)
        self.assertEqual((header.version, header.compressed, header.encrypted), (5, True, False))
        out = self.tmp / "fs"
        counts = android_backup.extract_to_filesystem(ab, out)
        self.assertEqual(counts["files"], 3)
        self.assertEqual((out / "data/data/com.example.chat/databases/messages.db").read_bytes()[:6], b"SQLite")
        self.assertTrue((out / "data/data/com.example.chat/shared_prefs/settings.xml").is_file())
        self.assertTrue((out / "data/media/0/DCIM/Camera/IMG_0001.jpg").is_file())
        self.assertFalse((self.tmp / "escape.txt").exists())
        self.assertFalse(any(p.name == "_manifest" for p in out.rglob("*")))

    def test_encrypted_backup_needs_its_password(self):
        ab = self.tmp / "pixel.ab"
        write_ab(ab, password=PASSWORD)
        self.assertTrue(android_backup.read_header(ab).encrypted)
        with self.assertRaises(android_backup.PasswordRequired):
            android_backup.extract_to_filesystem(ab, self.tmp / "none")
        with self.assertRaises(android_backup.WrongPassword):
            android_backup.extract_to_filesystem(ab, self.tmp / "wrong", "not-it")
        counts = android_backup.extract_to_filesystem(ab, self.tmp / "fs", PASSWORD)
        self.assertEqual(counts["files"], 3)
        self.assertTrue((self.tmp / "fs/data/data/com.example.chat/databases/messages.db").is_file())

    def test_version_one_checksum(self):
        ab = self.tmp / "old.ab"
        write_ab(ab, password=PASSWORD, version=1)
        self.assertEqual(android_backup.extract_to_filesystem(ab, self.tmp / "fs", PASSWORD)["files"], 3)

    def test_not_a_backup(self):
        other = self.tmp / "x.ab"
        other.write_bytes(b"PK\x03\x04")
        self.assertFalse(android_backup.is_android_backup(other))
        with self.assertRaises(android_backup.AndroidBackupError):
            android_backup.read_header(other)

    def test_phone_paths(self):
        self.assertEqual(android_backup.phone_path("apps/com.x/d_db/a.db"), "data/user_de/0/com.x/databases/a.db")
        self.assertEqual(android_backup.phone_path("apps/com.x/ef/Download/f.pdf"),
                         "data/media/0/Android/data/com.x/files/Download/f.pdf")
        self.assertIsNone(android_backup.phone_path("apps/com.x/_manifest"))
        self.assertIsNone(android_backup.phone_path("apps/com.x/zz/whatever"))
        self.assertIsNone(android_backup.phone_path("/etc/passwd"))


# ---- finding and registering evidence -------------------------------------------------------

class ClassifyTest(Tmp):
    def test_each_kind(self):
        backup = itunes_backup(self.tmp / "00008030-001A", encrypted=True)
        ab = self.tmp / "pixel7.ab"
        write_ab(ab)
        bugreport = self.tmp / "bugreport-panther-UQ1A.zip"
        with zipfile.ZipFile(bugreport, "w") as z:
            z.writestr("bugreport-panther-UQ1A-2026-11-01-10-00-00.txt", "== dumpstate ==")
            z.writestr("FS/data/misc/x", "x")
        ios_zip = self.tmp / "iPhone_FFS.zip"
        with zipfile.ZipFile(ios_zip, "w") as z:
            z.writestr("filesystem1/private/var/mobile/Library/SMS/sms.db", "x")
        android_tgz = self.tmp / "galaxy.tar.gz"
        with tarfile.open(android_tgz, "w:gz") as tar:
            info = tarfile.TarInfo("Dump/data/data/com.whatsapp/databases/msgstore.db")
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
        android_dir = self.tmp / "pixel_ffs"
        (android_dir / "data/system").mkdir(parents=True)
        (android_dir / "data/system/packages.xml").write_text("<packages/>")
        nothing = self.tmp / "notes.txt"
        nothing.write_text("hello")

        cases = {
            backup: ("itunes_backup", "iOS", "itunes", True, "Ben_s_iPhone"),
            ab: ("adb_backup", "Android", "fs", False, "pixel7"),
            bugreport: ("bugreport", "Android", "zip", False, "bugreport-panther-UQ1A"),
            ios_zip: ("ios_filesystem", "iOS", "zip", False, "iPhone_FFS"),
            android_tgz: ("android_filesystem", "Android", "gz", False, "galaxy"),
            android_dir: ("android_filesystem", "Android", "fs", False, "pixel_ffs"),
        }
        for path, expected in cases.items():
            with self.subTest(path=path.name):
                found = core_mobile.classify(path)
                self.assertIsNotNone(found)
                self.assertEqual((found.kind, found.platform, found.input_type, found.encrypted, found.name), expected)
        self.assertIsNone(core_mobile.classify(nothing))
        self.assertEqual(core_mobile.classify(backup).details["Product Type"], "iPhone15,2")
        # A folder of them: each one inside
        self.assertEqual(len(core_mobile.find_evidence(self.tmp)), 6)

    def test_ingest_registers_hosts_without_copying_or_keeping_the_password(self):
        source = self.tmp / "phones"
        itunes_backup(source / "backup1", encrypted=True)
        ios_filesystem(source / "Ben_s_iPhone")  # the same host name as the backup's device: made unique
        case = self.tmp / "case"
        case.mkdir()
        core_mobile.set_backup_password(PASSWORD)
        self.assertNotIn(PASSWORD, repr(core_mobile._BACKUP_PASSWORD))
        allimgs = {}
        hosts = core_mobile.ingest_mobile(str(case) + "/", "", str(source), allimgs)
        self.assertEqual(sorted(hosts), ["Ben_s_iPhone", "Ben_s_iPhone-2"])
        self.assertEqual(sorted(allimgs.values()), ["Ben_s_iPhone-2::iOS", "Ben_s_iPhone::iOS"])
        for raw, img in allimgs.items():
            self.assertTrue(core_mobile.is_mobile_image(img))
            self.assertEqual(os.listdir(raw), [])
        backup_host = next(h for h in hosts if core_mobile.load_evidence(str(case), h).kind == "itunes_backup")
        self.assertTrue(core_mobile.load_evidence(str(case), backup_host).encrypted)
        self.assertTrue((case / backup_host / "artefacts/host.info").read_text().startswith(f"{backup_host}::iOS\n"))
        for path in case.rglob("*"):
            if path.is_file():
                self.assertNotIn(PASSWORD.encode(), path.read_bytes(), path)

    def test_evidence_is_hashed_when_registered_and_checked_after(self):
        source = self.tmp / "phones"
        ios_filesystem(source / "Ben_s_iPhone")
        case = self.tmp / "case"
        case.mkdir()
        host, = core_mobile.ingest_mobile(str(case) + "/", "", str(source), {})
        recorded = (case / host / core_mobile.HASH_FILE).read_text().splitlines()
        files = [p for p in (source / "Ben_s_iPhone").rglob("*") if p.is_file()]
        self.assertEqual(recorded[0], "file_path,size,sha256")
        self.assertEqual(len(recorded) - 1, len(files))
        self.assertEqual(core_mobile.verify_evidence("", str(case) + "/", host),
                         {"verified": len(files), "MISMATCH": 0, "missing": 0})
        changed, gone = files[0], files[1]
        changed.write_bytes(changed.read_bytes() + b"altered")
        gone.unlink()
        counts = core_mobile.verify_evidence("", str(case) + "/", host)
        self.assertEqual((counts["MISMATCH"], counts["missing"]), (1, 1))
        rows = [json.loads(line) for line in (case / host / "mobile_integrity.jsonl").read_text().splitlines()]
        statuses = {r["file_path"]: r["status"] for r in rows}
        self.assertEqual([s for p, s in statuses.items() if p.endswith(changed.name)], ["MISMATCH"])
        self.assertEqual([s for p, s in statuses.items() if p.endswith(gone.name)], ["missing"])
        self.assertIn(",mobile integrity,", (case / "rowanholt_audit.log").read_text())

    def test_password_from_standard_input(self):
        self.assertEqual(core_mobile.read_backup_password(io.StringIO(PASSWORD + "\nmore\n")), PASSWORD)
        self.assertIsNone(core_mobile.read_backup_password(io.StringIO("\n")))
        self.assertFalse(core_mobile.is_mobile_image("host::Windows"))
        self.assertFalse(core_mobile.is_mobile_image("image.E01::/mnt/elrond_mount00::disk"))


# ---- device management --------------------------------------------------------------------

class ManagementTest(unittest.TestCase):
    def test_ios_profiles_and_mdm(self):
        path = "private/var/containers/Shared/SystemGroup/X/Library/ConfigurationProfiles/profile-1.stub"
        self.assertTrue(mobile_config.is_ios_config_file(path))
        self.assertFalse(mobile_config.is_ios_config_file("private/var/mobile/Library/SMS/sms.db"))
        row, = mobile_config.ios_config_rows(path, plistlib.dumps(MDM_PROFILE))
        self.assertEqual(row["Technique"], "T1632.001")
        self.assertEqual(row["Server"], "https://mdm.corp.example/server")
        self.assertIn("enrols in MDM", row["Flag"])
        self.assertIn("root certificate", row["Flag"])
        self.assertEqual(row["Installed"], "2026-10-30T09:15:00Z")
        signed = b"0\x82junk" + plistlib.dumps(WIFI_PROFILE) + b"\x00sig"
        wifi, = mobile_config.ios_config_rows(path, signed, "2026-01-01T00:00:00Z")
        self.assertEqual((wifi["Name"], wifi["Technique"], wifi["Flag"]), ("Office Wi-Fi", "", ""))
        self.assertEqual(wifi["Installed"], "2026-01-01T00:00:00Z")
        mdm, = mobile_config.ios_config_rows(path.replace("profile-1.stub", "MDM.plist"),
                                             plistlib.dumps({"ServerURL": "https://m.example"}))
        self.assertEqual((mdm["Kind"], mdm["Technique"]), ("MDM enrolment", "T1632.001"))
        self.assertEqual(mobile_config.ios_config_rows(path, b"not a plist"), [])

    def test_android_admins_and_owners(self):
        self.assertTrue(mobile_config.is_android_config_file("Dump/data/system/device_policies.xml"))
        self.assertTrue(mobile_config.is_android_config_file("data/system/users/10/device_policies.xml"))
        self.assertFalse(mobile_config.is_android_config_file("data/system/packages.xml"))
        admin, = mobile_config.android_config_rows("data/system/device_policies.xml", DEVICE_POLICIES)
        self.assertEqual((admin["Package"], admin["Technique"], admin["Policies"]),
                         ("com.spy.app", "T1626.001", "disable-camera"))
        owner, = mobile_config.android_config_rows("data/system/device_owner_2.xml", DEVICE_OWNER)
        self.assertEqual((owner["Kind"], owner["Package"], owner["User"]), ("device owner", "com.corp.dpc", "0"))
        self.assertEqual(mobile_config.android_config_rows("data/system/device_policies.xml", b"ABX\x00\x01"), [])

    def test_mobile_techniques_have_names(self):
        from rowanholt.post.mitre.attack_data import enrich_technique
        from rowanholt.post.mitre.mobile_attack import is_mobile_technique

        self.assertEqual(enrich_technique("T1626.001")["mitre_tactics"], ["Privilege Escalation"])
        self.assertTrue(is_mobile_technique("t1632.001"))
        self.assertFalse(is_mobile_technique("T1059.001"))
        self.assertNotEqual(enrich_technique("T1059.001")["mitre_technique_name"], "Unknown Technique")


# ---- LEAPP reports cooked -----------------------------------------------------------------

SMS_HEADER = ["Message Timestamp", "Read Timestamp", "Message", "Service", "Contact"]
SMS_ROWS = [
    ["2026-11-01 08:00:00", "", "your code is 123456 http://evil.example/x", "SMS", "+447700900123"],
    ["2026-10-31 22:15:30", "2026-10-31 22:20:00", "see you at\tten", "iMessage", "alice@example.org"],
]


def write_tsv(path, header, rows, repeat_header=True):
    path.parent.mkdir(parents=True, exist_ok=True)
    import csv

    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh, delimiter="\t")
        writer.writerow(header)
        writer.writerow(rows[0])
    if repeat_header:  # LEAPP appends a second write of the same artefact, header and all
        with open(path, "a", encoding="utf-8-sig", newline="") as fh:
            writer = csv.writer(fh, delimiter="\t")
            writer.writerow(header)
            for row in rows[1:]:
                writer.writerow(row)


class FakeLeapp:
    """Stands in for subprocess.run: records the call and writes a LEAPP-shaped report."""

    def __init__(self, tsvs=None, status=0):
        self.calls = []
        self.tsvs = tsvs if tsvs is not None else {"SMS - Messages": (SMS_HEADER, SMS_ROWS)}
        self.status = status

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        work = Path(command[command.index("-o") + 1])
        report = work / command[command.index("--custom_output_folder") + 1]
        for name, (header, rows) in self.tsvs.items():
            write_tsv(report / "_TSV Exports" / f"{name}.tsv", header, rows)
        write_tsv(report / "_TSV Exports" / "_Staged files SHA-256.tsv", ["Path", "SHA256"], [["a", "b"]], False)
        (report / "_HTML").mkdir(parents=True, exist_ok=True)
        (report / "_HTML" / "index.html").write_text("<html>report</html>")
        kwargs["stdout"].write("iLEAPP: done\n")
        return mock.Mock(returncode=self.status)


class ProcessPhoneTest(Tmp):
    def register(self, source):
        case = self.tmp / "case"
        case.mkdir(exist_ok=True)
        allimgs = {}
        core_mobile.ingest_mobile(str(case) + "/", "", str(source), allimgs)
        return case, allimgs

    def run_phone(self, case, img, runner):
        with mock.patch.object(mobile, "tool_path", return_value="/usr/local/bin/leapp"):
            return mobile.process_phone("", str(case) + "/", img, runner=runner)

    def test_ios_extraction_end_to_end(self):
        case, allimgs = self.register(ios_filesystem(self.tmp / "iPhone14"))
        (img,) = allimgs.values()
        runner = FakeLeapp()
        summary = self.run_phone(case, img, runner)
        host = case / "iPhone14"

        command, kwargs = runner.calls[0]
        self.assertEqual(command[:3], ["/usr/local/bin/leapp", "-t", "fs"])
        self.assertTrue(kwargs["start_new_session"])
        self.assertEqual(kwargs["stdin"], mock.ANY)
        self.assertNotIn("input", kwargs)

        sms = [r for _, r in read_records(host / "artefacts/cooked/ileapp/sms_messages.jsonl")]
        self.assertEqual(len(sms), 2)  # the repeated header isn't a row
        self.assertEqual(sms[0]["host"], "iPhone14")
        self.assertEqual(sms[0]["artefact"], "ileapp/sms_messages")
        self.assertEqual(sms[0]["timestamp"], "2026-11-01T08:00:00Z")
        self.assertEqual(sms[1]["Message"], "see you at\tten")
        self.assertTrue(sms[0]["source_path"].endswith("_TSV Exports/SMS - Messages.tsv"))
        self.assertFalse((host / "artefacts/cooked/ileapp/staged_files_sha_256.jsonl").exists())

        management = [r for _, r in read_records(host / "artefacts/cooked/mobile_management.jsonl")]
        self.assertEqual(len(management), 3)
        self.assertEqual(sorted({t for r in management for t in r["techniques"]}), ["T1632.001"])
        self.assertEqual(summary["techniques"], ["T1632.001"])
        self.assertIn("T1632.001", (case / "mitre_techniques.txt").read_text().split())

        timeline = [r for _, r in read_records(host / "artefacts/mobile_timeline.jsonl")]
        times = [r["timestamp"] for r in timeline]
        self.assertEqual(times, sorted(times))
        self.assertIn("2026-10-31T22:15:30Z", times)
        self.assertTrue(any(r["techniques"] == ["T1632.001"] for r in timeline))
        self.assertTrue(all(r["artefact"] == "mobile_timeline" for r in timeline))

        # A second run replaces what the first made, not doubles it
        self.run_phone(case, img, FakeLeapp())
        self.assertEqual(len(list(read_records(host / "artefacts/cooked/ileapp/sms_messages.jsonl"))), 2)

    def test_encrypted_backup_password_reaches_the_tool_on_stdin_only(self):
        case, allimgs = self.register(itunes_backup(self.tmp / "backup", encrypted=True))
        (img,) = allimgs.values()

        runner = FakeLeapp()
        summary = self.run_phone(case, img, runner)
        self.assertEqual(summary["status"], "password needed")
        self.assertEqual(runner.calls, [])

        core_mobile.set_backup_password(PASSWORD)
        runner = FakeLeapp()
        self.run_phone(case, img, runner)
        command, kwargs = runner.calls[0]
        self.assertIn("itunes", command)
        self.assertNotIn(PASSWORD, " ".join(command))
        self.assertEqual(kwargs["input"], PASSWORD + "\n")
        self.assertTrue(kwargs["start_new_session"])
        for path in case.rglob("*"):
            if path.is_file():
                self.assertNotIn(PASSWORD.encode(), path.read_bytes(), path)
        # An encrypted backup's own files aren't read without decrypting it: no management rows
        self.assertFalse((case / img.split("::")[0] / "artefacts/cooked/mobile_management.jsonl").exists())

    def test_unencrypted_backup_profiles_from_its_manifest(self):
        case, allimgs = self.register(itunes_backup(self.tmp / "backup"))
        (img,) = allimgs.values()
        runner = FakeLeapp()
        self.run_phone(case, img, runner)
        self.assertEqual(runner.calls[0][1]["stdin"], mock.ANY)
        rows = [r for _, r in read_records(case / img.split("::")[0] / "artefacts/cooked/mobile_management.jsonl")]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["techniques"], ["T1632.001"])

    def test_adb_backup_goes_to_aleapp_as_a_file_system(self):
        ab = self.tmp / "pixel.ab"
        write_ab(ab, password=PASSWORD)
        case, allimgs = self.register(ab)
        (img,) = allimgs.values()
        self.assertTrue(img.endswith("::Android"))
        core_mobile.set_backup_password(PASSWORD)
        runner = FakeLeapp({"Chats": (["Timestamp", "Body"], [["2026-11-02 12:00:00", "hi"]])})
        summary = self.run_phone(case, img, runner)
        command, kwargs = runner.calls[0]
        self.assertEqual(command[command.index("-t") + 1], "fs")
        layout = Path(command[command.index("-i") + 1])
        self.assertTrue((layout / "data/data/com.example.chat/databases/messages.db").is_file())
        self.assertNotIn("input", kwargs)  # ALEAPP never needs it: Elrond opened the backup
        self.assertIn("aleapp/chats", summary["tables"])

    def test_wrong_adb_password_is_reported_not_raised(self):
        ab = self.tmp / "pixel.ab"
        write_ab(ab, password=PASSWORD)
        case, allimgs = self.register(ab)
        core_mobile.set_backup_password("wrong")
        runner = FakeLeapp()
        summary = self.run_phone(case, next(iter(allimgs.values())), runner)
        self.assertIn("password", summary["status"])
        self.assertEqual(runner.calls, [])

    def test_android_extraction_device_admins(self):
        root = self.tmp / "galaxy"
        (root / "data/system").mkdir(parents=True)
        (root / "data/system/device_policies.xml").write_bytes(DEVICE_POLICIES)
        (root / "data/system/device_owner_2.xml").write_bytes(DEVICE_OWNER)
        archive = self.tmp / "galaxy.zip"
        with zipfile.ZipFile(archive, "w") as z:
            for path in root.rglob("*"):
                if path.is_file():
                    z.write(path, "Dump/" + path.relative_to(root).as_posix())
        case, allimgs = self.register(archive)
        summary = self.run_phone(case, next(iter(allimgs.values())), FakeLeapp())
        self.assertEqual(summary["techniques"], ["T1626.001"])
        self.assertEqual(summary["tables"]["mobile_management"], 2)

    def test_missing_tool_still_reads_management(self):
        case, allimgs = self.register(ios_filesystem(self.tmp / "iPhone"))
        with mock.patch.object(mobile, "tool_path", return_value=None):
            summary = mobile.process_phone("", str(case) + "/", next(iter(allimgs.values())), runner=FakeLeapp())
        self.assertIn("isn't installed", summary["status"])
        self.assertEqual(summary["techniques"], ["T1632.001"])


class CookingTest(Tmp):
    def test_large_tables_written_in_parts_below_the_ioc_limit(self):
        rows = ({"Time": "2026-11-01 00:00:00", "Text": "x" * 200, "n": i} for i in range(3000))
        written, parts = mobile.write_parts(self.tmp / "cooked/ileapp/big", rows, host="h", artefact="ileapp/big",
                                            source_path="", time="Time", part_bytes=100_000)
        self.assertEqual(written, 3000)
        self.assertGreater(len(parts), 1)
        self.assertEqual(parts[1].name, "big-0002.jsonl")
        self.assertEqual(sum(len(list(read_records(p))) for p in parts), 3000)

    def test_time_column_chosen_by_its_values(self):
        header = ["Update Count", "Last Seen", "Name"]
        sample = [{"Update Count": "5", "Last Seen": "2026-01-01 10:00:00", "Name": "a"}]
        self.assertEqual(mobile.time_field(header, sample), "Last Seen")
        self.assertIsNone(mobile.time_field(["Sender", "Body"], [{"Sender": "bob", "Body": "x"}]))
        self.assertEqual(mobile.slug("Safari - History (iOS 17+)"), "safari_history_ios_17")

    def test_password_found_in_the_report_is_named(self):
        report = self.tmp / "iLEAPP"
        (report / "_HTML").mkdir(parents=True)
        (report / "_HTML" / "log.html").write_text(f"pw={PASSWORD}")
        (report / "data").mkdir()
        (report / "data" / "notes.txt").write_text(PASSWORD)  # the phone's own file: not LEAPP's output
        self.assertEqual(mobile.password_in_report(report, PASSWORD), [str(Path("_HTML/log.html"))])
        self.assertEqual(mobile.password_in_report(report, None), [])


class RoutingTest(Tmp):
    def test_phones_branch_off_the_disk_processing(self):
        from rowanholt.core import core

        imgs = {"/case/phone/artefacts/raw": "phone::iOS", "/mnt/elrond_mount00": "disk.E01::/mnt/elrond_mount00::disk"}
        with mock.patch.object(core, "process_mobile") as phones, \
                mock.patch.object(core, "select_pre_process_artefacts") as disks:
            core.collect_process_keyword_analysis_timeline(
                True, False, True, False, False, False, None, False, False, False, False, None, False, False, False,
                False, False, "/case/", "/", None, [], [], "/case/", "", "", {}, imgs, "/case/", "", "", "",
                "processing", phase="process")
        self.assertEqual(phones.call_args[0][2], {"/case/phone/artefacts/raw": "phone::iOS"})
        self.assertEqual(disks.call_args[0][6], {"/mnt/elrond_mount00": "disk.E01::/mnt/elrond_mount00::disk"})

        with mock.patch.object(core, "process_mobile") as phones, \
                mock.patch.object(core, "select_pre_process_artefacts") as disks:
            core.collect_process_keyword_analysis_timeline(
                True, False, True, False, False, False, None, False, False, False, False, None, False, False, False,
                False, False, "/case/", "/", None, [], [], "/case/", "", "", {}, {"/x": "phone::Android"}, "/case/",
                "", "", "", "processing", phase="process")
        phones.assert_called_once()
        disks.assert_not_called()

    def test_mobile_timeline_is_indexed(self):
        from rowanholt.post.elastic.ingest import host_tables
        from rowanholt.post.splunk.ingest import indexed_tables

        host = self.tmp / "phone"
        (host / "artefacts/cooked/ileapp").mkdir(parents=True)
        (host / "artefacts/cooked/ileapp/sms.jsonl").write_text("{}\n")
        (host / "artefacts/mobile_timeline.jsonl").write_text("{}\n")
        self.assertIn("mobile_timeline", [name for _, name in host_tables(str(host))])
        self.assertIn("artefacts/mobile_timeline.jsonl", indexed_tables(str(host)))

    def test_elrond_takes_mobile_and_the_password_flag(self):
        source = (Path(__file__).resolve().parents[2] / "src" / "analysis" / "elrond.py").read_text()
        for flag in ('"--Mobile"', '"--backupPasswordStdin"'):
            self.assertIn(flag, source)
        self.assertEqual(source.count("mobile=mobile,"), 5)  # every phase's call to main()


if __name__ == "__main__":
    unittest.main()
