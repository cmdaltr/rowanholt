"""Sample data as ready cases (rowanholt/samples, rowanholt samples, /api/samples): the catalogue,
downloads checked against their publishers' hashes (resumed, or recorded when none is
published), safe unpacking, and the job each becomes. No network: urlopen is canned."""
import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.append(str(REPO / "src" / "analysis"))

from rowanholt.samples import samples  # noqa: E402

from test_server_access import BackendCase, TestClient  # noqa: E402


class Response(io.BytesIO):
    def __init__(self, body, url, status=200):
        super().__init__(body)
        self.url, self.status = url, status
        self.headers = {"Content-Length": str(len(body))}

    def geturl(self):
        return self.url

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def serving(body, seen=None):
    def urlopen(request, timeout=None):
        if seen is not None:
            seen.append(dict(request.headers))
        start = int(request.headers.get("Range", "bytes=0-")[6:-1] or 0)
        return Response(body[start:], request.full_url, 206 if start else 200)
    return mock.patch.object(samples.urllib.request, "urlopen", urlopen)


def zipped(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


class TheCatalogue(unittest.TestCase):
    def test_every_slot_is_covered_once_checked(self):
        listed = samples.catalogue()
        self.assertEqual(len({s["id"] for s in listed}), len(listed))
        covers = {c for s in listed for c in s["covers"]}
        for slot in ("windows-disk", "windows-memory", "linux-disk", "linux-memory", "macos-disk", "android", "ios"):
            self.assertIn(slot, covers)
        for s in listed:
            for entry in s["files"]:
                self.assertTrue(entry["url"].startswith("https://"), entry["url"])
            self.assertTrue(s["images"])
            self.assertTrue(s["folder"] and not s["folder"].startswith("/"))

    def test_only_13cubed_has_no_published_hash(self):
        unhashed = [e["name"] for s in samples.catalogue() for e in s["files"]
                    if not (e.get("sha256") or e.get("md5") or e.get("sha256_from"))]
        self.assertEqual(unhashed, ["linux_challenge.zip"])


class Fetching(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def sample(self, **entry):
        return {"id": "t", "folder": "samples/t", "images": ["*.E01"],
                "files": [{"name": "t.zip", "url": "https://example.org/t.zip", **entry}]}

    def test_a_matching_hash_keeps_the_file_and_records_it(self):
        body = b"evidence"
        s = self.sample(md5=hashlib.md5(body).hexdigest())
        with serving(body):
            path = samples.fetch_file(s, s["files"][0], self.root)
        self.assertEqual(path.read_bytes(), body)
        self.assertEqual(samples.recorded(self.root, "samples/t/t.zip"), hashlib.sha256(body).hexdigest())

    def test_a_mismatch_is_kept_aside_as_bad(self):
        s = self.sample(sha256="00" * 32)
        with serving(b"tampered"), self.assertRaisesRegex(samples.SampleError, "is not the published"):
            samples.fetch_file(s, s["files"][0], self.root)
        self.assertEqual(sorted(p.name for p in (self.root / "samples/t").iterdir()), ["t.zip.bad"])
        self.assertEqual(samples.status(s, self.root)["files"][0]["state"], "bad")

    def test_a_part_download_resumes(self):
        body = b"0123456789"
        s = self.sample(sha256=hashlib.sha256(body).hexdigest())
        folder = self.root / "samples/t"
        folder.mkdir(parents=True)
        (folder / "t.zip.part").write_bytes(body[:4])
        self.assertEqual(samples.status(s, self.root)["files"][0]["state"], "partial")
        seen = []
        with serving(body, seen):
            samples.fetch_file(s, s["files"][0], self.root)
        self.assertEqual(seen[0].get("Range"), "bytes=4-")
        self.assertEqual((folder / "t.zip").read_bytes(), body)

    def test_no_published_hash_is_held_to_the_first_download(self):
        s = self.sample()
        with serving(b"first"):
            samples.fetch_file(s, s["files"][0], self.root)
        (self.root / "samples/t/t.zip").unlink()
        with serving(b"changed"), self.assertRaisesRegex(samples.SampleError, "differs from the first download"):
            samples.fetch_file(s, s["files"][0], self.root)

    def test_digital_corpora_hash_from_its_api(self):
        rows = [{"key": "corpora/x/other.7z", "sha2_256": "aa"}, {"key": "corpora/x/2022 CTF - Linux.7z", "sha2_256": "BB"}]
        with serving(json.dumps(rows).encode()):
            self.assertEqual(samples.published_hash({"name": "2022 CTF - Linux.7z", "sha256_from": "digitalcorpora"}),
                             ("sha256", "bb"))

    def test_only_https(self):
        s = self.sample()
        s["files"][0]["url"] = "http://example.org/t.zip"
        with self.assertRaises(samples.SampleError):
            samples.fetch_file(s, s["files"][0], self.root)


class Unpacking(unittest.TestCase):
    def test_unpacked_beside_the_archive_and_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "samples/t"
            folder.mkdir(parents=True)
            (folder / "t.zip").write_bytes(zipped({"case/DESKTOP.E01": b"e01", "case/readme.txt": b""}))
            s = {"id": "t", "folder": "samples/t", "images": ["*.E01"], "files": [{"name": "t.zip", "url": "https://x/t.zip"}]}
            found = samples.unpack(s, root)
            self.assertEqual(found, [folder / "t" / "case" / "DESKTOP.E01"])
            self.assertTrue(samples.status(s, root)["ready"])

    def test_an_archive_escaping_its_folder_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp, "bad.zip")
            archive.write_bytes(zipped({"../../escape.txt": b"x"}))
            with self.assertRaisesRegex(samples.SampleError, "unsafe paths"):
                samples._unpack(archive, Path(tmp, "out"))
            self.assertFalse(Path(tmp).parent.joinpath("escape.txt").exists())

    def test_inner_archives_the_sample_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "phones"
            folder.mkdir(parents=True)
            (folder / "outer.zip").write_bytes(zipped({"x/00008030-001259123E50802E.zip":
                                                       zipped({"00008030-001259123E50802E/Manifest.db": b""})}))
            s = {"id": "b", "folder": "phones", "images": ["00008030-001259123E50802E"],
                 "unpack": ["00008030-001259123E50802E.zip"], "files": [{"name": "outer.zip", "url": "https://x"}]}
            found = samples.unpack(s, root)
            self.assertTrue((found[0] / "00008030-001259123E50802E" / "Manifest.db").is_file() or
                            (found[0] / "Manifest.db").is_file())


class Jobs(unittest.TestCase):
    def test_job_request(self):
        s = samples.sample("ios17-backup")
        body = samples.job_request(s, [Path("/v/backup")], force=True)
        self.assertEqual(body["case_number"], "SAMPLE-IOS17-BACKUP")
        self.assertEqual(body["source_paths"], ["/v/backup"])
        self.assertTrue(body["options"]["mobile"] and body["options"]["force_overwrite"])
        self.assertEqual(body["backup_password"], "MyPassword123")
        self.assertNotIn("backup_password", samples.job_request(samples.sample("szechuan-desktop"), []))


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class SampleRoutes(BackendCase):
    def test_admins_only(self):
        self.assertEqual(self.client.get("/api/samples", headers=self.alice).status_code, 403)
        self.assertEqual(self.client.post("/api/samples/ios17/fetch", headers=self.alice).status_code, 403)

    def test_listing_and_the_job_body(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict("os.environ", {"ROWANHOLT_SAMPLES_DIR": tmp}):
            backup = Path(tmp, "phones", "x", "00008030-001259123E50802E")
            backup.mkdir(parents=True)
            body = self.client.get("/api/samples", headers=self.admin).json()
            listed = {s["id"]: s for s in body["samples"]}
            self.assertEqual(body["dir"], tmp)
            self.assertEqual(listed["ios17-backup"]["images"], [str(backup)])
            self.assertNotIn("backup_password", listed["ios17-backup"]["job"])
            self.assertTrue(listed["ios17-backup"]["has_backup_password"])
            self.assertEqual(listed["szechuan-desktop"]["files"][0]["state"], "missing")
            job = self.client.post("/api/samples/ios17-backup/import", headers=self.admin).json()
            self.assertEqual(job["backup_password"], "MyPassword123")
            self.assertEqual(self.client.post("/api/samples/szechuan-desktop/import", headers=self.admin).status_code, 409)
            self.assertEqual(self.client.post("/api/samples/nope/import", headers=self.admin).status_code, 404)


if __name__ == "__main__":
    unittest.main()
