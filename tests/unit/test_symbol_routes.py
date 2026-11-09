"""Aragorn's symbol tables (/api/symbols, symbol_routes.py) over the real backend in server
mode: admin-only, the listing from the index, and an upload handed to the worker's task."""
import base64
import json
import lzma
import unittest
from pathlib import Path
from unittest import mock

from test_server_access import TMP, BackendCase, TestClient

BANNER = "Linux version 6.1.0-18-amd64 (debian-kernel@lists.debian.org) (gcc-12) #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01)"


def isf(banner):
    data = base64.b64encode(banner.encode()).decode()
    return lzma.compress(json.dumps({"symbols": {"linux_banner": {"constant_data": data}}}).encode())


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class SymbolTables(BackendCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import symbol_routes
        cls.routes = symbol_routes
        cls.root = Path(TMP) / "symbols"
        (cls.root / "linux").mkdir(parents=True, exist_ok=True)
        cls.dir = mock.patch.object(symbol_routes, "SYMBOLS_DIR", cls.root)
        cls.dir.start()

    @classmethod
    def tearDownClass(cls):
        cls.dir.stop()
        super().tearDownClass()

    def test_admins_only(self):
        self.assertEqual(self.client.get("/api/symbols", headers=self.alice).status_code, 403)
        resp = self.client.post("/api/symbols/add", headers=self.alice, data={"kind": "table"},
                                files={"file": ("t.json.xz", b"x")})
        self.assertEqual(resp.status_code, 403)

    def test_listing_shows_indexed_and_unindexed_tables(self):
        cache = self.routes.symbols_cache()
        table = self.root / "linux" / "debian.json.xz"
        table.write_bytes(isf(BANNER))
        cache.add("linux", BANNER, table, "debian", "https://snapshot.debian.org/file/x", self.root)
        (self.root / "linux" / "other.json.xz").write_bytes(b"")
        cache.log("linux", "symbols built debian.json.xz", self.root)
        body = self.client.get("/api/symbols", headers=self.admin).json()
        by_file = {t["file"]: t for t in body["tables"]}
        self.assertEqual(by_file["debian.json.xz"]["banner"], BANNER)
        self.assertEqual(by_file["other.json.xz"]["source"], "")
        self.assertTrue(body["log"][-1].endswith("symbols built debian.json.xz"))
        self.assertIn("downloads", body)

    def test_an_upload_goes_to_the_worker(self):
        task = mock.Mock(id="t-1")
        with mock.patch("tasks_docker.add_symbol_table.delay", return_value=task) as delay:
            resp = self.client.post("/api/symbols/add", headers=self.admin, data={"kind": "kdk"},
                                    files={"file": ("kernel", b"macho"), "dwarf": ("kernel", b"dwarf")})
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json(), {"task_id": "t-1"})
        args, folder = delay.call_args[0]
        self.assertEqual(args, ["--kdk", folder])
        self.assertTrue(Path(folder, "System/Library/Kernels/kernel.dSYM/Contents/Resources/DWARF/kernel").is_file())
        self.assertEqual(Path(folder).parent, self.root / "incoming")

    def test_a_table_must_look_like_one(self):
        resp = self.client.post("/api/symbols/add", headers=self.admin, data={"kind": "table"},
                                files={"file": ("notes.txt", b"x")})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(list((self.root / "incoming").glob("*")) if (self.root / "incoming").exists() else [], [])


if __name__ == "__main__":
    unittest.main()
