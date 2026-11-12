"""GET /api/fs/browse keeps to the allowed folders by whole folder names (output_removal.contained),
as job paths do: a string prefix let /tmp/rowanholtX through as inside /tmp/rowanholt.

Driven through the real app in server mode (test_server_access.BackendCase, whose allowed folder is
its `evidence`). Also auth/security_utils.sanitize_path, the other prefix comparison.

Run: python3 -m unittest tests/unit/test_fs_browse.py
"""

import importlib
import sys
import unittest
from pathlib import Path
from unittest import mock

from test_server_access import BackendCase, TestClient

WEB = Path(__file__).resolve().parents[2] / "src" / "web"


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class BrowseTest(BackendCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # The allowed folder as resolved (macOS's /var is /private/var): the old check resolved the
        # path asked for and compared it with the folder as configured, so only a resolved folder
        # shows what that comparison let through
        cls.evidence = cls.evidence.resolve()
        cls.resolved = mock.patch.object(type(cls.settings), "allowed_paths", new_callable=mock.PropertyMock,
                                         return_value=[str(cls.evidence)])
        cls.resolved.start()
        (cls.evidence / "cases").mkdir(exist_ok=True)
        (cls.evidence / "cases" / "disk.E01").write_bytes(b"")
        # Starts with the allowed folder's name, but isn't inside it
        cls.sibling = cls.evidence.parent / f"{cls.evidence.name}X"
        cls.sibling.mkdir(exist_ok=True)
        (cls.sibling / "secret.E01").write_bytes(b"")
        cls.outside = cls.evidence.parent / "outside"
        cls.outside.mkdir(exist_ok=True)
        # In a folder of its own, out of the way of the other tests over the same evidence folder
        cls.link = cls.evidence / "browse" / "link"
        cls.link.parent.mkdir(exist_ok=True)
        link = cls.link
        if not link.is_symlink():
            link.symlink_to(cls.outside, target_is_directory=True)

    @classmethod
    def tearDownClass(cls):
        cls.resolved.stop()
        super().tearDownClass()

    def browse(self, path):
        return self.client.get("/api/fs/browse", headers=self.alice, params={"path": str(path)})

    def test_a_folder_inside_an_allowed_folder_is_listed(self):
        resp = self.browse(self.evidence / "cases")
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertIn("disk.E01", [item["name"] for item in resp.json()["items"]])
        self.assertEqual(self.browse(self.evidence).status_code, 200)  # the allowed folder itself

    def test_a_sibling_whose_name_starts_the_same_is_refused(self):
        resp = self.browse(self.sibling)
        self.assertEqual(resp.status_code, 403, resp.text)
        self.assertNotIn("secret.E01", resp.text)

    def test_dot_dot_is_refused(self):
        for path in (f"{self.evidence}/cases/..", f"{self.evidence}/cases/../../{self.sibling.name}"):
            self.assertEqual(self.browse(path).status_code, 403, path)

    def test_a_symbolic_link_below_the_allowed_folder_is_refused(self):
        self.assertEqual(self.browse(self.link).status_code, 403)

    def test_outside_every_allowed_folder_is_refused(self):
        self.assertEqual(self.browse("/").status_code, 403)
        self.assertEqual(self.browse(self.outside).status_code, 403)


class SanitizePathTest(unittest.TestCase):
    """auth/security_utils.sanitize_path (nothing mounted calls it) compared by string prefix too."""

    @classmethod
    def setUpClass(cls):
        try:
            sys.path.insert(0, str(WEB))
            cls.utils = importlib.import_module("backend.auth.security_utils")
        except ImportError as exc:  # bleach, pyotp or cryptography missing
            raise unittest.SkipTest(f"backend.auth.security_utils not importable: {exc}")
        finally:
            sys.path.remove(str(WEB))

    def test_whole_folder_names_only(self):
        sanitize = self.utils.sanitize_path
        self.assertIsNone(sanitize("/tmp/rowanholtX/disk.E01", ["/tmp/rowanholt"]))
        self.assertIsNone(sanitize("/tmp/rowanholt/../rowanholtX", ["/tmp/rowanholt"]))
        self.assertEqual(sanitize("/tmp/rowanholt/case/disk.E01", ["/tmp/rowanholt"]), "/tmp/rowanholt/case/disk.E01")
        self.assertEqual(sanitize("/tmp/rowanholt", ["/tmp/rowanholt/"]), "/tmp/rowanholt")


if __name__ == "__main__":
    unittest.main()
