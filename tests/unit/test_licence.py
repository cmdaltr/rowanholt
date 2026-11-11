"""Unit tests for a team server's licence through the real backend (test_server_access.BackendCase):
the Licence API, accepting the terms, the audit log, the seat checks wherever an account is added,
and `rowanholt server licence`. Licences are signed with a throwaway key.

Run: python3 -m unittest tests/unit/test_licence.py
"""

import io
import json
import os
import sys
import tempfile
import unittest
import uuid
from contextlib import redirect_stderr, redirect_stdout
from datetime import date
from pathlib import Path
from unittest import mock

import test_server_access  # noqa: F401  (sets the backend's environment before anything imports it)
from test_server_access import BackendCase, TestClient

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:
    Ed25519PrivateKey = None


@unittest.skipIf(TestClient is None or Ed25519PrivateKey is None, "backend requirements not installed")
class LicenceApiTest(BackendCase):
    """admin, alice and bob hold three places, and other classes over the same user store may hold more:
    the seat tests fill to the limit from wherever it is."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import licence
        import manage_licence
        from auth import oidc, users
        cls.licence, cls.cli, cls.oidc, cls.users = licence, manage_licence, oidc, users
        cls.key = Ed25519PrivateKey.generate()
        public = cls.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        cls.keys = mock.patch.object(licence, "PUBLIC_KEYS", (public,))
        cls.keys.start()

    @classmethod
    def tearDownClass(cls):
        cls.keys.stop()
        super().tearDownClass()

    def setUp(self):
        path = f"{tempfile.mkdtemp()}/licence.json"
        patch = mock.patch.dict(os.environ, {"ROWANHOLT_LICENCE": path})
        patch.start()
        self.addCleanup(patch.stop)
        self.path = Path(path)
        self.added = []
        self.addCleanup(self.disable_added)

    def disable_added(self):
        """Other test classes share this user store: leave it with the places it had."""
        users = self.users.load_users()
        for user in users.values():
            if user["username"] in self.added:
                user["is_active"] = False
        self.users.save_users(users)

    def line(self, edition="pro", seats=10, expires=date(2099, 12, 31), product="rowanholt", **extra):
        return self.licence.sign(self.key, self.licence.Licence(
            self.licence.new_id(), "Northwind Ltd", self.licence.Edition(edition), seats, date(2026, 11, 11),
            expires, product=product, **extra))

    def add(self, name):
        self.added.append(name)
        return self.client.post("/api/auth/users", headers=self.admin, json={
            "username": name, "email": f"{name}@example.org", "password": f"{name}-password-123"})

    def held(self):
        return self.licence.places_held(self.users.load_users())

    def fill_free_places(self):
        """Add accounts until the free edition's four places are all taken."""
        while self.held() < self.licence.FREE_SEATS:
            self.assertEqual(self.add(f"filler-{uuid.uuid4().hex[:8]}").status_code, 200)

    def install(self, text, **body):
        version = self.client.get("/api/licence/terms", headers=self.admin).json()["version"]
        return self.client.put("/api/licence", headers=self.admin,
                               json={"text": text, "accept_terms": True, "terms_version": version, **body})

    def audit_rows(self):
        from storage import AuditLogModel
        session = self.main.job_storage.Session()
        try:
            return [(r.action, r.username, r.details) for r in session.query(AuditLogModel).order_by(AuditLogModel.timestamp)]
        finally:
            session.close()

    def test_only_admins_see_the_licence(self):
        self.assertEqual(self.client.get("/api/licence", headers=self.alice).status_code, 403)
        self.assertEqual(self.client.put("/api/licence", headers=self.alice, json={"text": "x"}).status_code, 403)
        body = self.client.get("/api/licence", headers=self.admin).json()
        self.assertEqual((body["edition"], body["state"], body["seats"], body["free_seats"]), ("free", "free", 4, 4))
        self.assertGreaterEqual(body["places_held"], 3)

    def test_checking_a_licence_shows_whom_the_terms_are_for_and_installs_nothing(self):
        resp = self.client.post("/api/licence/check", headers=self.admin, json={"text": self.line("services", seats=25)})
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual((resp.json()["licensee"], resp.json()["seats"]), ("Northwind Ltd", 25))
        self.assertIn("managed-service", resp.json()["features"])
        self.assertFalse(self.path.exists())
        refused = self.client.post("/api/licence/check", headers=self.admin, json={"text": self.line(product="shikari")})
        self.assertEqual(refused.status_code, 422)
        self.assertIn("licence for shikari", refused.json()["detail"])

    def test_installing_needs_the_current_terms_accepted_and_records_who_did(self):
        text = self.line(seats=25)
        unaccepted = self.client.put("/api/licence", headers=self.admin, json={"text": text})
        self.assertEqual(unaccepted.status_code, 422)
        self.assertIn("Accept the commercial licence terms for Northwind Ltd", unaccepted.json()["detail"])
        stale = self.install(text, terms_version="0.9")
        self.assertEqual(stale.status_code, 409)
        self.assertIn("now version 1.1", stale.json()["detail"])
        self.assertFalse(self.path.exists())

        resp = self.install(text)
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertEqual((body["edition"], body["state"], body["seats"], body["licensee"]), ("pro", "active", 25, "Northwind Ltd"))
        self.assertEqual(body["accepted"]["terms_version"], "1.1")
        self.assertIn("<admin@", body["accepted"]["by"])
        stored = json.loads(self.path.read_text())
        self.assertEqual(stored["licence"], text)
        self.assertEqual(stored["terms_version"], "1.1")
        self.assertTrue(stored["accepted_by"] and stored["accepted_at"])
        action, username, details = self.audit_rows()[-1]
        self.assertEqual((action, username, details["terms_version"], details["seats"]), ("licence_installed", "admin", "1.1", 25))

        removed = self.client.delete("/api/licence", headers=self.admin)
        self.assertEqual((removed.json()["edition"], removed.json()["accepted"]), ("free", None))
        self.assertEqual(self.audit_rows()[-1][0], "licence_removed")

    def test_a_licence_that_has_run_out_isnt_installed(self):
        resp = self.install(self.line(expires=date(2025, 1, 1)))
        self.assertEqual(resp.status_code, 422)
        self.assertIn("ran out", resp.json()["detail"])

    def test_the_free_edition_has_four_places_and_a_licence_adds_more(self):
        self.fill_free_places()
        refused = self.add("dave")
        self.assertEqual(refused.status_code, 402)
        self.assertIn("All 4 places on the free edition are taken", refused.json()["detail"])
        self.assertEqual(self.install(self.line(seats=self.held() + 1)).status_code, 200)
        self.assertEqual(self.add("dave").status_code, 200)
        self.assertEqual(self.add("dora").status_code, 402)

    def test_re_enabling_someone_needs_a_free_place_and_nobody_is_ever_disabled(self):
        self.assertEqual(self.install(self.line(seats=max(self.held(), 3) + 2)).status_code, 200)
        self.assertEqual(self.add("erin").status_code, 200)
        self.assertEqual(self.add("frank").status_code, 200)
        before = self.held()
        erin = next(u for u in self.users.load_users().values() if u["username"] == "erin")
        self.client.delete("/api/licence", headers=self.admin)
        # More can sign in than the free edition's four places: removing the licence took nobody out
        self.assertGreater(before, self.licence.FREE_SEATS)
        self.assertEqual(self.held(), before)
        self.client.post("/api/auth/login", data={"username": "erin", "password": "erin-password-123"}).raise_for_status()
        self.client.cookies.clear()
        self.assertEqual(self.client.patch(f"/api/auth/users/{erin['id']}", headers=self.admin,
                                           json={"is_active": False}).status_code, 200)
        self.assertEqual(self.client.patch(f"/api/auth/users/{erin['id']}", headers=self.admin,
                                           json={"is_active": True}).status_code, 402)

    def test_a_first_single_sign_on_needs_a_free_place_but_a_returning_user_doesnt(self):
        self.fill_free_places()
        # test_oidc.py may have left a group requirement in the settings: this test is about places only
        for name in ("oidc_allowed_group", "oidc_admin_group"):
            patch = mock.patch.object(self.oidc.settings, name, "")
            patch.start()
            self.addCleanup(patch.stop)
        claims = {"iss": "https://idp.test", "sub": f"new-{uuid.uuid4().hex[:8]}", "email": "new@example.org", "name": "New"}
        with self.assertRaisesRegex(self.oidc.SignInRefused, "no place for a new account"):
            self.oidc.user_for(claims)
        self.assertEqual(self.install(self.line(seats=None)).status_code, 200)
        user = self.oidc.user_for(claims)
        self.added.append(user["username"])
        self.client.delete("/api/licence", headers=self.admin)
        self.assertEqual(self.oidc.user_for(claims)["id"], user["id"])  # already here: signs in regardless

    def test_the_users_command_checks_places_on_add_and_enable(self):
        self.fill_free_places()
        with mock.patch.object(self.users, "hash_password", lambda p: "x"), \
                mock.patch("getpass.getpass", return_value="a-long-enough-password"):
            from auth import manage_users
            with self.assertRaisesRegex(SystemExit, "All 4 places"):
                manage_users.main(["add", "ivan", "ivan@example.org"])

    def test_local_mode_is_free_with_no_licence_and_its_analyst_can_install_one(self):
        self.settings.rowanholt_server_mode = False
        try:
            # Local mode has no sign-in: the analyst is the admin, with no token
            local = self.client.get("/api/licence")
            self.assertEqual(local.status_code, 200, local.text)
            self.assertEqual((local.json()["edition"], local.json()["server_mode"]), ("free", False))
            self.assertEqual(self.install_local(self.line("pro")).status_code, 200)
            now = self.client.get("/api/licence").json()
            self.assertEqual(now["edition"], "pro")
            self.assertIn("report-branding", now["features"])
            self.assertEqual(now["accepted"]["by"], "Local analyst <local>")
            self.assertIsNone(self.licence.seat_refusal({str(i): {} for i in range(50)}, self.settings.rowanholt_server_mode))
        finally:
            self.settings.rowanholt_server_mode = True

    def install_local(self, text):
        version = self.client.get("/api/licence/terms").json()["version"]
        return self.client.put("/api/licence", json={"text": text, "accept_terms": True, "terms_version": version})

    def test_the_server_command_needs_the_terms_accepted_then_installs_and_removes(self):
        line = Path(tempfile.mkdtemp()) / "northwind.licence"
        line.write_text(self.line("services", seats=25) + "\n")
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(self.cli.main(["install", str(line)]), 1)
        self.assertIn("--accept-terms", err.getvalue())
        self.assertFalse(self.path.exists())

        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(self.cli.main(["install", str(line), "--accept-terms", "Ben Smith <ben@example.org>"]), 0)
            self.assertEqual(self.cli.main(["show"]), 0)
        self.assertIn("Installed services for Northwind Ltd", out.getvalue())
        self.assertIn("Commercial licence v1.1 accepted by Ben Smith <ben@example.org>", out.getvalue())
        stored = json.loads(self.path.read_text())
        self.assertEqual((stored["accepted_by"], stored["accepted_by_name"]), (None, "Ben Smith <ben@example.org>"))
        action, username, details = self.audit_rows()[-1]
        self.assertEqual((action, details["via"], details["accepted_by"], details["terms_version"]),
                         ("licence_installed", "cli", "Ben Smith <ben@example.org>", "1.1"))
        with redirect_stdout(io.StringIO()):
            self.assertEqual(self.cli.main(["remove"]), 0)
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
