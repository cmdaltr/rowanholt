"""Unit tests for resetting someone's access (src/web/backend/auth/reset_access.py, its routes in
auth/routes_simple.py and `server users reset-access`): issuing ends the account's sessions, revokes
its API tokens and replaces an earlier link, and is audited; a link sets a new password and a new
authenticator only once a code from it is confirmed, with fresh backup codes, signs in once, and
expires; disabled and single sign-on accounts are refused; only admins issue one.

Run from tests/unit: python3 -m unittest test_reset_access.py
"""

import sys
import time
import unittest
from itertools import count
from unittest import mock

from test_server_access import BackendCase, TestClient

PASSWORD = "reset-test-password-1"
NEW_PASSWORD = "a-brand-new-password-2"
_names = count()


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class ResetAccessTest(BackendCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.mfa = sys.modules["auth.mfa"]
        cls.users_module = sys.modules["auth.users"]
        cls.reset = sys.modules["auth.reset_access"]

    def setUp(self):
        self.now = time.time()
        patcher = mock.patch.object(self.mfa, "_now", lambda: self.now)
        patcher.start()
        self.addCleanup(patcher.stop)
        seats = mock.patch.object(sys.modules["auth.routes_simple"].licence, "seat_refusal", return_value=None)
        seats.start()
        self.addCleanup(seats.stop)

    # ── helpers ──────────────────────────────────────────────────────────────

    def new_user(self):
        name = f"reset{next(_names)}x{int(self.now) % 100000}"
        user = self.make_user(name, PASSWORD)
        return name, user["id"], self.login(name, PASSWORD)

    def code(self, secret):
        """The next step's code (the clock moves on 30 s first)."""
        self.now += self.mfa.STEP_SECONDS
        return self.mfa.code_at(secret, self.mfa.current_step())

    def enrol(self, headers):
        secret = self.client.post("/api/auth/mfa/setup", headers=headers, json={}).json()["secret"]
        enabled = self.client.post("/api/auth/mfa/enable", headers=headers, json={"code": self.code(secret)})
        self.assertEqual(enabled.status_code, 200, enabled.text)
        return secret, enabled.json()["backup_codes"]

    def issue(self, user_id, headers=None):
        resp = self.client.post(f"/api/auth/users/{user_id}/reset-access", headers=headers or self.admin)
        self.assertEqual(resp.status_code, 200, resp.text)
        link = resp.json()["link"]
        self.assertTrue(link.startswith("https://rowanholt.test/reset-access#"), link)
        return link.split("#", 1)[1]

    def start(self, token):
        self.client.cookies.clear()
        return self.client.post("/api/auth/reset-access/start", json={"token": token})

    def complete(self, token, code, password=NEW_PASSWORD):
        resp = self.client.post("/api/auth/reset-access/complete",
                                json={"token": token, "new_password": password, "code": code})
        self.client.cookies.clear()
        return resp

    def record(self, user_id):
        return self.users_module.load_users()[user_id]

    def audited(self, user_id, action):
        storage = sys.modules["auth.access"]._storage
        return [row for row in storage.audit_records(resource_id=user_id, action_prefix="access_reset")
                if row["action"] == action]

    def password_step(self, name, password):
        self.client.cookies.clear()
        resp = self.client.post("/api/auth/login", data={"username": name, "password": password})
        self.client.cookies.clear()
        return resp

    # ── issuing ──────────────────────────────────────────────────────────────

    def test_issuing_ends_sessions_revokes_tokens_and_is_audited(self):
        _, user_id, headers = self.new_user()
        made = self.client.post("/api/auth/tokens", headers=headers, json={"name": "s", "scope": "full", "days": 1})
        self.assertEqual(made.status_code, 200, made.text)
        self.assertEqual(self.client.get("/api/auth/me", headers=bearer(made.json()["token"])).status_code, 200)
        token = self.issue(user_id)
        self.assertEqual(self.client.get("/api/auth/me", headers=headers).status_code, 401)
        self.assertEqual(self.client.get("/api/auth/me", headers=bearer(made.json()["token"])).status_code, 401)
        # Only a hash is kept, with an expiry a few days on
        stored = self.record(user_id)
        self.assertNotIn(token, str(stored))
        self.assertEqual(stored["access_reset_hash"], self.reset.token_hash(token))
        self.assertAlmostEqual(stored["access_reset_expires"] - self.now, self.reset.RESET_HOURS * 3600, delta=5)
        [row] = self.audited(user_id, "access_reset_issued")
        self.assertEqual(row["username"], "admin")
        self.assertEqual(row["details"]["tokens_revoked"], 1)

    def test_a_new_link_replaces_an_earlier_one(self):
        _, user_id, _ = self.new_user()
        first = self.issue(user_id)
        second = self.issue(user_id)
        self.assertEqual(self.start(first).status_code, 400)
        self.assertEqual(self.start(second).status_code, 200)

    def test_only_admins_issue_a_link(self):
        _, user_id, headers = self.new_user()
        for who in (headers, self.alice):
            self.assertEqual(self.client.post(f"/api/auth/users/{user_id}/reset-access", headers=who).status_code, 403)
        self.assertEqual(self.client.post("/api/auth/users/no-such-user/reset-access", headers=self.admin).status_code, 404)
        # Not through an API token, even an admin's
        made = self.client.post("/api/auth/tokens", headers=self.admin, json={"name": "a", "scope": "full", "days": 1})
        self.assertEqual(self.client.post(f"/api/auth/users/{user_id}/reset-access",
                                          headers=bearer(made.json()["token"])).status_code, 403)
        self.assertNotIn("access_reset_hash", self.record(user_id))

    def test_disabled_and_single_sign_on_accounts_are_refused(self):
        _, user_id, _ = self.new_user()
        self.client.patch(f"/api/auth/users/{user_id}", headers=self.admin, json={"is_active": False})
        refused = self.client.post(f"/api/auth/users/{user_id}/reset-access", headers=self.admin)
        self.assertEqual(refused.status_code, 400)
        self.assertIn("disabled", refused.json()["detail"])
        users = self.users_module.load_users()
        sso = self.users_module.new_user(f"sso{next(_names)}", "sso-reset@example.org", oidc_subject="https://idp|r")
        users[sso["id"]] = sso
        self.users_module.save_users(users)
        refused = self.client.post(f"/api/auth/users/{sso['id']}/reset-access", headers=self.admin)
        self.assertEqual(refused.status_code, 400)
        self.assertIn("single sign-on", refused.json()["detail"])

    # ── using the link ───────────────────────────────────────────────────────

    def test_a_reset_sets_a_new_password_authenticator_and_backup_codes_and_signs_in(self):
        name, user_id, headers = self.new_user()
        old_secret, old_codes = self.enrol(headers)
        token = self.issue(user_id)
        started = self.start(token)
        self.assertEqual(started.status_code, 200, started.text)
        body = started.json()
        self.assertEqual(body["username"], name)
        self.assertTrue(body["qr_svg"].startswith("data:image/svg+xml"))
        self.assertNotIn(body["secret"], str(self.record(user_id)))  # kept encrypted
        new_secret = body["secret"]
        # Nothing has changed yet: the old password still takes the old authenticator
        self.assertTrue(self.password_step(name, PASSWORD).json()["mfa_required"])
        # A code from the old authenticator isn't one from the new
        self.assertEqual(self.complete(token, self.code(old_secret)).status_code, 400)
        done = self.complete(token, self.code(new_secret))
        self.assertEqual(done.status_code, 200, done.text)
        body = done.json()
        self.assertTrue(body["user"]["mfa_enabled"])
        self.assertEqual(len(body["backup_codes"]), 10)
        self.assertFalse(set(body["backup_codes"]) & set(old_codes))
        self.assertEqual(self.client.get("/api/auth/me", headers=bearer(body["access_token"])).json()["id"], user_id)
        record = self.record(user_id)
        self.assertNotIn("access_reset_hash", record)
        self.assertNotIn("access_reset_pending_secret", record)
        # The old password and old codes are gone; the new password asks for the new authenticator
        self.assertEqual(self.password_step(name, PASSWORD).status_code, 401)
        challenge = self.password_step(name, NEW_PASSWORD).json()["challenge"]
        self.assertEqual(self.client.post("/api/auth/login/mfa", json={"challenge": challenge, "code": old_codes[0]}).status_code, 401)
        challenge = self.password_step(name, NEW_PASSWORD).json()["challenge"]
        self.assertEqual(self.client.post("/api/auth/login/mfa", json={"challenge": challenge,
                                                                      "code": self.code(new_secret)}).status_code, 200)
        self.client.cookies.clear()
        [row] = self.audited(user_id, "access_reset_completed")
        self.assertEqual(row["username"], name)

    def test_mfa_goes_on_even_when_the_server_does_not_require_it(self):
        self.assertFalse(self.settings.rowanholt_require_mfa)
        _, user_id, _ = self.new_user()
        token = self.issue(user_id)
        secret = self.start(token).json()["secret"]
        done = self.complete(token, self.code(secret))
        self.assertEqual(done.status_code, 200, done.text)
        self.assertTrue(self.mfa.is_enabled(self.record(user_id)))

    def test_a_link_works_once(self):
        _, user_id, _ = self.new_user()
        token = self.issue(user_id)
        secret = self.start(token).json()["secret"]
        self.assertEqual(self.complete(token, self.code(secret)).status_code, 200)
        self.assertEqual(self.start(token).status_code, 400)
        self.assertEqual(self.complete(token, self.code(secret)).status_code, 400)

    def test_an_expired_link_is_refused(self):
        _, user_id, _ = self.new_user()
        token = self.issue(user_id)
        secret = self.start(token).json()["secret"]
        self.now += self.reset.RESET_HOURS * 3600 + 1
        self.assertEqual(self.start(token).status_code, 410)
        self.assertEqual(self.complete(token, self.code(secret)).status_code, 410)
        self.assertFalse(self.mfa.is_enabled(self.record(user_id)))

    def test_refusals_before_anything_changes(self):
        name, user_id, _ = self.new_user()
        token = self.issue(user_id)
        self.assertEqual(self.start("not-a-token").status_code, 400)
        self.assertEqual(self.start("").status_code, 400)
        # No authenticator started yet
        self.assertEqual(self.complete(token, "123456").status_code, 400)
        secret = self.start(token).json()["secret"]
        self.assertEqual(self.complete(token, self.code(secret), password="short").status_code, 400)
        self.assertEqual(self.complete(token, "000000").status_code, 400)
        record = self.record(user_id)
        self.assertFalse(self.mfa.is_enabled(record))
        self.assertIn("access_reset_hash", record)
        self.assertEqual(self.password_step(name, PASSWORD).status_code, 200)

    def test_wrong_codes_count_towards_the_lockout(self):
        _, user_id, _ = self.new_user()
        token = self.issue(user_id)
        secret = self.start(token).json()["secret"]
        for _ in range(self.settings.max_login_attempts):
            self.assertEqual(self.complete(token, "000000").status_code, 400)
        self.assertEqual(self.complete(token, self.code(secret)).status_code, 429)

    def test_tokens_made_before_the_reset_completes_are_revoked(self):
        name, user_id, _ = self.new_user()
        token = self.issue(user_id)
        # The old password still signs in until the reset is finished, and could make a token
        signed_in = self.password_step(name, PASSWORD).json()["access_token"]
        made = self.client.post("/api/auth/tokens", headers=bearer(signed_in), json={"name": "s", "scope": "full", "days": 1})
        self.assertEqual(made.status_code, 200, made.text)
        secret = self.start(token).json()["secret"]
        self.assertEqual(self.complete(token, self.code(secret)).status_code, 200)
        self.assertEqual(self.client.get("/api/auth/me", headers=bearer(made.json()["token"])).status_code, 401)
        self.assertEqual(self.client.get("/api/auth/me", headers=bearer(signed_in)).status_code, 401)

    # ── the server's CLI ─────────────────────────────────────────────────────

    def test_the_server_cli_issues_a_link(self):
        name, user_id, headers = self.new_user()
        manage_users = sys.modules.get("auth.manage_users")
        if manage_users is None:
            from auth import manage_users
        with mock.patch.object(manage_users, "_audit_storage", lambda: sys.modules["auth.access"]._storage), \
                mock.patch("builtins.print") as printed:
            self.assertEqual(manage_users.main(["reset-access", f"{name}@example.org"]), 0)
        output = " ".join(str(arg) for call in printed.call_args_list for arg in call.args)
        token = output.split("https://rowanholt.test/reset-access#", 1)[1].split()[0]
        self.assertEqual(self.client.get("/api/auth/me", headers=headers).status_code, 401)
        self.assertEqual(self.start(token).status_code, 200)
        [row] = self.audited(user_id, "access_reset_issued")
        self.assertEqual((row["username"], row["details"]["via"]), ("server-cli", "cli"))
        with self.assertRaises(SystemExit):
            manage_users.main(["reset-access", "nobody-here"])

    def test_not_on_a_local_stack(self):
        _, user_id, _ = self.new_user()
        record = self.record(user_id)
        with mock.patch.object(self.settings, "rowanholt_server_mode", False), \
                self.assertRaises(self.reset.ResetRefused):
            self.reset.issue(record, None)


if __name__ == "__main__":
    unittest.main()
