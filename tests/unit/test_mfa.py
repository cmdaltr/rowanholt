"""Unit tests for multi-factor authentication (src/web/backend/auth/mfa.py and its routes in
auth/routes_simple.py): enrolment confirmed by a code, a sign-in with no session before the second
step, single-use challenges and TOTP steps, backup codes, disabling, admins' reset, the
ROWANHOLT_REQUIRE_MFA policy, the secret encrypted at rest, API tokens and single sign-on unaffected.

Run from tests/unit: python3 -m unittest test_mfa.py
"""

import json
import sys
import time
import unittest
from itertools import count
from pathlib import Path
from unittest import mock

from test_server_access import BackendCase, TestClient

PASSWORD = "mfa-test-password-1"
_names = count()


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class MfaTest(BackendCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.mfa = sys.modules["auth.mfa"]
        cls.users_module = sys.modules["auth.users"]

    def setUp(self):
        # A clock the test moves on, so each code is for a step of its own
        self.now = time.time()
        patcher = mock.patch.object(self.mfa, "_now", lambda: self.now)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(setattr, self.settings, "rowanholt_require_mfa", False)
        # Every test makes its own users, past the free edition's four places
        seats = mock.patch.object(sys.modules["auth.routes_simple"].licence, "seat_refusal", return_value=None)
        seats.start()
        self.addCleanup(seats.stop)

    # ── helpers ──────────────────────────────────────────────────────────────

    def new_user(self):
        name = f"mfa{next(_names)}x{int(self.now) % 100000}"
        resp = self.client.post("/api/auth/users", headers=self.admin, json={
            "username": name, "email": f"{name}@example.org", "password": PASSWORD})
        self.assertEqual(resp.status_code, 200, resp.text)
        return name, resp.json()["id"], self.login(name, PASSWORD)

    def code(self, secret):
        """The next step's code (the clock moves on 30 s first)."""
        self.now += self.mfa.STEP_SECONDS
        return self.mfa.code_at(secret, self.mfa.current_step())

    def enrol(self, headers):
        started = self.client.post("/api/auth/mfa/setup", headers=headers, json={})
        self.assertEqual(started.status_code, 200, started.text)
        secret = started.json()["secret"]
        enabled = self.client.post("/api/auth/mfa/enable", headers=headers, json={"code": self.code(secret)})
        self.assertEqual(enabled.status_code, 200, enabled.text)
        return secret, enabled.json()["backup_codes"]

    def password_step(self, name, password=PASSWORD):
        self.client.cookies.clear()
        resp = self.client.post("/api/auth/login", data={"username": name, "password": password})
        self.client.cookies.clear()
        return resp

    def second_step(self, challenge, code):
        resp = self.client.post("/api/auth/login/mfa", json={"challenge": challenge, "code": code})
        self.client.cookies.clear()
        return resp

    def record(self, user_id):
        return self.users_module.load_users()[user_id]

    def audited(self, user_id, action):
        storage = sys.modules["auth.access"]._storage
        return [row for row in storage.audit_records(resource_id=user_id, action_prefix="mfa_")
                if row["action"] == action]

    # ── enrolment ────────────────────────────────────────────────────────────

    def test_enrolment_needs_a_confirmed_code(self):
        name, user_id, headers = self.new_user()
        status = self.client.get("/api/auth/mfa", headers=headers).json()
        self.assertEqual((status["available"], status["enabled"]), (True, False))
        started = self.client.post("/api/auth/mfa/setup", headers=headers, json={}).json()
        self.assertTrue(started["otpauth_uri"].startswith(f"otpauth://totp/Rowanholt%3A{name}?secret={started['secret']}"))
        self.assertIn("period=30", started["otpauth_uri"])
        self.assertTrue(started["qr_svg"].startswith("data:image/svg+xml"))
        # Started but not confirmed: still off, and the password alone still signs in
        self.assertFalse(self.client.get("/api/auth/mfa", headers=headers).json()["enabled"])
        self.assertIn("access_token", self.password_step(name).json())
        wrong = self.client.post("/api/auth/mfa/enable", headers=headers, json={"code": "000000"})
        self.assertEqual(wrong.status_code, 400)
        self.assertFalse(self.client.get("/api/auth/mfa", headers=headers).json()["enabled"])
        enabled = self.client.post("/api/auth/mfa/enable", headers=headers, json={"code": self.code(started["secret"])})
        self.assertEqual(enabled.status_code, 200, enabled.text)
        body = enabled.json()
        self.assertTrue(body["enabled"])
        self.assertEqual(len(body["backup_codes"]), 10)
        self.assertEqual(body["backup_codes_left"], 10)
        # The secret never comes back
        status = self.client.get("/api/auth/mfa", headers=headers).json()
        self.assertNotIn(started["secret"], json.dumps(status))
        self.assertTrue(self.client.get("/api/auth/me", headers=headers).json()["mfa_enabled"])
        self.assertEqual(len(self.audited(user_id, "mfa_enabled")), 1)

    def test_re_enrolment_needs_a_current_code_and_replaces_the_secret_only_on_confirmation(self):
        name, user_id, headers = self.new_user()
        old, codes = self.enrol(headers)
        self.assertEqual(self.client.post("/api/auth/mfa/setup", headers=headers, json={}).status_code, 400)
        started = self.client.post("/api/auth/mfa/setup", headers=headers, json={"code": self.code(old)})
        self.assertEqual(started.status_code, 200, started.text)
        new = started.json()["secret"]
        # Not confirmed yet: the old secret still signs in, the new one doesn't
        challenge = self.password_step(name).json()["challenge"]
        self.assertEqual(self.second_step(challenge, self.mfa.code_at(new, self.mfa.current_step() + 1)).status_code, 401)
        self.assertEqual(self.second_step(challenge, self.code(old)).status_code, 200)
        confirmed = self.client.post("/api/auth/mfa/enable", headers=headers, json={"code": self.code(new)})
        self.assertEqual(confirmed.status_code, 200, confirmed.text)
        self.assertIsNone(confirmed.json()["backup_codes"])  # the codes they have still stand
        challenge = self.password_step(name).json()["challenge"]
        self.assertEqual(self.second_step(challenge, self.code(old)).status_code, 401)
        challenge = self.password_step(name).json()["challenge"]
        self.assertEqual(self.second_step(challenge, self.code(new)).status_code, 200)
        self.assertEqual(len(self.audited(user_id, "mfa_reenrolled")), 1)

    def test_the_secret_is_encrypted_at_rest(self):
        name, user_id, headers = self.new_user()
        secret, codes = self.enrol(headers)
        stored = Path(self.users_module.USERS_FILE).read_text()
        self.assertNotIn(secret, stored)
        for code in codes:
            self.assertNotIn(code, stored)
            self.assertNotIn(code.replace("-", ""), stored)
        record = self.record(user_id)
        self.assertNotEqual(record["mfa_secret"], secret)
        self.assertEqual(self.mfa.decrypt_secret(record["mfa_secret"]), secret)
        # Under another server's key it's unreadable
        with mock.patch.object(self.settings, "secret_key", "another-servers-key-0123456789abcdef"):
            self.assertIsNone(self.mfa.decrypt_secret(record["mfa_secret"]))

    # ── sign-in ──────────────────────────────────────────────────────────────

    def test_sign_in_without_mfa_is_unchanged(self):
        name, _, _ = self.new_user()
        resp = self.password_step(name)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("access_token", resp.json())
        self.assertNotIn("mfa_required", resp.json())

    def test_no_session_before_the_second_step(self):
        name, user_id, headers = self.new_user()
        secret, _ = self.enrol(headers)
        resp = self.password_step(name)
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["mfa_required"])
        self.assertNotIn("access_token", body)
        self.assertNotIn("session_token", resp.cookies)
        # The challenge is no token anywhere else
        self.assertEqual(self.client.get("/api/auth/me", headers=bearer(body["challenge"])).status_code, 401)
        self.assertEqual(self.client.get("/api/jobs", headers={"Cookie": f"session_token={body['challenge']}"}).status_code, 401)
        self.assertEqual(self.client.get("/api/auth/verify", headers=bearer(body["challenge"])).status_code, 401)

        done = self.client.post("/api/auth/login/mfa", json={"challenge": body["challenge"], "code": self.code(secret)})
        self.assertEqual(done.status_code, 200, done.text)
        self.assertIn("session_token", done.cookies)
        self.client.cookies.clear()
        signed_in = done.json()
        self.assertEqual(signed_in["user"]["username"], name)
        self.assertEqual(self.client.get("/api/auth/me", headers=bearer(signed_in["access_token"])).json()["id"], user_id)

    def test_a_challenge_signs_in_once_and_expires(self):
        name, _, headers = self.new_user()
        secret, _ = self.enrol(headers)
        challenge = self.password_step(name).json()["challenge"]
        self.assertEqual(self.second_step(challenge, self.code(secret)).status_code, 200)
        used = self.second_step(challenge, self.code(secret))
        self.assertEqual(used.status_code, 401)
        challenge = self.password_step(name).json()["challenge"]
        self.now += self.mfa.CHALLENGE_SECONDS + 1
        expired = self.second_step(challenge, self.code(secret))
        self.assertEqual(expired.status_code, 401)
        self.assertIn("expired", expired.json()["detail"])
        # A forged one (the body changed, the signature not)
        challenge = self.password_step(name).json()["challenge"]
        body, signature = challenge[len("mfa_"):].split(".")
        self.assertEqual(self.second_step(f"mfa_{body[:-2]}AA.{signature}", self.code(secret)).status_code, 401)

    def test_a_password_change_makes_an_outstanding_challenge_stale(self):
        name, _, headers = self.new_user()
        secret, _ = self.enrol(headers)
        challenge = self.password_step(name).json()["challenge"]
        changed = self.client.post("/api/auth/change-password", headers=headers,
                                   json={"current_password": PASSWORD, "new_password": "a-new-password-22"})
        self.assertEqual(changed.status_code, 200, changed.text)
        self.assertEqual(self.second_step(challenge, self.code(secret)).status_code, 401)

    def test_a_used_totp_step_is_refused(self):
        name, _, headers = self.new_user()
        secret, _ = self.enrol(headers)
        code = self.code(secret)
        self.assertEqual(self.second_step(self.password_step(name).json()["challenge"], code).status_code, 200)
        # Same code, same step, a fresh challenge: refused
        self.assertEqual(self.second_step(self.password_step(name).json()["challenge"], code).status_code, 401)
        # The step before is older than the one used: refused too
        earlier = self.mfa.code_at(secret, self.mfa.current_step() - 1)
        self.assertEqual(self.second_step(self.password_step(name).json()["challenge"], earlier).status_code, 401)

    def test_wrong_codes_count_towards_the_lockout(self):
        name, user_id, headers = self.new_user()
        secret, _ = self.enrol(headers)
        challenge = self.password_step(name).json()["challenge"]
        for _ in range(self.settings.max_login_attempts):
            self.assertEqual(self.second_step(challenge, "000000").status_code, 401)
        locked = self.second_step(challenge, self.code(secret))
        self.assertEqual(locked.status_code, 429)
        # And the right password doesn't reset the count while the second factor is outstanding
        self.assertEqual(self.password_step(name).status_code, 429)
        self.assertGreaterEqual(len(self.audited(user_id, "mfa_failed")), self.settings.max_login_attempts)

    def test_a_right_password_does_not_reset_failed_codes(self):
        name, _, headers = self.new_user()
        secret, _ = self.enrol(headers)
        for _ in range(self.settings.max_login_attempts - 1):
            challenge = self.password_step(name).json()["challenge"]
            self.second_step(challenge, "111111")
        challenge = self.password_step(name).json()["challenge"]
        self.assertEqual(self.second_step(challenge, "222222").status_code, 401)
        self.assertEqual(self.password_step(name).status_code, 429)

    # ── backup codes ─────────────────────────────────────────────────────────

    def test_a_backup_code_signs_in_once(self):
        name, user_id, headers = self.new_user()
        _, codes = self.enrol(headers)
        done = self.second_step(self.password_step(name).json()["challenge"], codes[0].lower())
        self.assertEqual(done.status_code, 200, done.text)
        self.assertEqual(self.client.get("/api/auth/mfa", headers=headers).json()["backup_codes_left"], 9)
        again = self.second_step(self.password_step(name).json()["challenge"], codes[0])
        self.assertEqual(again.status_code, 401)
        [used] = self.audited(user_id, "mfa_backup_code_used")
        self.assertEqual(used["details"]["left"], 9)

    def test_regenerating_backup_codes_needs_a_current_code_and_replaces_them(self):
        name, user_id, headers = self.new_user()
        secret, old = self.enrol(headers)
        self.assertEqual(self.client.post("/api/auth/mfa/backup-codes", headers=headers,
                                          json={"code": "123456"}).status_code, 400)
        # A backup code won't do: losing them is why someone makes new ones
        self.assertEqual(self.client.post("/api/auth/mfa/backup-codes", headers=headers,
                                          json={"code": old[0]}).status_code, 400)
        made = self.client.post("/api/auth/mfa/backup-codes", headers=headers, json={"code": self.code(secret)})
        self.assertEqual(made.status_code, 200, made.text)
        new = made.json()["backup_codes"]
        self.assertEqual(len(new), 10)
        self.assertFalse(set(new) & set(old))
        self.assertEqual(self.second_step(self.password_step(name).json()["challenge"], old[1]).status_code, 401)
        self.assertEqual(self.second_step(self.password_step(name).json()["challenge"], new[1]).status_code, 200)
        self.assertEqual(len(self.audited(user_id, "mfa_backup_codes_regenerated")), 1)

    # ── turning it off ───────────────────────────────────────────────────────

    def test_disabling_needs_the_password_and_a_code(self):
        name, user_id, headers = self.new_user()
        secret, codes = self.enrol(headers)
        disable = "/api/auth/mfa/disable"
        self.assertEqual(self.client.post(disable, headers=headers, json={"password": "wrong-password-1",
                                                                          "code": self.code(secret)}).status_code, 400)
        self.assertEqual(self.client.post(disable, headers=headers, json={"password": PASSWORD,
                                                                          "code": "000000"}).status_code, 400)
        self.assertEqual(self.client.post(disable, headers=headers, json={"password": PASSWORD}).status_code, 422)
        self.assertTrue(self.client.get("/api/auth/mfa", headers=headers).json()["enabled"])
        done = self.client.post(disable, headers=headers, json={"password": PASSWORD, "code": codes[3]})
        self.assertEqual(done.status_code, 200, done.text)
        self.assertFalse(done.json()["enabled"])
        self.assertNotIn("mfa_secret", self.record(user_id))
        self.assertIn("access_token", self.password_step(name).json())
        self.assertEqual(len(self.audited(user_id, "mfa_disabled")), 1)

    def test_an_admin_resets_someones_mfa_and_nobody_else_can(self):
        name, user_id, headers = self.new_user()
        self.enrol(headers)
        _, _, other = self.new_user()
        self.assertEqual(self.client.delete(f"/api/auth/users/{user_id}/mfa", headers=other).status_code, 403)
        self.assertEqual(self.client.delete(f"/api/auth/users/{user_id}/mfa", headers=headers).status_code, 403)
        self.assertTrue(self.record(user_id)["mfa_enabled"])
        reset = self.client.delete(f"/api/auth/users/{user_id}/mfa", headers=self.admin)
        self.assertEqual(reset.status_code, 200, reset.text)
        self.assertFalse(reset.json()["mfa_enabled"])
        self.assertIn("access_token", self.password_step(name).json())
        [row] = self.audited(user_id, "mfa_admin_reset")
        self.assertEqual(row["username"], "admin")
        self.assertEqual(self.client.delete(f"/api/auth/users/{user_id}/mfa", headers=self.admin).status_code, 400)
        self.assertEqual(self.client.delete("/api/auth/users/no-such-user/mfa", headers=self.admin).status_code, 404)

    def test_the_server_cli_resets_mfa(self):
        name, user_id, headers = self.new_user()
        self.enrol(headers)
        manage_users = sys.modules.get("auth.manage_users")
        if manage_users is None:
            from auth import manage_users
        with mock.patch.object(manage_users, "_audit_storage", lambda: sys.modules["auth.access"]._storage):
            self.assertEqual(manage_users.main(["mfa-reset", name]), 0)
            with self.assertRaises(SystemExit):
                manage_users.main(["mfa-reset", name])  # nothing left to reset
        self.assertFalse(self.mfa.is_enabled(self.record(user_id)))
        [row] = self.audited(user_id, "mfa_admin_reset")
        self.assertEqual(row["details"]["via"], "cli")

    # ── the policy ───────────────────────────────────────────────────────────

    def test_require_mfa_holds_a_password_user_to_enrolment(self):
        name, user_id, _ = self.new_user()
        self.settings.rowanholt_require_mfa = True
        signed_in = self.password_step(name)
        self.assertEqual(signed_in.status_code, 200)
        self.assertTrue(signed_in.json()["mfa_enrolment_required"])
        headers = bearer(signed_in.json()["access_token"])
        refused = self.client.get("/api/jobs", headers=headers)
        self.assertEqual(refused.status_code, 403)
        self.assertTrue(refused.json()["mfa_enrolment_required"])
        self.assertIn("multi-factor authentication", refused.json()["detail"])
        self.assertEqual(self.client.get("/api/auth/verify", headers=headers).status_code, 403)
        self.assertEqual(self.client.post("/api/auth/tokens", headers=headers,
                                          json={"name": "x", "scope": "full", "days": 1}).status_code, 403)
        self.assertEqual(self.client.get("/api/auth/me", headers=headers).status_code, 200)
        self.assertTrue(self.client.get("/api/auth/mfa", headers=headers).json()["required"])
        secret, _ = self.enrol(headers)
        self.assertEqual(self.client.get("/api/jobs", headers=headers).status_code, 200)
        # With the policy on, turning MFA off isn't offered; an admin's reset still is
        self.assertEqual(self.client.post("/api/auth/mfa/disable", headers=headers,
                                          json={"password": PASSWORD, "code": self.code(secret)}).status_code, 400)

    def test_require_mfa_leaves_api_tokens_alone(self):
        _, _, headers = self.new_user()
        made = self.client.post("/api/auth/tokens", headers=headers, json={"name": "s", "scope": "full", "days": 1})
        self.assertEqual(made.status_code, 200, made.text)
        self.settings.rowanholt_require_mfa = True
        self.assertEqual(self.client.get("/api/jobs", headers=bearer(made.json()["token"])).status_code, 200)

    # ── what MFA doesn't touch ───────────────────────────────────────────────

    def test_api_tokens_need_no_second_factor_and_cannot_manage_it(self):
        _, _, headers = self.new_user()
        made = self.client.post("/api/auth/tokens", headers=headers, json={"name": "s", "scope": "full", "days": 1})
        token = bearer(made.json()["token"])
        self.enrol(headers)
        self.assertEqual(self.client.get("/api/jobs", headers=token).status_code, 200)
        self.assertEqual(self.client.post("/api/auth/mfa/setup", headers=token, json={}).status_code, 403)

    def test_single_sign_on_accounts_are_not_offered_enrolment(self):
        users = self.users_module.load_users()
        sso = self.users_module.new_user(f"sso{next(_names)}", "sso@example.org", oidc_subject="https://idp|abc")
        users[sso["id"]] = sso
        self.users_module.save_users(users)
        headers = bearer(sys.modules["auth.security"].create_access_token({"sub": sso["id"], "role": "user"}))
        status = self.client.get("/api/auth/mfa", headers=headers).json()
        self.assertEqual((status["available"], status["reason"]), (False, "sso"))
        self.assertIn("identity provider", status["message"])
        self.assertEqual(self.client.post("/api/auth/mfa/setup", headers=headers, json={}).status_code, 400)
        # Nor held by the policy: their MFA is the identity provider's
        self.settings.rowanholt_require_mfa = True
        self.assertEqual(self.client.get("/api/jobs", headers=headers).status_code, 200)

    def test_local_mode_says_mfa_is_for_a_server(self):
        self.settings.rowanholt_server_mode = False
        try:
            status = self.client.get("/api/auth/mfa").json()
            self.assertEqual((status["available"], status["reason"]), (False, "local"))
            self.assertIn("team server", status["message"])
            self.assertEqual(self.client.post("/api/auth/mfa/setup", json={}).status_code, 400)
        finally:
            self.settings.rowanholt_server_mode = True


class TotpTest(unittest.TestCase):
    """RFC 6238's SHA-1 test vectors, at 6 digits."""

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "web" / "backend"))
        from auth import mfa
        cls.mfa = mfa

    def test_rfc_6238_vectors(self):
        import base64
        secret = base64.b32encode(b"12345678901234567890").decode()
        for when, code in ((59, "287082"), (1111111109, "081804"), (1111111111, "050471"),
                           (1234567890, "005924"), (2000000000, "279037"), (20000000000, "353130")):
            self.assertEqual(self.mfa.code_at(secret, when // 30), code, when)

    def test_one_step_either_side_and_no_further(self):
        secret = self.mfa.new_secret()
        now = 1_800_000_000.0
        step = int(now // 30)
        for offset in (-1, 0, 1):
            self.assertEqual(self.mfa.matching_step(secret, self.mfa.code_at(secret, step + offset), now=now), step + offset)
        for offset in (-2, 2):
            self.assertIsNone(self.mfa.matching_step(secret, self.mfa.code_at(secret, step + offset), now=now))
        self.assertIsNone(self.mfa.matching_step(secret, self.mfa.code_at(secret, step), last_step=step, now=now))
        spaced = self.mfa.code_at(secret, step)
        self.assertEqual(self.mfa.matching_step(secret, f"{spaced[:3]} {spaced[3:]}", now=now), step)
        self.assertIsNone(self.mfa.matching_step(secret, "12345", now=now))


if __name__ == "__main__":
    unittest.main()
