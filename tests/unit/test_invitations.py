"""Unit tests for invitations (src/web/backend/auth/invitations.py, its routes in auth/routes_simple.py
and `server users invite|invitations|revoke-invitation`): how a team server's accounts are made. An
admin invites an email with a role; the link makes the account only once a code from a new
authenticator is confirmed, with the role, MFA on and ten backup codes, signed in, once, within 24
hours. Refused for an email with an account, past the licence's places, and on a local stack; a newer
invitation replaces an older one; admins list and withdraw them; admins no longer set a new
account's password on a server, and a local stack keeps its own sign-up.

Run from tests/unit: python3 -m unittest test_invitations.py
"""

import sys
import time
import unittest
from itertools import count
from unittest import mock

from test_server_access import BackendCase, TestClient

PASSWORD = "invited-password-12"
_names = count()


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class InvitationTest(BackendCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.mfa = sys.modules["auth.mfa"]
        cls.users_module = sys.modules["auth.users"]
        cls.invitations = sys.modules["auth.invitations"]
        cls.reset = sys.modules["auth.reset_access"]

    def setUp(self):
        self.now = time.time()
        patcher = mock.patch.object(self.mfa, "_now", lambda: self.now)
        patcher.start()
        self.addCleanup(patcher.stop)
        # Other classes share this user store: the seat tests below set their own limit
        self.seats = mock.patch.object(sys.modules["licence"], "current",
                                       return_value=mock.Mock(seats=None, edition=None))
        self.seats.start()
        self.addCleanup(self.seats.stop)

    # ── helpers ──────────────────────────────────────────────────────────────

    def email(self):
        return f"inv{next(_names)}x{int(self.now) % 100000}@example.org"

    def issue(self, email, role="user", **body):
        resp = self.invite(email, role, **body)
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertTrue(resp.json()["link"].startswith("https://rowanholt.test/accept-invite#"))
        return resp.json(), resp.json()["link"].split("#", 1)[1]

    def code(self, secret):
        self.now += self.mfa.STEP_SECONDS
        return self.mfa.code_at(secret, self.mfa.current_step())

    def preview(self, token):
        self.client.cookies.clear()
        return self.client.post("/api/auth/invitations/accept", json={"token": token})

    def start(self, token, username):
        self.client.cookies.clear()
        return self.client.post("/api/auth/invitations/accept/start", json={"token": token, "username": username})

    def complete(self, token, username, code, password=PASSWORD, full_name=None):
        resp = self.client.post("/api/auth/invitations/accept/complete", json={
            "token": token, "username": username, "full_name": full_name, "new_password": password, "code": code})
        self.client.cookies.clear()
        return resp

    def find(self, username):
        return self.users_module.find_user(self.users_module.load_users(), username)

    def audited(self, resource_id, action):
        storage = sys.modules["auth.access"]._storage
        return [row for row in storage.audit_records(resource_id=resource_id) if row["action"] == action]

    def disable(self, username):
        accounts = self.users_module.load_users()
        self.users_module.find_user(accounts, username)["is_active"] = False
        self.users_module.save_users(accounts)

    def limit(self, seats):
        """A licence with `seats` places, over whatever the shared store holds."""
        self.seats.stop()
        patch = mock.patch.object(sys.modules["licence"], "current",
                                  return_value=mock.Mock(seats=seats, edition=mock.Mock(value="pro")))
        patch.start()
        self.addCleanup(patch.stop)

    # ── inviting ─────────────────────────────────────────────────────────────

    def test_an_invitation_makes_the_account_only_once_a_code_is_confirmed(self):
        email = self.email()
        invitation, token = self.issue(email, "admin", full_name="Ada Lovelace")
        stored = self.invitations.load()[invitation["id"]]
        self.assertNotIn(token, str(stored))  # only its hash
        self.assertAlmostEqual(stored["expires"] - self.now, self.reset.RESET_HOURS * 3600, delta=5)
        preview = self.preview(token).json()
        self.assertEqual((preview["email"], preview["role"], preview["full_name"]), (email, "admin", "Ada Lovelace"))
        username = preview["username"]
        self.assertEqual(username, email.split("@")[0])
        started = self.start(token, username)
        self.assertEqual(started.status_code, 200, started.text)
        secret = started.json()["secret"]
        self.assertTrue(started.json()["otpauth_uri"].startswith(f"otpauth://totp/Rowanholt%3A{username}"))
        self.assertNotIn(secret, str(self.invitations.load()))  # kept encrypted
        # Nothing made yet, and a wrong code makes nothing
        self.assertIsNone(self.find(username))
        self.assertEqual(self.complete(token, username, "000000").status_code, 400)
        self.assertIsNone(self.find(username))
        done = self.complete(token, username, self.code(secret))
        self.assertEqual(done.status_code, 200, done.text)
        body = done.json()
        self.addCleanup(self.disable, username)  # other classes share the store and count its admins
        self.assertEqual(len(body["backup_codes"]), 10)
        self.assertEqual((body["user"]["role"], body["user"]["mfa_enabled"]), ("admin", True))
        self.assertEqual(body["user"]["full_name"], "Ada Lovelace")
        me = self.client.get("/api/auth/me", headers=bearer(body["access_token"]))
        self.assertEqual(me.json()["username"], username)
        self.assertNotIn(invitation["id"], self.invitations.load())
        # Signing in again takes the password and the new authenticator
        self.client.cookies.clear()
        first = self.client.post("/api/auth/login", data={"username": username, "password": PASSWORD}).json()
        self.assertTrue(first["mfa_required"])
        self.assertEqual(len(self.audited(invitation["id"], "invitation_created")), 1)
        [created] = self.audited(body["user"]["id"], "account_created")
        self.assertEqual((created["details"]["role"], created["details"]["invited_by"]), ("admin", "admin"))

    def test_mfa_goes_on_even_when_the_server_does_not_require_it(self):
        self.assertFalse(self.settings.rowanholt_require_mfa)
        email = self.email()
        _, token = self.issue(email)
        username = email.split("@")[0]
        done = self.complete(token, username, self.code(self.start(token, username).json()["secret"]))
        self.assertEqual(done.status_code, 200, done.text)
        self.assertEqual(done.json()["user"]["role"], "user")
        self.assertTrue(self.mfa.is_enabled(self.find(username)))

    def test_the_username_is_chosen_and_must_be_free_and_well_formed(self):
        email = self.email()
        _, token = self.issue(email)
        self.assertEqual(self.start(token, "alice").status_code, 400)  # taken
        self.assertEqual(self.start(token, "a b").status_code, 400)
        secret = self.start(token, "chosen-name-x").json()["secret"]
        # Taken between start and complete: refused, and the invitation still stands
        self.make_user("chosen-name-x", "someone-elses-pass")
        self.assertEqual(self.complete(token, "chosen-name-x", self.code(secret)).status_code, 400)
        self.assertEqual(self.preview(token).status_code, 200)

    def test_a_username_cant_be_an_email_another_account_or_invitation_is_for(self):
        # Sign-in finds an account by username or email: two accounts mustn't answer to one name
        pending = self.email()
        self.issue(pending)
        _, token = self.issue(self.email())
        for taken in (pending, pending.upper(), "alice@example.org", "ALICE"):
            self.assertEqual(self.start(token, taken).status_code, 400, taken)

    def test_an_email_someone_took_as_a_username_cant_be_accepted(self):
        email = self.email()
        _, token = self.issue(email)
        username = email.split("@")[0]
        secret = self.start(token, username).json()["secret"]
        accounts = self.users_module.load_users()
        self.users_module.find_user(accounts, "bob")["username"] = email  # an account made before the fix
        self.users_module.save_users(accounts)
        self.addCleanup(self._rename, email, "bob")
        refused = self.complete(token, username, self.code(secret))
        self.assertEqual(refused.status_code, 409, refused.text)
        self.assertIsNone(self.find(username))

    def _rename(self, old, new):
        accounts = self.users_module.load_users()
        self.users_module.find_user(accounts, old)["username"] = new
        self.users_module.save_users(accounts)

    def test_a_suggested_username_avoids_one_taken(self):
        _, token = self.issue("alice@elsewhere.example")
        self.assertEqual(self.preview(token).json()["username"], "alice2")

    def test_an_invitation_works_once(self):
        email = self.email()
        _, token = self.issue(email)
        username = email.split("@")[0]
        secret = self.start(token, username).json()["secret"]
        self.assertEqual(self.complete(token, username, self.code(secret)).status_code, 200)
        self.assertEqual(self.preview(token).status_code, 400)
        self.assertEqual(self.complete(token, username + "2", self.code(secret)).status_code, 400)

    def test_an_invitation_expires_after_24_hours(self):
        email = self.email()
        _, token = self.issue(email)
        username = email.split("@")[0]
        secret = self.start(token, username).json()["secret"]
        self.now += self.reset.RESET_HOURS * 3600 + 1
        self.assertEqual(self.preview(token).status_code, 410)
        self.assertEqual(self.complete(token, username, self.code(secret)).status_code, 410)
        self.assertIsNone(self.find(username))
        # Another invitation written meanwhile doesn't turn "expired" into "never valid"
        self.issue(self.email())
        self.assertEqual(self.preview(token).status_code, 410)
        # A day later it's dropped
        self.now += self.invitations.KEEP_EXPIRED_SECONDS
        self.issue(self.email())
        self.assertEqual(self.preview(token).status_code, 400)

    def test_a_newer_invitation_replaces_an_older_one(self):
        email = self.email()
        first, old = self.issue(email)
        second, new = self.issue(email, "admin")
        self.assertEqual(self.preview(old).status_code, 400)
        self.assertEqual(self.preview(new).json()["role"], "admin")
        ids = [inv["id"] for inv in self.client.get("/api/auth/users/invitations", headers=self.admin).json()]
        self.assertIn(second["id"], ids)
        self.assertNotIn(first["id"], ids)

    def test_refusals(self):
        refused = self.invite("alice@example.org")
        self.assertEqual(refused.status_code, 409)
        self.assertIn("reset-access", refused.json()["detail"])
        self.assertEqual(self.invite("not-an-email").status_code, 400)
        self.assertEqual(self.invite(self.email(), "superuser").status_code, 400)
        self.assertEqual(self.start("not-a-token", "someone").status_code, 400)
        self.assertEqual(self.preview("").status_code, 400)
        _, token = self.issue(self.email())
        self.assertEqual(self.complete(token, "x" * 5, "123456").status_code, 400)  # no authenticator yet
        self.assertEqual(self.complete(token, "x" * 5, "123456", password="short").status_code, 400)

    def test_wrong_codes_count_towards_the_lockout(self):
        email = self.email()
        _, token = self.issue(email)
        username = email.split("@")[0]
        secret = self.start(token, username).json()["secret"]
        invitation_id = next(inv["id"] for inv in self.invitations.load().values() if inv["email"] == email)
        for _ in range(self.settings.max_login_attempts):
            self.assertEqual(self.complete(token, username, "000000").status_code, 400)
        self.assertEqual(self.complete(token, username, self.code(secret)).status_code, 429)
        failed = self.audited(invitation_id, "mfa_failed")
        self.assertEqual(len(failed), self.settings.max_login_attempts)
        self.assertEqual(failed[0]["details"]["stage"], "invitation")

    def test_only_admins_invite_list_and_revoke_and_never_with_a_token(self):
        for who in (self.alice, self.bob):
            self.assertEqual(self.invite(self.email(), headers=who).status_code, 403)
            self.assertEqual(self.client.get("/api/auth/users/invitations", headers=who).status_code, 403)
        made = self.client.post("/api/auth/tokens", headers=self.admin, json={"name": "a", "scope": "full", "days": 1})
        self.assertEqual(self.invite(self.email(), headers=bearer(made.json()["token"])).status_code, 403)

    def test_admins_list_and_withdraw_invitations(self):
        email = self.email()
        invitation, token = self.issue(email)
        listed = self.client.get("/api/auth/users/invitations", headers=self.admin).json()
        mine = next(inv for inv in listed if inv["id"] == invitation["id"])
        self.assertEqual((mine["email"], mine["invited_by"]), (email, "admin"))
        self.assertNotIn("token_hash", mine)
        withdrawn = self.client.delete(f"/api/auth/users/invitations/{invitation['id']}", headers=self.admin)
        self.assertEqual(withdrawn.status_code, 200, withdrawn.text)
        self.assertEqual(self.preview(token).status_code, 400)
        self.assertEqual(self.client.delete(f"/api/auth/users/invitations/{invitation['id']}",
                                            headers=self.admin).status_code, 404)
        self.assertEqual(len(self.audited(invitation["id"], "invitation_revoked")), 1)

    # ── places ───────────────────────────────────────────────────────────────

    def test_places_are_checked_when_inviting_and_again_when_accepting(self):
        held = sys.modules["licence"].places_held(self.users_module.load_users())
        self.limit(held + 1)
        email = self.email()
        _, token = self.issue(email)
        # The pending invitation holds the last place
        self.assertEqual(self.invite(self.email()).status_code, 402)
        username = email.split("@")[0]
        secret = self.start(token, username).json()["secret"]
        # Someone else took it meanwhile (a first single sign-on, say): the acceptance is refused
        self.make_user(f"late{next(_names)}", "late-comer-password")
        refused = self.complete(token, username, self.code(secret))
        self.assertEqual(refused.status_code, 402)
        self.assertIsNone(self.find(username))

    def test_replacing_an_invitation_does_not_need_another_place(self):
        held = sys.modules["licence"].places_held(self.users_module.load_users())
        self.limit(held + 1)
        email = self.email()
        self.issue(email)
        self.issue(email, "admin")

    # ── no admin-set passwords on a server ───────────────────────────────────

    def test_a_server_refuses_accounts_made_with_a_password(self):
        for path in ("/api/auth/users", "/api/auth/register"):
            refused = self.client.post(path, headers=self.admin, json={
                "username": "pwmade", "email": "pwmade@example.org", "password": "chosen-by-admin-1"})
            self.assertEqual(refused.status_code, 400, path)
            self.assertIn("invitation", refused.json()["detail"])
        self.assertIsNone(self.find("pwmade"))
        from auth import manage_users
        with self.assertRaisesRegex(SystemExit, "invite <email>$"):
            manage_users.main(["add", "pwmade", "pwmade@example.org"])

    def test_a_server_refuses_an_admin_setting_someones_password(self):
        alice = self.find("alice")
        before = alice["hashed_password"]
        refused = self.client.patch(f"/api/auth/users/{alice['id']}", headers=self.admin,
                                    json={"password": "chosen-by-admin-2", "full_name": "Alice"})
        self.assertEqual(refused.status_code, 400, refused.text)
        self.assertIn("reset-access", refused.json()["detail"])
        self.assertEqual(self.find("alice")["hashed_password"], before)
        self.assertNotEqual(self.find("alice").get("full_name"), "Alice")  # nothing else changed either
        from auth import manage_users
        with self.assertRaisesRegex(SystemExit, "reset-access <user>$"):
            manage_users.main(["password", "alice"])
        self.assertEqual(self.find("alice")["hashed_password"], before)

    def test_a_local_stack_keeps_its_own_sign_up_and_has_no_invitations(self):
        self.settings.rowanholt_server_mode = False
        try:
            made = self.client.post("/api/auth/register", json={
                "username": f"local{next(_names)}", "email": f"local{next(_names)}@example.org",
                "password": "a-local-password"})
            self.assertEqual(made.status_code, 200, made.text)
            self.assertEqual(self.invite(self.email()).status_code, 400)
            from auth import manage_users
            with mock.patch("getpass.getpass", return_value="a-local-password-2"):
                self.assertEqual(manage_users.main(["add", f"local{next(_names)}", "l@example.org"]), 0)
        finally:
            self.settings.rowanholt_server_mode = True

    # ── the server's CLI ─────────────────────────────────────────────────────

    def test_the_server_cli_invites_lists_and_withdraws(self):
        from auth import manage_users
        email = self.email()
        storage = sys.modules["auth.access"]._storage
        with mock.patch.object(manage_users, "_audit_storage", lambda: storage), \
                mock.patch("builtins.print") as printed:
            self.assertEqual(manage_users.main(["invite", email, "--role", "admin", "--name", "Grace"]), 0)
            output = " ".join(str(arg) for call in printed.call_args_list for arg in call.args)
            token = output.split("https://rowanholt.test/accept-invite#", 1)[1].split()[0]
            preview = self.preview(token).json()
            self.assertEqual((preview["role"], preview["full_name"]), ("admin", "Grace"))
            [invitation] = [inv for inv in self.invitations.pending() if inv["email"] == email]
            [row] = self.audited(invitation["id"], "invitation_created")
            self.assertEqual((row["username"], row["details"]["via"]), ("server-cli", "cli"))
            printed.reset_mock()
            self.assertEqual(manage_users.main(["invitations"]), 0)
            listing = " ".join(str(arg) for call in printed.call_args_list for arg in call.args)
            self.assertIn(email, listing)
            self.assertEqual(manage_users.main(["revoke-invitation", invitation["id"]]), 0)
            with self.assertRaises(SystemExit):
                manage_users.main(["revoke-invitation", invitation["id"]])
            with self.assertRaisesRegex(SystemExit, "already has an account"):
                manage_users.main(["invite", "alice@example.org"])
        self.assertEqual(self.preview(token).status_code, 400)


if __name__ == "__main__":
    unittest.main()
