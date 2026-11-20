"""Unit tests for invitations (src/web/backend/auth/invitations.py, its routes in auth/routes_simple.py
and `server users invite|invitations|revoke-invitation`): how a team server's accounts are made. An
admin invites an email with a role; the link makes the account only once a code from a new
authenticator is confirmed, with the role, MFA on and ten backup codes, signed in, once, within 24
hours. Opening it again shows the same authenticator; five wrong codes close it; it's refused if the
admin who made it can no longer invite. Refused for an email with an account, past the licence's
places, and on a local stack; a newer invitation replaces an older one; admins list and withdraw
them; nobody sets another person's password, on a server or locally; a local stack keeps its own
sign-up only while it's published on loopback.

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

    def issue(self, email, role="user", headers=None, **body):
        resp = self.invite(email, role, headers=headers, **body)
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
        self.assertEqual(self.preview(token).status_code, 404)
        self.assertEqual(self.complete(token, username + "2", self.code(secret)).status_code, 404)

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
        self.assertEqual(self.preview(token).status_code, 404)

    def test_a_newer_invitation_replaces_an_older_one(self):
        email = self.email()
        first, old = self.issue(email)
        second, new = self.issue(email, "admin")
        self.assertEqual(self.preview(old).status_code, 404)
        self.assertEqual(self.preview(new).json()["role"], "admin")
        ids = [inv["id"] for inv in self.client.get("/api/auth/users/invitations", headers=self.admin).json()]
        self.assertIn(second["id"], ids)
        self.assertNotIn(first["id"], ids)
        [revoked] = self.audited(first["id"], "invitation_revoked")
        self.assertEqual((revoked["details"]["reason"], revoked["details"]["replaced_by"]), ("replaced", second["id"]))

    def test_refusals(self):
        refused = self.invite("alice@example.org")
        self.assertEqual(refused.status_code, 409)
        self.assertIn("reset-access", refused.json()["detail"])
        self.assertEqual(self.invite("not-an-email").status_code, 400)
        self.assertEqual(self.invite(self.email(), "superuser").status_code, 400)
        self.assertEqual(self.start("not-a-token", "someone").status_code, 404)
        self.assertEqual(self.preview("").status_code, 404)
        _, token = self.issue(self.email())
        self.assertEqual(self.complete(token, "x" * 5, "123456").status_code, 400)  # no authenticator yet
        self.assertEqual(self.complete(token, "x" * 5, "123456", password="short").status_code, 400)

    def test_five_wrong_codes_close_the_invitation(self):
        email = self.email()
        _, token = self.issue(email)
        username = email.split("@")[0]
        secret = self.start(token, username).json()["secret"]
        invitation_id = next(inv["id"] for inv in self.invitations.load().values() if inv["email"] == email)
        for _ in range(self.invitations.MAX_WRONG_CODES - 1):
            wrong = self.complete(token, username, "000000")
            self.assertEqual(wrong.status_code, 400)
            self.assertIn("Incorrect code", wrong.json()["detail"])
        closed = self.complete(token, username, "000000")
        self.assertEqual(closed.status_code, 400)
        self.assertEqual(closed.json()["detail"], self.invitations.CLOSED)
        self.assertNotIn(invitation_id, self.invitations.load())  # its authenticator gone with it
        # The right code is too late: the admin issues a new invitation
        self.assertEqual(self.complete(token, username, self.code(secret)).status_code, 404)
        self.assertIsNone(self.find(username))
        failed = self.audited(invitation_id, "invitation_wrong_code")
        self.assertEqual([row["details"]["attempt"] for row in failed], [1, 2, 3, 4, 5])
        self.assertEqual(len(self.audited(invitation_id, "invitation_closed")), 1)
        # Not a sign-in lockout against the invited email: a new invitation works at once
        _, again = self.issue(email)
        done = self.complete(again, username, self.code(self.start(again, username).json()["secret"]))
        self.assertEqual(done.status_code, 200, done.text)

    def test_opening_it_again_shows_the_same_authenticator(self):
        email = self.email()
        _, token = self.issue(email)
        username = email.split("@")[0]
        first = self.start(token, username).json()["secret"]
        self.assertEqual(self.start(token, username).json()["secret"], first)
        self.assertEqual(self.start(token, username + "x").json()["secret"], first)  # another username, too
        self.assertEqual(self.complete(token, username, self.code(first)).status_code, 200)

    def test_an_expired_invitation_drops_its_authenticator(self):
        email = self.email()
        invitation, token = self.issue(email)
        self.start(token, email.split("@")[0])
        self.assertIn("pending_secret", self.invitations.load()[invitation["id"]])
        self.now += self.reset.RESET_HOURS * 3600 + 1
        self.assertEqual(self.preview(token).status_code, 410)
        self.assertNotIn("pending_secret", self.invitations.load()[invitation["id"]])

    def test_the_inviter_must_still_be_able_to_invite(self):
        # An admin who invites someone and is then disabled or made a user can't have the invitation honoured
        boss = f"boss{next(_names)}"
        self.make_user(boss, "boss-password-1234", role="admin")
        boss_headers = self.login(boss, "boss-password-1234")
        for change in ({"role": "user"}, {"is_active": False}):
            email = self.email()
            _, token = self.issue(email, headers=boss_headers)
            username = email.split("@")[0]
            secret = self.start(token, username).json()["secret"]
            self.assertEqual(self.client.patch(f"/api/auth/users/{self.find(boss)['id']}", headers=self.admin,
                                               json=change).status_code, 200)
            refused = self.complete(token, username, self.code(secret))
            self.assertEqual(refused.status_code, 403, change)
            self.assertEqual(refused.json()["detail"], self.invitations.INVITER_GONE)
            self.assertIsNone(self.find(username))
            self.client.patch(f"/api/auth/users/{self.find(boss)['id']}", headers=self.admin,
                              json={"role": "admin", "is_active": True})
            boss_headers = self.login(boss, "boss-password-1234")
        self.disable(boss)
        # The server's own (the CLI's) have no inviter to check
        invitation = {"id": "x", "email": "e@example.org", "invited_by": "server-cli"}
        self.assertIsNone(self.invitations.inviter_refusal(self.users_module.load_users(), invitation))

    def test_without_a_public_url_the_link_is_the_requests_own_address(self):
        with mock.patch.object(self.settings, "rowanholt_public_url", ""):
            resp = self.invite(self.email(), headers={**self.admin, "Origin": "https://rh.internal:8443"})
        self.assertTrue(resp.json()["link"].startswith("https://rh.internal:8443/accept-invite#"), resp.text)

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
        self.assertEqual(self.preview(token).status_code, 404)
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
        with self.assertRaises(SystemExit), mock.patch("sys.stderr"):  # no add command any more
            manage_users.main(["add", "pwmade", "pwmade@example.org"])

    def test_nobody_sets_someone_elses_password_on_a_server_or_locally(self):
        alice = self.find("alice")
        before = alice["hashed_password"]
        from auth import manage_users
        for server in (True, False):
            self.settings.rowanholt_server_mode = server
            try:
                refused = self.client.patch(f"/api/auth/users/{alice['id']}", headers=self.admin,
                                            json={"password": "chosen-by-admin-2", "full_name": "Alice"})
                self.assertEqual(refused.status_code, 400, refused.text)
                self.assertIn("reset-access", refused.json()["detail"])
                made = self.client.post("/api/auth/users", headers=self.admin, json={
                    "username": "pwmade2", "email": "pwmade2@example.org", "password": "chosen-by-admin-3"})
                self.assertEqual(made.status_code, 400, made.text)
                with self.assertRaises(SystemExit), mock.patch("sys.stderr"):  # no password command any more
                    manage_users.main(["password", "alice"])
            finally:
                self.settings.rowanholt_server_mode = True
        self.assertEqual(self.find("alice")["hashed_password"], before)
        self.assertNotEqual(self.find("alice").get("full_name"), "Alice")  # nothing else changed either
        self.assertIsNone(self.find("pwmade2"))

    def test_a_local_stack_keeps_its_own_sign_up_on_loopback_only_and_has_no_invitations(self):
        self.settings.rowanholt_server_mode = False
        try:
            username = f"local{next(_names)}"
            made = self.client.post("/api/auth/register", json={
                "username": username, "email": f"{username}@example.org", "password": "a-local-password"})
            self.assertEqual(made.status_code, 200, made.text)
            [created] = self.audited(made.json()["id"], "account_created")
            self.assertEqual(created["details"]["via"], "register")
            self.assertEqual(self.invite(self.email()).status_code, 400)
            config = self.client.get("/api/auth/config").json()
            self.assertTrue(config["register"] and config["guest"])
            self.assertEqual(self.client.post("/api/auth/guest").status_code, 200)
            self.client.cookies.clear()
            # Published beyond this machine: no sign-up and no guests, as no default admin
            with mock.patch.object(self.settings, "rowanholt_bind", "0.0.0.0"):
                config = self.client.get("/api/auth/config").json()
                self.assertFalse(config["register"] or config["guest"])
                refused = self.client.post("/api/auth/register", json={
                    "username": f"wide{next(_names)}", "email": "wide@example.org", "password": "a-local-password"})
                self.assertEqual(refused.status_code, 403)
                self.assertIn("ROWANHOLT_BIND", refused.json()["detail"])
                self.assertEqual(self.client.post("/api/auth/guest").status_code, 403)
        finally:
            self.settings.rowanholt_server_mode = True
            self.client.cookies.clear()

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
        self.assertEqual(self.preview(token).status_code, 404)


if __name__ == "__main__":
    unittest.main()
