"""Forgot password (POST /api/auth/forgot-password, auth/reset_access.issue_self_service, mailer.py): with
email and ROWANHOLT_PUBLIC_URL set up, an active password account matching the address (or username)
is emailed a reset-access link, the same link and page as an admin's, always at the public URL (never
the request's forgeable Origin or Host); the answer is the same whether or not one matched; it's
rate-limited per address and per client address; the account's sessions and tokens stand until the
reset is completed, and its old password keeps working until then; it never replaces an admin's open
link, but replaces an earlier self-service one; a local stack has it too. Without email it says to ask
an administrator. The SMTP sender uses STARTTLS (or TLS on 465) and signs in when given a username.

Run: python3 -m pytest tests/unit/test_forgot_password.py
"""

import sys
import time
import unittest
from itertools import count
from unittest import mock

from test_server_access import BackendCase, TestClient

PASSWORD = "forgot-test-password-1"
NEW_PASSWORD = "forgot-new-password-2"
_names = count()


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class ForgotPasswordTest(BackendCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.mfa = sys.modules["auth.mfa"]
        cls.users_module = sys.modules["auth.users"]
        cls.reset = sys.modules["auth.reset_access"]
        cls.routes = sys.modules["auth.routes_simple"]
        cls.mailer = sys.modules["mailer"]
        cls.throttle = sys.modules["auth.throttle"].throttle

    def setUp(self):
        self.now = time.time()
        for patch in (mock.patch.object(self.mfa, "_now", lambda: self.now),
                      mock.patch.object(self.routes.licence, "seat_refusal", return_value=None),
                      mock.patch.object(self.settings, "rowanholt_smtp_host", "smtp.example.org"),
                      mock.patch.object(self.settings, "rowanholt_smtp_from", "rowanholt@example.org")):
            patch.start()
            self.addCleanup(patch.stop)
        self.sent = []
        sender = mock.patch.object(self.mailer, "send", lambda to, subject, body: self.sent.append((to, body)))
        sender.start()
        self.addCleanup(sender.stop)
        self.setUp_rate_limit()

    def setUp_rate_limit(self):
        """Every request here comes from the test client's one address: its rate limit starts afresh."""
        for key in [k for k in self.throttle._memory if k.startswith("rate:")]:
            del self.throttle._memory[key]

    # ── helpers ──────────────────────────────────────────────────────────────

    def new_user(self):
        name = f"forgot{next(_names)}x{int(self.now) % 100000}"
        user = self.make_user(name, PASSWORD)
        return name, user["id"], self.login(name, PASSWORD)

    def forgot(self, email, headers=None):
        self.client.cookies.clear()
        return self.client.post("/api/auth/forgot-password", json={"email": email}, headers=headers or {})

    def token(self):
        _, body = self.sent[-1]
        return body.split("/reset-access#", 1)[1].split()[0]

    def code(self, secret):
        self.now += self.mfa.STEP_SECONDS
        return self.mfa.code_at(secret, self.mfa.current_step())

    def complete(self, token):
        self.client.cookies.clear()
        secret = self.client.post("/api/auth/reset-access/start", json={"token": token}).json()["secret"]
        done = self.client.post("/api/auth/reset-access/complete",
                                json={"token": token, "new_password": NEW_PASSWORD, "code": self.code(secret)})
        self.client.cookies.clear()
        return done

    def record(self, user_id):
        return self.users_module.load_users()[user_id]

    def audited(self, user_id, action):
        storage = sys.modules["auth.access"]._storage
        return [row for row in storage.audit_records(resource_id=user_id) if row["action"] == action]

    def sign_in(self, name, password):
        self.client.cookies.clear()
        resp = self.client.post("/api/auth/login", data={"username": name, "password": password})
        self.client.cookies.clear()
        return resp

    # ── tests ────────────────────────────────────────────────────────────────

    def test_without_email_it_says_to_ask_an_administrator(self):
        with mock.patch.object(self.settings, "rowanholt_smtp_host", ""):
            self.assertFalse(self.client.get("/api/auth/config").json()["forgot_password"])
            resp = self.forgot("alice@example.org")
        self.assertEqual(resp.status_code, 503)
        self.assertIn("administrator", resp.json()["detail"])
        self.assertEqual(self.sent, [])
        self.assertTrue(self.client.get("/api/auth/config").json()["forgot_password"])

    def test_a_matching_account_is_emailed_a_link_and_the_answer_is_the_same_either_way(self):
        name, user_id, _ = self.new_user()
        known = self.forgot(f"{name}@example.org")
        unknown = self.forgot("nobody-here@example.org")
        self.assertEqual((known.status_code, known.json()), (unknown.status_code, unknown.json()))
        self.assertEqual(known.json()["message"], self.routes.LINK_ON_ITS_WAY)
        [(to, body)] = self.sent
        self.assertEqual(to, f"{name}@example.org")
        self.assertIn("https://rowanholt.test/reset-access#", body)
        stored = self.record(user_id)
        self.assertEqual(stored["access_reset_hash"], self.reset.token_hash(self.token()))
        self.assertEqual(stored["access_reset_via"], "self-service")
        [row] = self.audited(user_id, "access_reset_issued")
        self.assertEqual(row["details"]["via"], "self-service")
        # By username, too
        self.forgot(name)
        self.assertEqual(len(self.sent), 2)

    def test_asking_ends_nothing_and_completing_ends_everything(self):
        name, user_id, headers = self.new_user()
        made = self.client.post("/api/auth/tokens", headers=headers, json={"name": "s", "scope": "full", "days": 1})
        api_token = bearer(made.json()["token"])
        self.forgot(name)
        # Anyone could have asked: the session, the token and the old password all stand
        self.assertEqual(self.client.get("/api/auth/me", headers=headers).status_code, 200)
        self.assertEqual(self.client.get("/api/auth/me", headers=api_token).status_code, 200)
        self.assertEqual(self.sign_in(name, PASSWORD).status_code, 200)
        done = self.complete(self.token())
        self.assertEqual(done.status_code, 200, done.text)
        self.assertEqual(self.client.get("/api/auth/me", headers=headers).status_code, 401)
        self.assertEqual(self.client.get("/api/auth/me", headers=api_token).status_code, 401)
        self.assertTrue(self.mfa.is_enabled(self.record(user_id)))
        [row] = self.audited(user_id, "access_reset_completed")
        self.assertEqual((row["details"]["via"], row["details"]["tokens_revoked"]), ("self-service", 1))

    def test_an_admins_open_link_is_never_replaced_but_an_earlier_request_is(self):
        name, user_id, _ = self.new_user()
        self.forgot(name)
        first = self.token()
        self.forgot(name)
        second = self.token()
        self.assertNotEqual(first, second)
        self.assertEqual(self.record(user_id)["access_reset_hash"], self.reset.token_hash(second))
        admin_link = self.client.post(f"/api/auth/users/{user_id}/reset-access", headers=self.admin).json()["link"]
        sent = len(self.sent)
        self.assertEqual(self.forgot(name).json()["message"], self.routes.LINK_ON_ITS_WAY)
        self.assertEqual(len(self.sent), sent)  # nothing sent
        self.assertEqual(self.record(user_id)["access_reset_hash"], self.reset.token_hash(admin_link.split("#")[1]))
        # Once the admin's has expired, asking works again (an hour on, past the rate limit too)
        self.now += self.reset.RESET_HOURS * 3600 + 1
        self.setUp_rate_limit()
        self.forgot(name)
        self.assertEqual(len(self.sent), sent + 1)

    def test_disabled_and_single_sign_on_accounts_get_nothing(self):
        name, user_id, _ = self.new_user()
        self.client.patch(f"/api/auth/users/{user_id}", headers=self.admin, json={"is_active": False})
        self.assertEqual(self.forgot(name).status_code, 200)
        users = self.users_module.load_users()
        sso = self.users_module.new_user(f"ssof{next(_names)}", f"ssof{next(_names)}@example.org",
                                         oidc_subject="https://idp|f")
        users[sso["id"]] = sso
        self.users_module.save_users(users)
        self.assertEqual(self.forgot(sso["email"]).status_code, 200)
        self.assertEqual(self.sent, [])

    def test_rate_limited_per_address_and_per_client_address(self):
        name, _, _ = self.new_user()
        for _ in range(self.routes.FORGOT_PER_ADDRESS):
            self.assertEqual(self.forgot(name).status_code, 200)
        self.assertEqual(self.forgot(name).status_code, 429)
        self.assertEqual(len(self.sent), self.routes.FORGOT_PER_ADDRESS)
        for n in range(self.routes.FORGOT_PER_IP - self.routes.FORGOT_PER_ADDRESS - 1):
            self.assertEqual(self.forgot(f"other{n}@example.org").status_code, 200)
        self.assertEqual(self.forgot("one-more@example.org").status_code, 429)

    def test_a_forged_origin_or_host_never_reaches_the_email(self):
        # Host-header injection: the asker chooses these, and the victim would get a real token pointing at them
        name, _, _ = self.new_user()
        forged = {"Origin": "https://evil.example", "Host": "evil.example",
                  "X-Forwarded-Host": "evil.example", "X-Forwarded-Proto": "https"}
        self.assertEqual(self.forgot(name, headers=forged).status_code, 200)
        [(_, body)] = self.sent
        self.assertNotIn("evil.example", body)
        self.assertIn("https://rowanholt.test/reset-access#", body)

    def test_without_a_public_url_it_is_not_offered(self):
        name, user_id, _ = self.new_user()
        with mock.patch.object(self.settings, "rowanholt_public_url", ""):
            self.assertFalse(self.client.get("/api/auth/config").json()["forgot_password"])
            refused = self.forgot(name, headers={"Origin": "http://localhost:5687"})
        self.assertEqual(refused.status_code, 503)
        self.assertIn("administrator", refused.json()["detail"])
        self.assertEqual(self.sent, [])
        self.assertNotIn("access_reset_hash", self.record(user_id))

    def test_a_local_stack_has_it_too_with_a_public_url(self):
        name, _, _ = self.new_user()
        self.settings.rowanholt_server_mode = False
        try:
            self.assertEqual(self.forgot(name, headers={"Origin": "https://evil.example"}).status_code, 200)
            self.assertIn("https://rowanholt.test/reset-access#", self.sent[-1][1])
            self.assertEqual(self.complete(self.token()).status_code, 200)
        finally:
            self.settings.rowanholt_server_mode = True


class SmtpSenderTest(unittest.TestCase):
    def setUp(self):
        try:
            import mailer
        except ImportError:
            self.skipTest("backend modules not importable")
        self.mailer = mailer
        settings = mailer.settings
        for name, value in (("rowanholt_smtp_host", "smtp.example.org"), ("rowanholt_smtp_from", "rh@example.org"),
                            ("rowanholt_smtp_username", "rh"), ("rowanholt_smtp_password", "pw"),
                            ("rowanholt_smtp_port", 587), ("rowanholt_smtp_starttls", True)):
            patch = mock.patch.object(settings, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        self.settings = settings

    def test_starttls_then_sign_in_then_send(self):
        with mock.patch.object(self.mailer.smtplib, "SMTP") as smtp:
            self.mailer.send("a@example.org", "Subject", "Body")
        smtp.assert_called_once_with("smtp.example.org", 587, timeout=self.mailer.TIMEOUT)
        session = smtp.return_value
        session.starttls.assert_called_once()
        session.login.assert_called_once_with("rh", "pw")
        message = session.send_message.call_args.args[0]
        self.assertEqual((message["To"], message["From"], message["Subject"]), ("a@example.org", "rh@example.org", "Subject"))

    def test_port_465_is_tls_from_the_start_and_no_username_no_sign_in(self):
        with mock.patch.object(self.settings, "rowanholt_smtp_port", 465), \
                mock.patch.object(self.settings, "rowanholt_smtp_username", ""), \
                mock.patch.object(self.mailer.smtplib, "SMTP_SSL") as smtp_ssl:
            self.mailer.send("a@example.org", "S", "B")
        session = smtp_ssl.return_value
        session.starttls.assert_not_called()
        session.login.assert_not_called()
        session.send_message.assert_called_once()

    def test_a_failed_send_is_logged_not_raised(self):
        with mock.patch.object(self.mailer.smtplib, "SMTP", side_effect=OSError("refused")), \
                self.assertLogs(self.mailer.logger, "ERROR"):
            self.mailer.send_reset_link("a@example.org", "alice", "https://x/reset-access#t", 24)

    def test_configured_needs_a_host_and_a_sender(self):
        self.assertTrue(self.mailer.configured())
        with mock.patch.object(self.settings, "rowanholt_smtp_from", ""):
            self.assertFalse(self.mailer.configured())


if __name__ == "__main__":
    unittest.main()
