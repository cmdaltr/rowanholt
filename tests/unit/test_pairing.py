"""Pairing with Ostraka (src/web/backend/pairing_routes.py, docs/suite/INTEGRATION.md): an admin's code,
claimed once within ten minutes without a sign-in, making an ostraka-scope token and Ostraka's webhook;
what that token may and mayn't do; and external_ref on a job. Through the real backend
(test_server_access.BackendCase), with nothing sent anywhere.

Run: python3 -m unittest tests/unit/test_pairing.py
"""

import hashlib
import json
import os
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta
from unittest import mock

import test_server_access  # noqa: F401  (sets the backend's environment before anything imports it)
from test_server_access import BackendCase, TestClient

WEBHOOK_URL = "https://ostraka.example.org/api/integrations/rowanholt/webhook"
INVALID = "This pairing link isn't valid. Ask for a new one."
EXPIRED = "This pairing link has expired. Ask for a new one."


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class PairingTest(BackendCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import webhooks
        cls.webhooks = webhooks
        cls.storage = sys.modules["auth.access"]._storage

    def setUp(self):
        folder = tempfile.mkdtemp()
        patch = mock.patch.dict(os.environ, {"ROWANHOLT_WEBHOOKS": f"{folder}/webhooks.json"})
        patch.start()
        self.addCleanup(patch.stop)

    def make(self, headers=None, note="Ostraka on the homelab"):
        resp = self.client.post("/api/pairing", headers=headers or self.admin, json={"note": note})
        self.assertEqual(resp.status_code, 201, resp.text)
        return resp.json()

    def claim(self, link_or_code, url=WEBHOOK_URL, **extra):
        code = link_or_code.split("#", 1)[-1]
        self.client.cookies.clear()
        return self.client.post("/api/pairing/claim", json={
            "code": code, "product": "ostraka", "name": "Ostraka", "version": "0.3.0", "webhook_url": url, **extra})

    def audits(self, pairing_id=None):
        return [r for r in self.storage.audit_records(resource_id=pairing_id, action_prefix="pairing")]

    def set_user(self, username, **fields):
        from auth import users as store
        with store.locked():
            accounts = store.load_users()
            record = store.find_user(accounts, username)
            before = {k: record.get(k) for k in fields}
            record.update(fields)
            store.save_users(accounts)
        return before

    def remove_user(self, username):
        from auth import users as store
        with store.locked():
            accounts = store.load_users()
            record = store.find_user(accounts, username)
            if record:
                del accounts[record["id"]]
                store.save_users(accounts)

    # ---- making codes ----

    def test_a_link_is_the_public_url_then_the_code_after_a_hash(self):
        made = self.make()
        link = made["link"]
        self.assertTrue(link.startswith("https://rowanholt.test/pair#pair_"), link)
        code = link.split("#", 1)[1]
        self.assertEqual(len(code), len("pair_") + 43)
        expires = datetime.fromisoformat(made["expires_at"])
        self.assertLess(abs((expires - datetime.now()) - timedelta(minutes=10)), timedelta(seconds=30))
        listed = next(c for c in self.client.get("/api/pairing", headers=self.admin).json() if c["id"] == made["id"])
        self.assertEqual(set(listed), {"id", "note", "created_by", "created_at", "expires_at", "claimed_at",
                                       "claimed_by_name"})
        self.assertEqual((listed["note"], listed["created_by"], listed["claimed_at"]),
                         ("Ostraka on the homelab", "admin", None))
        # Only the hash is stored
        from sqlalchemy import text
        with self.storage.engine.connect() as connection:
            [stored] = connection.execute(text("SELECT code_hash FROM pairing_codes WHERE id = :id"),
                                          {"id": made["id"]}).all()
        self.assertNotIn(code, stored[0])
        self.assertEqual(len(stored[0]), 64)

    def test_without_a_public_url_the_link_is_the_requests_origin(self):
        with mock.patch.object(self.settings, "rowanholt_public_url", ""):
            resp = self.client.post("/api/pairing", headers={**self.admin, "Origin": "https://rh.tail.ts.net"},
                                    json={})
        self.assertEqual(resp.status_code, 201, resp.text)
        self.assertTrue(resp.json()["link"].startswith("https://rh.tail.ts.net/pair#pair_"))

    def test_codes_are_for_admins_only_and_any_number_may_be_open(self):
        for method, path in (("POST", "/api/pairing"), ("GET", "/api/pairing"), ("DELETE", "/api/pairing/x")):
            self.assertEqual(self.client.request(method, path, headers=self.alice, json={}).status_code, 403, path)
        self.assertEqual(self.client.get("/api/pairing").status_code, 401)
        first, second = self.make(), self.make()
        ids = {c["id"] for c in self.client.get("/api/pairing", headers=self.admin).json()}
        self.assertTrue({first["id"], second["id"]} <= ids)
        [row] = self.audits(first["id"])
        self.assertEqual((row["action"], row["username"]), ("pairing_code_created", "admin"))

    def test_a_local_stack_has_no_pairing(self):
        with mock.patch.object(self.settings, "rowanholt_server_mode", False):
            resp = self.client.post("/api/pairing", json={})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("team server", resp.json()["detail"])

    def test_opening_the_link_is_the_web_apps_page(self):
        # /pair isn't an API route: the web app's catch-all serves index.html (nginx's try_files does the same)
        from pathlib import Path
        build = Path(tempfile.mkdtemp())
        (build / "index.html").write_text("<!doctype html>")
        self.assertEqual(self.main.spa_file(build, "pair"), build.resolve() / "index.html")

    # ---- claiming ----

    def test_a_claim_makes_the_token_and_the_webhook_and_says_so_once(self):
        made = self.make()
        resp = self.claim(made["link"])
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertEqual(set(body), {"product", "version", "token", "token_expires_at", "webhook_id",
                                     "webhook_secret", "events"})
        self.assertEqual((body["product"], body["version"]), ("rowanholt", self.settings.app_version))
        self.assertEqual(body["events"], ["job.completed", "job.failed", "finding.confirmed"])
        self.assertTrue(body["token"].startswith("rvt_"))

        # The token: ostraka scope, the admin's, a year, named for the pairing
        record = self.storage.token_by_hash(hashlib.sha256(body["token"].encode()).hexdigest())
        admin_id = self.client.get("/api/auth/me", headers=self.admin).json()["id"]
        self.assertEqual((record["scope"], record["user_id"], record["name"]),
                         ("ostraka", admin_id, "Ostraka (paired)"))
        self.assertLess(abs((record["expires_at"] - datetime.now()) - timedelta(days=365)), timedelta(minutes=1))
        self.assertEqual(datetime.fromisoformat(body["token_expires_at"]), record["expires_at"])
        me = self.client.get("/api/auth/me", headers=bearer(body["token"]))
        self.assertEqual((me.status_code, me.json()["username"]), (200, "admin"))

        # The webhook: Ostraka's URL, the three events, the secret in the answer, described for the pairing
        [hook] = [h for h in self.webhooks.hooks() if h["id"] == body["webhook_id"]]
        self.assertEqual((hook["url"], sorted(hook["events"]), hook["description"], hook["secret"], hook["enabled"]),
                         (WEBHOOK_URL, sorted(body["events"]), "Ostraka (paired)", body["webhook_secret"], True))
        self.assertGreaterEqual(len(hook["secret"]), 32)

        listed = next(c for c in self.client.get("/api/pairing", headers=self.admin).json() if c["id"] == made["id"])
        self.assertIsNotNone(listed["claimed_at"])
        self.assertEqual(listed["claimed_by_name"], "Ostraka")
        [created, claimed] = self.audits(made["id"])
        self.assertEqual(claimed["action"], "pairing_claimed")
        self.assertEqual(claimed["details"]["created_by"], "admin")
        self.assertEqual(claimed["details"]["token_prefix"], body["token"][:10])
        self.assertEqual(claimed["details"]["webhook_id"], body["webhook_id"])
        self.assertEqual(claimed["ip_address"], "testclient")

    def test_a_second_claim_is_refused(self):
        made = self.make()
        self.assertEqual(self.claim(made["link"]).status_code, 200)
        again = self.claim(made["link"])
        self.assertEqual((again.status_code, again.json()["detail"]), (404, INVALID))
        self.assertEqual(len(self.webhooks.hooks()), 1)
        self.assertEqual(self.audits(made["id"])[-1]["action"], "pairing_claim_refused")

    def test_of_claims_at_once_only_one_wins(self):
        made = self.make()
        code = made["link"].split("#", 1)[1]
        import pairing_routes
        hashed = pairing_routes.code_hash(code)
        barrier = threading.Barrier(8)
        won = []

        def race(n):
            barrier.wait()
            claimed = self.storage.claim_pairing(hashed, datetime.now(), f"Ostraka {n}")
            if claimed:
                won.append(claimed)

        threads = [threading.Thread(target=race, args=(n,)) for n in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(won), 1)
        self.assertEqual(self.claim(code).status_code, 404)

    def test_an_expired_code_says_so(self):
        made = self.make()
        from sqlalchemy import DateTime, bindparam, text
        update = text("UPDATE pairing_codes SET expires_at = :t WHERE id = :id").bindparams(
            bindparam("t", type_=DateTime))
        with self.storage.engine.begin() as connection:
            connection.execute(update, {"t": datetime.now() - timedelta(seconds=1), "id": made["id"]})
        resp = self.claim(made["link"])
        self.assertEqual((resp.status_code, resp.json()["detail"]), (410, EXPIRED))
        self.assertEqual(self.webhooks.hooks(), [])
        self.assertEqual(self.audits(made["id"])[-1]["details"]["reason"], "expired")

    def test_a_withdrawn_code_is_not_valid_and_a_claimed_one_cant_be_withdrawn(self):
        made = self.make()
        self.assertEqual(self.client.delete(f"/api/pairing/{made['id']}", headers=self.admin).status_code, 204)
        self.assertNotIn(made["id"], {c["id"] for c in self.client.get("/api/pairing", headers=self.admin).json()})
        resp = self.claim(made["link"])
        self.assertEqual((resp.status_code, resp.json()["detail"]), (404, INVALID))
        self.assertEqual(self.client.delete(f"/api/pairing/{made['id']}", headers=self.admin).status_code, 404)
        self.assertIn("pairing_code_withdrawn", [r["action"] for r in self.audits(made["id"])])

        claimed = self.make()
        self.assertEqual(self.claim(claimed["link"]).status_code, 200)
        self.assertEqual(self.client.delete(f"/api/pairing/{claimed['id']}", headers=self.admin).status_code, 409)

    def test_a_code_whose_admin_is_deactivated_or_demoted_is_not_valid(self):
        self.make_user("padmin", "padmin-password-123", role="admin")
        self.addCleanup(self.remove_user, "padmin")  # a second admin would hold a Free seat for later tests
        padmin = self.login("padmin", "padmin-password-123")
        for change in ({"is_active": False}, {"role": "user"}):
            made = self.make(padmin)
            before = self.set_user("padmin", **change)
            try:
                resp = self.claim(made["link"])
            finally:
                self.set_user("padmin", **before)
            self.assertEqual((resp.status_code, resp.json()["detail"]), (404, INVALID), change)
            self.assertEqual(self.audits(made["id"])[-1]["details"]["reason"], "maker_not_an_active_admin")
        self.assertEqual(self.webhooks.hooks(), [])

    def test_a_bad_webhook_url_is_refused_and_leaves_the_code_usable(self):
        made = self.make()
        for url in ("http://ostraka.example.org/hook", "https://user:pw@ostraka.example.org/hook",
                    "http://169.254.169.254/latest", "ftp://ostraka.example.org/"):
            resp = self.claim(made["link"], url=url)
            self.assertEqual(resp.status_code, 422, url)
            self.assertIsInstance(resp.json()["detail"], str)
        self.assertEqual(self.webhooks.hooks(), [])
        self.assertEqual(self.claim(made["link"]).status_code, 200)

    def test_unknown_and_malformed_codes_are_not_valid(self):
        for code in ("pair_nothing-like-this", "rvt_abc", ""):
            resp = self.claim(code)
            self.assertEqual((resp.status_code, resp.json()["detail"]), (404, INVALID), code)

    def test_nothing_secret_is_audited(self):
        made = self.make()
        code = made["link"].split("#", 1)[1]
        body = self.claim(made["link"]).json()
        self.claim(made["link"])  # refused
        dumped = json.dumps([r["details"] for r in self.audits(made["id"])])
        for secret in (code, made["link"], body["token"], body["webhook_secret"],
                       hashlib.sha256(code.encode()).hexdigest()):
            self.assertNotIn(secret, dumped)

    # ---- the ostraka scope ----

    def ostraka_token(self):
        return bearer(self.claim(self.make()["link"]).json()["token"])

    def test_the_ostraka_scope_reads_jobs_and_starts_them_and_nothing_else(self):
        token = self.ostraka_token()
        job = self.create_job(self.alice, "PAIR-SCOPE-1")
        source = self.evidence / "PAIR-SCOPE-2.E01"
        source.write_bytes(b"")
        started = self.client.post("/api/jobs", headers=token, json={
            "case_number": "PAIR-SCOPE-2", "source_paths": [str(source)], "external_ref": "OST-26-014",
            "destination_path": str(self.evidence / "out" / "PAIR-SCOPE-2")})
        self.assertEqual(started.status_code, 200, started.text)
        self.assertEqual(started.json()["owner"], "admin")  # the token's owner, the code's maker

        for path in ("/api/health", "/api/auth/me", "/api/jobs", f"/api/jobs/{job}", f"/api/jobs/{job}/case",
                     f"/api/jobs/{job}/case/findings", f"/api/jobs/{job}/case/notes",
                     "/api/validate/case-id/PAIR-SCOPE-9", f"/api/fs/browse?path={self.evidence}"):
            resp = self.client.get(path, headers=token)
            self.assertNotEqual(resp.status_code, 403, f"GET {path}: {resp.text}")
            self.assertLess(resp.status_code, 500, f"GET {path}: {resp.text}")
            self.assertNotEqual(self.client.head(path, headers=token).status_code, 403, f"HEAD {path}")

        refused = (
            ("POST", f"/api/jobs/{job}/cancel"), ("POST", f"/api/jobs/{job}/restart"), ("DELETE", f"/api/jobs/{job}"),
            ("PATCH", f"/api/jobs/{job}"), ("PUT", f"/api/jobs/{job}/sharing"),
            ("POST", f"/api/jobs/{job}/case/findings"), ("POST", f"/api/jobs/{job}/case/notes"),
            ("PATCH", f"/api/jobs/{job}/case/findings/1"), ("POST", "/api/jobs/bulk/delete"),
            ("POST", "/api/jobs/bulk/cancel"), ("GET", "/api/busy"), ("GET", "/api/ai/cases"),
            ("POST", "/api/ai/offline/answer"), ("GET", "/api/threat-intel"), ("GET", "/api/webhooks"),
            ("POST", "/api/webhooks"), ("GET", "/api/pairing"), ("POST", "/api/pairing"), ("GET", "/api/licence"),
            ("GET", "/api/auth/users"), ("GET", "/api/auth/tokens"), ("POST", "/api/auth/tokens"),
            ("POST", "/api/auth/session"), ("GET", "/api/lab/status"), ("GET", "/api/anduril/containers"),
            ("GET", "/api/jobs/"), ("GET", "/api/jobsx"), ("OPTIONS", "/api/jobs"),
        )
        for method, path in refused:
            resp = self.client.request(method, path, headers=token, json={})
            self.assertEqual(resp.status_code, 403, f"{method} {path}: {resp.text}")

    def test_the_refusal_rule_itself(self):
        from auth import tokens
        ostraka = {"scope": "ostraka"}
        job = "0b8e3c1a-1111-4222-8333-444455556666"
        allowed = [("GET", "/api/health"), ("HEAD", "/api/auth/me"), ("GET", "/api/jobs"), ("POST", "/api/jobs"),
                   ("GET", f"/api/jobs/{job}"), ("GET", f"/api/jobs/{job}/case/rows"),
                   ("GET", "/api/validate/case-id/CASE-1"), ("GET", "/api/fs/browse")]
        for method, path in allowed:
            self.assertIsNone(tokens.refusal(ostraka, method, path, ()), f"{method} {path}")
        for method, path in (("POST", f"/api/jobs/{job}"), ("PUT", "/api/jobs"), ("GET", "/api/jobs/not-a-job"),
                             ("GET", "/api/validate/case-id/a/b"), ("GET", "/api/fs/browse/x"),
                             ("POST", "/api/fs/browse"), ("GET", "/api/healthz")):
            self.assertIsNotNone(tokens.refusal(ostraka, method, path, ()), f"{method} {path}")

    # ---- external_ref ----

    def start(self, case, headers=None, **body):
        source = self.evidence / f"{case}.E01"
        source.write_bytes(b"")
        return self.client.post("/api/jobs", headers=headers or self.admin, json={
            "case_number": case, "source_paths": [str(source)],
            "destination_path": str(self.evidence / "out" / case), **body})

    def test_external_ref_is_checked_kept_and_returned(self):
        for ref in ("OST-26-14", "ost-26-014", "OST-2-014", "XYZ-26-014", "OST-26-014 ", "OST-265-014",
                    "OST-٢٦-014", "OST-26-014\n", "HNT-26-", ""):
            self.assertEqual(self.start("PAIR-REF-BAD", external_ref=ref).status_code, 422, repr(ref))
        for n, ref in enumerate(("OST-26-014", "HNT-2026-0031")):
            made = self.start(f"PAIR-REF-{n}", external_ref=ref)
            self.assertEqual(made.status_code, 200, made.text)
            self.assertEqual(made.json()["external_ref"], ref)
            fetched = self.client.get(f"/api/jobs/{made.json()['id']}", headers=self.admin).json()
            self.assertEqual(fetched["external_ref"], ref)
        plain = self.start("PAIR-REF-NONE")
        self.assertIsNone(self.client.get(f"/api/jobs/{plain.json()['id']}", headers=self.admin).json()["external_ref"])

    def test_a_workers_save_keeps_external_ref(self):
        from models.job import JobStatus
        made = self.start("PAIR-REF-KEEP", external_ref="OST-26-015").json()
        storage = self.main.job_storage
        stale = storage.get_job(made["id"])
        stale.external_ref = None  # a copy from before the field
        stale.status = JobStatus.RUNNING
        storage.save_worker_job(stale)
        self.assertEqual(storage.get_job(made["id"]).external_ref, "OST-26-015")


if __name__ == "__main__":
    unittest.main()
