"""Webhooks (automation): validation, signing, the edition gate at delivery, staying registered across
a lapse, the events a job, a finding and a report send, and the admin API. Through the real backend
(test_server_access.BackendCase), with licences signed by a throwaway key and nothing sent anywhere:
the HTTP POST is replaced.

Run: python3 -m unittest tests/unit/test_webhooks.py
"""

import hashlib
import hmac
import json
import os
import tempfile
import unittest
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
class WebhookTest(BackendCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import licence
        import webhooks
        cls.licence, cls.webhooks = licence, webhooks
        cls.key = Ed25519PrivateKey.generate()
        public = cls.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        cls.keys = mock.patch.object(licence, "PUBLIC_KEYS", (public,))
        cls.keys.start()

    @classmethod
    def tearDownClass(cls):
        cls.keys.stop()
        super().tearDownClass()

    def setUp(self):
        folder = tempfile.mkdtemp()
        for patch in (mock.patch.dict(os.environ, {"ROWANHOLT_LICENCE": f"{folder}/licence.json",
                                                   "ROWANHOLT_WEBHOOKS": f"{folder}/webhooks.json"}),
                      mock.patch.object(self.webhooks, "BACKGROUND", False),
                      mock.patch.object(self.webhooks.time, "sleep", lambda s: None)):
            patch.start()
            self.addCleanup(patch.stop)
        self.sent = []
        self.answer = 200

        def post(url, body, headers):
            self.sent.append((url, body, headers))
            return self.answer
        patch = mock.patch.object(self.webhooks, "_post", post)
        patch.start()
        self.addCleanup(patch.stop)

    def licensed(self, edition="pro", expires=date(2099, 12, 31)):
        L = self.licence
        line = L.sign(self.key, L.Licence(L.new_id(), "Northwind Ltd", L.Edition(edition), 10, date(2026, 11, 11), expires))
        L.record_install(line, accepted_by="u1", accepted_by_name="Ada Admin <ada@example.org>")

    def hook(self, events=("job.completed", "job.failed", "finding.confirmed", "report.ready"), secret="s3cret"):
        return self.webhooks.add("https://soar.example.org/rowanholt", list(events), secret)

    # ---- the rules ----

    def test_https_only_but_http_for_localhost_and_private_addresses(self):
        v = self.webhooks.validate
        events = ["job.completed"]
        self.assertIsNone(v("https://soar.example.org/hook", events))
        for private in ("http://localhost:8080/h", "http://127.0.0.1/h", "http://10.1.2.3/h", "http://172.20.0.5/h",
                        "http://192.168.1.10:5000/h", "http://[::1]/h"):
            self.assertIsNone(v(private, events), private)
        for refused in ("http://soar.example.org/h", "http://8.8.8.8/h", "http://172.32.0.1/h", "ftp://x/h", "soar",
                        "https://user:pw@soar.example.org/h"):
            self.assertIsNotNone(v(refused, events), refused)
        self.assertIn("Choose events", v("https://soar.example.org/h", ["job.deleted"]))
        self.assertIn("Choose events", v("https://soar.example.org/h", []))

    def test_a_webhook_is_kept_on_free_but_not_sent(self):
        self.hook()
        self.assertEqual(self.webhooks.emit("job.completed", {"job_id": "j1"}), 0)
        self.assertEqual(self.sent, [])
        on, why = self.webhooks.sending()
        self.assertFalse(on)
        self.assertIn("Pro and Services", why)
        self.assertEqual(len(self.webhooks.hooks()), 1)

    def test_on_pro_it_is_sent_signed_with_the_webhooks_secret(self):
        self.licensed("pro")
        self.hook()
        self.assertEqual(self.webhooks.emit("report.ready", {"job_id": "j1", "case_number": "C-1"}), 1)
        [(url, body, headers)] = self.sent
        self.assertEqual(url, "https://soar.example.org/rowanholt")
        self.assertEqual(headers["X-Rowanholt-Event"], "report.ready")
        expected = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
        self.assertEqual(headers["X-Rowanholt-Signature"], expected)
        sent = json.loads(body)
        self.assertEqual((sent["event"], sent["data"]), ("report.ready", {"job_id": "j1", "case_number": "C-1"}))
        self.assertIn("sent_at", sent)
        [delivery] = self.webhooks.hooks()[0]["deliveries"]
        self.assertTrue(delivery["ok"])

    def test_it_stays_registered_across_a_lapse_and_sends_again_on_renewal(self):
        self.licensed("pro", expires=date(2026, 1, 1))  # ran out over 30 days ago: lapsed, so Free
        self.hook()
        self.assertEqual(self.webhooks.emit("job.completed", {"job_id": "j1"}), 0)
        self.assertIn("run out", self.webhooks.sending()[1])
        self.licensed("services")
        self.assertEqual(self.webhooks.emit("job.completed", {"job_id": "j1"}), 1)

    def test_three_tries_on_a_server_error_one_on_a_refusal_and_twenty_kept(self):
        self.licensed()
        hook = self.hook()
        self.answer = 503
        self.assertEqual(self.webhooks.deliver(hook, "job.completed", {})["tries"], 3)
        self.answer = 404
        self.assertEqual(self.webhooks.deliver(hook, "job.completed", {})["tries"], 1)
        self.answer = 200
        for _ in range(25):
            self.webhooks.deliver(hook, "job.completed", {})
        self.assertEqual(len(self.webhooks.hooks()[0]["deliveries"]), 20)

    # ---- the events ----

    def test_a_job_ending_sends_once_whichever_path_ended_it_and_no_paths_leave(self):
        from models.job import JobStatus
        self.licensed()
        self.hook()
        job_id = self.create_job(self.admin, "WEBHOOK-CASE")
        storage = self.main.job_storage
        job = storage.get_job(job_id)
        job.status = JobStatus.FAILED
        job.error = "FileNotFoundError: '/mnt/elrond_mount00/Windows/' on /Volumes/Evidence/disk.E01"
        storage.save_job(job)
        storage.save_job(job)  # saved again with the same status: no second event
        [(_, body, headers)] = self.sent
        data = json.loads(body)["data"]
        self.assertEqual(headers["X-Rowanholt-Event"], "job.failed")
        self.assertEqual((data["job_id"], data["case_number"], data["images"]), (job_id, "WEBHOOK-CASE", 1))
        self.assertNotIn("/Volumes", body.decode())
        self.assertNotIn("/mnt", body.decode())
        self.assertIn("<path>", data["error"])

    def test_confirming_a_finding_and_building_a_report_send_their_events(self):
        self.licensed()
        self.hook()
        case_routes = self.main.case_routes
        job_id = self.create_job(self.admin, "WEBHOOK-FINDING")
        finding = case_routes.store().add_finding(job_id, "admin", host="HOST1", artefact="evt/Security.jsonl",
                                                  row_ref="7", row_hash="ab" * 32, excerpt="EventID: 1102",
                                                  title="Log cleared", technique="T1685.005", status="lead")
        resp = self.client.patch(f"/api/jobs/{job_id}/case/findings/{finding['id']}", headers=self.admin,
                                 json={"status": "confirmed", "updated_at": finding["updated_at"]})
        self.assertEqual(resp.status_code, 200, resp.text)
        [(_, body, headers)] = self.sent
        self.assertEqual(headers["X-Rowanholt-Event"], "finding.confirmed")
        data = json.loads(body)["data"]
        self.assertEqual((data["finding_id"], data["host"], data["technique"], data["case_number"]),
                         (finding["id"], "HOST1", "T1685.005", "WEBHOOK-FINDING"))
        self.assertNotIn("1102", body.decode())  # the row's contents never leave

    # ---- the admin API ----

    def test_the_api_is_admins_only_and_says_why_nothing_is_sent_on_free(self):
        self.assertEqual(self.client.get("/api/webhooks", headers=self.alice).status_code, 403)
        made = self.client.post("/api/webhooks", headers=self.admin, json={
            "url": "https://soar.example.org/h", "events": ["job.completed"]})
        self.assertEqual(made.status_code, 200, made.text)
        self.assertTrue(made.json()["secret"])  # shown once
        listed = self.client.get("/api/webhooks", headers=self.admin).json()
        self.assertFalse(listed["sending"])
        self.assertIn("Pro and Services", listed["reason"])
        self.assertNotIn("secret", listed["webhooks"][0])
        self.assertTrue(listed["webhooks"][0]["has_secret"])
        test = self.client.post(f"/api/webhooks/{made.json()['id']}/test", headers=self.admin)
        self.assertEqual(test.status_code, 402)
        self.assertEqual(self.sent, [])
        self.licensed()
        test = self.client.post(f"/api/webhooks/{made.json()['id']}/test", headers=self.admin)
        self.assertEqual(test.status_code, 200, test.text)
        self.assertTrue(test.json()["ok"])
        bad = self.client.post("/api/webhooks", headers=self.admin, json={"url": "http://example.org/h",
                                                                           "events": ["job.completed"]})
        self.assertEqual(bad.status_code, 422)


if __name__ == "__main__":
    unittest.main()
