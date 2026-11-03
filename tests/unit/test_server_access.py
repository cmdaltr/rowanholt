"""Unit tests for server mode: sign-in, job ownership and sharing, admin areas.

Drives the real backend app (src/web/backend/main.py) through FastAPI's test client,
with SQLite standing in for Postgres and a temporary user store. Needs the backend's
Python requirements; skipped without them.

Run: python3 -m unittest tests/unit/test_server_access.py
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TMP = tempfile.mkdtemp(prefix="dernvale-access-")
# The backend's settings read .env from the working directory; never the repository's
os.chdir(TMP)
os.environ.update({
    "DATABASE_URL": f"sqlite:///{TMP}/jobs.db",
    "USERS_FILE": f"{TMP}/users.json",
    "OUTPUT_DIR": f"{TMP}/output",
    "SECRET_KEY": "test-secret-key-for-unit-tests-only-0123456789",
    "DERNVALE_ADMIN_PASSWORD": "correct horse battery staple",
    "DERNVALE_PUBLIC_URL": "https://dernvale.test",
    # No Redis here: sign-in lockouts fall back to memory (port 1 refuses at once)
    "REDIS_HOST": "127.0.0.1",
    "REDIS_PORT": "1",
    # Threat intelligence from this checkout, as the backend container mounts it
    "DERNVALE_ELROND_SRC": str(Path(__file__).resolve().parents[2] / "src" / "analysis"),
})

try:
    from fastapi.testclient import TestClient
except ImportError:  # backend requirements not installed
    TestClient = None

BACKEND = Path(__file__).resolve().parents[2] / "src" / "web" / "backend"


def load_app():
    sys.path.insert(0, str(BACKEND))
    # Another test file may have imported backend modules first (config, storage), with settings
    # read before this file's environment was set: start them afresh.
    for name, module in list(sys.modules.items()):
        if str(getattr(module, "__file__", "") or "").startswith(str(BACKEND)):
            del sys.modules[name]
    # No Celery or forensic tools here: the job queue is a stand-in. (Not patch.dict, which
    # would unload config with it and leave the test holding a second settings object.)
    fake_tasks = mock.MagicMock()
    fake_tasks.start_analysis.delay.return_value = mock.Mock(id="celery-task")
    sys.modules["tasks_docker"] = fake_tasks
    import main  # noqa: E402
    return main


class BackendCase(unittest.TestCase):
    """The real backend in server mode, with an admin, alice and bob signed in (no tests of its own:
    test_eru_mcp.py drives its MCP server against the same setup)."""

    @classmethod
    def setUpClass(cls):
        cls.main = load_app()
        from config import settings
        cls.settings = settings
        cls.evidence = Path(TMP) / "evidence"
        cls.evidence.mkdir(exist_ok=True)
        cls.allowed = mock.patch.object(type(settings), "allowed_paths",
                                        new_callable=mock.PropertyMock, return_value=[str(cls.evidence)])
        cls.allowed.start()
        settings.dernvale_server_mode = True
        cls.client = TestClient(cls.main.app)
        cls.admin = cls.login("admin", "correct horse battery staple")
        for name in ("alice", "bob"):
            resp = cls.client.post("/api/auth/users", headers=cls.admin, json={
                "username": name, "email": f"{name}@example.org", "password": f"{name}-password-123"})
            # Another class over the same store may have made them already
            assert resp.status_code == 200 or "already taken" in resp.text, resp.text
        cls.alice = cls.login("alice", "alice-password-123")
        cls.bob = cls.login("bob", "bob-password-123")

    @classmethod
    def tearDownClass(cls):
        cls.allowed.stop()
        cls.settings.dernvale_server_mode = False

    @classmethod
    def login(cls, username, password):
        resp = cls.client.post("/api/auth/login", data={"username": username, "password": password})
        assert resp.status_code == 200, resp.text
        cls.client.cookies.clear()  # each test says who it is with a header
        return {"Authorization": f"Bearer {resp.json()['access_token']}"}

    def create_job(self, headers, case):
        source = self.evidence / f"{case}.E01"
        source.write_bytes(b"")
        resp = self.client.post("/api/jobs", headers=headers, json={
            "case_number": case, "source_paths": [str(source)],
            "destination_path": str(self.evidence / "out" / case)})
        self.assertEqual(resp.status_code, 200, resp.text)
        return resp.json()["id"]

    def ids(self, headers):
        resp = self.client.get("/api/jobs", headers=headers)
        self.assertEqual(resp.status_code, 200, resp.text)
        return {job["id"] for job in resp.json()["jobs"]}


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class ServerAccessTest(BackendCase):
    def test_sign_in_required(self):
        for path in ("/api/jobs", "/api/fs/browse", "/api/ai/cases", "/api/auth/me"):
            self.assertEqual(self.client.get(path).status_code, 401, path)
        self.assertEqual(self.client.get("/api/health").status_code, 200)
        config = self.client.get("/api/auth/config").json()
        self.assertTrue(config["server_mode"])
        self.assertFalse(config["guest"])

    def test_no_guest_or_open_sign_up(self):
        # Refused by the middleware (401) before the route's own 403
        self.assertIn(self.client.post("/api/auth/guest").status_code, (401, 403))
        resp = self.client.post("/api/auth/register", json={
            "username": "mallory", "email": "m@example.org", "password": "mallory-password-1"})
        self.assertEqual(resp.status_code, 401)

    def test_builtin_admin_password_refused(self):
        resp = self.client.post("/api/auth/login", data={"username": "admin", "password": self.settings.default_admin_password})
        self.assertEqual(resp.status_code, 401)

    def test_jobs_visible_to_owner_shared_users_and_admins(self):
        job = self.create_job(self.alice, "CASE-ALICE-1")
        self.assertIn(job, self.ids(self.alice))
        self.assertIn(job, self.ids(self.admin))
        self.assertNotIn(job, self.ids(self.bob))
        self.assertEqual(self.client.get(f"/api/jobs/{job}", headers=self.bob).status_code, 404)
        self.assertEqual(self.client.get(f"/api/jobs/{job}", headers=self.alice).json()["owner"], "alice")

        resp = self.client.put(f"/api/jobs/{job}/sharing", headers=self.alice, json={"usernames": ["bob"]})
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertIn(job, self.ids(self.bob))
        self.assertEqual(self.client.get(f"/api/jobs/{job}", headers=self.bob).status_code, 200)
        # Shared with, not owner: can't reshare
        resp = self.client.put(f"/api/jobs/{job}/sharing", headers=self.bob, json={"usernames": []})
        self.assertEqual(resp.status_code, 403)

    def test_shared_users_cant_destroy_the_job(self):
        # Deleting, archiving and a fresh restart lose the owner's work: owner and admins only.
        # A plain restart, which re-runs into the output, the people it's shared with can do
        from models.job import JobStatus
        job = self.create_job(self.alice, "CASE-SHARED-1")
        self.client.put(f"/api/jobs/{job}/sharing", headers=self.alice, json={"usernames": ["bob"]})
        stored = self.main.job_storage.get_job(job)
        stored.status = JobStatus.COMPLETED
        self.main.job_storage.save_job(stored)

        for method, path in (("DELETE", f"/api/jobs/{job}"), ("POST", f"/api/jobs/{job}/archive"),
                             ("POST", f"/api/jobs/{job}/restart"), ("POST", f"/api/jobs/{job}/restart?fresh=true")):
            resp = self.client.request(method, path, headers=self.bob)
            self.assertEqual(resp.status_code, 403, f"{method} {path}: {resp.text}")
            self.assertIn("owner or an admin", resp.json()["detail"])
        for path in ("/api/jobs/bulk/delete", "/api/jobs/bulk/archive", "/api/jobs/bulk/restart"):
            [result] = self.client.post(path, headers=self.bob, json=[job]).json()["results"]
            self.assertFalse(result["success"], path)
            self.assertIn("owner or an admin", result["error"])
        self.assertEqual(self.main.job_storage.get_job(job).status, JobStatus.COMPLETED)

        resp = self.client.post(f"/api/jobs/{job}/restart?fresh=false", headers=self.bob)
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertFalse(self.main.job_storage.get_job(job).options.force_overwrite)
        stored = self.main.job_storage.get_job(job)
        stored.status = JobStatus.COMPLETED
        self.main.job_storage.save_job(stored)
        self.assertEqual(self.client.post(f"/api/jobs/{job}/archive", headers=self.alice).status_code, 200)

    def test_sharing_with_unknown_user_refused(self):
        job = self.create_job(self.alice, "CASE-ALICE-2")
        resp = self.client.put(f"/api/jobs/{job}/sharing", headers=self.alice, json={"usernames": ["nobody"]})
        self.assertEqual(resp.status_code, 400)

    def test_bulk_actions_skip_other_peoples_jobs(self):
        job = self.create_job(self.alice, "CASE-ALICE-3")
        resp = self.client.post("/api/jobs/bulk/cancel", headers=self.bob, json=[job])
        self.assertEqual(resp.json()["results"][0]["error"], "Job not found")

    def test_restart_with_findings_needs_confirm(self):
        import case_routes
        from models.job import JobStatus
        job = self.create_job(self.alice, "CASE-RESTART-1")
        stored = self.main.job_storage.get_job(job)
        stored.status = JobStatus.COMPLETED
        self.main.job_storage.save_job(stored)
        case_routes.store().add_finding(job, "alice", host="WS01", artefact="artefacts/cooked/prefetch.csv",
                                        row_ref="2", row_hash="0" * 64, title="Odd prefetch")

        resp = self.client.post(f"/api/jobs/{job}/restart", headers=self.alice)
        self.assertEqual(resp.status_code, 409, resp.text)
        self.assertEqual(resp.json()["detail"]["findings"], 1)
        resp = self.client.post("/api/jobs/bulk/restart", headers=self.alice, json=[job])
        self.assertFalse(resp.json()["results"][0]["success"])
        self.assertEqual(self.main.job_storage.get_job(job).status, JobStatus.COMPLETED)

        resp = self.client.post(f"/api/jobs/{job}/restart?confirm=true", headers=self.alice)
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json()["status"], "pending")

    def test_restart_of_a_completed_job_is_fresh(self):
        # Elrond skips artefacts whose cooked file exists, so re-running a completed job into its
        # old output changed nothing: by default its output is removed first; a failed one keeps it
        from models.job import JobStatus
        for status, query, fresh in ((JobStatus.COMPLETED, "", True), (JobStatus.FAILED, "", False),
                                     (JobStatus.COMPLETED, "?fresh=false", False), (JobStatus.FAILED, "?fresh=true", True)):
            job = self.create_job(self.alice, f"CASE-FRESH-{status.value}-{bool(query)}")
            stored = self.main.job_storage.get_job(job)
            stored.status = status
            self.main.job_storage.save_job(stored)
            resp = self.client.post(f"/api/jobs/{job}/restart{query}", headers=self.alice)
            self.assertEqual(resp.status_code, 200, resp.text)
            self.assertEqual(bool(self.main.job_storage.get_job(job).options.force_overwrite), fresh, (status, query))
        # A fresh restart's wipe isn't kept: the next restart, of a failed run, keeps its output
        stored = self.main.job_storage.get_job(job)
        stored.status = JobStatus.FAILED
        self.main.job_storage.save_job(stored)
        self.client.post(f"/api/jobs/{job}/restart", headers=self.alice)
        self.assertFalse(self.main.job_storage.get_job(job).options.force_overwrite)

    def test_case_clash_reported_without_listing_others_jobs(self):
        self.create_job(self.alice, "CASE-CLASH-1")
        body = self.client.get("/api/validate/case-id/CASE-CLASH-1", headers=self.bob).json()
        self.assertTrue(body["exists"])
        self.assertEqual(body["jobs"], [])

    def test_job_from_before_server_mode_is_admin_only(self):
        from models.job import Job, JobStatus, AnalysisOptions
        legacy = Job(id="00000000-0000-0000-0000-000000000001", case_number="LEGACY-01", source_paths=[],
                     destination_path=None, options=AnalysisOptions(), status=JobStatus.COMPLETED)
        self.main.job_storage.save_job(legacy)
        self.assertIn(legacy.id, self.ids(self.admin))
        self.assertNotIn(legacy.id, self.ids(self.alice))

    def test_admin_areas(self):
        self.assertEqual(self.client.get("/api/lab/status", headers=self.alice).status_code, 403)
        self.assertEqual(self.client.get("/api/auth/users", headers=self.alice).status_code, 403)
        self.assertEqual(self.client.get("/api/auth/users", headers=self.admin).status_code, 200)
        self.assertEqual(self.client.get("/api/auth/directory", headers=self.alice).status_code, 200)

    def test_verify_for_the_proxy(self):
        self.assertEqual(self.client.get("/api/auth/verify").status_code, 401)
        resp = self.client.get("/api/auth/verify?login_redirect=1", follow_redirects=False)
        self.assertEqual(resp.headers["location"], "https://dernvale.test/login")
        resp = self.client.get("/api/auth/verify", headers=self.bob)
        self.assertEqual(resp.headers["X-Dernvale-User"], "bob")

    def test_navigator_layers_follow_the_case(self):
        self.create_job(self.alice, "CASE-LAYER-1")

        def layer(headers, uri):
            return self.client.get("/api/auth/verify?service=navigator",
                                   headers={**headers, "X-Forwarded-Uri": uri}).status_code
        self.assertEqual(layer(self.alice, "/assets/CASE-LAYER-1.json"), 200)
        self.assertEqual(layer(self.admin, "/assets/CASE-LAYER-1.json"), 200)
        self.assertEqual(layer(self.bob, "/assets/CASE-LAYER-1.json"), 403)
        self.assertEqual(layer(self.bob, "/assets/CASE%2DLAYER%2D1.json?x=1"), 403)
        # Other spellings of the same file, which the Navigator's nginx normalises and serves
        for uri in ("/assets//CASE-LAYER-1.json", "/assets/./CASE-LAYER-1.json", "//assets/CASE-LAYER-1.json",
                    "/assets/x/../CASE-LAYER-1.json", "/assets/%2E/CASE-LAYER-1.json"):
            self.assertEqual(layer(self.bob, uri), 403, uri)
        # The Navigator itself, and its ATT&CK data
        self.assertEqual(layer(self.bob, "/assets/enterprise-attack.json"), 200)
        self.assertEqual(layer(self.bob, "/"), 200)
        # A case run from the command line, with no job: admins only
        (self.settings.output_dir / "CLI-CASE-9").mkdir(parents=True, exist_ok=True)
        self.assertEqual(layer(self.bob, "/assets/CLI-CASE-9.json"), 403)
        self.assertEqual(layer(self.admin, "/assets/CLI-CASE-9.json"), 200)

    def test_lockout_after_repeated_failures(self):
        for _ in range(self.settings.max_login_attempts):
            self.client.post("/api/auth/login", data={"username": "locktest", "password": "wrong"})
        resp = self.client.post("/api/auth/login", data={"username": "locktest", "password": "wrong"})
        self.assertEqual(resp.status_code, 429)

    def test_username_and_email_share_a_lockout(self):
        resp = self.client.post("/api/auth/users", headers=self.admin, json={
            "username": "lockpair", "email": "lockpair@example.org", "password": "lockpair-password-1"})
        assert resp.status_code == 200 or "already taken" in resp.text, resp.text
        names = ("lockpair", "lockpair@example.org")
        for n in range(self.settings.max_login_attempts):
            self.client.post("/api/auth/login", data={"username": names[n % 2], "password": "wrong"})
        for name in names:
            resp = self.client.post("/api/auth/login", data={"username": name, "password": "wrong"})
            self.assertEqual(resp.status_code, 429, name)

    def test_lockout_is_per_address_until_it_is_everywhere(self):
        from auth.throttle import EVERYWHERE, SignInThrottle
        throttle = SignInThrottle("redis://127.0.0.1:1/0")
        limit = self.settings.max_login_attempts
        for _ in range(limit):
            throttle.failed("Alice", "10.0.0.66")
        self.assertGreater(throttle.locked_for("alice", "10.0.0.66"), 0)
        self.assertEqual(throttle.locked_for("alice", "10.0.0.5"), 0)
        throttle.succeeded("alice", "10.0.0.66")
        self.assertEqual(throttle.locked_for("alice", "10.0.0.66"), 0)
        for n in range(limit * EVERYWHERE):
            throttle.failed("alice", f"10.1.{n}.1")
        self.assertGreater(throttle.locked_for("alice", "10.0.0.5"), 0)

    def test_a_session_gets_a_token_for_scripts(self):
        """Account's token for scripts and dernvale mcp: the session cookie (a password or single
        sign-on) traded for a bearer token, with nothing more than the session had."""
        self.client.cookies.clear()
        self.assertEqual(self.client.post("/api/auth/session").status_code, 401)
        resp = self.client.post("/api/auth/login", data={"username": "bob", "password": "bob-password-123"})
        self.assertEqual(resp.status_code, 200, resp.text)
        cookie = resp.cookies.get("session_token")
        self.client.cookies.clear()
        # The cookie alone (Secure on a server, so the plain-HTTP test client won't send it by itself)
        issued = self.client.post("/api/auth/session", headers={"Cookie": f"session_token={cookie}"})
        self.assertEqual(issued.status_code, 200, issued.text)
        self.assertEqual(issued.json()["user"]["username"], "bob")
        bearer = {"Authorization": f"Bearer {issued.json()['access_token']}"}
        self.assertEqual(self.client.get("/api/auth/me", headers=bearer).json()["username"], "bob")
        self.assertEqual(self.client.get("/api/auth/users", headers=bearer).status_code, 403)  # still not an admin

    def test_only_admins_change_threat_intel_expiry(self):
        resp = self.client.post("/api/threat-intel/import", headers=self.admin,
                                files={"file": ("lab.txt", b"203.0.113.9\nMimikatz\n", "text/plain")})
        self.assertEqual(resp.status_code, 200, resp.text)
        page = self.client.get("/api/threat-intel/indicators", headers=self.bob, params={"q": "203.0.113.9"}).json()
        [ip] = page["indicators"]
        self.assertIsNotNone(ip["valid_until"])  # an IP's default 90 days
        path = f"/api/threat-intel/indicators/{ip['id']}/validity"
        self.assertEqual(self.client.put(path, headers=self.bob, json={"valid_until": None}).status_code, 403)
        self.assertEqual(self.client.put(path, headers=self.admin, json={"valid_until": "soon"}).status_code, 400)
        resp = self.client.put(path, headers=self.admin, json={"valid_until": "2030-01-01"})
        self.assertEqual(resp.json()["valid_until"], "2030-01-01T00:00:00")
        resp = self.client.put(path, headers=self.admin, json={"valid_until": None})
        self.assertIsNone(resp.json()["valid_until"])
        self.assertEqual(self.client.put("/api/threat-intel/indicators/999999/validity", headers=self.admin,
                                         json={"valid_until": None}).status_code, 404)

    def test_last_admin_stays_admin(self):
        users = self.client.get("/api/auth/users", headers=self.admin).json()
        admin_id = next(u["id"] for u in users if u["username"] == "admin")
        resp = self.client.patch(f"/api/auth/users/{admin_id}", headers=self.admin, json={"role": "user"})
        self.assertEqual(resp.status_code, 400)

    def test_local_mode_stays_open(self):
        self.settings.dernvale_server_mode = False
        try:
            self.assertEqual(self.client.get("/api/jobs").status_code, 200)
            self.assertEqual(self.client.get("/api/auth/me").json()["username"], "local")
        finally:
            self.settings.dernvale_server_mode = True


if __name__ == "__main__":
    unittest.main()
