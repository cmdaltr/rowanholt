"""Mobile jobs from the web app: the backup password reaches the worker through Redis, never the
job, and the worker runs Elrond with --Mobile (and --backupPasswordStdin when there's a password).

Drives the real backend (test_server_access.BackendCase). Run:
python3 -m unittest tests/unit/test_mobile_jobs.py
"""

import importlib.util
import sqlite3
import sys
import unittest
from pathlib import Path
from unittest import mock

import test_server_access  # noqa: F401  (sets the backend's environment before anything imports it)
from test_server_access import BACKEND, TMP, BackendCase, TestClient

PASSWORD = "Correct-Horse-7"


class FakeRedis:
    def __init__(self):
        self.store, self.expiry = {}, {}

    def set(self, key, value, ex=None):
        self.store[key], self.expiry[key] = value, ex

    def pipeline(self):
        redis, ops = self, []

        class Pipe:
            def get(self, key):
                ops.append(lambda: redis.store.get(key))

            def delete(self, key):
                ops.append(lambda: int(redis.store.pop(key, None) is not None))

            def execute(self):
                return [op() for op in ops]

        return Pipe()


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class MobileJobTest(BackendCase):
    def test_password_goes_to_redis_not_the_job(self):
        backup = self.evidence / "iphone-backup"
        backup.mkdir(exist_ok=True)
        with mock.patch.object(self.main.backup_secrets, "stash") as stash:
            resp = self.client.post("/api/jobs", headers=self.alice, json={
                "case_number": "MOBILE-01", "source_paths": [str(backup)],
                "destination_path": str(self.evidence / "out" / "MOBILE-01"),
                "options": {"mobile": True, "local": False}, "backup_password": PASSWORD})
        self.assertEqual(resp.status_code, 200, resp.text)
        job_id = resp.json()["id"]
        stash.assert_called_once_with(job_id, PASSWORD)
        self.assertNotIn(PASSWORD, resp.text)
        self.assertTrue(resp.json()["options"]["mobile"])
        got = self.client.get(f"/api/jobs/{job_id}", headers=self.alice)
        self.assertNotIn(PASSWORD, got.text)
        with sqlite3.connect(f"{TMP}/jobs.db") as db:
            for row in db.execute("SELECT * FROM jobs"):
                self.assertNotIn(PASSWORD, " ".join(str(v) for v in row))

    def test_password_only_for_mobile_jobs(self):
        source = self.evidence / "disk.E01"
        source.write_bytes(b"")
        with mock.patch.object(self.main.backup_secrets, "stash") as stash:
            resp = self.client.post("/api/jobs", headers=self.alice, json={
                "case_number": "NOTMOBILE", "source_paths": [str(source)], "backup_password": PASSWORD})
        self.assertEqual(resp.status_code, 400, resp.text)
        self.assertNotIn(PASSWORD, resp.text)
        stash.assert_not_called()

    def test_secret_taken_once(self):
        import backup_secrets

        redis = FakeRedis()
        backup_secrets.stash("job-1", PASSWORD, client=redis)
        self.assertEqual(redis.expiry["rowanholt:backup_password:job-1"], backup_secrets.TTL_SECONDS)
        self.assertEqual(backup_secrets.take("job-1", client=redis), PASSWORD)
        self.assertIsNone(backup_secrets.take("job-1", client=redis))

    def test_job_create_never_dumps_the_password(self):
        from models.job import JobCreate

        request = JobCreate(case_number="MOBILE-02", source_paths=["/x"], options={"mobile": True},
                            backup_password=PASSWORD)
        self.assertEqual(request.backup_password.get_secret_value(), PASSWORD)
        self.assertNotIn(PASSWORD, request.model_dump_json())
        self.assertNotIn(PASSWORD, repr(request))

    def test_worker_runs_elrond_with_mobile(self):
        spec = importlib.util.spec_from_file_location("tasks_docker_for_test", BACKEND / "tasks_docker.py")
        tasks = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tasks)
        from models.job import AnalysisOptions, Job

        job = Job(id="j", case_number="MOBILE-03", source_paths=["/tmp/rowanholt/phones/backup"],
                  destination_path="/tmp/rowanholt/MOBILE-03", options=AnalysisOptions(mobile=True, local=False))
        cmd = tasks.build_elrond_command(job)
        self.assertIn("--Mobile", cmd)
        self.assertNotIn("--Collect", cmd)
        self.assertNotIn("--Gandalf", cmd)
        source = (BACKEND / "tasks_docker.py").read_text()
        self.assertIn('cmd.append("--backupPasswordStdin")', source)
        self.assertIn("stdin=subprocess.PIPE if backup_password else None", source)


if __name__ == "__main__":
    unittest.main()
