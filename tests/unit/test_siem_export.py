"""POST /api/jobs/{id}/export-siem: the manual SIEM export of a completed job (main.trigger_siem_export).

The backend runs as `uvicorn main:app`, top-level modules with no package, where the route's old
`from .tasks import run_siem_export` raised ImportError and every export answered 500. Driven
through the real app in server mode (test_server_access.BackendCase), with tasks.run_siem_export
replaced: the export itself shells out to Splunk's container and Elrond's ingest code.

Run: python3 -m unittest tests/unit/test_siem_export.py
"""

import logging
import unittest
from pathlib import Path
from unittest import mock

from test_server_access import BackendCase, TestClient


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class SiemExportTest(BackendCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from models.job import JobStatus
        cls.JobStatus = JobStatus

    def completed_job(self, case: str, splunk: bool = True) -> str:
        job_id = self.create_job(self.alice, case)
        stored = self.main.job_storage.get_job(job_id)
        stored.status = self.JobStatus.COMPLETED
        stored.options.splunk = splunk
        self.main.job_storage.save_job(stored)
        Path(stored.destination_path).mkdir(parents=True, exist_ok=True)
        return job_id

    def export(self, job_id: str, headers: dict):
        with mock.patch("tasks.run_siem_export") as run:
            resp = self.client.post(f"/api/jobs/{job_id}/export-siem", headers=headers)
        return resp, run

    def test_the_export_runs_with_the_job_and_its_output_folder(self):
        job_id = self.completed_job("CASE-SIEM-1")
        resp, run = self.export(job_id, self.alice)
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json(), {"success": True, "message": "SIEM export completed successfully"})
        run.assert_called_once()
        job, dest, logger = run.call_args.args
        self.assertEqual(job.id, job_id)
        self.assertEqual(dest, Path(self.main.job_storage.get_job(job_id).destination_path))
        self.assertIsInstance(logger, logging.Logger)
        log = self.main.job_storage.get_job(job_id).log
        self.assertTrue(any("COMMENCING SIEM EXPORT" in line for line in log))
        self.assertTrue(any("SIEM EXPORT COMPLETED" in line for line in log))

    def test_a_failed_export_is_logged_and_answers_500(self):
        job_id = self.completed_job("CASE-SIEM-2")
        with mock.patch("tasks.run_siem_export", side_effect=FileNotFoundError("ingest script not found")):
            resp = self.client.post(f"/api/jobs/{job_id}/export-siem", headers=self.alice)
        self.assertEqual(resp.status_code, 500)
        self.assertIn("ingest script not found", resp.json()["detail"])
        self.assertTrue(any("Manual SIEM export failed" in line for line in self.main.job_storage.get_job(job_id).log))

    def test_only_a_completed_job_with_a_siem_option_exports(self):
        no_siem = self.completed_job("CASE-SIEM-3", splunk=False)
        resp, run = self.export(no_siem, self.alice)
        self.assertEqual(resp.status_code, 400)
        run.assert_not_called()

        running = self.completed_job("CASE-SIEM-4")
        self.main.job_storage.set_status(running, self.JobStatus.FAILED)
        resp, run = self.export(running, self.alice)
        self.assertEqual(resp.status_code, 400)
        run.assert_not_called()

    def test_whoever_can_see_the_job_may_export_it(self):
        # docs/API.md: the owner, the people it's shared with and admins; anyone else gets 404
        job_id = self.completed_job("CASE-SIEM-5")
        resp, run = self.export(job_id, self.bob)
        self.assertEqual(resp.status_code, 404)
        run.assert_not_called()

        self.assertEqual(self.client.put(f"/api/jobs/{job_id}/sharing", headers=self.alice,
                                         json={"usernames": ["bob"]}).status_code, 200)
        for headers in (self.bob, self.admin):
            resp, run = self.export(job_id, headers)
            self.assertEqual(resp.status_code, 200, resp.text)
            run.assert_called_once()

    def test_a_smith_mcp_token_is_refused(self):
        job_id = self.completed_job("CASE-SIEM-6")
        resp = self.client.post("/api/auth/tokens", headers=self.alice,
                                json={"name": "Smith", "scope": "smith-mcp", "days": 30})
        self.assertEqual(resp.status_code, 200, resp.text)
        smith = {"Authorization": f"Bearer {resp.json()['token']}"}
        resp, run = self.export(job_id, smith)
        self.assertEqual(resp.status_code, 403)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
