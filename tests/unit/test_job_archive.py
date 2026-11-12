"""Archiving keeps when, and the status to go back to (jobs.archived_at and archived_from).

Restoring used to read the status from what the job held, so a cancelled job (a cancel sets
completed_at) came back as completed, and the Archived Jobs page's "Archived" column read an
archived_at the job never had. Driven through the real app in server mode
(test_server_access.BackendCase), single and bulk.

Run: python3 -m unittest tests/unit/test_job_archive.py
"""

import unittest
from datetime import datetime

from test_server_access import BackendCase, TestClient


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class JobArchiveTest(BackendCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from models.job import JobStatus
        cls.JobStatus = JobStatus

    def ended_job(self, case: str, status, error=None) -> str:
        """A job that ended as `status`, with what that leaves on it: every end sets completed_at
        (a cancel too), a failure an error."""
        job_id = self.create_job(self.alice, case)
        stored = self.main.job_storage.get_job(job_id)
        stored.status = status
        stored.completed_at = datetime.now()
        stored.error = error
        self.main.job_storage.save_job(stored)
        return job_id

    def stored(self, job_id: str):
        return self.main.job_storage.get_job(job_id)

    def test_each_status_comes_back_as_it_was(self):
        S = self.JobStatus
        for n, (status, error) in enumerate(((S.CANCELLED, None), (S.FAILED, "Elrond exited 1"),
                                             (S.COMPLETED, None), (S.CANCELLED, "Stopped by its owner"))):
            with self.subTest(status=status.value, error=error):
                job_id = self.ended_job(f"CASE-ARC-{n}", status, error)
                resp = self.client.post(f"/api/jobs/{job_id}/archive", headers=self.alice)
                self.assertEqual(resp.status_code, 200, resp.text)
                self.assertEqual(resp.json()["status"], "archived")
                self.assertIsNotNone(resp.json()["archived_at"])
                job = self.stored(job_id)
                self.assertEqual((job.status, job.archived_from), (S.ARCHIVED, status))
                self.assertLessEqual(abs((datetime.now() - job.archived_at).total_seconds()), 60)

                resp = self.client.post(f"/api/jobs/{job_id}/unarchive", headers=self.alice)
                self.assertEqual(resp.status_code, 200, resp.text)
                self.assertEqual(resp.json()["status"], status.value)
                self.assertIsNone(resp.json()["archived_at"])
                job = self.stored(job_id)
                self.assertEqual((job.status, job.archived_at, job.archived_from), (status, None, None))

    def test_bulk_archive_and_restore_keep_the_status(self):
        S = self.JobStatus
        jobs = {self.ended_job("CASE-ARC-B1", S.CANCELLED): S.CANCELLED,
                self.ended_job("CASE-ARC-B2", S.FAILED, "boom"): S.FAILED,
                self.ended_job("CASE-ARC-B3", S.COMPLETED): S.COMPLETED}
        resp = self.client.post("/api/jobs/bulk/archive", headers=self.alice, json=list(jobs))
        self.assertTrue(all(r["success"] for r in resp.json()["results"]), resp.text)
        for job_id, status in jobs.items():
            job = self.stored(job_id)
            self.assertEqual((job.status, job.archived_from), (S.ARCHIVED, status))
            self.assertIsNotNone(job.archived_at)
        # The list the Archived Jobs page reads carries archived_at
        listed = {j["id"]: j for j in self.client.get("/api/jobs", headers=self.alice,
                                                      params={"status": "archived"}).json()["jobs"]}
        self.assertTrue(all(listed[job_id]["archived_at"] for job_id in jobs))

        resp = self.client.post("/api/jobs/bulk/unarchive", headers=self.alice, json=list(jobs))
        self.assertEqual({r["job_id"]: r["status"] for r in resp.json()["results"]},
                         {job_id: status.value for job_id, status in jobs.items()})
        for job_id, status in jobs.items():
            job = self.stored(job_id)
            self.assertEqual((job.status, job.archived_at, job.archived_from), (status, None, None))

    def test_a_job_archived_before_the_status_was_kept_falls_back(self):
        # Archived by the old code: no archived_from, so the status is read from the job, and a
        # cancelled one (completed_at set) still comes back as completed
        S = self.JobStatus
        for n, (error, expected) in enumerate(((None, S.COMPLETED), ("boom", S.FAILED))):
            job_id = self.ended_job(f"CASE-ARC-OLD{n}", S.CANCELLED, error)
            job = self.stored(job_id)
            job.status = S.ARCHIVED
            self.main.job_storage.save_job(job)
            self.assertIsNone(self.stored(job_id).archived_from)
            resp = self.client.post(f"/api/jobs/{job_id}/unarchive", headers=self.alice)
            self.assertEqual(resp.json()["status"], expected.value)


if __name__ == "__main__":
    unittest.main()
