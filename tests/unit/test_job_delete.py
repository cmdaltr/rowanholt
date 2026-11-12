"""Deleting a job takes its case's rows with it, and nothing else (storage.delete_job).

DELETE /api/jobs/{id} and POST /api/jobs/bulk/delete used to remove the job's row and its sharing
only, leaving the case's findings, notes, host assignments and activity in the database where
nothing could reach them. The security log (audit_logs) stays, and records the deletion; nothing on
disk is touched. Driven through the real app in server mode (test_server_access.BackendCase).

Run: python3 -m unittest tests/unit/test_job_delete.py
"""

import unittest
from datetime import datetime
from pathlib import Path

from test_server_access import BackendCase, TestClient


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class JobDeleteTest(BackendCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import storage
        from models.job import JobStatus
        cls.storage, cls.JobStatus = storage, JobStatus
        cls.case_models = (storage.CaseFindingModel, storage.CaseNoteModel, storage.CaseHostModel,
                           storage.CaseActivityModel, storage.JobAccessModel)

    def finished_job_with_a_case(self, case: str) -> str:
        """A completed job with a row in every case table, an audit row, and output on disk."""
        job_id = self.create_job(self.alice, case)
        stored = self.main.job_storage.get_job(job_id)
        stored.status = self.JobStatus.COMPLETED
        self.main.job_storage.save_job(stored)
        out = Path(stored.destination_path)
        (out / "WS01" / "artefacts" / "cooked").mkdir(parents=True, exist_ok=True)
        (out / "WS01" / "artefacts" / "cooked" / "prefetch.csv").write_text("Executable\nCMD.EXE\n")
        s = self.storage
        now = datetime.now()
        session = self.main.job_storage.Session()
        try:
            finding = s.CaseFindingModel(job_id=job_id, host="WS01", artefact="prefetch", row_ref="1",
                                         row_hash="h", title="Odd binary", author="alice", created_at=now)
            session.add(finding)
            session.flush()
            session.add_all([
                s.CaseNoteModel(job_id=job_id, finding_id=finding.id, author="alice", body="Look at this"),
                s.CaseHostModel(job_id=job_id, host="WS01", assignee="alice"),
                s.CaseActivityModel(job_id=job_id, actor="alice", action="flagged", detail="Odd binary"),
            ])
            session.commit()
        finally:
            session.close()
        self.main.job_storage.audit("job.note_added", {"id": "x", "username": "alice"}, None, resource_id=job_id)
        return job_id

    def rows(self, job_id: str) -> dict:
        session = self.main.job_storage.Session()
        try:
            counts = {m.__tablename__: session.query(m).filter_by(job_id=job_id).count() for m in self.case_models}
            counts["jobs"] = session.query(self.storage.JobModel).filter_by(id=job_id).count()
            return counts
        finally:
            session.close()

    def files(self, job_id: str) -> list:
        out = Path(self.main.job_storage.get_job(job_id).destination_path)
        return sorted(str(p.relative_to(out)) for p in out.rglob("*"))

    def assert_deleted(self, job_id: str, kept: str, on_disk: list, out: Path) -> None:
        self.assertEqual(set(self.rows(job_id).values()), {0}, self.rows(job_id))
        # Another job's case is untouched
        self.assertTrue(all(self.rows(kept).values()), self.rows(kept))
        actions = [row["action"] for row in self.main.job_storage.audit_records(resource_id=job_id)]
        self.assertIn("job.note_added", actions)  # the security log survives the deletion
        self.assertIn("job.deleted", actions)
        deleted = [r for r in self.main.job_storage.audit_records(resource_id=job_id) if r["action"] == "job.deleted"]
        self.assertEqual(deleted[0]["username"], "alice")
        self.assertEqual(deleted[0]["details"]["removed"], {
            "jobs": 1, "job_access": 1, "case_findings": 1, "case_notes": 1, "case_hosts": 1, "case_activity": 1})
        # Nothing on disk is removed
        self.assertEqual(sorted(str(p.relative_to(out)) for p in out.rglob("*")), on_disk)

    def test_delete_takes_the_case_rows_and_keeps_the_audit_log_and_the_files(self):
        job_id = self.finished_job_with_a_case("CASE-DEL-1")
        kept = self.finished_job_with_a_case("CASE-DEL-2")
        self.assertTrue(all(self.rows(job_id).values()), self.rows(job_id))
        on_disk, out = self.files(job_id), Path(self.main.job_storage.get_job(job_id).destination_path)

        resp = self.client.delete(f"/api/jobs/{job_id}", headers=self.alice)
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assert_deleted(job_id, kept, on_disk, out)

    def test_bulk_delete_does_the_same(self):
        job_id = self.finished_job_with_a_case("CASE-DEL-3")
        kept = self.finished_job_with_a_case("CASE-DEL-4")
        on_disk, out = self.files(job_id), Path(self.main.job_storage.get_job(job_id).destination_path)

        resp = self.client.post("/api/jobs/bulk/delete", headers=self.alice, json=[job_id])
        self.assertEqual(resp.json()["results"], [{"job_id": job_id, "success": True}])
        self.assert_deleted(job_id, kept, on_disk, out)
        self.assertTrue(self.main.job_storage.audit_records(resource_id=job_id, action_prefix="job.deleted")[0]
                        ["details"]["bulk"])

    def test_a_refused_delete_leaves_everything(self):
        job_id = self.finished_job_with_a_case("CASE-DEL-5")
        before = self.rows(job_id)
        self.assertEqual(self.client.delete(f"/api/jobs/{job_id}", headers=self.bob).status_code, 404)
        self.assertEqual(self.rows(job_id), before)


if __name__ == "__main__":
    unittest.main()
