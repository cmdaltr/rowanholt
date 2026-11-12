"""GET /api/busy, the homelab's question before a rebuild (busy.py): the registry and each check,
then the endpoint over the real backend in server mode: no sign-in, one bit of answer.

Run: python3 -m unittest tests/unit/test_busy.py
"""
import asyncio
import tempfile
import unittest
import uuid
from pathlib import Path
from datetime import datetime
from unittest import mock

from test_server_access import BackendCase, TestClient


def _quiet(busy):
    """Every registered check saying idle, so a test turns on only the one it's about."""
    return mock.patch.dict(busy._checks, {name: (lambda: False) for name in busy._checks})


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class Registry(BackendCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.busy = cls.main.busy

    def test_reasons_are_the_names_of_checks_that_say_busy(self):
        with _quiet(self.busy):
            self.busy.register("one", lambda: True)
            self.busy.register("two", lambda: False)
            self.assertEqual(self.busy.busy_reasons(), ["one"])

    def test_a_check_that_raises_counts_as_busy(self):
        def broken():
            raise RuntimeError("database unreachable")
        with _quiet(self.busy):
            self.busy.register("broken", broken)
            with self.assertLogs(self.busy.logger, "ERROR"):
                self.assertEqual(self.busy.busy_reasons(), ["broken"])

    def test_unregister(self):
        with _quiet(self.busy):
            self.busy.register("gone", lambda: True)
            self.busy.unregister("gone")
            self.busy.unregister("never-there")
            self.assertEqual(self.busy.busy_reasons(), [])

    def test_the_backend_registers_its_checks(self):
        self.assertLessEqual({"jobs", "requests", "downloads", "side-tasks", "telemetry-build"},
                             set(self.busy._checks))


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class Checks(BackendCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.busy = cls.main.busy

    def test_jobs_queued_running_or_paused_are_busy(self):
        import storage
        from models.job import AnalysisOptions, Job, JobStatus
        folder = tempfile.mkdtemp(prefix="rowanholt-busy-")
        store = storage.JobStorage(f"sqlite:///{folder}/jobs.db")
        active = self.main.ACTIVE_JOB_STATUSES
        self.assertFalse(store.any_job_in(active))
        job = Job(id=str(uuid.uuid4()), case_number="CASE-BUSY", source_paths=["/e/x.E01"],
                  destination_path=None, options=AnalysisOptions(), status=JobStatus.COMPLETED,
                  created_at=datetime.now())
        store.save_job(job)
        for status in JobStatus:
            store.set_status(job.id, status)
            self.assertEqual(store.any_job_in(active), status in active, status)
        for idle in (JobStatus.AWAITING_CONFIRMATION, JobStatus.FAILED, JobStatus.ARCHIVED):
            self.assertNotIn(idle, active)

    def test_the_jobs_check_asks_the_backends_storage(self):
        with mock.patch.object(self.main.job_storage, "any_job_in", return_value=True) as asked:
            self.assertTrue(self.busy._checks["jobs"]())
        asked.assert_called_once_with(self.main.ACTIVE_JOB_STATUSES)

    def test_a_counter_is_busy_while_work_is_in_flight(self):
        counter = self.busy.Counter()
        self.assertFalse(counter())
        with counter.working():
            with counter.working():
                self.assertTrue(counter())
            self.assertTrue(counter())
        self.assertFalse(counter())
        with self.assertRaises(ValueError), counter.working():
            raise ValueError("a failed download still ends")
        self.assertFalse(counter())

    def test_queued_tasks_are_busy_until_their_result_is_ready(self):
        ready = {"t-1": False}
        tasks = self.busy.QueuedTasks(lambda task_id: mock.Mock(ready=lambda: ready[task_id]))
        self.assertFalse(tasks())
        tasks.add("t-1")
        self.assertTrue(tasks())
        ready["t-1"] = True
        self.assertFalse(tasks())

    def test_a_task_with_no_result_is_forgotten_after_its_maximum_age(self):
        tasks = self.busy.QueuedTasks(lambda task_id: mock.Mock(ready=lambda: False), max_age=60)
        with mock.patch.object(self.busy.time, "monotonic", return_value=1000.0):
            tasks.add("lost")
        with mock.patch.object(self.busy.time, "monotonic", return_value=1059.0):
            self.assertTrue(tasks())
        with mock.patch.object(self.busy.time, "monotonic", return_value=1061.0), \
                self.assertLogs(self.busy.logger):
            self.assertFalse(tasks())

    def test_the_middleware_counts_mutating_api_requests_only(self):
        seen = []

        async def call_next(request):
            seen.append(self.busy.requests_in_flight())
            return "response"

        def request(method, path):
            return mock.Mock(method=method, url=mock.Mock(path=path))

        for method, path, counted in (("POST", "/api/jobs", True), ("DELETE", "/api/jobs/x", True),
                                      ("PUT", "/api/lab/config", True), ("GET", "/api/jobs", False),
                                      ("HEAD", "/api/health", False), ("POST", "/static/x", False)):
            seen.clear()
            answer = asyncio.run(self.busy.middleware(request(method, path), call_next))
            self.assertEqual(answer, "response")
            self.assertEqual(seen, [counted], (method, path))
            self.assertFalse(self.busy.requests_in_flight())

    def test_a_signed_in_post_is_counted_while_its_handled(self):
        seen = []
        with mock.patch.object(self.main.job_storage, "save_job",
                               side_effect=lambda job: seen.append(self.busy.requests_in_flight())):
            self.create_job(self.admin, "CASE-INFLIGHT")
        self.assertTrue(seen and all(seen))
        self.assertFalse(self.busy.requests_in_flight())

    def test_a_refused_request_is_never_counted(self):
        # The counter sits inside access's middleware: without an account, nothing holds a rebuild
        with mock.patch.object(self.busy.requests_in_flight, "working") as working:
            self.assertEqual(self.client.post("/api/jobs", json={}).status_code, 401)
        working.assert_not_called()

    def test_a_symbol_table_upload_is_tracked_until_the_worker_finishes(self):
        import symbol_routes
        task = mock.Mock(id="sym-1")
        folder = Path(tempfile.mkdtemp(prefix="rowanholt-busy-"))
        with mock.patch.object(symbol_routes, "SYMBOLS_DIR", folder), \
                mock.patch("tasks_docker.add_symbol_table.delay", return_value=task), \
                mock.patch.object(self.busy.side_tasks, "add") as add:
            resp = self.client.post("/api/symbols/add", headers=self.admin, data={"kind": "kdk"},
                                    files={"file": ("kernel", b"macho"),
                                           "dwarf": ("kernel", b"dwarf")})
        self.assertEqual(resp.status_code, 200, resp.text)
        add.assert_called_once_with("sym-1")

    def test_a_sample_fetch_is_tracked_until_the_worker_finishes(self):
        task = mock.Mock(id="sample-1")
        with mock.patch("tasks_docker.fetch_sample.delay", return_value=task), \
                mock.patch.object(self.busy.side_tasks, "add") as add:
            resp = self.client.post("/api/samples/ios17/fetch", headers=self.admin)
        self.assertEqual(resp.status_code, 200, resp.text)
        add.assert_called_once_with("sample-1")

    def test_a_telemetry_build_is_busy_while_it_runs(self):
        import mordor_routes
        with mock.patch.dict(mordor_routes._build_job, {"state": "running"}):
            self.assertTrue(self.busy._checks["telemetry-build"]())
        for state in ("idle", "done", "error"):
            with mock.patch.dict(mordor_routes._build_job, {"state": state}):
                self.assertFalse(self.busy._checks["telemetry-build"](), state)


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class Endpoint(BackendCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.busy = cls.main.busy

    def test_idle(self):
        with _quiet(self.busy):
            resp = self.client.get("/api/busy")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"busy": False})

    def only_jobs(self):
        """Every check idle but the backend's real jobs check."""
        jobs = self.busy._checks["jobs"]
        quiet = _quiet(self.busy)
        quiet.start()
        self.addCleanup(quiet.stop)
        self.busy.register("jobs", jobs)

    def test_busy_while_a_job_is_active(self):
        self.only_jobs()
        with mock.patch.object(self.main.job_storage, "any_job_in", return_value=False):
            self.assertEqual(self.client.get("/api/busy").json(), {"busy": False})
        with mock.patch.object(self.main.job_storage, "any_job_in", return_value=True):
            self.assertEqual(self.client.get("/api/busy").json(), {"busy": True})

    def test_busy_with_the_real_jobs_table(self):
        # Jobs here never reach a worker (the queue is a stand-in), so a new one stays pending
        self.only_jobs()
        self.create_job(self.alice, "CASE-PENDING")
        self.assertEqual(self.client.get("/api/busy").json(), {"busy": True})

    def test_a_failing_check_counts_as_busy(self):
        self.only_jobs()
        down = OSError("connection refused")
        with mock.patch.object(self.main.job_storage, "any_job_in", side_effect=down), \
                self.assertLogs(self.busy.logger, "ERROR"):
            resp = self.client.get("/api/busy")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"busy": True})

    def test_no_sign_in_needed_in_server_mode(self):
        self.assertTrue(self.settings.rowanholt_server_mode)
        self.client.cookies.clear()
        with _quiet(self.busy):
            resp = self.client.get("/api/busy")
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(self.client.get("/api/jobs").status_code, 401)

    def test_nothing_about_the_work_leaks(self):
        with _quiet(self.busy):
            self.busy.register("case CASE-SECRET-42 for alice", lambda: True)
            with self.assertLogs(self.main.logger, "INFO") as logs:
                resp = self.client.get("/api/busy")
        self.assertEqual(resp.json(), {"busy": True})
        self.assertEqual(resp.content, b'{"busy":true}')
        self.assertNotIn("SECRET", resp.text + str(dict(resp.headers)))
        # The reason is for whoever reads the server's log, not the caller
        self.assertTrue(any("CASE-SECRET-42" in line for line in logs.output))


if __name__ == "__main__":
    unittest.main()
