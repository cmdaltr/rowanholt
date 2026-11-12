"""The manual SIEM export of a completed job: POST /api/jobs/{id}/export-siem queues the worker's
export_siem task (Elrond's --Index of the job's output), GET reads its progress and outcome.

The routes are driven through the real app in server mode (test_server_access.BackendCase), with
Redis a stand-in (the export's record and heartbeat live there, siem_export) and the task's queuing
mocked. The task runs for real in tasks_docker against a store of its own, with Elrond's process
replaced by one that prints what --Index prints, so its arguments, its log lines, its record and
the busy check can be seen while it runs.

Run: python3 -m unittest tests/unit/test_siem_export.py
"""

import fnmatch
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from test_server_access import BACKEND, BackendCase, TestClient
from test_job_liveness import FakeRedis as LivenessRedis

if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


class FakeRedis(LivenessRedis):
    """job_liveness's stand-in, with the GET and SCAN the export's record and busy check use."""

    def get(self, key):
        self._check()
        if not self._alive(key):
            return None
        value = self.store[key]
        return value.encode() if isinstance(value, str) else value

    def scan_iter(self, match="*", count=None):
        self._check()
        return iter([key for key in list(self.store) if self._alive(key) and fnmatch.fnmatch(key, match)])


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class SiemExportRoutes(BackendCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from models.job import JobStatus
        import siem_export
        cls.JobStatus, cls.se = JobStatus, siem_export

    def setUp(self):
        self.redis = FakeRedis()
        for target, attribute, value in ((self.se, "_redis", lambda: self.redis),
                                         (self.se, "_queued_task_ids", lambda ids: set())):
            patcher = mock.patch.object(target, attribute, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def completed_job(self, case: str, splunk: bool = True, elastic: bool = False) -> str:
        job_id = self.create_job(self.alice, case)
        stored = self.main.job_storage.get_job(job_id)
        stored.status = self.JobStatus.COMPLETED
        stored.options.splunk = splunk
        stored.options.elastic = elastic
        stored.progress = 100
        stored.result = {"output_directory": stored.destination_path, "hosts": 2}
        self.main.job_storage.save_job(stored)
        Path(stored.destination_path).mkdir(parents=True, exist_ok=True)
        return job_id

    def export(self, job_id: str, headers: dict):
        with mock.patch("tasks_docker.export_siem") as task:
            resp = self.client.post(f"/api/jobs/{job_id}/export-siem", headers=headers)
        return resp, task.apply_async

    def test_the_export_is_queued_and_answers_202(self):
        job_id = self.completed_job("CASE-SIEM-1", elastic=True)
        resp, queued = self.export(job_id, self.alice)
        self.assertEqual(resp.status_code, 202, resp.text)
        body = resp.json()
        self.assertEqual(body["state"], "queued")
        self.assertEqual(body["targets"], ["Splunk", "Elastic"])
        self.assertEqual(body["requested_by"], "alice")
        queued.assert_called_once_with(args=[job_id], task_id=body["task_id"])
        job = self.main.job_storage.get_job(job_id)
        self.assertTrue(job.log[-1].endswith("SIEM export into Splunk, Elastic queued by alice"))
        # Only a line appended: the worker-owned columns are as they were
        self.assertEqual((job.status, job.progress, job.result["hosts"]), (self.JobStatus.COMPLETED, 100, 2))
        [audit] = self.main.job_storage.audit_records(job_id, "job.siem_export")
        self.assertEqual(audit["username"], "alice")

    def test_a_second_export_while_one_is_queued_or_running_gets_409(self):
        job_id = self.completed_job("CASE-SIEM-2")
        first, _ = self.export(job_id, self.alice)
        self.assertEqual(first.status_code, 202, first.text)
        again, queued = self.export(job_id, self.alice)
        self.assertEqual(again.status_code, 409)
        queued.assert_not_called()

        task_id = first.json()["task_id"]
        self.se.update(job_id, task_id, client=self.redis, state="running")
        self.redis.set(self.se.heartbeat_key(job_id), "w", ex=60)
        again, queued = self.export(job_id, self.alice)
        self.assertEqual(again.status_code, 409)
        queued.assert_not_called()

        self.se.update(job_id, task_id, client=self.redis, state="succeeded")
        self.redis.delete(self.se.heartbeat_key(job_id))
        again, queued = self.export(job_id, self.alice)
        self.assertEqual(again.status_code, 202, again.text)
        queued.assert_called_once()

    def test_an_export_whose_worker_died_doesnt_block_the_next(self):
        job_id = self.completed_job("CASE-SIEM-3")
        first, _ = self.export(job_id, self.alice)
        self.se.update(job_id, first.json()["task_id"], client=self.redis, state="running")
        status = self.client.get(f"/api/jobs/{job_id}/export-siem", headers=self.alice).json()
        self.assertEqual(status["state"], "interrupted")
        self.assertIn("worker running this export stopped", status["error"])
        again, _ = self.export(job_id, self.alice)
        self.assertEqual(again.status_code, 202, again.text)

    def test_a_queued_export_lost_from_the_queue_is_interrupted_after_its_grace(self):
        job_id = self.completed_job("CASE-SIEM-4")
        first, _ = self.export(job_id, self.alice)
        task_id = first.json()["task_id"]
        self.assertEqual(self.se.status(job_id, self.redis)["state"], "queued")
        later = lambda: self.se.read(job_id, self.redis)["queued_epoch"] + 121  # noqa: E731
        self.assertEqual(self.se.status(job_id, self.redis, queued_ids=lambda ids: {task_id}, clock=later)["state"],
                         "queued")
        self.assertEqual(self.se.status(job_id, self.redis, queued_ids=lambda ids: set(), clock=later)["state"],
                         "interrupted")

    def test_the_status_shows_progress_then_the_outcome(self):
        job_id = self.completed_job("CASE-SIEM-5", elastic=True)
        self.assertEqual(self.client.get(f"/api/jobs/{job_id}/export-siem", headers=self.alice).json(),
                         {"state": "none"})
        task_id = self.export(job_id, self.alice)[0].json()["task_id"]
        self.redis.set(self.se.heartbeat_key(job_id), "w", ex=60)
        self.se.update(job_id, task_id, client=self.redis, state="running", phase="Elastic", step=2, steps=2)
        body = self.client.get(f"/api/jobs/{job_id}/export-siem", headers=self.alice).json()
        self.assertEqual((body["state"], body["phase"], body["step"], body["steps"]), ("running", "Elastic", 2, 2))
        self.assertNotIn("queued_epoch", body)
        results = {"Splunk": {"ok": True}, "Elastic": {"ok": False, "error": "refused"}}
        self.se.update(job_id, task_id, client=self.redis, state="failed", results=results)
        self.redis.delete(self.se.heartbeat_key(job_id))
        body = self.client.get(f"/api/jobs/{job_id}/export-siem", headers=self.alice).json()
        self.assertEqual((body["state"], body["results"]), ("failed", results))

    def test_only_a_completed_job_with_a_siem_option_and_its_folder_exports(self):
        no_siem = self.completed_job("CASE-SIEM-6", splunk=False)
        resp, queued = self.export(no_siem, self.alice)
        self.assertEqual(resp.status_code, 400)
        queued.assert_not_called()

        failed = self.completed_job("CASE-SIEM-7")
        self.main.job_storage.set_status(failed, self.JobStatus.FAILED)
        resp, queued = self.export(failed, self.alice)
        self.assertEqual(resp.status_code, 400)
        queued.assert_not_called()

        gone = self.completed_job("CASE-SIEM-8")
        Path(self.main.job_storage.get_job(gone).destination_path).rmdir()
        resp, queued = self.export(gone, self.alice)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("does not exist", resp.json()["detail"])
        queued.assert_not_called()
        self.assertIsNone(self.se.read(gone, self.redis))

    def test_whoever_can_see_the_job_may_export_it(self):
        # docs/API.md: the owner, the people it's shared with and admins; anyone else gets 404
        job_id = self.completed_job("CASE-SIEM-9")
        resp, queued = self.export(job_id, self.bob)
        self.assertEqual(resp.status_code, 404)
        queued.assert_not_called()
        self.assertEqual(self.client.get(f"/api/jobs/{job_id}/export-siem", headers=self.bob).status_code, 404)

        self.assertEqual(self.client.put(f"/api/jobs/{job_id}/sharing", headers=self.alice,
                                         json={"usernames": ["bob"]}).status_code, 200)
        for headers in (self.bob, self.admin):
            self.redis.delete(self.se.record_key(job_id))
            resp, queued = self.export(job_id, headers)
            self.assertEqual(resp.status_code, 202, resp.text)
            queued.assert_called_once()

    def test_a_smith_mcp_token_is_refused(self):
        job_id = self.completed_job("CASE-SIEM-10")
        resp = self.client.post("/api/auth/tokens", headers=self.alice,
                                json={"name": "Smith", "scope": "smith-mcp", "days": 30})
        self.assertEqual(resp.status_code, 200, resp.text)
        smith = {"Authorization": f"Bearer {resp.json()['token']}"}
        resp, queued = self.export(job_id, smith)
        self.assertEqual(resp.status_code, 403)
        queued.assert_not_called()

    def test_nothing_is_queued_without_redis(self):
        job_id = self.completed_job("CASE-SIEM-11")
        self.redis.down = True
        resp, queued = self.export(job_id, self.alice)
        self.assertEqual(resp.status_code, 503)
        queued.assert_not_called()

    def test_a_task_that_cant_be_queued_leaves_no_claim(self):
        job_id = self.completed_job("CASE-SIEM-12")
        with mock.patch("tasks_docker.export_siem") as task:
            task.apply_async.side_effect = ConnectionError("broker down")
            resp = self.client.post(f"/api/jobs/{job_id}/export-siem", headers=self.alice)
        self.assertEqual(resp.status_code, 503)
        self.assertIsNone(self.se.read(job_id, self.redis))

    def test_a_running_export_is_busy(self):
        import busy
        self.assertIs(busy._checks["siem-exports"], self.se.running)
        self.assertFalse(self.se.running())
        self.redis.set(self.se.heartbeat_key("some-job"), "w", ex=60)
        self.assertTrue(self.se.running())
        self.assertIn("siem-exports", busy.busy_reasons())
        self.redis.down = True
        with self.assertLogs(busy.logger, "ERROR"):
            self.assertIn("siem-exports", busy.busy_reasons())  # can't tell is busy


class ProgressTest(unittest.TestCase):
    """What Elrond's --Index output says happened (siem_export.Progress)."""

    @classmethod
    def setUpClass(cls):
        import siem_export
        cls.se = siem_export

    def test_phases_hosts_counts_and_failures(self):
        progress = self.se.Progress(["Splunk", "OpenSearch", "Navigator"])
        lines = [
            "\x1b[1;36m  ||  banner art  ||\x1b[1;m",
            "   Indexing 2 processed host(s): win10, ubuntu",
            "  -> \x1b[1;36mCommencing Splunk Phase...\x1b[1;m",
            "  ----------------------------------------",
            "     ERROR: Splunk indexing failed: Splunk wouldn't create index 'case' (500)",
            "  -> \x1b[1;36mCommencing OpenSearch Phase...\x1b[1;m",
            "     Indexed 120 records for 'win10' into OpenSearch",
            "     Indexed 30 records for 'ubuntu' into OpenSearch",
            " -> 2026-11-12 10:00:00 -> indexed 'prefetch' for 'win10'",
            "  -> \x1b[1;36mCommencing Navigator Phase...\x1b[1;m",
            "     Enterprise layer: 41 techniques",
        ]
        logged = [progress.feed(line) for line in lines]
        self.assertIsNone(logged[0])
        self.assertIsNone(logged[3])
        self.assertIsNone(logged[8])  # one per artefact: the full log only
        self.assertEqual(logged[1], "Indexing 2 processed host(s): win10, ubuntu")
        self.assertEqual(progress.hosts, ["win10", "ubuntu"])
        self.assertEqual(progress.step(), {"phase": "Navigator", "step": 3, "steps": 3})
        results = progress.results(1)
        self.assertEqual(results["Splunk"], {"ok": False, "error": "Splunk wouldn't create index 'case' (500)"})
        self.assertEqual(results["OpenSearch"], {"ok": True, "by_host": {"win10": 120, "ubuntu": 30}, "total": 150})
        self.assertEqual(results["Navigator"], {"ok": True, "techniques": 41})

    def test_a_run_that_stops_before_indexing_fails_every_target(self):
        progress = self.se.Progress(["Splunk", "Elastic"])
        progress.feed("  Error: Splunk at splunk:8089 is unreachable")
        results = progress.results(1)
        self.assertEqual(results, {name: {"ok": False, "error": "Splunk at splunk:8089 is unreachable"}
                                   for name in ("Splunk", "Elastic")})

    def test_the_command_is_elronds_index_with_the_jobs_targets(self):
        self.assertEqual(self.se.index_command("/opt/elrond-src/elrond.py", "CASE-1", "/out/CASE-1",
                                               ["Splunk", "Navigator"]),
                         ["python3", "/opt/elrond-src/elrond.py", "CASE-1", "/out/CASE-1", "--Index",
                          "--Splunk", "--Navigator"])
        options = mock.Mock(splunk=True, elastic=False, opensearch=True, timesketch=False, navigator=True)
        self.assertEqual(self.se.targets(options), ["Splunk", "OpenSearch", "Navigator"])

    def test_elastics_count_is_read_after_a_refresh(self):
        calls = []

        def opener(request, timeout):
            calls.append((request.get_method(), request.full_url, request.get_header("Authorization")))
            return io.BytesIO(json.dumps({"count": 4242}).encode())

        env = {"ELASTICSEARCH_HOST": "elastic", "ELASTIC_USERNAME": "elastic", "ELASTIC_PASSWORD": "pw"}
        self.assertEqual(self.se.elastic_count("CASE-1", env, opener), 4242)
        self.assertEqual([c[:2] for c in calls], [("POST", "http://elastic:9200/case-1/_refresh"),
                                                  ("GET", "http://elastic:9200/case-1/_count")])
        self.assertTrue(calls[0][2].startswith("Basic "))
        self.assertIsNone(self.se.elastic_count("CASE-1", {}, opener))


class FakeProcess:
    """Elrond's --Index as the worker sees it: its output, line by line, then its exit status.
    `during` runs before each line is read, to look at the world while the export is running."""

    def __init__(self, lines, returncode=0, during=None):
        self.lines, self.returncode, self.during = lines, returncode, during
        self.pid = 4242
        self.stdout = self._read()

    def _read(self):
        for line in self.lines:
            if self.during:
                self.during()
            yield line + "\n"

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode


def load_worker():
    """tasks_docker for real (Celery and Redis's client needed, not their servers)."""
    try:
        spec = importlib.util.spec_from_file_location("tasks_docker_for_siem", BACKEND / "tasks_docker.py")
        tasks = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tasks)
    except ImportError as exc:
        raise unittest.SkipTest(f"worker requirements not installed: {exc}")
    return tasks


INDEX_OUTPUT = [
    "   Indexing 1 processed host(s): win10",
    "  -> \x1b[1;36mCommencing Splunk Phase...\x1b[1;m",
    "     Data inputs configured for 1 image(s)",
    "  -> Completed Splunk Phase.",
    "  -> \x1b[1;36mCommencing Elastic Phase...\x1b[1;m",
    " -> 2026-11-12 10:00:00 -> indexed 'prefetch' for 'win10'",
    "     Elasticsearch ingestion complete",
    "  -> Completed Elastic Phase.",
]


class WorkerExportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tasks = load_worker()
        import storage
        from models.job import AnalysisOptions, Job, JobStatus
        cls.Job, cls.AnalysisOptions, cls.JobStatus = Job, AnalysisOptions, JobStatus
        cls.store = storage.JobStorage(f"sqlite:///{tempfile.mkdtemp(prefix='rowanholt-siem-')}/jobs.db")

    def setUp(self):
        self.se = self.tasks.siem_export
        self.redis = FakeRedis()
        self.elrond = Path(tempfile.mkdtemp(prefix="rowanholt-elrond-"))
        (self.elrond / "elrond.py").write_text("")
        self.popen = mock.Mock()
        for target, attribute, value in ((self.tasks, "job_storage", self.store),
                                         (self.se, "_redis", lambda: self.redis),
                                         (self.tasks.job_liveness, "_redis", lambda: self.redis),
                                         (self.se, "elastic_count", lambda case: 4242),
                                         (self.tasks.subprocess, "Popen", self.popen)):
            patcher = mock.patch.object(target, attribute, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.dict(os.environ, {"ELROND_HOME": str(self.elrond)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def queued(self, case="CASE-WORKER", elastic=True):
        """A completed job and the export the backend claimed for it: (job, task id)."""
        out = Path(tempfile.mkdtemp(prefix="rowanholt-case-")) / case
        out.mkdir()
        job = self.Job(id=f"job-{case}", case_number=case, source_paths=["/e/a.E01"], destination_path=str(out),
                       options=self.AnalysisOptions(splunk=True, elastic=elastic), status=self.JobStatus.COMPLETED,
                       progress=100, result={"output_directory": str(out), "hosts": 1}, log=["[t] -> done"])
        self.store.save_job(job)
        names = self.se.targets(job.options)
        record = self.se.claim(job.id, f"task-{case}", names, "alice", client=self.redis,
                               queued_ids=lambda ids: set())
        self.assertIsNotNone(record)
        return job, record["task_id"]

    def run_task(self, job, task_id):
        self.tasks.export_siem.push_request(id=task_id)
        try:
            return self.tasks.export_siem.run(job.id)
        finally:
            self.tasks.export_siem.pop_request()

    def test_elronds_index_runs_with_the_jobs_targets_and_succeeds(self):
        job, task_id = self.queued("CASE-W-1")
        seen = []

        def during():
            # While it runs: busy, and its record says running; a note lands in the log meanwhile
            seen.append((self.se.running(self.redis), self.se.status(job.id, self.redis)["state"]))
            if len(seen) == 3:
                self.store.transition(job.id, (self.JobStatus.COMPLETED,), self.JobStatus.COMPLETED,
                                      log_line="Note from bob: checking Splunk")

        self.popen.return_value = FakeProcess(INDEX_OUTPUT, during=during)
        outcome = self.run_task(job, task_id)

        cmd = self.popen.call_args.args[0]
        self.assertEqual(cmd, ["python3", str(self.elrond / "elrond.py"), "CASE-W-1", job.destination_path,
                               "--Index", "--Splunk", "--Elastic"])
        kwargs = self.popen.call_args.kwargs
        self.assertEqual(kwargs["cwd"], job.destination_path)
        self.assertEqual(kwargs["env"]["ELROND_NONINTERACTIVE"], "1")
        self.assertTrue(kwargs["env"]["PYTHONPATH"].startswith(str(self.elrond)))

        self.assertTrue(all(busy and state == "running" for busy, state in seen), seen)
        self.assertFalse(self.se.running(self.redis))
        self.assertEqual(outcome["state"], "succeeded")
        record = self.se.status(job.id, self.redis)
        self.assertEqual(record["state"], "succeeded")
        self.assertEqual(record["hosts"], ["win10"])
        self.assertEqual(record["results"]["Elastic"], {"ok": True, "total": 4242})
        self.assertTrue(record["results"]["Splunk"]["ok"])
        self.assertIn("index=case-w-1", record["results"]["Splunk"]["note"])

        stored = self.store.get_job(job.id)
        self.assertEqual((stored.status, stored.progress, stored.result["hosts"]), (self.JobStatus.COMPLETED, 100, 1))
        log = "\n".join(stored.log)
        self.assertIn("SIEM export started: Elrond --Index into Splunk, Elastic", log)
        self.assertIn("Commencing Splunk Phase", log)
        self.assertIn("Note from bob: checking Splunk", log)  # not clobbered by the export's lines
        self.assertNotIn("indexed 'prefetch'", log)
        self.assertTrue(stored.log[-1].endswith("SIEM export finished: indexed into Splunk, Elastic (Elastic 4,242)"))
        full = (Path(job.destination_path) / self.se.LOG_FILE).read_text()
        self.assertIn("indexed 'prefetch' for 'win10'", full)

    def test_a_failed_target_fails_the_export_and_says_why(self):
        job, task_id = self.queued("CASE-W-2")
        lines = INDEX_OUTPUT[:2] + ["     ERROR: Splunk indexing failed: Splunk kept losing the new index"] + INDEX_OUTPUT[3:]
        self.popen.return_value = FakeProcess(lines, returncode=1)
        outcome = self.run_task(job, task_id)
        self.assertEqual(outcome["state"], "failed")
        record = self.se.status(job.id, self.redis)
        self.assertEqual(record["results"]["Splunk"], {"ok": False, "error": "Splunk kept losing the new index"})
        self.assertTrue(record["results"]["Elastic"]["ok"])
        self.assertTrue(self.store.get_job(job.id).log[-1].endswith(
            "SIEM export failed: Splunk: Splunk kept losing the new index"))
        self.assertFalse(self.se.running(self.redis))

    def test_an_unreachable_siem_fails_every_target(self):
        job, task_id = self.queued("CASE-W-3")
        self.popen.return_value = FakeProcess(["  Error: Splunk at splunk:8089 is unreachable"], returncode=1)
        self.run_task(job, task_id)
        record = self.se.status(job.id, self.redis)
        self.assertEqual(record["state"], "failed")
        self.assertEqual(record["error"], "Splunk at splunk:8089 is unreachable")
        self.assertEqual({r["ok"] for r in record["results"].values()}, {False})

    def test_a_task_that_isnt_the_queued_export_does_nothing(self):
        job, task_id = self.queued("CASE-W-4")
        self.assertEqual(self.run_task(job, "someone-elses-task"), {"state": "skipped"})
        self.se.update(job.id, task_id, client=self.redis, state="succeeded")
        self.assertEqual(self.run_task(job, task_id), {"state": "skipped"})  # re-delivered
        self.popen.assert_not_called()

    def test_a_job_restarted_mid_export_stops_elrond(self):
        job, task_id = self.queued("CASE-W-5")
        restarted = []

        def during():
            if not restarted:
                self.store.set_status(job.id, self.JobStatus.PENDING)
                restarted.append(True)

        self.popen.return_value = FakeProcess(INDEX_OUTPUT, during=during)
        with mock.patch.object(self.tasks, "_stop_process_group") as stop:
            outcome = self.run_task(job, task_id)
        stop.assert_called_once()
        self.assertEqual(outcome["state"], "failed")
        self.assertIn("restarted, archived or deleted", outcome["error"])
        self.assertEqual(self.store.get_job(job.id).status, self.JobStatus.PENDING)

    def test_a_job_thats_no_longer_completed_isnt_exported(self):
        job, task_id = self.queued("CASE-W-6")
        self.store.set_status(job.id, self.JobStatus.ARCHIVED)
        outcome = self.run_task(job, task_id)
        self.assertEqual(outcome["state"], "failed")
        self.popen.assert_not_called()

    def test_a_crash_in_the_task_still_ends_the_record(self):
        job, task_id = self.queued("CASE-W-7")
        self.popen.side_effect = OSError("no python3")
        outcome = self.run_task(job, task_id)
        self.assertEqual(outcome["state"], "failed")
        self.assertEqual(self.se.status(job.id, self.redis)["error"], "no python3")
        self.assertFalse(self.se.running(self.redis))


if __name__ == "__main__":
    unittest.main()
