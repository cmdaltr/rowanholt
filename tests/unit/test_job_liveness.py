"""Whether a pending, running or paused job still has a worker (job_liveness.py): the worker's
heartbeat, the queued marker and the broker's queue, the failing of jobs left by a crash, and what
GET /api/busy makes of them (running and paused jobs only: a pending job waits out a rebuild in
Redis's queue), over the real backend in server mode.

Run: python3 -m unittest tests/unit/test_job_liveness.py
"""
import importlib.util
import sys
import tempfile
import threading
import time
import unittest
import uuid
from datetime import datetime
from unittest import mock

from test_server_access import BACKEND, BackendCase, TestClient


class Clock:
    """A clock the test moves by hand."""

    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class FakeRedis:
    """The few Redis commands job_liveness uses, with expiry on the given clock."""

    def __init__(self, clock=None) -> None:
        self.clock = clock or Clock()
        self.store, self.expires, self.lists, self.hashes = {}, {}, {}, {}
        self.sets = 0
        self.down = False

    def _alive(self, key):
        if key in self.expires and self.expires[key] <= self.clock():
            self.store.pop(key, None)
            self.expires.pop(key, None)
        return key in self.store

    def _check(self):
        if self.down:
            raise ConnectionError("Error 111 connecting to redis:6379. Connection refused.")

    def set(self, key, value, ex=None):
        self._check()
        self.sets += 1
        self.store[key] = value
        if ex is None:
            self.expires.pop(key, None)
        else:
            self.expires[key] = self.clock() + ex

    def delete(self, *keys):
        self._check()
        for key in keys:
            self.store.pop(key, None)
            self.expires.pop(key, None)

    def exists(self, key):
        self._check()
        return int(self._alive(key))

    def ttl(self, key):
        return self.expires[key] - self.clock() if self._alive(key) and key in self.expires else -1

    def lrange(self, key, start, end):
        self._check()
        return list(self.lists.get(key, []))

    def hvals(self, key):
        self._check()
        return list(self.hashes.get(key, {}).values())

    def flush(self):
        """Redis restarted without its data."""
        self.store.clear()
        self.expires.clear()

    def pipeline(self):
        redis, ops = self, []

        class Pipe:
            def __getattr__(self, name):
                return lambda *args, **kwargs: ops.append((name, args, kwargs))

            def execute(self):
                return [getattr(redis, name)(*args, **kwargs) for name, args, kwargs in ops]

        return Pipe()


def kombu_message(task_id: str) -> bytes:
    """A message as kombu's Redis transport stores it (shape trimmed)."""
    return ('{"body": "W1tdLCB7fV0=", "content-encoding": "utf-8", "headers": {"lang": "py", '
            f'"task": "tasks_docker.start_analysis", "id": "{task_id}", "root_id": "{task_id}"}}}}').encode()


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class LivenessCase(BackendCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import job_liveness
        import storage
        from models.job import AnalysisOptions, Job, JobStatus
        cls.lv, cls.Job, cls.JobStatus, cls.AnalysisOptions = job_liveness, Job, JobStatus, AnalysisOptions
        cls.store = storage.JobStorage(f"sqlite:///{tempfile.mkdtemp(prefix='rowanholt-live-')}/jobs.db")

    def setUp(self):
        self.clock = Clock()
        self.redis = FakeRedis(self.clock)
        self.broker = FakeRedis(self.clock)
        self.liveness = self.lv.Liveness(self.store, self.main.ACTIVE_JOB_STATUSES,
                                         client_factory=lambda: self.redis,
                                         broker_factory=lambda: self.broker, clock=self.clock)
        # The worker module is a stand-in here: record what's released for a failed job
        self.worker = mock.MagicMock()
        patcher = mock.patch.dict("sys.modules", {"tasks_docker": self.worker})
        patcher.start()
        self.addCleanup(patcher.stop)
        # Jobs from other tests in this store are done with
        for job_id, _, _ in self.store.active_jobs(self.main.ACTIVE_JOB_STATUSES):
            self.store.set_status(job_id, self.JobStatus.CANCELLED)

    def job(self, status, task_id=None):
        job = self.Job(id=str(uuid.uuid4()), case_number="CASE-LIVE", source_paths=["/e/live.E01"],
                       destination_path=None, options=self.AnalysisOptions(), status=status,
                       celery_task_id=task_id, log=["[2026-11-12 09:00:00] -> Starting rowanholt..."],
                       created_at=datetime.now())
        self.store.save_job(job)
        return job.id

    def beat(self, job_id):
        self.lv.Heartbeat(job_id, client=self.redis).beat()

    def wait(self, seconds):
        self.clock.now += seconds


class HeartbeatTest(LivenessCase):
    def test_a_beat_sets_the_key_with_its_ttl(self):
        self.beat("job-1")
        self.assertTrue(self.redis.exists(self.lv.heartbeat_key("job-1")))
        self.assertEqual(self.redis.ttl(self.lv.heartbeat_key("job-1")), self.lv.HEARTBEAT_TTL)

    def test_the_key_expires_on_its_own_when_the_beats_stop(self):
        self.beat("job-1")
        self.wait(self.lv.HEARTBEAT_TTL - 1)
        self.assertTrue(self.redis.exists(self.lv.heartbeat_key("job-1")))
        self.wait(2)
        self.assertFalse(self.redis.exists(self.lv.heartbeat_key("job-1")))

    def test_the_thread_refreshes_until_stopped_then_removes_the_key(self):
        heartbeat = self.lv.Heartbeat("job-2", client=self.redis, interval=0.01).start()
        deadline = time.monotonic() + 5
        while self.redis.sets < 4 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertGreaterEqual(self.redis.sets, 4)
        heartbeat.stop()
        self.assertFalse(heartbeat._thread.is_alive())
        self.assertFalse(self.redis.exists(self.lv.heartbeat_key("job-2")))
        sets = self.redis.sets
        time.sleep(0.05)
        self.assertEqual(self.redis.sets, sets)

    def test_refresh_interval_leaves_room_for_missed_beats(self):
        # A live job only looks dead after several refreshes in a row are missed, and the grace
        # outlasts a Redis restart's lost keys by several refreshes again
        self.assertGreaterEqual(self.lv.HEARTBEAT_TTL, 3 * self.lv.HEARTBEAT_INTERVAL)
        self.assertGreaterEqual(self.lv.STALE_GRACE, 3 * self.lv.HEARTBEAT_INTERVAL)

    def test_a_redis_thats_down_fails_fast(self):
        # Inside the homelab's five seconds, which it would read as idle
        quick = self.lv._quick()
        self.assertEqual(quick["retry"]._retries, 0)
        self.assertLessEqual(quick["socket_timeout"] + quick["socket_connect_timeout"], 2)

    def test_a_redis_error_is_logged_never_raised(self):
        self.redis.down = True
        heartbeat = self.lv.Heartbeat("job-3", client=self.redis, interval=60)
        with self.assertLogs(self.lv.logger, "WARNING"):
            self.assertFalse(heartbeat.beat())
        with self.assertLogs(self.lv.logger, "WARNING"):
            heartbeat.start().stop()

    def test_a_beat_after_a_redis_restart_brings_the_key_back(self):
        heartbeat = self.lv.Heartbeat("job-4", client=self.redis)
        heartbeat.beat()
        self.redis.flush()
        heartbeat.beat()
        self.assertTrue(self.redis.exists(self.lv.heartbeat_key("job-4")))

    def test_the_marker_lasts_the_queued_grace(self):
        self.lv.mark_queued("job-5", client=self.redis)
        self.assertEqual(self.redis.ttl(self.lv.queued_key("job-5")), self.lv.QUEUED_GRACE)
        self.redis.down = True
        with self.assertLogs(self.lv.logger, "WARNING"):
            self.lv.mark_queued("job-6", client=self.redis)


class ReconcileTest(LivenessCase):
    def test_nothing_active_needs_no_redis(self):
        self.redis.down = self.broker.down = True
        self.assertFalse(self.liveness.check())

    def test_a_running_job_with_a_heartbeat_is_live_and_left_alone(self):
        job_id = self.job(self.JobStatus.RUNNING)
        for _ in range(10):
            self.beat(job_id)
            self.assertTrue(self.liveness.check())
            self.wait(self.lv.HEARTBEAT_INTERVAL)
        job = self.store.get_job(job_id)
        self.assertEqual(job.status, self.JobStatus.RUNNING)
        self.assertIsNone(job.error)
        self.worker.release_image_locks_for_job.assert_not_called()

    def test_a_paused_job_with_a_heartbeat_is_live(self):
        job_id = self.job(self.JobStatus.PAUSED)
        self.beat(job_id)
        self.wait(self.lv.STALE_GRACE + 1)
        self.beat(job_id)
        self.assertTrue(self.liveness.check())
        self.assertEqual(self.store.get_job(job_id).status, self.JobStatus.PAUSED)

    def test_a_stale_running_job_is_failed_with_a_reason_after_the_grace(self):
        job_id = self.job(self.JobStatus.RUNNING)
        self.beat(job_id)
        self.wait(self.lv.HEARTBEAT_TTL + 1)  # the worker died; its key has expired
        self.assertTrue(self.liveness.check())  # first seen dead: not yet long enough to tell
        self.wait(self.lv.STALE_GRACE - 1)
        self.assertTrue(self.liveness.check())
        self.assertEqual(self.store.get_job(job_id).status, self.JobStatus.RUNNING)
        self.wait(1)
        self.assertFalse(self.liveness.check())
        job = self.store.get_job(job_id)
        self.assertEqual(job.status, self.JobStatus.FAILED)
        self.assertEqual(job.error, self.lv.RUNNING_REASON)
        self.assertTrue(job.log[-1].endswith(self.lv.RUNNING_REASON))
        self.assertEqual(job.log[0], "[2026-11-12 09:00:00] -> Starting rowanholt...")  # kept
        self.assertIsNotNone(job.completed_at)
        self.worker.release_image_locks_for_job.assert_called_once_with(job_id, ["/e/live.E01"])
        self.worker._clear_job_process.assert_called_once_with(job_id)

    def test_a_dead_job_beside_a_live_one(self):
        live, dead = self.job(self.JobStatus.RUNNING), self.job(self.JobStatus.RUNNING)
        self.beat(live)
        self.assertTrue(self.liveness.check())
        self.wait(self.lv.STALE_GRACE)
        self.beat(live)
        self.assertTrue(self.liveness.check())
        self.assertEqual(self.store.get_job(dead).status, self.JobStatus.FAILED)
        self.assertEqual(self.store.get_job(live).status, self.JobStatus.RUNNING)

    def test_a_redis_restart_doesnt_fail_live_jobs(self):
        job_id = self.job(self.JobStatus.RUNNING)
        self.beat(job_id)
        self.redis.flush()
        self.assertTrue(self.liveness.check())  # no key: suspect
        self.wait(self.lv.HEARTBEAT_INTERVAL)
        self.beat(job_id)  # the next refresh puts it back
        self.assertTrue(self.liveness.check())
        self.wait(self.lv.STALE_GRACE)
        self.beat(job_id)
        self.assertTrue(self.liveness.check())
        self.assertEqual(self.store.get_job(job_id).status, self.JobStatus.RUNNING)

    def test_a_pending_job_just_queued_is_live_but_not_busy(self):
        job_id = self.job(self.JobStatus.PENDING, task_id="task-just-queued")
        self.lv.mark_queued(job_id, client=self.redis)
        self.wait(self.lv.QUEUED_GRACE - 1)
        self.assertFalse(self.liveness.check())
        self.wait(self.lv.STALE_GRACE)  # the marker has lapsed: first seen with no signal, not failed yet
        self.liveness.check()
        self.assertEqual(self.store.get_job(job_id).status, self.JobStatus.PENDING)

    def test_a_pending_job_waiting_in_the_queue_is_live_for_hours_and_never_busy(self):
        # The queue is in Redis, which a rebuild leaves running: holding updates for it held them
        # for as long as the queue was
        task_id = str(uuid.uuid4())
        job_id = self.job(self.JobStatus.PENDING, task_id=task_id)
        self.broker.lists["celery"] = [kombu_message(str(uuid.uuid4())), kombu_message(task_id)]
        for _ in range(3):
            self.wait(3600)
            self.assertFalse(self.liveness.check())
        self.assertEqual(self.store.get_job(job_id).status, self.JobStatus.PENDING)

    def test_a_pending_job_in_a_priority_queue_or_delivered_is_live_but_not_busy(self):
        for where in ("priority", "unacked"):
            task_id = str(uuid.uuid4())
            job_id = self.job(self.JobStatus.PENDING, task_id=task_id)
            self.broker.lists, self.broker.hashes = {}, {}
            if where == "priority":
                self.broker.lists["celery\x06\x169"] = [kombu_message(task_id)]
            else:
                self.broker.hashes["unacked"] = {"tag-1": b'[' + kombu_message(task_id) + b', "", "celery"]'}
            self.wait(self.lv.STALE_GRACE + 1)
            self.assertFalse(self.liveness.check(), where)
            self.wait(self.lv.STALE_GRACE + 1)
            self.assertFalse(self.liveness.check(), where)
            self.assertEqual(self.store.get_job(job_id).status, self.JobStatus.PENDING, where)
            self.store.set_status(job_id, self.JobStatus.CANCELLED)

    def test_a_pending_job_waiting_for_image_locks_has_a_heartbeat(self):
        # Not busy itself: the job holding the locks it waits for is running, and that one is
        job_id = self.job(self.JobStatus.PENDING, task_id="task-taken")
        self.beat(job_id)
        self.wait(self.lv.STALE_GRACE + 1)
        self.beat(job_id)
        self.assertFalse(self.liveness.check())
        self.wait(self.lv.STALE_GRACE + 1)
        self.beat(job_id)
        self.liveness.check()
        self.assertEqual(self.store.get_job(job_id).status, self.JobStatus.PENDING)

    def test_only_the_running_job_beside_a_pending_one_is_busy(self):
        running, pending = self.job(self.JobStatus.RUNNING), self.job(self.JobStatus.PENDING, task_id="t")
        self.lv.mark_queued(pending, client=self.redis)
        self.beat(running)
        self.assertTrue(self.liveness.check())
        self.store.set_status(running, self.JobStatus.COMPLETED)
        self.assertFalse(self.liveness.check())
        self.assertEqual(self.store.get_job(pending).status, self.JobStatus.PENDING)

    def test_a_pending_job_with_nothing_queued_is_failed(self):
        job_id = self.job(self.JobStatus.PENDING, task_id=str(uuid.uuid4()))
        self.lv.mark_queued(job_id, client=self.redis)
        self.broker.lists["celery"] = [kombu_message(str(uuid.uuid4()))]  # someone else's
        self.wait(self.lv.QUEUED_GRACE + 1)
        self.assertFalse(self.liveness.check())  # suspect, and never busy
        self.wait(self.lv.STALE_GRACE - 1)
        self.liveness.check()
        self.assertEqual(self.store.get_job(job_id).status, self.JobStatus.PENDING)  # not yet
        self.wait(1)
        self.assertFalse(self.liveness.check())
        job = self.store.get_job(job_id)
        self.assertEqual(job.status, self.JobStatus.FAILED)
        self.assertEqual(job.error, self.lv.PENDING_REASON)
        self.assertTrue(job.log[-1].endswith(self.lv.PENDING_REASON))

    def test_a_pending_job_with_no_task_id_and_no_marker_is_failed(self):
        job_id = self.job(self.JobStatus.PENDING)
        self.liveness.check()
        self.wait(self.lv.STALE_GRACE)
        self.liveness.check()
        self.assertEqual(self.store.get_job(job_id).status, self.JobStatus.FAILED)

    def test_a_job_that_finished_meanwhile_is_left_as_it_is(self):
        job_id = self.job(self.JobStatus.RUNNING)
        self.store.set_status(job_id, self.JobStatus.COMPLETED)
        self.assertIsNone(self.store.interrupt_job(job_id, self.main.ACTIVE_JOB_STATUSES, "too late"))
        job = self.store.get_job(job_id)
        self.assertEqual(job.status, self.JobStatus.COMPLETED)
        self.assertIsNone(job.error)

    def test_a_job_that_comes_back_before_the_grace_is_forgiven(self):
        job_id = self.job(self.JobStatus.RUNNING)
        self.liveness.check()
        self.wait(self.lv.STALE_GRACE - 1)
        self.beat(job_id)
        self.liveness.check()
        self.wait(self.lv.STALE_GRACE - 1)
        self.redis.flush()
        self.liveness.check()  # missing again: the grace starts afresh
        self.wait(self.lv.STALE_GRACE - 1)
        self.assertTrue(self.liveness.check())
        self.assertEqual(self.store.get_job(job_id).status, self.JobStatus.RUNNING)

    def test_failing_a_job_sends_its_webhook(self):
        import webhooks
        job_id = self.job(self.JobStatus.RUNNING)
        with mock.patch.object(webhooks, "emit_job") as emit:
            self.liveness.check()
            self.wait(self.lv.STALE_GRACE)
            self.liveness.check()
        emit.assert_called_once()
        self.assertEqual(emit.call_args.args[0].id, job_id)

    def test_redis_unreachable_raises_so_busy_says_busy(self):
        self.job(self.JobStatus.RUNNING)
        self.redis.down = True
        with self.assertRaises(ConnectionError):
            self.liveness.check()
        self.liveness.grace = 0
        with self.assertLogs(self.lv.logger, "ERROR"):
            self.liveness.reconcile()  # the background pass logs and carries on

    def test_the_background_loop_reconciles_at_start_and_on_its_interval(self):
        passes = threading.Semaphore(0)
        with mock.patch.object(self.liveness, "check", side_effect=lambda: passes.release()):
            stop = self.liveness.start(interval=0.01)
            try:
                for _ in range(3):
                    self.assertTrue(passes.acquire(timeout=5))
            finally:
                stop.set()

    def test_a_pass_is_quick(self):
        for _ in range(50):
            self.beat(self.job(self.JobStatus.RUNNING))
        started = time.monotonic()
        self.assertTrue(self.liveness.check())
        self.assertLess(time.monotonic() - started, 0.5)


class BusyEndpointTest(LivenessCase):
    def setUp(self):
        super().setUp()
        quiet = mock.patch.dict(self.main.busy._checks, {name: (lambda: False) for name in self.main.busy._checks})
        quiet.start()
        self.addCleanup(quiet.stop)
        self.main.busy.register("jobs", self.liveness.check)

    def test_busy_ignores_a_job_left_running_by_a_crash(self):
        job_id = self.job(self.JobStatus.RUNNING)
        self.assertEqual(self.client.get("/api/busy").json(), {"busy": True})
        self.wait(self.lv.STALE_GRACE)
        self.assertEqual(self.client.get("/api/busy").json(), {"busy": False})
        self.assertEqual(self.store.get_job(job_id).status, self.JobStatus.FAILED)

    def test_a_queued_job_doesnt_hold_a_rebuild(self):
        task_id = str(uuid.uuid4())
        job_id = self.job(self.JobStatus.PENDING, task_id=task_id)
        self.lv.mark_queued(job_id, client=self.redis)
        self.assertEqual(self.client.get("/api/busy").json(), {"busy": False})
        self.broker.lists["celery"] = [kombu_message(task_id)]
        self.wait(self.lv.QUEUED_GRACE + self.lv.STALE_GRACE)
        self.assertEqual(self.client.get("/api/busy").json(), {"busy": False})
        self.assertEqual(self.store.get_job(job_id).status, self.JobStatus.PENDING)

    def test_busy_while_a_paused_job_has_its_heartbeat(self):
        job_id = self.job(self.JobStatus.PAUSED)
        self.beat(job_id)
        self.assertEqual(self.client.get("/api/busy").json(), {"busy": True})

    def test_busy_while_the_worker_beats(self):
        job_id = self.job(self.JobStatus.RUNNING)
        self.wait(self.lv.STALE_GRACE)
        self.beat(job_id)
        self.assertEqual(self.client.get("/api/busy").json(), {"busy": True})

    def test_busy_says_busy_when_redis_cant_be_read(self):
        self.job(self.JobStatus.RUNNING)
        self.redis.down = True
        with self.assertLogs(self.main.busy.logger, "ERROR"):
            self.assertEqual(self.client.get("/api/busy").json(), {"busy": True})

    def test_the_backend_checks_its_own_jobs_with_liveness(self):
        self.assertIs(self.main.job_liveness_check.storage, self.main.job_storage)
        self.assertEqual(self.main.job_liveness_check.statuses, self.main.ACTIVE_JOB_STATUSES)


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class QueueingTest(BackendCase):
    """Every way a job is queued goes through main.queue_job."""

    def setUp(self):
        import job_liveness
        from models.job import JobStatus
        self.lv, self.JobStatus = job_liveness, JobStatus
        self.redis = FakeRedis()
        patcher = mock.patch.object(job_liveness, "_client", self.redis)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_new_job_is_marked_queued_and_keeps_its_task_id(self):
        job_id = self.create_job(self.alice, "CASE-QUEUED")
        self.assertTrue(self.redis.exists(self.lv.queued_key(job_id)))
        job = self.main.job_storage.get_job(job_id)
        self.assertEqual(job.status, self.JobStatus.PENDING)
        self.assertEqual(job.celery_task_id, "celery-task")

    def test_the_task_id_save_doesnt_undo_the_workers_progress(self):
        # The worker can pick the task up and save before the API records the task's ID
        def worker_starts(job_id):
            self.main.job_storage.set_status(job_id, self.JobStatus.RUNNING)
            return mock.Mock(id="celery-fast")
        with mock.patch.object(self.main.start_analysis, "delay", side_effect=worker_starts):
            job_id = self.create_job(self.alice, "CASE-FAST")
        job = self.main.job_storage.get_job(job_id)
        self.assertEqual(job.status, self.JobStatus.RUNNING)
        self.assertEqual(job.celery_task_id, "celery-fast")

    def test_a_job_that_cant_be_queued_is_failed_not_left_pending(self):
        source = self.evidence / "CASE-NOQUEUE.E01"
        source.write_bytes(b"")
        with mock.patch.object(self.main.start_analysis, "delay", side_effect=ConnectionError("redis down")):
            resp = self.client.post("/api/jobs", headers=self.alice, json={
                "case_number": "CASE-NOQUEUE", "source_paths": [str(source)],
                "destination_path": str(self.evidence / "out" / "CASE-NOQUEUE")})
        self.assertEqual(resp.status_code, 500)
        jobs = [job for job in self.main.job_storage.list_jobs(limit=500) if job.case_number == "CASE-NOQUEUE"]
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0].status, self.JobStatus.FAILED)
        self.assertIn("Not queued: redis down", jobs[0].error)

    def awaiting(self, case):
        job_id = self.create_job(self.admin, case)
        store = self.main.job_storage
        job = store.get_job(job_id)
        job.status = self.JobStatus.AWAITING_CONFIRMATION
        job.celery_task_id = "celery-finished-task"
        store.save_job(job)
        self.redis.flush()

        def confirm(job_id):  # what tasks_docker.confirm_sudo_action does once rm -rf succeeds
            job = store.get_job(job_id)
            job.status, job.pending_action = self.JobStatus.PENDING, None
            store.save_job(job)
            return True
        return job_id, confirm

    def test_sudo_removal_queues_the_restart(self):
        job_id, confirm = self.awaiting("CASE-SUDO")
        with mock.patch("tasks_docker.confirm_sudo_action", side_effect=confirm), \
                mock.patch.object(self.main.start_analysis, "delay", return_value=mock.Mock(id="celery-again")) as delay:
            resp = self.client.post(f"/api/jobs/{job_id}/confirm-sudo", headers=self.admin)
        self.assertEqual(resp.status_code, 200, resp.text)
        delay.assert_called_once_with(job_id)
        job = self.main.job_storage.get_job(job_id)
        self.assertEqual(job.status, self.JobStatus.PENDING)
        self.assertEqual(job.celery_task_id, "celery-again")
        self.assertTrue(self.redis.exists(self.lv.queued_key(job_id)))

    def test_sudo_removal_that_cant_requeue_fails_the_job(self):
        job_id, confirm = self.awaiting("CASE-SUDO-NOQUEUE")
        with mock.patch("tasks_docker.confirm_sudo_action", side_effect=confirm), \
                mock.patch.object(self.main.start_analysis, "delay", side_effect=ConnectionError("redis down")):
            resp = self.client.post(f"/api/jobs/{job_id}/confirm-sudo", headers=self.admin)
        self.assertEqual(resp.status_code, 500)
        job = self.main.job_storage.get_job(job_id)
        self.assertEqual(job.status, self.JobStatus.FAILED)
        self.assertIn("Not queued", job.error)

    def test_no_route_queues_a_job_but_through_queue_job(self):
        source = (BACKEND / "main.py").read_text()
        self.assertEqual(source.count("start_analysis.delay("), 1)


class WorkerHeartbeatTest(unittest.TestCase):
    """start_analysis beats from its start to after its final save, however the job ends."""

    def test_the_heartbeat_outlasts_the_final_save(self):
        if str(BACKEND) not in sys.path:  # run on its own, before any backend test loaded it
            sys.path.insert(0, str(BACKEND))
        try:
            spec = importlib.util.spec_from_file_location("tasks_docker_for_liveness", BACKEND / "tasks_docker.py")
            tasks = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(tasks)
        except ImportError as exc:
            self.skipTest(f"worker requirements not installed: {exc}")
        from models.job import AnalysisOptions, Job

        events = []
        job = Job(id="job-w", case_number="CASE-W", source_paths=[], destination_path="/tmp/x",
                  options=AnalysisOptions())

        class Beat:
            def __init__(self, job_id):
                events.append(("heartbeat", job_id))

            def start(self):
                events.append("start")
                return self

            def stop(self):
                events.append("stop")

        storage = mock.Mock()
        storage.get_job.return_value = job
        storage.save_job.side_effect = lambda saved: events.append(("save", saved.status.value))
        with mock.patch.object(tasks, "job_storage", storage), \
                mock.patch.object(tasks.job_liveness, "Heartbeat", Beat), \
                mock.patch.object(tasks, "build_elrond_command", side_effect=RuntimeError("boom")), \
                mock.patch.object(tasks, "_clear_job_process"):
            tasks.start_analysis("job-w")
        self.assertEqual(events[:2], [("heartbeat", "job-w"), "start"])
        self.assertEqual(events[-2:], [("save", "failed"), "stop"])
        self.assertEqual(events.count("stop"), 1)


if __name__ == "__main__":
    unittest.main()
