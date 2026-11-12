"""Image locks: a job releases only the locks it took, and only while they're still its own.

Run: python3 -m unittest tests/unit/test_image_locks.py
"""

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

BACKEND = Path(__file__).resolve().parents[2] / "src" / "web" / "backend"


def load_worker():
    if str(BACKEND) not in sys.path:
        sys.path.insert(0, str(BACKEND))
    try:
        spec = importlib.util.spec_from_file_location("tasks_docker_for_locks", BACKEND / "tasks_docker.py")
        tasks = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tasks)
    except ImportError as exc:
        raise unittest.SkipTest(f"worker requirements not installed: {exc}")
    return tasks


class FakeRedis:
    """SET NX, GET, DEL and the worker's two scripts, run here as Redis would run them: the
    value check and the change in one step (checked against Redis 7 on 12 November 2026)."""

    def __init__(self, tasks) -> None:
        self.tasks = tasks
        self.store = {}

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.store:
            return None
        self.store[key] = value.encode()
        return True

    def get(self, key):
        return self.store.get(key)

    def delete(self, *keys):
        for key in keys:
            self.store.pop(key, None)

    def eval(self, script, numkeys, key, *args):
        value = self.store.get(key, b"").decode() or None
        if script == self.tasks._RELEASE_IF_HELD:
            owner, mode = args
            if value and (value == owner or (mode == "prefix" and value.startswith(owner))):
                del self.store[key]
                return 1
            return 0
        if script == self.tasks._REFRESH_IF_HELD:
            return int(value == args[0])
        raise AssertionError("unknown script")

    def holder(self, key):
        value = self.store.get(key)
        return value.decode().split(":")[0] if value else None


class ImageLockTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tasks = load_worker()
        from models.job import AnalysisOptions, Job, JobStatus
        cls.Job, cls.AnalysisOptions, cls.JobStatus = Job, AnalysisOptions, JobStatus

    def setUp(self):
        self.redis = FakeRedis(self.tasks)
        self.x = self.tasks._get_image_lock_key("/e/x.E01")
        self.y = self.tasks._get_image_lock_key("/e/y.E01")
        self.redis.set(self.x, "job-a:2026-11-12T10:00:00", nx=True)  # job A is using X
        for target, attribute, value in ((self.tasks, "get_redis_client", lambda: self.redis),
                                         (self.tasks.time, "sleep", lambda seconds: None)):
            patcher = mock.patch.object(target, attribute, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_a_job_cancelled_while_waiting_releases_only_what_it_took(self):
        # Job B wants Y then X, takes Y, waits for A's X and is cancelled while it waits
        job = self.Job(id="job-b", case_number="CASE-B", source_paths=["/e/y.E01", "/e/x.E01"],
                       destination_path="/tmp/b", options=self.AnalysisOptions(), status=self.JobStatus.PENDING)
        waited = []
        storage = mock.Mock()
        # Pending until it has waited once for X, then cancelled (POST /cancel meanwhile)
        storage.get_job.side_effect = lambda job_id: job.model_copy(
            update={"status": self.JobStatus.CANCELLED if waited else self.JobStatus.PENDING})
        with mock.patch.object(self.tasks, "job_storage", storage), \
                mock.patch.object(self.tasks.time, "sleep", lambda seconds: waited.append(seconds)), \
                mock.patch.object(self.tasks.job_liveness, "Heartbeat"), \
                mock.patch.object(self.tasks, "_clear_job_process"):
            self.tasks.start_analysis("job-b")
        self.assertEqual(len(waited), 1)
        self.assertEqual(self.redis.holder(self.x), "job-a")
        self.assertIsNone(self.redis.holder(self.y))
        storage.transition.assert_not_called()  # never ran

    def test_a_lock_that_expired_and_was_taken_by_another_job_is_left_alone(self):
        held = {}
        self.assertTrue(self.tasks.acquire_image_locks("job-b", ["/e/y.E01"], held=held))
        self.redis.store[self.y] = b"job-c:2026-11-12T11:00:00"  # B's expired; C has it now
        self.tasks.release_image_locks(held)
        self.assertEqual(self.redis.holder(self.y), "job-c")
        self.assertEqual(held, {})

    def test_cancelling_a_job_releases_its_locks_and_no_one_elses(self):
        self.redis.set(self.y, "job-b:2026-11-12T10:05:00", nx=True)
        self.tasks.release_image_locks_for_job("job-b", ["/e/x.E01", "/e/y.E01"])
        self.assertEqual(self.redis.holder(self.x), "job-a")
        self.assertIsNone(self.redis.holder(self.y))
        self.tasks.release_image_locks_for_job("job-", ["/e/x.E01"])  # a prefix of A's id isn't A's
        self.assertEqual(self.redis.holder(self.x), "job-a")

    def test_the_same_image_twice_doesnt_wait_for_itself(self):
        held = {}
        self.assertTrue(self.tasks.acquire_image_locks("job-b", ["/e/y.E01", "/e/y.E01"], held=held))
        self.assertEqual(list(held), [self.y])

    def test_the_heartbeat_extends_only_the_jobs_own_locks(self):
        held = {self.x: "job-b:2026-11-12T09:00:00"}  # B's lock on X expired and A took it
        with mock.patch.object(self.redis, "eval", wraps=self.redis.eval) as run:
            self.tasks._refresh_image_locks(held)
        run.assert_called_once_with(self.tasks._REFRESH_IF_HELD, 1, self.x, held[self.x], self.tasks.IMAGE_LOCK_TTL)
        self.assertEqual(self.redis.holder(self.x), "job-a")


if __name__ == "__main__":
    unittest.main()
