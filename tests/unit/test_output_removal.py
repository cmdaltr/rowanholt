"""Removing a job's old output: the paths the API accepts, which folder the worker may remove, who
may confirm a retry, and the cross-site header (the 12 November 2026 review).

Run: python3 -m unittest tests/unit/test_output_removal.py
"""

import importlib.util
import os
import sys
import tempfile
import unittest
import uuid
from datetime import datetime
from pathlib import Path
from unittest import mock

from test_server_access import BACKEND, BackendCase, TestClient, TMP

if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

import output_removal as orm  # noqa: E402
from models.job import AnalysisOptions, Job, JobStatus, PendingAction  # noqa: E402

REPO = BACKEND.parents[2]


def make_job(dest, sources=(), status=JobStatus.COMPLETED, marker=True, case="CASE-RM-1", **options):
    return Job(id=str(uuid.uuid4()), case_number=case, source_paths=[str(s) for s in sources],
               destination_path=str(dest) if dest else None,
               options=AnalysisOptions(output_marker=marker, **options), status=status, created_at=datetime.now())


class Folders(unittest.TestCase):
    """An allowed folder with evidence in it, in a temporary directory of its own."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rowanholt-removal-"))
        self.root = self.tmp / "evidence"
        (self.root / "client-a").mkdir(parents=True)
        self.image = self.root / "client-a" / "disk.E01"
        self.image.write_bytes(b"evidence")
        self.roots = [str(self.root)]

    def output(self, job, name="out", files=3, marker=True):
        folder = self.root / name
        (folder / "cooked").mkdir(parents=True, exist_ok=True)
        for index in range(files):
            (folder / "cooked" / f"{index}.csv").write_text("a,b\n")
        if marker:
            orm.write_marker(folder, job.id)
        return folder


class ContainmentTest(Folders):
    def refused(self, path, **kwargs):
        with self.assertRaises(orm.PathRefused, msg=str(path)):
            orm.contained(path, self.roots, **kwargs)

    def test_an_allowed_folder_itself_and_anything_above_it_is_refused(self):
        self.refused(self.root)
        self.refused(f"{self.root}/")
        self.refused(self.tmp)

    def test_a_sibling_with_the_same_prefix_is_outside(self):
        sibling = Path(f"{self.root}X")
        sibling.mkdir()
        self.refused(sibling / "case")
        self.refused(sibling, allow_root=True)

    def test_dot_dot_is_refused_even_when_it_stays_inside(self):
        self.refused(f"{self.root}/client-a/../client-a/case")
        self.refused(f"{self.root}/../evidence/case")

    def test_a_symbolic_link_below_the_allowed_folder_is_refused(self):
        outside = self.tmp / "elsewhere"
        outside.mkdir()
        (self.root / "link").symlink_to(outside)
        self.refused(self.root / "link" / "case")
        self.refused(self.root / "link", allow_root=True)

    def test_relative_and_empty_paths_are_refused(self):
        self.refused("evidence/case")
        self.refused("")

    def test_a_folder_inside_is_accepted_normalised(self):
        self.assertEqual(orm.contained(f"{self.root}//client-a/./case", self.roots), self.root / "client-a" / "case")
        # A source may be a whole allowed folder: reading it removes nothing
        self.assertEqual(orm.contained(self.root, self.roots, allow_root=True), self.root)
        with self.assertRaises(orm.PathRefused):
            orm.contained(self.root / "missing.E01", self.roots, allow_root=True, must_exist=True)

    def test_the_resolved_spelling_of_an_allowed_folder_counts(self):
        real = self.root.resolve()  # macOS: /var is /private/var
        self.assertEqual(orm.contained(real / "case", self.roots), real / "case")

    def test_the_host_folders_three_spellings_are_one_place(self):
        self.assertEqual(orm.place("/host/tmp/rowanholt/a"), orm.place("/tmp/rowanholt/a"))
        self.assertEqual(orm.place("/tmp/rowanholt/a"), orm.place("/tmp/elrond/output/a/"))
        self.assertEqual(orm.translate_path_for_worker("/host/tmp/rowanholt/a"), "/tmp/elrond/output/a")
        self.assertEqual(orm.translate_path_for_worker("/host/tmp/rowanholtX/a"), "/host/tmp/rowanholtX/a")


class DestinationTest(Folders):
    def test_a_destination_holding_evidence_is_refused(self):
        refusal = orm.destination_refusal(self.root / "client-a", None, [str(self.image)], [])
        self.assertIn("would hold the evidence", refusal)
        other = make_job(self.root / "o", sources=[self.image], case="CASE-OTHER")
        self.assertIn("evidence of case CASE-OTHER", orm.destination_refusal(self.root / "client-a", None, [], [other]))

    def test_another_running_jobs_output_is_refused_at_in_and_around(self):
        running = make_job(self.root / "out" / "case", status=JobStatus.RUNNING, case="CASE-RUN")
        for dest in (self.root / "out" / "case", self.root / "out", self.root / "out" / "case" / "sub"):
            self.assertIn("CASE-RUN", orm.destination_refusal(dest, None, [], [running]) or "", dest)
        done = make_job(self.root / "out" / "case", status=JobStatus.COMPLETED)
        self.assertIsNone(orm.destination_refusal(self.root / "out" / "case", None, [], [done]))

    def test_elrond_mounts_are_never_an_output(self):
        self.assertIn("mounts images", orm.destination_refusal("/mnt/elrond_mount01/case", None, [], []))
        self.assertIsNone(orm.destination_refusal(self.root / "case", None, [str(self.image)], []))


class CheckRemovalTest(Folders):
    def remove(self, folder, job, jobs=(), **kwargs):
        return orm.remove_output(folder, job, list(jobs), self.roots, translate=lambda p: p, **kwargs)

    def test_its_own_marked_output_is_removed_and_counted(self):
        job = make_job(self.root / "out")
        folder = self.output(job, files=3)
        marker = (folder / orm.MARKER).stat().st_size
        plan = self.remove(folder, job, [job])
        self.assertEqual((plan.files, plan.bytes), (4, 3 * len("a,b\n") + marker))
        self.assertFalse(folder.exists())
        self.assertTrue(self.image.exists())

    def test_an_allowed_folder_or_a_folder_outside_is_never_removed(self):
        job = make_job(self.root)
        orm.write_marker(self.root, job.id)
        with self.assertRaisesRegex(orm.PathRefused, "one of the allowed folders"):
            self.remove(self.root, job)
        outside = self.tmp / "outside"
        outside.mkdir()
        orm.write_marker(outside, job.id)
        with self.assertRaisesRegex(orm.PathRefused, "outside the folders"):
            self.remove(outside, make_job(outside))
        self.assertTrue(self.image.exists() and outside.exists())

    def test_a_folder_that_isnt_rowanholts_is_never_removed(self):
        # Another client's evidence folder named as a destination, with force_overwrite
        job = make_job(self.root / "client-a")
        with self.assertRaisesRegex(orm.PathRefused, "no .rowanholt-output naming this job"):
            self.remove(self.root / "client-a", job)
        self.assertTrue(self.image.exists())

    def test_another_jobs_marker_isnt_enough(self):
        other = make_job(self.root / "out", case="CASE-OTHER")
        folder = self.output(other)
        job = make_job(folder)
        with self.assertRaisesRegex(orm.PathRefused, "output of another job"):
            self.remove(folder, job, [other])
        # ...unless the API recorded that this job replaces it (after checking the caller may)
        replacing = make_job(folder, replaces_output_of=other.id)
        self.remove(folder, replacing, [other])
        self.assertFalse(folder.exists())

    def test_a_marker_copied_into_another_folder_counts_for_nothing(self):
        other = make_job(self.root / "out", case="CASE-OTHER")
        copied = self.output(other, name="client-b")  # its marker, in a folder it never wrote
        self.assertIsNone(orm.folder_owner(copied, [other]))
        with self.assertRaisesRegex(orm.PathRefused, "recorded output folder of the job it replaces"):
            self.remove(copied, make_job(copied, replaces_output_of=other.id), [other])
        self.assertTrue(copied.exists())

    def test_output_from_before_the_marker_is_recognised_by_its_log_and_record(self):
        old = make_job(self.root / "out", marker=False)
        folder = self.output(old, marker=False)
        (folder / orm.JOB_LOG).write_text("log\n")
        self.assertEqual(orm.folder_owner(folder, [old]), old.id)
        # A new job pointed at it can't claim it as its own
        with self.assertRaisesRegex(orm.PathRefused, "no .rowanholt-output"):
            self.remove(folder, make_job(folder), [old])
        self.remove(folder, old, [old])
        self.assertFalse(folder.exists())

    def test_a_job_log_alone_isnt_enough_when_the_record_says_elsewhere(self):
        old = make_job(self.root / "elsewhere", marker=False)
        folder = self.output(old, marker=False)
        (folder / orm.JOB_LOG).write_text("log\n")
        self.assertIsNone(orm.folder_owner(folder, [old]))
        with self.assertRaisesRegex(orm.PathRefused, "isn't the recorded output folder"):
            self.remove(folder, old.copy(update={"destination_path": str(self.root / "elsewhere")}), [old])

    def test_a_folder_holding_evidence_is_refused_by_path_and_by_inode(self):
        job = make_job(self.root / "client-a", sources=[self.image])
        orm.write_marker(self.root / "client-a", job.id)
        with self.assertRaisesRegex(orm.PathRefused, "evidence"):
            self.remove(self.root / "client-a", job, [job])
        # A hard link to another job's image, by another name: only the inode gives it away
        other = make_job(self.root / "o", sources=[self.image], case="CASE-SRC")
        mine = make_job(self.root / "out")
        folder = self.output(mine)
        os.link(self.image, folder / "copy.E01")
        with self.assertRaisesRegex(orm.PathRefused, "evidence of case CASE-SRC"):
            self.remove(folder, mine, [other])
        self.assertTrue((folder / "copy.E01").exists())

    def test_a_folder_holding_another_jobs_output_is_refused(self):
        mine = make_job(self.root / "out")
        folder = self.output(mine)
        inner = make_job(folder / "nested", case="CASE-NESTED")
        (folder / "nested").mkdir()
        with self.assertRaisesRegex(orm.PathRefused, "CASE-NESTED"):
            self.remove(folder, mine, [inner])

    def test_a_running_jobs_output_at_or_around_it_is_refused(self):
        mine = make_job(self.root / "out")
        folder = self.output(mine)
        around = make_job(self.root, status=JobStatus.RUNNING, case="CASE-AROUND")
        with self.assertRaisesRegex(orm.PathRefused, "CASE-AROUND"):
            self.remove(folder, mine, [around])
        same = make_job(folder, status=JobStatus.PAUSED, case="CASE-SAME")
        with self.assertRaisesRegex(orm.PathRefused, "CASE-SAME"):
            self.remove(folder, mine, [same])
        self.assertTrue(folder.exists())

    def test_a_mount_point_in_it_is_refused(self):
        job = make_job(self.root / "out")
        folder = self.output(job)
        (folder / "mnt").mkdir()
        with mock.patch.object(orm, "mount_points", return_value=["/", str(folder / "mnt")]):
            with self.assertRaisesRegex(orm.PathRefused, "mount point"):
                self.remove(folder, job, [job])
        self.assertTrue(folder.exists())

    def test_another_device_in_it_is_refused(self):
        job = make_job(self.root / "out")
        folder = self.output(job)
        real = os.lstat

        def lstat(path):
            st = real(path)
            if str(path).endswith("cooked"):
                return os.stat_result((st.st_mode, st.st_ino, st.st_dev + 1) + tuple(st)[3:])
            return st
        with mock.patch.object(orm, "_lstat", lstat):
            with self.assertRaisesRegex(orm.PathRefused, "another file system"):
                self.remove(folder, job, [job])
        self.assertTrue((folder / "cooked" / "0.csv").exists())

    def test_links_are_removed_not_followed(self):
        job = make_job(self.root / "out")
        folder = self.output(job)
        keep = self.tmp / "keep"
        keep.mkdir()
        (keep / "precious").write_text("x")
        (folder / "to-keep").symlink_to(keep)
        self.remove(folder, job, [job])
        self.assertTrue((keep / "precious").exists())

    def test_a_folder_still_there_afterwards_is_a_failure(self):
        job = make_job(self.root / "out")
        folder = self.output(job)
        with self.assertRaisesRegex(orm.RemovalFailed, "still there"):
            self.remove(folder, job, [job], remover=lambda path, device: None)


def load_worker():
    """tasks_docker for real (Celery and Redis's client needed, not their servers), on a store of
    its own, as WorkerHeartbeatTest loads it."""
    try:
        spec = importlib.util.spec_from_file_location("tasks_docker_for_removal", BACKEND / "tasks_docker.py")
        tasks = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tasks)
    except ImportError as exc:
        raise unittest.SkipTest(f"worker requirements not installed: {exc}")
    return tasks


class Beat:
    started = []

    def __init__(self, job_id):
        Beat.started.append(job_id)

    def start(self):
        return self

    def stop(self):
        pass


class WorkerTest(Folders):
    @classmethod
    def setUpClass(cls):
        cls.tasks = load_worker()
        import storage
        cls.store = storage.JobStorage(f"sqlite:///{tempfile.mkdtemp(prefix='rowanholt-worker-')}/jobs.db")

    def setUp(self):
        super().setUp()
        Beat.started = []
        for target, attribute, value in ((self.tasks, "job_storage", self.store),
                                         (self.tasks, "worker_roots", lambda: self.roots),
                                         (self.tasks.job_liveness, "Heartbeat", Beat),
                                         (self.tasks.job_liveness, "mark_queued", lambda job_id: None),
                                         (self.tasks, "_clear_job_process", lambda job_id: None)):
            patcher = mock.patch.object(target, attribute, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.delay = mock.patch.object(self.tasks.start_analysis, "delay", return_value=mock.Mock(id="again")).start()
        self.addCleanup(mock.patch.stopall)

    def saved(self, job, status=None):
        if status is not None:
            job.status = status
        self.store.save_job(job)
        return job

    def audits(self, job):
        return [row["action"] for row in self.store.audit_records(job.id, "output.")]

    def test_a_confirmed_removal_removes_checks_and_queues_the_run(self):
        job = make_job(self.root / "out", status=JobStatus.REMOVING, force_overwrite=True)
        folder = self.output(job)
        self.saved(job)
        result = self.tasks.remove_output(job.id, {"id": "u1", "username": "alice"}, "100.64.0.9")
        self.assertEqual(result["outcome"], "removed")
        self.assertFalse(folder.exists())
        stored = self.store.get_job(job.id)
        self.assertEqual(stored.status, JobStatus.PENDING)
        self.assertIsNone(stored.pending_action)
        self.delay.assert_called_once_with(job.id)
        self.assertEqual(stored.celery_task_id, "again")
        [record] = self.store.audit_records(job.id, "output.removed")
        self.assertEqual((record["username"], record["ip_address"]), ("alice", "100.64.0.9"))
        self.assertEqual(record["details"]["files"], 4)  # three tables and the marker
        self.assertEqual(record["details"]["path"], str(folder))
        self.assertEqual(Beat.started, [job.id])  # counts for /api/busy while it works

    def test_a_removal_the_checks_refuse_fails_the_job_and_removes_nothing(self):
        job = make_job(self.root / "client-a", status=JobStatus.REMOVING, sources=[self.image])
        self.saved(job)
        self.tasks.remove_output(job.id)
        stored = self.store.get_job(job.id)
        self.assertEqual(stored.status, JobStatus.FAILED)
        self.assertIn("wasn't removed", stored.error)
        self.assertTrue(self.image.exists())
        self.delay.assert_not_called()
        self.assertEqual(self.audits(job), ["output.removal_refused"])

    def test_a_removal_that_leaves_the_folder_fails_with_the_reason(self):
        job = make_job(self.root / "out", status=JobStatus.REMOVING)
        folder = self.output(job)
        self.saved(job)
        with mock.patch.object(self.tasks.output_removal, "remove_tree", lambda path, device: None):
            self.tasks.remove_output(job.id)
        stored = self.store.get_job(job.id)
        self.assertEqual(stored.status, JobStatus.FAILED)
        self.assertIn("still there", stored.error)
        self.assertTrue(folder.exists())
        self.delay.assert_not_called()
        self.assertEqual(self.audits(job), ["output.removal_failed"])

    def test_only_a_job_being_removed_is_touched(self):
        job = make_job(self.root / "out", status=JobStatus.AWAITING_CONFIRMATION)
        folder = self.output(job)
        self.saved(job)
        self.assertEqual(self.tasks.remove_output(job.id)["outcome"], "not removing")
        self.assertTrue(folder.exists())
        self.assertEqual(self.store.get_job(job.id).status, JobStatus.AWAITING_CONFIRMATION)

    def test_start_analysis_runs_only_a_pending_job(self):
        for status in (JobStatus.RUNNING, JobStatus.REMOVING, JobStatus.COMPLETED):
            job = make_job(self.root / "out", status=status, force_overwrite=True)
            folder = self.output(job)
            self.saved(job)
            with mock.patch.object(self.tasks, "build_elrond_command") as build:
                self.tasks.start_analysis(job.id)
            build.assert_not_called()
            self.assertEqual(self.store.get_job(job.id).status, status)
            self.assertTrue(folder.exists())
        self.assertEqual(Beat.started, [])  # no heartbeat to remove the running task's

    def test_a_task_that_loses_the_job_to_another_writes_nothing(self):
        job = self.saved(make_job(self.root / "out", status=JobStatus.PENDING, force_overwrite=True))
        folder = self.output(job)
        other_task_started = self.store.get_job(job.id)
        other_task_started.status = JobStatus.RUNNING
        with mock.patch.object(self.store, "transition", return_value=None), \
                mock.patch.object(self.store, "save_job", wraps=self.store.save_job) as save, \
                mock.patch.object(self.tasks, "build_elrond_command") as build:
            self.tasks.start_analysis(job.id)
        build.assert_not_called()
        self.assertEqual(save.call_count, 0)
        self.assertTrue(folder.exists())

    def test_the_first_try_applies_the_same_checks(self):
        # force_overwrite onto another client's evidence folder: refused, the job failed, nothing gone
        job = self.saved(make_job(self.root / "client-a", status=JobStatus.PENDING, force_overwrite=True))
        with mock.patch.object(self.tasks, "build_elrond_command", return_value=["--Brisk"]):
            self.tasks.start_analysis(job.id)
        stored = self.store.get_job(job.id)
        self.assertEqual(stored.status, JobStatus.FAILED)
        self.assertIn("wasn't removed", stored.error)
        self.assertTrue(self.image.exists())
        self.assertEqual(self.audits(job), ["output.removal_refused"])

    def test_the_first_try_removes_its_own_output_and_marks_the_new_one(self):
        job = self.saved(make_job(self.root / "out", status=JobStatus.PENDING, force_overwrite=True))
        folder = self.output(job)
        with mock.patch.object(self.tasks, "build_elrond_command", return_value=["--Brisk"]), \
                mock.patch.dict(os.environ, {"ELROND_HOME": str(self.tmp / "no-elrond")}):
            self.tasks.start_analysis(job.id)  # removes, recreates, then finds no Elrond to run
        self.assertFalse((folder / "cooked").exists())
        self.assertEqual(orm.read_marker(folder), job.id)
        self.assertEqual(self.audits(job), ["output.removed"])

    def test_a_failed_first_try_waits_for_confirmation(self):
        job = self.saved(make_job(self.root / "out", status=JobStatus.PENDING, force_overwrite=True))
        self.output(job)
        with mock.patch.object(self.tasks, "build_elrond_command", return_value=["--Brisk"]), \
                mock.patch.object(self.tasks.output_removal, "remove_tree", side_effect=PermissionError("busy")):
            self.tasks.start_analysis(job.id)
        stored = self.store.get_job(job.id)
        self.assertEqual(stored.status, JobStatus.AWAITING_CONFIRMATION)
        self.assertEqual(stored.pending_action.action_type, "remove_output")
        self.assertNotIn("sudo", stored.pending_action.message.lower())
        self.assertEqual(self.audits(job), ["output.removal_failed"])


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class RemovalApiTest(BackendCase):
    def post_job(self, headers, case, dest=None, source=None, **options):
        source = source or self.evidence / f"{case}.E01"
        Path(source).write_bytes(b"")
        body = {"case_number": case, "source_paths": [str(source)], "options": options}
        if dest is not None:
            body["destination_path"] = str(dest)
        return self.client.post("/api/jobs", headers=headers, json=body)

    def awaiting(self, owner, case):
        job_id = self.create_job(owner, case)
        job = self.main.job_storage.get_job(job_id)
        job.status = JobStatus.AWAITING_CONFIRMATION
        job.pending_action = PendingAction(action_type="remove_output", target_path=job.destination_path,
                                           message="Removing the old output failed: busy. Try again?")
        self.main.job_storage.save_job(job)
        return job_id

    def test_destinations_must_be_inside_an_allowed_folder(self):
        sibling = Path(f"{self.evidence}X")
        sibling.mkdir(exist_ok=True)
        outside = Path(TMP) / "outside-dest"
        outside.mkdir(exist_ok=True)
        link = self.evidence / "link-out"
        if not link.is_symlink():
            link.symlink_to(outside)
        for dest in (self.evidence, sibling / "case", f"{self.evidence}/x/../out", link / "case"):
            resp = self.post_job(self.alice, "CASE-DEST-1", dest=dest)
            self.assertEqual(resp.status_code, 403, f"{dest}: {resp.text}")
        resp = self.post_job(self.alice, "CASE-DEST-2", dest=self.evidence / "out" / "CASE-DEST-2")
        self.assertEqual(resp.status_code, 200, resp.text)

    def test_sources_must_be_inside_an_allowed_folder(self):
        sibling = Path(f"{self.evidence}X")
        sibling.mkdir(exist_ok=True)
        resp = self.post_job(self.alice, "CASE-SRC-1", source=sibling / "disk.E01")
        self.assertEqual(resp.status_code, 403, resp.text)

    def test_a_destination_holding_the_evidence_is_refused(self):
        folder = self.evidence / "client-b"
        folder.mkdir(exist_ok=True)
        resp = self.post_job(self.alice, "CASE-HOLD-1", dest=folder, source=folder / "disk.E01")
        self.assertEqual(resp.status_code, 409, resp.text)

    def test_what_may_be_removed_is_the_apis_to_say(self):
        resp = self.post_job(self.alice, "CASE-OPTS-1", dest=self.evidence / "out" / "CASE-OPTS-1",
                             replaces_output_of="someone-elses-job", output_marker=False)
        self.assertEqual(resp.status_code, 200, resp.text)
        options = self.main.job_storage.get_job(resp.json()["id"]).options
        self.assertIsNone(options.replaces_output_of)
        self.assertTrue(options.output_marker)

    def test_force_overwrite_never_takes_a_folder_that_isnt_rowanholts(self):
        folder = self.evidence / "client-c"
        folder.mkdir(exist_ok=True)
        (folder / "notes.txt").write_text("theirs")
        resp = self.post_job(self.admin, "CASE-FORCE-1", dest=folder, force_overwrite=True)
        self.assertEqual(resp.status_code, 409, resp.text)
        self.assertIn("isn't a Rowanholt output folder", resp.json()["detail"])
        self.assertNotIn("File exists", resp.json()["detail"])  # the web app would offer to overwrite
        self.assertTrue((folder / "notes.txt").exists())

    def test_force_overwrite_of_another_jobs_output_is_its_owners_or_an_admins(self):
        old_id = self.create_job(self.alice, "CASE-FORCE-2")
        old = self.main.job_storage.get_job(old_id)
        old.status = JobStatus.COMPLETED
        self.main.job_storage.save_job(old)
        Path(old.destination_path).mkdir(parents=True, exist_ok=True)
        orm.write_marker(old.destination_path, old_id)

        resp = self.post_job(self.bob, "CASE-FORCE-2", dest=old.destination_path, force_overwrite=True)
        self.assertEqual(resp.status_code, 403, resp.text)
        resp = self.post_job(self.bob, "CASE-FORCE-2", dest=old.destination_path)
        self.assertEqual(resp.status_code, 400, resp.text)  # exists: the web app asks about overwriting
        self.assertIn("[Errno 17]", resp.json()["detail"])
        resp = self.post_job(self.alice, "CASE-FORCE-2", dest=old.destination_path, force_overwrite=True)
        self.assertEqual(resp.status_code, 200, resp.text)
        new = self.main.job_storage.get_job(resp.json()["id"])
        self.assertEqual(new.options.replaces_output_of, old_id)
        [record] = self.main.job_storage.audit_records(new.id, "output.removal_requested")
        self.assertEqual(record["username"], "alice")
        self.assertEqual(record["details"]["path"], old.destination_path)

    def test_force_overwrite_of_a_running_jobs_output_is_refused(self):
        old_id = self.create_job(self.alice, "CASE-FORCE-3")
        old = self.main.job_storage.get_job(old_id)
        Path(old.destination_path).mkdir(parents=True, exist_ok=True)
        orm.write_marker(old.destination_path, old_id)
        resp = self.post_job(self.alice, "CASE-FORCE-3B", dest=old.destination_path, force_overwrite=True)
        self.assertEqual(resp.status_code, 409, resp.text)

    def test_a_fresh_restart_into_a_folder_no_longer_allowed_is_refused(self):
        job_id = self.create_job(self.alice, "CASE-OLD-DEST")
        job = self.main.job_storage.get_job(job_id)
        job.status, job.destination_path = JobStatus.COMPLETED, str(self.evidence)  # recorded before the checks
        self.main.job_storage.save_job(job)
        resp = self.client.post(f"/api/jobs/{job_id}/restart?fresh=true", headers=self.alice)
        self.assertEqual(resp.status_code, 403, resp.text)
        self.assertIn("can't be removed", resp.json()["detail"])

    def test_confirming_twice_removes_once(self):
        job_id = self.awaiting(self.alice, "CASE-CONFIRM-1")
        tasks = sys.modules["tasks_docker"]
        tasks.remove_output.delay.reset_mock()
        first = self.client.post(f"/api/jobs/{job_id}/confirm-removal", headers=self.alice)
        self.assertEqual(first.status_code, 202, first.text)
        self.assertEqual(first.json()["status"], "removing")
        second = self.client.post(f"/api/jobs/{job_id}/confirm-removal", headers=self.alice)
        self.assertEqual(second.status_code, 409, second.text)
        tasks.remove_output.delay.assert_called_once()
        args = tasks.remove_output.delay.call_args.args
        self.assertEqual((args[0], args[1]["username"]), (job_id, "alice"))
        job = self.main.job_storage.get_job(job_id)
        self.assertEqual((job.status, job.celery_task_id), (JobStatus.REMOVING, "celery-removal"))
        [record] = self.main.job_storage.audit_records(job_id, "output.removal_confirmed")
        self.assertEqual(record["username"], "alice")
        self.assertIsNotNone(record["ip_address"])
        # Being removed: it can't be deleted, archived or cancelled under the worker
        self.assertEqual(self.client.delete(f"/api/jobs/{job_id}", headers=self.alice).status_code, 400)
        self.assertEqual(self.client.post(f"/api/jobs/{job_id}/archive", headers=self.alice).status_code, 400)
        self.assertEqual(self.client.post(f"/api/jobs/{job_id}/cancel", headers=self.alice).status_code, 400)

    def test_the_old_route_names_still_answer(self):
        job_id = self.awaiting(self.alice, "CASE-CONFIRM-2")
        self.assertEqual(self.client.post(f"/api/jobs/{job_id}/confirm-sudo", headers=self.alice).status_code, 202)
        job_id = self.awaiting(self.alice, "CASE-CANCEL-2")
        self.assertEqual(self.client.post(f"/api/jobs/{job_id}/cancel-sudo", headers=self.alice).status_code, 200)

    def test_a_removal_that_cant_be_queued_fails_the_job(self):
        job_id = self.awaiting(self.alice, "CASE-CONFIRM-3")
        tasks = sys.modules["tasks_docker"]
        with mock.patch.object(tasks.remove_output, "delay", side_effect=ConnectionError("redis down")):
            resp = self.client.post(f"/api/jobs/{job_id}/confirm-removal", headers=self.alice)
        self.assertEqual(resp.status_code, 503, resp.text)
        job = self.main.job_storage.get_job(job_id)
        self.assertEqual(job.status, JobStatus.FAILED)
        self.assertIn("Not queued", job.error)

    def test_giving_up_fails_the_job_and_is_audited(self):
        job_id = self.awaiting(self.alice, "CASE-CANCEL-1")
        resp = self.client.post(f"/api/jobs/{job_id}/cancel-removal", headers=self.alice)
        self.assertEqual(resp.status_code, 200, resp.text)
        job = self.main.job_storage.get_job(job_id)
        self.assertEqual(job.status, JobStatus.FAILED)
        self.assertIsNone(job.pending_action)
        self.assertEqual(self.client.post(f"/api/jobs/{job_id}/cancel-removal", headers=self.alice).status_code, 409)
        self.assertEqual(self.client.post(f"/api/jobs/{job_id}/confirm-removal", headers=self.alice).status_code, 409)
        [record] = self.main.job_storage.audit_records(job_id, "output.removal_cancelled")
        self.assertEqual(record["username"], "alice")

    def test_a_removal_counts_for_busy(self):
        import busy
        import removal_routes
        self.assertEqual(busy._checks["removals"], removal_routes._liveness.check)
        self.assertEqual(removal_routes._liveness.statuses, (JobStatus.REMOVING,))

    def test_the_removal_liveness_starts_with_the_backend(self):
        import removal_routes
        with mock.patch.object(removal_routes._liveness, "start", return_value=mock.Mock()) as start, \
                mock.patch.object(self.main.job_liveness_check, "start", return_value=mock.Mock()):
            with TestClient(self.main.app):
                start.assert_called_once_with()
                stop = removal_routes.router.stop_liveness
            stop.set.assert_called_once_with()
            self.assertIsNone(removal_routes.router.stop_liveness)

    def test_a_removal_with_no_worker_is_failed_and_one_with_a_worker_is_busy(self):
        import job_liveness
        import removal_routes
        from test_job_liveness import Clock, FakeRedis
        clock, redis = Clock(), FakeRedis()
        redis.clock = clock
        liveness = job_liveness.Liveness(removal_routes._RemovalRows(self.main.job_storage), (JobStatus.REMOVING,),
                                         client_factory=lambda: redis, broker_factory=lambda: FakeRedis(clock),
                                         clock=clock)
        for job_id, _, _ in self.main.job_storage.active_jobs((JobStatus.REMOVING,)):
            self.main.job_storage.set_status(job_id, JobStatus.CANCELLED)
        dead, live = (self.awaiting(self.alice, case) for case in ("CASE-DEAD-RM", "CASE-LIVE-RM"))
        for job_id in (dead, live):
            self.main.job_storage.set_status(job_id, JobStatus.REMOVING)
        with mock.patch.dict("sys.modules", {"tasks_docker": mock.MagicMock()}):
            redis.set(job_liveness.heartbeat_key(live), "w", ex=60)
            self.assertTrue(liveness.check())
            clock.now += job_liveness.STALE_GRACE + 1
            redis.set(job_liveness.heartbeat_key(live), "w", ex=60)
            self.assertTrue(liveness.check())
        self.assertEqual(self.main.job_storage.get_job(dead).status, JobStatus.FAILED)
        self.assertIn("removing this job's old output", self.main.job_storage.get_job(dead).error)
        self.assertEqual(self.main.job_storage.get_job(live).status, JobStatus.REMOVING)

    def test_a_cookie_needs_the_header_and_a_token_doesnt(self):
        resp = self.client.post("/api/auth/login", data={"username": "bob", "password": "bob-password-123"})
        cookie = {"Cookie": f"session_token={resp.cookies.get('session_token')}"}
        self.client.cookies.clear()
        refused = self.client.post("/api/jobs/bulk/cancel", headers=cookie, json=[])
        self.assertEqual(refused.status_code, 403, refused.text)
        self.assertIn("X-Rowanholt", refused.json()["detail"])
        allowed = self.client.post("/api/jobs/bulk/cancel", headers={**cookie, "X-Rowanholt": "1"}, json=[])
        self.assertEqual(allowed.status_code, 200, allowed.text)
        self.assertEqual(self.client.get("/api/jobs", headers=cookie).status_code, 200)  # reads aren't refused
        self.assertEqual(self.client.post("/api/jobs/bulk/cancel", headers=self.bob, json=[]).status_code, 200)
        both = {**cookie, **self.bob}  # a bearer token decides, whatever cookie comes with it
        self.assertEqual(self.client.post("/api/jobs/bulk/cancel", headers=both, json=[]).status_code, 200)


if __name__ == "__main__":
    unittest.main()
