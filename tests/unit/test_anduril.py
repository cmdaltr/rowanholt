"""Unit tests for Anduril's scope rules (no Docker engine needed).

Run: python3 -m unittest tests/unit/test_anduril.py
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "common"))

from anduril import BusyError, DockerAdmin, ScopeError  # noqa: E402
from anduril.scope import (  # noqa: E402
    check_action,
    container_in_scope,
    find_job_processes,
    split_image_ref,
)


def container(name, project="rowanholt", service=None, image_id="sha256:aaa", state="running"):
    return {
        "Id": f"{name}-id-000000000000",
        "Names": [f"/{name}"],
        "Labels": {"com.docker.compose.project": project, "com.docker.compose.service": service or name.split("-", 1)[-1]},
        "ImageID": image_id,
        "Image": "img",
        "State": state,
    }


class FakeEngine:
    socket_path = "/fake.sock"

    def __init__(self, containers, images, top=None):
        self._containers = containers
        self._images = images
        self._top = top or {"Titles": ["PID", "COMMAND"], "Processes": []}
        self.calls = []

    def containers(self):
        return self._containers

    def images(self):
        return self._images

    def top(self, cid):
        return self._top

    def stop(self, cid, timeout=30):
        self.calls.append(("stop", cid))

    def restart(self, cid, timeout=30):
        self.calls.append(("restart", cid))

    def start(self, cid):
        self.calls.append(("start", cid))

    def remove_image(self, image_id):
        self.calls.append(("rmi", image_id))


ELROND_TOP = {"Titles": ["PID", "COMMAND"], "Processes": [["17", "python3 /opt/elrond-src/elrond.py TEST_win_full /img /out"]]}


class ScopeTests(unittest.TestCase):
    def test_container_needs_project_label_and_prefix(self):
        self.assertTrue(container_in_scope(container("rowanholt-backend")))
        self.assertFalse(container_in_scope(container("rowanholt-backend", project="other")))
        self.assertFalse(container_in_scope(container("caddy-local", project="rowanholt")))
        self.assertFalse(container_in_scope({"Names": ["/rowanholt-x"], "Labels": {}}))

    def test_inspect_shape_is_understood(self):
        inspected = {"Name": "/rowanholt-redis", "Config": {"Labels": {"com.docker.compose.project": "rowanholt"}}}
        self.assertTrue(container_in_scope(inspected))

    def test_sensitive_services_refuse_while_elrond_runs(self):
        jobs = find_job_processes(ELROND_TOP)
        self.assertEqual(len(jobs), 1)
        for service in ("celery-worker", "postgres", "redis"):
            with self.assertRaises(BusyError):
                check_action(service, "restart", jobs, force=False)
            check_action(service, "restart", jobs, force=True)
        check_action("frontend", "restart", jobs, force=False)

    def test_anduril_cannot_act_on_itself_from_the_web(self):
        with self.assertRaises(ScopeError):
            check_action("anduril", "stop", [], force=True)
        check_action("anduril", "stop", [], force=False, allow_self=True)

    def test_split_image_ref(self):
        self.assertEqual(split_image_ref("postgres:16-alpine"), ("postgres", "16-alpine"))
        self.assertEqual(split_image_ref("splunk/splunk"), ("splunk/splunk", "latest"))
        self.assertEqual(split_image_ref("localhost:5000/x"), ("localhost:5000/x", "latest"))
        self.assertEqual(split_image_ref("docker.elastic.co/kibana/kibana:8.11.0"), ("docker.elastic.co/kibana/kibana", "8.11.0"))


class AdminTests(unittest.TestCase):
    def make(self, top=None):
        containers = [
            container("rowanholt-celery-worker", service="celery-worker", image_id="sha256:" + "1" * 64),
            container("rowanholt-postgres", service="postgres", image_id="sha256:" + "2" * 64),
            container("caddy-local", project="caddy", service="caddy", image_id="sha256:" + "3" * 64),
            container("other-app", project="other", service="web", image_id="sha256:" + "2" * 64),
        ]
        images = [
            {"Id": "sha256:" + "1" * 64, "RepoTags": ["rowanholt-celery-worker:latest"], "Labels": {"com.docker.compose.project": "rowanholt"}, "Size": 1},
            {"Id": "sha256:" + "2" * 64, "RepoTags": ["postgres:16-alpine"], "Labels": {}, "Size": 1},
            {"Id": "sha256:" + "3" * 64, "RepoTags": ["caddy:2"], "Labels": {}, "Size": 1},
            {"Id": "sha256:" + "4" * 64, "RepoTags": ["<none>:<none>"], "Labels": {"com.docker.compose.project": "rowanholt"}, "Size": 5},
        ]
        engine = FakeEngine(containers, images, top)
        return DockerAdmin(engine=engine), engine

    def test_only_rowanholt_containers_listed_and_resolvable(self):
        admin, _ = self.make()
        self.assertEqual([c["name"] for c in admin.list_containers()], ["rowanholt-celery-worker", "rowanholt-postgres"])
        self.assertEqual(admin.resolve("postgres")["Names"], ["/rowanholt-postgres"])
        for name in ("caddy-local", "other-app", "web", "../rowanholt-postgres"):
            with self.assertRaises(ScopeError):
                admin.resolve(name)

    def test_only_rowanholt_images_listed(self):
        admin, _ = self.make()
        tags = [t for i in admin.list_images() for t in i["tags"]]
        self.assertIn("postgres:16-alpine", tags)
        self.assertNotIn("caddy:2", tags)

    def test_shared_image_not_removable(self):
        admin, engine = self.make()
        with self.assertRaises(ScopeError) as ctx:
            admin.remove_image("2" * 12)
        self.assertIn("other-app", str(ctx.exception))
        with self.assertRaises(ScopeError):
            admin.remove_image("3" * 12)  # caddy: not ours
        with self.assertRaises(ScopeError):
            admin.remove_image("1" * 6)  # too short to be unambiguous
        self.assertEqual(engine.calls, [])

    def test_worker_restart_refused_while_job_runs(self):
        admin, engine = self.make(top=ELROND_TOP)
        with self.assertRaises(BusyError):
            admin.restart("celery-worker")
        self.assertEqual(engine.calls, [])
        admin.restart("celery-worker", force=True)
        self.assertEqual(engine.calls[0][0], "restart")

    def test_pull_scope(self):
        admin, _ = self.make()
        with self.assertRaises(ScopeError):
            admin.validate_pull("caddy:2")
        with self.assertRaises(ScopeError):
            admin.validate_pull("rowanholt-celery-worker:latest")  # built locally
        self.assertEqual(admin.validate_pull("postgres:16-alpine"), "postgres:16-alpine")

    def test_clone_config_drops_image_defaults(self):
        info = {
            "Id": "abcdef1234567890",
            "Config": {
                "Hostname": "abcdef123456",
                "Image": "redis:7-alpine",
                "Cmd": ["redis-server"],
                "Env": ["PATH=/usr/bin", "FOO=bar"],
                "Labels": {"com.docker.compose.image": "sha256:old", "img.label": "1", "com.docker.compose.project": "rowanholt"},
                "Volumes": {"/data": {}},
            },
            "HostConfig": {"Binds": ["/host:/named:ro"], "Memory": 1},
            "Mounts": [
                {"Type": "volume", "Name": "anon123", "Destination": "/data"},
                {"Type": "bind", "Destination": "/named"},
            ],
        }
        old_cfg = {"Cmd": ["redis-server"], "Env": ["PATH=/usr/bin"], "Labels": {"img.label": "1"}, "Volumes": {"/data": {}}}
        cfg = DockerAdmin._clone_config(info, old_cfg, {"Id": "sha256:new"})
        self.assertNotIn("Cmd", cfg)
        self.assertNotIn("Hostname", cfg)
        self.assertEqual(cfg["Env"], ["FOO=bar"])
        self.assertEqual(cfg["Labels"]["com.docker.compose.image"], "sha256:new")
        self.assertNotIn("img.label", cfg["Labels"])
        self.assertEqual(cfg["HostConfig"]["Mounts"], [{"Type": "volume", "Source": "anon123", "Target": "/data"}])


if __name__ == "__main__":
    unittest.main()
