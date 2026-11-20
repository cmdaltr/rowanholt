"""First admins (auth/users.init_default_admin, `server users first-admin`, server init --admin and the
launcher's offer_first_admin): a local stack seeds admin / 3000YearsAgo, and only while it's published
on loopback; a team server seeds nothing, ignores an old ROWANHOLT_ADMIN_PASSWORD, and its first admin
comes from a one-time admin's invitation, refused once an active admin exists unless --force, needing
no free licence place while no admin is left, of which only the newest works.

Run: python3 -m pytest tests/unit/test_first_admin.py
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from test_server_access import BackendCase, TestClient

REPO = Path(__file__).resolve().parents[2]
PASSWORD = "first-admin-password-1"


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class FirstAdminTest(BackendCase):
    """Each test has an empty user store of its own; the class's admin, alice and bob are elsewhere."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.mfa = sys.modules["auth.mfa"]
        cls.users_module = sys.modules["auth.users"]
        cls.invitations = sys.modules["auth.invitations"]
        from auth import manage_users
        cls.cli = manage_users

    def setUp(self):
        store = Path(tempfile.mkdtemp(prefix="rowanholt-first-admin-")) / "users.json"
        for patch in (mock.patch.object(self.users_module, "USERS_FILE", str(store)),
                      mock.patch.object(self.cli, "_audit_storage", lambda: sys.modules["auth.access"]._storage)):
            patch.start()
            self.addCleanup(patch.stop)
        self.now = time.time()
        clock = mock.patch.object(self.mfa, "_now", lambda: self.now)
        clock.start()
        self.addCleanup(clock.stop)

    # ── helpers ──────────────────────────────────────────────────────────────

    def first_admin(self, *args):
        """(exit status, what it printed)."""
        with mock.patch("builtins.print") as printed:
            status = self.cli.main(["first-admin", *args])
        return status, " ".join(str(arg) for call in printed.call_args_list for arg in call.args)

    def token(self, output):
        return output.split("https://rowanholt.test/accept-invite#", 1)[1].split()[0]

    def accept(self, token, username):
        self.client.cookies.clear()
        started = self.client.post("/api/auth/invitations/accept/start", json={"token": token, "username": username})
        if started.status_code != 200:
            return started
        self.now += self.mfa.STEP_SECONDS
        code = self.mfa.code_at(started.json()["secret"], self.mfa.current_step())
        done = self.client.post("/api/auth/invitations/accept/complete", json={
            "token": token, "username": username, "new_password": PASSWORD, "code": code})
        self.client.cookies.clear()
        return done

    def sign_in(self, username, password):
        self.client.cookies.clear()
        resp = self.client.post("/api/auth/login", data={"username": username, "password": password})
        self.client.cookies.clear()
        return resp

    def seats(self, seats):
        patch = mock.patch.object(sys.modules["licence"], "current",
                                  return_value=mock.Mock(seats=seats, edition=mock.Mock(value="pro")))
        patch.start()
        self.addCleanup(patch.stop)

    # ── a server seeds nothing ───────────────────────────────────────────────

    def test_a_server_seeds_no_account_and_says_how_to_make_the_first_admin(self):
        refused = self.sign_in("admin", self.settings.default_admin_password)
        self.assertEqual(refused.status_code, 503)
        self.assertIn("first-admin", refused.json()["detail"])
        self.assertEqual(self.users_module.load_users(), {})

    def test_an_old_admin_password_is_ignored_on_a_server(self):
        with mock.patch.object(self.settings, "rowanholt_admin_password", "an-old-env-password"), \
                self.assertLogs("auth.users", "WARNING") as logged:
            self.assertEqual(self.sign_in("admin", "an-old-env-password").status_code, 503)
        self.assertIn("ROWANHOLT_ADMIN_PASSWORD is set but ignored", " ".join(logged.output))
        self.assertEqual(self.users_module.load_users(), {})

    # ── first-admin ──────────────────────────────────────────────────────────

    def test_first_admin_makes_an_admin_and_is_refused_once_there_is_one(self):
        status, output = self.first_admin("boss@example.org")
        self.assertEqual(status, 0)
        done = self.accept(self.token(output), "boss")
        self.assertEqual(done.status_code, 200, done.text)
        self.assertEqual((done.json()["user"]["role"], done.json()["user"]["mfa_enabled"]), ("admin", True))
        self.assertEqual(self.sign_in("boss", PASSWORD).json()["mfa_required"], True)
        status, _ = self.first_admin("other@example.org")
        self.assertEqual(status, self.cli.ADMIN_EXISTS)
        status, output = self.first_admin("other@example.org", "--force")
        self.assertEqual(status, 0)
        self.assertIn("accept-invite#", output)

    def test_only_the_newest_first_admin_link_works(self):
        # An ordinary invitation isn't replaced by a first admin's (the seat check is out of the way here)
        with mock.patch.object(sys.modules["licence"], "current", return_value=mock.Mock(seats=None)):
            ordinary, _ = self.invitations.create({}, "analyst@example.org")
        _, first = self.first_admin("one@example.org")
        _, second = self.first_admin("two@example.org")
        self.assertEqual(self.accept(self.token(first), "one").status_code, 404)
        self.assertEqual(self.accept(self.token(second), "two").status_code, 200)
        self.assertEqual([inv["id"] for inv in self.invitations.pending()], [ordinary["id"]])

    def test_link_only_prints_just_the_link(self):
        status, output = self.first_admin("boss@example.org", "--link-only")
        self.assertEqual(status, 0)
        self.assertRegex(output, r"^https://rowanholt\.test/accept-invite#\S+$")

    def test_without_a_public_url_the_link_is_this_machines_with_a_warning(self):
        for args in ((), ("--link-only",)):
            with mock.patch.object(self.settings, "rowanholt_public_url", ""), \
                    mock.patch("builtins.print") as printed:
                self.assertEqual(self.cli.main(["first-admin", "boss@example.org", *args]), 0)
            out = [(" ".join(map(str, call.args)), call.kwargs.get("file")) for call in printed.call_args_list]
            self.assertTrue(any("https://localhost/accept-invite#" in text for text, _ in out), out)
            self.assertTrue(any("ROWANHOLT_PUBLIC_URL isn't set" in text and where is sys.stderr
                                for text, where in out), out)

    def test_no_free_place_is_needed_while_no_admin_can_sign_in(self):
        # Two analysts hold the licence's two places, and the only admin is disabled
        users = {}
        for name, role, active in (("ann", "user", True), ("ben", "user", True), ("old", "admin", False)):
            record = self.users_module.new_user(name, f"{name}@example.org", role=role, password=PASSWORD)
            record["is_active"] = active
            users[record["id"]] = record
        self.users_module.save_users(users)
        self.seats(2)
        status, output = self.first_admin("boss@example.org")
        self.assertEqual(status, 0, output)
        self.assertEqual(self.accept(self.token(output), "boss").status_code, 200)
        # With an admin back, an ordinary invitation needs a place again
        self.assertEqual(self.invite("more@example.org", headers=self._header("boss")).status_code, 402)

    def _header(self, username):
        record = self.users_module.find_user(self.users_module.load_users(), username)
        token = sys.modules["auth.security"].create_access_token({"sub": record["id"], "role": record["role"]})
        return {"Authorization": f"Bearer {token}"}

    def test_has_admin(self):
        with mock.patch("builtins.print") as printed:
            self.assertEqual(self.cli.main(["has-admin"]), 0)
        printed.assert_called_with("false")
        _, output = self.first_admin("boss@example.org")
        self.accept(self.token(output), "boss")
        with mock.patch("builtins.print") as printed:
            self.cli.main(["has-admin"])
        printed.assert_called_with("true")

    # ── a local stack ────────────────────────────────────────────────────────

    def test_a_local_stack_seeds_admin_with_the_published_password(self):
        with mock.patch.object(self.settings, "rowanholt_server_mode", False):
            signed_in = self.sign_in("admin", "3000YearsAgo")
            self.assertEqual(signed_in.status_code, 200, signed_in.text)
            self.assertEqual(signed_in.json()["user"]["role"], "admin")
            storage = sys.modules["auth.access"]._storage
            [seeded] = [row for row in storage.audit_records(resource_id=signed_in.json()["user"]["id"])
                        if row["action"] == "default_admin_seeded"]
            self.assertEqual(seeded["details"]["bind"], "127.0.0.1")
            with self.assertRaisesRegex(SystemExit, "team server"):
                self.cli.main(["first-admin", "boss@example.org"])

    def test_a_local_stack_published_beyond_loopback_seeds_nothing(self):
        with mock.patch.object(self.settings, "rowanholt_server_mode", False), \
                mock.patch.object(self.settings, "rowanholt_bind", "0.0.0.0"), \
                self.assertLogs("auth.users", "WARNING") as logged:
            self.assertEqual(self.sign_in("admin", "3000YearsAgo").status_code, 401)
        self.assertIn("first-admin", " ".join(logged.output))
        self.assertEqual(self.users_module.load_users(), {})

    def test_what_counts_as_loopback(self):
        for bind in ("127.0.0.1", "127.1.2.3", "::1", "[::1]", "localhost"):
            self.assertTrue(self.users_module.loopback_only(bind), bind)
        for bind in ("0.0.0.0", "192.168.1.10", "100.64.0.1", "::", "", "rowanholt.example.org"):
            self.assertFalse(self.users_module.loopback_only(bind), bind)


# ── server init --admin and the launcher ─────────────────────────────────────

def init_tree(tmp_path: Path) -> tuple:
    root = tmp_path / "rowanholt"
    (root / "deploy" / "linux").mkdir(parents=True)
    shutil.copy(REPO / "deploy" / "linux" / "install.sh", root / "deploy" / "linux" / "install.sh")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text("#!/bin/sh\nexit 1\n")
    (bin_dir / "docker").chmod(0o755)
    return root, {**os.environ, "PATH": f"{bin_dir}:/usr/bin:/bin:/usr/sbin"}


def server_init(root: Path, env: dict, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(root / "deploy" / "linux" / "install.sh"), "rowanholt.example.org", *args],
                          env=env, capture_output=True, text=True, check=False)


def test_server_init_records_the_first_admin_and_makes_no_password(tmp_path):
    root, env = init_tree(tmp_path)
    done = server_init(root, env, "--admin", "boss@example.org")
    assert done.returncode == 0, done.stderr
    text = (root / ".env").read_text()
    assert "ROWANHOLT_FIRST_ADMIN=boss@example.org" in text
    assert "ROWANHOLT_ADMIN_PASSWORD" not in text
    assert "boss@example.org" in done.stdout and "rowanholt start" in done.stdout


def test_server_init_without_an_admin_says_how_to_make_one(tmp_path):
    root, env = init_tree(tmp_path)
    done = server_init(root, env)
    assert done.returncode == 0, done.stderr
    assert "rowanholt server users first-admin" in done.stdout
    assert server_init(root, env, "--admin", "not-an-email").returncode == 1


def test_server_init_removes_an_old_admin_password(tmp_path):
    root, env = init_tree(tmp_path)
    (root / ".env").write_text("ROWANHOLT_ADMIN_PASSWORD=from-before\nSECRET_KEY=x\n")
    done = server_init(root, env)
    assert done.returncode == 0, done.stderr
    assert "ROWANHOLT_ADMIN_PASSWORD" not in (root / ".env").read_text()
    assert "Removed ROWANHOLT_ADMIN_PASSWORD" in done.stdout


def offer(tmp_path: Path, env_text: str, backend: str, stderr: bool = False) -> str:
    """offer_first_admin, run on its own: `backend` is the stand-in for compose exec's answer. What it
    printed (on stderr, with `stderr`)."""
    launcher = (REPO / "rowanholt").read_text()
    function = re.search(r"^offer_first_admin\(\) \{\n.*?^\}\n", launcher, re.DOTALL | re.MULTILINE).group(0)
    (tmp_path / ".env").write_text(env_text)
    script = (f'{function}\nROOT="$1"\nsleep() {{ :; }}\ncompose_cmd() {{ {backend}; }}\noffer_first_admin')
    done = subprocess.run(["bash", "-c", script, "bash", str(tmp_path)], capture_output=True, text=True, check=True)
    return done.stderr if stderr else done.stdout


def test_the_launcher_prints_the_first_admins_link_while_there_is_no_admin(tmp_path):
    out = offer(tmp_path, "ROWANHOLT_FIRST_ADMIN=boss@example.org\n",
                'echo "$*" > "$ROOT/asked"; echo https://r.test/accept-invite#tok')
    assert "https://r.test/accept-invite#tok" in out and "boss@example.org" in out
    assert "first-admin --link-only boss@example.org" in (tmp_path / "asked").read_text()


def test_the_launcher_warns_when_the_link_has_no_public_url(tmp_path):
    env = "ROWANHOLT_FIRST_ADMIN=boss@example.org\n"
    warned = offer(tmp_path, env, "echo https://localhost/accept-invite#tok", stderr=True)
    assert "ROWANHOLT_PUBLIC_URL isn't set" in warned
    assert offer(tmp_path, env, "echo https://r.test/accept-invite#tok", stderr=True) == ""


def test_the_launcher_says_nothing_once_there_is_an_admin(tmp_path):
    assert offer(tmp_path, "ROWANHOLT_FIRST_ADMIN=boss@example.org\n", "return 5").strip() == ""
    assert offer(tmp_path, "", "echo true").strip() == ""


def test_the_launcher_without_a_named_admin_says_how(tmp_path):
    assert "first-admin you@example.org" in offer(tmp_path, "", "echo false")
    # The backend never answered: the command to run once it does
    assert "Once the backend is up" in offer(tmp_path, "ROWANHOLT_FIRST_ADMIN=b@example.org\n", "return 1")


def test_the_launcher_says_an_old_admin_password_is_ignored(tmp_path):
    out = offer(tmp_path, "ROWANHOLT_ADMIN_PASSWORD=x\n", "echo true")
    assert "ROWANHOLT_ADMIN_PASSWORD in .env is ignored" in out


if __name__ == "__main__":
    unittest.main()
