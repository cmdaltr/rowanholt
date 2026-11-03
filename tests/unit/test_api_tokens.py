"""Unit tests for long-lived API tokens (src/web/backend/auth/tokens.py): made from a sign-in,
stored as a hash, revocable, expiring, and an eru-mcp scope that holds Eru to reading, leads
and notes whatever headers it sends.

Run from tests/unit: python3 -m unittest test_api_tokens.py
"""

import sys
import unittest
from datetime import datetime, timedelta

from test_server_access import BackendCase, TestClient


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class ApiTokenTest(BackendCase):
    def make(self, headers, name="script", scope="full", days=30):
        resp = self.client.post("/api/auth/tokens", headers=headers, json={"name": name, "scope": scope, "days": days})
        self.assertEqual(resp.status_code, 200, resp.text)
        return resp.json()

    def case(self, case):
        job = self.create_job(self.alice, case)
        cooked = self.evidence / "out" / case / "WS01" / "artefacts" / "cooked"
        cooked.mkdir(parents=True)
        (cooked / "prefetch.csv").write_text("Executable,LastRun\nCMD.EXE,2026-10-01\nX7KQ.EXE,2026-10-02\n")
        return job

    def test_a_token_works_until_revoked(self):
        made = self.make(self.alice)
        self.assertTrue(made["token"].startswith("rvt_"))
        self.assertTrue(made["token"].startswith(made["prefix"]))
        me = self.client.get("/api/auth/me", headers=bearer(made["token"]))
        self.assertEqual(me.status_code, 200, me.text)
        self.assertEqual(me.json()["username"], "alice")

        listed = self.client.get("/api/auth/tokens", headers=self.alice).json()["tokens"]
        mine = next(t for t in listed if t["id"] == made["id"])
        self.assertNotIn("token", mine)
        self.assertNotIn("token_hash", mine)
        self.assertIsNotNone(mine["last_used_at"])

        self.assertEqual(self.client.delete(f"/api/auth/tokens/{made['id']}", headers=self.alice).status_code, 200)
        self.assertEqual(self.client.get("/api/auth/me", headers=bearer(made["token"])).status_code, 401)

    def test_only_a_hash_is_stored(self):
        made = self.make(self.alice)
        from sqlalchemy import text
        storage = sys.modules["auth.access"]._storage
        with storage.engine.connect() as connection:
            rows = connection.execute(text("SELECT token_hash FROM api_tokens WHERE id = :id"), {"id": made["id"]}).all()
        self.assertEqual(len(rows), 1)
        self.assertNotIn(made["token"], rows[0][0])
        self.assertEqual(len(rows[0][0]), 64)

    def test_an_expired_token_is_refused(self):
        made = self.make(self.alice, days=1)
        from sqlalchemy import text
        storage = sys.modules["auth.access"]._storage
        with storage.engine.begin() as connection:
            connection.execute(text("UPDATE api_tokens SET expires_at = :t WHERE id = :id"),
                               {"t": datetime.now() - timedelta(seconds=1), "id": made["id"]})
        self.assertEqual(self.client.get("/api/auth/me", headers=bearer(made["token"])).status_code, 401)

    def test_a_deactivated_users_tokens_stop(self):
        resp = self.client.post("/api/auth/users", headers=self.admin, json={
            "username": "carol", "email": "carol@example.org", "password": "carol-password-123"})
        self.assertIn(resp.status_code, (200, 400), resp.text)
        carol = self.login("carol", "carol-password-123")
        made = self.make(carol)
        carol_id = self.client.get("/api/auth/me", headers=carol).json()["id"]
        self.assertEqual(self.client.patch(f"/api/auth/users/{carol_id}", headers=self.admin,
                                           json={"is_active": False}).status_code, 200)
        try:
            self.assertEqual(self.client.get("/api/auth/me", headers=bearer(made["token"])).status_code, 401)
        finally:
            self.client.patch(f"/api/auth/users/{carol_id}", headers=self.admin, json={"is_active": True})

    def test_tokens_are_managed_from_a_sign_in(self):
        token = bearer(self.make(self.alice)["token"])
        for method, path in (("POST", "/api/auth/tokens"), ("GET", "/api/auth/tokens"), ("POST", "/api/auth/session")):
            resp = self.client.request(method, path, headers=token, json={"name": "more"})
            self.assertEqual(resp.status_code, 403, f"{method} {path}: {resp.text}")

    def test_limits_on_making_and_revoking(self):
        for body in ({"name": "", "scope": "full"}, {"name": "x", "scope": "admin"},
                     {"name": "x", "days": 0}, {"name": "x", "days": 366}):
            self.assertEqual(self.client.post("/api/auth/tokens", headers=self.alice, json=body).status_code, 400, body)
        made = self.make(self.alice)
        # Bob can't see or revoke Alice's tokens; an admin can
        self.assertNotIn(made["id"], {t["id"] for t in self.client.get("/api/auth/tokens", headers=self.bob).json()["tokens"]})
        self.assertEqual(self.client.get("/api/auth/tokens?all=true", headers=self.bob).status_code, 403)
        self.assertEqual(self.client.delete(f"/api/auth/tokens/{made['id']}", headers=self.bob).status_code, 404)
        self.assertIn(made["id"], {t["id"] for t in self.client.get("/api/auth/tokens?all=true", headers=self.admin).json()["tokens"]})
        self.assertEqual(self.client.delete(f"/api/auth/tokens/{made['id']}", headers=self.admin).status_code, 200)
        self.assertEqual(self.client.get("/api/auth/me", headers=bearer(made["token"])).status_code, 401)

    def test_an_eru_token_is_eru_without_the_header(self):
        job = self.case("CASE-TOKEN-1")
        eru = bearer(self.make(self.alice, name="Eru", scope="eru-mcp")["token"])
        base = f"/api/jobs/{job}/case"
        row = {"host": "WS01", "artefact": "artefacts/cooked/prefetch.csv", "row_ref": "3", "title": "x"}

        self.assertEqual(self.client.get(f"{base}/findings", headers=eru).status_code, 200)
        lead = self.client.post(f"{base}/findings", headers=eru, json=row)
        self.assertEqual(lead.status_code, 200, lead.text)
        self.assertEqual(lead.json()["author"], "Eru (for alice)")
        note = self.client.post(f"{base}/notes", headers=eru, json={"body": "worth a look"})
        self.assertEqual(note.json()["author"], "Eru (for alice)")

        self.assertEqual(self.client.post(f"{base}/findings", headers=eru, json={**row, "status": "confirmed"}).status_code, 403)
        lead_id = lead.json()["id"]
        self.assertEqual(self.client.patch(f"{base}/findings/{lead_id}", headers=eru, json={"status": "confirmed"}).status_code, 403)
        self.assertEqual(self.client.delete(f"{base}/findings/{lead_id}", headers=eru).status_code, 403)
        self.assertEqual(self.client.put(f"{base}/hosts/WS01", headers=eru, json={"status": "done"}).status_code, 403)
        # Nothing else that writes: not starting or deleting jobs, not sharing them
        source = self.evidence / "CASE-TOKEN-2.E01"
        source.write_bytes(b"")
        self.assertEqual(self.client.post("/api/jobs", headers=eru, json={
            "case_number": "CASE-TOKEN-2", "source_paths": [str(source)]}).status_code, 403)
        self.assertEqual(self.client.delete(f"/api/jobs/{job}", headers=eru).status_code, 403)

    def test_an_admins_eru_token_has_no_admin_areas(self):
        eru = bearer(self.make(self.admin, name="Eru", scope="eru-mcp")["token"])
        self.assertEqual(self.client.get("/api/auth/me", headers=eru).status_code, 200)
        for path in ("/api/auth/users", "/api/lab/status", "/api/aragorn/containers"):
            self.assertEqual(self.client.get(path, headers=eru).status_code, 403, path)


if __name__ == "__main__":
    unittest.main()
