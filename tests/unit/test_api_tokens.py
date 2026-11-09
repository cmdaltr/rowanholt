"""Unit tests for long-lived API tokens (src/web/backend/auth/tokens.py): made from a sign-in,
stored as a hash, revocable, expiring, and an aule-mcp scope that holds Aulë to reading, leads
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
        for method, path in (("POST", "/api/auth/tokens"), ("GET", "/api/auth/tokens"), ("POST", "/api/auth/session"),
                             ("POST", "/api/auth/change-password")):
            resp = self.client.request(method, path, headers=token, json={"name": "more"})
            self.assertEqual(resp.status_code, 403, f"{method} {path}: {resp.text}")

    def test_an_admins_token_cant_set_passwords_or_make_accounts(self):
        # Either would outlive the token: revoking it must end the access
        token = bearer(self.make(self.admin)["token"])
        alice = next(u for u in self.client.get("/api/auth/users", headers=self.admin).json() if u["username"] == "alice")
        for method, path, body in (("PATCH", f"/api/auth/users/{alice['id']}", {"password": "taken-over-123456"}),
                                   ("POST", "/api/auth/users", {"username": "backdoor", "email": "b@example.org",
                                                                "password": "backdoor-password-1", "role": "admin"}),
                                   ("GET", "/api/auth/users", None)):
            resp = self.client.request(method, path, headers=token, json=body)
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

    def test_an_aule_token_is_aule_without_the_header(self):
        job = self.case("CASE-TOKEN-1")
        aule = bearer(self.make(self.alice, name="Aulë", scope="aule-mcp")["token"])
        base = f"/api/jobs/{job}/case"
        row = {"host": "WS01", "artefact": "artefacts/cooked/prefetch.csv", "row_ref": "3", "title": "x"}

        self.assertEqual(self.client.get(f"{base}/findings", headers=aule).status_code, 200)
        lead = self.client.post(f"{base}/findings", headers=aule, json=row)
        self.assertEqual(lead.status_code, 200, lead.text)
        self.assertEqual(lead.json()["author"], "Aulë (for alice)")
        note = self.client.post(f"{base}/notes", headers=aule, json={"body": "worth a look"})
        self.assertEqual(note.json()["author"], "Aulë (for alice)")

        self.assertEqual(self.client.post(f"{base}/findings", headers=aule, json={**row, "status": "confirmed"}).status_code, 403)
        lead_id = lead.json()["id"]
        self.assertEqual(self.client.patch(f"{base}/findings/{lead_id}", headers=aule, json={"status": "confirmed"}).status_code, 403)
        self.assertEqual(self.client.delete(f"{base}/findings/{lead_id}", headers=aule).status_code, 403)
        self.assertEqual(self.client.put(f"{base}/hosts/WS01", headers=aule, json={"status": "done"}).status_code, 403)
        # Nothing else that writes: not starting or deleting jobs, not sharing them
        source = self.evidence / "CASE-TOKEN-2.E01"
        source.write_bytes(b"")
        self.assertEqual(self.client.post("/api/jobs", headers=aule, json={
            "case_number": "CASE-TOKEN-2", "source_paths": [str(source)]}).status_code, 403)
        self.assertEqual(self.client.delete(f"/api/jobs/{job}", headers=aule).status_code, 403)

    def test_an_aule_token_can_ask_aule(self):
        # The MCP server's ask_offline, ask_aule, case_summary and suggestions are POSTs that only read
        from auth import tokens
        token = {"scope": "aule-mcp"}
        for path in ("/api/ai/offline/answer", "/api/ai/cases/CASE-1/query", "/api/ai/cases/CASE-1/summary",
                     "/api/ai/cases/CASE-1/suggestions"):
            self.assertIsNone(tokens.refusal(token, "POST", path, ("/api/admin",)), path)
        for path in ("/api/ai/cases/CASE-1/query/x", "/api/ai/models/pull", "/api/ai/cases/CASE-1"):
            self.assertIsNotNone(tokens.refusal(token, "POST", path, ("/api/admin",)), path)
        aule = bearer(self.make(self.alice, name="Aulë", scope="aule-mcp")["token"])
        self.assertNotEqual(self.client.post("/api/ai/offline/answer", headers=aule,
                                             json={"question_id": "general"}).status_code, 403)

    def test_the_scope_from_before_the_rename_is_still_aule(self):
        # Aulë was Eru: an eru-mcp token asked for is made aule-mcp, and one stored before the
        # migration (f2b7c9d4e816) is held to what an aule-mcp token may do
        from auth import tokens
        made = self.make(self.alice, name="old script", scope="eru-mcp")
        self.assertEqual(made["scope"], "aule-mcp")
        me = self.client.get("/api/auth/me", headers=bearer(made["token"])).json()
        self.assertEqual(me["token"]["scope"], "aule-mcp")
        old = {"scope": "eru-mcp"}
        self.assertIsNone(tokens.refusal(old, "POST", "/api/ai/cases/CASE-1/query", ("/api/admin",)))
        self.assertIsNotNone(tokens.refusal(old, "DELETE", "/api/jobs/x", ("/api/admin",)))
        self.assertIsNotNone(tokens.refusal(old, "GET", "/api/admin/x", ("/api/admin",)))

    def test_an_admins_aule_token_has_no_admin_areas(self):
        aule = bearer(self.make(self.admin, name="Aulë", scope="aule-mcp")["token"])
        self.assertEqual(self.client.get("/api/auth/me", headers=aule).status_code, 200)
        for path in ("/api/auth/users", "/api/lab/status", "/api/aragorn/containers"):
            self.assertEqual(self.client.get(path, headers=aule).status_code, 403, path)


if __name__ == "__main__":
    unittest.main()
