"""Eru's MCP server (src/eru_mcp/server.py), driven through the MCP SDK's in-memory client against
the real backend in server mode (test_server_access.BackendCase). These are the threat model's
checks before it goes near a live case: the tool list against what's never exposed, no reaching a
job that isn't yours or shared with you, no reaching raw/, and no calls but Rowanholt's API.

Needs the backend's requirements and requirements/mcp.txt; skipped without them.
"""

import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

import test_server_access  # noqa: F401  (sets the backend's environment before anything imports it)
from test_server_access import BackendCase, TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
try:
    from mcp import Client
    from eru_mcp import server as eru_mcp
except ImportError:  # requirements/mcp.txt not installed
    Client = None

PHASE_1 = {"list_cases", "case_overview", "read_rows", "ask_offline", "ask_eru", "case_summary", "suggestions",
           "check_indicator", "rare_across_hosts", "findings", "report", "navigator_layer"}
PHASE_2 = {"flag_lead", "add_note"}
NEVER = ("start", "restart", "delete", "cancel", "acquire", "gandalf", "collect", "import", "upload", "share",
         "assign", "confirm", "dismiss", "update", "remove", "raw")


@unittest.skipIf(TestClient is None or Client is None, "backend requirements or requirements/mcp.txt not installed")
class EruMcpTest(BackendCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.calls = []
        # Ollama isn't here: the model tools should say so and point to ask_offline
        cls.no_llm = mock.patch.object(sys.modules["ai_routes"].ollama, "check_available",
                                       mock.AsyncMock(return_value={"available": False}))
        cls.no_llm.start()

    @classmethod
    def tearDownClass(cls):
        cls.no_llm.stop()
        super().tearDownClass()

    def server(self, headers, **options):
        def send(method, path, params, body, token):
            self.calls.append(path)
            # RowanholtAPI._urllib sends the agent header (test_the_agent_header_is_sent)
            resp = self.client.request(method, path, params=params, json=body,
                                       headers={**headers, eru_mcp.AGENT_HEADER[0]: eru_mcp.AGENT_HEADER[1]})
            is_json = "json" in resp.headers.get("content-type", "")
            return resp.status_code, resp.json() if is_json else resp.text
        return eru_mcp.build_server(eru_mcp.RowanholtAPI("http://testserver", transport=send), **options)

    def call(self, headers, name, server=None, **arguments):
        """(is_error, result): the tool's structured result, or its error text."""
        async def run():
            async with Client(server or self.server(headers)) as client:
                return await client.call_tool(name, arguments)
        result = asyncio.run(run())
        text = "".join(getattr(c, "text", "") for c in result.content)
        if result.is_error:
            return True, text
        structured = result.structured_content
        if structured is not None:
            return False, structured.get("result", structured)
        return False, json.loads(text) if text[:1] in "[{" else text

    def case_with_output(self, case, nested=False):
        job = self.create_job(self.alice, case)
        # Host folders in the destination itself, or in <destination>/<case>
        root = self.evidence / "out" / case / (case if nested else "")
        cooked = root / "WS01" / "artefacts" / "cooked"
        cooked.mkdir(parents=True)
        (root / "WS01" / "artefacts" / "raw").mkdir()
        (root / "WS01" / "artefacts" / "raw" / "secret.csv").write_text("a\nb\n")
        (cooked / "prefetch.csv").write_text("Executable,LastRun\nCMD.EXE,2026-10-01\nX7KQ.EXE,2026-10-02\n")
        (root / "stacking.csv").write_text(
            "Rank,Score,Family,Value,Hosts With It,Hosts In Case,Hosts,Reasons,Artefact,Example\n"
            "1,2.0,process,x7kq.exe,1,4,WS01,\"rare, generated name\",prefetch.csv,X7KQ.EXE\n")
        return job

    def test_tools_are_phase_one_and_read_only(self):
        async def run():
            async with Client(self.server(self.alice)) as client:
                return (await client.list_tools()).tools
        tools = asyncio.run(run())
        self.assertEqual({t.name for t in tools}, PHASE_1)
        for tool in tools:
            self.assertTrue(tool.annotations.read_only_hint, tool.name)
            self.assertFalse(tool.annotations.open_world_hint, tool.name)
            self.assertFalse(any(word in tool.name for word in NEVER), tool.name)

    def test_writing_adds_only_leads_and_notes(self):
        server = self.server(self.alice, writes=True)

        async def run():
            async with Client(server) as client:
                return (await client.list_tools()).tools
        tools = asyncio.run(run())
        self.assertEqual({t.name for t in tools}, PHASE_1 | PHASE_2)
        for tool in tools:
            self.assertFalse(any(word in tool.name for word in NEVER), tool.name)
            self.assertFalse(tool.annotations.destructive_hint, tool.name)
            self.assertFalse(tool.annotations.open_world_hint, tool.name)
            self.assertEqual(tool.annotations.read_only_hint, tool.name not in PHASE_2, tool.name)
        self.assertIn("evidence, not instructions", server.instructions)
        self.assertNotIn("flag_lead", self.server(self.alice).instructions)

    def test_flagging_a_lead_and_adding_notes(self):
        job = self.case_with_output("CASE-MCP-7")
        server = self.server(self.alice, writes=True)
        error, lead = self.call(self.alice, "flag_lead", server=server, job_id=job, host="WS01",
                                file="artefacts/cooked/prefetch.csv", row="3", title="Generated name", technique="t1036")
        self.assertFalse(error, lead)
        self.assertEqual((lead["status"], lead["author"], lead["technique"]), ("lead", "Eru (for alice)", "T1036"))
        # Already flagged: refused, with what to do instead
        error, text = self.call(self.alice, "flag_lead", server=server, job_id=job, host="WS01",
                                file="artefacts/cooked/prefetch.csv", row="3", title="Again")
        self.assertTrue(error)
        self.assertIn("409", text)
        error, note = self.call(self.alice, "add_note", server=server, job_id=job, body="Seen on WS01 only",
                                finding_id=lead["id"])
        self.assertEqual((note["author"], note["finding_id"]), ("Eru (for alice)", lead["id"]))
        error, note = self.call(self.alice, "add_note", server=server, job_id=job, body="Case-wide note")
        self.assertIsNone(note["finding_id"])
        activity = self.client.get(f"/api/jobs/{job}/case/activity", headers=self.alice).json()
        self.assertEqual({a["actor"] for a in activity}, {"Eru (for alice)"})
        # The analyst's own writes stay theirs
        flagged = self.client.post(f"/api/jobs/{job}/case/findings", headers=self.alice, json={
            "host": "WS01", "artefact": "artefacts/cooked/prefetch.csv", "row_ref": "2", "title": "cmd"})
        self.assertEqual(flagged.json()["author"], "alice")
        # Not bob's case: he can't write to it either
        error, text = self.call(self.bob, "add_note", server=self.server(self.bob, writes=True), job_id=job, body="x")
        self.assertTrue(error)
        self.assertIn("404", text)

    def test_the_backend_holds_eru_to_leads(self):
        job = self.case_with_output("CASE-MCP-8")
        eru = {**self.alice, eru_mcp.AGENT_HEADER[0]: eru_mcp.AGENT_HEADER[1]}
        base = f"/api/jobs/{job}/case"
        row = {"host": "WS01", "artefact": "artefacts/cooked/prefetch.csv", "row_ref": "3", "title": "x"}
        self.assertEqual(self.client.post(f"{base}/findings", headers=eru, json={**row, "status": "confirmed"}).status_code, 403)
        lead = self.client.post(f"{base}/findings", headers=eru, json=row).json()
        self.assertEqual(self.client.patch(f"{base}/findings/{lead['id']}", headers=eru,
                                           json={"status": "confirmed"}).status_code, 403)
        self.assertEqual(self.client.delete(f"{base}/findings/{lead['id']}", headers=eru).status_code, 403)
        self.assertEqual(self.client.put(f"{base}/hosts/WS01", headers=eru, json={"status": "done"}).status_code, 403)
        # The analyst confirms it
        confirmed = self.client.patch(f"{base}/findings/{lead['id']}", headers=self.alice, json={"status": "confirmed"})
        self.assertEqual(confirmed.json()["status"], "confirmed")

    def test_an_mcp_server_from_before_the_rename_is_still_eru(self):
        job = self.case_with_output("CASE-MCP-24")
        eru = {**self.alice, "X-Rivendell-Agent": "eru-mcp"}
        base = f"/api/jobs/{job}/case"
        row = {"host": "WS01", "artefact": "artefacts/cooked/prefetch.csv", "row_ref": "3", "title": "x"}
        self.assertEqual(self.client.post(f"{base}/findings", headers=eru, json={**row, "status": "confirmed"}).status_code, 403)
        self.assertEqual(self.client.post(f"{base}/findings", headers=eru, json=row).json()["author"], "Eru (for alice)")

    def test_a_session_stops_at_its_write_limit(self):
        job = self.case_with_output("CASE-MCP-9")
        server = self.server(self.alice, writes=True, max_writes=2)
        for n in range(2):
            self.assertFalse(self.call(self.alice, "add_note", server=server, job_id=job, body=f"note {n}")[0])
        error, text = self.call(self.alice, "add_note", server=server, job_id=job, body="one too many")
        self.assertTrue(error)
        self.assertIn("2 writes", text)
        self.assertEqual(len(self.client.get(f"/api/jobs/{job}/case/notes", headers=self.alice).json()), 2)

    def test_writes_need_an_eru_token_on_a_server(self):
        def api(headers):
            def send(method, path, params, body, token):
                resp = self.client.request(method, path, params=params, json=body, headers=headers)
                return resp.status_code, resp.json()
            return eru_mcp.RowanholtAPI("http://testserver", transport=send)

        def token(scope):
            made = self.client.post("/api/auth/tokens", headers=self.alice, json={"name": "mcp", "scope": scope})
            return {"Authorization": f"Bearer {made.json()['token']}"}

        self.assertIsNone(eru_mcp.write_refusal(api(token("eru-mcp"))))
        self.assertIn("not a full token", eru_mcp.write_refusal(api(token("full"))))
        self.assertIn("not a sign-in token", eru_mcp.write_refusal(api(self.alice)))
        self.assertIn("can't check the token", eru_mcp.write_refusal(api({})))
        # On an analyst's own machine there's no token to check
        self.settings.rowanholt_server_mode = False
        try:
            self.assertIsNone(eru_mcp.write_refusal(api({})))
        finally:
            self.settings.rowanholt_server_mode = True

    def test_over_http_each_request_is_its_own_analyst(self):
        """Streamable HTTP (a team server's /mcp): no token of its own; each request's API token is checked
        against Rowanholt and used for its calls; only eru-mcp tokens are taken, reads included."""
        import socket
        import threading
        import time
        import httpx2
        import uvicorn
        from mcp.client.streamable_http import streamable_http_client

        def send(method, path, params, body, token):
            headers = {eru_mcp.AGENT_HEADER[0]: eru_mcp.AGENT_HEADER[1], **({"Authorization": f"Bearer {token}"} if token else {})}
            resp = self.client.request(method, path, params=params, json=body, headers=headers)
            return resp.status_code, resp.json() if "json" in resp.headers.get("content-type", "") else resp.text

        def token(headers, scope):
            made = self.client.post("/api/auth/tokens", headers=headers, json={"name": "mcp-http", "scope": scope})
            self.assertEqual(made.status_code, 200, made.text)
            return made.json()["token"]

        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        url = f"http://127.0.0.1:{port}/mcp"
        api = eru_mcp.RowanholtAPI("http://testserver", eru_mcp.request_token, transport=send)
        self.assertIsNone(eru_mcp.http_refusal(api, "https://rowanholt.example.org"))
        self.assertIn("https", eru_mcp.http_refusal(api, "http://rowanholt.example.org"))
        self.settings.rowanholt_server_mode = False
        try:
            self.assertIn("team server", eru_mcp.http_refusal(api, "https://rowanholt.example.org"))
        finally:
            self.settings.rowanholt_server_mode = True
        server = eru_mcp.build_server(api, writes=True, max_writes=1, http_url=url)
        web = uvicorn.Server(uvicorn.Config(server.streamable_http_app(host="127.0.0.1"), host="127.0.0.1", port=port,
                                            log_level="warning"))
        thread = threading.Thread(target=web.run, daemon=True)
        thread.start()
        for _ in range(100):
            if web.started:
                break
            time.sleep(0.05)

        async def call(bearer, name, **arguments):
            async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {bearer}"}, timeout=30) as http:
                async with Client(streamable_http_client(url, http_client=http)) as client:
                    result = await client.call_tool(name, arguments)
            return result.is_error, "".join(getattr(c, "text", "") for c in result.content)

        try:
            # What a client reads after a 401 names Rowanholt as analysts reach it, not the backend inside the stack
            meta = httpx2.get(f"http://127.0.0.1:{port}/.well-known/oauth-protected-resource/mcp").json()
            self.assertEqual([s.rstrip("/") for s in meta["authorization_servers"]], [url[:-len("/mcp")]])
            job = self.create_job(self.alice, "CASE-MCP-HTTP-1")
            alice, bob = token(self.alice, "eru-mcp"), token(self.bob, "eru-mcp")
            self.assertIn(job, asyncio.run(call(alice, "list_cases"))[1])
            self.assertNotIn(job, asyncio.run(call(bob, "list_cases"))[1])
            # A full token, a sign-in's JWT, or nothing Rowanholt knows: 401, before any tool
            for refused in (token(self.alice, "full"), self.alice["Authorization"][7:], "not-a-token"):
                with self.assertRaises(Exception):
                    asyncio.run(call(refused, "list_cases"))
            error, text = asyncio.run(call(bob, "add_note", job_id=job, body="from bob"))
            self.assertTrue(error and "not found" in text.lower(), text)  # bob's eru-mcp token, alice's job
            self.assertEqual(asyncio.run(call(alice, "add_note", job_id=job, body="from Eru"))[0], False)
            error, text = asyncio.run(call(alice, "add_note", job_id=job, body="again"))
            self.assertTrue(error and "made its 1 writes" in text, text)
            notes = self.client.get(f"/api/jobs/{job}/case/notes", headers=self.alice).json()
            self.assertEqual([(n["body"], n["author"]) for n in notes], [("from Eru", "Eru (for alice)")])
        finally:
            web.should_exit = True
            thread.join(10)

    def test_the_agent_header_is_sent(self):
        sent = []

        class Response:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b"{}"

        def urlopen(request, timeout):
            sent.append(dict(request.header_items()))
            return Response()

        with mock.patch.object(eru_mcp.urllib.request, "urlopen", urlopen):
            eru_mcp.RowanholtAPI("http://testserver", "t0ken").get("/api/jobs")
        self.assertEqual(sent[0].get("X-rowanholt-agent"), "eru-mcp")
        self.assertEqual(sent[0].get("Authorization"), "Bearer t0ken")

    def test_reading_a_case(self):
        job = self.case_with_output("CASE-MCP-1")
        error, cases = self.call(self.alice, "list_cases")
        self.assertIn(job, {c["id"] for c in cases})
        error, overview = self.call(self.alice, "case_overview", job_id=job)
        self.assertFalse(error, overview)
        self.assertEqual(overview["job"]["case_number"], "CASE-MCP-1")
        self.assertEqual([h["host"] for h in overview["case"]["hosts"]], ["WS01"])

        error, page = self.call(self.alice, "read_rows", job_id=job, host="WS01",
                                file="artefacts/cooked/prefetch.csv", filter="x7kq")
        self.assertFalse(error, page)
        self.assertEqual(len(page["rows"]), 1)
        self.assertTrue(page["rows"][0]["cite"].startswith("WS01: artefacts/cooked/prefetch.csv row "))
        error, rare = self.call(self.alice, "rare_across_hosts", job_id=job)
        self.assertEqual(rare["rows"][0]["cells"]["Value"], "x7kq.exe")

        error, answer = self.call(self.alice, "ask_offline", job_id=job, question="Which hosts are in this case?")
        self.assertIn("WS01", answer["answer"])
        error, answer = self.call(self.alice, "ask_offline", job_id=job, question="rare")
        self.assertIn("x7kq.exe", answer["answer"])
        self.assertEqual([r["cite"][:23] for r in answer["rows"]], ["(case): stacking.csv ro"])
        error, unknown = self.call(self.alice, "ask_offline", job_id=job, question="who did it")
        self.assertIn("hosts", {q["id"] for q in unknown["questions"]})

        error, answer = self.call(self.alice, "ask_eru", job_id=job, question="What happened?")
        self.assertEqual(answer["available"], "no")
        self.assertIn("ask_offline", answer["instead"])
        self.assertEqual(self.call(self.alice, "findings", job_id=job), (False, []))
        error, layer = self.call(self.alice, "navigator_layer", job_id=job)
        self.assertEqual(layer["techniques"], [])
        error, text = self.call(self.alice, "report", job_id=job)
        self.assertIn("CASE-MCP-1", text)

    def test_offline_answers_in_a_nested_case(self):
        job = self.case_with_output("CASE-MCP-5", nested=True)
        error, answer = self.call(self.alice, "ask_offline", job_id=job, question="hosts")
        self.assertFalse(error, answer)
        self.assertIn("WS01", answer["answer"])
        error, overview = self.call(self.alice, "case_overview", job_id=job)
        self.assertEqual([h["host"] for h in overview["case"]["hosts"]], ["WS01"])

    def test_flagging_a_cited_row(self):
        job = self.case_with_output("CASE-MCP-6")
        analysis = self.evidence / "out" / "CASE-MCP-6" / "WS01" / "analysis"
        analysis.mkdir()
        (analysis / "analysis.csv").write_text("Filename,analysis_type,analysis_value\nX7KQ.EXE,masquerading,svchost\n")
        resp = self.client.post("/api/ai/offline/answer", headers=self.alice,
                                json={"question_id": "analysis", "case_id": "CASE-MCP-6"})
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertEqual(body["job_id"], job)
        [row] = body["rows"]
        self.assertEqual((row["host"], row["file"], row["row_ref"]), ("WS01", "analysis/analysis.csv", "2"))
        flagged = self.client.post(f"/api/jobs/{job}/case/findings", headers=self.alice, json={
            "host": row["host"], "artefact": row["file"], "row_ref": row["row_ref"], "title": "X7KQ.EXE posing as svchost"})
        self.assertEqual(flagged.status_code, 200, flagged.text)
        self.assertEqual(flagged.json()["row_hash"], row["hash"])
        # A stacking row is flagged on the host row it was read from
        (self.evidence / "out" / "CASE-MCP-6" / "stacking.csv").write_text(
            "Rank,Score,Family,Value,Hosts With It,Hosts In Case,Hosts,Reasons,Artefact,Example,Host,Row\n"
            "1,2.0,process,x7kq.exe,1,4,WS01,rare,artefacts/cooked/prefetch.csv,X7KQ.EXE,WS01,3\n")
        body = self.client.post("/api/ai/offline/answer", headers=self.alice,
                                json={"question_id": "rare", "case_id": "CASE-MCP-6"}).json()
        [row] = body["rows"]
        self.assertEqual((row["host"], row["file"], row["row_ref"]), ("WS01", "artefacts/cooked/prefetch.csv", "3"))
        flagged = self.client.post(f"/api/jobs/{job}/case/findings", headers=self.alice, json={
            "host": row["host"], "artefact": row["file"], "row_ref": row["row_ref"], "title": row["line"]})
        self.assertEqual(flagged.status_code, 200, flagged.text)
        self.assertIn("X7KQ.EXE", flagged.json()["excerpt"])
        # Not bob's case: no answer from it, so nothing to flag
        resp = self.client.post("/api/ai/offline/answer", headers=self.bob,
                                json={"question_id": "analysis", "case_id": "CASE-MCP-6"})
        self.assertEqual(resp.status_code, 404)

    def test_eru_reads_the_job_asked_for(self):
        # Two of alice's jobs share a case number: each answers from its own output, not the first one's
        first = self.case_with_output("CASE-MCP-21")
        source = self.evidence / "CASE-MCP-21b.E01"
        source.write_bytes(b"")
        second = self.client.post("/api/jobs", headers=self.alice, json={
            "case_number": "CASE-MCP-21", "source_paths": [str(source)],
            "destination_path": str(self.evidence / "out" / "CASE-MCP-21b")}).json()["id"]
        cooked = self.evidence / "out" / "CASE-MCP-21b" / "WS02" / "artefacts" / "cooked"
        cooked.mkdir(parents=True)
        (cooked / "prefetch.csv").write_text("Executable,LastRun\nNOTEPAD.EXE,2026-10-03\n")
        for job, host, other in ((first, "WS01", "WS02"), (second, "WS02", "WS01")):
            error, answer = self.call(self.alice, "ask_offline", job_id=job, question="hosts")
            self.assertFalse(error, answer)
            self.assertIn(host, answer["answer"])
            self.assertNotIn(other, answer["answer"])
        # Ask Eru lists each (completed) job, not one per case number
        from models.job import JobStatus
        for job in (first, second):
            stored = self.main.job_storage.get_job(job)
            stored.status = JobStatus.COMPLETED
            self.main.job_storage.save_job(stored)
        listed = {c.get("job_id") for c in self.client.get("/api/ai/cases", headers=self.alice).json()["cases"]}
        self.assertLessEqual({first, second}, listed)
        # Someone else's job, or a job that isn't this case: nothing
        bobs = self.create_job(self.bob, "CASE-MCP-22")
        for case in ("CASE-MCP-22", "CASE-MCP-21"):
            resp = self.client.post("/api/ai/offline/answer", headers=self.alice,
                                    json={"question_id": "hosts", "case_id": case, "job_id": bobs})
            self.assertEqual(resp.status_code, 404, (case, resp.text))

    def test_a_case_folder_is_for_admins(self):
        # A folder in Eru's data directory has no job, so no owner: a user whose job has the same case
        # number gets their job's output, not the folder
        import ai_routes
        data = self.evidence / "eru-data"
        (data / "CASE-MCP-23" / "WS09" / "artefacts" / "cooked").mkdir(parents=True)
        bobs = self.create_job(self.bob, "CASE-MCP-23")
        (self.evidence / "out" / "CASE-MCP-23" / "WS01" / "artefacts" / "cooked").mkdir(parents=True)
        with mock.patch.object(ai_routes, "ROWANHOLT_DATA_DIR", str(data)):
            def hosts(headers):
                resp = self.client.post("/api/ai/offline/answer", headers=headers,
                                        json={"question_id": "hosts", "case_id": "CASE-MCP-23"})
                return resp.json()
            self.assertIn("WS01", hosts(self.bob)["answer"])
            self.assertNotIn("WS09", hosts(self.bob)["answer"])
            self.assertEqual(hosts(self.bob)["job_id"], bobs)
            self.assertIn("WS09", hosts(self.admin)["answer"])
            listed = self.client.get("/api/ai/cases", headers=self.bob).json()["cases"]
            self.assertFalse([c for c in listed if not c.get("job_id")], listed)

    def test_other_peoples_jobs_unreachable(self):
        job = self.case_with_output("CASE-MCP-2")
        error, cases = self.call(self.bob, "list_cases")
        self.assertNotIn(job, {c["id"] for c in cases})
        for name, args in (("case_overview", {}), ("findings", {}), ("report", {}), ("rare_across_hosts", {}),
                           ("ask_offline", {"question": "hosts"}),
                           ("read_rows", {"host": "WS01", "file": "artefacts/cooked/prefetch.csv"})):
            error, text = self.call(self.bob, name, job_id=job, **args)
            self.assertTrue(error, f"{name}: {text}")
            self.assertIn("404", text)
        # Shared with bob, it is
        self.client.put(f"/api/jobs/{job}/sharing", headers=self.alice, json={"usernames": ["bob"]})
        self.assertFalse(self.call(self.bob, "case_overview", job_id=job)[0])

    def test_raw_unreachable(self):
        job = self.case_with_output("CASE-MCP-3")
        for host, file in (("WS01", "artefacts/raw/secret.csv"), ("WS01", "artefacts/cooked/../raw/secret.csv"),
                           ("(case)", "WS01/artefacts/raw/secret.csv")):
            error, text = self.call(self.alice, "read_rows", job_id=job, host=host, file=file)
            self.assertTrue(error, f"{host} {file}: {text}")
        error, text = self.call(self.alice, "case_overview", job_id="..")
        self.assertTrue(error, text)

    def test_only_rowanholts_api(self):
        api = eru_mcp.RowanholtAPI("http://testserver", transport=lambda *a: (200, {}))
        for path in ("http://198.51.100.23/api/jobs", "/api/jobs/../../etc", "/healthz", "//198.51.100.23/api/"):
            with self.assertRaises(ValueError, msg=path):
                api.get(path)
        self.assertEqual(api.path("jobs", "a/b?c"), "/api/jobs/a%2Fb%3Fc")
        self.calls.clear()
        job = self.case_with_output("CASE-MCP-4")
        for name, args in (("list_cases", {}), ("case_overview", {"job_id": job}), ("check_indicator", {"value": "x7kq.exe"}),
                           ("ask_offline", {"job_id": job, "question": "hosts"}), ("suggestions", {"job_id": job})):
            self.call(self.alice, name, **args)
        self.assertTrue(self.calls)
        self.assertTrue(all(p.startswith("/api/") for p in self.calls), self.calls)


@unittest.skipIf(Client is None, "requirements/mcp.txt not installed")
class TransportSecurityTest(unittest.TestCase):
    def test_other_addresses_are_allowed_beside_the_public_one(self):
        # server init --service: the Tailscale Service name is public, the host-and-port address stays open
        security = eru_mcp.transport_security("https://rowanholt.tail1234.ts.net/",
                                              "https://homelab.tail1234.ts.net:8443, ", "0.0.0.0:5690")
        self.assertEqual(security.allowed_hosts,
                         ["rowanholt.tail1234.ts.net", "homelab.tail1234.ts.net:8443", "0.0.0.0:5690"])
        self.assertEqual(security.allowed_origins,
                         ["https://rowanholt.tail1234.ts.net", "https://homelab.tail1234.ts.net:8443"])
        alone = eru_mcp.transport_security("https://rowanholt.example.org", "", "0.0.0.0:5690")
        self.assertEqual(alone.allowed_hosts, ["rowanholt.example.org", "0.0.0.0:5690"])


if __name__ == "__main__":
    unittest.main()
