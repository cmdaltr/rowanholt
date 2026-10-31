"""Eru's MCP server (src/eru_mcp/server.py), driven through the MCP SDK's in-memory client against
the real backend in server mode (test_server_access.BackendCase). These are the threat model's
checks before it goes near a live case: the tool list against what's never exposed, no reaching a
job that isn't yours or shared with you, no reaching raw/, and no calls but Rivendell's API.

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
NEVER = ("start", "restart", "delete", "cancel", "acquire", "gandalf", "collect", "import", "upload", "share",
         "flag", "note", "assign", "raw")


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

    def server(self, headers):
        def send(method, path, params, body):
            self.calls.append(path)
            resp = self.client.request(method, path, params=params, json=body, headers=headers)
            is_json = "json" in resp.headers.get("content-type", "")
            return resp.status_code, resp.json() if is_json else resp.text
        return eru_mcp.build_server(eru_mcp.RivendellAPI("http://testserver", transport=send))

    def call(self, headers, name, **arguments):
        """(is_error, result): the tool's structured result, or its error text."""
        async def run():
            async with Client(self.server(headers)) as client:
                return await client.call_tool(name, arguments)
        result = asyncio.run(run())
        text = "".join(getattr(c, "text", "") for c in result.content)
        if result.is_error:
            return True, text
        structured = result.structured_content
        if structured is not None:
            return False, structured.get("result", structured)
        return False, json.loads(text) if text[:1] in "[{" else text

    def case_with_output(self, case):
        job = self.create_job(self.alice, case)
        root = self.evidence / "out" / case  # host folders in the destination itself
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

    def test_only_rivendells_api(self):
        api = eru_mcp.RivendellAPI("http://testserver", transport=lambda *a: (200, {}))
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


if __name__ == "__main__":
    unittest.main()
