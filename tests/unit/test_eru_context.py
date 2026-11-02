"""What Eru's model is given (src/web/backend/eru_context.py): numbered rows from the per-host case
layout, and only rows it was shown come back as citations. The end-to-end test asks a case through
the real backend (test_server_access.BackendCase) with the model mocked."""
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "web" / "backend"))

import test_server_access  # noqa: F401,E402  (sets the backend's environment before anything imports it)
from test_server_access import BackendCase, TestClient  # noqa: E402

import case_files  # noqa: E402
import eru_context  # noqa: E402


def make_case(root: Path) -> Path:
    for host in ("WS01", "WS02"):
        cooked = root / host / "artefacts" / "cooked"
        cooked.mkdir(parents=True)
        (root / host / "artefacts" / "host.info").write_text(f"{host}::Windows\n")
    (root / "WS01" / "artefacts" / "cooked" / "prefetch.csv").write_text(
        "Executable,LastRun\nCMD.EXE,2026-10-01\nX7KQ.EXE,2026-10-02\n")
    (root / "WS02" / "artefacts" / "cooked" / "autostart.csv").write_text(
        "Source,Kind,Name,Command,Flag\n/etc/xdg/autostart,desktop,lab-sync,/tmp/.s/sync,command in a temporary directory\n")
    (root / "mitre_techniques.txt").write_text("T1547.001\n")
    return root


def test_terms():
    assert eru_context.terms("What ran X7KQ.EXE on the host, and when?") == ["x7kq.exe"]
    assert eru_context.terms("what happened") == []


def test_context_is_numbered_from_the_hosts(tmp_path):
    root = make_case(tmp_path / "CASE")
    context = eru_context.build(str(root), "Did x7kq.exe run?")
    text = context.text()
    assert "WS01" in text and "T1547.001" in text
    tag = next(t for t, row in context.rows.items() if row["file"] == "artefacts/cooked/prefetch.csv")
    assert re.search(rf"\[{tag}\] WS01 artefacts/cooked/prefetch.csv row 3: .*X7KQ.EXE", text)
    lead = next(t for t, row in context.rows.items() if row["file"] == "artefacts/cooked/autostart.csv")
    assert f"[{lead}] WS02" in text  # flagged persistence, though the question doesn't name it
    row = context.rows[tag]
    page = case_files.page(case_files.resolve(root, "WS01", row["file"]))
    assert row["hash"] == next(r["hash"] for r in page["rows"] if r["ref"] == "3")


def test_only_shown_tags_are_cited(tmp_path):
    root = make_case(tmp_path / "CASE")
    context = eru_context.build(str(root), "x7kq.exe")
    context.text()
    real = next(iter(context.rows))
    assert eru_context.cited(f"It ran [{real}], twice [{real}], and [R999].", context) == [{**context.rows[real], "tag": real}]
    # A row cut off the end of the context wasn't shown, so it can't be cited
    with mock.patch.object(eru_context, "MAX_CHARS", 10):
        context.text()
    assert eru_context.cited(f"[{real}]", context) == []


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class EruQueryTest(BackendCase):
    def test_query_cites_rows_it_was_given(self):
        job = self.create_job(self.alice, "CASE-CTX-1")
        make_case(self.evidence / "out" / "CASE-CTX-1")
        prompts = []

        async def model(prompt, system=None):
            prompts.append((prompt, system))
            # The prefetch row when the question brought it in; otherwise the first row given
            tag = (re.search(r"\[(R\d+)\] WS01 artefacts/cooked/prefetch.csv row 3", prompt) or
                   re.search(r"\[(R\d+)\]", prompt)).group(1)
            return f"X7KQ.EXE ran on WS01 [{tag}]; it also beaconed [R404]."

        with mock.patch.object(sys.modules["ai_routes"].ollama, "generate", model):
            resp = self.client.post("/api/ai/cases/CASE-CTX-1/query", headers=self.alice,
                                    json={"question": "Did x7kq.exe run?"})
            self.assertEqual(resp.status_code, 200, resp.text)
            body = resp.json()
            self.assertEqual(body["job_id"], job)
            self.assertEqual([(r["host"], r["file"], r["row_ref"]) for r in body["rows"]],
                             [("WS01", "artefacts/cooked/prefetch.csv", "3")])
            self.assertIn("never invent", prompts[0][1])
            flagged = self.client.post(f"/api/jobs/{job}/case/findings", headers=self.alice, json={
                "host": "WS01", "artefact": body["rows"][0]["file"], "row_ref": "3", "title": "X7KQ.EXE ran"})
            self.assertEqual(flagged.json()["row_hash"], body["rows"][0]["hash"])

            summary = self.client.post("/api/ai/cases/CASE-CTX-1/summary", headers=self.alice).json()
            # No question, so no question rows: the flagged autostart entry is what it has
            self.assertEqual([r["file"] for r in summary["rows"]], ["artefacts/cooked/autostart.csv"])
            # Bob can't see the case, so he can't ask about it
            self.assertEqual(self.client.post("/api/ai/cases/CASE-CTX-1/query", headers=self.bob,
                                              json={"question": "x7kq.exe"}).status_code, 404)


if __name__ == "__main__":
    unittest.main()
