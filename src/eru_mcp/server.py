"""
Eru's MCP server, phase 1: reading a case.

Every Eru capability an MCP host can use is registered here, and nowhere else. The server is a
thin client of Rivendell's API, not a second way into the case files:

- every call carries the analyst's token (RIVENDELL_TOKEN), so on a team server job sharing
  (auth/access.py) decides what it can see, exactly as for the web app;
- what it reads comes through the case browser's routes, which are read-only over cooked/,
  analysis/ and the case root and never reach raw/;
- it calls nothing but the Rivendell API at RIVENDELL_API (RivendellAPI refuses any other URL),
  so it adds no outbound access.

Never exposed: starting, restarting or deleting jobs, Gandalf acquisition, importing or deleting
threat intelligence, and anything under raw/. Writing leads and notes is phase 2, deferred.

Runs over stdio: `rivendell mcp`, or `python3 -m eru_mcp.server` with src/ on the path. Needs
Python 3.10+ and requirements/mcp.txt. Nothing but the protocol may go to stdout.
"""

import argparse
import json
import logging
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

logger = logging.getLogger("eru_mcp")

DEFAULT_API = "http://127.0.0.1:5688"
CASE_HOST = "(case)"  # case_files.CASE_HOST: the case's own files, such as stacking.csv
READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
INSTRUCTIONS = """Eru works one Rivendell case at a time, read-only.
Start from a job id: list_cases, then case_overview to see the hosts and their files.
Cite file and row for every claim (read_rows gives each row's reference); don't state what no row shows.
A stacking row (rare_across_hosts) or a threat intelligence match (check_indicator) is a lead, not a verdict.
Confirmed findings are an analyst's; leads are not confirmations.
When Ollama isn't running, ask_eru, case_summary and suggestions say so: use ask_offline instead."""

# (status, body) for a method, an /api path, query parameters and a JSON body
Transport = Callable[[str, str, Dict[str, Any], Optional[dict]], Tuple[int, Any]]


class ApiError(ToolError):
    """Rivendell answered with an error (or couldn't be reached). A ToolError, so the host sees why."""

    def __init__(self, status: int, detail: str):
        super().__init__(f"Rivendell answered {status}: {detail}" if status else detail)
        self.status = status
        self.detail = detail


class NotRivendell(ToolError, ValueError):
    """A request for anything but an /api path on the configured Rivendell."""


class RivendellAPI:
    """Rivendell's API, and nothing else: paths must be under /api/ on the configured base URL."""

    def __init__(self, base_url: str = DEFAULT_API, token: str = "", transport: Optional[Transport] = None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.transport = transport or self._urllib

    @staticmethod
    def path(*parts: str) -> str:
        """An /api path with each part quoted, so an id or host name can't add a segment or a host."""
        return "/api/" + "/".join(urllib.parse.quote(str(p), safe="") for p in parts)

    def _urllib(self, method: str, path: str, params: Dict[str, Any], body: Optional[dict]) -> Tuple[int, Any]:
        url = self.base_url + path + (f"?{urllib.parse.urlencode(params)}" if params else "")
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                return response.status, _decode(response.read(), response.headers.get("Content-Type", ""))
        except urllib.error.HTTPError as exc:
            return exc.code, _decode(exc.read(), exc.headers.get("Content-Type", ""))
        except urllib.error.URLError as exc:
            raise ApiError(0, f"Rivendell isn't reachable at {self.base_url} ({exc.reason}). Is it running?")

    def call(self, method: str, path: str, params: Optional[Dict[str, Any]] = None, body: Optional[dict] = None) -> Any:
        if not path.startswith("/api/") or "://" in path or ".." in path.split("?")[0].split("/"):
            raise NotRivendell(f"Not a Rivendell API path: {path!r}")
        status, payload = self.transport(method, path, {k: v for k, v in (params or {}).items() if v not in (None, "")}, body)
        if status >= 400:
            detail = payload.get("detail", payload) if isinstance(payload, dict) else payload
            raise ApiError(status, detail if isinstance(detail, str) else json.dumps(detail))
        return payload

    def get(self, path: str, /, **params: Any) -> Any:
        # Positional-only: the case browser's rows take a `path` parameter of their own
        return self.call("GET", path, params)

    def post(self, path: str, body: Optional[dict] = None) -> Any:
        return self.call("POST", path, body=body)


def _decode(raw: bytes, content_type: str) -> Any:
    text = raw.decode("utf-8", errors="replace")
    if "json" in content_type:
        try:
            return json.loads(text)
        except ValueError:
            pass
    return text


JOB_FIELDS = ("id", "case_number", "status", "progress", "owner", "created_at", "completed_at", "error")


def build_server(api: RivendellAPI) -> MCPServer:
    """The MCP server, its tools bound to one Rivendell API client."""
    server = MCPServer("rivendell-eru", title="Eru (Rivendell)", instructions=INSTRUCTIONS)

    def job(job_id: str) -> Dict[str, Any]:
        found = api.get(api.path("jobs", job_id))
        return {k: found.get(k) for k in JOB_FIELDS}

    def case_base(job_id: str) -> str:
        return api.path("jobs", job_id, "case")

    def llm_unavailable() -> Optional[Dict[str, str]]:
        status = api.get(api.path("ai", "status"))
        if status.get("llm_available"):
            return None
        return {"available": "no", "reason": status.get("reason") or "Eru's model isn't available.",
                "instead": "ask_offline answers fixed questions straight from the case files, without a model."}

    @server.tool(annotations=READ_ONLY)
    def list_cases() -> List[Dict[str, Any]]:
        """The Rivendell jobs (cases) you can see, newest first: id, case number, status, owner and dates.
        Every other tool takes one of these ids."""
        listing = api.get(api.path("jobs"))
        return [{k: j.get(k) for k in JOB_FIELDS} for j in listing.get("jobs", [])]

    @server.tool(annotations=READ_ONLY)
    def case_overview(job_id: str) -> Dict[str, Any]:
        """One job, its hosts and each host's files (cooked artefacts and analysis), the case's own files,
        each host's assignee and status, and the findings counted by status."""
        overview: Dict[str, Any] = {"job": job(job_id)}
        try:
            overview["case"] = api.get(case_base(job_id))
        except ApiError as exc:
            if exc.status != 404:
                raise
            overview["case"] = f"No output to read yet: {exc.detail}"
        return overview

    @server.tool(annotations=READ_ONLY)
    def read_rows(job_id: str, host: str, file: str, filter: str = "", offset: int = 0, limit: int = 50) -> Dict[str, Any]:
        """Rows of one file from case_overview (host and path as listed there; host "(case)" for the case's
        own files), optionally only those containing `filter`. Each row has `cite`, the reference to quote:
        file, row and the row's SHA-256, the same reference a finding stores."""
        page = api.get(case_base(job_id) + "/rows", host=host, path=file, q=filter, offset=max(offset, 0),
                       limit=min(max(limit, 1), 500))
        for row in page.get("rows", []):
            row["cite"] = f"{host}: {file} row {row['ref']} (sha256 {row['hash'][:16]})"
        return page

    @server.tool(annotations=READ_ONLY)
    def ask_offline(job_id: str, question: str) -> Dict[str, Any]:
        """One of Eru's fixed questions, answered exactly from the case files with no model (hosts, ATT&CK
        techniques, persistence, logins, IOCs, suspicious commands, staging, detections, analysis, threat
        intelligence, what's rare, what analysts confirmed). `question` is its id or its wording; an unknown
        one returns the list."""
        catalogue = api.get(api.path("ai", "offline", "questions")).get("questions", [])
        wanted = question.strip().lower().rstrip("?")
        match = next((q for q in catalogue if wanted in (q["id"].lower(), q["question"].lower().rstrip("?"))), None)
        if match is None:
            return {"unknown question": question, "questions": [{"id": q["id"], "question": q["question"]} for q in catalogue]}
        body = {"question_id": match["id"], "case_id": job(job_id)["case_number"] if match.get("needs_case") else None}
        return {"question": match["question"], "answer": api.post(api.path("ai", "offline", "answer"), body)["answer"]}

    @server.tool(annotations=READ_ONLY)
    def ask_eru(job_id: str, question: str) -> Dict[str, Any]:
        """A free-text question about the case, answered by Eru's local model (Ollama) from the case's
        indexed data. Says so when the model isn't available."""
        unavailable = llm_unavailable()
        if unavailable:
            return unavailable
        return api.post(api.path("ai", "cases", job(job_id)["case_number"], "query"), {"question": question})

    @server.tool(annotations=READ_ONLY)
    def case_summary(job_id: str) -> Dict[str, Any]:
        """Eru's summary of the case, from its local model. Says so when the model isn't available."""
        unavailable = llm_unavailable()
        if unavailable:
            return unavailable
        return api.post(api.path("ai", "cases", job(job_id)["case_number"], "summary"))

    @server.tool(annotations=READ_ONLY)
    def suggestions(job_id: str) -> Dict[str, Any]:
        """Eru's suggestions for where to look next, from its local model. Says so when the model isn't
        available."""
        unavailable = llm_unavailable()
        if unavailable:
            return unavailable
        return api.post(api.path("ai", "cases", job(job_id)["case_number"], "suggestions"))

    @server.tool(annotations=READ_ONLY)
    def check_indicator(value: str) -> Dict[str, Any]:
        """What Rivendell's imported threat intelligence says about one value: a process name, command line,
        path, IP, domain or hash. A match is a lead, not attribution."""
        return api.get(api.path("threat-intel", "enrich"), value=value)

    @server.tool(annotations=READ_ONLY)
    def rare_across_hosts(job_id: str, limit: int = 20) -> Dict[str, Any]:
        """The top of the case's stacking (stacking.csv): values on few of the case's hosts, highest score
        first, each with its hosts and the named reasons for its score. Each row is a lead, not a verdict."""
        job(job_id)  # a job you can't see stays an error, not "no stacking"
        try:
            return read_rows(job_id, CASE_HOST, "stacking.csv", limit=limit)
        except ApiError as exc:
            if exc.status not in (400, 404):
                raise
            return {"rows": [], "note": "No stacking for this case: it needs two or more hosts and Elrond's "
                                        "analysis (--Analysis); rare needs three or more hosts of an OS."}

    @server.tool(annotations=READ_ONLY)
    def findings(job_id: str, status: str = "") -> List[Dict[str, Any]]:
        """What analysts have flagged: lead, confirmed or benign (all when `status` is empty), each with its
        file, row and `intact` (false when a re-run has changed the row since it was flagged)."""
        return api.get(case_base(job_id) + "/findings", status=status, verify="true")

    @server.tool(annotations=READ_ONLY)
    def report(job_id: str) -> str:
        """The case report in Markdown: case notes, then confirmed findings by host with their notes."""
        return api.get(case_base(job_id) + "/report")

    @server.tool(annotations=READ_ONLY)
    def navigator_layer(job_id: str) -> Dict[str, Any]:
        """An ATT&CK Navigator layer of the confirmed findings' techniques."""
        return api.get(case_base(job_id) + "/layer")

    return server


def main(argv: Optional[List[str]] = None) -> int:
    cli = argparse.ArgumentParser(prog="rivendell mcp", description="Eru's MCP server (stdio), read-only over a Rivendell.")
    cli.add_argument("--api", default=os.environ.get("RIVENDELL_API", DEFAULT_API),
                     help=f"Rivendell's API (RIVENDELL_API, default {DEFAULT_API})")
    options = cli.parse_args(argv)
    # The token comes from the environment only: an argument would show in the process list
    token = os.environ.get("RIVENDELL_TOKEN", "")
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="eru-mcp: %(message)s")
    logger.info(f"Serving Rivendell at {options.api} over stdio ({'with' if token else 'without'} a token)")
    build_server(RivendellAPI(options.api, token)).run("stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
