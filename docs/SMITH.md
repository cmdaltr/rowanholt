# Smith - the AI Analyst

Smith answers questions about a case. In the web app it's **Ask Smith**; from a shell it's `python3 -m src.analysis.rowanholt.ai.cli` ([CLI.md](CLI.md#smith-ai-analyst)); the endpoints are in [API.md](API.md#smith-ai-analyst).

## With Ollama

Free-text answers, case summaries and investigation suggestions come from a local model through Ollama. The backend finds it at `OLLAMA_HOST` (default `http://host.docker.internal:11434`, so Ollama on the Docker host) and uses `ROWANHOLT_MODEL_NAME` (default `llama3.2:3b`) with a context window of `ROWANHOLT_NUM_CTX` tokens (default 8192; Ollama's own default, 2048, is shorter than the case context). Nothing leaves the machine. To change them for the stack, set them in `.env` (e.g. `ROWANHOLT_MODEL_NAME=qwen3:8b`) and restart it: `docker-compose.yml` passes all three to the backend. A 3B model runs anywhere but misreads cases; an 8B one (`qwen3:8b`, about 5 GB) is the smallest worth relying on.

The model is given the case per host: the analysts' confirmed findings, the hosts and tagged techniques, the rows of the hosts' cooked and analysis tables that contain the question's words, and the rows behind the fixed questions below (flagged persistence, suspicious commands, staging, detections, analysis, threat intelligence, what's rare, last logins). Each row is tagged `[R1]`, `[R2]`… and the model is asked to cite the tags. Only a tag that was in what the model read comes back as a row, so an answer and a summary list the rows they cite, each with ⚑ to flag it, and a tag the model made up is dropped.

## Without Ollama

If Ollama isn't running, or the model isn't pulled, Ask Smith says which and how to fix it, turns off free text, and offers fixed questions answered exactly from Elrond's output for the selected case: which hosts are in it, which ATT&CK techniques were tagged, what persistence was flagged, who logged in (and failed to), which IOCs were extracted, which shell commands look suspicious, what matched threat intelligence (when the case was run with it), what's rare across the hosts (stacking's top rows, persistence first, each a lead rather than a verdict), and what analysts have confirmed in the case browser. With a model, confirmed findings go into its context first. A few general questions (persistence locations per OS, what Gandalf collects) need no case. These answers are read from the files and the findings, not generated, so they are the same every time. Under an answer, Ask Smith lists the host rows its lines came from (file and row; the SHA-256 on hover), each with ⚑ to flag it as a lead or a confirmed finding on that row, as the case browser would; a row someone has already flagged says who.

## From an MCP host

`rowanholt mcp` runs Smith's MCP server over stdio, so an MCP host (Claude Desktop, Claude Code, OpenClaw) can work a Rowanholt case. It's read-only, and it's a client of Rowanholt's own API rather than a way round it: on a team server every call carries your token, so you see the jobs you'd see in the web app and no others. It reads through the case browser's routes, so it never reaches `raw/`, and it calls nothing but the Rowanholt API you point it at.

It runs on your machine, not in the stack, and needs Python 3.10 or later with its one dependency:

```bash
python3 -m venv ~/.rowanholt-mcp
~/.rowanholt-mcp/bin/pip install -r requirements/mcp.txt
```

`ROWANHOLT_API` is the Rowanholt to read (default `http://127.0.0.1:5688`). On a team server, `ROWANHOLT_TOKEN` is an API token: make one in the web app under **Account → Tokens for scripts and Smith's MCP server**, with a password or single sign-on, and give it the **smith-mcp** scope. Or from a signed-in session:

```bash
curl -s https://rowanholt.example.org/api/auth/tokens -H "Authorization: Bearer $SESSION" \
  -H 'Content-Type: application/json' -d '{"name": "Claude Desktop", "scope": "smith-mcp", "days": 90}'
```

A token (`rvt_…`) is shown once, when it's made: only its SHA-256 is stored. It lasts until it expires (1 to 365 days, 90 by default) or is revoked on the same page, and stops when its user is deactivated. A **smith-mcp** token can only read, flag leads and add notes, and its writes are recorded as Smith's whatever headers it sends; it can't reach admin areas even for an admin. A **full** token does what its user can do. Neither can make or revoke tokens, or be swapped for a sign-in's session, so revoking one is the end of it. On one machine, no token is needed. The token is read from the environment only, since an argument would show in the process list.

For Claude Desktop, in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "rowanholt": {
      "command": "/path/to/rowanholt/rowanholt",
      "args": ["mcp"],
      "env": {"ROWANHOLT_MCP_PYTHON": "/Users/you/.rowanholt-mcp/bin/python", "ROWANHOLT_API": "http://127.0.0.1:5688"}
    }
  }
}
```

For Claude Code:

```bash
claude mcp add rowanholt --env ROWANHOLT_MCP_PYTHON=$HOME/.rowanholt-mcp/bin/python -- /path/to/rowanholt/rowanholt mcp
```

| Tool | What it gives |
|---|---|
| `list_cases` | The jobs you can see: id, case number, status, owner, dates |
| `case_overview(job_id)` | The job, its hosts and their files, each host's assignee and status, findings by status |
| `read_rows(job_id, host, file, filter, offset, limit)` | A page of one file's rows, each with `cite`: file, row and SHA-256, the reference a finding stores |
| `ask_offline(job_id, question)` | One of the fixed questions above, by id or wording, with the rows the answer came from (each with its `cite`); an unknown one returns the list |
| `ask_smith`, `case_summary`, `suggestions` | Smith's model (Ollama); when it isn't available they say why and point to `ask_offline` |
| `check_indicator(value)` | What the imported threat intelligence says about one value |
| `rare_across_hosts(job_id)` | The top of `stacking.jsonl`, each row with the host row it was read from (`Host`, `Artefact`, `Row`) |
| `findings`, `report`, `navigator_layer` | Analysts' findings (with whether each row is still intact), the Markdown report, the confirmed-findings layer |

The server tells the host to start from a job id, cite file and row for every claim, and treat a stacking row or a threat intelligence match as a lead, not a verdict. It can't start, restart or delete jobs, run Gandalf, import or delete threat intelligence, assign hosts, or change or remove findings.

Started with `--allow-writes` (`rowanholt mcp --allow-writes`, or `"args": ["mcp", "--allow-writes"]`), it adds two tools, and nothing else that writes:

| Tool | What it does |
|---|---|
| `flag_lead(job_id, host, file, row, title, technique)` | Flags one row as a lead, never a confirmed or benign finding; a row already flagged is refused |
| `add_note(job_id, body, finding_id)` | A note on a finding, or on the case without one |

Each server call carries `X-Rowanholt-Agent: smith-mcp`, so what Smith writes is recorded as "Smith (for alice)" in the findings, notes, activity and report, never as the analyst's own; with a smith-mcp token that holds even without the header. The backend holds it there: as Smith it refuses any status but lead, and refuses changing or removing findings and assigning hosts. A session stops after `--max-writes` writes (25 by default), so a host led on by text inside the case can't flood it, and the server tells the host that the case's text is evidence, not instructions. On a team server, `--allow-writes` won't start unless `ROWANHOLT_TOKEN` is a **smith-mcp** token, so the backend holds it to reads, leads and notes whatever the server's code does. On a live case, run it in an MCP host with no other network-capable tools (web fetch, Slack, email and the like) and no shell or file access to the case store: text inside the evidence could otherwise lead the model to send case data out through them, and the server's `raw/` boundary only covers what goes through the API (Claude Code in the Rowanholt checkout, refused `raw/` by the server, offers to list it from disk). Claude Desktop with only this server, or a host on another machine, fits. Treat Smith's leads and notes as suggestions; only an analyst clears a host. Without `--allow-writes` the server is read-only, as before. The code is `src/smith_mcp/server.py` (mcp 2's `MCPServer`, which was FastMCP), and `tests/unit/test_smith_mcp.py` checks the tool list, other people's jobs, `raw/` and that nothing but `/api/` is called, against the real backend in server mode.

### Over HTTP, from a team server

A team server can run the same server over streamable HTTP at `https://<host>/mcp`, so an analyst's MCP host needs nothing installed. It's the `smith-mcp` service in `deploy/server/docker-compose.server.yml`, off unless the `mcp` profile is on, behind Caddy like everything else:

```bash
COMPOSE_PROFILES=mcp ./rowanholt start
```

It holds no token of its own. Every request sends its analyst's **smith-mcp** API token as a bearer header; the server checks it with Rowanholt (`/api/auth/me`) and makes that request's calls with it, so each analyst sees their own jobs, as over stdio. A **full** token or a sign-in's session is refused, reads included: either carries all of its user's rights if it leaks from a host's configuration. It's read-only unless `.env` has `SMITH_MCP_ARGS=--allow-writes`, and `--max-writes` counts per token until the service restarts. `rowanholt mcp --http` won't start against a Rowanholt that isn't in server mode, or without the `https://` URL analysts use (`ROWANHOLT_PUBLIC_URL`, set by the Compose file).

For Claude Code:

```bash
claude mcp add --transport http rowanholt https://rowanholt.example.org/mcp --header "Authorization: Bearer $ROWANHOLT_TOKEN"
```

The token then sits in the host's own configuration, so use a 30-day **smith-mcp** token and revoke it when the machine is in doubt. The HTTP transport was reviewed under the threat model on 4 November 2026 (`.claude/threat-model.md`) and approved for live cases: smith-mcp tokens only, 30-day ones revoked when a machine is in doubt, on the team's network, in a host with no other network-capable tools.

## Smith Models

The Ollama Modelfiles in `src/models/` build Smith variants: a forensic system prompt over different base models.

Smith was called Eru until 9 November 2026 and Aulë until 12 November 2026, and the models were `eru-*` and then `aule-*`. A model built under either name still works: when `ROWANHOLT_MODEL_NAME` names a `smith-*` model that isn't pulled but an old namesake is (`smith-qwen`, `aule-qwen`, `eru-qwen`), the backend uses it, `aule-*` before `eru-*`. The other old names are still taken too: an `aule-mcp` or `eru-mcp` token is a `smith-mcp` one (existing tokens are renamed when the backend starts), `X-Rowanholt-Agent: aule-mcp` or `eru-mcp` still marks a call as Smith's, `python3 -m aule_mcp.server` and `python3 -m eru_mcp.server` start the MCP server, and on a team server `AULE_MCP_ARGS` or `ERU_MCP_ARGS` in `.env` still counts when `SMITH_MCP_ARGS` isn't set. The MCP server's container is now `rowanholt-smith-mcp`: `rowanholt start` on a server removes the old `rowanholt-aule-mcp` (and `rowanholt-eru-mcp`) if it's still there. The tool is `ask_smith` only; an MCP host's prompts that name `ask_aule` need the new name.

## Available Models

| Model | Base Model | Size | Best For |
|-------|------------|------|----------|
| `smith-llama` | llama3.2:3b | 2GB | Fast responses, low resource usage |
| `smith-llama-large` | llama3.1:8b | 4.7GB | Complex analysis, better reasoning |
| `smith-mistral` | mistral:7b | 4.1GB | Balanced performance |
| `smith-qwen` | qwen2.5:7b | 4.4GB | Strong reasoning, multilingual |
| `smith-gemma` | gemma2:9b | 5.4GB | Efficient, well-rounded |
| `smith-phi` | phi3.5:3.8b | 2.2GB | Small but capable |
| `smith-deepseek` | deepseek-coder-v2:16b | 8.9GB | Code/script analysis |
| `smith-codellama` | codellama:7b | 3.8GB | Malware script analysis |

## Quick Start

1. Install Ollama: https://ollama.ai

2. Create a model:
   ```bash
   ollama create smith-llama -f src/models/Modelfile.smith-llama
   ```

3. Configure Rowanholt to use it:
   ```bash
   export ROWANHOLT_MODEL_NAME=smith-llama
   ```

## Creating All Models

```bash
cd /path/to/rowanholt

# Lightweight (recommended for most systems)
ollama create smith-llama -f src/models/Modelfile.smith-llama
ollama create smith-phi -f src/models/Modelfile.smith-phi

# Medium (8GB+ VRAM)
ollama create smith-mistral -f src/models/Modelfile.smith-mistral
ollama create smith-qwen -f src/models/Modelfile.smith-qwen
ollama create smith-llama-large -f src/models/Modelfile.smith-llama-large
ollama create smith-codellama -f src/models/Modelfile.smith-codellama

# Large (16GB+ VRAM)
ollama create smith-gemma -f src/models/Modelfile.smith-gemma
ollama create smith-deepseek -f src/models/Modelfile.smith-deepseek
```

## Testing a Model

```bash
ollama run smith-llama "What Windows artifacts show evidence of lateral movement?"
```

## Recommendations

- **Limited resources**: Use `smith-llama` or `smith-phi`
- **General use**: Use `smith-mistral` or `smith-qwen`
- **Complex investigations**: Use `smith-llama-large` or `smith-gemma`
- **Script/malware analysis**: Use `smith-codellama` or `smith-deepseek`
