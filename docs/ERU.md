# Eru - the AI Analyst

Eru answers questions about a case. In the web app it's **Ask Eru**; from a shell it's `python3 -m src.analysis.rivendell.ai.cli` ([CLI.md](CLI.md#eru-ai-analyst)); the endpoints are in [API.md](API.md#eru-ai-analyst).

## With Ollama

Free-text answers, case summaries and investigation suggestions come from a local model through Ollama. The backend finds it at `OLLAMA_HOST` (default `http://host.docker.internal:11434`, so Ollama on the Docker host) and uses `RIVENDELL_MODEL_NAME` (default `llama3.2:3b`) with a context window of `RIVENDELL_NUM_CTX` tokens (default 8192; Ollama's own default, 2048, is shorter than the case context). Nothing leaves the machine.

The model is given the case per host: the analysts' confirmed findings, the hosts and tagged techniques, the rows of the hosts' cooked and analysis tables that contain the question's words, and the rows behind the fixed questions below (flagged persistence, suspicious commands, staging, detections, analysis, threat intelligence, what's rare, last logins). Each row is tagged `[R1]`, `[R2]`… and the model is asked to cite the tags. Only a tag that was in what the model read comes back as a row, so an answer and a summary list the rows they cite, each with ⚑ to flag it, and a tag the model made up is dropped.

## Without Ollama

If Ollama isn't running, or the model isn't pulled, Ask Eru says which and how to fix it, turns off free text, and offers fixed questions answered exactly from Elrond's output for the selected case: which hosts are in it, which ATT&CK techniques were tagged, what persistence was flagged, who logged in (and failed to), which IOCs were extracted, which shell commands look suspicious, what matched threat intelligence (when the case was run with it), what's rare across the hosts (stacking's top rows, persistence first, each a lead rather than a verdict), and what analysts have confirmed in the case browser. With a model, confirmed findings go into its context first. A few general questions (persistence locations per OS, what Gandalf collects) need no case. These answers are read from the files and the findings, not generated, so they are the same every time. Under an answer, Ask Eru lists the host rows its lines came from (file and row; the SHA-256 on hover), each with ⚑ to flag it as a lead or a confirmed finding on that row, as the case browser would; a row someone has already flagged says who.

## From an MCP host

`rivendell mcp` runs Eru's MCP server over stdio, so an MCP host (Claude Desktop, Claude Code, OpenClaw) can work a Rivendell case. It's read-only, and it's a client of Rivendell's own API rather than a way round it: on a team server every call carries your token, so you see the jobs you'd see in the web app and no others. It reads through the case browser's routes, so it never reaches `raw/`, and it calls nothing but the Rivendell API you point it at.

It runs on your machine, not in the stack, and needs Python 3.10 or later with its one dependency:

```bash
python3 -m venv ~/.rivendell-mcp
~/.rivendell-mcp/bin/pip install -r requirements/mcp.txt
```

`RIVENDELL_API` is the Rivendell to read (default `http://127.0.0.1:5688`). On a team server, `RIVENDELL_TOKEN` is an API token: make one in the web app under **Account → Tokens for scripts and Eru's MCP server**, with a password or single sign-on, and give it the **eru-mcp** scope. Or from a signed-in session:

```bash
curl -s https://rivendell.example.org/api/auth/tokens -H "Authorization: Bearer $SESSION" \
  -H 'Content-Type: application/json' -d '{"name": "Claude Desktop", "scope": "eru-mcp", "days": 90}'
```

A token (`rvt_…`) is shown once, when it's made: only its SHA-256 is stored. It lasts until it expires (1 to 365 days, 90 by default) or is revoked on the same page, and stops when its user is deactivated. An **eru-mcp** token can only read, flag leads and add notes, and its writes are recorded as Eru's whatever headers it sends; it can't reach admin areas even for an admin. A **full** token does what its user can do. Neither can make or revoke tokens, or be swapped for a sign-in's session, so revoking one is the end of it. On one machine, no token is needed. The token is read from the environment only, since an argument would show in the process list.

For Claude Desktop, in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "rivendell": {
      "command": "/path/to/rivendell/rivendell",
      "args": ["mcp"],
      "env": {"RIVENDELL_MCP_PYTHON": "/Users/you/.rivendell-mcp/bin/python", "RIVENDELL_API": "http://127.0.0.1:5688"}
    }
  }
}
```

For Claude Code:

```bash
claude mcp add rivendell --env RIVENDELL_MCP_PYTHON=$HOME/.rivendell-mcp/bin/python -- /path/to/rivendell/rivendell mcp
```

| Tool | What it gives |
|---|---|
| `list_cases` | The jobs you can see: id, case number, status, owner, dates |
| `case_overview(job_id)` | The job, its hosts and their files, each host's assignee and status, findings by status |
| `read_rows(job_id, host, file, filter, offset, limit)` | A page of one file's rows, each with `cite`: file, row and SHA-256, the reference a finding stores |
| `ask_offline(job_id, question)` | One of the fixed questions above, by id or wording, with the rows the answer came from (each with its `cite`); an unknown one returns the list |
| `ask_eru`, `case_summary`, `suggestions` | Eru's model (Ollama); when it isn't available they say why and point to `ask_offline` |
| `check_indicator(value)` | What the imported threat intelligence says about one value |
| `rare_across_hosts(job_id)` | The top of `stacking.csv`, each row with the host row it was read from (`Host`, `Artefact`, `Row`) |
| `findings`, `report`, `navigator_layer` | Analysts' findings (with whether each row is still intact), the Markdown report, the confirmed-findings layer |

The server tells the host to start from a job id, cite file and row for every claim, and treat a stacking row or a threat intelligence match as a lead, not a verdict. It can't start, restart or delete jobs, run Gandalf, import or delete threat intelligence, assign hosts, or change or remove findings.

Started with `--allow-writes` (`rivendell mcp --allow-writes`, or `"args": ["mcp", "--allow-writes"]`), it adds two tools, and nothing else that writes:

| Tool | What it does |
|---|---|
| `flag_lead(job_id, host, file, row, title, technique)` | Flags one row as a lead, never a confirmed or benign finding; a row already flagged is refused |
| `add_note(job_id, body, finding_id)` | A note on a finding, or on the case without one |

Each server call carries `X-Rivendell-Agent: eru-mcp`, so what Eru writes is recorded as "Eru (for alice)" in the findings, notes, activity and report, never as the analyst's own; with an eru-mcp token that holds even without the header. The backend holds it there: as Eru it refuses any status but lead, and refuses changing or removing findings and assigning hosts. A session stops after `--max-writes` writes (25 by default), so a host led on by text inside the case can't flood it, and the server tells the host that the case's text is evidence, not instructions. Without `--allow-writes` the server is read-only, as before. The code is `src/eru_mcp/server.py` (mcp 2's `MCPServer`, which was FastMCP), and `tests/unit/test_eru_mcp.py` checks the tool list, other people's jobs, `raw/` and that nothing but `/api/` is called, against the real backend in server mode.

## Eru Models

The Ollama Modelfiles in `src/models/` build Eru variants: a forensic system prompt over different base models.

## Available Models

| Model | Base Model | Size | Best For |
|-------|------------|------|----------|
| `eru-llama` | llama3.2:3b | 2GB | Fast responses, low resource usage |
| `eru-llama-large` | llama3.1:8b | 4.7GB | Complex analysis, better reasoning |
| `eru-mistral` | mistral:7b | 4.1GB | Balanced performance |
| `eru-qwen` | qwen2.5:7b | 4.4GB | Strong reasoning, multilingual |
| `eru-gemma` | gemma2:9b | 5.4GB | Efficient, well-rounded |
| `eru-phi` | phi3.5:3.8b | 2.2GB | Small but capable |
| `eru-deepseek` | deepseek-coder-v2:16b | 8.9GB | Code/script analysis |
| `eru-codellama` | codellama:7b | 3.8GB | Malware script analysis |

## Quick Start

1. Install Ollama: https://ollama.ai

2. Create a model:
   ```bash
   ollama create eru-llama -f src/models/Modelfile.eru-llama
   ```

3. Configure Rivendell to use it:
   ```bash
   export RIVENDELL_MODEL_NAME=eru-llama
   ```

## Creating All Models

```bash
cd /path/to/rivendell

# Lightweight (recommended for most systems)
ollama create eru-llama -f src/models/Modelfile.eru-llama
ollama create eru-phi -f src/models/Modelfile.eru-phi

# Medium (8GB+ VRAM)
ollama create eru-mistral -f src/models/Modelfile.eru-mistral
ollama create eru-qwen -f src/models/Modelfile.eru-qwen
ollama create eru-llama-large -f src/models/Modelfile.eru-llama-large
ollama create eru-codellama -f src/models/Modelfile.eru-codellama

# Large (16GB+ VRAM)
ollama create eru-gemma -f src/models/Modelfile.eru-gemma
ollama create eru-deepseek -f src/models/Modelfile.eru-deepseek
```

## Testing a Model

```bash
ollama run eru-llama "What Windows artifacts show evidence of lateral movement?"
```

## Recommendations

- **Limited resources**: Use `eru-llama` or `eru-phi`
- **General use**: Use `eru-mistral` or `eru-qwen`
- **Complex investigations**: Use `eru-llama-large` or `eru-gemma`
- **Script/malware analysis**: Use `eru-codellama` or `eru-deepseek`
