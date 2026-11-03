# Rivendell — Threat Model

## What Claude Code can touch

- Source code under `rivendell/`, `mcp/`, `src/`, `tests/`, `scripts/`
- Case metadata and structured output JSON
- XLSX evidence files under `data/`
- Documentation under `docs/`

## What Claude Code must never touch

- `evidence/` — raw forensic artefacts. This directory is write-denied in settings.json. If a task requires reading from it, confirm with Ben first.
- `.env` — contains API keys (Anthropic, Ollama endpoint, LinkedIn). Never read or write.
- Any file containing credentials, tokens, or certificates.

## Risk areas specific to this project

- **Eru MCP tools** — Eru has outbound network access for threat intel enrichment. Any new MCP tool registration must be reviewed before it goes near a live case. The write tools (`flag_lead`, `add_note`, phase 2) exist only with `rivendell mcp --allow-writes`: leads only, recorded as "Eru (for <user>)", the backend refusing Eru other statuses, edits, deletes and assignments, and a per-session write cap. Reviewed 3 November 2026 (below).
- **Subprocess calls to forensic tools** — Volatility3, log2timeline, RegRipper run with elevated access to memory dumps. Do not modify subprocess invocation patterns without explicit instruction.
- **SQLite case database** — schema changes require a migration. Do not ALTER TABLE directly; create a migration script.
- **Iran APT XLSX loader** — `rivendell/threat_intel/iran_apt_loader.py`. The 10-column schema is fixed. Do not add columns without updating the dataclass, index, and tests.

## Review: Eru MCP phase 2 (3 November 2026, Ben)

Approved for live cases on these conditions.

1. **Prompt injection from case data: accepted.** Text in the evidence (a filename, a task description, a log line) can lead the model to flag decoy leads or write misleading notes. It can't confirm, change or remove findings, assign hosts, or write more than `--max-writes` (25) times a session, and every write is labelled "Eru (for <user>)". It can't be prevented in code: the model reads the evidence it's asked to analyse. Team rule: an Eru lead or note is a suggestion, never a clearance; only an analyst clears a host.
2. **Case data leaving through another tool: required rule.** Eru sends nothing outside Rivendell, but an MCP host with other network-capable tools (web fetch, Slack, GitHub, email) could be led by injected text to send case data out through them. On a live case, `--allow-writes` runs only in a host with no network-capable tools besides the Rivendell server, or Ask Eru with local Ollama is used instead. Policy, not code: Rivendell can't see the host's other tools.
3. **Token: enforced.** On a team server `--allow-writes` refuses to start unless `RIVENDELL_TOKEN` is an `eru-mcp` API token (`eru_mcp.server.write_refusal`, checked against `/api/auth/me`), so the backend itself holds the caller to reads, leads and notes whether or not the agent header is sent. Use 30-day tokens on live cases and revoke one as soon as its machine is suspect. A `full` token or a sign-in's JWT carries the user's whole rights and isn't accepted for writes.
4. **Outbound calls: confirmed none.** The MCP server calls only `/api/` on the configured Rivendell (`RivendellAPI` refuses other paths; tested). `check_indicator` uses the backend's local value index (`/api/threat-intel/enrich`); the only outbound code in threat intelligence is TAXII import (`threat_intel/stix.py`), admin-only and refused to an `eru-mcp` token.

Re-review when a tool is added to the MCP server, when its writes go beyond leads and notes, or when online lookups are proposed.

## Chain of custody note

Evidence packages are SHA256-hashed at acquisition time. Do not modify anything under `evidence/` or `cases/<CASE-ID>/raw/`. Processed output under `cases/<CASE-ID>/output/` is writable.
