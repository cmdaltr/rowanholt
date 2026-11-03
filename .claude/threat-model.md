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

- **Eru MCP tools** — Eru has outbound network access for threat intel enrichment. Any new MCP tool registration must be reviewed before it goes near a live case. The write tools (`flag_lead`, `add_note`, phase 2) exist only with `rivendell mcp --allow-writes` and are pending that review: leads only, recorded as "Eru (for <user>)", the backend refusing Eru other statuses, edits, deletes and assignments, and a per-session write cap against prompt injection from case data.
- **Subprocess calls to forensic tools** — Volatility3, log2timeline, RegRipper run with elevated access to memory dumps. Do not modify subprocess invocation patterns without explicit instruction.
- **SQLite case database** — schema changes require a migration. Do not ALTER TABLE directly; create a migration script.
- **Iran APT XLSX loader** — `rivendell/threat_intel/iran_apt_loader.py`. The 10-column schema is fixed. Do not add columns without updating the dataclass, index, and tests.

## Chain of custody note

Evidence packages are SHA256-hashed at acquisition time. Do not modify anything under `evidence/` or `cases/<CASE-ID>/raw/`. Processed output under `cases/<CASE-ID>/output/` is writable.
