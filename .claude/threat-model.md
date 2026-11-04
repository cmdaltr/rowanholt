# Dernvale — Threat Model

## What Claude Code can touch

- Source code under `dernvale/`, `mcp/`, `src/`, `tests/`, `scripts/`
- Case metadata and structured output JSON
- XLSX evidence files under `data/`
- Documentation under `docs/`

## What Claude Code must never touch

- `evidence/` — raw forensic artefacts. This directory is write-denied in settings.json. If a task requires reading from it, confirm with Ben first.
- `.env` — contains API keys (Anthropic, Ollama endpoint, LinkedIn). Never read or write.
- Any file containing credentials, tokens, or certificates.

## Risk areas specific to this project

- **Eru MCP tools** — Eru has outbound network access for threat intel enrichment. Any new MCP tool registration must be reviewed before it goes near a live case. The write tools (`flag_lead`, `add_note`, phase 2) exist only with `dernvale mcp --allow-writes`: leads only, recorded as "Eru (for <user>)", the backend refusing Eru other statuses, edits, deletes and assignments, and a per-session write cap. Reviewed 3 November 2026; the HTTP transport, 4 November (below).
- **Subprocess calls to forensic tools** — Volatility3, log2timeline, RegRipper run with elevated access to memory dumps. Do not modify subprocess invocation patterns without explicit instruction.
- **SQLite case database** — schema changes require a migration. Do not ALTER TABLE directly; create a migration script.
- **Iran APT XLSX loader** — `dernvale/threat_intel/iran_apt_loader.py`. The 10-column schema is fixed. Do not add columns without updating the dataclass, index, and tests.

## Review: Eru MCP phase 2 (3 November 2026, Ben)

Approved for live cases on these conditions.

1. **Prompt injection from case data: accepted.** Text in the evidence (a filename, a task description, a log line) can lead the model to flag decoy leads or write misleading notes. It can't confirm, change or remove findings, assign hosts, or write more than `--max-writes` (25) times a session, and every write is labelled "Eru (for <user>)". It can't be prevented in code: the model reads the evidence it's asked to analyse. Team rule: an Eru lead or note is a suggestion, never a clearance; only an analyst clears a host.
2. **Case data leaving through another tool, or `raw/` read round the API: required rule.** Eru sends nothing outside Dernvale, but an MCP host with other network-capable tools (web fetch, Slack, GitHub, email) could be led by injected text to send case data out through them. The server's `raw/` boundary holds only for what goes through the API: a host with a shell or file tools on the machine holding the case store can read `raw/` (and every other case) directly, and the 3 November test run on THREATINTEL-DEMO-01 saw Claude Code offer to do just that when the server refused. On a live case, `--allow-writes` runs only in a host with no network-capable tools besides the Dernvale server and no shell or file access to the case store (e.g. Claude Desktop with only this server, or a host on another machine from the Dernvale server), or Ask Eru with local Ollama is used instead. Policy, not code: Dernvale can't see the host's other tools.
3. **Token: enforced.** On a team server `--allow-writes` refuses to start unless `DERNVALE_TOKEN` is an `eru-mcp` API token (`eru_mcp.server.write_refusal`, checked against `/api/auth/me`), so the backend itself holds the caller to reads, leads and notes whether or not the agent header is sent. Use 30-day tokens on live cases and revoke one as soon as its machine is suspect. A `full` token or a sign-in's JWT carries the user's whole rights and isn't accepted for writes.
4. **Outbound calls: confirmed none.** The MCP server calls only `/api/` on the configured Dernvale (`DernvaleAPI` refuses other paths; tested). `check_indicator` uses the backend's local value index (`/api/threat-intel/enrich`); the only outbound code in threat intelligence is TAXII import (`threat_intel/stix.py`), admin-only and refused to an `eru-mcp` token.

Re-review when a tool is added to the MCP server, when its writes go beyond leads and notes, or when online lookups are proposed.

## Review: Eru MCP over streamable HTTP (4 November 2026, Ben)

Approved for live cases on these conditions, all as recommended, with 3 built as proposed.

What changed: `dernvale mcp --http` (the `eru-mcp` service, Compose profile `mcp`, behind Caddy at `https://<host>/mcp`) serves the same tools to MCP hosts on other machines. It holds no token. Each request's bearer token is checked with `/api/auth/me` (`DernvaleTokens`) and used for that request's calls; only `eru-mcp` API tokens are taken; writes, with `ERU_MCP_ARGS=--allow-writes`, are capped at `--max-writes` per token until the service restarts.

1. **The endpoint is on the network: accepted.** Anyone who can reach the server's 443 can reach `/mcp`, but every MCP request (initialise and tool listing included) needs a token Dernvale accepts as an eru-mcp API token, and what it can see is that token's user's jobs, as in the web app. The protected-resource metadata at `/.well-known/oauth-protected-resource` is public; it names only the public URL (fixed 4 November: it had named the backend's address inside the stack). No port is published; the service only answers Caddy's Host and Origin (DNS rebinding protection).
2. **Tokens in MCP hosts' configuration: accepted, with a rule.** Over HTTP the token sits in the host's own configuration (for Claude Code, `claude mcp add --header`), as `DERNVALE_TOKEN` did over stdio. Rule: 30-day eru-mcp tokens, revoked as soon as the machine is in doubt (as condition 3).
3. **Full tokens: refused, enforced.** A `full` token, sitting in a host's configuration, would carry its user's whole rights against the API if it leaked. Over HTTP every request, reads included, needs the `eru-mcp` scope (`DernvaleTokens`; tested: a full token, a JWT and an unknown token get 401 before any tool), so a leaked MCP token is worth only reads, leads and notes.
4. **Sessions: confirmed no crossing.** A streamable HTTP session ID gives nothing without a token: every request is checked again and its Dernvale calls carry its own token, never one cached from the session (`request_token`, tested with two analysts on one server).
5. **Write cap: accepted.** Over stdio the cap is per session (the process); over HTTP it's per token until the service restarts. It still bounds what text inside a case can make one host write. An analyst can mint more tokens, but the cap is against a misled model, not the analyst.
6. **Condition 2 still applies: kept.** HTTP helps its file-access half (the host is on another machine from the case store), but a host with other network-capable tools is the same risk as before.
7. **Unauthenticated load: accepted for a team network.** Every request with a bad token costs a call to `/api/auth/me`. Caddy could rate-limit `/mcp` if the server is ever reachable from outside the team's network.
8. **Outbound calls: confirmed still none.** The service calls only `/api/` on `http://backend:5688` inside the stack.

Re-review if the endpoint is opened beyond the team's network, if it takes any token but eru-mcp, or on the phase 2 triggers above.

## Chain of custody note

Evidence packages are SHA256-hashed at acquisition time. Do not modify anything under `evidence/` or `cases/<CASE-ID>/raw/`. Processed output under `cases/<CASE-ID>/output/` is writable.
