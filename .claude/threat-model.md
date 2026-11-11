# Rowanholt — Threat Model

## What Claude Code can touch

- Source code under `rowanholt/`, `mcp/`, `src/`, `tests/`, `scripts/`
- Case metadata and structured output JSON
- XLSX evidence files under `data/`
- Documentation under `docs/`

## What Claude Code must never touch

- `evidence/` — raw forensic artefacts. This directory is write-denied in settings.json. If a task requires reading from it, confirm with Ben first.
- `.env` — contains API keys (Anthropic, Ollama endpoint, LinkedIn). Never read or write.
- Any file containing credentials, tokens, or certificates.

## Risk areas specific to this project

- **Aulë MCP tools** — Aulë has outbound network access for threat intel enrichment. Any new MCP tool registration must be reviewed before it goes near a live case. The write tools (`flag_lead`, `add_note`, phase 2) exist only with `rowanholt mcp --allow-writes`: leads only, recorded as "Aulë (for <user>)", the backend refusing Aulë other statuses, edits, deletes and assignments, and a per-session write cap. Reviewed 3 November 2026; the HTTP transport, 4 November (below).
- **Subprocess calls to forensic tools** — Volatility3, log2timeline, RegRipper run with elevated access to memory dumps. Do not modify subprocess invocation patterns without explicit instruction.
- **SQLite case database** — schema changes require a migration. Do not ALTER TABLE directly; create a migration script.
- **Iran APT XLSX loader** — `rowanholt/threat_intel/iran_apt_loader.py`. The 10-column schema is fixed. Do not add columns without updating the dataclass, index, and tests.

## Review: Aulë MCP phase 2 (3 November 2026, Ben)

Approved for live cases on these conditions.

1. **Prompt injection from case data: accepted.** Text in the evidence (a filename, a task description, a log line) can lead the model to flag decoy leads or write misleading notes. It can't confirm, change or remove findings, assign hosts, or write more than `--max-writes` (25) times a session, and every write is labelled "Aulë (for <user>)". It can't be prevented in code: the model reads the evidence it's asked to analyse. Team rule: an Aulë lead or note is a suggestion, never a clearance; only an analyst clears a host.
2. **Case data leaving through another tool, or `raw/` read round the API: required rule.** Aulë sends nothing outside Rowanholt, but an MCP host with other network-capable tools (web fetch, Slack, GitHub, email) could be led by injected text to send case data out through them. The server's `raw/` boundary holds only for what goes through the API: a host with a shell or file tools on the machine holding the case store can read `raw/` (and every other case) directly, and the 3 November test run on THREATINTEL-DEMO-01 saw Claude Code offer to do just that when the server refused. On a live case, `--allow-writes` runs only in a host with no network-capable tools besides the Rowanholt server and no shell or file access to the case store (e.g. Claude Desktop with only this server, or a host on another machine from the Rowanholt server), or Ask Aulë with local Ollama is used instead. Policy, not code: Rowanholt can't see the host's other tools.
3. **Token: enforced.** On a team server `--allow-writes` refuses to start unless `ROWANHOLT_TOKEN` is an `aule-mcp` API token (`aule_mcp.server.write_refusal`, checked against `/api/auth/me`), so the backend itself holds the caller to reads, leads and notes whether or not the agent header is sent. Use 30-day tokens on live cases and revoke one as soon as its machine is suspect. A `full` token or a sign-in's JWT carries the user's whole rights and isn't accepted for writes.
4. **Outbound calls: confirmed none.** The MCP server calls only `/api/` on the configured Rowanholt (`RowanholtAPI` refuses other paths; tested). `check_indicator` uses the backend's local value index (`/api/threat-intel/enrich`); the only outbound code in threat intelligence is TAXII import (`threat_intel/stix.py`, through `samarkand.taxii`, which follows no redirects), admin-only and refused to an `aule-mcp` token.

Re-review when a tool is added to the MCP server, when its writes go beyond leads and notes, or when online lookups are proposed.

## Review: Aulë MCP over streamable HTTP (4 November 2026, Ben)

Approved for live cases on these conditions, all as recommended, with 3 built as proposed.

What changed: `rowanholt mcp --http` (the `aule-mcp` service, Compose profile `mcp`, behind Caddy at `https://<host>/mcp`) serves the same tools to MCP hosts on other machines. It holds no token. Each request's bearer token is checked with `/api/auth/me` (`RowanholtTokens`) and used for that request's calls; only `aule-mcp` API tokens are taken; writes, with `AULE_MCP_ARGS=--allow-writes`, are capped at `--max-writes` per token until the service restarts.

1. **The endpoint is on the network: accepted.** Anyone who can reach the server's 443 can reach `/mcp`, but every MCP request (initialise and tool listing included) needs a token Rowanholt accepts as an aule-mcp API token, and what it can see is that token's user's jobs, as in the web app. The protected-resource metadata at `/.well-known/oauth-protected-resource` is public; it names only the public URL (fixed 4 November: it had named the backend's address inside the stack). No port is published; the service only answers Caddy's Host and Origin (DNS rebinding protection).
2. **Tokens in MCP hosts' configuration: accepted, with a rule.** Over HTTP the token sits in the host's own configuration (for Claude Code, `claude mcp add --header`), as `ROWANHOLT_TOKEN` did over stdio. Rule: 30-day aule-mcp tokens, revoked as soon as the machine is in doubt (as condition 3).
3. **Full tokens: refused, enforced.** A `full` token, sitting in a host's configuration, would carry its user's whole rights against the API if it leaked. Over HTTP every request, reads included, needs the `aule-mcp` scope (`RowanholtTokens`; tested: a full token, a JWT and an unknown token get 401 before any tool), so a leaked MCP token is worth only reads, leads and notes.
4. **Sessions: confirmed no crossing.** A streamable HTTP session ID gives nothing without a token: every request is checked again and its Rowanholt calls carry its own token, never one cached from the session (`request_token`, tested with two analysts on one server).
5. **Write cap: accepted.** Over stdio the cap is per session (the process); over HTTP it's per token until the service restarts. It still bounds what text inside a case can make one host write. An analyst can mint more tokens, but the cap is against a misled model, not the analyst.
6. **Condition 2 still applies: kept.** HTTP helps its file-access half (the host is on another machine from the case store), but a host with other network-capable tools is the same risk as before.
7. **Unauthenticated load: accepted for a team network.** Every request with a bad token costs a call to `/api/auth/me`. Caddy could rate-limit `/mcp` if the server is ever reachable from outside the team's network.
8. **Outbound calls: confirmed still none.** The service calls only `/api/` on `http://backend:5688` inside the stack.

Re-review if the endpoint is opened beyond the team's network, if it takes any token but aule-mcp, or on the phase 2 triggers above.

## Review: online lookups (4 November 2026, Ben)

Approved as built, any analyst. Built on `feat/rowanholt-outstanding` behind a switch that's off: nothing leaves until `.env` sets `ROWANHOLT_ONLINE_LOOKUPS=virustotal` and `VIRUSTOTAL_API_KEY`.

What it does. `POST /api/threat-intel/lookup` sends one value to VirusTotal v3 (`threat_intel_lookup.py`, stdlib `urllib`, a fixed `https://www.virustotal.com/api/v3/` URL, 15-second timeout) and returns the detection counts, reputation, tags and a link. Pippin's *Check a value* shows a **Look up on VirusTotal** button only when it's on. Answers are cached in memory for an hour, so a second click doesn't send again.

1. **Who can send: any signed-in analyst, never Aulë.** The route refuses an aule-mcp token and any request carrying `X-Rowanholt-Agent` (or the old header), and an aule-mcp token is refused by `tokens.refusal` anyway (a POST outside leads, notes and Aulë's questions). The MCP server has no tool for it and Ask Aulë doesn't call it, so point 4 of the phase 2 review ("outbound calls: confirmed none") still holds for Aulë. Elrond never calls it. Decided: any analyst, not admin-only.
2. **What can be sent: an IP, domain or hash only.** Private, loopback, link-local, CGNAT, reserved and documentation addresses are refused (`is_global`), as are single-label names and `.local`, `.lan`, `.corp`, `.internal`, `.home.arpa` and the like. Command lines, paths and process names can't be sent. Risk accepted: a public domain that is the client's own (their AD forest's public name, an internal service on a real domain) still goes, and tells VirusTotal, and anyone with VirusTotal's intelligence feeds, that someone is investigating it. A file hash looked up reveals interest in that file, and an unknown hash is a strong hint that something new is being looked at. No list of the client's own domains: the analyst decides what to look up.
3. **The key.** Read from the environment only (`VIRUSTOTAL_API_KEY`), never stored, logged or returned. A public-API key's quota is small (`429` is shown as such). On a team server the key is the team's, so every analyst's lookups count against one account and appear in that account's history.
4. **Audit.** Each lookup is logged (`Online lookup: <user> asked virustotal about <kind> <value>`) in the backend log, not the case's activity, because Pippin has no case. The roadmap's agreed shape was per case and in the case's audit log. Accepted: the backend log, from Pippin, not per case.
5. **Prompt injection: none new.** Nothing a model reads reaches the lookup, and its answer goes only to the analyst's browser, not into Aulë's context.

Tests: `tests/unit/test_threat_intel_lookup.py` (off by default, what's refused, Aulë refused, cache, VirusTotal's 404/429/401/timeouts) against the real backend in server mode, with the fetcher swapped so nothing is sent.

Re-review if lookups are made automatic, offered to Aulë or Elrond, sent to another provider, or given values other than IPs, domains and hashes.

## Elrond's DNS lookups of extracted IOCs (4 November 2026, Ben)

Found in the accuracy review: Elrond ran `host` on every domain and IPv4 address it extracted (`analysis/iocs.py`, the `resolvable` column of `iocs.csv`), always on. That is an automatic online lookup, and each one tells the domain's nameserver someone is asking. Ben chose to gate it: it runs only when `ROWANHOLT_ONLINE_LOOKUPS` lists `dns` (a comma list now, beside `virustotal`), and the column reads `not checked` otherwise. The worker is given the setting; Pippin's VirusTotal lookup still needs `virustotal` and its key.

## Review: a Tailscale Service name (6 November 2026, Ben)

Approved as built (`028b5ed`). What changed: `server init --service <name>` (with `--tls tailscale`) gives the server a name of its own, `https://<name>.<tailnet>.ts.net`, through `tailscale serve --service`. tailscaled in the VM ends TLS for the name with Tailscale's certificate and hands each request to Caddy on `127.0.0.1:5680` (5681–5683 for Splunk, Kibana and the Navigator), published by `docker-compose.service.yml` on the VM's loopback only. Caddy's `Caddyfile.service` sites import the same `(app)` routes and `signed_in` gates as the main site. The old address (`:8443`) keeps working.

1. **Plain HTTP on the VM's loopback: accepted.** The only unencrypted hop is tailscaled to Caddy inside the VM. Watching it needs a shell on the VM, which already reaches `.env` and the case store. Nothing is published to the LAN or the tailnet beyond the Service's own address.
2. **`X-Forwarded-Proto: https` set unconditionally on the service sites: accepted.** Caddy sees plain HTTP from tailscaled, so the backend would otherwise build `http://` redirects and login URLs. A process on the VM calling 5680 directly is taken as HTTPS too, but still has to sign in; it gains nothing it doesn't already have.
3. **Other URLs accepted (`ROWANHOLT_OTHER_URLS`, the `:8443` address): accepted.** They're added to the backend's CORS and websocket origins, aule-mcp's allowed Hosts and Origins (DNS rebinding protection), and the SIEM `/verify` redirect, which picks the sign-in URL matching `X-Forwarded-Host` among the configured URLs and otherwise falls back to the public URL, so it can't be steered off them. Every MCP request still needs an aule-mcp token; full tokens and JWTs are still refused.
4. **Who can reach the name: the tailnet policy.** The Service has its own address (the VIP), defined in the admin console, approved for tagged hosts (`autoApprovers.services`) and reachable only through the grants `tailscale-setup.py` writes, per port.

Re-review if the Service is shared outside the tailnet (Funnel or a shared node), if the loopback ports are published beyond `127.0.0.1`, or if `ROWANHOLT_OTHER_URLS` takes an address that isn't the server's own.

## Rename: Eru to Aulë (9 November 2026, not a review)

The AI analyst was renamed from Eru to Aulë; the reviews above were made under the old name and their dates and conditions stand unchanged. Nothing a token, header or tool may do changed. The old names are kept as aliases, deliberately, like the Rivendell leftovers: the `eru-mcp` scope is read as `aule-mcp` wherever a scope is given or checked (`auth/tokens.py` `OLD_SCOPES`; stored scopes renamed by migration `f2b7c9d4e816`), `X-Rowanholt-Agent: eru-mcp` (and `X-Rivendell-Agent`) still marks a call as Aulë's, the MCP server answers `python -m eru_mcp.server` and the Compose network name `eru-mcp`. The MCP tool itself has only its new name, `ask_aule`: the `ask_eru` alias was dropped on 9 November 2026 (Ben), so no tool was added without a review.

## Symbol table downloads (9 November 2026: design approved by Ben, the build not yet reviewed)

The worker can now go online for memory images: Elrond finds the Volatility symbol table for a Linux or macOS kernel from its banner and fetches what it hasn't got (`src/analysis/rowanholt/memory/symbols/`, `symbols/README.md`). Ben approved the design on 9 November 2026: on by default locally, `ROWANHOLT_SYMBOL_DOWNLOADS=off` turns it off, and `server init` writes off.

1. **What leaves.** A kernel's release and package version (`5.15.0-91-generic`, `5.15.0-91.101`), asked of GitHub (the prebuilt collection's index and its releases API), Launchpad, snapshot.debian.org, or Rocky's or Alma's vault, over HTTPS only (redirects off HTTPS refused). This tells those services that someone wants that kernel's symbols, nothing about the case. With downloads on, Volatility's own Windows PDB fetches (msdl.microsoft.com, the PDB's GUID, Volatility's behaviour before this change) carry on; with them off, `vol.py` runs `--offline`, so those stop too.
2. **Integrity.** Every file is hashed as it downloads and checked against its publisher's hash before anything opens it. A mismatch deletes it. The prebuilt collection's SHA-256 comes from GitHub's asset digest, the distributions' from their own metadata, and Debian's is SHA-1, the only one the snapshot gives (it's also the file's address there). Risk accepted: a hash proves only that the file is what its publisher put up. The prebuilt collection is one person's builds with no licence and no signature. A wrong table gives wrong or missing plugin output, not code execution: an ISF is JSON. dwarf2json is built from its `v0.9.0` tag, a tag and not a pinned commit.
3. **Parsing untrusted packages.** Debug packages are unpacked in the worker by `dpkg-deb -x` and by `rpm2cpio | cpio --no-absolute-filenames` (only `*vmlinux*`), in a temporary folder that's always removed. The tools are Ubuntu's own packages.
4. **Audit.** Every download, build and failure is in the case's audit log (`symbols` stage) and in `symbols/<os>/rowanholt-symbols.log`, which also records `rowanholt symbols` and Aragorn's uploads.
5. **Who can trigger it.** A job, for its own image's kernel. The `rowanholt symbols` command, run on the host, which already has Docker. Aragorn's upload (`/api/symbols`, admin-only, in `ADMIN_PREFIXES`, so aule-mcp tokens are refused), which fetches nothing: it builds from the uploaded files in the worker, and the task refuses any folder outside `symbols/incoming/`. Aulë has no route to any of it.

Re-review if a source is added, a check is dropped, downloads are turned on by default for servers, or Aulë or a non-admin is given a way to trigger a fetch.

## Sample data downloads (9 November 2026, Ben asked for it; not yet reviewed)

`rowanholt samples` and Aragorn's Sample data card download public forensic images (`src/analysis/rowanholt/samples/`). The CLI runs on the host, and Aragorn's Fetch runs in the worker: a new outbound path from the worker, admin-only (`/api/samples` is in `ADMIN_PREFIXES`, so aule-mcp tokens are refused). The URLs are fixed in the catalogue, HTTPS only, with redirects off HTTPS refused. Each file is checked against its publisher's hash before it's kept: MD5 for DFIR Madness, the only hash it publishes; SHA-256 from Digital Corpora's search API (fetched at download time, from the same publisher as the file); none for 13Cubed, whose first download's SHA-256 is recorded and held to. Archives are unpacked with path traversal refused (zip and tar members with absolute or `..` paths; tar links and devices skipped; 7z by `7z x`). The images are attack scenarios and may hold live malware: they're unpacked as data and analysed by Elrond as any evidence is, never executed. An import is an ordinary job, made by the analyst who clicks it.

Re-review if a sample's URL is taken from anywhere but the catalogue, a check is dropped, or fetches are offered to Aulë or non-admins.

## Chain of custody note

Evidence packages are SHA256-hashed at acquisition time. Do not modify anything under `evidence/` or `cases/<CASE-ID>/raw/`. Processed output under `cases/<CASE-ID>/output/` is writable.
