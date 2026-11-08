# Roadmap: the v2.3 features

Plans for four of the README's v2.3 items: what already exists, what each one needs, and the order to build them in. Everything else requested is in `docs/FEATURE_REQUESTS.md`. One output format for every artefact (JSON Lines) is planned in `docs/OUTPUT_FORMAT.md`.

| Feature | Already there | Size | Order |
|---|---|---|---|
| Container forensics | Built (see below) | Done | 1 |
| Threat intelligence | Built (see below) | Done | 2 |
| Collaborative investigation | Built (see below) | Done | 3 |
| ML-based anomaly detection | Stacking, features and baseline built and measured in the lab; no learned model | Done | 4 |
| Azure, tested in a lab | Acquisition and Activity Log code from v2.1, never run against a tenant or tested | **Parked: needs paid Azure resources** (below) | — |

Container forensics goes first because half of it is written. ML goes last because it needs multi-host cases and the lab's ground truth to measure it against, and an unmeasured anomaly score is worse than none.

## Container forensics (Docker, Kubernetes)

**Built.** The outputs are listed in `docs/CLI.md` (Gandalf's Linux table).

- **Collection.** All three collectors take the same set: `gandalf.sh`, `gandalf.py`, and Elrond's image collection in `collect/linux.py`. It covers:
  - each Docker container's `config.v2.json`, `hostconfig.json` and log;
  - static pod manifests, pod logs and the API server's audit log.
- **The writable layer.** Each container's writable layer is listed with hashes as `gandalf+container_changes.csv`, and the executables and scripts in it are copied (up to 500 per container, 64 MB each) into `container_layer/<id>/`, where Elrond reads them as staged files. That makes the change set the container version of misplaced binaries, without the tens of gigabytes of image layers that `gandalf.py` used to risk.
- **Parsing.** `process/extractions/containers.py` and `k8s_audit.py`, routed from `linux_artefacts.py`.
- **Techniques.** A technique is tagged only where a row justifies it. A container is tagged for what it can reach, not for existing; a Kubernetes component doing its job is never a finding.
- **Exported audit logs.** `python3 -m src.analysis.rowanholt.cloud.cli k8s analyze-logs` handles audit logs exported from EKS, AKS or GKE.
- **The lab.** The Linux targets seed a Docker host's and a Kubernetes node's state on disk (`lab/linux-targets/seed/seed-containers.sh`), with the expected results in their `expected.json`. `tests/unit/test_containers.py` runs that seed through collection and processing.

**Still to do.**
- **The bash collector against the seed.** `gandalf.py`'s copy of the container lists ran against the rebuilt targets on 29 October (the containers video section shows its output). `gandalf.sh` collected the seed the same day, layer copy included, and Elrond over its result passed every container row of `verify-expected.py` on both targets (the one miss, `status.php`, needs YARA, which that run didn't use).
- **containerd's own metadata** (`/var/lib/containerd`, a bbolt database) is collected by all three collectors since 29 October, with Podman/CRI-O's `containers.json`, and parsed since 2 November: every container in every namespace but Docker's own (`moby`) becomes a `docker_containers.csv` row, `Runtime` `containerd`, flagged by the same rules. Podman's own state is read too (2 November): `db.sql` (SQLite, Podman 4.8 on; its `-wal` read with it, from a copy) or `libpod/bolt_state.db` (bbolt, before), each container's config with its OCI spec, `Runtime` `podman`. Rootless stores too since 3 November: each user's `~/.local/share/containers/storage` state is collected by all three collectors into the user's files and read the same way, `Runtime` `podman (rootless, <user>)`. `containers.json` stays unparsed: it has names and images but no settings.
- **Live container capture** built 3 November as the explicit opt-in this line asked for: `gandalf.sh -l` and `gandalf.py -L` save each running container's `inspect`, `top` and `export` (cut at `GANDALF_CONTAINER_EXPORT_MAX`, 2 GB), every command audited as `ran`; Elrond reads the processes into `container_processes.csv`. CRIU checkpoints stay out (experimental, and they can stop the container).

## Threat intelligence integration

**Built.** The package is `src/analysis/rowanholt/threat_intel/`, inside Elrond's tree, so the worker has it and the backend mounts it.

- **Schema and loader.** The fixed ten columns are a frozen dataclass (`schema.py`). `iran_apt_loader.py` reads the workbook and finds its header row. Postgres holds the indicators in `threat_intel_indicators`, added by Alembic revision `7c41d2e9a0b3`.
- **Intake.** `sources.py` takes a file and recognises its format. It handles:
  - the workbook;
  - Rowanholt's CSV;
  - MITRESaw's procedures CSV;
  - STIX 2.1 bundles;
  - text watchlists;
  - TAXII 2.1 collections (`stix.py`).

  The STIX and TAXII parsers are ported from Archer. `Source Type` records each row's origin, and duplicates are dropped on element, group, technique and source. No columns were added.
- **Matching.** `index.py` infers each indicator's kind and refuses the ones that would flood a case: built-ins, ordinary words, prose, placeholders, bare extensions and shallow directories. Archer's `known_good.json` supplies part of that list. Each element carries its breadth, the number of groups behind it, and an element more than 15 groups use is marked common. Against a whole case, MITRESaw contributes only software names and multi-word command phrases. On a copy of the Windows 11 demo case, that took the result from 86,829 matches (Lazarus first, on `.jpg`) to 42 matches across seven elements.
- **Elrond.** `--threatIntel FILE ...`, or Threat Intelligence on Elrond's page, runs after analysis (`match.py`). It writes `<host>/analysis/threat_intel_matches.csv`, fills `watchlist_match` in `iocs.csv`, and writes the case's `threat_groups.csv`. That file ranks groups by atomic indicators, then specific elements, then technique overlap. Its Basis column states which of those each rank rests on, and a group that overlaps only on techniques says so.
- **Web.** Pippin, the threat intelligence page (`/pippin`), imports files, pulls TAXII collections, lists and removes sources, searches indicators and checks a single value (`/api/threat-intel`, [API.md](API.md#threat-intelligence)). Importing is admin-only on a team server.
- **Eru.** The offline question "Does anything match known threat intelligence?" lists the most specific matches first. `enrich_artefact()` (`threat_intel_routes.enrich_value`) is ready for the planned MCP server.
- **Tests.** `tests/unit/test_threat_intel.py`, and the Eru question in `test_eru_offline.py`.

**Still to do.**
- **Expiry** (done 2 November). STIX `valid_until` and confidence are kept beside the ten columns in `threat_intel_validity` (`threat_intel/validity.py`, Alembic `9e3c5a7b1f42`); other sources default to 90 days for IPs and domains, as Archer does. Expired indicators stay listed but are left out of Elrond's matching and Eru's value index.
- **Online lookups** (4 November, approved under the threat model the same day). VirusTotal only, off unless `.env` sets `ROWANHOLT_ONLINE_LOOKUPS=virustotal` and `VIRUSTOTAL_API_KEY`: a **Look up on VirusTotal** button on Pippin's *Check a value*, one IP, domain or hash per click, refused to Eru, private addresses and internal names never sent, logged with who asked (`threat_intel_lookup.py`, `test_threat_intel_lookup.py`). The review accepted them from Pippin, logged in the backend log, not per case.

## Collaborative investigation

**Built.** It works the same on one analyst's machine as on a team server, where access follows job sharing (`auth/access.py`'s job check covers every route, since they're all under `/api/jobs/{id}/case`).

- **Case browser.** **Browse Case** on a completed job opens `/jobs/{id}/case`. It lists each host's cooked artefacts and analysis files, plus the case's own CSVs (`threat_groups.csv`), in paged tables you can filter on any field. It is read-only by construction (`case_files.py`): requests are resolved against `artefacts/cooked/`, `analysis/` and the case root, `raw/` is never reachable, and nothing opens a file for writing.
- **Findings.** ⚑ on any row flags it as a lead or confirms it outright, with a title and an optional technique. The server reads the row itself and stores its file, row reference, SHA-256 and an excerpt. If a re-run or an edited file changes the row, the finding shows "row changed" rather than silently pointing at something else.
- **Notes, assignment and activity.** Notes are Markdown, on the case or on a finding. Each host has an assignee and a status: to do, in progress or done. On a team server the assignee must be an active user (an email is stored as the username); on one machine it's free text. An append-only feed records who flagged, marked, assigned, noted or exported what. The page reloads when anything changes, told by a websocket (`/case/live`, 3 November), and polls every 15 seconds only while that's down.
- **Working at the same time.** Findings, notes and activity are separate rows, so simultaneous additions never collide.
  - A second flag on an already-flagged row is refused with the existing finding's number and author; the second analyst adds a note to it instead.
  - A status change carries the `updated_at` it was made against, and the server refuses it (409) if a colleague changed the finding first; the page then reloads it.
  - The worker's image locks keep two jobs off the same evidence. Re-running a case that already has findings rewrites its cooked output, and the affected findings then show "row changed". So a restart of a job with findings is refused (409, with the count) unless the request says `confirm=true`; the bulk restart skips such jobs the same way. The Job page and the Jobs list say how many findings there are and send `confirm` once the analyst agrees.
- **Output.** **Findings** is Markdown: case notes first, then confirmed findings by host with their notes. **Navigator layer** holds confirmed findings' techniques only. Elrond's own layer is unchanged. **Report (DOCX)** and **Report (Markdown)** are the case report (FR-07, 8 November): confirmed findings first, then open leads and dismissed rows, then Elrond's report from the case (`docs/CLI.md`, Case report).
- **Eru.** The offline question "What have analysts confirmed?" lists confirmed findings, then open leads. With a model, confirmed findings go into its context first.
- **Storage.** Four tables, `case_findings`, `case_notes`, `case_hosts` and `case_activity`, added by Alembic revision `4d8b1f6e2c57`.
- **Tests.** `tests/unit/test_case_browser.py` covers the refusals around `raw/`, paging and filters, the finding lifecycle (including a changed row), notes, assignment (checked against the users on a server), activity, the report, the layer and Eru's answer.

**Still to do.**
- **Live updates.** Built 3 November: a websocket that says when the activity feed or the job changes, the data still read through the ordinary routes. It checks Postgres every 2 seconds per open page, which is fine at a team's size; a pub/sub (Postgres `LISTEN`/`NOTIFY` or Redis) would replace that if it ever isn't.

## ML-based anomaly detection

"ML-based" is easy to oversell. This plan builds the frequency analysis practitioners already trust first, then features, then a model, and measures each step against the lab before it ships.

**Built: Phases 1, 2 and 4.** The code is `src/analysis/rowanholt/analysis/stacking.py`, stdlib only. `--Analysis` runs it on any case with two or more hosts; a value is only called rare among three or more hosts of its OS (`MIN_HOSTS`), since on two, "on one of them" is a diff of their builds. A baseline still applies below that. Linux hosts are compared within their distribution family (Debian, RHEL, SUSE, Arch, Alpine), from os-release or the distro's fingerprints, so a lone Rocky host among Ubuntu ones doesn't make its whole distro rare.

- **Stacking.** For each host, it collects the values the host has in each family:
  - processes (Prefetch, Amcache, 4688, Sysmon 1);
  - parent and child pairs;
  - services (7045, systemd units);
  - scheduled tasks (4698, the task files);
  - autoruns (Run keys, startup items, Linux autostart, BTM);
  - WMI consumers;
  - kernel modules.

  A value on at most a fifth of the hosts of its OS (one, in a small case) goes to the case's `stacking.csv`, which the case browser shows. Families are compared across hosts of the same OS only. A Windows host's programs aren't rare because the case also holds Linux, but a WMI consumer on one of five Windows hosts is rare even when the other four have none. User folders are normalised, so `C:\Users\alice\x` and `C:\Users\bob\x` stack together, and so are the GUIDs and SIDs in task names. A single-host case writes nothing and says so in the log.
- **Features.** Each row's score is the sum of named reasons, and the row lists them:
  - **rare**;
  - **user path** (Users, AppData, Temp, ProgramData, `/tmp`, `/dev/shm`, `/home`);
  - **generated name**;
  - **not in baseline**;
  - **unsigned**: a kernel module that tainted the kernel as unsigned (`E`), or a driver Sysmon (event 6) saw load without a valid signature;
  - **no team ID**: a third-party BTM item whose code signature names no Team ID (ad hoc or unsigned);
  - **outside logon hours**: a process, task, service or driver first seen at an hour (UTC) when no one logs on to that host. Its 4624 logons of types 2, 10 and 11 (accounts not ending `$`) give its hours, widened an hour each way, once there are ten. Windows only: the Linux and macOS families carry no times.

  The last three (3 November) belong to the host, and only add to a value that's already rare or new against the baseline. Signatures come only from where the cooked artefacts already have them: Prefetch, Amcache and 4688 carry none, so a rare program's signature isn't judged.

  "Generated name" looks at shape: few vowels, a long consonant run, digits and letters interleaved, or long hex. Entropy alone flagged every long English compound (`backgroundtaskhost.exe`) on the demo case, and a program under `\Windows\` (not `\Windows\Temp\`) isn't called generated, so `mscorsvw.exe` stays quiet. At equal score, persistence (services, tasks, autoruns, WMI, kernel modules) ranks above programs.
- **Baseline.** `python3 -m rowanholt.analysis.stacking --baseline OUT CASE...` (from `src/analysis`) writes every value from clean cases. `--stackBaseline OUT` then scores what's absent from it, and with a baseline even a one-OS-host family is scored. It stays a lab-built, local file.
- **Measurement.** `precision_at_k(stacking.csv, seeded values, k)` is the lab's yardstick. `tests/unit/test_stacking.py` seeds an eight-host case (five Windows, three Linux) and requires the seeded values in the top three, plus a mixed-distro case.
- **In the lab, Windows (29 October 2026).** Three Windows 11 hosts, one seeded (`lab/README.md`, clean siblings): all four planted persistence values rare on the seeded host, ranked 1, 2, 6 and 8 of 74 once persistence ranks above programs at equal score. The other rows are what the seeded VM gained from four days' use.
- **In the lab, Linux (29 October 2026).** `./lab.sh linux-targets stacking` adds two clean Ubuntu targets to the seeded `lab-ubuntu` and `lab-rocky`. Over all four as one case, stacking returned four rows, every one planted on `lab-ubuntu` (`lab-sync.service`, `lab-agent.service` system and user, the `lab updater` autostart): precision@3 of 1.0, no noise. Before Linux hosts were grouped by distro, the same case gave twenty rows, all Rocky's own units.
- **On real data.** Across the two Windows images in `claude_testing`, the two hosts differ in almost everything, which shows how little two hosts give. The list still surfaced `bcwipe service` on the nfury Windows 7 image, a disk wiper.

**Still to do.**
- **Evaluate in the lab per release.** The Linux and Windows runs above are the method. The clean Windows VMs have no Sysmon (only `mordor-sensor` installs it, on the seeded one) and a few days' logons at most, so the signature and logon-hour reasons need a run on a case with both before their weights are trusted.
- **No learned model (Ben, 29 October 2026).** An isolation forest was considered and dropped, with `scikit-learn`, because stacking found every plant in the lab. The note below is kept for the record.
- **The isolation forest, as considered.** It would score how unusual each host's values are, not only how many hosts have them, catching what counting can't, such as a process every host runs but with an odd parent or command line on one. Against: `scikit-learn` (with numpy and scipy, about 30–40 MB) in the worker image, which the dependency rule needs agreed, and a score that's harder to explain than stacking's named reasons. Stacking found every plant with no noise on the lab case, so there was nothing for a forest to improve on.
- **Eru's "What's rare in this case?"** (built 30 October). An offline question over `stacking.csv`: persistence rows first, then programs and process pairs, each with its hosts and reasons, and the reminder that a row is a lead, not a verdict.

## Azure, tested in a lab (parked, 6 November 2026)

**Parked: it needs paid Azure resources** (a VM, disk snapshots, storage, a key vault), so it waits until that's worth paying for. It would test Rowanholt's cloud side, not host anything: the homelab stays on the tailnet server.

**There now.** `src/analysis/rowanholt/cloud/azure/` dates from v2.1, reached through `python3 -m src.analysis.rowanholt.cloud.cli azure …` (`docs/CLI.md`): `vm.py` lists VMs, acquires a disk through a snapshot, storage and logs, and reviews NSG rules; `activity_log.py` pulls the Activity Log and maps operations to ATT&CK. None of it has a unit test or is known to have run against a tenant. Its Azure SDKs are optional imports in no `requirements/` file, and it doesn't read Entra ID sign-in or audit logs.

**The plan, if it's picked up**, the way the Linux and Windows lab targets work:
1. **A lab target** (`lab/azure/`): one resource group with the cheapest Linux VM, a storage account and a key vault; `create`, `seed`, `collect`, `teardown`. The seed does attacker-like things with their expected results: a role assignment (**T1098**), a key vault secret read (**T1555.006**), Run Command (**T1651**), an NSG opened to the internet (**T1562.007**), a disk snapshot (**T1578.001**) and its export URL (**T1537**), a storage account's keys listed (**T1552**).
2. **The existing code made to pass** against it, with unit tests over recorded API responses.
3. **Entra ID logs** as new artefacts, through `docs/FEATURE_REQUESTS.md` first.
4. **Archer**: the same activity as the test set for Sentinel and KQL queries.

Guardrails: its own resource group or subscription with a budget alert set first; a least-privilege service principal, its secret out of the repo; the seed run as a separate "attacker" identity; teardown after every run; no real case data. Decisions then: separate subscription or not; the SDKs in a `requirements/cloud.txt` or not at all; whether the tenant has Entra ID P1/P2 (sign-in and audit logs past 7 days).

## Plan for what's left (29 October 2026)

Each feature's "Still to do" above, as work to schedule, then the Eru MCP server. Sizes are for one person with the lab to hand. Nothing here is started; the decisions at the end are made.

### Container forensics

1. **The bash collector against the seed** (done 29 October). `./lab.sh linux-targets reset`, `./lab.sh gandalf-collect bash`, Elrond over the result, then `lab/verify-expected.py` against each target's `expected.json`. Done when `docker_containers.csv`, `container_changes.csv`, `static_pods.csv` and `k8s_audit.csv` match for `gandalf.sh` as they already do for `gandalf.py`.
2. **containerd's metadata** (done 2 November). On a containerd or CRI-O node, per-container settings (image, mounts, privileges, namespaces) live in `/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db`, a bbolt database.
   - Collect `meta.db` in all three collectors, read-only, beside the Docker files. Done 29 October.
   - Parse it into the existing `docker_containers.csv` columns, adding a `Runtime` column (`docker`, `containerd`) so one table covers both; the technique rules then apply unchanged. Done: `containers.containerd_rows` reads `v1/<namespace>/containers/<id>` (image, labels, `createdat`, and the OCI spec inside the protobuf `Any` in `spec`). Privileged is every device plus `CAP_SYS_ADMIN`; a host namespace is one the spec leaves out or one joined from PID 1 (`/proc/1/ns/…`); a pod's labels give its namespace, pod and container names. The resolver files a runtime mounts read-only into every container (`/etc/hosts`, `/etc/resolv.conf`, `/etc/hostname`) aren't flagged, for Docker either. Missing a seccomp profile isn't flagged: ctr and the CRI leave it out by default, so it would be on every row. Started, finished and running state aren't in `meta.db` (they're the task's, in memory).
   - Seed a containerd-only node in the lab (`ctr` with a privileged container) with its rows in `expected.json`, and a unit test from that seed. Done, on the existing Linux targets rather than a node of its own: `seed/containerd/meta.db` was made by containerd 1.7 itself (`make-meta-db.sh` beside it: a privileged container with `/` mounted and the host's PID namespace, a harmless one, and a host-network pod), the seed copies it into place, and `expected.json` lists it. Tests: `test_containerd_metadata`, `test_bbolt_refuses_what_it_cannot_read` and the seed end to end in `test_containers.py`.
   - Read bbolt with a stdlib reader in `process/extractions/` (decision 2). Done: `process/extractions/bbolt.py` (meta pages with their checksums, the later transaction's root; branch, leaf, inline and overflow pages; bounds checked).
3. **Live capture** built as an opt-in (above). In all three collectors since 4 November (`Invoke-Gandalf.ps1 -LiveContainers` for Docker on Windows) and on the web app's acquisition page.

### Threat intelligence

1. **Expiry and confidence** (done 2 November: built on `feat/ti-expiry`, merged into `feat/server-deployment`, Alembic `9e3c5a7b1f42`). The ten-column schema stays as it is. A side table, `threat_intel_validity` (indicator id, `valid_until`, `confidence`, `first_seen`), added by an Alembic migration:
   - STIX imports fill it from `valid_until` and `confidence`; other sources get a default lifetime per kind (90 days for IPs and domains, as Archer does; none for hashes and tool names).
   - Matching skips expired indicators and says how many it skipped; Pippin shows the expiry and lets an admin extend or clear it.
   - Tests: an expired STIX indicator doesn't match; a refreshed import revives it.
   - Agreed (decision 3).
2. **Online lookups** (built and approved 4 November, `.claude/threat-model.md`). Keys only in `.env`, off by default, one provider (VirusTotal), from the Pippin page only, so nothing is sent from `raw/` or by Elrond or Eru. The review dropped the per-case switch and case audit log: any analyst, from Pippin, in the backend log.

### Collaborative investigation

1. **Restart with findings** (done 30 October). `POST /api/jobs/{id}/restart` answers 409 with the number of findings when there are any, unless the request says `confirm`; the bulk restart skips them likewise; the Job page shows the count and asks before restarting. Test: `test_restart_with_findings_needs_confirm` in `test_server_access.py`.
2. **Assignees checked on a team server** (done 30 October). In server mode, `PUT /hosts/{host}` refuses an assignee who isn't an active user; on one machine it stays free text. Test: `test_assignees_checked_on_a_team_server` in `test_case_browser.py`.
3. **Flagging from an Eru answer.** Offline answers done 2 November: each line built from a row carries it (`eru_offline.Cited`; only the lines shown are cited), `POST /api/ai/offline/answer` returns them with the job whose case it read, and Ask Eru lists them under the answer with ⚑, which opens the usual finding form on that row. A finding rests on a host's row, as in the case browser, so rows of the case's own summaries aren't offered for flagging; a "What's rare?" line cites the host row its value was read from instead (2 November: `stacking.csv` gained `Host` and `Row`, the reference the case browser uses, with `Artefact`; a `stacking.csv` from before then cites itself and can't be flagged until the analysis is re-run; `Sources` gives every host's row, and a line cites up to five). `threat_groups.csv` rows stay unflaggable. MCP's `ask_offline` returns them as `cite`s. Tests: `test_answers_cite_their_rows`, `test_only_shown_lines_are_cited` and `test_rare_cites_the_host_row` in `test_eru_offline.py`, `test_rows_point_at_the_host_row` in `test_stacking.py`, `test_flagging_a_cited_row` in `test_eru_mcp.py`. The model's half done 2 November: `eru_context.py` replaces `_gather_case_context` (which read `<case>/cooked/*.json`, not the per-host layout) with the hosts' rows, tagged `[R1]`…: the question's words searched in the cooked and analysis CSVs, then the rows behind the offline answers. The model is asked to cite tags; `/query` and `/summary` return the cited rows that were in what it read (a tag past the context's cut, or made up, is dropped), and Ask Eru lists them with ⚑. `/query` now finds the case as the offline answers do (nested layout, only jobs the caller can see). Ollama's window is `ROWANHOLT_NUM_CTX` (8192). Tests: `test_eru_context.py`. Suggestions cite too: each parsed suggestion carries the rows its own text cites, and the response all of them with `job_id`.
4. **Live updates** stay as polling until someone asks.

### Stacking (anomaly detection)

1. **Eru's "What's rare in this case?"** (done 30 October). An offline question over `stacking.csv`: the top rows, persistence first, each with its hosts and reasons, and the reminder that a row is a lead, not a verdict. Tests in `test_eru_offline.py`, one keeping its persistence families equal to `stacking.PERSISTENCE`.
2. **One command for the lab evaluation** (built 30 October; first run end to end 3 November: precision at 4, 8 and 20 all 1.00, the plants at ranks 1, 2 and 4, recorded in `lab/README.md`). `./lab.sh stacking-eval` builds the stacking targets, collects them into a folder of its own, runs Elrond in the worker and prints precision at 4, 8 and 20 against the plants (the `stacking` values in each target's `expected.json`), appending the result to a table in `lab/README.md`. The scorer, `lab/lib/stacking_eval.py`, is tested in `test_stacking_eval.py`. Linux every release; Windows when its clean VMs are rebuilt (about two hours), at least once per major release.

### The Eru MCP server

**Phase 1 built (31 October 2026):** `src/eru_mcp/server.py`, `rowanholt mcp`, `requirements/mcp.txt`, documented in `docs/ERU.md`. mcp 2 renamed FastMCP to `MCPServer`, which it uses. Streamable HTTP behind Caddy built 3 November (`rowanholt mcp --http`, the `eru-mcp` service under the server profile's `mcp` Compose profile): each request's own eru-mcp API token is checked with `/api/auth/me` and used for that request's calls (full tokens and JWTs refused), writes capped per token. Reviewed and approved under the threat model on 4 November. Lab run on THREATINTEL-DEMO-01 done 3 November, in Claude Code: the tools listed the case, its hosts and techniques and its persistence with row citations, a lead was written as "Eru (for local)", and `raw/` was refused. It found a broken registry file (E47) and Run keys missing from Eru's persistence answer (E48), both fixed, and led to review condition 2 covering shell access (below).

**Phase 2 built (3 November 2026):** `flag_lead` and `add_note`, only with `rowanholt mcp --allow-writes`. Leads only; every call sends `X-Rowanholt-Agent: eru-mcp`, so the backend records the write as "Eru (for <user>)" and refuses Eru other statuses, edits, deletes and host assignment; `--max-writes` (25) caps a session. Tests in `test_eru_mcp.py`. Long-lived API tokens (3 November, Alembic a3f8c6e1d295): an `eru-mcp` token holds the caller to reads, Eru's questions, leads and notes in the backend itself, header or not, and `--allow-writes` needs one on a team server. Reviewed 3 November with conditions (`.claude/threat-model.md`): live cases only in an MCP host without other network-capable tools and without shell or file access to the case store.

**What it is.** One MCP server, built with FastMCP (mcp 2's `MCPServer`), through which an MCP host (Claude Desktop, Claude Code, OpenClaw) works a Rowanholt case. It registers every Eru capability; nothing else registers tools.

**How it's built.** A thin client of Rowanholt's own API, not a second way into the case files.
- On a team server, every call carries the analyst's token, so job sharing (`auth/access.py`) decides what the server can see, exactly as for the web app.
- The case browser's guarantees carry over: read-only over `cooked/`, `analysis/` and the case root, and `raw/` never reachable.
- It calls nothing but the Rowanholt API, so it adds no outbound access.
- It runs over stdio on the analyst's machine (`src/eru_mcp/server.py`, `rowanholt mcp` to start it), and optionally over streamable HTTP behind Caddy on a team server.

The March 2026 prototype ("Building an MCP") kept its own case folders, ran its own acquisition and could call Anthropic's API. None of that carries over: cases are Rowanholt jobs, acquisition is Gandalf's, and Eru's model is Ollama. Archer keeps its own server.

**Phase 1: reading a case** (two days; built).

| Tool | Calls |
|---|---|
| `list_cases` | `GET /api/jobs` |
| `case_overview(job_id)` | the job, its hosts and their files (`GET /api/jobs/{id}`, `GET /api/jobs/{id}/case`) |
| `read_rows(job_id, host, file, filter, offset, limit)` | `GET /api/jobs/{id}/case/rows`, with each row's reference for citing |
| `ask_offline(job_id, question)` | `POST /api/ai/offline/answer`: the twelve fixed case questions, "What's rare?" among them, with the rows each answer came from as `cite`s |
| `ask_eru(job_id, question)`, `case_summary`, `suggestions` | `/api/ai/cases/{case}/…`, when Ollama is up; otherwise they say so and point to `ask_offline` |
| `check_indicator(value)` | `GET /api/threat-intel/enrich` (`enrich_artefact()`) |
| `rare_across_hosts(job_id)` | `stacking.csv` through the case rows |
| `findings`, `report`, `navigator_layer` | the case browser's routes |

The server's instructions: start from a job id; cite file and row for every claim; a stacking row or a threat intelligence match is a lead, not a verdict.

**Phase 2: writing leads** (a day, after review). `flag_lead` (a lead on a cited row, never a confirmed finding: confirming stays with an analyst) and `add_note`. Each write lands in `case_activity` as "Eru (for <user>)". Deferred (decision 4).

**Never exposed:** starting, restarting or deleting jobs, Gandalf acquisition, importing or deleting threat intelligence, and anything under `raw/`.

**Before it goes near a live case**, the threat model's review:
- the tool list against the never-exposed list;
- a test that a user can't reach a job that isn't theirs or shared with them;
- a test that no tool reaches `raw/`;
- confirmation that it makes no outbound calls.

**Tests and docs.** Unit tests drive the tools through FastMCP's in-memory client against the FastAPI test client; the lab run uses THREATINTEL-DEMO-01. `docs/ERU.md` gets a section, and `.claude/CLAUDE.md` moves it out of "Planned".

### Suggested order

The small items first: restart warning, assignees, "What's rare?", bash collector, lab evaluation command (about three days together). Then the MCP server's phase 1, then flagging from Eru answers (it uses the server's row citations), then threat intelligence expiry, then containerd, then the MCP server's phase 2 after its review.

## Done 3 November 2026

The day v2.3 was merged (PR #2, merge commit `a9c118b`). Bug numbers are in `tests/docs/BUGS.md`.

| What | Bugs |
|---|---|
| Registry JSON stays valid when a value has quotes in it (Edge's Run key broke whole hives); Eru's fixed persistence answer lists Run keys | E47, E48 |
| A completed job's restart re-processes it (Elrond skipped everything already written); the case browser answers a broken file with 400, not 500 | P16, P15 |
| Eru's model settings reach the backend (`ROWANHOLT_MODEL_NAME` in `.env`); rows cited as lists or ranges come back to flag | P17, P18 |
| Ask Eru with Ollama tested: `llama3.2:3b` works but misreads the case; `qwen3:8b` (about 5 GB) is the smallest worth relying on, at about a minute an answer | |
| The PR #2 review's ten findings: an `eru-mcp` token may ask Eru; tokens can't set passwords or make accounts; one sign-in lockout per account; the Navigator layer check can't be skipped with `//` or `../`; Eru reads every job, not the newest 50, and the job asked for (`job_id`), not the first with its case number; only a job's owner or an admin can delete, archive or wipe it; one finding per row (Alembic `c71d4e9a2b58`); a fresh restart's wipe isn't kept for the next one | P19 |
| Lab: a VM cloned from the same image as another project's shared its MAC, so `tart ip` sent provisioning and collection to that VM; start refuses a clash and clones get their own MAC. A stopped VM is started by its state, not its IP | L30 |

## Done 5 November 2026

| What | Where |
|---|---|
| Linux memory images are identified by their kernel banner, not by a running `sudo`; a folder of memory images alone is accepted; the audit log records the real profile | `memory/memory.py`, `main.py` |
| A Linux image with 5-level page tables (LA57), which Volatility 3 can't walk, is named in the audit log rather than passing as a clean host; a 5-level layer is a feature request in the plugins repo's plan | `memory/memory.py` |
| `linux.zsh` and `linux.containers` tested on an x86_64 Ubuntu VM's memory: all six zsh commands it had read, both Docker containers | |
| The CLI banner says Rowanholt, with a rowan in it; the banner quotes are the books' words, each credited, no film dialogue | `src/cli/rowanholt.py`, Gandalf, `passkey_decrypt.py` |
| Lab VMs are `rowan-lab-*`; `./lab.sh stacking-eval --reuse` scores Elrond over a saved collection; the stacking table names each row's case; `rowanholt elrond process-one` processes one raw file | `lab/`, `src/analysis/process_one.py` |
| The architecture map is drawn on a new parchment map | `scripts/docs/architecture/` |
| Windows live containers: `Invoke-Gandalf -LiveContainers` no longer ends the collection at the first container, and Elrond flags a Windows host's containers from `docker inspect` (Docker Desktop keeps `config.v2.json` in its WSL VM); the lab tests it without Docker Desktop (`./lab.sh windows-vm live-containers`) | `Set-ArtefactCollection`, `containers.py`, `lab/windows/` |
| A team server stood up on a tailnet (Ubuntu in OrbStack on the Mac Mini) and passed its smoke test: exposure, TLS, sign-in, two users, a job on the evidence share, Eru's MCP endpoint, a second device, a restart. It found three bugs, all fixed: the production frontend didn't build (lock file out of step); an Elrond run stopped by an error exited 0, so its job "completed" with an empty case; a `*.ts.net` name got no certificate | `src/web/frontend/package-lock.json`, Elrond's error exits |
| `server init --tls tailscale` serves Tailscale's certificate for a MagicDNS name (refusing `internal` there), and `rowanholt server cert` renews it | `scripts/server/`, [SERVER.md](SERVER.md#certificates) |
| A server's accounts live in the checkout's `users.json`, not the images: rebuilds keep them, `git clean -x` doesn't, so back it up with `.env` and Postgres | [SERVER.md](SERVER.md#limits-worth-knowing) |

## Decisions (Ben, 29 October 2026)

1. **The `mcp` package: yes,** in its own `requirements/mcp.txt`, installed only where the MCP server runs, not in the worker or backend images.
2. **containerd's bbolt database: a stdlib reader** in `process/extractions/`, read-only, no new dependency. The records inside are protobuf and need decoding by hand whichever way the file is read.
3. **Threat intelligence expiry: yes,** as the `threat_intel_validity` side table and an Alembic migration; the ten columns stay as they are.
4. **The MCP server's phase 2: deferred,** then built on 3 November: `flag_lead` and `add_note` behind `--allow-writes`, leads only, recorded as "Eru (for <user>)" (see `docs/ERU.md`). Reviewed the same day, with conditions (`.claude/threat-model.md`).
