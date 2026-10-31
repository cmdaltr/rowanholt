# Roadmap: the v2.3 features

Plans for four of the README's v2.3 items: what already exists, what each one needs, and the order to build them in. Everything else requested is in `docs/FEATURE_REQUESTS.md`.

| Feature | Already there | Size | Order |
|---|---|---|---|
| Container forensics | Built (see below) | Done | 1 |
| Threat intelligence | Built (see below) | Done | 2 |
| Collaborative investigation | Built (see below) | Done | 3 |
| ML-based anomaly detection | Stacking, features and baseline built and measured in the lab; no learned model | Done | 4 |

Container forensics goes first because half of it is written. ML goes last because it needs multi-host cases and the lab's ground truth to measure it against, and an unmeasured anomaly score is worse than none.

## Container forensics (Docker, Kubernetes)

**Built.** The outputs are listed in `docs/CLI.md` (Gandalf's Linux table).

- **Collection.** All three collectors take the same set: `gandalf.sh`, `gandalf.py`, and Elrond's image collection in `collect/linux.py`. It covers:
  - each Docker container's `config.v2.json`, `hostconfig.json` and log;
  - static pod manifests, pod logs and the API server's audit log.
- **The writable layer.** Each container's writable layer is listed with hashes as `gandalf+container_changes.csv`, and the executables and scripts in it are copied (up to 500 per container, 64 MB each) into `container_layer/<id>/`, where Elrond reads them as staged files. That makes the change set the container version of misplaced binaries, without the tens of gigabytes of image layers that `gandalf.py` used to risk.
- **Parsing.** `process/extractions/containers.py` and `k8s_audit.py`, routed from `linux_artefacts.py`.
- **Techniques.** A technique is tagged only where a row justifies it. A container is tagged for what it can reach, not for existing; a Kubernetes component doing its job is never a finding.
- **Exported audit logs.** `python3 -m src.analysis.rivendell.cloud.cli k8s analyze-logs` handles audit logs exported from EKS, AKS or GKE.
- **The lab.** The Linux targets seed a Docker host's and a Kubernetes node's state on disk (`lab/linux-targets/seed/seed-containers.sh`), with the expected results in their `expected.json`. `tests/unit/test_containers.py` runs that seed through collection and processing.

**Still to do.**
- **The bash collector against the seed.** `gandalf.py`'s copy of the container lists ran against the rebuilt targets on 29 October (the containers video section shows its output). `gandalf.sh` collected the seed the same day, layer copy included, and Elrond over its result passed every container row of `verify-expected.py` on both targets (the one miss, `status.php`, needs YARA, which that run didn't use).
- **containerd's own metadata** (`/var/lib/containerd`, a bbolt database) is collected by all three collectors since 29 October, with Podman/CRI-O's `containers.json`, but isn't parsed yet. On a containerd or CRI-O node, the pod logs, static pods and audit log are covered, but per-container settings come only from Docker.
- **Live container capture** (`docker export`, CRIU checkpoints) stays out of scope. It changes the running state, so if it's ever added it must be an explicit opt-in, recorded in the audit log.

## Threat intelligence integration

**Built.** The package is `src/analysis/rivendell/threat_intel/`, inside Elrond's tree, so the worker has it and the backend mounts it.

- **Schema and loader.** The fixed ten columns are a frozen dataclass (`schema.py`). `iran_apt_loader.py` reads the workbook and finds its header row. Postgres holds the indicators in `threat_intel_indicators`, added by Alembic revision `7c41d2e9a0b3`.
- **Intake.** `sources.py` takes a file and recognises its format. It handles:
  - the workbook;
  - Rivendell's CSV;
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
- **Expiry.** Archer expires IPs and domains after 90 days. Here, STIX `valid_until` and confidence aren't kept, because the schema has no column for them. Re-import and delete by source for now.
- **Online lookups** (VirusTotal and the like) stay out. They would be opt-in per case, after the threat model's review of Eru's outbound access.

## Collaborative investigation

**Built.** It works the same on one analyst's machine as on a team server, where access follows job sharing (`auth/access.py`'s job check covers every route, since they're all under `/api/jobs/{id}/case`).

- **Case browser.** **Browse Case** on a completed job opens `/jobs/{id}/case`. It lists each host's cooked artefacts and analysis files, plus the case's own CSVs (`threat_groups.csv`), in paged tables you can filter on any field. It is read-only by construction (`case_files.py`): requests are resolved against `artefacts/cooked/`, `analysis/` and the case root, `raw/` is never reachable, and nothing opens a file for writing.
- **Findings.** ⚑ on any row flags it as a lead or confirms it outright, with a title and an optional technique. The server reads the row itself and stores its file, row reference, SHA-256 and an excerpt. If a re-run or an edited file changes the row, the finding shows "row changed" rather than silently pointing at something else.
- **Notes, assignment and activity.** Notes are Markdown, on the case or on a finding. Each host has an assignee and a status: to do, in progress or done. On a team server the assignee must be an active user (an email is stored as the username); on one machine it's free text. An append-only feed records who flagged, marked, assigned, noted or exported what. The page polls every 15 seconds.
- **Working at the same time.** Findings, notes and activity are separate rows, so simultaneous additions never collide.
  - A second flag on an already-flagged row is refused with the existing finding's number and author; the second analyst adds a note to it instead.
  - A status change carries the `updated_at` it was made against, and the server refuses it (409) if a colleague changed the finding first; the page then reloads it.
  - The worker's image locks keep two jobs off the same evidence. Re-running a case that already has findings rewrites its cooked output, and the affected findings then show "row changed". So a restart of a job with findings is refused (409, with the count) unless the request says `confirm=true`; the bulk restart skips such jobs the same way. The Job page and the Jobs list say how many findings there are and send `confirm` once the analyst agrees.
- **Output.** **Report** is Markdown: case notes first, then confirmed findings by host with their notes. **Navigator layer** holds confirmed findings' techniques only. Elrond's own layer is unchanged.
- **Eru.** The offline question "What have analysts confirmed?" lists confirmed findings, then open leads. With a model, confirmed findings go into its context first.
- **Storage.** Four tables, `case_findings`, `case_notes`, `case_hosts` and `case_activity`, added by Alembic revision `4d8b1f6e2c57`.
- **Tests.** `tests/unit/test_case_browser.py` covers the refusals around `raw/`, paging and filters, the finding lifecycle (including a changed row), notes, assignment (checked against the users on a server), activity, the report, the layer and Eru's answer.

**Still to do.**
- **Flagging from an Eru answer.** A finding needs a row, and Eru's answers are prose. This needs Eru to cite rows first.
- **Live updates.** Polling is enough at this size. Websockets can wait until someone asks.

## ML-based anomaly detection

"ML-based" is easy to oversell. This plan builds the frequency analysis practitioners already trust first, then features, then a model, and measures each step against the lab before it ships.

**Built: Phases 1, 2 and 4.** The code is `src/analysis/rivendell/analysis/stacking.py`, stdlib only. `--Analysis` runs it on any case with two or more hosts; a value is only called rare among three or more hosts of its OS (`MIN_HOSTS`), since on two, "on one of them" is a diff of their builds. A baseline still applies below that. Linux hosts are compared within their distribution family (Debian, RHEL, SUSE, Arch, Alpine), from os-release or the distro's fingerprints, so a lone Rocky host among Ubuntu ones doesn't make its whole distro rare.

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
  - **not in baseline**.

  "Generated name" looks at shape: few vowels, a long consonant run, digits and letters interleaved, or long hex. Entropy alone flagged every long English compound (`backgroundtaskhost.exe`) on the demo case, and a program under `\Windows\` (not `\Windows\Temp\`) isn't called generated, so `mscorsvw.exe` stays quiet. At equal score, persistence (services, tasks, autoruns, WMI, kernel modules) ranks above programs.
- **Baseline.** `python3 -m rivendell.analysis.stacking --baseline OUT CASE...` (from `src/analysis`) writes every value from clean cases. `--stackBaseline OUT` then scores what's absent from it, and with a baseline even a one-OS-host family is scored. It stays a lab-built, local file.
- **Measurement.** `precision_at_k(stacking.csv, seeded values, k)` is the lab's yardstick. `tests/unit/test_stacking.py` seeds an eight-host case (five Windows, three Linux) and requires the seeded values in the top three, plus a mixed-distro case.
- **In the lab, Windows (29 October 2026).** Three Windows 11 hosts, one seeded (`lab/README.md`, clean siblings): all four planted persistence values rare on the seeded host, ranked 1, 2, 6 and 8 of 74 once persistence ranks above programs at equal score. The other rows are what the seeded VM gained from four days' use.
- **In the lab, Linux (29 October 2026).** `./lab.sh linux-targets stacking` adds two clean Ubuntu targets to the seeded `lab-ubuntu` and `lab-rocky`. Over all four as one case, stacking returned four rows, every one planted on `lab-ubuntu` (`lab-sync.service`, `lab-agent.service` system and user, the `lab updater` autostart): precision@3 of 1.0, no noise. Before Linux hosts were grouped by distro, the same case gave twenty rows, all Rocky's own units.
- **On real data.** Across the two Windows images in `claude_testing`, the two hosts differ in almost everything, which shows how little two hosts give. The list still surfaced `bcwipe service` on the nfury Windows 7 image, a disk wiper.

**Still to do.**
- **Evaluate in the lab per release.** The Linux and Windows runs above are the method. Signed or unsigned, and time of day against the host's logons, aren't features yet, because the cooked artefacts don't carry signatures and logon patterns need a per-host model of their own.
- **No learned model (Ben, 29 October 2026).** An isolation forest was considered and dropped, with `scikit-learn`, because stacking found every plant in the lab. The note below is kept for the record.
- **The isolation forest, as considered.** It would score how unusual each host's values are, not only how many hosts have them, catching what counting can't, such as a process every host runs but with an odd parent or command line on one. Against: `scikit-learn` (with numpy and scipy, about 30–40 MB) in the worker image, which the dependency rule needs agreed, and a score that's harder to explain than stacking's named reasons. Stacking found every plant with no noise on the lab case, so there was nothing for a forest to improve on.
- **Eru's "What's rare in this case?"** (built 30 October). An offline question over `stacking.csv`: persistence rows first, then programs and process pairs, each with its hosts and reasons, and the reminder that a row is a lead, not a verdict.

## Plan for what's left (29 October 2026)

Each feature's "Still to do" above, as work to schedule, then the Eru MCP server. Sizes are for one person with the lab to hand. Nothing here is started; the decisions at the end are made.

### Container forensics

1. **The bash collector against the seed** (done 29 October). `./lab.sh linux-targets reset`, `./lab.sh gandalf-collect bash`, Elrond over the result, then `lab/verify-expected.py` against each target's `expected.json`. Done when `docker_containers.csv`, `container_changes.csv`, `static_pods.csv` and `k8s_audit.csv` match for `gandalf.sh` as they already do for `gandalf.py`.
2. **containerd's metadata** (two to three days). On a containerd or CRI-O node, per-container settings (image, mounts, privileges, namespaces) live in `/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db`, a bbolt database.
   - Collect `meta.db` in all three collectors, read-only, beside the Docker files. Done 29 October.
   - Parse it into the existing `docker_containers.csv` columns, adding a `Runtime` column (`docker`, `containerd`) so one table covers both; the technique rules then apply unchanged.
   - Seed a containerd-only node in the lab (`ctr` with a privileged container) with its rows in `expected.json`, and a unit test from that seed.
   - Read bbolt with a stdlib reader in `process/extractions/` (decision 2). The container records inside are protobuf, decoded by hand either way, so the `bbolt` CLI would only save the page walking.
3. **Live capture** stays out of scope, as recorded above. No work planned.

### Threat intelligence

1. **Expiry and confidence** (a day). The ten-column schema stays as it is. A side table, `threat_intel_validity` (indicator id, `valid_until`, `confidence`, `first_seen`), added by an Alembic migration:
   - STIX imports fill it from `valid_until` and `confidence`; other sources get a default lifetime per kind (90 days for IPs and domains, as Archer does; none for hashes and tool names).
   - Matching skips expired indicators and says how many it skipped; Pippin shows the expiry and lets an admin extend or clear it.
   - Tests: an expired STIX indicator doesn't match; a refreshed import revives it.
   - Agreed (decision 3).
2. **Online lookups** stay out until the threat model's review of Eru's outbound access. If that review approves them, the shape is: one provider interface, keys only in `.env`, off by default and switched on per case, every lookup in the case's audit log, and nothing sent from `raw/`.

### Collaborative investigation

1. **Restart with findings** (done 30 October). `POST /api/jobs/{id}/restart` answers 409 with the number of findings when there are any, unless the request says `confirm`; the bulk restart skips them likewise; the Job page shows the count and asks before restarting. Test: `test_restart_with_findings_needs_confirm` in `test_server_access.py`.
2. **Assignees checked on a team server** (done 30 October). In server mode, `PUT /hosts/{host}` refuses an assignee who isn't an active user; on one machine it stays free text. Test: `test_assignees_checked_on_a_team_server` in `test_case_browser.py`.
3. **Flagging from an Eru answer** (two days, after the MCP server's row citations). Eru's offline answers are built from specific rows, so they return those rows with the text: file, row number and SHA-256, the same reference a finding stores. The Eru page shows ⚑ beside each cited line, which opens the usual finding form on that row. With a model, the context Eru sends is numbered by row and the model is asked to cite the numbers; only cited, existing rows can be flagged, so a model can't invent a finding.
4. **Live updates** stay as polling until someone asks.

### Stacking (anomaly detection)

1. **Eru's "What's rare in this case?"** (done 30 October). An offline question over `stacking.csv`: the top rows, persistence first, each with its hosts and reasons, and the reminder that a row is a lead, not a verdict. Tests in `test_eru_offline.py`, one keeping its persistence families equal to `stacking.PERSISTENCE`.
2. **One command for the lab evaluation** (built 30 October, not yet run end to end). `./lab.sh stacking-eval` builds the stacking targets, collects them into a folder of its own, runs Elrond in the worker and prints precision at 4, 8 and 20 against the plants (the `stacking` values in each target's `expected.json`), appending the result to a table in `lab/README.md`. The scorer, `lab/lib/stacking_eval.py`, is tested in `test_stacking_eval.py`. Linux every release; Windows when its clean VMs are rebuilt (about two hours), at least once per major release.

### The Eru MCP server

**Phase 1 built (31 October 2026):** `src/eru_mcp/server.py`, `rivendell mcp`, `requirements/mcp.txt`, documented in `docs/ERU.md`. mcp 2 renamed FastMCP to `MCPServer`, which it uses. Stdio only: the streamable HTTP option behind Caddy isn't built, because on a team server it would have to take each analyst's token from their request rather than the environment. The lab run on THREATINTEL-DEMO-01 is still to do; a smoke run over stdio against the local stack listed its cases and answered an offline question.

**What it is.** One MCP server, built with FastMCP (mcp 2's `MCPServer`), through which an MCP host (Claude Desktop, Claude Code, OpenClaw) works a Rivendell case. It registers every Eru capability; nothing else registers tools.

**How it's built.** A thin client of Rivendell's own API, not a second way into the case files.
- On a team server, every call carries the analyst's token, so job sharing (`auth/access.py`) decides what the server can see, exactly as for the web app.
- The case browser's guarantees carry over: read-only over `cooked/`, `analysis/` and the case root, and `raw/` never reachable.
- It calls nothing but the Rivendell API, so it adds no outbound access.
- It runs over stdio on the analyst's machine (`src/eru_mcp/server.py`, `rivendell mcp` to start it), and optionally over streamable HTTP behind Caddy on a team server.

The March 2026 prototype ("Building an MCP") kept its own case folders, ran its own acquisition and could call Anthropic's API. None of that carries over: cases are Rivendell jobs, acquisition is Gandalf's, and Eru's model is Ollama. Archer keeps its own server.

**Phase 1: reading a case** (two days; built).

| Tool | Calls |
|---|---|
| `list_cases` | `GET /api/jobs` |
| `case_overview(job_id)` | the job, its hosts and their files (`GET /api/jobs/{id}`, `GET /api/jobs/{id}/case`) |
| `read_rows(job_id, host, file, filter, offset, limit)` | `GET /api/jobs/{id}/case/rows`, with each row's reference for citing |
| `ask_offline(job_id, question)` | `POST /api/ai/offline/answer`: the twelve fixed case questions, "What's rare?" among them |
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

## Decisions (Ben, 29 October 2026)

1. **The `mcp` package: yes,** in its own `requirements/mcp.txt`, installed only where the MCP server runs, not in the worker or backend images.
2. **containerd's bbolt database: a stdlib reader** in `process/extractions/`, read-only, no new dependency. The records inside are protobuf and need decoding by hand whichever way the file is read.
3. **Threat intelligence expiry: yes,** as the `threat_intel_validity` side table and an Alembic migration; the ten columns stay as they are.
4. **The MCP server's phase 2: deferred.** Phase 1 ships read-only; flagging leads and adding notes are decided once phase 1 has been used.
