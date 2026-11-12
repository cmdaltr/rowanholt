# Plan: one output format (JSON Lines)

Status: **approved, 6 November 2026** (decisions at the end); built on `feat/jsonl-output` (what changed from the plan while building it is in "As built", before the decisions).

Elrond's output today is two formats chosen by whichever parser wrote the file: about 30 writers produce JSON (Artemis, registry, browsers, plists, journalctl, Linux logs and services, mail, clipboard, USB) and about 70 file names are CSV (the native parsers in `process/windows_artefacts.py`, `linux_artefacts.py`, `mac_artefacts.py`, `extra_artefacts.py`, plus bash and zsh history, `group` and UAL). No artefact gets both, and nothing converts between them. Readers cope unevenly: the case browser reads both, stacking mostly JSON, Smith's context search CSV only, so Smith never sees Artemis, registry, event log, browser or journal output.

The goal: every record Rowanholt writes, in `cooked/`, `analysis/` and the case-level tables, is a JSON Lines file (`.jsonl`, one object per line) with the same envelope fields, so every reader treats every artefact the same way.

## Why JSON Lines

- **Nested records survive.** Artemis's event logs (`data.Event.System…`), tasks and plists are nested. CSV would flatten them or pack JSON into a cell.
- **Real escaping and types.** No more commas, quotes and newlines in command lines shifting columns. The Plaso timeline already has this bug (below), and the string-built JSON writers produce invalid JSON on awkward input.
- **One record per line, not one array.** An MFT or event log export can be millions of records. JSONL streams, appends, survives a broken line, works with `grep` and `jq`, and Splunk and Elastic take it as it is (Elastic's step converts everything to NDJSON today, which is the same thing).
- **Row references stay line numbers**, as CSV's are today, so the case browser, saved findings and Smith's citations keep working the same way.

## The record

Each line is one flat JSON object: five envelope fields first, then the artefact's own fields under their current names.

```json
{"host": "LAB-WIN11", "artefact": "startup_items", "source_path": "raw/registry/NTUSER.DAT", "timestamp": "2026-10-29T14:03:11Z", "techniques": ["T1547.001"], "Item": "Updater", "Command": "C:\\Users\\Public\\upd.exe", "Flag": "suspicious"}
```

| Field | Meaning |
|---|---|
| `host` | The host the record came from (`img.split("::")[0]`, as the cooked path already uses) |
| `artefact` | The artefact's name, the same as the file name without `.jsonl` (`startup_items`, `evt/Security`, `registry/SYSTEM`) |
| `source_path` | The collected file it was parsed from, relative to the host's folder |
| `timestamp` | The record's main time as ISO 8601 UTC (`…Z`), or `null` when the artefact has no time. The original time fields stay as they are beside it |
| `techniques` | ATT&CK IDs for this record, a list (empty when none). `mitre_techniques.txt` is still written as now |

Flat rather than nesting the artefact's fields under a key, because Splunk's transforms, the shipped Splunk dashboards and Kibana's saved objects all search on top-level field names (`Command`, `Filename`, `artefact`, `host`), and the case browser shows columns. An artefact field that clashes with an envelope name is renamed with an `orig_` prefix (only Artemis's `timestamp` does today, and it means the same thing, so it fills the envelope instead).

`timestamp` comes from one declared time field per artefact (`HEADERS` gains a time field alongside each schema): `LastWriteTime` for most, `Created`, `RecordTime`, `PageModified`, `Start` and so on for the rest, Artemis's own `timestamp`. About 20 artefacts have no time at all (startup items, sudoers, hosts, notepad tabs, PAM and others) and get `null`.

`techniques` is the route's list applied to each row, or the row's own where the parser already works them out per row (BTM items, containers, the `Technique` and `Techniques` columns some schemas carry).

## What becomes JSONL, and what doesn't

| Output | Now | After |
|---|---|---|
| `cooked/**` (every artefact) | CSV or JSON array | `.jsonl` |
| `analysis/` (`analysis`, `iocs`, `yara`, `keyword_matches`, `threat_intel_matches`, masquerading, misplaced) | CSV | `.jsonl` |
| Case-level `stacking`, `threat_groups`, `<host>/gandalf_integrity` | CSV | `.jsonl` |
| `artefacts/plaso_timeline` | CSV via a regex | `.jsonl` from psteal's own `json_line` output |
| `artefacts/LastAccessTimes` | CSV | `.jsonl` |
| Volatility `memory_<plugin>` | JSON | `.jsonl` (from Volatility 3's `-r json`, which the parsers already read) |
| `raw/` | as collected | **unchanged** (chain of custody) |
| `mitre_techniques.txt` | a list of IDs | unchanged: not records |
| Navigator layer, Splunk and Kibana content | their own formats | unchanged formats, updated searches |
| Stacking baseline you supply | CSV | stays CSV: it's your input, not Rowanholt's output |
| Gandalf's `raw/linux/gandalf+*.csv` | CSV | unchanged: collector output in `raw/` |

## Existing cases

Cases already processed stay as they are and stay readable: every reader keeps its CSV and JSON branch alongside JSONL. No conversion of old cases, because saved findings are tied to a file and row (`row_ref` + `row_hash`), and rewriting the files would break every one of them. Re-processing an old case produces JSONL, and that case's old findings then show as "not intact", as they would today if a re-run changed a row. If old cases should be converted later, that's a separate `rowanholt migrate` command with findings moved across; not in this plan.

## The work, in order

Built on a branch in its own worktree (no schema change, no new dependency: everything is stdlib). Readers go first so nothing breaks when the writers switch.

### 0. Baseline
Finish the Windows stacking eval and `verify-expected` (`rowanholt-accuracy.sh --from 5`) on the current formats, so the lab results after this change have something to be compared with.

### 1. One reader and one writer
A stdlib module, `src/analysis/rowanholt/core/records.py`, loaded by the backend the way `threat_intel_store.py` loads the threat intelligence package:

- `write_records(path, rows, *, host, artefact, source_path, time_field, techniques)`: appends JSONL lines with the envelope, normalising the timestamp; returns the count.
- `read_records(path)`: yields `(ref, record)` for `.jsonl` (ref = line number, streamed, no size cap), `.json` (array or object, ref `#n`, as now) and `.csv` (ref = line number, as now).

It replaces the two copies of `_append_rows` (`windows_artefacts.py:49`, `linux_artefacts.py:118`) and the five separate readers: `case_files.records()`, stacking's `_json_records`/`_csv_rows`, threat intelligence's `_records()`, `smith_offline`'s `_rows`/`_json_records`, Artemis's `_records()`.

### 2. Readers accept JSONL

| Reader | Change |
|---|---|
| Case browser (`case_files.py`) | `.jsonl` in `ROW_FILES` and the case-level glob; `read_records`; envelope fields shown as columns |
| Smith context (`smith_context.py:86`) | search `*.jsonl` as well as `*.csv`: this is the fix that lets Smith see Windows evidence |
| Smith fixed answers (`smith_offline.py`) | about 30 named files: each looked up as `.jsonl`, then the old name; `stacking`'s `Sources` becomes a real list |
| Smith MCP (`smith_mcp/server.py:303`) | `rare_across_hosts` reads `stacking.jsonl`, then `stacking.csv` |
| `ai_routes.py:323`, `tasks.py:189`, `:263` | count `.jsonl`; fix `ai_routes`' path (it misses `artefacts/`) |
| Stacking (`analysis/stacking.py:304`) | sources matched by artefact name, any of the three formats |
| `analysis/analysis.py:451` | its sniff for Artemis's UUID-named MFT files would open every `.jsonl`; match on the envelope's `artefact` instead |
| Threat intelligence matching (`threat_intel/match.py`) | `.jsonl` in its walk; envelope fields not flattened into the match text; `_fill_watchlist` rewritten for JSONL |
| `process_one.py:41` | a `.jsonl` preview |
| Smith CLI indexer (`ai/indexer.py`) | reads paths that no longer exist (`processed/*.csv`); point it at the real files with `read_records`, or remove it (your call) |

### 3. Writers produce JSONL

- **The four routers** (`windows_artefacts`, `linux_artefacts`, `mac_artefacts`, `extra_artefacts`): `write_records` with `host`, `source_path` and the time field. They already have all three. `mac_artefacts`' `_append_table` (SQLite dumps with no fixed schema) just writes the dicts.
- **Artemis** (`extractions/artemis.py:892-952`): the merge step already reads every output file; it writes JSONL with the envelope instead of re-dumping arrays. `enrich_with_mitre` reads event logs line by line (`:367`).
- **Registry, plists, browsers, WMI fallback**: already dicts; switch `json.dump(list)` to `write_records`. Registry's append-mode array (`[...][...]` on a second write, guarded only by an existence check) goes away.
- **String-built JSON** (journalctl `linux.py:122`, USB `usb.py:80`, clipboard `clipboard.py:894`, mail `nix.py:450`, logs `:878`, services `:976`): rebuilt as dicts. These are the riskiest rewrites and also fix invalid JSON on awkward input, so each gets a test with quotes, backslashes and newlines in the values.
- **Hand-rolled CSV**: bash and zsh history (`nix.py:144`, `:225`), `group` (`:480`), UAL (`windows.py:579`, where KStrike's commas are currently stripped), `LastAccessTimes` (`process.py:418`).
- **Analysis writers**: `analysis.py` (`analysis.csv`, `iocs.csv`), `iocs.py:257`, YARA, ClamAV, keywords, masquerading, misplaced, threat intelligence's `threat_intel_matches` and `threat_groups`, stacking's output and Gandalf's integrity table.
- **Plaso** (`process/timeline.py`): psteal with `-o json_line`, each line decoded with `json.loads`, the envelope added. This replaces the regex.
- **Volatility** (`memory/extract.py:76`): `-r jsonl`.

### 4. SIEMs and post-processing

- **Splunk** (`post/splunk/ingest.py`, `config.py`, `app/`): one sourcetype, `rowanholt_jsonl` (`INDEXED_EXTRACTIONS=json`, `TIMESTAMP_FIELDS=timestamp`, ISO format), one recursive monitor per host for `cooked/` and `analysis/`, with Splunk's `host` set from the record. Today most of the ~70 cooked CSVs are never indexed at all, because the monitors name files one by one. The shipped dashboards and macros (`source=*iocs.csv`, `*analysis.csv`, `*usb.log.json`, …) search by `artefact=` instead. Transforms keyed on top-level column names keep working because the fields stay flat.
- **Elastic** (`post/elastic/ingest.py`): the four CSV/JSON-to-NDJSON converters go; each JSONL line is bulk-posted with `@timestamp` from `timestamp` and the technique fields Kibana's dashboards use (`mitre_technique_id`, …) filled from `techniques`. The remote path's globs gain `.jsonl`.
- **ATT&CK enrichment** (`post/mitre/enrichment.py:420`, `:621`, `:667`): streams and rewrites JSONL line by line (its `indent=2` dump would break JSONL), and reads `techniques`.
- **Clean-up** (`post/clean.py:179`): deletes files with no records, not files of 100 bytes or less, which would delete a one-record JSONL file.

### 5. Lab, tests and docs

- **Lab**: `verify-expected.py` reads `.jsonl` and matches against decoded values (JSON escaping of `\` would otherwise break substring matches on Windows paths); the Linux seed's 19 `"cooked": "<name>.csv"` entries are renamed; `stacking_eval.py` reads `stacking.jsonl`. Not touched while a lab run is going.
- **A format check**: a test, and a step in `verify-expected`, that every `.jsonl` file in a case parses line by line and every record has the five envelope fields. That's the "consistent" part held in place.
- **Tests**: about 30 test files build or assert on cooked CSV/JSON (the largest: `test_smith_offline` 33, `test_linux_artefacts` 21, `test_smith_mcp` 21, `test_stacking` 20, `test_containers` 18, `test_case_browser` 17, `test_threat_intel` 15); updated with the code they test, plus tests that old-format cases still read.
- **Docs and help text**: `docs/CLI.md` (output structure), `USAGE.md`, `README.md`, `QUICKSTART.md`, `SMITH.md` and the rest that name CSVs; `elrond.py`'s help; the About page (`HelpPage.js`), the guide and the architecture pages.

### 6. Bugs fixed on the way

| Bug | Where | Fix |
|---|---|---|
| Pagefile strings are never written: `">>"` is passed to `strings` as an argument, with no shell | `process/windows.py:809` | write `strings`' stdout to the file; guard on each pagefile's own output, not the `memory/` folder (only the first pagefile per host is processed today) |
| The shimcache guard never fires: it looks for `ShimCache.csv`, but Artemis writes `shimcache.json`, so shimcache re-runs for every `.SYSTEM` | `process/process.py:116` | check the file Artemis writes; Splunk's `shimcache.csv` stanza goes with step 4 |
| Plaso rows shift when a message contains a comma (regex parsing) | `process/timeline.py` | psteal's `json_line` output |
| Elastic's local ingest drops the host from the path (`os.path.join(…, "/artefacts/cooked/")`) | `post/elastic/ingest.py:457`, `:461` | fixed with step 4 |
| Linux Splunk monitors use a sourcetype, `json_noTime`, that props.conf never defines | `post/splunk/ingest.py:116` | gone with the single sourcetype |

## How it's checked

1. Unit tests after each step: the whole suite, as now (`tests/unit`).
2. The Linux and Windows stacking evals and `verify-expected` on the branch, compared with step 0's baseline: the same planted items found, the same stacking ranks, every file passing the format check. A difference is a bug in this change, not a finding.
3. One case each from Splunk and Elastic: every artefact indexed, with its time.
4. Smith asked about something only in Windows JSON (a service, a scheduled task, an event) to show the context search now finds it.

## As built

- **The writers share one function**, `write_records` in `rowanholt/core/records.py` (`write_cooked` for a table under `cooked/`, which takes the host and name from the path). A writer names its time field, or candidates tried in order (Artemis's `timestamp`, `last_run_time`, `modified` and so on); a row's own `timestamp` is used when it parses and kept as `orig_timestamp` when it doesn't.
- **Techniques per record.** A router's techniques go on every row of the route, or only on the flagged rows when the schema has a `Flag` column, plus the row's own `Technique` or `Techniques`. Artemis's event logs are tagged per record; tasks, services and WMI persistence only where the item isn't Windows's own. Bash and zsh lines tag **T1059.004** only when suspicious, systemd units **T1543.002** only when unusual. MITRE enrichment (`post/mitre/enrichment.py`) adds what it matches to `techniques` as well as the `mitre_*` fields.
- **Case-level tables** (`stacking`, `threat_groups`) have `host` `""`: their rows are about several hosts, named in their own fields.
- **Not records, so not JSON Lines:** the paging files' `.strings` dumps (text, fed to the paged-strings table), `mitre_techniques.txt`, `rowanholt_audit.log`, and the stacking baseline you supply (CSV, your input).
- **Volatility** keeps `-r json`: the three parsers in `memory/volatility3/plugins/` already read it, and the subprocess call is unchanged. The output name is `memory_<plugin>.jsonl` in the host's folder, which the existing guard, enrichment and SIEM readers already expected (the writer used to write `<plugin>.json`, so the guard never matched).
- **Times are UTC.** Chrome's history query converted to local time and Firefox and Safari used naive local times; all three are UTC now. Times a source records without a zone (setupapi's, the analysis rows' own) are recorded as written and marked UTC: check them against the host's time zone.
- **Splunk** uses one sourcetype, `rowanholt_jsonl`; a record with a null `timestamp` gets the index time and `time_source=indexed` so a timeline can leave it out. **Elastic** sets no `@timestamp` on such a record, so it's missing from Kibana's time-filtered views.
- **The lab** reads either format (`lab/verify-expected.py`, `lab/lib/stacking_eval.py`) and checks every `.jsonl` for the envelope (the "JSON Lines format" row).

## Decisions (Ben, 6 November 2026)

1. **Envelope names** as above: `host`, `artefact`, `source_path`, `timestamp`, `techniques`. `source_path` with an underscore: a hyphen would read as subtraction in SPL and need quoting in Kibana.
2. **Old cases** are left as they are and read in their old format.
3. **The dead extractors are removed**, in their own commit first: 13 modules in `process/extractions/` (`mft.py`, `usn.py`, `shimcache.py`, `wbem.py`, `sru.py`, `wmi_full.py`, `linux_enhanced.py`, `macos_enhanced.py`, `wmi.py`, `evtx.py`, `artifact_models.py`, `plist.py`, the empty `macos/`) that nothing imports since Artemis replaced them.
4. **The Smith CLI indexer** (`ai/indexer.py`) is fixed: pointed at the real files through `read_records`.
5. **Download as CSV**: the case browser gets a button that downloads the artefact being viewed as CSV (nested values as JSON text in their cell), for Excel and Timeline Explorer. Built with step 5.

## Decisions while building (Ben, 7 November 2026)

6. **Enrichment adds to `techniques`**: what `post/mitre/enrichment.py` matches goes into the record's `techniques` as well as its `mitre_*` fields, so `techniques` agrees with `mitre_techniques.txt`.
7. **A JSON Lines table isn't lifted** out of a one-file `cooked/` subdirectory by `post/clean.py`: its records name it by its path there. Old CSV and JSON files still are.
8. **`stacking` and `threat_groups` stay out of Splunk and Elastic** for now: they'd need a case-level monitor and the host taken from each record.
