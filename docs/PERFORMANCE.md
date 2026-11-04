# Processing Time by Option

How long each Elrond option takes, measured from the E2E test matrix. Use it to size a job before you start it: the right option set on a 12 GB E01 takes 15 minutes, the wrong one takes 10 hours.

Numbers come from `rowanholt_audit.log` in each test's output directory. Each audit entry is written when a piece of work finishes, so a stage is charged the time since the previous entry and stage times add up to the job's total. Regenerate the tables with:

```bash
python tests/scripts/test_timings.py --output-root <test output dir> \
    --markdown timings.md --csv timings.csv --json timings.json
```

## Test Environment

All figures below were measured on this setup. Absolute times will differ on other hardware; the ratios between options hold better.

| Component | Value |
|---|---|
| Host | Apple M2 Pro, 10 cores, 16 GB RAM |
| Docker | Docker Desktop, ~16 GB / 10 CPU allocated, SIEM profile up |
| Worker | `ubuntu:22.04`, native arm64 (Splunk runs amd64 under Rosetta) |
| Evidence storage | USB external drive (APFS), passed into the worker via VirtioFS |
| Celery concurrency | 1 (higher values let jobs unmount each other's shared mount points) |
| `carve.py` sleep | 0.5 s per carved file up to `linux_collect_files_all`, 0.1 s from 20 Oct (see Carving) |
| `$I30` walk | Walked the whole evidence directory until 22 Oct; Windows runs before then include it (see What Affects the Time) |

| Image | Format | Size | Contents |
|---|---|---|---|
| `win7-64-nfury-c-drive.E01` | E01 (compressed) | 12.03 GB | Windows 7 x64 system drive |
| `win7-64-nfury-memory-raw.001` | raw | 2.15 GB | Windows 7 x64 memory |
| `Linux_mail.vmdk.raw` | raw | 21.47 GB | Linux mail server, ext4 |
| `5.8.0-44-generic.mem` | raw | 4.29 GB | Linux memory (kernel 5.8.0-44) |

## Windows Disk (12.03 GB E01)

A plain run takes 15–18 minutes, and processing alone accounts for 14–16 minutes of it (registry, event logs, MFT and browser artefacts, 241 audit entries). Most options sit on top of that baseline.

| Option(s) | Total (min) | Added over baseline | Where the time goes |
|---|---|---|---|
| none / `archive` / `collect_files_<type>` | 15.6–17.8 | — | processing 13.9–15.4 min |
| `archive` | 15.6 | +0.9 | zipping output |
| `collect_files_<type>` (one type) | 16.0–17.8 | +0.2–1.8 | scales with matched files: 1 (mail) to 4,763 (scripts) |
| `verbose` | 18.0 | +~2 | collecting 3.6 min |
| `userprofiles` | 17.9 | +~1.5 | larger profile copies in processing |
| `analysis` + `splunk`, `elastic`, `navigator` | 25.9 | +~10 | analysing 9.4 min, SIEM indexing 2.1 min |
| `brisk` | 32.2 | +~16 | also runs analysis (11.2 min); not faster than a basic run |
| `analysis` + `extract_iocs` | 58.9 | +~43 | analysing 43.1 min (10,919 IOCs) |
| `analysis` + `memory` (with 2.15 GB memory image) | 33.1 | +~17 | Volatility 6.0 min, analysing 10.3 min |
| `collect_files_all` | 81.2 | +~65 | collected 31.8 min (9,379 files), processing 37.9 min, carving 6.5 min (39 files, see Carving) |
| `timeline` (Plaso) | ~150 (223 measured) | +~135 | Plaso 105 min (1.4 GB CSV), processing 43 min; measured run also included a 73 min $I30 walk (see What Affects the Time) |
| `yara_dir` | 44.4 | +~28 | YARA scanning inside processing (41.4 min) |
| Threat Hunt via CLI, SIEM up | 50.2 | +~35 | SIEM indexing 27.4 min |

SIEM indexing varied from 2 to 27 minutes for the same image. The longer figure came from the CLI Threat Hunt run, where indexing waited on Splunk. A cold or restarting Splunk adds most of that time.

## Volume Shadow Copies (`vss`)

`vss` repeats collection, processing and analysis for every shadow copy, one after another. `win7-64-nfury-c-drive.E01` has 7. `win_full` (`analysis`, `extract_iocs`, `vss`, `userprofiles`, SIEM) ran for 36.7 hours on 22–24 Oct 2026 and never finished:

| Volume | Collecting (min) | Processing (min) | Analysing (min) |
|---|---|---|---|
| Live volume | 61 | 75 | 238 |
| Shadow copy #1 | 4 | 67 | 182 |
| Shadow copy #2 | 5 | 91 | 134+ (stopped) |
| Shadow copy #3 | 7 | 144 | — |
| Shadow copy #4 | 7 | 160 | — |
| Shadow copy #5 | 15 | 282 | — |
| Shadow copy #6 | 12 | 314 | — |
| Shadow copy #7 | 35 | 405 | — |
| **Total** | **93** (+32 silent cleanup) | **1,539** (25.7 h) | **554+** |

The job failed in analysis of shadow copy #2. Postgres stalled at 02:23 UTC on 24 Oct with an 87-second checkpoint sync, because the `jobs` table had grown to 126 GB. The Celery task lost its database connection, marked the job FAILED and stopped reading Elrond's stdout. Elrond blocked on the full pipe from 02:13 UTC until it was killed 12 hours later. See "Job log writes" below.

Each copy has roughly the same artefacts (213–232 processing entries), yet processing grew from 67 to 405 minutes. Event logs are most of each copy's time, and `extract_with_artemis()` (`process/extractions/artemis.py`) re-runs MITRE ATT&CK enrichment over every JSON in the copy's `cooked` folder after each Artemis call. With 60–80 event-log JSONs of 230–380 MB per copy, that is quadratic in the number of logs and re-reads gigabytes over USB per copy. It also appends to `mitre_techniques.txt` without de-duplicating: 77,585 lines, 25 unique techniques. Elrond stayed at 5–7% CPU throughout, so the job was I/O-bound. The growth beyond what the quadratic re-read explains is unmeasured; slower reads through `vshadowmount` for older snapshots are one possibility.

Analysis runs once per volume (`core/core.py`), and on each pass IOC extraction walks the mount and the whole `artefacts/` tree, so every pass rescans every copy's raw and cooked artefacts and appends duplicates to one shared `iocs.csv`. Copy #2's IOC pass was reading files under `raw/vss5/` when it stopped. The magic-byte check reads each file whole (up to 10 MB) to compare a few header bytes: 52 minutes on the live volume against 10 minutes in a live-only run.

Collection ended with a 32-minute silent step: `collect.py` removes empty directories with three `os.walk` passes over the output (7,699 directories and 24,480 files across the 7 copies).

At these rates the remaining analysis passes would have taken another 15–20 hours. Count the shadow copies (`vshadowinfo`) before enabling `vss`, and don't combine it with `extract_iocs` until the issues above are fixed.

## Windows Memory (2.15 GB raw)

| Option(s) | Total (min) | Where the time goes |
|---|---|---|
| `memory` | 6.0 | 27 Volatility 3 plugins, 5.8 min |
| `memory` + `memory_timeline` | 8.6 | timeliner adds 2.6 min |

## Linux Disk (21.47 GB raw)

The Linux image is nearly twice the size of the Windows E01 yet processes in about 3 minutes, unless IOC extraction is on. Image size isn't what drives the time: Linux has far fewer structured artefacts to parse, and the raw format avoids the E01 decompression overhead.

| Option(s) | Total (min) | Added over baseline | Where the time goes |
|---|---|---|---|
| none / `debug` / `archive` | 2.7–3.0 | — | processing 2.5 min |
| `collect_files_<type>` (one type) | 2.9–3.1 | +0.2–0.5 | 65–267 matched files |
| `analysis` | 3.5 | +0.8 | analysing 0.8 min |
| `splunk`, `elastic`, `navigator` | 6.0 | +3 | analysing 1.5 min, indexing about 1 min with Splunk warm |
| `analysis` + `extract_iocs` | 73.7 | +71 | analysing 71.0 min (74,710 IOCs) |
| `analysis`, `extract_iocs`, `userprofiles`, SIEM (`linux_full`) | 182 | +179 | analysing 163 min (86,918 IOCs), SIEM indexing 11 min |
| `hash_collected` | 186 | +183 | hashing 183,989 files at about 17 files/s |
| `collect_files_unalloc` (0.1 s sleep) | 253.5 | +4.2 h | carving 182 min (foremost 36 min, logging 146 min), analysis and result stats ~58 min, processing 13 min |
| `collect_files_all` (0.5 s sleep) | 823 | +13.7 h | carving 701 min, analysis ~32 min, result stats ~33 min, script obfuscation scan 27 min (14,641 checks), collected 15 min (5,680 files), processing 13 min |

## Windows + Linux Together

`multi_win_linux` (both disk images, `analysis`) took 138 minutes, of which 67 were the $I30 walk, so about 72 minutes of real work: Windows processing and analysis dominate, the Linux image adds a few minutes.

## Carving (`collect_files_all`, `collect_files_unalloc`)

Carving is by far the most expensive option. It runs foremost over the whole image and then logs each carved file. That loop slept 0.5 s per file at the time of these runs (`src/analysis/rowanholt/collect/files/carve.py`), so the total is roughly:

```
carving time ≈ foremost time + carved files × sleep
```

On `Linux_mail.vmdk.raw` foremost took 59 minutes (about 6 MB/s, CPU-bound) and carved 76,237 files. At 0.5 s per file the logging loop alone adds 10.6 hours. At 0.1 s it measured 2.4 hours (about 8.7 files/s, so the audit-log write costs roughly 15 ms per file on top of the sleep), and foremost took 36 minutes on the second pass. `collect_files_all` always includes carving (file selection `A`), so it costs as much as `collect_files_unalloc` plus every other file type.

On the Windows E01 carving took only 6.5 minutes and produced 39 files. `carve.py` passes the evidence path straight to foremost, and foremost's `audit.txt` confirms it scanned the 12,034,347,442-byte EWF container, not the decompressed disk. Only files sitting in uncompressed chunks are found, so Windows E01 carving figures measure a bug, not carving.

Carving also slows the end of the job. Once Elrond exits, the Celery task counts and sizes every output file (`src/web/backend/tasks_docker.py`, `rglob` then `stat`). With 87,382 files reached over VirtioFS that took about 33 minutes. Nothing is logged during this step, so the job looks stalled.

## What Affects the Time

These parameters changed results noticeably during testing, roughly in order of impact:

1. **Carved file count.** Multiply it by the per-file sleep in `carve.py`. It depends on unallocated space and file content, not image size.
2. **Keyword list contents.** Keyword search cost is keywords × lines in every collected file. One blank line in the list matched every line and turned a 45-minute test into 14.6 hours, so strip blank and `#` lines.
3. **YARA rule set size.** One rule directory added about 28 minutes on the Windows E01.
4. **OS and artefact richness.** Windows processing costs about 5× Linux for an image half the size.
5. **Evidence format.** E01 needs decompressing through ewfmount; raw images are read directly.
6. **SIEM state.** A warm Splunk/Elastic indexes a Windows case in about 2 minutes; a cold or restarting Splunk can take 25 or more.
7. **Analysis and IOC extraction.** `analysis` adds about 10 minutes on Windows and under a minute on Linux. `extract_iocs` scales with the number of IOCs found, not image size: about 43 minutes for 10,919 IOCs on the Windows E01 and 71 minutes for 74,710 on the Linux image, where package lists and the public suffix list produce thousands of domain hits.
8. **Celery redelivery.** With Redis's default 1-hour visibility timeout, a job queued behind one that runs over an hour is delivered again and runs more than once. Set `visibility_timeout` above the longest job (now 24 h in `tasks_docker.py`).
9. **Host resources.** Splunk under Rosetta, Elastic, Kibana and an active job together can exhaust 16 GB, which stalls the API and restarts containers. Run one job at a time.
10. **Output stored under the image folder.** `$I30` extraction walked the whole evidence directory, so every case output saved beside the images added to each Windows job: 11, 21, 45 and 73 minutes as the test output grew. Fixed in `collect/files/i30.py`; until then keep output outside the image folder.
11. **Storage path.** Evidence on USB via VirtioFS is slower than local NVMe. It hasn't been measured separately for processing, but walking a large output directory over VirtioFS is slow (see Carving).
12. **Job log writes.** `tasks_docker.py` saves the whole job row, log included, every 10 lines of Elrond output. The cost of each save grows with the log, and IOC extraction logs every IOC, so `win_full` (540k log lines) rewrote megabytes per save tens of thousands of times. Autovacuum had never run on the `jobs` table, which reached 126 GB for 38 rows, Postgres stalled, and the job failed. Long, chatty jobs need the log moved out of the job row or saved on a timer.

## Results Excluded from the Tables

Some test runs finished with misleading times and are flagged in the raw data rather than used above: Linux runs that hit the loop-device leak (0.3 min false passes), Linux memory tests that never received a memory image or produced no Volatility output, `win_keywords` (blank keyword line), `linux_keywords` and `win_collect_files_bin` (interrupted), `linux_archive` (no zip produced), `linux_timeline` (Plaso wrote an empty CSV in 13 seconds), `linux_mordor_mode` (empty output; Mordor mode expects datasets, not a disk image) and `linux_yara` (YARA followed `/dev/fd` back into the mount and never finished; cancelled after 15.5 hours). `win_vss` (7.5 min, 76 processing entries) is also excluded: in `win_full` each shadow copy processes 213–220 entries and takes over an hour, so the `win_vss` run cannot have processed its shadow copies.
