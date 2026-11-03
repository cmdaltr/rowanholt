# Test Results

Final snapshot of the E2E matrix run of 12–24 Oct 2026. The Notion "Dernvale — Test Plan" database is the live record; [`docs/PERFORMANCE.md`](../../docs/PERFORMANCE.md) has the timing analysis.

A FAIL here includes false passes: jobs the API marked COMPLETED that produced no or wrong output. Durations are wall-clock minutes from the audit log.

## Summary

| Category | Passed | Failed | Incomplete | Running | Not run | Total |
|---|---|---|---|---|---|---|
| Windows Disk | 15 | 7 | 1 | 0 | 0 | 23 |
| Windows Memory | 3 | 1 | 0 | 0 | 0 | 4 |
| Linux Disk | 15 | 8 | 1 | 0 | 0 | 24 |
| Linux Memory | 0 | 4 | 0 | 0 | 0 | 4 |
| macOS Disk | 0 | 0 | 0 | 0 | 24 | 24 |
| macOS Memory | 0 | 0 | 0 | 0 | 4 | 4 |
| Multi-Image | 1 | 0 | 0 | 0 | 4 | 5 |
| Gandalf | 0 | 0 | 0 | 0 | 10 | 10 |
| Cloud | 0 | 0 | 0 | 0 | 11 | 11 |
| Mordor | 0 | 0 | 0 | 0 | 11 | 11 |
| **Total** | **34** | **20** | **2** | **0** | **64** | **120** |

## Environment

- **Host:** Apple M2 Pro, 16 GB RAM; Docker Desktop with ~16 GB, worker at concurrency 1
- **Images:** `/Volumes/Portable6TB/Data/rivendell` (USB, VirtioFS)
- **API:** http://localhost:5688
- **Known issues:** tracked as Known issue rows in the Notion Test Plan

## Windows Disk Tests

| Test | Result | Date | Duration (min) | Notes |
|---|---|---|---|---|
| win_archive | 🟢 PASS | 2026-10-13 | 15.6 | — |
| win_brisk | 🟢 PASS | 2026-10-13 | 32.2 | Also runs analysis, so slower than a basic run |
| win_collect_files_all | 🔴 FAIL | 2026-10-20 | 81.2 | Carving invalid (E01 container bug); collection valid |
| win_collect_files_archive | 🟢 PASS | 2026-10-13 | 17.0 | — |
| win_collect_files_bin | 🟠 INCOMPLETE | 2026-10-14 | 0.7 | Interrupted by Docker VM wipe |
| win_collect_files_docs | 🟢 PASS | 2026-10-13 | 16.9 | — |
| win_collect_files_hidden | 🟢 PASS | 2026-10-13 | 16.7 | — |
| win_collect_files_lnk | 🟢 PASS | 2026-10-13 | 16.8 | — |
| win_collect_files_mail | 🟢 PASS | 2026-10-13 | 16.0 | — |
| win_collect_files_scripts | 🟢 PASS | 2026-10-13 | 17.8 | — |
| win_carve_unalloc | 🔴 FAIL | 2026-10-20 | 56.6 | foremost scans the compressed E01 container; 39 files |
| win_collect_files_virtual | 🟢 PASS | 2026-10-13 | 16.7 | — |
| win_collect_files_web | 🟢 PASS | 2026-10-13 | 16.1 | — |
| win_verbose | 🟢 PASS | 2026-10-13 | 18.0 | — |
| win_extract_iocs | 🟢 PASS | 2026-10-13 | 58.9 | 10,919 IOCs |
| win_full | 🔴 FAIL | 2026-10-24 | 2200 | Partial: job failed in VSS #2 analysis when Postgres stalled (126 GB jobs table); processing 25.7 h |
| win_keywords | 🔴 FAIL | 2026-10-13 | 875 | Blank/# lines in keywords file match every line |
| win_splunk_elastic_nav | 🔴 FAIL | 2026-10-12 | 25.9 | Elastic OK; Splunk 0 events (monitors watch /tmp) |
| win_timeline | 🟢 PASS | 2026-10-21 | 223.3 | Plaso 105 min; ~150 min without the $I30 walk |
| win_userprofiles | 🟢 PASS | 2026-10-12 | 17.9 | — |
| win_vss | 🔴 FAIL | 2026-10-12 | 7.5 | 76 processing entries; shadow copies not processed |
| win_yara | 🟢 PASS | 2026-10-12 | 44.4 | YARA 41 min |
| win_mordor_mode | 🔴 FAIL | — | — | Produces nothing on an E01; job COMPLETED |

## Windows Memory Tests

| Test | Result | Date | Duration (min) | Notes |
|---|---|---|---|---|
| win_disk_and_memory | 🟢 PASS | 2026-10-13 | 33.1 | — |
| win_memory_basic | 🟢 PASS | 2026-10-13 | 6.0 | — |
| win_mem_splunk_elastic_nav | 🔴 FAIL | 2026-10-13 | 6.7 | Nothing indexed into SIEM |
| win_memory_timeline | 🟢 PASS | 2026-10-13 | 8.6 | — |

## Linux Disk Tests

| Test | Result | Date | Duration (min) | Notes |
|---|---|---|---|---|
| linux_analysis | 🟢 PASS | 2026-10-13 | 3.5 | — |
| linux_archive | 🔴 FAIL | 2026-10-13 | 2.9 | Archiving 'completes' with no zip |
| linux_basic | 🟢 PASS | 2026-10-13 | 2.7 | — |
| linux_collect_files_all | 🟢 PASS | 2026-10-19 | 823 | 0.5 s carve sleep; carving 701 min |
| linux_collect_files_archive | 🟢 PASS | 2026-10-13 | 2.9 | — |
| linux_collect_files_bin | 🟢 PASS | 2026-10-13 | 3.1 | — |
| linux_collect_files_docs | 🟢 PASS | 2026-10-13 | 3.1 | — |
| linux_collect_files_hidden | 🟢 PASS | 2026-10-13 | 3.0 | — |
| linux_collect_files_lnk | 🟢 PASS | 2026-10-13 | 3.1 | — |
| linux_collect_files_mail | 🟢 PASS | 2026-10-13 | 3.0 | — |
| linux_collect_files_scripts | 🔴 FAIL | 2026-10-13 | 0.3 | Loop-device leak false pass |
| linux_carve_unalloc | 🟢 PASS | 2026-10-20 | 253.5 | 76,237 carved files |
| linux_collect_files_virtual | 🔴 FAIL | 2026-10-13 | 0.3 | Loop-device leak false pass |
| linux_collect_files_web | 🔴 FAIL | 2026-10-13 | 0.3 | Loop-device leak false pass |
| linux_debug | 🟢 PASS | 2026-10-13 | 3.0 | — |
| linux_extract_iocs | 🟢 PASS | 2026-10-13 | 73.7 | 74,710 IOCs |
| linux_full | 🟢 PASS | 2026-10-20 | 182 | 86,918 IOCs; Splunk subject to /tmp monitor issue |
| linux_hash_collected | 🟢 PASS | 2026-10-21 | 186 | 183,989 files hashed |
| linux_keywords | 🟠 INCOMPLETE | 2026-10-14 | 0.1 | Stopped after metadata |
| linux_splunk_elastic_nav | 🟢 PASS | 2026-10-21 | 6.0 | — |
| linux_timeline | 🔴 FAIL | 2026-10-21 | 5.7 | Plaso CSV empty (header only); job COMPLETED |
| linux_userprofiles | 🔴 FAIL | 2026-10-13 | 0.3 | Loop-device leak false pass |
| linux_yara | 🔴 FAIL | 2026-10-21 | 930 | yara -r looped via /dev/fd; cancelled. Re-run with -N pending |
| linux_mordor_mode | 🔴 FAIL | 2026-10-21 | 0.2 | Empty output, no audit log; job COMPLETED |

## Linux Memory Tests

| Test | Result | Date | Duration (min) | Notes |
|---|---|---|---|---|
| linux_disk_and_memory | 🔴 FAIL | 2026-10-13 | 3.7 | Memory produced nothing |
| linux_mem_splunk_elastic_nav | 🔴 FAIL | 2026-10-13 | 0.5 | Linux Volatility plugins find nothing |
| linux_memory | 🔴 FAIL | 2026-10-13 | 2.7 | Test passes only the disk image |
| linux_memory_timeline | 🔴 FAIL | 2026-10-13 | 2.9 | Test passes only the disk image |

## macOS Disk Tests

| Test | Result | Date | Duration (min) | Notes |
|---|---|---|---|---|
| mac_analysis | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_archive | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_basic | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_collect_files_all | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_collect_files_archive | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_collect_files_bin | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_collect_files_docs | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_collect_files_hidden | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_collect_files_lnk | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_collect_files_mail | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_collect_files_scripts | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_carve_unalloc | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_collect_files_virtual | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_collect_files_web | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_debug | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_extract_iocs | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_full | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_hash_collected | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_keywords | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_splunk_elastic_nav | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_timeline | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_userprofiles | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_yara | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_mordor_mode | 🟣 NOT RUN | — | — | macOS images not on the test drive |

## macOS Memory Tests

| Test | Result | Date | Duration (min) | Notes |
|---|---|---|---|---|
| mac_disk_and_memory | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_mem_splunk_elastic_nav | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_memory | 🟣 NOT RUN | — | — | macOS images not on the test drive |
| mac_memory_timeline | 🟣 NOT RUN | — | — | macOS images not on the test drive |

## Multi-Image Tests

| Test | Result | Date | Duration (min) | Notes |
|---|---|---|---|---|
| multi_all_platforms | 🟣 NOT RUN | — | — | Not run in this matrix |
| multi_all_with_memory | 🟣 NOT RUN | — | — | Not run in this matrix |
| multi_full_exhaustive | 🟣 NOT RUN | — | — | Not run in this matrix |
| multi_win_linux | 🟢 PASS | 2026-10-21 | 138.4 | ~72 min without the $I30 walk |
| multi_win_mac | 🟣 NOT RUN | — | — | Not run in this matrix |

## Gandalf Tests

| Test | Result | Date | Duration (min) | Notes |
|---|---|---|---|---|
| gandalf_bash_analysis | 🟣 NOT RUN | — | — | Gandalf collections not on the test drive |
| gandalf_bash_basic | 🟣 NOT RUN | — | — | Gandalf collections not on the test drive |
| gandalf_bash_timeline | 🟣 NOT RUN | — | — | Gandalf collections not on the test drive |
| gandalf_powershell_analysis | 🟣 NOT RUN | — | — | Gandalf collections not on the test drive |
| gandalf_powershell_basic | 🟣 NOT RUN | — | — | Gandalf collections not on the test drive |
| gandalf_powershell_elastic | 🟣 NOT RUN | — | — | Gandalf collections not on the test drive |
| gandalf_powershell_splunk | 🟣 NOT RUN | — | — | Gandalf collections not on the test drive |
| gandalf_python_analysis | 🟣 NOT RUN | — | — | Gandalf collections not on the test drive |
| gandalf_python_basic | 🟣 NOT RUN | — | — | Gandalf collections not on the test drive |
| gandalf_python_full_siem | 🟣 NOT RUN | — | — | Gandalf collections not on the test drive |

## Cloud Tests

| Test | Result | Date | Duration (min) | Notes |
|---|---|---|---|---|
| cloud_aws_disk_analysis | 🟣 NOT RUN | — | — | No cloud credentials configured |
| cloud_aws_disk_basic | 🟣 NOT RUN | — | — | No cloud credentials configured |
| cloud_aws_disk_memory_combined | 🟣 NOT RUN | — | — | No cloud credentials configured |
| cloud_aws_full_pipeline | 🟣 NOT RUN | — | — | No cloud credentials configured |
| cloud_aws_memory | 🟣 NOT RUN | — | — | No cloud credentials configured |
| cloud_azure_disk_analysis | 🟣 NOT RUN | — | — | No cloud credentials configured |
| cloud_azure_disk_basic | 🟣 NOT RUN | — | — | No cloud credentials configured |
| cloud_azure_disk_mem | 🟣 NOT RUN | — | — | No cloud credentials configured |
| cloud_azure_full_pipeline | 🟣 NOT RUN | — | — | No cloud credentials configured |
| cloud_azure_memory | 🟣 NOT RUN | — | — | No cloud credentials configured |
| cloud_multi_aws_azure | 🟣 NOT RUN | — | — | No cloud credentials configured |

## Mordor Tests

| Test | Result | Date | Duration (min) | Notes |
|---|---|---|---|---|
| mordor_apt29_day1 | 🟣 NOT RUN | — | — | Mordor datasets not on the test drive |
| mordor_apt29_day2 | 🟣 NOT RUN | — | — | Mordor datasets not on the test drive |
| mordor_apt29_full | 🟣 NOT RUN | — | — | Mordor datasets not on the test drive |
| mordor_atomic_cred_access | 🟣 NOT RUN | — | — | Mordor datasets not on the test drive |
| mordor_atomic_defense_evasion | 🟣 NOT RUN | — | — | Mordor datasets not on the test drive |
| mordor_atomic_lateral_movement | 🟣 NOT RUN | — | — | Mordor datasets not on the test drive |
| mordor_atomic_persistence | 🟣 NOT RUN | — | — | Mordor datasets not on the test drive |
| mordor_full_detection_test | 🟣 NOT RUN | — | — | Mordor datasets not on the test drive |
| mordor_malware_cobalt_strike | ⚪ REMOVED | — | — | OTRF doesn't publish this dataset (P11) |
| mordor_malware_emotet | ⚪ REMOVED | — | — | OTRF doesn't publish this dataset (P11) |
| mordor_malware_trickbot | ⚪ REMOVED | — | — | OTRF doesn't publish this dataset (P11) |
