# Rowanholt Test Lab

Targets to acquire with Gandalf and datasets to analyse with Mordor, all on one machine. Containers and VMs are seeded with known artefacts: persistence entries, suspicious shell history, IOCs on documentation-only addresses (198.51.100.0/24, `*.rivendell-lab.test`), YARA bait strings. Each target also gets an `expected.json` listing what Elrond should find, with MITRE ATT&CK IDs. Nothing in the lab is malicious, and all networking is loopback or host-only.

`lab.sh` detects the host OS and CPU and uses the right tooling:

| Host | Linux targets | Linux VM | macOS VM | Windows VM | Mordor capture |
|---|---|---|---|---|---|
| macOS, Intel | 4 containers | Vagrant + VirtualBox | — (Tart needs Apple silicon) | Windows 11 x64, unattended | Yes |
| macOS, Apple silicon | 4 containers | Tart | Tart | Windows 11 ARM in UTM, unattended (you download the ISO) | Download only |
| Linux x86-64 | 4 containers | Vagrant + VirtualBox | — (macOS licensing) | Windows 11 x64, unattended | Yes |
| Linux arm64 | 4 containers | — | — | — | Download only |

On Windows hosts, run the lab inside WSL2.

## Requirements

- Rowanholt installed and running (`docker compose ... up -d`; see [QUICKSTART](../docs/QUICKSTART.md)), on Docker Desktop or OrbStack. The lab builds its containers on the same engine.
- 16 GB RAM minimum; 32 GB if you want the Windows VM and Rowanholt's SIEM profile up together.
- Free disk: about 5 GB for the containers, plus 15 GB for the Windows box, 30 GB for the macOS image, and 2–10 GB for Mordor datasets. VMs can live on an external drive (see [Settings](#settings)).
- An admin password for this machine, the first time only (Homebrew, VirtualBox).

## First Run

```bash
cd lab
./lab.sh
```

Choose **1) Quickstart**. It checks the host, offers to install what's missing, asks where to keep data and VMs, and and sets up the lab password: the `gandalf` user on every target gets it. The default is `mellon`, which is fine because every target listens only on loopback or a host-only network. If you set your own (`./lab.sh configure`, or **Aragorn → Settings** in the web UI), it's stored in your Keychain (or the Secret Service keyring on Linux), never on disk; an empty entry goes back to the default. Targets keep the password they were created with, so re-create them after a change. Then it builds and starts the Linux containers, collects from them with both the Bash and Python collectors, downloads APT29 days 1–2 from OTRF, and writes the settings Rowanholt's test runner needs.

The same steps exist as single commands:

```bash
./lab.sh check                      # what this host can run, and what's missing
./lab.sh install                    # Homebrew/apt/dnf packages for this profile
./lab.sh configure                  # data location, VM directory, VM sizes, password
./lab.sh linux-targets up           # lab-ubuntu, lab-rocky
./lab.sh linux-targets stacking     # and two clean Ubuntu hosts, for stacking
./lab.sh gandalf-collect bash       # every running target; or name them:
./lab.sh gandalf-collect python "lab-ubuntu lab-rocky"
./lab.sh mordor-download apt29/day1 apt29/day2
./lab.sh rowanholt-env
```

`./lab.sh help` lists everything.

## Running It from the Web UI

Start the lab agent on the machine running Rowanholt:

```bash
cd lab
./lab.sh agent start
```

Then sign in to Rowanholt as an admin and open **Aragorn**. It has three tabs:

- **Lab** (`/aragorn#lab`; `/lab` goes there too) is the lab itself: the `lab.sh` target commands with maintenance (Rowanholt test settings, teardown), the lab machines (see [The Mordor Page](#the-mordor-page)) and recent runs.
- **Deploy** (`/aragorn#deploy`) builds a run and deploys it. Pick **Gandalf**, **Elrond** or **Mordor**, then work through its steps: for Gandalf, the collector, the targets to deploy it to, where the acquisition lands, and optionally an Elrond analysis of it under a case ID; for Elrond, which acquisitions to analyse, the case ID and how deep; for Mordor, record Atomic Red Team on a lab machine (which machine, set it up first or not, the techniques, the snapshot to revert to), set a machine up without recording (logging, Sysmon on Windows, Atomic Red Team) so you can snapshot it ready, capture a dataset in the Windows VM, download OTRF datasets, or update the telemetry sources (OTRF, Splunk attack_data, EVTX-ATTACK-SAMPLES) and rebuild the technique index. A recording, a capture or a download can be analysed by Elrond straight after, under a case ID. A recording is first turned into a dataset (`./lab.sh mordor-dataset <run>`, which writes `$MORDOR_ROOT/lab/<run>/acquisitions/` and an `expected.json` of the tests that ran): Windows events become an event dataset, and Linux and macOS logs a Gandalf-style archive. Elrond ingests both. The plan underneath lists what **Deploy** will do, and Deploy runs those steps in order, stopping at the first failure, with the output streaming below. An Elrond step starts a job and links to it.
- **Settings** (`/aragorn#settings`) has Rowanholt's own containers and images (Anduril, the Docker manager) and the lab's host profile, settings and password. **Hidden machines** (`LAB_HIDDEN_MACHINES` in `lab.conf`, space-separated) leaves VMs on the host out of the lab entirely, such as another project's UTM VM; Rowanholt otherwise lists every UTM VM, since it can drive any of them.

Every lab step except `install`, which needs your password at a terminal, is on one tab or the other.

The agent is a small Python service (standard library only) on loopback port 5691. It accepts only the lab commands, with validated arguments, and runs one at a time. Its access token is regenerated on each start and written to `/tmp/rowanholt/.lab-agent/token`, which the Rowanholt backend already mounts. The page also stays off until the backend's `SECRET_KEY` is set, because the default JWT secret would let anyone mint an admin token. Stop the agent with `./lab.sh agent stop`.

## Gandalf Targets

The two **Linux containers**, Ubuntu 24.04 (Debian family, apt) and Rocky 9 (RHEL family, dnf), listen for SSH on `127.0.0.1:2221–2222`. They are quick to rebuild (`linux-targets reset`), but there's no real kernel, so memory acquisition can't be tested against them.

For stacking, `linux-targets stacking` adds two clean Ubuntu hosts, `lab-ubuntu-clean1` and `-clean2` (`127.0.0.1:2223–2224`), built from the same image with nothing planted. With `lab-ubuntu` that's three hosts of one OS with the plants on one, which is what stacking needs to call anything rare. Collect all four, run Elrond with `--Analysis` over them as one case, and score `stacking.csv` against the planted values with `precision_at_k` (`rowanholt/analysis/stacking.py`):

```bash
./lab.sh gandalf-collect python
```

Stacking compares Linux hosts within their distribution family, so `lab-rocky` (RHEL, one host) is only compared with itself and nothing on it is called rare; the three Ubuntu hosts are compared with each other. On 29 October 2026 that gave four rows, all planted on `lab-ubuntu` (`lab-sync.service`, `lab-agent.service` system and user, the `lab updater` autostart): precision@3 of 1.0, where before distro grouping the same case gave twenty rows of Rocky's own units. The clean hosts have no `expected.json`.

`./lab.sh stacking-eval` does all of that in one go: it starts the four targets, collects them with `gandalf.py` into a folder of its own under `<data>/stacking-eval/STACKEVAL-<date>/`, runs Elrond in Rowanholt's worker with `--Gandalf --Process --Analysis`, and scores `stacking.csv` against the `stacking` values in each target's `expected.json` (`lib/stacking_eval.py`). It prints precision at 4, 8 and 20 and each plant's rank, adds a row to the table below, and exits 1 if a plant isn't in `stacking.csv` at all. `./lab.sh stacking-eval --reuse` skips the collection and runs Elrond over the latest case's (or `--reuse STACKEVAL-<date>`'s), for when only Elrond has changed; collect afresh when Gandalf or the seeded targets have. For a change to one parser, `rowanholt elrond process-one <case>/<host>/artefacts/raw/<file>` runs that file through Elrond's dispatcher with the checkout's code, in a throwaway worker container, and prints what it cooks and the techniques it records, in seconds. Run it every release; the Windows evaluation (clean siblings, below) at least once per major release.

| Date | Case | Hosts | Rows | P@4 | P@8 | P@20 | Plant ranks |
|---|---|---|---|---|---|---|---|
| 2026-11-03 | `STACKEVAL-20261103-0257` | Linux containers (python collector) | 4 | 1.00 | 1.00 | 1.00 | 1, 2, 4 |
| 2026-11-04 | `STACKEVAL-20261104-1203` | Linux containers (python collector) | 4 | 1.00 | 1.00 | 1.00 | 1, 2, 4 |
| 2026-11-04 | `STACKEVAL-20261104-2129` | Linux containers (python collector) | 4 | 1.00 | 1.00 | 1.00 | 1, 2, 4 |
| 2026-11-05 | `STACKEVAL-20261105-1023` | Linux containers (python collector) | 4 | 1.00 | 1.00 | 1.00 | 1, 2, 4 |
<!-- stacking-eval: rows above -->

The **Linux VM** (`linux-vm create`) is Ubuntu with a real kernel (`bento/ubuntu-24.04` under Vagrant, Cirrus Labs `ubuntu:latest` under Tart), on SSH port 2230. The **macOS VM** (`macos-vm create`, Apple silicon only) is a Cirrus Labs Sequoia image on port 2231, provisioned without prompts: a `gandalf` user, a LaunchAgent, zsh history with a download, and a hidden staging folder in `/Users/Shared`. Both collectors work against it. `gandalf.sh` runs with sudo and also gets the root-only TCC and KnowledgeC databases; `gandalf.py` collects as the SSH user, so it skips what that user can't read. On the reference run (USB HDD), first boot took about an hour, then provisioning took 2.5 minutes, the bash and Python collections about 3 and 2 minutes, and Elrond 1.5–4 minutes.

The **Windows VM** (`windows-vm create`) is Windows 11, provisioned with a Run key, a scheduled task, a service, failed logons and PSReadLine history.

- On x86-64 hosts it's `gusztavvargadr/windows-11` under Vagrant, with PowerShell remoting. The first boot takes 10–20 minutes.
- On Apple silicon it's Windows 11 ARM in UTM, built unattended from Microsoft's ISO, or an installed VM you bring with `adopt`. See [Windows 11 ARM on Apple silicon](#windows-11-arm-on-apple-silicon).

The collectors run from a controller container (`rowanholt-lab-controller`) that reaches the VMs via `host.docker.internal`, so nothing is installed on the host. Output goes where Elrond's `--Gandalf` mode expects it:

```
<data>/gandalf/<collector>_collection/acquisitions/<target>/
```

Each target folder also gets that target's `expected.json` and a `collector.log`. The Windows collector is the exception to the controller container: `gandalf-collect powershell` runs Invoke-Gandalf inside the Windows VM (over WinRM on Vagrant, over SSH on UTM) and copies the archive out.

The Bash collector runs unencrypted by default; set `GANDALF_ENCRYPTION=Key` to test Key encryption (the key comes back as `<target>.shadowfax.key` next to the archive). The lab runs Gandalf as shipped. `GANDALF_WORKAROUNDS=1` repacks `.tar.gz` archives as `.zip`, for Rowanholt builds whose Elrond predates `.tar.gz` support (bug E7 in [BUGS.md](../tests/docs/BUGS.md)).

### Windows 11 ARM on Apple silicon

Tart can't run Windows (Apple's Virtualization framework only boots macOS and Linux), so the lab drives UTM through its AppleScript API. The VM lives under `$LAB_VM_DIR/utm/`, and its SSH is forwarded to `127.0.0.1:2232`, user `gandalf`, the lab password (default `mellon`).

**Building one (`windows-vm create`).** Download the Windows 11 ARM64 ISO from [Microsoft](https://www.microsoft.com/software-download/windows11arm64) (or with CrystalFetch) into `$LAB_DATA_DIR/isos/`; Microsoft only issues links through its web form, so this is the one manual step. Then:

```bash
./lab.sh windows-vm create
```

It downloads the virtio-win drivers and Win32-OpenSSH, builds a config ISO (`autounattend.xml`, the lab scripts, Gandalf, OpenSSH), creates `rowan-lab-win11` and boots the installer. Setup runs without prompts: TPM, Secure Boot and RAM checks are bypassed, the VirtIO disk and network drivers load from the virtio-win ISO, and a local `gandalf` administrator signs in once to run `firstlogon.ps1`, which provisions the target and starts sshd. It first adds Defender exclusions for `C:\lab`, `C:\ProgramData\RivendellLab`, `C:\TEMP` and `C:\Users\Public\Documents`: the seeded artefacts contain inert `IEX` and mimikatz strings, and AMSI otherwise blocks the provisioning script and quarantines what it seeds (L11). It takes 30–60 minutes on an SSD and longer on a spinning disk. When it's ready, the install media are detached and the config ISO, which holds the lab password, is deleted.

Two UTM details shape how this works. The system disk is VirtIO, not NVMe, because QEMU crashes in its NVMe TRIM handler when Windows trims (the VM just stops; L5 in [BUGS.md](../tests/docs/BUGS.md)). And because UTM's `export` drops removable media, the ISOs are hard-linked into the VM bundle as fixed CD images rather than attached as removable drives (L6).

To watch an install, set `WINDOWS_VM_VNC=1` before `create`: QEMU then also serves the VM's screen over VNC on `127.0.0.1:5959` (loopback only, no password), which any VNC client can open (`open vnc://127.0.0.1:5959`). Automatic updates are turned off in the answer file; a first-boot update run on a slow disk otherwise adds hours. `WINDOWS_INSTALL_WAIT` sets how many minutes `create` waits (default 90), and running `create` again on an existing VM just resumes waiting. `WINDOWS_BOOT_WAIT` (default 30) is the wait for SSH after `start` or a reboot; on a USB HDD, Windows took about 15 minutes to answer.

**Clean siblings, for stacking.** `WINDOWS_CLEAN=<n>` before any `windows-vm` action, or before `windows/utm-vm.sh collect`, works on `rowan-lab-win11-clean<n>` instead: computer name `LAB-WINCLEAN<n>`, SSH on `127.0.0.1:2232+n`, provisioned with the `gandalf` user and remoting but nothing seeded (`Provision-GandalfTarget.ps1 -Clean`). It doesn't change which VM the lab drives by default. Two of them with `rowan-lab-win11` make three Windows hosts, one seeded; run them one at a time on a 16 GB Mac:

```bash
WINDOWS_CLEAN=1 ./lab.sh windows-vm create
WINDOWS_CLEAN=1 ./windows/utm-vm.sh collect
```

On 29 October 2026 the two took 43 and 57 minutes to build and about 25 minutes each to collect (USB HDD). Stacked with the seeded VM, all four planted persistence values were rare on `LAB-WIN11` alone: the `LabUpdater` Run key, the `LabSync` task, the `LabHelper` service and the `LabUpdaterConsumer` WMI consumer. Four more persistence rows are ones the seeded VM gained from use (OneDrive's per-user tasks, a Defender driver service), and 66 programs from Prefetch and Amcache are rare only because that VM has run for four days (Gandalf, RawCopy, Atomic Red Team, Defender updates) and the clean ones for an hour. At the same score, persistence ranks above programs, so the plants came 1, 2, 6 and 8 of 74: all four in the top eight.

**Live containers on Windows (`windows-vm live-containers`).** `Invoke-Gandalf -LiveContainers` asks the `docker` CLI about running containers, and Docker Desktop needs WSL2, which needs nested virtualisation that UTM on Apple silicon can't give a Windows guest. So the lab runs a throwaway Docker engine on the Mac, published on `127.0.0.1:2375` only (no authentication, so it exists only for the run), which the VM reaches as `10.0.2.2` through UTM's emulated network. It seeds `lab-web` and a privileged `lab-priv` with `/` mounted, puts the Docker CLI (x64, run under emulation) in `C:\lab\docker`, collects with `-LiveContainers` and removes the engine. The acquisition lands where `collect` puts it, replacing the seeded VM's last one. What it can't test is Docker Desktop itself; a Windows x64 host with nested virtualisation can. On 5 November 2026 the first run found that `-LiveContainers` ended the whole collection (a relative output path handed to .NET's file calls), fixed the same day.

**Bringing your own (`windows-vm adopt`).** Put an installed Windows 11 ARM `.utm` in `$LAB_VM_DIR/utm/`, open it in place rather than dragging it into UTM (UTM keeps a separate copy of anything imported into its library, and the lab can't reach that copy), and run:

```bash
./lab.sh windows-vm adopt /path/to/vm.utm
```

`adopt` registers the bundle, adds the port forward and boots it. It logs in as `vagrant`/`vagrant` (set `ADOPT_USER` and `ADOPT_PASSWORD` for another account); if the VM has WinRM but no SSH, as Vagrant boxes do, it installs Win32-OpenSSH over WinRM first. Then it runs the same provisioning as `create`. The VM's name is saved as `WINDOWS_UTM_VM`. An adopted VM is never deleted by the lab: `windows-vm delete` and teardown refuse anything not named `rowan-lab-*`. An NVMe system disk on an adopted VM can still hit the QEMU crash above.

**Collecting.** `./lab.sh gandalf-collect powershell` runs `Run-GandalfLocal.ps1` in the VM and copies the archive to `$ACQ_ROOT/powershell_collection/acquisitions/<COMPUTERNAME>/`. DumpIt is x64-only, so Windows memory acquisition can't be tested on ARM. Gandalf's raw-copy artefacts (`$MFT`, `Amcache.hve`, `setupapi.dev.log`, `SRUDB.dat`) need `tools/disk_tools.zip`, which isn't in the repository; without it they are reported as FAILURE and everything else is collected (G21). After the copy, `collect` lists the VM's folder and fetches again any file that didn't arrive, and warns if one is still missing (G36). On the reference run (Windows 11 ARM on a USB HDD) a collection took about 3 minutes and produced a 38 MB archive. The old manual walkthrough is still in the `windows-vm` menu.

## Mordor Datasets

`mordor-download` fetches only the OTRF Security-Datasets that Rowanholt's tests reference: a sparse, blob-less clone, so you don't pull the multi-gigabyte repository. It unpacks them under `<data>/mordor/<test path>/` and writes a `manifest.json`. `--list` shows the mapping without downloading.

You can also generate your own datasets in the Windows VM. `mordor-sensor` runs on both Vagrant and UTM; `mordor-capture` runs on x86-64 hosts and prints the command to run inside the VM on Apple silicon:

```bash
./lab.sh mordor-sensor               # Sysmon (sysmon-modular), PowerShell logging, Atomic Red Team
./lab.sh mordor-capture persistence  # presets: persistence, credential_access, defense_evasion, discovery
./lab.sh mordor-capture custom my_set T1059.001,T1003.001
```

Each capture runs the Atomic tests, exports the Sysmon, Security and PowerShell logs as OTRF-style JSONL, and writes a zip with an `expected.json` of the techniques run. Elrond's `--Mordor` mode can't ingest OTRF JSON yet (bug E6), so the Mordor tests will fail until it can.

### Recorded Telemetry

`mordor-capture` makes one dataset from a whole run, for Elrond to analyse. `mordor-record` keeps each Atomic test's logs apart, so the telemetry engine (`src/mordor/telemetry`, ported from Archer) knows which log records which technique:

```bash
./lab.sh mordor-sensor                                 # once per VM
./lab.sh mordor-record persistence                     # same presets as mordor-capture
./lab.sh mordor-record custom my_run T1059.001,T1003.001
```

It copies `Invoke-MordorRecord.ps1` into the VM and runs each test of each technique: prerequisites, then the test, then a 20-second settle (`MORDOR_SETTLE`), then cleanup. Each test's Windows event logs (Security, System, PowerShell, Sysmon, Task Scheduler, WMI, Defender, BITS) are saved as `events.xml`. The run is copied to `src/mordor/data/telemetry/lab/lab-win11-<preset>-<time>/` and the `lab` source is rebuilt. The recordings hold the VM's host name, so they're gitignored and never written to the shipped files. `ROWANHOLT_TELEMETRY_LAB` puts them somewhere else.

The shipped data covers 1,632 recordings across 354 techniques (OTRF Security-Datasets, Splunk attack_data, EVTX-to-MITRE-Attack), plus Microsoft GUIDE's Defender XDR alerting for 441 techniques. The API is under `/api/mordor/telemetry` (see [docs/API.md](../docs/API.md#mordor-recorded-attack-telemetry)). From the repository root:

```bash
python3 -m src.mordor.telemetry                          # sources and technique count
python3 -m src.mordor.telemetry --build --source lab     # re-read your recordings
python3 -m src.mordor.telemetry --build                  # re-fetch what the public sources changed (needs PyYAML; evtx needs the evtx package)
python3 -m src.mordor.telemetry --guide <Kaggle zip>     # re-summarise Microsoft GUIDE
```

### The Mordor Page

**Mordor** in the web UI (`/mordor`) is one page, Archer's Emulate page ported. It shows where the telemetry comes from (the pipeline diagram and a card per public dataset, with **Update** for admins), a link to the lab that records your own, and every recorded technique with the logs its recordings hold, searchable by a value in the recorded events. An OTRF recording in a technique's detail has **Download for Elrond**, which fetches its raw events for `--Mordor` analysis. Its last section, **Downloadable datasets**, is the OTRF catalogue: the datasets that span several techniques (APT29's days) and bulk download.

Recording is a Mordor run on **Aragorn → Deploy**; the machines themselves are on **Aragorn → Lab** (`/aragorn#lab`), with the rest of what Rowanholt runs on this host. Both need the lab agent and an admin login. The **Lab machines** panel shows this host and the engines it can drive (Docker, Tart, UTM), what you can create on it, and every machine:

- **Create a machine**: an Ubuntu container (Docker), an Ubuntu or macOS VM (Tart, Apple silicon). Windows comes from UTM: **Clone existing** copies a built VM; **From ISO** checks a Windows 11 ARM64 ISO and can run `./lab.sh windows-vm create` to build the lab's VM unattended.
- **Your machines**: Start/Stop, Snapshot, Revert, Clone (UTM), Set OS (a UTM VM the lab didn't build), Set up (audit logging, PowerShell, Atomic Red Team), Record (Atomic Red Team, with a preview and a snapshot confirmation), Logs, and Delete.

The lab's own machines (the `lab-*` Gandalf containers, `rowan-lab-macos`, `rowan-lab-win11`) are listed and can be driven, but only `./lab.sh` deletes them. Delete appears only on machines this page created. Other VMs in UTM (Archer's `archer-win11`, say) can be started, snapshotted and recorded on, never deleted. **Set up** and **Record** on the lab's Windows VM run `mordor-sensor` and `mordor-record` over SSH; on any other machine they run inside it through `docker exec`, `tart exec` or `utmctl exec`, which on a UTM VM needs the UTM guest tools. Machines go to the Docker engine Rowanholt runs on and to `LAB_TART_HOME`. What the page knows about them (template, OS, set-up steps) is in `~/.config/rowanholt-lab/mordor-machines.json`. Slow actions run one at a time with the other lab commands and show their log on the page.

## Running Rowanholt's Tests Against the Lab

```bash
./lab.sh rowanholt-env
set -a; . ~/.config/rowanholt-lab/rowanholt-tests.env; set +a
python3 tests/scripts/run_test.py --run-tags gandalf
```

`rowanholt-env` also checks that Rowanholt's worker can see the lab's data directory. If it can't, it generates `lab/docker-compose.lab.yml` and prints the command to recreate the backend and worker with that extra mount.

## Settings

Settings live in `~/.config/rowanholt-lab/lab.conf`. Edit them with `./lab.sh configure` or from the web UI. Environment variables of the same name win for one-off runs.

| Setting | Default | |
|---|---|---|
| `LAB_DATA_DIR` | `~/rowanholt-lab-data` | Collected data and datasets |
| `TEST_IMAGES_PATH` | — | When set, data goes to `$TEST_IMAGES_PATH/gandalf` and `/mordor`, the paths `run_test.py` uses |
| `LAB_VM_DIR` | `$LAB_DATA_DIR/vms` | Vagrant boxes, VirtualBox VMs, Tart images (`tart/`) and UTM bundles (`utm/`). Existing lab VMs in the default locations are left where they are |
| `WINDOWS_UTM_VM` | `rowan-lab-win11` | Apple silicon: the UTM VM the lab drives (set by `windows-vm adopt`) |
| `LAB_TART_HOME` | — | Apple silicon: keep the Tart VMs here instead of `$LAB_VM_DIR/tart`, for example on the internal SSD while testing macOS (a first boot from a USB HDD took about an hour). `./lab.sh macos-vm move <dir>` moves the VM there, keeping its disk sparse (`rsync -S` and `cp` don't between APFS volumes), checks the copy, sets this, and offers to remove the old copy |
| `WINDOWS_VM_MEMORY_MB` / `WINDOWS_VM_CPUS` | 6144 / 2 | |
| `LINUX_VM_MEMORY_MB` | 2048 | |

Unattended runs: `LAB_YES=1` accepts every default, `LAB_FORCE=1` answers yes to everything, and `LAB_PASSWORD` overrides both the keyring and the default.

## Tearing Down

```bash
./lab.sh teardown
```

This removes the lab's containers, volumes and VMs; collected data is kept, and so are the built `rowanholt-lab-*` images (remove them with `docker rmi` if you want the space back). It asks whether to remove the stored password too. The lab only touches the `rowanholt-lab` compose project and its own VMs; other containers and VMs on the machine (Tart or VirtualBox) are left alone.

## Troubleshooting

- **The image build hangs on "load build context".** This happens when the repo is in a cloud-synced folder (OneDrive, iCloud). The lab avoids it by streaming the context as a tar; if you build by hand, do the same.
- **"No input … menus need a terminal".** You ran `lab.sh` without a terminal and without a command. Pass a command, or set `LAB_YES=1`.
- **The web UI says the agent isn't reachable.** Check `./lab.sh agent status` and `~/.config/rowanholt-lab/run/agent.log`. On Linux, the backend needs `host.docker.internal`, which `docker-compose.yml` maps to the host gateway.
- **Collector failures.** Each collection leaves `collector.log` next to its archive (`collector-python.log` for the Python collector), and the lab's known Gandalf issues are tracked in [BUGS.md](../tests/docs/BUGS.md).
- **A UTM Windows VM stops on its own.** Look for `QEMULauncher-*.ips` in `~/Library/Logs/DiagnosticReports`. A crash in `nvme_dsm_cb` is QEMU's NVMe TRIM bug: lab-built VMs use a VirtIO disk to avoid it, so it only affects VMs brought in with `adopt`.
- **`utmctl start` fails with OSStatus -1712.** UTM is waiting on a dialog, or wedged after a VM crash. Check its window, or quit and reopen UTM.
- **`adopt` says UTM is running a different copy.** The VM was dragged into UTM's library, which copies it into UTM's own storage. Remove it from UTM (this deletes UTM's copy only) and run `adopt` again; it opens the bundle in place.
- **A VM takes ages to boot, or Tart gives up waiting for an IP.** `LAB_VM_DIR` is probably on a spinning USB disk. It works, but first boots take many minutes; an SSD is much faster. Run one VM at a time on a 16 GB Mac with Rowanholt up.
- **Windows provisioning stops and SSH never comes up.** Read `C:\lab\firstlogon.log` in the VM (VNC, see above). `ScriptContainedMaliciousContent` means Defender blocked the provisioning script: the exclusions in `firstlogon.ps1` must run before it. Once fixed, re-run `firstlogon.ps1` from an elevated PowerShell; `create` (still waiting, or run again) picks it up.
- **`delete` won't remove a Windows VM.** It only deletes VMs the lab built (`rowan-lab-*`). Remove an adopted VM in UTM yourself.
