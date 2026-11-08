# Feature requests

Requested, not built. Each entry says why it's wanted, what it would take, how to know it's done, and what it depends on. When one is built, its entry moves into the docs for the feature and is deleted from here.

The v2.3 features that are being built are planned in `docs/ROADMAP.md`.

| ID | Request | Area |
|---|---|---|
| FR-01 | Team servers on Linux beyond Ubuntu (RHEL, Rocky, Alma) | Server |
| FR-02 | Team servers on Windows Server | Server |
| FR-03 | Desktop app RPM for Rocky Linux 9 / RHEL 9 | Desktop app |
| FR-04 | Lab VM consoles in the browser | Aragorn, server |
| FR-05 | Mobile device forensics (iOS, Android) | Gandalf, Elrond |
| FR-06 | Network forensics (PCAP, Zeek, NetFlow) | Elrond |
| FR-07 | Automated reporting | Elrond, web |
| FR-08 | More SIEM integrations: OpenSearch/Wazuh and Timesketch (built; Wazuh untried) | Elrond output |

## FR-01: Team servers on Linux beyond Ubuntu

**Built 8 November 2026, not yet run on a Rocky host.** `docs/SERVER.md` (Rocky, RHEL and Alma): SELinux through `deploy/docker-compose.selinux.yml` (`label=disable` on the services that mount host folders, so no evidence is relabelled), firewalld ports opened by `server init`, and `rowanholt start` refusing a missing Docker or Podman's `docker` with Docker's RHEL install steps.

**Done when** `rowanholt server init` and `rowanholt start` bring up a working, signed-in server on Rocky 9 with SELinux enforcing, an analysis job reads evidence from a configured folder, and the same passes on Ubuntu 24.04. Then this entry goes.

**Depends on** a Rocky 9 VM in the lab; headless is enough.

## FR-02: Team servers on Windows Server

**Built 8 November 2026, not yet run on Windows Server.** `scripts/server/windows/Install-RowanholtServer.ps1` and `Start-RowanholtServer.ps1`, `docs/SERVER.md` (Windows Server): its own WSL 2 distribution with Docker Engine, the same `server init`, the certificate from the Windows store, evidence through `/mnt/<drive>`, portproxy and a firewall rule, and a boot task that needs nobody signed in. Parsed by PowerShell 7 only; Windows PowerShell 5.1, WSL and the task are untried.

**Done when** a Windows Server 2022 host runs the server profile through WSL 2, survives a reboot without anyone signing in, and analyses evidence from a Windows volume. Then this entry goes.

**Depends on** a Windows Server 2022 VM: an x86 host, since WSL 2 needs nested virtualisation, which Apple silicon's VMs don't have.

## FR-03: Desktop app RPM for Rocky Linux 9 / RHEL 9

**Built 8 November 2026.** `app/linux/package-rpm.sh` and the `linux-rpm` job in `desktop-release.yml` (built, linted, installed and removed in `rockylinux:9`); `app/README.md`.

**Done when** first-run setup starts the stack on a Rocky 9 desktop with SELinux enforcing (a desktop VM: the container check can't run the menu entry or Docker). Then this entry goes.

## FR-04: Lab VM consoles in the browser

**Why.** When the lab's VMs run on a team server, admins never sit at the host. Today, seeing a VM's screen means a remote-desktop session to the server.

**What it takes.**
- A Console button per VM on Aragorn › Lab.
- Each VM serves its screen over VNC on the host's loopback: QEMU's `-vnc 127.0.0.1:N` in a UTM bundle's `config.plist` (found through UTM's registry), or Tart's `--vnc-experimental`.
- The backend relays a WebSocket to that port for signed-in admins only, asking the lab agent which port belongs to which VM.
- noVNC 1.5.0 (vendored, pinned, MPL-2.0) draws it, with keyboard, mouse and Ctrl+Alt+Del.

**Done when** an admin opens a lab VM's console from the browser on a team server, and a non-admin can't reach the relay at all.

**Depends on** the lab agent running on the server host. See `docs/SERVER.md`.

## FR-05: Mobile device forensics (iOS, Android)

**Why.** Phones are in scope for most intrusions that involve people: MFA prompts, messaging, mobile device management (MDM) profiles.

**What it takes.**
- **Input:** iTunes/Finder backups (encrypted, with the password), Android ADB backups and bug reports, and full file system extractions from a commercial tool's output folder. Rowanholt doesn't do device extraction itself, which is a deliberately different job with its own tooling and legal footing.
- **Parsing:**
  - iLEAPP and ALEAPP as subprocess tools, defined in `tools/definitions.py` like the others, into `cooked/`;
  - techniques from the Mobile ATT&CK matrix;
  - IOCs through the existing extractor.

**Done when** an iOS backup and an Android extraction each produce a case with a timeline, cooked artefacts and mobile techniques, with known answers from test images.

**Depends on** public test images (for example Josh Hickman's) in the lab.

## FR-06: Network forensics (PCAP, Zeek, NetFlow)

**Why.** Host evidence says what ran, and network evidence says where it talked. Today Rowanholt only sees a network through host artefacts (connections in memory, DNS caches, firewall logs).

**What it takes.**
- A new evidence type: PCAP files, Zeek logs and NetFlow/IPFIX exports.
- PCAP goes through Zeek as a subprocess (conn, dns, http, ssl, files), and Suricata optionally for alerts.
- Zeek's logs are cooked like any artefact and fed to the timeline and the IOC extractor, so a domain seen in PowerShell history and in DNS on the wire joins up.
- Techniques for **T1071**, **T1048**, **T1572** and similar from the protocol logs.

**Done when** a PCAP from the lab's Mordor recordings produces cooked Zeek logs, timeline entries and IOCs that match the host artefacts from the same run.

**Depends on** the Zeek and Suricata images; PCAP capture in the lab's Mordor recordings.

## FR-07: Automated reporting

**Why.** Every case ends in a report, and today the analyst writes it from scratch out of the case directory.

**What it takes.**
- A report generated from a case:
  - summary of hosts and timespan;
  - ATT&CK techniques, with the artefacts behind each;
  - indicators;
  - Gandalf's integrity result;
  - Elrond's options and tool versions as the method.
- DOCX and Markdown output.
- Once collaboration's findings exist (`docs/ROADMAP.md`), the report is built from confirmed findings first, and the rest is an appendix.

**Done when** a finished case produces a report a reviewer can follow back to the evidence for every claim, with no edits needed to make it accurate.

**Depends on** the findings work in `docs/ROADMAP.md` for the curated version; the uncurated one can come first.

## FR-08: More SIEM integrations

**Built 8 November 2026: OpenSearch (and Wazuh, whose indexer is OpenSearch) and Timesketch** (`post/opensearch.py`, `post/timesketch.py`; `docs/CLI.md`, SIEM Integration). Ben chose these two; Microsoft Sentinel and Chronicle are dropped. Run against OpenSearch 2.19 with its security plugin (a 1,157,224-record Windows host: every record, searchable by host and technique) and Timesketch 20261014.

**Done when** a case appears in a Wazuh deployment's dashboard (only OpenSearch itself has been tried), and Archer can generate the matching detections for Wazuh. Then this entry goes.

**Depends on** a Wazuh deployment in the lab.
