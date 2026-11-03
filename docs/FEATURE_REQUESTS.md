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
| FR-08 | More SIEM integrations | Elrond output |

## FR-01: Team servers on Linux beyond Ubuntu

**Why.** Organisations run servers on the distributions they already support, and for many that's RHEL or one of its rebuilds. Today the server guide's tested shape is Ubuntu 24.04 with Docker's packages.

**What it takes.**
- **SELinux.** Rocky and RHEL enforce it, and a bind mount without a label is unreadable inside a container. The stack's own mounts in `docker-compose.yml` and the evidence folders from `RIVENDELL_EVIDENCE_PATHS` and `docker-compose.local.yml` need `:z` (or `bind: {selinux: z}` in the long form) on SELinux hosts. The Docker socket mount for Andúril needs a policy check, not just a label.
- **firewalld.** `server init` opens 443 and 80 (redirects and ACME) and nothing else, or says exactly which `firewall-cmd` lines to run.
- **Docker.** It comes from Docker's own RHEL repository; the distribution ships Podman. The runtime check should say so, not just "docker missing". Podman's Docker-compatible socket stays unsupported until it's tested with Andúril and the worker.
- **The guide.** `docs/SERVER.md` gets a per-distribution set-up section.

**Done when** `rivendell server init` and `rivendell start` bring up a working, signed-in server on Rocky 9 with SELinux enforcing, an analysis job reads evidence from a configured folder, and the same passes on Ubuntu 24.04.

**Depends on** a Rocky 9 VM in the lab; headless is enough.

## FR-02: Team servers on Windows Server

**Why.** Some teams only get Windows Server from IT.

**What it takes.**
- Rivendell's images are Linux containers. Docker Desktop isn't supported or licensed for Windows Server, and Windows Server's native container runtime runs Windows containers only. The route is WSL 2 (Windows Server 2022 and 2025) with Docker Engine inside an Ubuntu distribution, or a Hyper-V Linux VM.
- In both cases the server is really Linux, so the work is set-up and plumbing:
  - a PowerShell `server init` that sets up WSL and Docker;
  - evidence on Windows volumes reached through `/mnt/<drive>`, which is slow for large images (copying to the WSL filesystem is the usual answer, and the guide must say so);
  - port forwarding from the host to WSL for 443;
  - starting the stack at boot without a signed-in user, through a scheduled task.
- **Certificates.** The organisation's certificate, from the Windows certificate store, exported for Caddy.

**Done when** a Windows Server 2022 host runs the server profile through WSL 2, survives a reboot without anyone signing in, and analyses evidence from a Windows volume.

**Depends on** FR-01's server checks; a Windows Server 2022 VM in the lab.

## FR-03: Desktop app RPM for Rocky Linux 9 / RHEL 9

**Why.** It completes the desktop downloads for RHEL-family desktops. That's lower value than FR-01: analysts on Linux mostly run Ubuntu, SIFT or Kali, which the `.deb` covers.

**What it takes.**
- `app/linux/package-rpm.sh`, mirroring `package-deb.sh`:
  - the same `/opt/rivendell` layout, menu entry and icon;
  - `Requires: zenity` and `Recommends: docker-ce docker-compose-plugin`.
- Built by `rpmbuild` in a `rockylinux:9` container as a fourth job in `desktop-release.yml`, checked with `rpm -qpl` and `rpmlint`.
- The SELinux work from FR-01, for the evidence folders setup writes.

**Done when** the release attaches `rivendell-<version>.noarch.rpm`, `dnf install` adds the menu entry, and first-run setup starts the stack on a Rocky 9 desktop.

**Depends on** FR-01 (SELinux); a Rocky 9 desktop VM.

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
- **Input:** iTunes/Finder backups (encrypted, with the password), Android ADB backups and bug reports, and full file system extractions from a commercial tool's output folder. Rivendell doesn't do device extraction itself, which is a deliberately different job with its own tooling and legal footing.
- **Parsing:**
  - iLEAPP and ALEAPP as subprocess tools, defined in `tools/definitions.py` like the others, into `cooked/`;
  - techniques from the Mobile ATT&CK matrix;
  - IOCs through the existing extractor.

**Done when** an iOS backup and an Android extraction each produce a case with a timeline, cooked artefacts and mobile techniques, with known answers from test images.

**Depends on** public test images (for example Josh Hickman's) in the lab.

## FR-06: Network forensics (PCAP, Zeek, NetFlow)

**Why.** Host evidence says what ran, and network evidence says where it talked. Today Rivendell only sees a network through host artefacts (connections in memory, DNS caches, firewall logs).

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

**Why.** Teams use the SIEM they have. Today it's Splunk and Elastic.

**What it takes.**
- Output modules beside `post/splunk/` and `post/elastic/`:
  - Microsoft Sentinel (Logs Ingestion API with a data collection rule);
  - OpenSearch (close to Elastic);
  - Wazuh;
  - Chronicle.
- Each sends the cooked artefacts with the same field names and technique tags, and the credentials go into `.env`, never the case.
- Archer can generate the matching detections for each.

**Done when** a case appears in each SIEM, searchable by host and technique, from a single tick box on Elrond's page.

**Depends on** test tenants (Sentinel and Chronicle can't run locally).
