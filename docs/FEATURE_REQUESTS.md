# Feature requests

Requested, not built. Each entry says why it's wanted, what it would take, how to know it's done, and what it depends on. When one is built, its entry moves into the docs for the feature and is deleted from here.

The v2.3 features that are being built are planned in `docs/ROADMAP.md`.

| ID | Request | Area |
|---|---|---|
| FR-01 | Team servers on Linux beyond Ubuntu (RHEL, Rocky, Alma): built, not yet run on Rocky | Server |
| FR-02 | Team servers on Windows Server: built, not yet run on Windows Server | Server |
| FR-03 | Desktop app RPM for Rocky Linux 9 / RHEL 9: built, first run on a desktop untried | Desktop app |
| FR-04 | Lab VM consoles in the browser: built, not yet run on a server | Aragorn, server |
| FR-05 | Mobile device forensics (iOS, Android): built, needs test images | Gandalf, Elrond |

## FR-01: Team servers on Linux beyond Ubuntu

**Built 8 November 2026, not yet run on a Rocky host.** `docs/SERVER.md` (Rocky, RHEL and Alma): SELinux through `deploy/docker-compose.selinux.yml` (`label=disable` on the services that mount host folders, so no evidence is relabelled), firewalld ports opened by `server init`, and `rowanholt start` refusing a missing Docker or Podman's `docker` with Docker's RHEL install steps.

**Done when** `rowanholt server init` and `rowanholt start` bring up a working, signed-in server on Rocky 9 with SELinux enforcing, an analysis job reads evidence from a configured folder, and the same passes on Ubuntu 24.04. Then this entry goes.

**Depends on** a Rocky 9 VM in the lab; headless is enough.

## FR-03: Desktop app RPM for Rocky Linux 9 / RHEL 9

**Built 8 November 2026.** `app/linux/package-rpm.sh` and the `linux-rpm` job in `desktop-release.yml` (built, linted, installed and removed in `rockylinux:9`); `app/README.md`.

**Done when** first-run setup starts the stack on a Rocky 9 desktop with SELinux enforcing (a desktop VM: the container check can't run the menu entry or Docker). Then this entry goes.

## FR-04: Lab VM consoles in the browser

Built 8 November 2026 on `feat/lab-consoles`: **Console** per Tart and UTM VM on Aragorn › Lab, drawn by noVNC, opt-in with `LAB_VM_CONSOLE=1`; Tart VMs start with `--vnc-experimental`, the lab's UTM VMs get `-vnc 127.0.0.1:N` (a clone a free display of its own); the lab agent finds each running VM's port (`src/mordor/lab/consoles.py`) and tunnels to it on loopback by VM name; the backend's websocket relay takes signed-in admins only, locally and on a server. Described in `lab/README.md` (VM Consoles). noVNC is `@novnc/novnc` 1.5.0, exact-pinned (MPL-2.0). Still to do: Vagrant/VirtualBox VMs have no console.

**Done when** an admin opens a lab VM's console from the browser on a team server, and a non-admin can't reach the relay at all.

**Depends on** the lab agent running on the server host. See `docs/SERVER.md`.

## FR-05: Mobile device forensics (iOS, Android)

Built 8 November 2026 (`feat/mobile-forensics`): `elrond.py --Mobile` (and the job form's Mobile source) takes iTunes/Finder backups, encrypted ones with the password on standard input (`--backupPasswordStdin`; the web app hands it to the worker through Redis, never the job), ADB backups (opened and laid out as a file system by Elrond), bug reports and full file system extractions (folders or archives). iLEAPP v2026.4.6 and ALEAPP v2026.4.5 run as subprocesses from their own virtualenvs in the worker image; their TSV exports are cooked into `cooked/ileapp/` and `cooked/aleapp/`, with `artefacts/mobile_timeline.jsonl` and IOC extraction as for any host; device management (configuration profiles, MDM, Android device administrators and owners) is read by Elrond and tagged **T1632.001** and **T1626.001** from ATT&CK Mobile. Each item's files are hashed (SHA-256) when it's registered and checked again after processing (`mobile_integrity`). Documented in `docs/CLI.md` (Phones). Tested only against synthetic fixtures shaped like the tools' output: neither tool has been run by Rowanholt yet, and the worker image with them hasn't been built.

**Done when** (not yet) an iOS backup and an Android extraction each produce a case with a timeline, cooked artefacts and mobile techniques, with known answers from test images.

**Depends on** public test images (for example Josh Hickman's) in the lab, and a rebuild of the worker image.
