# Forensic Artefacts Implementation Guide

This document provides a comprehensive gap analysis of forensic artefacts across Windows, macOS, and Linux platforms. It identifies what is currently collected/processed, what is missing, and provides implementation guidance.

**Last Updated:** December 2024
**Version:** 1.0.0

---

## Table of Contents

1. [Windows Artefacts](#windows-artefacts)
   - [Currently Processed](#windows-currently-processed)
   - [Quick Wins (Functions Exist)](#windows-quick-wins)
   - [Missing Artefacts](#windows-missing-artefacts)
2. [macOS Artefacts](#macos-artefacts)
   - [Currently Processed](#macos-currently-processed)
   - [Missing Artefacts](#macos-missing-artefacts)
3. [Linux Artefacts](#linux-artefacts)
   - [Currently Processed](#linux-currently-processed)
   - [Missing Artefacts](#linux-missing-artefacts)
4. [Implementation Priority](#implementation-priority)
5. [MITRE ATT&CK Mapping](#mitre-attck-mapping)

---

## Windows Artefacts

### Windows Currently Processed

#### Collection Phase (`rowanholt/collect/windows.py`)

| Category | Artefact | Location | Status |
|----------|----------|----------|--------|
| **NTFS Metadata** | $MFT | Root | ✅ Collected |
| | $LogFile | Root | ✅ Collected |
| | $UsnJrnl | Root | ✅ Collected |
| | $ObjId | Root | ✅ Collected |
| | $Reparse | Root | ✅ Collected |
| **Registry** | SYSTEM | `Windows/System32/config/` | ✅ Collected |
| | SAM | `Windows/System32/config/` | ✅ Collected |
| | SOFTWARE | `Windows/System32/config/` | ✅ Collected |
| | SECURITY | `Windows/System32/config/` | ✅ Collected |
| | NTUSER.DAT | Per user profile | ✅ Collected |
| | UsrClass.dat | Per user profile | ✅ Collected |
| **Event Logs** | All .evtx files | `Windows/System32/winevt/Logs/` | ✅ Collected |
| **Execution** | Prefetch (.pf) | `Windows/Prefetch/` | ✅ Collected |
| | Amcache.hve | `Windows/AppCompat/Programs/` | ✅ Collected |
| | RecentFileCache.bcf | `Windows/AppCompat/Programs/` | ✅ Collected |
| **WMI/WBEM** | Repository | `Windows/System32/wbem/Repository/` | ✅ Collected |
| | Logs | `Windows/System32/wbem/Logs/` | ✅ Collected |
| **SRUM** | SRUDB.dat | `Windows/System32/LogFiles/sru/` | ✅ Collected |
| **UAL** | .mdb files | `Windows/System32/LogFiles/Sum/` | ✅ Collected |
| **Deleted Files** | $Recycle.Bin | Root | ✅ Collected |
| **Memory** | hiberfil.sys | Root | ✅ Collected |
| | pagefile.sys | Root | ✅ Collected |
| | swapfile.sys | Root | ✅ Collected |
| | MEMORY.DMP | `Windows/` | ✅ Collected |

#### Processing Phase (`rowanholt/process/windows.py`)

| Artefact | Parser | Output Format | Status |
|----------|--------|---------------|--------|
| Prefetch | Artemis | JSON | ✅ Active |
| Event Logs (.evtx) | Artemis | JSON | ✅ Active |
| $MFT | Artemis | JSON | ✅ Active |
| Shimcache | Artemis | JSON | ✅ Active |
| $UsnJrnl | Artemis | JSON | ✅ Active |
| SRUM | Artemis | JSON | ✅ Active |
| Jump Lists | Artemis | JSON | ✅ Active |
| Outlook (OST) | Artemis | JSON | ✅ Active |
| WMI Persistence | Artemis | JSON | ✅ Active |
| UAL | KStrike | CSV | ✅ Active |
| Registry (System) | dumpreg | JSON | ✅ Active |
| Registry (User) | dumpreg | JSON | ✅ Active |
| Clipboard | Custom | JSON | ✅ Active |
| USB Devices | Custom | JSON | ✅ Active |

---

### Windows Quick Wins

These Artemis extraction functions are **already implemented** in `rowanholt/process/extractions/artemis.py` but **not called** from the main processing flow. Enabling them requires minimal effort.

| Artefact | Function | Artemis Command | Output | ATT&CK Technique |
|----------|----------|-----------------|--------|------------------|
| **Amcache** | `extract_amcache()` | `artemis amcache` | amcache.json | T1059 (Execution) |
| **UserAssist** | `extract_userassist()` | `artemis userassist` | userassist.json | T1059 (Execution) |
| **Shell Bags** | `extract_shellbags()` | `artemis shellbags` | shellbags.json | T1083 (File Discovery) |
| **BITS Jobs** | `extract_bits()` | `artemis bits` | bits.json | T1197 (BITS Jobs) |
| **Scheduled Tasks** | `extract_tasks()` | `artemis tasks` | tasks.json | T1053.005 (Scheduled Task) |
| **Windows Services** | `extract_services()` | `artemis services` | services.json | T1543.003 (Windows Service) |
| **LNK Shortcuts** | `extract_shortcuts()` | `artemis shortcuts` | shortcuts.json | T1547.009 (Shortcut Modification) |
| **Recycle Bin** | `extract_recyclebin()` | `artemis recyclebin` | recyclebin.json | T1070.004 (File Deletion) |
| **Windows Search** | `extract_search()` | `artemis search` | search.json | T1083 (File Discovery) |

#### Implementation Steps for Quick Wins

1. Edit `rowanholt/process/windows.py`
2. Import the extraction functions from `artemis.py`
3. Add detection logic for the artefact files
4. Call the appropriate extraction function
5. Add MITRE ATT&CK enrichment tags

Example implementation pattern:
```python
# In process/windows.py

from rowanholt.process.extractions.artemis import extract_amcache

def process_amcache(artefact_path, output_dir):
    """Process Amcache.hve for program execution history."""
    if os.path.exists(artefact_path):
        extract_amcache(artefact_path, output_dir)
```

---

### Windows Missing Artefacts

#### High Priority - Not Collected or Processed

| Artefact | Location | Forensic Value | Parseable | ATT&CK |
|----------|----------|----------------|-----------|--------|
| **BAM/DAM** | SYSTEM registry | Process execution timeline (Win10+) | Yes (registry) | T1059 |
| **ActivitiesCache.db** | `AppData/Local/ConnectedDevicesPlatform/` | Windows Timeline activity | Yes (SQLite) | T1083 |
| **Thumbcache.db** | `AppData/Local/Microsoft/Windows/Explorer/` | File access, deleted file recovery | Yes (binary) | T1083 |
| **WordWheelQuery** | NTUSER.DAT registry | Search queries | Yes (registry) | T1083 |
| **TypedPaths** | NTUSER.DAT registry | Recently typed paths | Yes (registry) | T1083 |
| **RecentDocs** | NTUSER.DAT registry | Accessed files/folders | Yes (registry) | T1083 |
| **RDP Bitmap Cache** | `AppData/Local/Microsoft/Terminal Server Client/` | RDP session screenshots | Partial (binary) | T1021.001 |
| **PowerShell History** | `AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/` | Command history | Yes (text) | T1059.001 |
| **SCCM Logs** | `Windows/CCM/Logs/` | Deployment history | Yes (text/CSV) | T1105 |
| **Windows Defender Logs** | `ProgramData/Microsoft/Windows Defender/` | Threat detections | Yes (ETW/WMI) | T1562.001 |
| **Notifications** | `AppData/Local/Microsoft/Windows/Notifications/` | App notification history | Yes (database) | T1005 |

#### Medium Priority

| Artefact | Location | Forensic Value | Parseable |
|----------|----------|----------------|-----------|
| **$LogFile** | Root NTFS | Transaction log recovery | Partial |
| **Browser Cookies** | Various browser locations | Session data, tracking | Yes (SQLite) |
| **Browser Cache** | Various browser locations | Cached content | Yes (files) |
| **Browser Extensions** | Various browser locations | Installed extensions | Yes (JSON) |
| **Outlook PST** | User documents | Email archive | Yes (readpst) |
| **Sticky Notes** | `AppData/Local/Packages/Microsoft.MicrosoftStickyNotes_*/` | User notes | Yes (SQLite) |

---

## macOS Artefacts

### macOS Currently Processed

#### Collection Phase (`rowanholt/collect/mac.py`)

| Category | Artefact | Location | Status |
|----------|----------|----------|--------|
| **System** | passwd, shadow, group | `/etc/` | ✅ Collected |
| | hosts | `/etc/hosts` | ✅ Collected |
| | crontab | `/etc/crontab` | ✅ Collected |
| | System Logs | `/Library/Logs/` | ✅ Collected |
| | var logs | `/var/log/` | ✅ Collected |
| **Launch Items** | LaunchAgents | `/Library/LaunchAgents/` | ✅ Collected |
| | LaunchDaemons | `/Library/LaunchDaemons/` | ✅ Collected |
| | StartupItems | `/Library/StartupItems/` | ✅ Collected |
| | System LaunchAgents | `/System/Library/LaunchAgents/` | ✅ Collected |
| | System LaunchDaemons | `/System/Library/LaunchDaemons/` | ✅ Collected |
| **Preferences** | System Preferences | `/Library/Preferences/` | ✅ Collected |
| | User Preferences | `~/Library/Preferences/` | ✅ Collected |
| **User** | Keychain | `~/Library/keychains/` | ✅ Collected |
| | SSH | `~/.ssh/` | ✅ Collected |
| | Trash | `~/.Trash/` | ✅ Collected |
| | Bash History | `~/.bash_history` | ✅ Collected |
| | Bash Config | `~/.bashrc`, etc. | ✅ Collected |
| **Mail** | Mail.app | `~/Library/Mail/` | ✅ Collected |
| **Browsers** | Safari History | `~/Library/Safari/History.db` | ✅ Collected |
| | Chrome History | `~/Library/Application Support/Google/Chrome/` | ✅ Collected |
| | Firefox History | `~/Library/Application Support/Firefox/Profiles/` | ✅ Collected |
| **Memory** | Sleep Image | `/var/vm/sleepimage` | ✅ Collected (volatility mode) |
| | Swap | `/var/vm/swapfile` | ✅ Collected (volatility mode) |

#### Processing Phase (`rowanholt/process/mac.py`)

| Artefact | Parser | Output Format | Status |
|----------|--------|---------------|--------|
| Plist Files | plistlib | JSON | ✅ Active |
| LaunchAgents/Daemons | Custom | JSON | ✅ Active |

The unified log, KnowledgeC, TCC, FSEvents and quarantine events are parsed natively now (`process/mac_artefacts.py`, `process/extra_artefacts.py`); the never-integrated `macos_enhanced.py` was removed on 6 November 2026.

---

### macOS Missing Artefacts

#### High Priority

| Artefact | Location | Forensic Value | Parseable | ATT&CK |
|----------|----------|----------------|-----------|--------|
| **Messages.app** | `~/Library/Messages/chat.db` | iMessage/SMS history | Yes (SQLite) | T1005 |
| **Notes.app** | `~/Library/Notes/` | User notes | Yes (SQLite) | T1005 |
| **Calendar.app** | `~/Library/Calendars/` | Calendar events | Yes (SQLite) | T1005 |
| **Contacts.app** | `~/Library/Contacts/` | Contact database | Yes (SQLite) | T1005 |
| **Reminders.app** | `~/Library/Reminders/` | Reminders database | Yes (SQLite) | T1005 |
| **Recent Items** | `~/Library/Application Support/com.apple.sharedfilelist/` | Recently accessed files (.sfl2) | Partial | T1005 |
| **Bash/Zsh History** | `~/.bash_history`, `~/.zsh_history` | Command history (collected, not parsed) | Yes (text) | T1552.003 |
| **SSH authorized_keys** | `~/.ssh/authorized_keys` | SSH access (collected, not parsed) | Yes (text) | T1021.006 |
| **WiFi Known Networks** | `/Library/Preferences/SystemConfiguration/com.apple.wifi.known-networks.plist` | WiFi connection history | Yes (plist) | T1016 |
| **Bluetooth Devices** | `/Library/Preferences/com.apple.Bluetooth.plist` | Paired devices | Yes (plist) | T1011 |

#### Medium Priority

| Artefact | Location | Forensic Value | Parseable |
|----------|----------|----------------|-----------|
| **Photos.app** | `~/Library/Photos/` | Photo metadata, faces | Partial (APFS) |
| **Spotlight Index** | `/.Spotlight-V100/` | File search index | Partial (binary) |
| **Browser Cookies** | Safari/Chrome/Firefox | Session data | Yes |
| **Browser Bookmarks** | Safari/Chrome/Firefox | User bookmarks | Yes |
| **Dock Preferences** | `~/Library/Preferences/com.apple.dock.plist` | Pinned apps, recent items | Yes (plist) |
| **Login Items** | `~/Library/Preferences/com.apple.loginitems.plist` | Auto-start items | Yes (plist) |
| **Network Config** | `/Library/Preferences/SystemConfiguration/` | Network settings | Yes (plist) |
| **VPN Config** | `/Library/Preferences/SystemConfiguration/` | VPN connections | Yes (plist) |
| **Firewall Config** | `~/Library/Preferences/com.apple.alf.plist` | ALF firewall rules | Yes (plist) |
| **Installation History** | `/var/log/install.log` | Software installs | Yes (text) |
| **Crash Reports** | `/Library/Logs/DiagnosticReports/` | Application crashes | Yes (plist/text) |
| **USB History** | System logs, TimeMachine plist | Device connections | Partial |

---

## Linux Artefacts

### Linux Currently Processed

#### Collection Phase (`rowanholt/collect/linux.py`)

| Category | Artefact | Location | Status |
|----------|----------|----------|--------|
| **System Config** | passwd | `/etc/passwd` | ✅ Collected |
| | shadow | `/etc/shadow` | ✅ Collected |
| | group | `/etc/group` | ✅ Collected |
| | hosts | `/etc/hosts` | ✅ Collected |
| | crontab | `/etc/crontab` | ✅ Collected |
| | security configs | `/etc/security/*.conf` | ✅ Collected |
| | systemd configs | `/etc/systemd/*.conf` | ✅ Collected |
| **Logs** | var logs | `/var/log/` | ✅ Collected |
| | systemd journal | `/var/log/journal/` | ✅ Collected |
| | runtime journal | `/run/log/journal/` | ✅ Collected |
| **Services** | systemd user services | `/usr/lib/systemd/user/` | ✅ Collected |
| **User** | bash_history | `/home/*/.bash_history`, `/root/.bash_history` | ✅ Collected |
| | bash config | `.bashrc`, `.bash_aliases`, etc. | ✅ Collected |
| | SSH | `/home/*/.ssh/`, `/root/.ssh/` | ✅ Collected |
| | autostart | `~/.config/autostart/` | ✅ Collected |
| | Trash | `~/.local/share/Trash/` | ✅ Collected |
| | recently-used | `~/.local/share/recently-used.xbel` | ✅ Collected |
| | keyrings | `~/.local/share/keyrings/` | ✅ Collected |
| **Mail** | Thunderbird | `~/.thunderbird/` | ✅ Collected |
| **Browsers** | Firefox | `~/.mozilla/firefox/` | ✅ Collected |
| | Chrome | `~/.config/google-chrome/` | ✅ Collected |
| **Printing** | CUPS | `/var/cache/cups/` | ✅ Collected |
| **Temp** | tmp | `/tmp/` | ✅ Collected |

The journal, command histories and Docker are parsed natively now (`process/linux.py`, `process/linux_artefacts.py`); the never-integrated `linux_enhanced.py` was removed on 6 November 2026.

---

### Linux Missing Artefacts

#### High Priority

| Artefact | Location | Forensic Value | Parseable | ATT&CK |
|----------|----------|----------------|-----------|--------|
| **wtmp** | `/var/log/wtmp` | Login records | Yes (binary struct) | T1078 |
| **btmp** | `/var/log/btmp` | Failed login attempts | Yes (binary struct) | T1110 |
| **lastlog** | `/var/log/lastlog` | Last login per user | Yes (binary struct) | T1078 |
| **auth.log** | `/var/log/auth.log` (Debian) | Authentication events | Yes (text) | T1078 |
| **secure** | `/var/log/secure` (RHEL) | Authentication events | Yes (text) | T1078 |
| **User crontabs** | `/var/spool/cron/` | Scheduled tasks | Yes (text) | T1053.003 |
| **cron.d** | `/etc/cron.d/` | System cron jobs | Yes (text) | T1053.003 |
| **anacrontab** | `/etc/anacrontab` | Anacron jobs | Yes (text) | T1053.003 |
| **sudoers** | `/etc/sudoers`, `/etc/sudoers.d/` | Privilege escalation | Yes (text) | T1548.003 |

#### Medium Priority - Network

| Artefact | Location | Forensic Value | Parseable |
|----------|----------|----------------|-----------|
| **interfaces** | `/etc/network/interfaces` (Debian) | Network config | Yes (text) |
| **network-scripts** | `/etc/sysconfig/network-scripts/` (RHEL) | Network config | Yes (text) |
| **resolv.conf** | `/etc/resolv.conf` | DNS configuration | Yes (text) |
| **hosts.allow/deny** | `/etc/hosts.allow`, `/etc/hosts.deny` | TCP wrappers | Yes (text) |
| **iptables** | `iptables-save` output | Firewall rules | Yes (text) |
| **UFW** | `/etc/ufw/` | Ubuntu firewall | Yes (text) |
| **firewalld** | `/etc/firewalld/` | RHEL firewall | Yes (XML) |

#### Medium Priority - Services & Applications

| Artefact | Location | Forensic Value | Parseable |
|----------|----------|----------------|-----------|
| **Apache logs** | `/var/log/apache2/` | Web server access/errors | Yes (text) |
| **Nginx logs** | `/var/log/nginx/` | Web server access/errors | Yes (text) |
| **MySQL logs** | `/var/log/mysql/` | Database activity | Yes (text) |
| **PostgreSQL logs** | `/var/log/postgresql/` | Database activity | Yes (text) |
| **syslog** | `/var/log/syslog` (Debian) | System messages | Yes (text) |
| **messages** | `/var/log/messages` (RHEL) | System messages | Yes (text) |
| **kern.log** | `/var/log/kern.log` | Kernel messages | Yes (text) |
| **boot.log** | `/var/log/boot.log` | Boot messages | Yes (text) |

#### Medium Priority - Extended Histories

| Artefact | Location | Forensic Value | Parseable |
|----------|----------|----------------|-----------|
| **zsh_history** | `~/.zsh_history` | Zsh commands | Yes (text) |
| **python_history** | `~/.python_history` | Python REPL | Yes (text) |
| **mysql_history** | `~/.mysql_history` | MySQL client | Yes (text) |
| **psql_history** | `~/.psql_history` | PostgreSQL client | Yes (text) |
| **sqlite_history** | `~/.sqlite_history` | SQLite3 client | Yes (text) |
| **node_repl_history** | `~/.node_repl_history` | Node.js REPL | Yes (text) |

#### Lower Priority - Containers & Kernel

| Artefact | Location | Forensic Value | Parseable |
|----------|----------|----------------|-----------|
| **Docker containers** | `/var/lib/docker/containers/` | Container configs | Yes (JSON) |
| **Docker images** | `/var/lib/docker/overlay2/` | Image layers | Partial |
| **Kubernetes** | `/var/lib/kubelet/` | K8s node data | Yes (YAML/JSON) |
| **Kernel modules** | `/proc/modules`, `/sys/module/` | Loaded modules | Yes (text) |
| **cmdline** | `/proc/cmdline` | Boot parameters | Yes (text) |
| **SELinux logs** | `/var/log/audit/` (AVC denials) | Policy violations | Yes (text) |
| **AppArmor logs** | `/var/log/kern.log` | Policy violations | Yes (text) |

---

## Implementation Priority

### Phase 1: Quick Wins (Minimal Effort)

Enable existing Artemis functions in Windows processing:

1. ✅ Amcache - `extract_amcache()`
2. ✅ UserAssist - `extract_userassist()`
3. ✅ Shell Bags - `extract_shellbags()`
4. ✅ BITS Jobs - `extract_bits()`
5. ✅ Scheduled Tasks - `extract_tasks()`
6. ✅ Windows Services - `extract_services()`
7. ✅ LNK Shortcuts - `extract_shortcuts()`
8. ✅ Recycle Bin - `extract_recyclebin()`
9. ✅ Windows Search - `extract_search()`

**Estimated Effort:** 2-4 hours

### Phase 2: High-Value Additions

#### Windows
- BAM/DAM registry parsing
- PowerShell history parsing
- ActivitiesCache.db (Windows Timeline)

#### macOS
- Messages.app (chat.db) collection and parsing
- Bash/Zsh history parsing (already collected)
- Integrate enhanced parsers (FSEvents, TCC, Quarantine)

#### Linux
- wtmp/btmp binary parsing
- auth.log/secure collection and parsing
- User crontab collection

**Estimated Effort:** 1-2 weeks

### Phase 3: Comprehensive Coverage

- Browser cookies and cache
- Network configuration artefacts
- Application-specific logs
- Container artefacts (Docker/K8s)
- Desktop environment artefacts

**Estimated Effort:** 2-4 weeks

---

## MITRE ATT&CK Mapping

### Execution (TA0002)
| Technique | Artefact | Platform |
|-----------|----------|----------|
| T1059.001 (PowerShell) | PowerShell history, Event logs | Windows |
| T1059.003 (Cmd) | Prefetch, Amcache | Windows |
| T1059.004 (Bash) | bash_history, auth.log | Linux/macOS |

### Persistence (TA0003)
| Technique | Artefact | Platform |
|-----------|----------|----------|
| T1053.003 (Cron) | crontab, /var/spool/cron | Linux |
| T1053.005 (Scheduled Task) | Tasks, Event logs | Windows |
| T1543.003 (Windows Service) | Services, Registry | Windows |
| T1547.001 (Registry Run Keys) | Registry, Autoruns | Windows |
| T1547.009 (Shortcut Modification) | LNK files | Windows |
| T1197 (BITS Jobs) | BITS database | Windows |
| T1543.001 (Launch Agent) | LaunchAgents plists | macOS |
| T1543.004 (Launch Daemon) | LaunchDaemons plists | macOS |

### Privilege Escalation (TA0004)
| Technique | Artefact | Platform |
|-----------|----------|----------|
| T1548.003 (Sudo) | /etc/sudoers, auth.log | Linux |

### Defense Evasion (TA0005)
| Technique | Artefact | Platform |
|-----------|----------|----------|
| T1070.001 (Clear Event Logs) | Event logs | Windows |
| T1070.002 (Clear Bash History) | bash_history timestamps | Linux/macOS |
| T1070.004 (File Deletion) | $Recycle.Bin, USN Journal | Windows |
| T1562.001 (Disable Tools) | Windows Defender logs | Windows |

### Credential Access (TA0006)
| Technique | Artefact | Platform |
|-----------|----------|----------|
| T1003 (OS Credential Dumping) | SAM, SECURITY, lsass | Windows |
| T1552.001 (Files) | Config files, scripts | All |
| T1552.003 (Bash History) | bash_history | Linux/macOS |
| T1110 (Brute Force) | btmp, auth.log | Linux |

### Discovery (TA0007)
| Technique | Artefact | Platform |
|-----------|----------|----------|
| T1083 (File Discovery) | Shell Bags, MFT, FSEvents | All |
| T1087 (Account Discovery) | SAM, passwd, shadow | All |
| T1016 (Network Discovery) | Network configs | All |

### Lateral Movement (TA0008)
| Technique | Artefact | Platform |
|-----------|----------|----------|
| T1021.001 (RDP) | Event logs, RDP cache | Windows |
| T1021.004 (SSH) | SSH logs, known_hosts | Linux/macOS |
| T1021.006 (Windows Admin) | Event logs, SMB | Windows |

### Collection (TA0009)
| Technique | Artefact | Platform |
|-----------|----------|----------|
| T1005 (Local Data) | User documents, databases | All |
| T1114 (Email Collection) | Outlook, Thunderbird, Mail.app | All |

### Exfiltration (TA0010)
| Technique | Artefact | Platform |
|-----------|----------|----------|
| T1041 (C2 Channel) | Network logs, firewall | All |
| T1011 (Other Network) | Bluetooth, USB logs | All |

---

## Appendix A: Parser Implementation Templates

### SQLite to JSON (Python)

```python
import sqlite3
import json
from datetime import datetime

def parse_sqlite_db(db_path: str, output_path: str, table: str):
    """Generic SQLite to JSON parser."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(f"SELECT * FROM {table}")
    rows = [dict(row) for row in cursor.fetchall()]

    with open(output_path, 'w') as f:
        json.dump(rows, f, indent=2, default=str)

    conn.close()
    return len(rows)
```

### Binary wtmp/btmp Parser (Python)

```python
import struct
from datetime import datetime

UTMP_STRUCT = struct.Struct('hi32s4s32s256shhiii4I20s')

def parse_wtmp(wtmp_path: str) -> list:
    """Parse Linux wtmp/btmp binary file."""
    entries = []

    with open(wtmp_path, 'rb') as f:
        while True:
            data = f.read(UTMP_STRUCT.size)
            if not data:
                break

            fields = UTMP_STRUCT.unpack(data)
            entry = {
                'type': fields[0],
                'pid': fields[1],
                'line': fields[2].decode('utf-8').rstrip('\x00'),
                'id': fields[3].decode('utf-8').rstrip('\x00'),
                'user': fields[4].decode('utf-8').rstrip('\x00'),
                'host': fields[5].decode('utf-8').rstrip('\x00'),
                'timestamp': datetime.fromtimestamp(fields[9]).isoformat()
            }
            entries.append(entry)

    return entries
```

### Text Log Parser (Python)

```python
import re
from datetime import datetime

def parse_auth_log(log_path: str) -> list:
    """Parse Linux auth.log for authentication events."""
    events = []

    # Common auth.log patterns
    patterns = {
        'ssh_accepted': r'Accepted (\w+) for (\w+) from ([\d.]+)',
        'ssh_failed': r'Failed (\w+) for (\w+) from ([\d.]+)',
        'sudo': r'(\w+) : .* COMMAND=(.*)',
        'session_opened': r'session opened for user (\w+)',
        'session_closed': r'session closed for user (\w+)',
    }

    with open(log_path, 'r') as f:
        for line in f:
            for event_type, pattern in patterns.items():
                match = re.search(pattern, line)
                if match:
                    events.append({
                        'type': event_type,
                        'raw': line.strip(),
                        'matches': match.groups()
                    })
                    break

    return events
```

---

## Appendix B: File Locations Reference

### Windows Default Paths

```
C:\Windows\System32\config\          # Registry hives
C:\Windows\System32\winevt\Logs\     # Event logs
C:\Windows\Prefetch\                 # Prefetch files
C:\Windows\AppCompat\Programs\       # Amcache, RecentFileCache
C:\Windows\System32\Tasks\           # Scheduled Tasks
C:\Windows\System32\wbem\            # WMI repository
C:\$Recycle.Bin\                     # Recycle Bin
C:\Users\<user>\NTUSER.DAT           # User registry
C:\Users\<user>\AppData\Local\Microsoft\Windows\Explorer\  # Thumbcache
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\  # Recent items
```

### macOS Default Paths

```
/Library/LaunchAgents/               # System launch agents
/Library/LaunchDaemons/              # System launch daemons
/Library/Preferences/                # System preferences
/var/log/                            # System logs
/private/var/db/diagnostics/         # Unified logs
/private/var/db/CoreDuet/            # KnowledgeC.db
~/Library/Preferences/               # User preferences
~/Library/Messages/                  # Messages.app
~/Library/Safari/                    # Safari data
~/Library/Application Support/       # Application data
```

### Linux Default Paths

```
/etc/passwd                          # User accounts
/etc/shadow                          # Password hashes
/var/log/                            # System logs
/var/log/journal/                    # Systemd journal
/var/log/audit/                      # Audit logs
/var/spool/cron/                     # User crontabs
/home/<user>/.bash_history           # Bash history
/home/<user>/.ssh/                   # SSH configuration
/var/lib/docker/                     # Docker data
```

---

## Contributing

When adding new artefact parsers:

1. Add collection logic to the appropriate `collect/*.py` file
2. Add processing logic to the appropriate `process/*.py` file
3. Ensure JSON output format with consistent field naming
4. Add MITRE ATT&CK technique mapping to enrichment
5. Update this document with the new artefact
6. Add unit tests for the parser

---

*This document is part of the Rowanholt Digital Forensics Acceleration Suite.*
