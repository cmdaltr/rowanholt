#!/usr/bin/env python3 -tt
import argparse
import base64
import getpass
import os
import paramiko
import random
import shutil
import socket
import subprocess
import sys
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from scp import SCPClient

# Resolve Gandalf's files from this script's location, not the working directory:
# python/collect_artefacts-py is the template, tools/ and lists/ sit beside python/.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GANDALF_HOME = os.path.dirname(SCRIPT_DIR)
TOOLS_DIR = os.path.join(GANDALF_HOME, "tools")
LISTS_DIR = os.path.join(GANDALF_HOME, "lists")
ACQUIRE_TEMPLATE = os.path.join(SCRIPT_DIR, "collect_artefacts-py")
ACQUIRE_SCRIPT = os.path.join(TOOLS_DIR, "acquire_artefacts.py")
MEMORY_TOOLS = [os.path.join(TOOLS_DIR, "memory", "avml-main.zip"), os.path.join(TOOLS_DIR, "memory", "osxpmem.app.zip")]


def remote_can_sudo(ssh, password):
    """True when the SSH account can sudo with its password."""
    stdin, stdout, _ = ssh.exec_command("sudo -S -p '' -v")
    stdin.write(password + "\n")
    stdin.flush()
    return stdout.channel.recv_exit_status() == 0


def run_remote(ssh, command, password, as_root):
    """Run command over SSH, through sudo -S when as_root; returns its stdout."""
    if not as_root:
        _, stdout, _ = ssh.exec_command(command)
        return stdout.read().decode(errors="replace")
    stdin, stdout, _ = ssh.exec_command("sudo -S -p '' " + command)
    stdin.write(password + "\n")
    stdin.flush()
    return stdout.read().decode(errors="replace")


parser = argparse.ArgumentParser()
parser.add_argument(
    "EncryptionMethod",
    help="Encrpytion Method - Key (recommended), Password or None",
)
parser.add_argument(
    "Acquisition",
    help="Acquisition Method - Local or Remote",
)
parser.add_argument(
    "-O",
    "--OutputDirectory",
    nargs="?",
    help="Directory location to output the artefact archive",
    const=True,
    default=False,
)
parser.add_argument(
    "-M",
    "--Memory",
    help="Acquire live memory",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-A",
    "--AccessTimes",
    help="Obtain Last Access Times for every file",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-F",
    "--CollectFiles",
    help="Collect specific files, anywhere in the fileystem",
    action="store_const",
    const=True,
    default=False,
)

parser.add_argument(
    "-L",
    "--LiveContainers",
    help="Ask Docker and Podman about their running containers (inspect, processes, filesystem "
    "export): opt-in, as it touches the live host; every command is audited",
    action="store_const",
    const=True,
    default=False,
)

parser.add_argument(
    "-P",
    "--ShowProgress",
    help="Print each artefact as it is taken",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-N",
    "--NoPrompt",
    help="Ask no questions and accept the defaults; an encryption or SSH password is still asked for",
    action="store_const",
    const=True,
    default=False,
)

args = parser.parse_args()
encryption_method = args.EncryptionMethod
acquisition = args.Acquisition
output_dir = args.OutputDirectory
mem = args.Memory
access_times = args.AccessTimes
files = args.CollectFiles
live_containers = args.LiveContainers
show_progress = args.ShowProgress
no_prompt = args.NoPrompt

system_artefacts = {
    # macOS artifacts
    "/.Trashes/": "trash",
    "/Library/Logs/": "logs",
    "/Library/Preferences/": "plists",
    "/Library/LaunchAgents/": "plists",
    "/Library/LaunchDaemons/": "plists",
    "/Library/StartupItems/": "plists",
    "/System/Library/LaunchDaemons/": "plists",
    "/System/Library/StartupItems/": "plists",
    "/Users/": "user",
    "/private/etc/group": "",
    "/private/etc/hosts": "",
    "/private/etc/modules-load": "",
    "/private/etc/passwd": "",
    "/private/etc/security/": "",
    "/private/etc/shadow": "",
    "/private/etc/systemd": "",
    "/var/vm/sleepimage": "memory",
    "/var/vm/swapfile": "memory",
    # macOS Enhanced Artifacts (Feature 3)
    "/private/var/db/diagnostics/": "unified_logs",
    "/private/var/db/uuidtext/": "unified_logs",
    "/private/var/db/CoreDuet/Knowledge/knowledgeC.db": "coreduet",
    "/Library/Application Support/com.apple.TCC/TCC.db": "tcc",
    "/.fseventsd/": "fseventsd",
    "/System/Volumes/Data/.fseventsd/": "fseventsd",
    "/private/var/db/dhcpclient/": "dhcp_leases",
    "/.Spotlight-V100/": "spotlight",
    "/private/var/db/.TimeMachine/": "timemachine",
    "/var/db/FileVaultKeys/": "filevault",
    "/Library/Keychains/": "keychains",
    "/var/log/system.log": "system_log",
    "/var/log/install.log": "install_log",
    "/Library/Logs/DiagnosticReports/": "crash_reports",
    # Linux artifacts
    "/boot/": "boot",
    "/etc/cron.d/": "cron",
    "/etc/cron.daily/": "cron",
    "/etc/cron.monthly/": "cron",
    "/etc/cron.weekly/": "cron",
    "/etc/crontab": "",
    "/etc/group": "",
    "/etc/hosts": "",
    "/etc/modules-load": "",
    "/etc/passwd": "",
    "/etc/security/": "",
    "/etc/shadow": "",
    "/etc/systemd/": "conf",
    "/home/": "home",
    "/root/": "root",
    "/swapfile": "memory",
    "/tmp/": "tmp",
    "/var/tmp/": "var_tmp",
    "/dev/shm/": "dev_shm",
    "/usr/lib/systemd/user/": "services",
    "/var/cache/cups/": "",
    "/var/at/": "cron",
    "/var/log/": "logs",
    # Linux Enhanced Artifacts (Feature 3)
    "/var/log/journal/": "journal",
    "/var/log/audit/": "audit",
    "/var/lib/docker/containers/": "docker_containers",
    "/var/lib/docker/volumes/": "docker_volumes",
    "/var/lib/docker/overlay2/": "docker_overlay",
    "/var/log/dpkg.log": "package_log",
    "/var/log/apt/": "package_log",
    "/var/log/yum.log": "package_log",
    "/var/log/dnf.log": "package_log",
    "/proc/net/tcp": "network_connections",
    "/proc/modules": "kernel_modules",
    "/var/log/wtmp": "login_records",
    "/var/log/btmp": "failed_logins",
    "/var/spool/cron/": "cron_jobs",
    "/var/spool/at/": "at_jobs",
    "/etc/anacrontab": "",
    "/etc/rc.local": "startup_scripts",
    "/lib/systemd/system/": "systemd_units",
    "/etc/init.d/": "init_scripts",
    # Windows artifacts
    "/Windows/System32/wbem/Repository/": "wmi_repo",
    "/Windows/System32/wbem/Repository/FS/": "wmi_repo",
}
# A copy of QUIPS in src/common/quips.py, the source: this script runs on its own, without the
# rest of the repo, so the copy must match it
quotes = [
    "Hash it before you trust it.",
    "Volatile first. The disk will wait; the RAM won't.",
    "If it isn't in the timeline, it didn't happen. If it is, prove it.",
    "Every artefact is innocent until correlated.",
    "The attacker cleared the logs. The logs about the logs are still here.",
    "Absence of evidence is a finding. Write it down.",
    "Time zones: the oldest adversary.",
    "Never analyse the original. Not even once. Especially not once.",
    "Prefetch remembers what the user would rather forget.",
    "The registry keeps secrets badly and grudges well.",
    "A clean system is either clean or very well cleaned.",
    "Your hypothesis is not your conclusion. Yet.",
    "Write the report as if the defence will read it. They will.",
    "Chain of custody: boring until the day it isn't.",
    "Correlation is a lead. Causation needs a second source.",
    "Timestamps lie. Four of them lie less.",
    "The first alert is rarely the first event.",
    "Living off the land still leaves footprints in the mud.",
    "Assume the clock is wrong until it proves otherwise.",
    "Scope creep is also an incident.",
    "Read the ShimCache, then distrust it accordingly.",
    "If the binary is signed, ask who signed it and why.",
    "Every persistence mechanism was somebody's convenience feature.",
    "The quietest host is worth a second look.",
    "Collect broadly. Conclude narrowly.",
    "No IOC survives contact with a competent adversary.",
    "Lateral movement leaves logons. Logons leave 4624s.",
    "Deleted is a state of mind. The MFT disagrees.",
    "Document now. Your memory is not evidence.",
    "The answer is in the data. The question is usually the problem.",
]
gandalf_root = "/tmp/gandalf"
gandalf_directory = os.path.join(gandalf_root, "gandalf", "acquisitions")
if isinstance(output_dir, str):  # -O DIR (a bare -O gives True: use the default)
    output_directory = output_dir
else:
    output_directory = gandalf_directory
if mem != False:
    memory = "True"
else:
    memory = "None"
if access_times == True:
    access_times = "True"
else:
    access_times = "None"
if files == True:
    collect_files = "True"
else:
    collect_files = "None"


def generate_filekey():
    """A new Fernet key. It's saved beside the archive as <host>.shadowfax.key, as gandalf.sh
    does, which Elrond reads to decrypt; keep it apart from the archive in transit."""
    key = Fernet.generate_key()
    print("     Encryption key created; it is saved as <host>.shadowfax.key beside the archive.\r")
    return key


def save_filekey(key, directory, host):
    key_path = os.path.join(directory, "{}.shadowfax.key".format(host))
    with open(key_path, "wb") as keyfile:
        keyfile.write(key)
    os.chmod(key_path, 0o600)
    print(
        "     \033[1;33mEncryption key: {}\n       Store it apart from the archive; anyone holding both can read it.\033[1;m".format(
            key_path
        )
    )


def generate_cipher():
    pswd = getpass.getpass(
        "    \033[1;30mEnter password to encrypt acquisition archive:\033[1;m "
    ).encode()
    password = bytes(pswd)
    pswdsalt = "" if no_prompt else input("    \033[1;30mEnter salt [isengard.pork]:\033[1;m ")
    pswdsalt = pswdsalt or "isengard.pork"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(pswdsalt.encode()),
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    print("     Cipher created successfully\r")
    return key


def available_memory_tools():
    """Memory tools present in tools/memory; warn about any that are missing."""
    present = [t for t in MEMORY_TOOLS if os.path.exists(t)]
    for t in MEMORY_TOOLS:
        if t not in present:
            print("     \033[1;33m{} not found; memory acquisition with it is skipped\033[1;m".format(os.path.basename(t)))
    return present


def configure_acquisition(
    encryption_method,
    system_artefacts,
    output_directory,
    memory,
    access_times,
    collect_files,
    encryption_object,
    gandalf_directory,
    gandalf_host,
):
    shutil.copy2(ACQUIRE_TEMPLATE, ACQUIRE_SCRIPT)
    with open(ACQUIRE_SCRIPT, "a") as acquire_artefacts:
        if live_containers:
            acquire_artefacts.write("\n\nLIVE_CONTAINERS = True\n")
        if show_progress:
            acquire_artefacts.write("\n\nSHOW_PROGRESS = True\n")
        acquire_artefacts.write(
            '\n\nacquire_artefacts(\n    "{}",\n    {},\n    "{}",\n    "{}",\n    "{}",\n    "{}",\n    {!r},\n    "{}",\n    "{}",\n)\n'.format(
                encryption_method,
                system_artefacts,
                output_directory,
                memory,
                access_times,
                collect_files,
                encryption_object,
                gandalf_directory,
                gandalf_host,
            )
        )
    os.chmod(ACQUIRE_SCRIPT, 0o755)


def main():
    subprocess.Popen(["clear"])
    time.sleep(2)
    starttime = time.time()
    print(
        """
    \n\n
      \033[1;35m                       __             .___.__
        ____  __ __  _______/  |_  ____   __| _/|__|____    ____
      _/ ___\\|  |  \\/  ___/\\   __\\/  _ \\ / __ | |  \\__  \\  /    \\
      \\  \\___|  |  /\\___ \\  |  | (  <_> ) /_/ | |  |/ __ \\|   |  \\
       \\___  >____//____  > |__|  \\____/\\____ | |__(____  /___|  /
           \\/           \\/                   \\/         \\/     \\/\n\n{}\033[1;m
    """.format(
            "     " + random.choice(quotes) + "\n"
        )
    )
    if os.path.exists("C:\\TEMP\\gandalf") and acquisition.title() == "Local":
        print(
            "      gandalf.py is not designed to run Locally on Windows devices.\n       Please use Invoke-Gandalf.ps1 instead.\n\n"
        )
        sys.exit()
    else:
        pass
    if (
        encryption_method.title() != "Key"
        and encryption_method.title() != "Password"
        and encryption_method.title() != "None"
    ):
        print(
            "     Invalid encryption method - it must be either 'Key', 'Password' or 'None'\n       Please try again.\n\n"
        )
        sys.exit()
    else:
        pass
    if acquisition.title() != "Local" and acquisition.title() != "Remote":
        print(
            "     Invalid acquisition method - it must be either 'Local' or 'Remote'\n       Please try again.\n\n"
        )
        sys.exit()
    else:
        pass
    if os.path.exists(gandalf_directory):
        shutil.rmtree(gandalf_directory)
    else:
        pass
    try:
        subprocess.Popen(["mkdir", "-p", "{}".format(gandalf_directory)])
    except:
        print(
            "     {} could not be created. Are you running as 'root'?\n       Please try again.\n\n".format(
                gandalf_directory
            )
        )
        sys.exit()
    if encryption_method.title() == "Key":
        encryption_object = generate_filekey()
        print()
    elif encryption_method.title() == "Password":
        encryption_object = generate_cipher()
        print()
    else:  # None
        encryption_object = None
    hostlist = []
    hostlist.append(socket.gethostname())
    if acquisition == "Local":
        configure_acquisition(
            encryption_method,
            system_artefacts,
            output_directory,
            memory,
            access_times,
            collect_files,
            encryption_object,
            gandalf_directory,
            os.path.join(gandalf_directory, hostlist[0]),
        )
        if memory:
            for tool in available_memory_tools():
                shutil.copy2(tool, "/tmp/gandalf/")
        subprocess.Popen(
            ["sudo", "python3", ACQUIRE_SCRIPT]
        ).communicate()
        if encryption_method.title() == "Key":
            save_filekey(encryption_object, output_directory, hostlist[0])
        if output_directory != gandalf_directory:
            if os.path.exists(
                os.path.join(gandalf_directory, "{}.zip.enc".format(hostlist[0]))
            ):
                shutil.move(
                    os.path.join(gandalf_directory, "{}.zip.enc".format(hostlist[0])),
                    os.path.join(output_directory, "{}.zip.enc".format(hostlist[0])),
                )
            else:
                shutil.move(
                    os.path.join(gandalf_directory, "{}.zip".format(hostlist[0])),
                    os.path.join(output_directory, "{}.zip".format(hostlist[0])),
                )
            shutil.rmtree("/tmp/gandalf/")
        else:
            ext = ""
            if os.path.exists(
                os.path.join(gandalf_directory, "{}.zip.enc".format(hostlist[0]))
            ):
                ext = ".enc"
            else:
                pass
            archive = "{}/{}.zip{}".format(gandalf_directory, hostlist[0], ext)
            if no_prompt:
                # Nobody is there to take the archive before /tmp/gandalf goes, so it stays
                print("\n    The archive is '{}'; '/tmp/gandalf/' is left for you to remove".format(archive))
            else:
                print(
                    "\n    '/tmp/gandalf/' will now be \033[1;31mdeleted\033[1;m. Ensure you have collected '{}'".format(archive)
                )
                time.sleep(4)
                input("      Collected? [Yes] ")
                shutil.rmtree("/tmp/gandalf/")
        os.remove(ACQUIRE_SCRIPT)
    else:  # Remote
        if encryption_object == None and not no_prompt:
            confirm_encryption = input(
                "     You have chosen to use no encryption when archiving the artefacts. This is not recommended.\n      Are you sure you want to proceed? y/N [N] :"
            )
            if confirm_encryption != "y":
                print(
                    "      Please try again with the 'EncryptionObject' parameter set to 'Key' or 'Password'\n\n"
                )
                sys.exit()
            else:
                pass
        else:
            pass
        ssh = paramiko.client.SSHClient()
        hostlist = []  # the collecting machine itself isn't a remote target
        with open(os.path.join(LISTS_DIR, "hosts.list")) as host_list:
            for each_host in host_list:
                if not each_host.startswith("#"):
                    hostlist.append(each_host.strip())
                else:
                    pass
        for host in hostlist:
            print("    \033[1;30mConnecting to '{}'...\033[1;m".format(host))
            default_user = os.environ.get("SUDO_USER") or getpass.getuser()
            if no_prompt:
                ssh_ip, ssh_user = host, default_user
            else:
                ssh_ip = input("     \033[1;30mIP address [{}]:\033[1;m ".format(host)) or host
                ssh_user = input("     \033[1;30m  Username [{}]:\033[1;m ".format(default_user)) or default_user
            ssh_pswd = getpass.getpass("     \033[1;30m  Password:\033[1;m ")
            gandalf_host = os.path.join(gandalf_directory, host)
            configure_acquisition(
                encryption_method,
                system_artefacts,
                output_directory,
                memory,
                access_times,
                collect_files,
                encryption_object,
                gandalf_directory,
                gandalf_host,
            )
            print()
            try:
                ssh.set_missing_host_key_policy(
                    paramiko.AutoAddPolicy()
                )  # initiating connection
                ssh.connect(ssh_ip, username=ssh_user, password=ssh_pswd)
                sshin, sshout, ssherr = ssh.exec_command(
                    "mkdir -p {}".format(gandalf_directory)
                )  # making gandalf directories
                # exec_command returns once the command is sent: wait for mkdir, or the scp
                # below can reach the host first and fail with "No such file or directory"
                sshout.channel.recv_exit_status()
                scp = SCPClient(ssh.get_transport())
                if memory:  # sending memory dump tools
                    for tool in available_memory_tools():
                        scp.put(tool, "/tmp/gandalf/")
                scp.put(
                    ACQUIRE_SCRIPT,
                    "/tmp/gandalf/acquire_artefacts.py",
                )  # sending gandalf acquisition script
                # As root where the account can sudo, as Local mode does: otherwise
                # root-only artefacts (TCC, KnowledgeC, /var/at) are skipped
                as_root = remote_can_sudo(ssh, ssh_pswd)
                exec_script = run_remote(
                    ssh, "python3 /tmp/gandalf/acquire_artefacts.py", ssh_pswd, as_root
                )  # executing gandalf acquisition script
                print(exec_script)
                _, list_out, list_err = ssh.exec_command(
                    "ls /tmp/gandalf/gandalf/acquisitions/"
                )  # listing acquisition archive directory
                dir_listing = str(list_out.read())
                if (
                    "{}.zip.enc".format(gandalf_host.split("/")[-1]) in dir_listing
                ):  # checking for encrypted archive
                    scp.get(
                        "/tmp/gandalf/gandalf/acquisitions/{}.zip.enc".format(
                            gandalf_host.split("/")[-1]
                        ),
                        ".",
                    )
                    print(
                        "     \033[1;30mEncrypted archive collected for '{}'\033[1;m".format(
                            gandalf_host.split("/")[-1]
                        )
                    )
                    if encryption_method.title() == "Key":
                        save_filekey(encryption_object, ".", gandalf_host.split("/")[-1])
                elif (
                    "{}.zip".format(gandalf_host.split("/")[-1]) in dir_listing
                ):  # checking for unencrypted archive
                    scp.get(
                        "/tmp/gandalf/gandalf/acquisitions/{}.zip".format(
                            gandalf_host.split("/")[-1]
                        ),
                        ".",
                    )
                    print(
                        "     \033[1;30mArchive collected for '{}'\033[1;m".format(
                            gandalf_host.split("/")[-1]
                        )
                    )
                else:
                    print(
                        "     \033[1;30mArchive could not be collected, please try again for '{}'\033[1;m\n".format(
                            gandalf_host.split("/")[-1]
                        )
                    )
                run_remote(ssh, "rm -rf /tmp/gandalf/", ssh_pswd, as_root)  # deleting gandalf
                ssh.close()
            except paramiko.ssh_exception.NoValidConnectionsError:
                print(
                    "      \033[1;31mSSH connection to '{}' could not be established.\033[1;m\n".format(
                        host
                    )
                )
            print()
    endtime = time.time()
    diffmins = "{} minutes".format(str(round(((endtime - starttime) - 4) / 60)))
    diffsecs = "{} seconds".format(str(round(((endtime - starttime) - 4) % 60)))
    if int(diffmins.split(" ")[0]) == 1:
        diffmins = diffmins[0:-1]
    else:
        pass
    if int(diffsecs.split(" ")[0]) > 0:
        seconds = "and {}".format(diffsecs)
    else:
        seconds = ""
    print(
        "\n  \033[1;30m-> Finished. Total elapsed time: {} {}\033[1;m\n    ----------------------------------------".format(
            str(diffmins), seconds
        )
    )
    print("      Custodian completed for:")
    for eachhost in hostlist:
        print("       - {}".format(eachhost))
    print("\n\n")


if __name__ == "__main__":
    main()
