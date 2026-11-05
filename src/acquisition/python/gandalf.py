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

args = parser.parse_args()
encryption_method = args.EncryptionMethod
acquisition = args.Acquisition
output_dir = args.OutputDirectory
mem = args.Memory
access_times = args.AccessTimes
files = args.CollectFiles
live_containers = args.LiveContainers

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
quotes = [
    "     Now come the days of the King, and may they be blessed.\n     -- Gandalf, The Return of the King\n",
    "     Forty-two, Master Legolas!\n     -- Gimli, The Two Towers\n",
    "     There is a lot more in him than you guess,\n     and a deal more than he has any idea of himself.\n     -- Gandalf, The Hobbit\n",
    "     One Ring to rule them all, One Ring to find them,\n     One Ring to bring them all and in the darkness bind them.\n     -- the Ring-verse, The Fellowship of the Ring\n",
    "     The world is changing: I feel it in the water,\n     I feel it in the earth, and I smell it in the air.\n     -- Treebeard, The Return of the King\n",
    "     Who knows? Have patience. Go where you must go, and hope!\n     -- Gandalf, The Two Towers\n",
    "     All we have to decide is what to do with the time that is given us.\n     -- Gandalf, The Fellowship of the Ring\n",
    "     Deeds will not be less valiant because they are unpraised.\n     -- Aragorn, The Two Towers\n",
    "     In the end the Shadow was only a small and passing thing.\n     -- Sam, in Mordor, The Return of the King\n",
    "     It's the job that's never started as takes longest to finish.\n     -- Sam, after the Gaffer, The Fellowship of the Ring\n",
    "     I laid low the warriors of old and their like is not in the world today.\n     -- Smaug, The Hobbit\n",
    "     Something is the matter with you! You are not the hobbit that you were.\n     -- Gandalf, The Hobbit\n",
    "     Do not be too eager to deal out death in judgement.\n     For even the very wise cannot see all ends.\n     -- Gandalf, The Fellowship of the Ring\n",
    "     The treacherous are ever distrustful.\n     -- Gandalf, The Two Towers\n",
    "     Let him not vow to walk in the dark, who has not seen the nightfall.\n     -- Elrond, The Fellowship of the Ring\n",
    "     He that breaks a thing to find out what it is has left the path of wisdom.\n     -- Gandalf, The Fellowship of the Ring\n",
    "     I was the herald of Gil-galad and marched with his host.\n     -- Elrond, The Fellowship of the Ring\n",
    "     I don't know half of you half as well as I should like;\n     and I like less than half of you half as well as you deserve.\n     -- Bilbo, The Fellowship of the Ring\n",
    "     The Company of the Ring shall be Nine;\n     and the Nine Walkers shall be set against the Nine Riders that are evil.\n     -- Elrond, The Fellowship of the Ring\n",
    "     You shall not pass!\n     -- Gandalf, The Fellowship of the Ring\n",
    "     Keep it secret, and keep it safe!\n     -- Gandalf, The Fellowship of the Ring\n",
    "     Small hands do them because they must, while the eyes of the great are elsewhere.\n     -- Elrond, The Fellowship of the Ring\n",
    "     I wish it need not have happened in my time.\n     -- Frodo, The Fellowship of the Ring\n",
    "     A hunted man sometimes wearies of distrust and longs for friendship.\n     -- Aragorn, The Fellowship of the Ring\n",
    "     The world is indeed full of peril, and in it there are many dark places.\n     -- Haldir, The Fellowship of the Ring\n",
    "     Someone else always has to carry on the story.\n     -- Bilbo, The Fellowship of the Ring\n",
    "     It is useless to meet revenge with revenge: it will heal nothing.\n     -- Frodo, The Return of the King\n",
    "     Despair is only for those who see the end beyond all doubt. We do not.\n     -- Gandalf, The Fellowship of the Ring\n",
    "     Speak, friend, and enter.\n     -- the West-gate of Moria, The Fellowship of the Ring\n",
    "     The wise speak only of what they know.\n     -- Gandalf, The Two Towers\n",
    "     Not all those who wander are lost.\n     -- Bilbo's verse, The Fellowship of the Ring\n",
    "     It's the deep breath before the plunge.\n     -- Gandalf, The Return of the King\n",
    "     There is nothing like looking, if you want to find something.\n     -- Thorin, The Hobbit\n",
    "     You certainly usually find something, if you look,\n     but it is not always quite the something you were after.\n     -- the narrator, The Hobbit\n",
    "     It does not do to leave a live dragon out of your calculations, if you live near him.\n     -- the narrator, The Hobbit\n",
    "     Never laugh at live dragons, Bilbo you fool!\n     -- Bilbo, The Hobbit\n",
    "     What has it got in its pocketses?\n     -- Gollum, The Hobbit\n",
    "     Thief, thief, thief! Baggins!\n     -- Gollum, The Hobbit\n",
    "     I am looking for someone to share in an adventure that I am arranging,\n     and it's very difficult to find anyone.\n     -- Gandalf, The Hobbit\n",
    "     We are plain quiet folk and have no use for adventures.\n     -- Bilbo, The Hobbit\n",
    "     In a hole in the ground there lived a hobbit.\n     -- the opening line, The Hobbit\n",
    "     Escaping goblins to be caught by wolves!\n     -- Bilbo, The Hobbit\n",
    "     Where there's life there's hope.\n     -- Bilbo, The Hobbit\n",
    "     Short cuts make long delays.\n     -- Pippin, The Fellowship of the Ring\n",
    "     It's a dangerous business, Frodo, going out your door.\n     -- Bilbo, The Fellowship of the Ring\n",
    "     The Road goes ever on and on\n     Down from the door where it began.\n     -- Bilbo's walking-song, The Fellowship of the Ring\n",
    "     Advice is a dangerous gift, even from the wise to the wise,\n     and all courses may run ill.\n     -- Gandalf, The Fellowship of the Ring\n",
    "     It is perilous to study too deeply the arts of the Enemy, for good or for ill.\n     -- Elrond, The Fellowship of the Ring\n",
    "     Always after a defeat and a respite, the Shadow takes another shape and grows again.\n     -- Gandalf, The Fellowship of the Ring\n",
    "     Faithless is he that says farewell when the road darkens.\n     -- Gimli, The Fellowship of the Ring\n",
    "     Do not meddle in the affairs of Wizards, for they are subtle and quick to anger.\n     -- Gildor, The Fellowship of the Ring\n",
    "     Go not to the Elves for counsel, for they will say both no and yes.\n     -- Frodo, The Fellowship of the Ring\n",
    "     Not idly do the leaves of Lorien fall.\n     -- Aragorn, The Two Towers\n",
    "     Strange are the turns of fortune! Often does hatred hurt itself!\n     -- Gandalf, The Two Towers\n",
    "     The burned hand teaches best.\n     After that advice about fire goes to the heart.\n     -- Gandalf, The Two Towers\n",
    "     Oft hope is born when all is forlorn.\n     -- Legolas, The Return of the King\n",
    "     Fly, you fools!\n     -- Gandalf, The Fellowship of the Ring\n",
    "     Well, I'm back.\n     -- Sam, The Return of the King\n",
    "     This tale grew in the telling.\n     -- Tolkien's foreword, The Fellowship of the Ring\n",
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
    pswdsalt = input("    \033[1;30mEnter salt [isengard.pork]:\033[1;m ") or "isengard.pork"
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
         \033[1;35m____                      .___        .__    _____  
        / ___\\ _____     ____    __| _/_____   |  | _/ ____\\ 
       / /_/  >\\__  \\   /    \\  / __ | \\__  \\  |  | \\   __\\  
       \\___  /  / __ \\_|   |  \\/ /_/ |  / __ \\_|  |__|  |    
      /_____/  (____  /|___|  /\\____ | (____  /|____/|__|    
                    \\/      \\/      \\/      \\/               \n\n{}\033[1;m
    """.format(
            random.choice(quotes)
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
            print(
                "\n    '/tmp/gandalf/' will now be \033[1;31mdeleted\033[1;m. Ensure you have collected '{}/{}.zip{}'".format(
                    gandalf_directory, hostlist[0], ext
                )
            )
            time.sleep(4)
            input("      Collected? [Yes] ")
            shutil.rmtree("/tmp/gandalf/")
        os.remove(ACQUIRE_SCRIPT)
    else:  # Remote
        if encryption_object == None:
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
            ssh_ip = input("     \033[1;30mIP address:\033[1;m ")
            ssh_user = input("     \033[1;30m  Username:\033[1;m ")
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
    print("      gandalf completed for:")
    for eachhost in hostlist:
        print("       - {}".format(eachhost))
    print("\n\n")


if __name__ == "__main__":
    main()
