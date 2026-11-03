#!/usr/bin/env python3 -tt
import argparse
import hashlib
import os
import sys
from datetime import datetime

# Set TERM environment variable to prevent warnings from subprocess commands
if 'TERM' not in os.environ:
    os.environ['TERM'] = 'xterm'

from rivendell.main import main
from rivendell.core.identify import process_deferred_memory, load_memory_profiles
from rivendell.mount import unmount_images, cleanup_stale_mounts
from rivendell.audit import write_audit_log_entry
from rivendell.post.clean import archive_artefacts
from rivendell.post.siem import SIEMUnavailableError, ensure_remote_siem_reachable


parser = argparse.ArgumentParser()
parser.add_argument("case", nargs=1, help="Investigation/Case/Incident Number")
parser.add_argument(
    "directory",
    nargs="+",
    help="Source directory where the artefact files are located; Optional: Provide a destination directory (default is current directory)",
)
parser.add_argument(
    "--Keywords",
    nargs=1,
    help="Search for keywords throughout image and artefacts based on provided Keyword File; Example syntax: --Keywords /path/to/keyword_file.txt",
)
parser.add_argument(
    "--Yara",
    nargs=1,
    help="Run Yara signatures against all files on disk image or just collected files; Example syntax: --Yara /path/to/directory_of_yara_files",
)
parser.add_argument(
    "--collectFiles",
    nargs="?",
    help="Collect files from disk including binaries, documents, scripts etc.; Optional: Provide an inclusion/exclusion file; Example syntax: --collectFiles include:/path/to/include_file.txt",
    const=True,
)
parser.add_argument(
    "--Analysis",
    help="Conduct 'automated forensic analysis' for disk artefacts; Extended Attributes; Alternate Data Streams; Timestomping",
    action="store_const",
    const=True,
    default=False,
)  # outstanding - Out-of-Sequence Windows-based file activity
parser.add_argument(
    "--Brisk",
    help="'Brisk Mode.' Invokes Analysis, extractIocs, Navigator, Process, and Userprofiles. You MUST provide either --Collect, --Gandalf, or --Mordor depending on your data source.",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--Collect",
    help="Collect artefacts from disk image (artefacts have NOT been collected seperately)",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--vss",
    help="Collect & process artefacts on Volume Shadow Copies (if available)",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--Delete",
    help="Delete raw data after processing",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--Elastic",
    help="Output data and index into local Elastic instance",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--Gandalf",
    help="Read artefacts acquired using gandalf",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--Mordor",
    help="Read artefacts from OTRF Mordor attack simulation datasets (pre-collected threat data)",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--extractIocs",
    help="Extract IOCs from processed files collected from disk; WARNING: This can take a long time!",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--iocsFile",
    nargs=1,
    help="IOC watchlist file to match against extracted IOCs; Example syntax: --iocsFile /path/to/iocs.txt",
)
parser.add_argument(
    "--threatIntel",
    nargs="+",
    metavar="FILE",
    help="Match the case against threat intelligence: the Iran APT workbook (XLSX), STIX 2.1 bundles "
    "(JSON), MITRESaw's mitre_procedures.csv, Rivendell's indicator CSV or a text watchlist; writes "
    "<host>/analysis/threat_intel_matches.csv and threat_groups.csv. Example: --threatIntel iran_apt.xlsx feed.json",
)
parser.add_argument(
    "--stackBaseline",
    nargs=1,
    metavar="FILE",
    help="A baseline of clean hosts for stacking (Analysis on a case of two or more hosts writes stacking.csv; rarity needs three of an OS); "
    "values absent from it score higher. Build one with python3 -m rivendell.analysis.stacking --baseline OUT CASE...",
)
parser.add_argument(
    "--misplacedBinaries",
    help="Find Windows system binaries in unexpected locations (MITRE ATT&CK T1036.005 - Masquerading: Match Legitimate Name or Location)",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--masquerading",
    help="Detect masquerading techniques: Right-to-Left Override, double file extensions, trailing spaces, renamed utilities (MITRE ATT&CK T1036)",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--Memory",
    help="Collect, process and analyse memory image using Volatility Framework",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--metacollected",
    help="Only hash artefacts which have been collected, processed & analysed (if applicable) and extract metadata from collected files (if applicable)",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--Navigator",
    help="Map identified artefacts to MITRE ATT&CK® navigator (a layer from mitre_techniques.txt)",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--nsrl",
    help="Compare hashes against known-goods from NSRL database; connection to Internet required",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--magicBytes",
    help="Verify file signatures against magic bytes",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--hashCollected",
    help="Hash only collected/processed artefacts and related metadata",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--hashAll",
    help="Hash all files on mounted image(s) and collected artefacts",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--Process",
    help="Process disk artefacts which have been collected",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--Splunk",
    help="Output data and index into local Splunk instance",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--symlinks",
    help="Copy contents of folders, including following full paths of symbolic links; WARNING: This can take a long time!",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--Timeline",
    help="Create Timeline of disk image using plaso; WARNING: This can take a VERY long time!",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--memorytimeline",
    help="Create Timeline of memory image using timeliner plugin; WARNING: This can take a long time!",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--Userprofiles",
    help="Collect user profile artefacts",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--eXhaustive",
    help="Exhaustive mode. Invoke all flags: Brisk, Delete, Elastic, Memory, nsrl, Splunk, Timeline, memorytimeline, and Ziparchive. You MUST provide either --Collect, --Gandalf, or --Mordor depending on your data source.",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--ThreatHunt",
    help="'Threat Hunt Mode.' Aggressive threat-hunting analysis. Invokes Analysis, extractIocs, Memory, Navigator, Process, Splunk, Elastic, and Userprofiles. Designed for comprehensive incident response and threat detection. You MUST provide either --Collect, --Gandalf, or --Mordor.",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "--Ziparchive",
    help="Archive raw data as zip after processing",
    action="store_const",
    const=True,
    default=False,
)

args = parser.parse_args()
directory = args.directory
case = args.case
analysis = args.Analysis
auto = True  # Always run in auto mode (non-interactive)
brisk = args.Brisk
collect = args.Collect
vss = args.vss
delete = args.Delete
elastic = args.Elastic
gandalf = args.Gandalf
collectfiles = args.collectFiles
extractiocs = args.extractIocs
iocsfile = args.iocsFile
threatintel = args.threatIntel or []
stackbaseline = args.stackBaseline[0] if args.stackBaseline else ""
misplaced_binaries = args.misplacedBinaries
masquerading = args.masquerading
keywords = args.Keywords
volatility = args.Memory
metacollected = args.metacollected
navigator = args.Navigator
nsrl = args.nsrl
magicbytes = args.magicBytes
process = args.Process
splunk = args.Splunk
symlinks = args.symlinks
timeline = args.Timeline
memorytimeline = args.memorytimeline
userprofiles = args.Userprofiles
yara = args.Yara
exhaustive = args.eXhaustive
threathunt = args.ThreatHunt
mordor = args.Mordor  # Input type flag for Mordor datasets
archive = args.Ziparchive

d = directory[0]
case = case[0]

# Validate case name length
if len(case) < 6:
    print(f"\n  Error: Case name must be at least 6 characters (got {len(case)})\n")
    sys.exit(1)
if len(case) > 30:
    print(f"\n  Error: Case name must be no longer than 30 characters (got {len(case)})\n")
    sys.exit(1)

cwd = os.getcwd()
hashcollected = args.hashCollected
hashall = args.hashAll
hashing_enabled = hashcollected or hashall

sha256 = hashlib.sha256() if hashing_enabled else None
allimgs = {}
flags = []
elrond_mount = [
    "/mnt/elrond_mount00",
    "/mnt/elrond_mount01",
    "/mnt/elrond_mount02",
    "/mnt/elrond_mount03",
    "/mnt/elrond_mount04",
    "/mnt/elrond_mount05",
    "/mnt/elrond_mount06",
    "/mnt/elrond_mount07",
    "/mnt/elrond_mount08",
    "/mnt/elrond_mount09",
    "/mnt/elrond_mount10",
    "/mnt/elrond_mount11",
    "/mnt/elrond_mount12",
    "/mnt/elrond_mount13",
    "/mnt/elrond_mount14",
    "/mnt/elrond_mount15",
    "/mnt/elrond_mount16",
    "/mnt/elrond_mount17",
    "/mnt/elrond_mount18",
    "/mnt/elrond_mount19",
]
ewf_mount = [
    "/mnt/ewf_mount00",
    "/mnt/ewf_mount01",
    "/mnt/ewf_mount02",
    "/mnt/ewf_mount03",
    "/mnt/ewf_mount04",
    "/mnt/ewf_mount05",
    "/mnt/ewf_mount06",
    "/mnt/ewf_mount07",
    "/mnt/ewf_mount08",
    "/mnt/ewf_mount09",
    "/mnt/ewf_mount10",
    "/mnt/ewf_mount11",
    "/mnt/ewf_mount12",
    "/mnt/ewf_mount13",
    "/mnt/ewf_mount14",
    "/mnt/ewf_mount15",
    "/mnt/ewf_mount16",
    "/mnt/ewf_mount17",
    "/mnt/ewf_mount18",
    "/mnt/ewf_mount19",
]
# to add new artefacts, include the directory or file in this list, and include it in process/select.py
system_artefacts = [
    "/",
    "/$MFT",
    "/$Extend/$UsnJrnl",
    "/$Extend/$ObjId",
    "/$Extend/$Reparse",
    "/$LogFile",
    "/$Recycle.Bin",
    "/Users/",
    "/Windows/AppCompat/Programs/RecentFileCache.bcf",
    "/Windows/AppCompat/Programs/Amcache.hve",
    "/Windows/inf/setupapi.dev.log",
    "/Windows/Prefetch/",
    "/Windows/System32/config/",
    "/Windows/System32/LogFiles/Sum/",
    "/Windows/System32/LogFiles/WMI/",
    "/Windows/System32/sru/",
    "/Windows/System32/wbem/Repository/",
    "/Windows/System32/wbem/Logs/",
    "/Windows/System32/winevt/Logs/",
    "/.Trashes",
    "/Library/Logs",
    "/Library/Preferences",
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
    "/Library/StartupItems",
    "/System/Library/LaunchDaemons",
    "/System/Library/StartupItems",
    "/boot",
    "/etc",
    "/etc/crontab",
    "/etc/group",
    "/etc/hosts",
    "/etc/passwd",
    "/etc/security",
    "/etc/shadow",
    "/home",
    "/root",
    "/tmp",
    "/usr/lib/systemd/user",
    "/var/cache/cups",
    "/var/log",
    "/var/log/journal",
    "/var/vm/sleepimage",
    "/var/vm/swapfile",
]
quotes = [
    "Not come the days of the King.\n     May they be blessed.",
    "If my old gaffer could see me now.",
    "I'll have no pointy-ear outscoring me!",
    "I think there is more to this hobbit, than meets the eye.",
    "You are full of surprises Master Baggins.",
    "One ring to rule them all, one ring to find them.\n     One ring to bring them all, and in the darkness bind them.",
    "The world is changed.\n     I feel it in the water.\n     I feel it in the earth.\n     I smell it in the air.",
    "Who knows? Have patience. Go where you must go, and hope!",
    "All we have to decide is what to do with the time that is given us.",
    "Deeds will not be less valiant because they are unpraised.",
    "It is not the strength of the body, but the strength of the spirit.",
    "But in the end it’s only a passing thing, this shadow; even darkness must pass.",
    "It’s the job that’s never started as takes longest to finish.",
    "Coward? Not every man's brave enough to wear a corset!",
    "Bilbo was right. You cannot see what you have become.",
    "He is known in the wild as Strider.\n     His true name, you must discover for yourself.",
    "Legolas said you fought well today. He's grown very fond of you.",
    "You will take NOTHING from me, dwarf.\n     I laid low your warriors of old.\n     I instilled terror in the hearts of men.\n     I AM KING UNDER THE MOUNTAIN!",
    "You've changed, Bilbo Baggins.\n     You're not the same Hobbit as the one who left the Shire...",
    "The world is not in your books and maps. It's out there.",
    "That is private, keep your sticky paws off! It's not ready yet!",
    "I wish you all the luck in the world. I really do.",
    "No. No. You can't turn back now. You're part of the company.\n     You're one of us.",
    "True courage is about knowing not when to take a life, but when to spare one.",
    "The treacherous are ever distrustful.",
    "Let him not vow to walk in the dark, who has not seen the nightfall.",
    "He that breaks a thing to find out what it is has left the path of wisdom.",
    "I was there, Gandalf.\n     I was there three thousand years ago, when Isildur took the ring.\n     I was there the day the strength of Men failed.",
    "I don't know half of you half as well as I should like,\n     and I like less than half of you half as well as you deserve.",
    "Certainty of death. Small chance of success.\n     What are we waiting for?",
    "Do not spoil the wonder with haste!",
    "It came to me, my own, my love... my... preciousssss.",
    "One does not simply walk into Mordor...",
    "Nine companions. So be it. You shall be the fellowship of the ring.",
    "You have my sword. You have my bow; And my axe!",
    "Build me an army, worthy of Mordor!",
    "Nobody tosses a Dwarf!",
    "If in doubt, Meriadoc, always follow your nose.",
    "This is beyond my skill to heal; he needs Elven medicine.",
    "No, thank you! We don't want any more visitors, well-wishers or distant relations!",
    "Mordor! I hope the others find a safer road.",
    "YOU SHALL NOT PASS!",
    "You cannot hide, I see you!\n     There is no life, after me.\n     Only!.. Death!",
    "A wizard is never late, Frodo Baggins.\n     Nor is he early.\n     He arrives precisely when he means to.",
    "Is it secret?! Is it safe?!",
    "Even the smallest person can change the course of the future.",
    "We must move on, we cannot linger.",
    "I wish the ring had never come to me. I wish none of this had happened.",
    "Moonlight drowns out all but the brightest stars.",
    "A hunted man sometimes wearies of distrust and longs for friendship.",
    "The world is indeed full of peril and in it there are many dark places.",
    "Someone else always has to carry on the story.",
    "Your time will come. You will face the same Evil, and you will defeat it.",
    "It is useless to meet revenge with revenge; it will heal nothing.",
    "Despair is only for those who see the end beyond all doubt. We do not.",
    "Anyways, you need people of intelligence on this sort of… mission… quest… thing.",
    "Oh, it’s quite simple. If you are a friend, you speak the password, and the doors will open.",
    "The wise speak only of what they know.",
    "Not all those who wander are lost.",
    "It's the deep breath before the plunge.",
]
asciitext = [
    "\n\n        \033[1;36mWelcome to Minas Tirith\n\n\n      |||            _.'   _      _.-. |        | |--\n     \\|||         _.'    -    _.-'  _|-|       -| |__\n      ||;-,    _.'   '-  _.-'' _.-''|  |-'      | `._\n     -'| / \\_,' _    _.-'   _.' |   |  |    -|  |\n     ----|,`   |  _.'   _.-' | ,| ,'| _| |      |_   \n        _:  _   ,'   .-'    _|/ \\ | | -|  _|_   | '\n       | |    ,'  .-'     , )|)-( |_|  |-       |    -\n     -   |  ,'  ,'(   `  /_\\||`.'   |- |   -|_  |\n     ___-| /  ,'   )     `.'||.-| _ | ||        | '-'\n     __( |;  /    / ,-    | ||  |/ \\|_ | _|    -|    \n       | :  ; ,-.-)       | ||  || ||  |   |_   |    _\n      _| | :/` _..\\  `-.  | ||__||_|;--;--------:  ,'`\n       | | |,-'  _/       |,-/\\_|  /__/__________\\::::\n       |-| |   ,' \\, ` ___|||||-|  |  |  _|_     ||___\n     _ | | | ,'   (   ;   :'''' /| ||_|       _  ||---\n     - | | |/     ;  /     :   : | |  |   _|_    ||---\n       | | |      |,'______|-..| | |_||      |  _||---\n       | | |      ||_      |   | | |_ |  -      -|----   \n     _|| | |      ;|-:  _  |   | |,|- |-   _|  _ |--,'\n       | | |______\\| |,' `.|`-.| |:|  | _|    |  |,','\n       |-| | ~   ~|| ||__|||! !| | ;--;----__---,','|\n       | | |,._,~_|:.||-'|||! !| |/__/____/\\_\\,','|\\|\n     -.| | ;     _.-'|| - ||`.!| ||  |    ||_|,'| | |,\n      || ;'|_,-''    -    - `.`| ||  | ___|| ||\\| |,',\n     , | | |    -     -     -  ) '|__||\\  || | \\|,','\n       ; | | -     -      -      |\\    \\\\ || |_,',' \n      /| | ;    -     -           \\\\    \\\\|| |','\n     / | |/                        \\\\    \\|| |' SSt\033[1;m",
    "\n\n        \033[1;36mWelcome to Bag End\n\n\n                        . .:.:.:.:. .:\\     /:. .:.:.:.:. ,\n                   .-._  `..:.:. . .:.:`- -':.:. . .:.:.,'  _.-.\n                  .:.:.`-._`-._..-''_...---..._``-.._.-'_.-'.:.:.\n               .:.:. . .:_.`' _..-''._________,``-.._ `.._:. . .:.:.\n            .:.:. . . ,-'_.-''      ||_-(O)-_||      ``-._`-. . . .:.:.\n           .:. . . .,'_.'           '---------'           `._`.. . . .:.\n         :.:. . . ,','               _________               `.`. . . .:.:\n        `.:.:. .,','            _.-''_________``-._            `._.     _.'\n      -._  `._./ /            ,'_.-'' ,       ``-._`.          ,' '`:..'  _.-\n     .:.:`-.._' /           ,','                   `.`.       /'  '  \\\\.-':.:.\n     :.:. . ./ /          ,','               ,       `.`.    / '  '  '\\\\. .:.: \n    :.:. . ./ /          / /    ,                      \\ \\  :  '  '  ' \\\\. .:.:\n    .:. . ./ /          / /            ,          ,     \\ \\ :  '  '  ' '::. .:.\n    :. . .: :    o     / /                               \\ ;'  '  '  ' ':: . .:\n    .:. . | |   /_\\   : :     ,                      ,    : '  '  '  ' ' :: .:.\n    :. . .| |  ((<))  | |,          ,       ,             |\\'__',-._.' ' ||. .:\n    .:.:. | |   `-'   | |---....____                      | ,---\\/--/  ' ||:.:.\n    ------| |         : :    ,.     ```--..._   ,         |''  '  '  ' ' ||----\n    _...--. |  ,       \\ \\             ,.    `-._     ,  /: '  '  '  ' ' ;;..._\n    :.:. .| | -O-       \\ \\    ,.                `._    / /:'  '  '  ' ':: .:.:\n    .:. . | |_(`__       \\ \\                        `. / / :'  '  '  ' ';;. .:.\n    :. . .<' (_)  `>      `.`.          ,.    ,.     ,','   \\  '  '  ' ;;. . .:\n    .:. . |):-.--'(         `.`-._  ,.           _,-','      \\ '  '  '//| . .:.\n    :. . .;)()(__)(___________`-._`-.._______..-'_.-'_________\\'  '  //_:. . .:\n    .:.:,' \\/\\/--\\/--------------------------------------------`._',;'`. `.:.:.\n    :.,' ,' ,'  ,'  /   /   /   ,-------------------.   \\   \\   \\  `. `.`. `..:\n    ,' ,'  '   /   /   /   /   //                   \\\\   \\   \\   \\   \\  ` `.SSt\033[1;m",
    "\n\n\n\n\n                                                \033[1;36m_______________________\n       _______________________-------------------                       `\\\n     /:--__                                                              |\n    ||< > |                                   ___________________________/\n    | \\__/_________________-------------------                         |\n    |                                                                  |\n     |                       THE LORD OF THE RINGS                      |\n     |                                                                  |\n     |      Three Rings for the Elven-kings under the sky,              |\n      |        Seven for the Dwarf-lords in their halls of stone,        |\n      |      Nine for Mortal Men doomed to die.                          |\n      |        One for the Dark Lord on his dark throne,                  |\n      |      In the Land of Mordor where the Shadows lie.                 |\n       |       One Ring to rule them all, One Ring to find them,          |\n       |       One Ring to bring them all and in the darkness bind them   |\n       |     In the Land of Mordor where the Shadows lie.                |\n      |                                              ____________________|_\n      |  ___________________-------------------------                      `\\\n      |/`--_                                                                 |\n      ||[ ]||                                            ___________________/\n       \\===/___________________--------------------------\033[1;m",
    "\n\n    ||                                ..........',:clooddddoolc:;''...   .......  .....'..'''||\n    ||                             ........'',;:clodxkkkkkkkkkxoc;,'............   ......''''||\n    ||                         ......',;,,;;:lddxxdxxxxxkkkkOOOkxdl:;'....... ...  ..........||\n    ||                      .....',;;;::;;:cloddoooodxxkkOOOOOOOOkkkxdolc;'...     ..........||\n    ||                  .....''',;;;;::c::;:ccllllodxxxxxxk0K000000OOkkkkxo:,'..     ........||\n    ||                ........',;,,;,,;:llclooooddxkkkxolokkxdk0Oxdxxdodddl:::,....  ........||\n    ||                ..........'''',,;;:cllddxkkOOOO00xox000KXX0xoolcccodocc:,'''......''''.||\n    ||               ...''....'''''.',;:coddxxkOOOOOOO0OxkO00K00Okdl:,'',;,';:cc;'.''....''..||\n    ||              ..........''''''';:cloxxkkkOOOOOO000KXXKKK00Okdol:,'..''...;:c'...''.....||\n    ||            ...'''''....',,;;;;;:cloxkkOOOOOOOO000KKKKKK00Okdooc;'...''....';,. .'''...||\n    ||            ..',,,,;;;;;;:::::::ccldxkkOOOOOOOO00KKKKKKK0OOxolc:;'....'.......'..','...||\n    ||            ..',,,;;;;;:::::::::clodkkOOOOOOOO0000KKKKKK00Okdl:;,'........... .........||\n    ||             .',;;;;::::::::::::cldxkkOOOOO0000000KKKXXKKKK0kdc;,''. ........    .....'||\n    ||             .',;;;:ccllcc::::cclodxkkkkkkOO000OOOO0KKKKKKKK0Oxc,'..   .......  ... .;;||\n    ||             ..,,;;:cllllc:::ccllodxxxxxxxxxxxdodxkO0KKKXKKKK0Oo;...    ......';:oo;...||\n    ||             ..',;;:cllllc::cclllooddollc:::cldxOO0000KKKKKKKK0x:'..    .....,codxkx:. ||\n    ||             .',,;;::cclll::clllllc::,'''',:oxOO0000000KKKKKKKKkl,...   .....,;;:okOd'.||\n    ||             ...',;::::clcc:::c:;,''..'''',,;:cldxkO0000KKKXKKKOo:...   ...'.,,;:cdkk;.||\n    ||            .......',;;:::::::::;;;,'''.......,:ccldxkO0KKXXXK0Odc'.    ...',;;:cldOk;.||\n    ||             .....  .....';clddxdlc;,,'',,,'',:loxOOOO00KKXXXKOkdc'........',,;;:lxOd' ||\n    ||              ...    .....;cok00Oxdoc;,,,,,,;:cldkO0000KKKKXK0Okoc,......'..',,;:okOc. ||\n    ||                ......','';ldOKKK0Okoc::::::ccloxkO0000KXXXKKOkdo:,..',..'..',;:lxko.. ||\n    ||                 ....'',',:lx0XXXXKK0kxoccccloodkOOOOO00KKKK0kxdl:'...'.....';ldkko'  .||\n    ||                 ..''',,,;cxOKXXXXXXXK0OxxdoooodxkkOOO000000Okxdl;'.........,:dOOd'   .||\n    ||                 ...',,,,:ok0KXXXXKXXXK000OkkkxdxxkkOOO00OOOOkxoc;'.........';oko'     ||\n    ||                 .,,,,,,;cok0KKKXK00000OOOOOOOOkkkkOOOOOOOOOkxdoc;,.........';l:..     ||\n    ||                 .,,,,,,;cdO000KKK00K0OdddxkkOOOOOOOO000OOOkxddl:;'...... ..';c;.      ||\n    ||                 .',,,,,,:lxkOxxxdoxO0OxllloxkkOOOO00000OOOkxdol:;'.....  ..':o:.      ||\n    ||                  .',,,,''',:lllllccdkOxdoooodxkOOO00000OOkxdolc:,'.....  ..,cxc.      ||\n    ||                   .''',,'...,:cdkxxkkkkxxxxddxkOO00000OOOkxdolc;,......  ..,oko'      ||\n    ||                   ...',,,''';::ldxxxxxkkkkkkkxxxkOO000OOOkxolc:;'......  ..;xkd,      ||\n    ||                    ..'',,'',:c;:ldxxxxkkOOkkkkkxxkOOOOOkkkdlc:;,'.....   ..:xkk:.     ||\n    ||                     ..''',,,:c::cllloooddddoodxkkkOOOOkkxxol:;,,'''...   ..ckOkl.   ..||\n    ||                      .''',,,,,,,;;;::cloolllcclodxkOOOkxddlc:;,,,;,..    ..:xxdc'..;ld||\n    ||                      ..''..''',;:cloodxkkkkkkxdooodxxkxddolc;,,;:c:..    .';lollodkkkx||\n    ||                       ..'''',,;;:cclloooddddxxddooodxxdddol:;;::clc,.  ...';ldkkkkkxoc||\n    ||                       .....',,;;;;;;::cccclloooooodxxxxdolc:::cclc:;......'coxkOkxoc;'||\n    ||                    ...''....',,,;;;;::clccclllllloodxxdolc::::c:::;;'.....,ldxxxdl:,..||\n    || .':lcc;,''',,;:cllloddxko:'..'',;::ccloddddoodoooooooolc:;;;;;;,;;;;,.....:oddooc;,.. ||\n    ||.:xO0KKK00OOOOOOOOOOkkkkO00Odc,',;:cccloddxxxxddooolcc:;;;,,,'',;:::cc:...'collcc;'..  ||\n    ||'lxO0KKKKKK0000000000OkOO00000kl:;;::::cllooddddoolc:;;,,,''',,;::clool,...;:cc:;'.. ..||\n    ||;lxO0KXXXXKKKK0000000OOO0KXKOkOOkdoc;;;;:::cclllc:::;,,''.',;::::cllooc.   .'::,...... ||\n    ||:ok0KKKKKKKKKKKKKKKK0OO0KXXNXOxdkOOkdlc;;,,,,,,,,,,,'''..',:ccccclooo:..    .,'......  ||\n    ||cdkO00KKKKKKKKKK0000OO0KXKKXNX0dldxkkOkxl:,.............',:cccclool:,..'.  .''......   ||\n    ||cdxkOOOO0KKKKKKK0O0K0kkKXXK00XNKd::clodxoc,.............':cccllooo;. ......,,'......   ||\n    ||coxxk00OkxxxxkkOOO0KK0kk0XXKOOKKKxlcloddol;. .......'''',:ccloooooc'.......'''.....    ||\n    ||loodk000Oxc'',,,cdk0KXKkk0KX0xxOO00kdol:'...........'''':ccloooololc;'....''......    .||\n    ||loodxOOxl,.......,cdO0K0kxOKXOooxO00x;... ...........'',cclloollllllc:..'''..'..       ||",
]


if __name__ == "__main__":
    # Gandalf archives and Mordor datasets are collected already: the presets below only
    # switch on collection options (user profiles, the disk timeline) when there's a disk
    # to collect from. Asked for by name, they still fail the check in main().
    precollected = gandalf or mordor
    if exhaustive:
        brisk = True
        delete = True
        elastic = True
        volatility = True
        nsrl = True
        splunk = True
        timeline = timeline or not precollected
        memorytimeline = True
        archive = True
    if brisk:
        analysis = True
        auto = True
        # vss = True  # Don't override VSS - respect command line flag
        # extractiocs = True  # Don't override extractIocs - respect command line flag
        magicbytes = True  # File signature mismatch detection
        metacollected = True
        # navigator stays off in brisk mode: it needs the siem profile's Navigator running
        process = True
        userprofiles = userprofiles or not precollected
    if threathunt:
        # Threat Hunt Mode: Aggressive threat-hunting analysis
        analysis = True
        auto = True
        extractiocs = True
        volatility = True  # Memory analysis
        metacollected = True
        navigator = True
        process = True
        splunk = True
        elastic = True
        userprofiles = userprofiles or not precollected
    if mordor:
        # Mordor input type: Treat like Gandalf (pre-collected artefacts)
        # Mordor datasets are pre-collected attack simulation data from OTRF
        gandalf = True  # Mordor datasets behave like Gandalf-collected artefacts

    # Check SIEM reachability before mounting/processing so a missing SIEM fails
    # the job up front rather than being swallowed hours later in the export phase
    try:
        ensure_remote_siem_reachable(splunk, elastic)
    except SIEMUnavailableError as e:
        print(f"\n  Error: {e}\n")
        sys.exit(1)

    # Process mode is always enabled - it's the core analysis functionality
    process = True

    veryverbose = True
    verbose = True

    # Create verbosity string from verbose flags (same logic as main.py)
    if (veryverbose and verbose) or veryverbose:
        verbosity = "veryverbose"
    elif verbose:
        verbosity = "verbose"
    else:
        verbosity = ""

    # Handle multiple source images
    # Format: case source1 [source2 ... sourceN] [destination]
    # Detect if paths are image files by extension
    IMAGE_EXTENSIONS = ('.e01', '.E01', '.vmdk', '.VMDK', '.dd', '.DD', '.raw', '.RAW', '.img', '.IMG', '.001')

    def is_image_file(path):
        """Check if a path is a disk/memory image file by extension."""
        return any(path.endswith(ext) for ext in IMAGE_EXTENSIONS)

    if len(directory) >= 2:
        # Check if the last path is an image file or a directory
        last_path = directory[-1]
        if is_image_file(last_path):
            # All paths are image files - use current directory as destination
            sources = directory
            destination = None
        else:
            # Last path is not an image file - treat it as destination
            sources = directory[:-1]
            destination = last_path
    else:
        sources = directory  # Single source
        destination = None  # Will default to "./" in main()

    # Phased multi-image processing:
    # Phase 1: Mount all images (mount img1, mount img2, mount img3)
    # Phase 2: Collect from all images (collect img1, collect img2, collect img3)
    # Phase 3: Process all images (process img1, process img2, process img3)

    # Store mounted image data for each source
    mounted_data = {}
    failed_sources = []

    # =========================================================================
    # CLEANUP: Unmount any stale mounts from previous runs
    # =========================================================================
    print("\n  -> Cleaning up stale mounts from previous runs...")
    cleanup_stale_mounts(elrond_mount.copy(), ewf_mount.copy())

    # =========================================================================
    # PHASE 1: Mount all images
    # =========================================================================
    print("\n  -> \033[1;36mCommencing Identification Phase...\033[1;m\n  ----------------------------------------")

    for idx, source in enumerate(sources):
        print(f"\n  [{idx + 1}/{len(sources)}] Mounting: {source}\n")

        # Create directory array for this source
        if destination:
            source_directory = [source, destination]
        else:
            source_directory = [source]

        # Reset state for this image
        source_allimgs = {}
        source_sha256 = hashlib.sha256() if hashcollected or hashall else None
        source_flags = []

        # Call main with phase="mount" to just mount the image
        # skip_unmount=True so we don't unmount previous images
        # main() exits when a source has nothing it can mount (E9); the other sources go on
        try:
            result = main(
                source_directory,
                case,
                analysis,
                auto,
                collect,
                vss,
                delete,
                elastic,
                gandalf,
                collectfiles,
                extractiocs,
                iocsfile,
                misplaced_binaries,
                masquerading,
                keywords,
                volatility,
                metacollected,
                navigator,
                nsrl,
                magicbytes,
                hashall,
                hashcollected,
                process,
                splunk,
                symlinks,
                timeline,
                memorytimeline,
                userprofiles,
                veryverbose,
                verbose,
                yara,
                archive,
                source,
                cwd,
                source_sha256,
                source_allimgs,
                source_flags,
                elrond_mount,
                ewf_mount,
                system_artefacts,
                quotes,
                asciitext,
                skip_unmount=(idx > 0),  # Don't unmount after first image
                phase="mount",
            )
        except SystemExit as e:
            if e.code != 2:  # 2: nothing in this source mounted; anything else ends the run
                raise
            failed_sources.append(source)
            result = None

        # Store the mounted image data for later phases
        if result:
            allimgs, imgs, output_directory, partitions = result
            mounted_data[source] = {
                "allimgs": allimgs,
                "imgs": imgs,
                "output_directory": output_directory,
                "partitions": partitions,
                "source_directory": source_directory,
                "source_sha256": source_sha256,
                "source_flags": source_flags,
            }
            print(f"  -> Mounted: {len(imgs)} image(s) from {source}")

    if not mounted_data:
        print("\n   ERROR: nothing could be mounted from {}\n".format(", ".join(failed_sources) or "the sources"), flush=True)
        sys.exit(2)
    print("\n  ----------------------------------------\n  -> Completed Identification Phase.\n")
    print("\n  -> \033[1;36mCommencing Collection Phase...\033[1;m\n  ----------------------------------------")

    for idx, source in enumerate(sources):
        if source not in mounted_data:
            print(f"\n  [{idx + 1}/{len(sources)}] Skipping {source} (not mounted)")
            continue

        print(f"\n  [{idx + 1}/{len(sources)}] Collecting from: {source}\n")

        data = mounted_data[source]

        # Call main with phase="collect" to collect artefacts
        result = main(
            data["source_directory"],
            case,
            analysis,
            auto,
            collect,
            vss,
            delete,
            elastic,
            gandalf,
            collectfiles,
            extractiocs,
            iocsfile,
            misplaced_binaries,
            masquerading,
            keywords,
            volatility,
            metacollected,
            navigator,
            nsrl,
            magicbytes,
            hashall,
            hashcollected,
            process,
            splunk,
            symlinks,
            timeline,
            memorytimeline,
            userprofiles,
            veryverbose,
            verbose,
            yara,
            archive,
            source,
            cwd,
            data["source_sha256"],
            data["allimgs"],
            data["source_flags"],
            elrond_mount,
            ewf_mount,
            system_artefacts,
            quotes,
            asciitext,
            skip_unmount=True,  # Don't unmount - images are still mounted
            phase="collect",
            mounted_imgs=data,
        )

        # Update mounted data with any changes from collection phase
        if result:
            allimgs, imgs, output_directory, partitions = result
            mounted_data[source]["allimgs"] = allimgs
            mounted_data[source]["imgs"] = imgs
            print(f"  -> Collection complete for {source}")

    print("\n  ----------------------------------------\n  -> Completed Collection Phase.\n")
    print("\n  -> \033[1;36mCommencing Processing Phase...\033[1;m\n  ----------------------------------------")

    for idx, source in enumerate(sources):
        if source not in mounted_data:
            print(f"\n  [{idx + 1}/{len(sources)}] Skipping {source} (not mounted)")
            continue

        print(f"\n  [{idx + 1}/{len(sources)}] Processing: {source}\n")

        data = mounted_data[source]

        # Call main with phase="process" to process artefacts
        # This also handles analysis, MITRE tagging, Splunk, Elastic, cleanup, etc.
        try:
            print(f"[DEBUG-ELROND] About to call main() for process phase", flush=True)
            main(
                data["source_directory"],
                case,
                analysis,
                auto,
                collect,
                vss,
                delete,
                elastic,
                gandalf,
                collectfiles,
                extractiocs,
                iocsfile,
                misplaced_binaries,
                masquerading,
                keywords,
                volatility,
                metacollected,
                navigator,
                nsrl,
                magicbytes,
                hashall,
                hashcollected,
                process,
                splunk,
                symlinks,
                timeline,
                memorytimeline,
                userprofiles,
                veryverbose,
                verbose,
                yara,
                archive,
                source,
                cwd,
                data["source_sha256"],
                data["allimgs"],
                data["source_flags"],
                elrond_mount,
                ewf_mount,
                system_artefacts,
                quotes,
                asciitext,
                skip_unmount=True,  # Don't unmount between processing
                phase="process",
                mounted_imgs=data,
            )
            print(f"[DEBUG-ELROND] main() returned successfully for process phase", flush=True)
        except Exception as e:
            import traceback
            import sys
            print(f"\n{'='*70}", flush=True)
            print(f"UNCAUGHT EXCEPTION IN main() PROCESS PHASE!", flush=True)
            print(f"Exception Type: {type(e).__name__}", flush=True)
            print(f"Exception Message: {e}", flush=True)
            print(f"{'='*70}", flush=True)
            print(f"Source: {source}", flush=True)
            print(f"\nFULL TRACEBACK WITH ALL FRAMES:", flush=True)
            print(f"{'='*70}", flush=True)
            traceback.print_exc(file=sys.stdout)
            print(f"{'='*70}", flush=True)
            print(f"\nLocal variables at this level:", flush=True)
            print(f"  verbose = {repr(verbose)}", flush=True)
            print(f"  veryverbose = {repr(veryverbose)}", flush=True)
            print(f"  'verbosity' in locals() = {'verbosity' in locals()}", flush=True)
            print(f"{'='*70}\n", flush=True)
            raise

        print(f"  -> Processing complete for {source}")

    # ========== PHASE 3b: DEFERRED MEMORY PROCESSING ==========
    # Process any memory images that were identified during the identification phase
    # This runs ONCE after all disk images are processed
    has_deferred_memory = bool(load_memory_profiles(output_directory))
    if volatility or has_deferred_memory:
        process_deferred_memory(
            verbosity,
            output_directory,
            [],  # flags - not used in deferred processing
            "/mnt/elrond_mount00",  # mount point for symbol table extraction
        )

    print("\n  ----------------------------------------\n  -> Completed Processing Phase.\n")

    # ========== PHASE 4: ANALYSE ALL IMAGES ==========
    print("\n  -> \033[1;36mCommencing Analysis Phase...\033[1;m\n  ----------------------------------------", flush=True)

    for idx, source in enumerate(sources):
        if source not in mounted_data:
            print(f"  -> [{idx + 1}/{len(sources)}] Skipping {source} (not mounted)", flush=True)
            continue

        print(f"  -> [{idx + 1}/{len(sources)}] Analysing: {source}", flush=True)

        data = mounted_data[source]

        # Call main with phase="analyse" to run keywords, analysis, timeline, metadata, YARA
        try:
            main(
                data["source_directory"],
                case,
                analysis,
                auto,
                collect,
                vss,
                delete,
                elastic,
                gandalf,
                collectfiles,
                extractiocs,
                iocsfile,
                misplaced_binaries,
                masquerading,
                keywords,
                volatility,
                metacollected,
                navigator,
                nsrl,
                magicbytes,
                hashall,
                hashcollected,
                process,
                splunk,
                symlinks,
                timeline,
                memorytimeline,
                userprofiles,
                veryverbose,
                verbose,
                yara,
                archive,
                source,
                cwd,
                data["source_sha256"],
                data["allimgs"],
                data["source_flags"],
                elrond_mount,
                ewf_mount,
                system_artefacts,
                quotes,
                asciitext,
                skip_unmount=True,
                phase="analyse",
                mounted_imgs=data,
            )
            print(f"  -> Analysis complete for {source}", flush=True)
        except Exception as e:
            import traceback
            print(f"  -> ERROR during analysis of {source}: {str(e)}", flush=True)
            print(f"     Traceback: {traceback.format_exc()}", flush=True)
            print(f"  -> Continuing to next source...", flush=True)

    print("\n  ----------------------------------------\n  -> Completed Analysis Phase.\n", flush=True)

    # ========== PHASE 4b: THREAT INTELLIGENCE (the whole case at once) ==========
    if threatintel and mounted_data:
        print("\n  -> \033[1;36mCommencing Threat Intelligence Phase...\033[1;m\n  ----------------------------------------", flush=True)
        try:
            from rivendell.threat_intel import load_all
            from rivendell.threat_intel.match import match_case

            indicators = load_all(threatintel)
            print(f"     Loaded {len(indicators)} indicators from {len(threatintel)} file(s)", flush=True)
            totals = match_case(output_directory, indicators, log=lambda m: print(f"     {m}", flush=True))
            entry, prnt = "{},{},threat intelligence,{} indicators; {} elements matched; {} iocs; {} groups; {} of Gandalf's own records left out\n".format(
                datetime.now().isoformat(), case, totals["indicators"], totals["elements"], totals["iocs"], totals["groups"],
                totals["collector"],
            ), " -> {} -> matched the case against {} threat intelligence indicators: {} elements found".format(
                datetime.now().isoformat().replace("T", " "), totals["indicators"], totals["elements"]
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
        except (OSError, ValueError) as e:
            print(f"  -> WARNING: threat intelligence matching failed: {e}", flush=True)
        print("  ----------------------------------------\n  -> Completed Threat Intelligence Phase.\n", flush=True)

    # ========== PHASE 4c: STACKING (least frequency of occurrence across hosts) ==========
    if analysis and mounted_data:
        try:
            from rivendell.analysis.stacking import stack_case

            stacked = stack_case(output_directory, stackbaseline)
            if stacked is None:
                print("     Stacking skipped: it compares hosts, and this case has one", flush=True)
            else:
                entry, prnt = "{},{},stacking,{} hosts; {} values; {} rare\n".format(
                    datetime.now().isoformat(), case, stacked["hosts"], stacked["values"], stacked["rows"]
                ), " -> {} -> stacked {} values across {} hosts: {} rare, in stacking.csv".format(
                    datetime.now().isoformat().replace("T", " "), stacked["values"], stacked["hosts"], stacked["rows"]
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
        except (OSError, ValueError, KeyError) as e:
            print(f"  -> WARNING: stacking failed: {e}", flush=True)

    # ========== PHASE 5: SIEM INDEXING (Splunk/Elastic/Navigator) ==========
    if splunk or elastic:
        # Build phase name based on selected SIEM tools
        siem_tools = []
        if splunk:
            siem_tools.append("Splunk")
        if elastic:
            siem_tools.append("Elastic")
        if navigator:
            siem_tools.append("Navigator")
        siem_phase_name = " & ".join(siem_tools) if siem_tools else "SIEM"

        print(f"\n  -> \033[1;36mCommencing {siem_phase_name} Phase...\033[1;m\n  ----------------------------------------")

        for idx, source in enumerate(sources):
            if source not in mounted_data:
                print(f"\n  [{idx + 1}/{len(sources)}] Skipping {source} (not mounted)")
                continue

            print(f"\n  [{idx + 1}/{len(sources)}] Indexing to {siem_phase_name}: {source}\n")

            data = mounted_data[source]

            # Call main with phase="index" to run Splunk/Elastic/Navigator indexing
            main(
                data["source_directory"],
                case,
                analysis,
                auto,
                collect,
                vss,
                delete,
                elastic,
                gandalf,
                collectfiles,
                extractiocs,
                iocsfile,
                misplaced_binaries,
                masquerading,
                keywords,
                volatility,
                metacollected,
                navigator,
                nsrl,
                magicbytes,
                hashall,
                hashcollected,
                process,
                splunk,
                symlinks,
                timeline,
                memorytimeline,
                userprofiles,
                veryverbose,
                verbose,
                yara,
                archive,
                source,
                cwd,
                data["source_sha256"],
                data["allimgs"],
                data["source_flags"],
                elrond_mount,
                ewf_mount,
                system_artefacts,
                quotes,
                asciitext,
                skip_unmount=True,
                phase="index",
                mounted_imgs=data,
            )

            # Note: Indexing completion messages are handled by main.py with proper image names

        print(f"\n  ----------------------------------------\n  -> Completed {siem_phase_name} Phase.\n")

    # ========== PHASE 6: ARCHIVE (if requested) ==========
    if archive and mounted_data:
        # Get output directory from first mounted image
        first_source = next(iter(mounted_data))
        output_directory = mounted_data[first_source]["output_directory"]
        verbosity = veryverbose

        archive_artefacts(verbosity, output_directory)

    print("\n" + "=" * 60)
    print("  ALL PHASES COMPLETE")
    print("=" * 60 + "\n")

    # Cleanup: unmount all images
    print("  -> Unmounting images...")
    unmount_images(elrond_mount, ewf_mount)
    print("  -> Cleanup complete.\n")
