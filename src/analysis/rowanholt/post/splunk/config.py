#!/usr/bin/env python3 -tt
import getpass
import os
import re
import subprocess
import time
from datetime import datetime
from collections import OrderedDict
from tarfile import TarFile

from rowanholt.audit import write_audit_log_entry
from rowanholt.utils import safe_input
from rowanholt.post.splunk.app.app import build_app_elrond
from rowanholt.post.splunk.ingest import ingest_splunk_data
from rowanholt.post.siem import memory_outputs, siem_hosts

# Try to import Splunk apps - they may not be installed
try:
    from rowanholt.post.splunk.apps.geolocate import build_app_geolocate
    from rowanholt.post.splunk.apps.lookup import build_app_lookup
    from rowanholt.post.splunk.apps.punchcard import build_app_punchcard
    from rowanholt.post.splunk.apps.sankey import build_app_sankey
    from rowanholt.post.splunk.apps.topology import build_app_topology
    from rowanholt.post.splunk.apps.treemap import build_app_treemap
except ImportError:
    build_app_geolocate = None
    build_app_lookup = None
    build_app_punchcard = None
    build_app_sankey = None
    build_app_topology = None
    build_app_treemap = None



# Where the Splunk container sees the output, as docker-compose.yml mounts it into the
# splunk service (the same paths as the worker's)
DEFAULT_MONITOR_ROOTS = "/tmp/elrond/output,/Volumes"


def monitor_roots():
    """The paths the Splunk container mounts: SPLUNK_MONITOR_ROOTS, comma-separated."""
    roots = os.environ.get("SPLUNK_MONITOR_ROOTS", DEFAULT_MONITOR_ROOTS)
    return [os.path.normpath(r.strip()) for r in roots.split(",") if r.strip()]


def splunk_can_see(path):
    """Whether a worker path is inside one of the Splunk container's mounts."""
    path = os.path.normpath(path)
    return any(path == root or path.startswith(root.rstrip("/") + "/") for root in monitor_roots())

def splunk_service(splunk_install_path, action):
    subprocess.Popen(
        ["/" + splunk_install_path + "splunk/bin/./splunk", action],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()


def overwrite_splunk_index(
    verbosity, output_directory, case, stage, allimgs, splunk_install_path
):
    indxq = safe_input(
        "    Index {} already exists, would you like to overwrite the existing index or create a new index? [O]verwrite/[n]ew O ".format(
            case
        ),
        default="O"
    )
    if indxq != "n":
        splkindx = str(
            subprocess.Popen(
                ["./splunk", "remove", "index", case],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()
        )
    else:
        case = safe_input("    Name of new index: ", default="").strip("\n")
    for _, everyimg in allimgs.items():
        entry, prnt = "{},{},adding {} index {}, {}".format(
            datetime.now().isoformat(),
            stage,
            stage,
            case,
            everyimg.split("::")[0],
        ), " -> {} -> adding {} index {} for '{}'".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            case,
            everyimg.split("::")[0],
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        splkindx = str(
            subprocess.Popen(
                [
                    "/" + splunk_install_path + "splunk/bin/./splunk",
                    "add",
                    "index",
                    case,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()[0]
        )
        if len(splkindx[2:-1]) == 0 or splkindx[2:-3] == 'Index "' + case + '" added.':
            if len(splkindx[2:-1]) == 0:
                print("    Splunk index '{}' already exists...".format(case))
                overwrite_splunk_index(
                    verbosity,
                    output_directory,
                    case,
                    stage,
                    allimgs,
                    splunk_install_path,
                )
            elif splkindx[2:-3] == 'Index "' + case + '" added.':
                print("    Splunk index created for '{}'...".format(case))
        else:
            print(
                "    Splunk index creation failed for '{}'.\n    Please try again.".format(
                    case
                )
            )
            overwrite_splunk_index(
                verbosity, output_directory, case, stage, allimgs, splunk_install_path
            )


def install_splunk_stack(
    verbosity,
    output_directory,
    case,
    stage,
    allimgs,
    splunk_deb_file,
    splunk_install_path,
):
    def verify_splunk_password(request_password, splunk_install_path):
        try:
            vrfypswd = subprocess.Popen(
                [
                    "/" + splunk_install_path + "splunk/bin/./splunk",
                    "validate-passwd",
                    request_password,
                    "--accept-license",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()[1]
        except:
            print(
                "\n     It looks like you have a corrupt Splunk installation - neither installed or uninstalled.\n     You may have a Splunk process still running from an unclean install. Remove all traces of Splunk and try again.\n"
            )
        if not str(vrfypswd) == "b''":
            request_password = getpass.getpass(
                "     -> Password did not meet complexity requirements...\n       * Password must contain at least 8 printable ASCII characters\n       Splunk admin password: "
            )
            verify_splunk_password(request_password, splunk_install_path)

    subprocess.Popen(
        ["dpkg", "-i", splunk_deb_file],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    subprocess.Popen(
        ["updatedb"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).communicate()
    requser, request_password = safe_input("       Splunk admin username: ", default=""), getpass.getpass(
        "       * Password must contain at least 8 printable ASCII character(s)\n       Splunk admin password: "
    )
    verify_splunk_password(request_password, splunk_install_path)
    pswdhash = subprocess.Popen(
        [
            "/" + splunk_install_path + "splunk/bin/./splunk",
            "hash-passwd",
            request_password,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()[0]
    with open(
        "/" + splunk_install_path + "splunk/etc/system/local/user-seed.conf", "w"
    ) as splunkuserfile:
        splunkuserfile.write(
            f"[user_info]\nUSERNAME = {requser}\nHASHED_PASSWORD = {str(pswdhash)[2:-3]}"
        )
    subprocess.Popen(
        [
            "/" + splunk_install_path + "splunk/bin/./splunk",
            "start",
            "--accept-license",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    splunk_service(splunk_install_path, "stop")
    if "already exists" in str(
        subprocess.Popen(
            ["/" + splunk_install_path + "splunk/bin/./splunk", "add", "index", case],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()[0]
    ):
        overwrite_splunk_index(
            verbosity, output_directory, case, stage, allimgs, splunk_install_path
        )
    print("     Splunk installed successfully.")
    return requser, request_password


def configure_splunk_stack(verbosity, output_directory, case, stage, allimgs):
    # Check if we're using remote Splunk (containerized environment)
    splunk_host = os.environ.get('SPLUNK_HOST', '')
    splunk_port = os.environ.get('SPLUNK_PORT', '8089')
    use_remote_splunk = bool(splunk_host)

    if use_remote_splunk:
        # Remote Splunk mode - containerized/external Splunk instance
        splunkuser = os.environ.get('SPLUNK_USERNAME', 'admin')
        splunkpswd = os.environ.get('SPLUNK_PASSWORD', '')

        # Get the first image name for audit logging
        first_img = list(allimgs.values())[0].split("::")[0] if allimgs else "unknown"

        if not splunkpswd:
            from rowanholt.audit import write_audit_log_entry
            entry, prnt = "{},{},remote splunk configured but SPLUNK_PASSWORD not set for '{}'".format(
                datetime.now().isoformat(),
                "splunk",
                first_img,
            ), " -> {} -> remote splunk configured but SPLUNK_PASSWORD environment variable not set for '{}'".format(
                datetime.now().isoformat().replace("T", " "),
                first_img
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            print("\n     ERROR: SPLUNK_PASSWORD environment variable not set for remote Splunk")
            return None, None

        print(
            "\n\n  -> \033[1;36mCommencing Splunk Phase (Remote Mode)...\033[1;m\n  ----------------------------------------"
        )
        from rowanholt.audit import write_audit_log_entry

        # Remote Splunk uses shared volume at /opt/splunk/etc
        remote_splunk_path = "opt/"

        # Step 1: Deploy elrond app to shared volume
        print("     Deploying elrond Splunk app...")
        try:
            if not os.path.isdir("/" + remote_splunk_path + "splunk/etc/apps/elrond/"):
                build_app_elrond(case, remote_splunk_path)
                print("     elrond app deployed successfully")
            else:
                print("     elrond app already exists, updating for case '{}'...".format(case))
                # Update nav menu with new case
                nav_file = "/" + remote_splunk_path + "splunk/etc/apps/elrond/default/data/ui/nav/default.xml"
                if os.path.exists(nav_file):
                    with open(nav_file) as default_nav:
                        default_nav_xml = default_nav.read()
                        if case not in default_nav_xml:
                            insert_new_case = re.sub(
                                r"([\S\s]+<collection label=\"Cases\">)(\n\s+<view source=\"all\" match=\")([^\"]+)(\" />)([\S\s]+)",
                                r"\1\2§±§±§±§\4\2\3\4\5",
                                default_nav_xml,
                            )
                            insert_new_case = insert_new_case.replace("§±§±§±§", case)
                            with open(nav_file, "w") as new_default_nav:
                                new_default_nav.write(insert_new_case + "\n")
        except Exception as e:
            print("     WARNING: Could not deploy elrond app: {}".format(e))

        # Step 2: Deploy dependency apps if available
        print("     Deploying Splunk dependency apps...")
        try:
            if build_app_geolocate:
                build_app_geolocate(remote_splunk_path)
            if build_app_lookup:
                build_app_lookup(remote_splunk_path)
            if build_app_punchcard:
                build_app_punchcard(remote_splunk_path)
            if build_app_sankey:
                build_app_sankey(remote_splunk_path)
            if build_app_topology:
                build_app_topology(remote_splunk_path)
            if build_app_treemap:
                build_app_treemap(remote_splunk_path)
            print("     Dependency apps deployed")
        except Exception as e:
            print("     WARNING: Some dependency apps could not be deployed: {}".format(e))

        # Step 3: Create index via REST API
        print("     Creating Splunk index '{}' via REST API...".format(case))
        try:
            import urllib.request
            import urllib.parse
            import ssl

            # Create SSL context that doesn't verify certificates (for self-signed)
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            # Create index
            index_url = "https://{}:{}/services/data/indexes".format(splunk_host, splunk_port)
            index_data = urllib.parse.urlencode({'name': case}).encode('utf-8')

            # Create request with basic auth
            req = urllib.request.Request(index_url, data=index_data, method='POST')
            credentials = '{}:{}'.format(splunkuser, splunkpswd)
            import base64
            encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
            req.add_header('Authorization', 'Basic {}'.format(encoded_credentials))

            try:
                response = urllib.request.urlopen(req, context=ssl_context, timeout=30)
                print("     Index '{}' created successfully".format(case))
            except urllib.error.HTTPError as e:
                if e.code == 409:
                    print("     Index '{}' already exists".format(case))
                else:
                    print("     WARNING: Could not create index: {} {}".format(e.code, e.reason))
        except Exception as e:
            print("     WARNING: Could not create index via REST API: {}".format(e))

        # Step 4: Write transforms.conf and props.conf for MITRE technique mapping
        print("     Configuring MITRE ATT&CK transforms...")
        try:
            app_default_path = "/" + remote_splunk_path + "splunk/etc/apps/elrond/default/"
            os.makedirs(app_default_path, exist_ok=True)

            # Import the transforms creation function
            from rowanholt.post.splunk.app.transforms import create_transforms

            # Create transforms.conf with MITRE mappings
            transforms_conf_path = app_default_path + "transforms.conf"
            with open(transforms_conf_path, "w") as transformsconf:
                # Basic transforms for field extractions
                transformsconf.write(
                    "[logtype_make]\nREGEX = (?<logtype>(?:registry|evt|shimcache|jumplists|usb|log|plist|service|journal|browser|analysis|timeline|memory|audit))\nSOURCE_KEY = source\n\n[IPAddress_get]\nREGEX = (?P<ip>(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\nSOURCE_KEY = _raw\nMV_ADD = true\n\n"
                )
                transformsconf.write(
                    "[Filenames_get]\nREGEX = (?<Filepath>.*)\\/(?<Filename>[^\\/]+)\\.(?<Fileext>[^\\:]+)$\nSOURCE_KEY = Filename\n\n"
                )
                transformsconf.write(
                    "[Commands_get]\nREGEX = (?<ProcessPath>.*)\\/(?<ProcessName>[^\\/]+)\\.(?<ProcessExt>.*)$\nSOURCE_KEY = Command\n\n[Processes_get]\nREGEX = (?<ProcessPath>.*)\\/(?<ProcessName>[^\\/]+)\\.(?<ProcessExt>.*)$\nSOURCE_KEY = Process\n\n"
                )
                transformsconf.write(
                    "[usb_win_hw]\nREGEX = [^\\-]\\ \\-\\ (?<HardwareType>[^\\\\\\\\]+)\nSOURCE_KEY = Artefact\n\n[usb_win_dvc]\nREGEX = (?<disk>[A-Za-z\\d]+)\\S(?:D|d)(?:I|i)(?:S|s)(?:K|k)\\S(?:V|v)(?:E|e)(?:N|n)_(?<ven>[a-z\\d]+)\\S+(?:P|p)(?:R|r)(?:O|o)(?:D|d)_(?<prod>\\w+)(\\S(?:R|r)(?:E|e)(?:V|v)_(?<rev>[a-z\\d]+))?\\S(?<serial>[^\\#]+)\nSOURCE_KEY = Artefact\n\n"
                )
                transformsconf.write(
                    '[usb_mac_ven]\nREGEX = idVendor\\": \\"(?P<ven>[^\\"]+)\nSOURCE_KEY = _raw\n\n[usb_mac_prod]\nREGEX = idProduct\\": \\"(?P<prod>[^\\"]+)\nSOURCE_KEY = _raw\n\n'
                )
                transformsconf.write(
                    "[usb_lin_ven]\nREGEX = Manufacturer: (?<ven>.+)\nSOURCE_KEY = Message\n\n[usb_lin_prod]\nREGEX = Product: (?<prod>.+)\nSOURCE_KEY = Message\n\n[usb_lin_rev]\nREGEX = bcdDevice= (?<rev>.+)\nSOURCE_KEY = Message\n\n[usb_lin_sn]\nREGEX = SerialNumber: (?<sn>.+)\nSOURCE_KEY = Message\n\n"
                )
                transformsconf.write(
                    "[MFTFiles1_get]\nREGEX = \\\\(?<MFTFilename>[^\\\\]+)$\nSOURCE_KEY = Filename\n\n[MFTFiles2_get]\nREGEX = \\\\(?<MFTFilepath>.+)\\\\[^\\\\]+$\nSOURCE_KEY = Filename\n\n[MFTFiles3_get]\nREGEX = (?<MFTFilename>[^\\/]+)$\nSOURCE_KEY = full_path\n\n[MFTFiles4_get]\nREGEX = (?<MFTFilepath>.+)\\/[^\\/]+$\nSOURCE_KEY = full_path\n\n"
                )
            # Append MITRE technique assignments
            with open(transforms_conf_path, "a") as transformsconf:
                create_transforms(transformsconf)

            # Create props.conf with sourcetype definitions
            props_conf_path = app_default_path + "props.conf"
            propsreports = "TRANSFORMS = mitre_assign\nREPORT-logtype_make = logtype_make\nREPORT-IPAddress_get = IPAddress_get\nREPORT-MFTFiles1_get = MFTFiles1_get\nREPORT-MFTFiles2_get = MFTFiles2_get\nREPORT-MFTFiles3_get = MFTFiles3_get\nREPORT-MFTFiles4_get = MFTFiles4_get\nREPORT-Commands_get = Commands_get\nREPORT-Processes_get = Processes_get\nREPORT-usb_win_hw = usb_win_hw\nREPORT-usb_win_dvc = usb_win_dvc\nREPORT-usb_mac_ven = usb_mac_ven\nREPORT-usb_mac_prod = usb_mac_prod\nREPORT-usb_lin_ven = usb_lin_ven\nREPORT-usb_lin_prod = usb_lin_prod\nREPORT-usb_lin_rev = usb_lin_rev\nREPORT-usb_lin_sn = usb_lin_sn"

            with open(props_conf_path, "w") as propsconf:
                propsconf.write(
                    '[elrondCSV]\nBREAK_ONLY_BEFORE_DATE = 0\nDATETIME_CONFIG = \nINDEXED_EXTRACTIONS = csv\nKV_MODE = none\nLINE_BREAKER = ([\\r\\n]+)\nMAX_DAYS_AGO = 999999\nMAX_DAYS_HENCE = 999999\nNO_BINARY_CHECK = true\n{}\nSHOULD_LINEMERGE = false\nTIMESTAMP_FIELDS = LastWriteTime\ncategory = Custom\ndescription = Comma-separated value format. Set header and other settings in "Delimited Settings"\ndisabled = false\npulldown_type = true\n\n'.format(
                        propsreports
                    )
                )
                propsconf.write(
                    '[elrondCSV_noTime]\nBREAK_ONLY_BEFORE_DATE = 0\nDATETIME_CONFIG = CURRENT\nINDEXED_EXTRACTIONS = csv\nKV_MODE = none\nLINE_BREAKER = ([\\r\\n]+)\nMAX_DAYS_AGO = 999999\nMAX_DAYS_HENCE = 999999\nNO_BINARY_CHECK = true\n{}\nSHOULD_LINEMERGE = false\nTIMESTAMP_FIELDS = LastWriteTime\ncategory = Custom\ndescription = Comma-separated value format. Set header and other settings in "Delimited Settings"\ndisabled = false\npulldown_type = true\n\n'.format(
                        propsreports
                    )
                )
                propsconf.write(
                    "[json]\nDATETIME_CONFIG = \nINDEXED_EXTRACTIONS = json\nKV_MODE = none\nLINE_BREAKER = ([\\r\\n]+)\nMAX_DAYS_AGO = 999999\nMAX_DAYS_HENCE = 999999\nNO_BINARY_CHECK = true\n{}\nTIMESTAMP_FIELDS = LastWriteTime\nTIME_FORMAT = %a %b %e %H:%M:%S %Y\ncategory = Custom\ndescription = JavaScript Object Notation format. For more information, visit http://json.org/\ndisabled = false\npulldown_type = true\n\n".format(
                        propsreports
                    )
                )
                propsconf.write(
                    "[json_noTime]\nDATETIME_CONFIG = CURRENT\nINDEXED_EXTRACTIONS = json\nKV_MODE = none\nLINE_BREAKER = ([\\r\\n]+)\nMAX_DAYS_AGO = 999999\nMAX_DAYS_HENCE = 999999\nNO_BINARY_CHECK = true\n{}\nTIMESTAMP_FIELDS = LastWriteTime\nTIME_FORMAT = %a %b %e %H:%M:%S %Y\ncategory = Custom\ndescription = JavaScript Object Notation format. For more information, visit http://json.org/\ndisabled = false\npulldown_type = true\n\n".format(
                        propsreports
                    )
                )

            print("     MITRE ATT&CK transforms configured successfully")
        except Exception as e:
            print("     WARNING: Could not configure transforms: {}".format(e))

        # Step 5: Write inputs.conf for remote monitoring
        print("     Configuring data inputs...")
        try:
            inputs_conf_path = "/" + remote_splunk_path + "splunk/etc/apps/elrond/default/inputs.conf"
            os.makedirs(os.path.dirname(inputs_conf_path), exist_ok=True)

            # Build inputs.conf entries for all images. The Splunk container mounts the
            # output where the worker does, so it monitors the worker's own path (E10:
            # it was always /tmp/elrond/output/<case>/, so custom destinations indexed 0)
            inputs_entries = []
            for img_name, img in siem_hosts(allimgs):
                base_path = os.path.join(os.path.normpath(output_directory), img_name)
                cooked_path = "{}/artefacts/cooked".format(base_path)
                if not splunk_can_see(base_path):
                    entry, prnt = "{},{},not indexed: '{}' is outside the Splunk container's mounts ({})\n".format(
                        datetime.now().isoformat(), "splunk", base_path, ", ".join(monitor_roots()),
                    ), " -> {} -> WARNING: '{}' won't be indexed: Splunk only mounts {} (set SPLUNK_MONITOR_ROOTS and mount the path into the splunk service)".format(
                        datetime.now().isoformat().replace("T", " "), base_path, ", ".join(monitor_roots()),
                    )
                    write_audit_log_entry(verbosity, output_directory, entry, prnt)

                # Log indexing for this image
                entry, prnt = "{},{},indexing artefacts for '{}'\n".format(
                    datetime.now().isoformat(),
                    "splunk",
                    img_name,
                ), " -> {} -> indexing artefacts for '{}'".format(
                    datetime.now().isoformat().replace("T", " "),
                    img_name
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)

                # Find and log actual artefact files being indexed
                import glob
                host_cooked_path = output_directory + img_name + "/artefacts/cooked"

                # Log CSV files
                csv_files = glob.glob(host_cooked_path + "/*.csv")
                for csv_file in csv_files:
                    artefact_name = os.path.basename(csv_file)
                    entry, prnt = "{},{},indexing '{}' for '{}'\n".format(
                        datetime.now().isoformat(), "splunk", artefact_name, img_name
                    ), " -> {} -> indexing '{}' for '{}'".format(
                        datetime.now().isoformat().replace("T", " "), artefact_name, img_name
                    )
                    write_audit_log_entry(verbosity, output_directory, entry, prnt)

                # Log JSON files
                json_files = glob.glob(host_cooked_path + "/*.json")
                for json_file in json_files:
                    artefact_name = os.path.basename(json_file)
                    entry, prnt = "{},{},indexing '{}' for '{}'\n".format(
                        datetime.now().isoformat(), "splunk", artefact_name, img_name
                    ), " -> {} -> indexing '{}' for '{}'".format(
                        datetime.now().isoformat().replace("T", " "), artefact_name, img_name
                    )
                    write_audit_log_entry(verbosity, output_directory, entry, prnt)

                # Log JSONL files (Artemis output format)
                jsonl_files = glob.glob(host_cooked_path + "/*.jsonl")
                for jsonl_file in jsonl_files:
                    artefact_name = os.path.basename(jsonl_file)
                    entry, prnt = "{},{},indexing '{}' for '{}'\n".format(
                        datetime.now().isoformat(), "splunk", artefact_name, img_name
                    ), " -> {} -> indexing '{}' for '{}'".format(
                        datetime.now().isoformat().replace("T", " "), artefact_name, img_name
                    )
                    write_audit_log_entry(verbosity, output_directory, entry, prnt)

                # Log registry files
                registry_files = glob.glob(host_cooked_path + "/registry/*.json")
                for reg_file in registry_files:
                    artefact_name = os.path.basename(reg_file)
                    entry, prnt = "{},{},indexing '{}' for '{}'\n".format(
                        datetime.now().isoformat(), "splunk", artefact_name, img_name
                    ), " -> {} -> indexing '{}' for '{}'".format(
                        datetime.now().isoformat().replace("T", " "), artefact_name, img_name
                    )
                    write_audit_log_entry(verbosity, output_directory, entry, prnt)

                # Log event log files (both json and jsonl)
                evt_files = glob.glob(host_cooked_path + "/evt/*.json") + glob.glob(host_cooked_path + "/evt/*.jsonl")
                for evt_file in evt_files:
                    artefact_name = os.path.basename(evt_file)
                    entry, prnt = "{},{},indexing '{}' for '{}'\n".format(
                        datetime.now().isoformat(), "splunk", artefact_name, img_name
                    ), " -> {} -> indexing '{}' for '{}'".format(
                        datetime.now().isoformat().replace("T", " "), artefact_name, img_name
                    )
                    write_audit_log_entry(verbosity, output_directory, entry, prnt)

                # Add CSV files
                inputs_entries.append(
                    "[monitor://{}/*.csv]\n"
                    "disabled = false\n"
                    "crcSalt = <SOURCE>\n"
                    "host = {}\n"
                    "sourcetype = elrondCSV\n"
                    "index = {}\n\n".format(cooked_path, img_name, case)
                )

                # Add JSON files
                inputs_entries.append(
                    "[monitor://{}/*.json]\n"
                    "disabled = false\n"
                    "crcSalt = <SOURCE>\n"
                    "host = {}\n"
                    "sourcetype = json\n"
                    "index = {}\n\n".format(cooked_path, img_name, case)
                )

                # Add JSONL files (Artemis output format)
                inputs_entries.append(
                    "[monitor://{}/*.jsonl]\n"
                    "disabled = false\n"
                    "crcSalt = <SOURCE>\n"
                    "host = {}\n"
                    "sourcetype = json\n"
                    "index = {}\n\n".format(cooked_path, img_name, case)
                )

                # Add registry subdirectory
                inputs_entries.append(
                    "[monitor://{}/registry/*.json]\n"
                    "disabled = false\n"
                    "crcSalt = <SOURCE>\n"
                    "host = {}\n"
                    "sourcetype = json\n"
                    "index = {}\n\n".format(cooked_path, img_name, case)
                )

                # Add evt subdirectory (both json and jsonl)
                inputs_entries.append(
                    "[monitor://{}/evt/*.json]\n"
                    "disabled = false\n"
                    "crcSalt = <SOURCE>\n"
                    "host = {}\n"
                    "sourcetype = json\n"
                    "index = {}\n\n".format(cooked_path, img_name, case)
                )
                inputs_entries.append(
                    "[monitor://{}/evt/*.jsonl]\n"
                    "disabled = false\n"
                    "crcSalt = <SOURCE>\n"
                    "host = {}\n"
                    "sourcetype = json\n"
                    "index = {}\n\n".format(cooked_path, img_name, case)
                )

                # Volatility's output sits beside artefacts/, not in cooked/
                for memory_file in memory_outputs(base_path):
                    entry, prnt = "{},{},indexing '{}' for '{}'\n".format(
                        datetime.now().isoformat(), "splunk", os.path.basename(memory_file), img_name
                    ), " -> {} -> indexing '{}' for '{}'".format(
                        datetime.now().isoformat().replace("T", " "), os.path.basename(memory_file), img_name
                    )
                    write_audit_log_entry(verbosity, output_directory, entry, prnt)
                inputs_entries.append(
                    "[monitor://{}/memory_*.json]\n"
                    "disabled = false\n"
                    "crcSalt = <SOURCE>\n"
                    "host = {}\n"
                    "sourcetype = json\n"
                    "index = {}\n\n".format(base_path, img_name, case)
                )

                # Add audit log file
                inputs_entries.append(
                    "[monitor://{}/rowanholt_audit.log]\n"
                    "disabled = false\n"
                    "host = {}\n"
                    "sourcetype = elrondCSV\n"
                    "index = {}\n\n".format(base_path, img_name, case)
                )

            with open(inputs_conf_path, "a") as inputs_conf:
                inputs_conf.write("\n# Auto-generated inputs for case: {}\n".format(case))
                for entry in inputs_entries:
                    inputs_conf.write(entry)

            print("     Data inputs configured for {} image(s)".format(len(allimgs)))
        except Exception as e:
            print("     WARNING: Could not configure inputs: {}".format(e))

        # Step 6: Restart Splunk to pick up changes (via REST API)
        print("     Requesting Splunk restart to apply changes...")
        try:
            restart_url = "https://{}:{}/services/server/control/restart".format(splunk_host, splunk_port)
            req = urllib.request.Request(restart_url, data=b'', method='POST')
            req.add_header('Authorization', 'Basic {}'.format(encoded_credentials))
            try:
                response = urllib.request.urlopen(req, context=ssl_context, timeout=30)
                print("     Splunk restart initiated")
            except urllib.error.HTTPError as e:
                # 503 is expected during restart
                if e.code == 503:
                    print("     Splunk restarting...")
                else:
                    print("     WARNING: Restart request returned: {} {}".format(e.code, e.reason))
        except Exception as e:
            print("     Note: Splunk may need manual restart to pick up changes")

        print("     Splunk configuration complete")
        entry, prnt = "{},{},splunk configured successfully for '{}'\n".format(
            datetime.now().isoformat(),
            "splunk",
            first_img,
        ), " -> {} -> splunk configured successfully for case '{}' for '{}'".format(
            datetime.now().isoformat().replace("T", " "),
            case,
            first_img
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        return splunkuser, splunkpswd

    # Local Splunk mode (original code path)
    def request_splunk_creds():
        # Check for environment variables first (for non-interactive mode)
        splunkuser = os.environ.get('SPLUNK_USERNAME', '')
        splunkpswd = os.environ.get('SPLUNK_PASSWORD', '')

        # If not in environment, prompt interactively
        if not splunkuser or not splunkpswd:
            splunkuser = safe_input("      Splunk admin username: ", default="admin")
            splunkpswd = getpass.getpass("      Splunk admin password: ")

        splunk_service(splunk_install_path, "start")
        testcreds = subprocess.Popen(
            [
                "curl",
                "-u",
                splunkuser.strip() + ":" + splunkpswd.strip(),
                "-k",
                "https://localhost:8089/services/search/jobs",
                "-d",
                "search=search index=* host=*",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
        if "Unauthorized" in str(testcreds)[3:-4] and "ERROR" in str(testcreds)[3:-4]:
            print("\n     Invalid credentials. Please try again...")
            splunkuser, splunkpswd = request_splunk_creds()
        splunk_service(splunk_install_path, "stop")
        return splunkuser, splunkpswd

    splunk_install_locations = []
    splunk_locations = subprocess.Popen(
        ["locate", "splunk.version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    for splunk_location in splunk_locations:
        if (
            not str(splunk_location)[2:-3].startswith("/mnt/elrond_mount")
            and str(splunk_location) != "b''"
        ):
            splunk_install_locations.append(str(splunk_location)[2:-3])
    splunk_install_locations = list(set(splunk_install_locations))
    allimgs = OrderedDict(sorted(allimgs.items(), key=lambda x: x[1]))
    splunk_install_path = "opt/"
    pwd = os.getcwd()
    apps = {
        "lookup_editor/": "lookup-file-editor_346.tar",
        "network_topology/": "network_topology.tar",
        "punchcard_app/": "punchcard-custom-visualization_140.tar",
        "sankey_diagram_app/": "splunk-sankey-diagram-custom-visualization_150.tar",
        "TA-geolocate/": "geolocation-lookup-for-splunk_114.tar",
        "treemap_app/": "treemap-custom-visualization_140.tar",
    }
    print(
        "\n\n  -> \033[1;36mCommencing Splunk Phase...\033[1;m\n  ----------------------------------------"
    )
    time.sleep(1)

    # Initialize credentials variables
    splunkuser = None
    splunkpswd = None

    if len(splunk_install_locations) > 0:
        if len(splunk_install_locations[0]) != 0:
            matches = re.findall(
                r"\/(.*)splunk\/etc\/splunk.version",
                str(splunk_install_locations[0]),
            )
            if matches and len(matches) > 0:
                pathfound = str(matches[0])
                if pathfound != "":
                    splunk_install_path = pathfound
                    print("     Splunk installation found, please provide")
                    splunkuser, splunkpswd = request_splunk_creds()

    if splunkuser is None or splunkpswd is None:
        # Check if running in non-interactive mode without Splunk
        from rowanholt.utils import is_noninteractive
        if is_noninteractive():
            first_img = list(allimgs.values())[0].split("::")[0] if allimgs else "unknown"
            print("    Splunk is not installed and running in non-interactive mode - skipping Splunk configuration")
            from rowanholt.audit import write_audit_log_entry
            entry, prnt = "{},{},splunk not installed - skipping in non-interactive mode for '{}'".format(
                datetime.now().isoformat(),
                "splunk",
                first_img,
            ), " -> {} -> splunk not installed - skipping splunk phase in non-interactive mode for '{}'".format(
                datetime.now().isoformat().replace("T", " "),
                first_img
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            return None, None

        print("    Splunk is not installed or not properly configured, please stand by...")
        splunkuser, splunkpswd = install_splunk_stack(
            verbosity,
            output_directory,
            case,
            stage,
            allimgs,
            "/opt/elrond/elrond/tools/.splunk.deb",
            splunk_install_path,
        )
        with open(
            "/" + splunk_install_path + "splunk/etc/system/default/limits.conf"
        ) as limitsconfread:
            oldlimitsdata = limitsconfread.read()
        newlimitsdata = re.sub(
            r"max_mem_usage_mb = \d+",
            r"max_mem_usage_mb = 1000",
            str(
                re.sub(
                    r"indexed_kv_limit = \d+", r"indexed_kv_limit = 0", oldlimitsdata
                )
            ),
        )
        with open(
            "/" + splunk_install_path + "splunk/etc/system/local/limits.conf", "w"
        ) as limitsconfwrite:
            limitsconfwrite.write(newlimitsdata)
    if not os.path.isdir(
        "/" + splunk_install_path + "splunk/etc/apps/elrond/"
    ):  # deploying elrond Splunk app
        build_app_elrond(case, splunk_install_path)
    else:
        with open(
            "/"
            + splunk_install_path
            + "splunk/etc/apps/elrond/default/data/ui/nav/default.xml"
        ) as default_nav:
            default_nav_xml = default_nav.read()
            if case not in default_nav_xml:
                insert_new_case = re.sub(
                    r"([\S\s]+<collection label=\"Cases\">)(\n\s+<view source=\"all\" match=\")([^\"]+)(\" />)([\S\s]+)",
                    r"\1\2§±§±§±§\4\2\3\4\5",
                    default_nav_xml,
                )
                insert_new_case = insert_new_case.replace("§±§±§±§", case)
                if "already exists" in str(
                    subprocess.Popen(
                        [
                            "/" + splunk_install_path + "splunk/bin/./splunk",
                            "add",
                            "index",
                            case,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).communicate()[0]
                ):
                    overwrite_splunk_index(
                        verbosity,
                        output_directory,
                        case,
                        stage,
                        allimgs,
                        splunk_install_path,
                    )
                with open(
                    "/"
                    + splunk_install_path
                    + "splunk/etc/apps/elrond/default/data/ui/nav/default.xml",
                    "w",
                ) as new_default_nav:
                    new_default_nav.write(insert_new_case + "\n")
            if not os.path.isfile(
                "/"
                + splunk_install_path
                + "splunk/etc/apps/elrond/default/data/ui/views/"
                + case
                + ".xml"
            ):
                with open(
                    "/"
                    + splunk_install_path
                    + "splunk/etc/apps/elrond/default/data/ui/views/"
                    + case
                    + ".xml",
                    "w",
                ) as casexml:
                    casexml.write(
                        '<form version="1.1" stylesheet="mitre.css" theme="light">\n  <search id="base">\n    <query>index={} host=* | dedup index host | table index host</query>\n    <earliest>$time_tok.earliest$</earliest>\n    <latest>$time_tok.latest$</latest>\n  </search>\n  <search id="browser">\n    <query>index={} host=$host_tok$ | `browser_domain` | stats count AS Count BY domain</query>\n    <earliest>$time_tok.earliest$</earliest>\n    <latest>$time_tok.latest$</latest>\n  </search>\n  <search id="ip">\n    <query>index={} host=$host_tok$ | fields ip count host | search ip!=NULL | mvexpand ip | search ip!=NULL | stats count BY ip host</query>\n    <earliest>$time_tok.earliest$</earliest>\n    <latest>$time_tok.latest$</latest>\n  </search>\n  <label>{}</label>\n  <fieldset submitButton="true" autoRun="false">\n    <input type="checkbox" token="it_tok" searchWhenChanged="true">\n      <label></label>\n      <search>\n        <query><![CDATA[| gentimes start=-1 | eval it="Toggle MITRE Information"]]></query>\n      </search>\n      <fieldForLabel>it</fieldForLabel>\n      <fieldForValue>it</fieldForValue>\n      <delimiter> </delimiter>\n    </input>\n    <input type="dropdown" token="host_tok" searchWhenChanged="false">\n      <label>Select a Host:</label>\n      <choice value="*">All</choice>\n      <default>*</default>\n      <initialValue>*</initialValue>\n      <fieldForLabel>host</fieldForLabel>\n      <fieldForValue>host</fieldForValue>\n      <search base="base">\n        <query>| dedup host | sort host</query>\n      </search>\n    </input>\n    <input type="time" token="time_tok" searchWhenChanged="false">\n      <label>Select a Time Range:</label>\n      <default>\n        <earliest>-1d@d</earliest>\n        <latest>@d</latest>\n      </default>\n    </input>\n  </fieldset>\n  <row>\n    <panel depends="$it_tok$">\n      <table>\n        <title>Adversarial Tactics, Techniques &amp; Common Knowledge</title>\n        <search>\n          <query>| inputlookup mitreall.csv | table name id tactic platform threat_actor description | sort name | rename name AS Name id AS ID tactic AS Tactic platform AS Platform threat_actor AS "Threat Actor" description AS Description</query>\n          <earliest>$earliest$</earliest>\n          <latest>$latest$</latest>\n        </search>\n        <option name="count">10</option>\n        <option name="dataOverlayMode">none</option>\n        <option name="drilldown">none</option>\n        <option name="percentagesRow">false</option>\n        <option name="refresh.display">progressbar</option>\n        <option name="rowNumbers">false</option>\n        <option name="totalsRow">false</option>\n        <option name="wrap">false</option>\n      </table>\n    </panel>\n  </row>\n  <row>\n    <panel>\n      <single>\n        <title>Total Number of Events</title>\n        <search>\n          <query>index={} host=$host_tok$ | stats count</query>\n          <earliest>$time_tok.earliest$</earliest>\n          <latest>$time_tok.latest$</latest>\n        </search>\n        <option name="colorBy">value</option>\n        <option name="colorMode">none</option>\n        <option name="drilldown">none</option>\n        <option name="height">188</option>\n        <option name="numberPrecision">0</option>\n        <option name="rangeColors">["0x53a051","0x0877a6","0xf8be34","0xf1813f","0xdc4e41"]</option>\n        <option name="rangeValues">[0,30,70,100]</option>\n        <option name="refresh.display">progressbar</option>\n        <option name="showSparkline">0</option>\n        <option name="showTrendIndicator">0</option>\n        <option name="trellis.enabled">0</option>\n        <option name="trellis.scales.shared">1</option>\n        <option name="trellis.size">medium</option>\n        <option name="trendColorInterpretation">standard</option>\n        <option name="trendDisplayMode">absolute</option>\n        <option name="unitPosition">after</option>\n        <option name="useColors">0</option>\n        <option name="useThousandSeparators">1</option>\n      </single>\n    </panel>\n    <panel>\n      <table>\n        <title>Top 5 Users</title>\n        <search>\n          <query>index={} host=$host_tok$ | `make_userprofile` | stats count BY user_profile | sort 5 -count | table count user_profile | rename user_profile AS "User Profile" count AS Count</query>\n          <earliest>$time_tok.earliest$</earliest>\n          <latest>$time_tok.latest$</latest>\n        </search>\n        <option name="count">5</option>\n        <option name="dataOverlayMode">highlow</option>\n        <option name="drilldown">none</option>\n        <option name="percentagesRow">false</option>\n        <option name="refresh.display">progressbar</option>\n        <option name="rowNumbers">false</option>\n        <option name="totalsRow">false</option>\n        <option name="wrap">false</option>\n      </table>\n    </panel>\n  </row>\n  <row>\n    <panel>\n      <chart>\n        <title>Log Activity</title>\n        <search>\n          <query>index={} host=$host_tok$ (logtype=evt OR logtype=log OR logtype=service OR logtype=plist) | timechart count BY logtype useother=0 usenull=0 limit=0</query>\n          <earliest>$time_tok.earliest$</earliest>\n          <latest>$time_tok.latest$</latest>\n        </search>\n        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>\n        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>\n        <option name="charting.axisTitleX.text">Time</option>\n        <option name="charting.axisTitleX.visibility">visible</option>\n        <option name="charting.axisTitleY.text">Count</option>\n        <option name="charting.axisTitleY.visibility">visible</option>\n        <option name="charting.axisTitleY2.visibility">visible</option>\n        <option name="charting.axisX.abbreviation">none</option>\n        <option name="charting.axisX.scale">linear</option>\n        <option name="charting.axisY.abbreviation">none</option>\n        <option name="charting.axisY.scale">linear</option>\n        <option name="charting.axisY2.abbreviation">none</option>\n        <option name="charting.axisY2.enabled">0</option>\n        <option name="charting.axisY2.scale">inherit</option>\n        <option name="charting.chart">line</option>\n        <option name="charting.chart.bubbleMaximumSize">50</option>\n        <option name="charting.chart.bubbleMinimumSize">10</option>\n        <option name="charting.chart.bubbleSizeBy">area</option>\n        <option name="charting.chart.nullValueMode">gaps</option>\n        <option name="charting.chart.showDataLabels">none</option>\n        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>\n        <option name="charting.chart.stackMode">default</option>\n        <option name="charting.chart.style">shiny</option>\n        <option name="charting.drilldown">none</option>\n        <option name="charting.layout.splitSeries">0</option>\n        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>\n        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>\n        <option name="charting.legend.mode">standard</option>\n        <option name="charting.legend.placement">bottom</option>\n        <option name="charting.lineWidth">2</option>\n        <option name="trellis.enabled">0</option>\n        <option name="trellis.scales.shared">1</option>\n        <option name="trellis.size">medium</option>\n      </chart>\n    </panel>\n  </row>\n  <row>\n    <panel>\n      <table>\n        <title>External Devices Connected via USB</title>\n        <search>\n          <query>index={} host=$host_tok$ | search `usb_out`</query>\n          <earliest>$time_tok.earliest$</earliest>\n          <latest>$time_tok.latest$</latest>\n        </search>\n        <option name="count">20</option>\n        <option name="dataOverlayMode">none</option>\n        <option name="drilldown">none</option>\n        <option name="percentagesRow">false</option>\n        <option name="refresh.display">progressbar</option>\n        <option name="rowNumbers">false</option>\n        <option name="totalsRow">false</option>\n        <option name="wrap">true</option>\n      </table>\n    </panel>\n  </row>\n  <row>\n    <panel>\n      <input type="checkbox" token="ltgt_tok" searchWhenChanged="true">\n        <label>Select Less/Greater Than:</label>\n        <choice value="&lt;">Less Than</choice>\n        <choice value="&gt;">Greater Than</choice>\n        <default>&gt;</default>\n        <initialValue>&gt;</initialValue>\n        <delimiter> </delimiter>\n      </input>\n      <input type="text" token="count_tok" searchWhenChanged="true">\n        <label>Enter Number of Connections:</label>\n        <default>0</default>\n        <initialValue>0</initialValue>\n      </input>\n      <viz type="network_topology.network_topology">\n        <title>Internal (IANA Private-Use Networks) Network Map</title>\n        <search>\n          <query>index={} host=$host_tok$ | stats count BY ip host | where count$ltgt_tok$$count_tok$ | fields ip count host | search ip=10.0.0.0/8 OR ip=172.16.0.0/16 OR ip=192.168.0.0/16 | table ip count host empty1 empty2 | eval count="#"+count | fillnull value=-</query>\n          <earliest>$time_tok.earliest$</earliest>\n          <latest>$time_tok.latest$</latest>\n        </search>\n        <option name="drilldown">none</option>\n        <option name="height">500</option>\n        <option name="network_topology.network_topology.drilldown">false</option>\n        <option name="network_topology.network_topology.link1">link1</option>\n        <option name="network_topology.network_topology.link1Color">#ffc000</option>\n        <option name="network_topology.network_topology.link1Dashed">true</option>\n        <option name="network_topology.network_topology.link1Label">Link 1</option>\n        <option name="network_topology.network_topology.link2">link2</option>\n        <option name="network_topology.network_topology.link2Color">#00b050</option>\n        <option name="network_topology.network_topology.link2Dashed">true</option>\n        <option name="network_topology.network_topology.link2Label">Link 2</option>\n        <option name="network_topology.network_topology.link3">link3</option>\n        <option name="network_topology.network_topology.link3Color">#006d9c</option>\n        <option name="network_topology.network_topology.link3Dashed">true</option>\n        <option name="network_topology.network_topology.link3Label">Link 3</option>\n        <option name="network_topology.network_topology.link4">link4</option>\n        <option name="network_topology.network_topology.link4Color">#7030A0</option>\n        <option name="network_topology.network_topology.link4Dashed">true</option>\n        <option name="network_topology.network_topology.link4Label">Link 4</option>\n        <option name="network_topology.network_topology.link5">link5</option>\n        <option name="network_topology.network_topology.link5Color">#c00000</option>\n        <option name="network_topology.network_topology.link5Dashed">true</option>\n        <option name="network_topology.network_topology.link5Label">Link 5</option>\n        <option name="network_topology.network_topology.unfocusOpacity">1</option>\n        <option name="refresh.display">progressbar</option>\n        <option name="trellis.enabled">0</option>\n        <option name="trellis.scales.shared">1</option>\n        <option name="trellis.size">medium</option>\n      </viz>\n    </panel>\n    <panel>\n      <table>\n        <title>Top 10 Most/Least Visited URLs</title>\n        <search base="browser">\n          <query>| sort 10 -Count | table Count domain | rename domain AS Domain</query>\n        </search>\n        <option name="count">10</option>\n        <option name="dataOverlayMode">highlow</option>\n        <option name="drilldown">none</option>\n        <option name="percentagesRow">false</option>\n        <option name="refresh.display">progressbar</option>\n        <option name="rowNumbers">false</option>\n        <option name="totalsRow">false</option>\n        <option name="wrap">false</option>\n      </table>\n      <table>\n        <search base="browser">\n          <query>| sort 10 Count | table Count domain | rename domain AS Domain</query>\n        </search>\n        <option name="count">10</option>\n        <option name="dataOverlayMode">highlow</option>\n        <option name="drilldown">none</option>\n        <option name="percentagesRow">false</option>\n        <option name="refresh.display">progressbar</option>\n        <option name="rowNumbers">false</option>\n        <option name="totalsRow">false</option>\n        <option name="wrap">false</option>\n      </table>\n    </panel>\n  </row>\n  <row>\n    <panel>\n      <map>\n        <title>External Network Communications</title>\n        <search base="ip">\n          <query>| search ip!=10.0.0.0/8 ip!=172.16.0.0/16 ip!=192.168.0.0/16 | iplocation ip | geostats count by Country</query>\n        </search>\n        <option name="drilldown">none</option>\n        <option name="height">600</option>\n        <option name="mapping.map.center">(20,10)</option>\n        <option name="mapping.map.zoom">3</option>\n        <option name="mapping.type">marker</option>\n      </map>\n    </panel>\n  </row>\n</form>'.format(
                            case,
                            case,
                            case,
                            case,
                            case,
                            case,
                            case,
                            case,
                            case,
                            case,
                        )
                    )
    ingest_splunk_data(
        verbosity,
        output_directory,
        case,
        stage,
        allimgs,
        splunk_install_path,
    )
    for appdir, apptar in apps.items():
        if not os.path.isdir("/" + splunk_install_path + "splunk/etc/apps/" + appdir):
            os.makedirs("/" + splunk_install_path + "splunk/etc/apps/" + appdir)
            with open("." + apptar, "w") as tarout:
                apphexdump = None
                if appdir == "TA-geolocate/" and build_app_geolocate is not None:
                    apphexdump = build_app_geolocate()
                elif appdir == "lookup_editor/" and build_app_lookup is not None:
                    apphexdump = build_app_lookup()
                elif appdir == "punchcard_app/" and build_app_punchcard is not None:
                    apphexdump = build_app_punchcard()
                elif appdir == "sankey_diagram_app/" and build_app_sankey is not None:
                    apphexdump = build_app_sankey()
                elif appdir == "network_topology/" and build_app_topology is not None:
                    apphexdump = build_app_topology()
                elif appdir == "treemap_app/" and build_app_treemap is not None:
                    apphexdump = build_app_treemap()

                if apphexdump is not None:
                    tarout.write(apphexdump)
                subprocess.call(["xxd", "-plain", "-revert", "." + apptar, apptar])
                tar = TarFile.open(apptar, "r:gz")
                tar.extractall("/" + splunk_install_path + "splunk/etc/apps/")
                tar.close()
                os.remove("." + apptar)
                os.remove(apptar)
                os.chdir("/" + splunk_install_path + "splunk/etc/apps/")
                subprocess.Popen(
                    ["chmod", "-R", "644", appdir],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()
                subprocess.Popen(
                    ["chown", "-R", "splunk:splunk", appdir],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()
    os.chdir("/" + splunk_install_path + "splunk/etc/apps/")
    for root, dirs, files in os.walk(
        "/" + splunk_install_path + "splunk/etc/apps/elrond/"
    ):
        for eachdir in dirs:
            subprocess.Popen(
                ["chmod", "755", os.path.join(root, eachdir)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()
        for eachfile in files:
            subprocess.Popen(
                ["chmod", "644", os.path.join(root, eachfile)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()
    subprocess.Popen(
        ["chmod", "755", "elrond/"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    subprocess.Popen(
        ["chown", "-R", "splunk:splunk", "elrond/"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    subprocess.Popen(
        ["sudo", "/bin/systemctl", "enable", "splunk.service"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    splunk_service(splunk_install_path, "start")
    os.chdir(pwd)
    return splunkuser, splunkpswd
