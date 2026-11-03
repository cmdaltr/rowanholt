#!/usr/bin/env python3 -tt
import os
import re
import subprocess
from datetime import datetime

from rivendell.audit import write_audit_log_entry
from rivendell.memory.extract import use_plugins
from rivendell.process.extractions.registry.dumpreg import extract_dumpreg_guess
from rivendell.process.extractions.registry.dumpreg import extract_dumpreg_profile
from rivendell.process.extractions.registry.dumpreg import extract_dumpreg_system


def print_extraction(
    verbosity,
    output_directory,
    artefact,
    volprefix,
    volversion,
    profile,
    mesginsrt,
    vssimage,
):
    if artefact.split("/")[-1] == vssimage:
        print(
            "{}{} is extracting artefacts from '{}' with {} '{}'...".format(
                volprefix,
                volversion,
                artefact.split("/")[-1],
                mesginsrt,
                profile,
            )
        )
        entry, prnt = "{},{},extracting,{} ({})\n".format(
            datetime.now().isoformat(), vssimage, artefact.split("/")[-1], profile
        ), " -> {} -> extracting artefacts from '{}' ({})".format(
            datetime.now().isoformat().replace("T", " "),
            artefact.split("/")[-1],
            profile,
        )
    else:
        print(
            "{}{} is extracting artefacts from '{}' with {} '{}' for {}...".format(
                volprefix,
                volversion,
                artefact.split("/")[-1],
                mesginsrt,
                profile,
                vssimage,
            )
        )
        entry, prnt = "{},{},extracting,{} ({})\n".format(
            datetime.now().isoformat(), vssimage, artefact.split("/")[-1], profile
        ), " -> {} -> extracting artefacts from '{}' ({}) for {}".format(
            datetime.now().isoformat().replace("T", " "),
            artefact.split("/")[-1],
            profile,
            vssimage,
        )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    return profile


def extract_memory_artefacts(
    verbosity,
    output_directory,
    volver,
    volprefix,
    artefact,
    profile,
    mempath,
    memext,
    vssimage,
    memtimeline,
    mesginsrt,
):
    # Create output directory for memory artefacts if it doesn't exist
    mem_output_dir = os.path.join(output_directory, mempath)
    if not os.path.exists(mem_output_dir):
        os.makedirs(mem_output_dir, exist_ok=True)

    if volver == "3":  # volatility3
        if not artefact.endswith("hiberfil.sys"):
            print_extraction(
                verbosity,
                output_directory,
                artefact,
                volprefix,
                mesginsrt,
                "Windows",
                "symbol table",
                vssimage,
            )
        else:
            print_extraction(
                verbosity,
                output_directory,
                artefact,
                volprefix,
                mesginsrt,
                profile,
                "symbol table",
                vssimage,
            )
        if "Windows" in profile or profile.startswith("Win"):
            volplugins = ["windows.info.Info"]
            volplugins = [
                "windows.cmdline.CmdLine",
                "windows.dlllist.DllList",
                "windows.driverscan.DriverScan",
                "windows.envars.Envars",
                "windows.filescan.Filescan",
                "windows.getservicesids.GetServiceSIDs",
                "windows.getsids.GetSIDs",
                "windows.handles.Handles",
                "windows.info.Info",
                "windows.malfind.Malfind",
                "windows.modscan.ModScan",
                "windows.modules.Modules",
                "windows.mutantscan.MutantScan",
                "windows.netscan.NetScan",
                "windows.netstat.NetStat",
                "windows.privileges.Privileges",
                "windows.pslist.PsList",
                "windows.psscan.PsScan",
                "windows.pstree.PsTree",
                "windows.registry.certificates.Certificates",
                "windows.registry.hivelist.HiveList",
                "windows.registry.hivescan.HiveScan",
                "windows.registry.printkey.PrintKey",
                "windows.registry.userassist.UserAssist",
                "windows.ssdt.SSDT",
                "windows.symlinkscan.SymlinkScan",
                "windows.vadinfo.VadInfo",
            ]
        elif (
            "macOS" in profile or profile.startswith("Mac") or profile.startswith("mac")
        ):
            volplugins = [
                "mac.bash.Bash",
                "mac.check_syscall.Check_syscall",
                "mac.check_sysctl.Check_sysctl",
                "mac.check_trap_table.Check_trap_table",
                "mac.ifconfig.Ifconfig",
                "mac.kauth_listeners.Kauth_listeners",
                "mac.kauth_scopes.Kauth_scopes",
                "mac.kevents.Kevents",
                "mac.lsmod.Lsmod",
                "mac.lsof.Lsof",
                "mac.malfind.Malfind",
                "mac.mount.Mount",
                "mac.netstat.Netstat",
                "mac.proc_maps.Maps",
                "mac.psaux.Psaux",
                "mac.pslist.PsList",
                "mac.pstree.PsTree",
                "mac.socket_filters.Socket_filters",
                "mac.timers.Timers",
                "mac.trustedbsd.Trustedbsd",
                "mac.vfsevents.VFSevents",
            ]
        else:
            volplugins = [
                "linux.bash.Bash",
                "linux.check_afinfo.Check_afinfo",
                "linux.check_creds.Check_creds",
                "linux.check_idt.Check_idt",
                "linux.check_modules.Check_modules",
                "linux.check_syscall.Check_syscall",
                "linux.elfs.Elfs",
                "linux.keyboard_notifiers.Keyboard_notifiers",
                "linux.lsmod.Lsmod",
                "linux.lsof.Lsof",
                "linux.malfind.Malfind",
                "linux.proc.Maps",
                "linux.pslist.PsList",
                "linux.pstree.PsTree",
                "linux.tty_check.tty_check",
            ]
        if memtimeline:
            plugin_count = str(len(volplugins) + 1)
        else:
            plugin_count = str(len(volplugins))
        print(
            "    Attempting to extract {} types of evidence from '{}'...".format(
                plugin_count,
                artefact.split("/")[-1],
            )
        )
        for plugin in volplugins:
            try:
                use_plugins(
                    output_directory,
                    verbosity,
                    vssimage,
                    artefact,
                    volver,
                    memext,
                    mempath,
                    profile,
                    plugin,
                )
            except Exception as e:
                print(f"    [ERROR] Failed to extract {plugin} from {artefact.split('/')[-1]}: {type(e).__name__}: {e}")
                if verbosity in ["verbose", "veryverbose"]:
                    import traceback
                    traceback.print_exc()
        if memtimeline:
            volplugins = ["timeliner.Timeliner"]
            for plugin in volplugins:
                try:
                    use_plugins(
                        output_directory,
                        verbosity,
                        vssimage,
                        artefact,
                        volver,
                        memext,
                        mempath,
                        profile,
                        plugin,
                    )
                except Exception as e:
                    print(f"    [ERROR] Failed to extract {plugin} from {artefact.split('/')[-1]}: {type(e).__name__}: {e}")
                    if verbosity in ["verbose", "veryverbose"]:
                        import traceback
                        traceback.print_exc()
    else:  # volatility2.6
        print_extraction(
            verbosity,
            output_directory,
            artefact,
            volprefix,
            mesginsrt,
            profile,
            "profile",
            vssimage,
        )
        if profile.startswith("Win"):
            volplugins = [
                "apihooks",
                "apihooksdeep",
                "cmdline",
                "cmdscan",
                "consoles",
                "directoryenumerator",
                "dlllist",
                "driverirp",
                "drivermodule",
                "driverscan",
                "envars",
                "filescan",
                "gahti",
                "gditimers",
                "getservicesids",
                "getsids",
                "handles",
                "hashdump",
                "hivelist",
                "iehistory",
                "ldrmodules",
                "malfind",
                "malprocfind",
                "messagehooks",
                "mimikatz",
                "modscan",
                "modules",
                "mutantscan",
                "ndispktscan",
                "netscan",
                "objtypescan",
                "privs",
                "pslist",
                "psscan",
                "pstree",
                "psxview",
                "shellbags",
                "shimcache",
                "shimcachemem",
                "svcscan",
                "symlinkscan",
                "systeminfo",
                "thrdscan",
                "unloadedmodules",
                "usbstor",
                "userassist",
                "userhandles",
                "vadinfo",
                "win10cookie",
            ]  # plugins
        elif (
            profile.startswith("Mac")
            or profile.startswith("mac")
            or profile.startswith("10.")
            or profile.startswith("11.")
        ):
            volplugins = [
                "mac_apihooks_kernel",
                "mac_apihooks",
                "mac_arp",
                "mac_bash",
                "mac_check_fop",
                "mac_check_mig_table",
                "mac_check_syscalls",
                "mac_check_sysctl",
                "mac_devfs",
                "mac_dyld_maps",
                "mac_ifconfig",
                "mac_kernel_classes",
                "mac_kevents",
                "mac_keychaindump",
                "mac_ldrmodules",
                "mac_list_sessions",
                "mac_lsmod_iokit",
                "mac_malfind",
                "mac_mount",
                "mac_netstat",
                "mac_network_conns",
                "mac_notifiers",
                "mac_orphan_threads",
                "mac_proc_maps",
                "mac_psaux",
                "mac_psenv",
                "mac_pslist",
                "mac_pstree",
                "mac_psxview",
                "mac_socket_filters",
                "mac_tasks",
                "mac_trustedbsd",
            ]
        else:
            volplugins = [
                "linux_arp",
                "linux_bash",
                "linux_bash_env",
                "linux_bash_hash",
                "linux_check_idt",
                "linux_check_syscall",
                "linux_check_tty",
                "linux_dmesg",
                "linux_elfs",
                "linux_enumerate_files",
                "linux_getcwd",
                "linux_ifconfig",
                "linux_info_regs",
                "linux_ldrmodules",
                "linux_library_list",
                "linux_lsof",
                "linux_malfind",
                "linux_mount",
                "linux_netscan",
                "linux_netstat",
                "linux_plthook",
                "linux_proc_maps",
                "linux_proc_maps_rb",
                "linux_psaux",
                "linux_psenv",
                "linux_pslist",
                "linux_psscan",
                "linux_pstree",
                "linux_threads",
            ]
        if memtimeline:
            plugin_count = str(len(volplugins) + 2)
        else:
            plugin_count = str(len(volplugins) + 1)
        print(
            "    Attempting to extract {} types of evidence from '{}'...".format(
                plugin_count,
                artefact.split("/")[-1],
            )
        )
        for plugin in volplugins:
            try:
                use_plugins(
                    output_directory,
                    verbosity,
                    vssimage,
                    artefact,
                    volver,
                    memext,
                    mempath,
                    profile,
                    plugin,
                )
            except:
                entry, prnt = "{},{},evidence extraction failed {},{} ({})\n".format(
                    datetime.now().isoformat(),
                    vssimage,
                    plugin,
                    artefact.split("/")[-1],
                    profile,
                ), " -> {} -> evidence extraction of '{}' failed from {}".format(
                    datetime.now().isoformat().replace("T", " "),
                    plugin,
                    vssimage,
                )
                write_audit_log_entry(
                    verbosity, output_directory, entry, prnt
                )  # failed to extract no evidence of plugin
        if profile.startswith("Win"):
            if memtimeline:
                try:
                    if not os.path.exists(output_directory + mempath + "timeliner.csv"):
                        with open(
                            output_directory + mempath + "timeliner.csv", "a"
                        ) as timeliner:
                            timeline = str(
                                subprocess.Popen(
                                    [
                                        "vol.py",
                                        "-f",
                                        artefact + memext,
                                        "--profile=" + profile,
                                        "timeliner",
                                    ],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                ).communicate()[0]
                            )[2:-1].split("\\n")
                            timeliner.write(
                                "LastWriteTime,ActionType,RegistryKey,Process,ProcessName,PID,PPID,Offset,Base,Registry,VolatilityPlugin,VolatilityProfile\n"
                            )
                            for line in timeline:
                                if "/P" in line:
                                    entries = re.findall(
                                        r"^(?P<LastWriteTime>[^\|]+)\|(?P<ActionType>[^\|]+)(?:\|(?P<RegistryKey>[\w\-\ \.\&\(\)]+\/[\w\-\ \.\&\(\)\/]+)?)?\|(?P<Process>[^\|]+)(?:\|Process\:\ (?P<ProcessName>[^\|]+))?\|PID\:\ (?P<PID>[^\|]+)\|PPID\:\ (?P<PPID>[^\|]+)\|P(?:rocess)?Offset\:\ (?P<Offset>[^\|]+)(?:\|Base\:\ (?P<Base>0x\S+))?$",
                                        str(
                                            str(line.strip())
                                            .replace("/P", "|P")
                                            .replace(" | ", "|")
                                            .replace("| ", "|")
                                            .replace("\\\\", "/")
                                            .replace(" PID:", "|PID:")
                                            .replace("Process PO", "ProcessO")
                                            .replace("/DLL B", "|B")
                                            .replace("||", "|")
                                        ),
                                    )
                                    if len(str(entries)) > 2:
                                        if len(entries[0][2]) > 0:
                                            timelinerow = str(entries[0])[1:-1].replace(
                                                "''", "'-'"
                                            ).replace(", ", ",").replace(
                                                "'", ""
                                            ) + ",{},timeliner,{}\n".format(
                                                str(entries[0][2]).lower(), profile
                                            )
                                        else:
                                            timelinerow = str(entries[0])[1:-1].replace(
                                                "''", "'-'"
                                            ).replace(", ", ",").replace(
                                                "'", ""
                                            ) + ",-,timeliner,{}\n".format(
                                                profile
                                            )
                                        timeliner.write(timelinerow)
                except:
                    (
                        entry,
                        prnt,
                    ) = "{},{},evidence extraction failed {},{} ({})\n".format(
                        datetime.now().isoformat(),
                        vssimage,
                        "timeliner",
                        artefact.split("/")[-1],
                        profile,
                    ), " -> {} -> evidence extraction or '{}' failed from {}".format(
                        datetime.now().isoformat().replace("T", " "),
                        "timeliner",
                        vssimage,
                    )
                    write_audit_log_entry(
                        verbosity, output_directory, entry, prnt
                    )  # failed to extract no evidence of plugin
            if not os.path.exists(os.path.join(output_directory, mempath, "dumpreg")):
                os.makedirs(os.path.join(output_directory, mempath, "dumpreg"))
                subprocess.Popen(
                    [
                        "vol.py",
                        "-f",
                        os.path.realpath(artefact) + memext,
                        "--profile=" + profile,
                        "dumpregistry",
                        "--dump-dir",
                        output_directory + mempath + "/dumpreg/",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()
                for dumpregroot, _, dumpregfiles in os.walk(
                    os.path.join(output_directory, mempath, "dumpreg")
                ):
                    for dumpregfile in dumpregfiles:
                        dumpreg = os.path.join(dumpregroot, dumpregfile)
                        if os.path.isfile(dumpreg) and (
                            "SAM" in dumpreg.split("/")[-1].upper()
                            or "SECURITY" in dumpreg.split("/")[-1].upper()
                            or "SOFTWARE" in dumpreg.split("/")[-1].upper()
                            or "SYSTEM" in dumpreg.split("/")[-1].upper()
                            or "ntuser" in dumpreg.split("/")[-1].lower()
                            or "usrclass" in dumpreg.split("/")[-1].lower()
                        ):
                            if os.path.isfile(dumpreg) and (
                                "SAM" in dumpreg.split("/")[-1].upper()
                                or "SECURITY" in dumpreg.split("/")[-1].upper()
                                or "SOFTWARE" in dumpreg.split("/")[-1].upper()
                                or "SYSTEM" in dumpreg.split("/")[-1].upper()
                            ):
                                extract_dumpreg_system(
                                    dumpreg,
                                    {},
                                    [],
                                    [],
                                )
                                (
                                    entry,
                                    prnt,
                                ) = "{},{},dumped registry ({}),{} ({})\n".format(
                                    datetime.now().isoformat(),
                                    vssimage,
                                    dumpregfile,
                                    artefact.split("/")[-1],
                                    profile,
                                ), " -> {} -> extracted evidence via 'dumpreg' ({}) from {}".format(
                                    datetime.now().isoformat().replace("T", " "),
                                    dumpregfile,
                                    vssimage,
                                )
                                write_audit_log_entry(
                                    verbosity, output_directory, entry, prnt
                                )  # evidence of plugin found
                            else:
                                extract_dumpreg_profile(
                                    dumpreg,
                                    {},
                                    [],
                                    [],
                                )
                        else:
                            guessed_hive = extract_dumpreg_guess(
                                dumpreg,
                                {},
                                [],
                                [],
                            )
                            if guessed_hive != "":
                                (
                                    entry,
                                    prnt,
                                ) = "{},{},dumped registry ({}),{} ({})\n".format(
                                    datetime.now().isoformat(),
                                    vssimage,
                                    dumpregfile,
                                    artefact.split("/")[-1],
                                    profile,
                                ), " -> {} -> extracted evidence via 'dumpreg' ({}) from {}".format(
                                    datetime.now().isoformat().replace("T", " "),
                                    dumpregfile,
                                    vssimage,
                                )
                                write_audit_log_entry(
                                    verbosity, output_directory, entry, prnt
                                )  # evidence of plugin found
    vssmem = profile
    if artefact.split("/")[-1] == vssimage:
        insertvssimage = " for " + vssimage
    else:
        insertvssimage = ""
    print(
        "{}Extraction of artefacts completed from '{}'{}.".format(
            volprefix, artefact.split("/")[-1], insertvssimage
        )
    )
    entry, prnt = "{},{},artefact extraction complete,{} ({})\n".format(
        datetime.now().isoformat(), vssimage, artefact.split("/")[-1], profile
    ), " -> {} -> artefact extraction from '{}' ({}) completed for {}".format(
        datetime.now().isoformat().replace("T", " "),
        artefact.split("/")[-1],
        profile,
        vssimage,
        insertvssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)

    # Enrich memory artefacts with MITRE ATT&CK techniques
    enrich_memory_artefacts_with_mitre(output_directory, mempath)

    print()
    return profile, vssmem


def enrich_memory_artefacts_with_mitre(output_directory, mempath):
    """
    Enrich memory artefact JSON files with MITRE ATT&CK technique metadata.

    Scans the memory output directory for JSON files and applies MITRE mappings
    based on the Volatility plugin type (e.g., pslist, netscan, malfind).
    """
    try:
        from rivendell.post.mitre.enrichment import MitreEnrichment, TECHNIQUES_FILE
        enrichment = MitreEnrichment()

        mem_dir = os.path.join(output_directory, mempath)
        if not os.path.exists(mem_dir):
            return

        # Find techniques file path (at case level)
        case_dir = output_directory.rstrip('/')
        techniques_file_path = os.path.join(case_dir, TECHNIQUES_FILE)

        print(" -> {} -> enriching memory artefacts with MITRE ATT&CK techniques...".format(
            datetime.now().isoformat().replace("T", " ")
        ))

        # Map Volatility plugin names to artefact types
        plugin_to_artefact = {
            "windows.pslist": "memory_pslist",
            "windows.pstree": "memory_pstree",
            "windows.cmdline": "memory_cmdline",
            "windows.netscan": "memory_netscan",
            "windows.netstat": "memory_netstat",
            "windows.malfind": "memory_malfind",
            "windows.dlllist": "memory_dlllist",
            "windows.handles": "memory_handles",
            "windows.filescan": "memory_filescan",
            "windows.driverscan": "memory_driverscan",
            "windows.modules": "memory_modules",
            "windows.svcscan": "memory_svcscan",
            "windows.getsids": "memory_getsids",
            "windows.envars": "memory_envars",
            "windows.privileges": "memory_privileges",
            "windows.mutantscan": "memory_mutantscan",
            "windows.registry": "memory_registry",
            # Also map short names
            "pslist": "memory_pslist",
            "pstree": "memory_pstree",
            "cmdline": "memory_cmdline",
            "netscan": "memory_netscan",
            "netstat": "memory_netstat",
            "malfind": "memory_malfind",
            "dlllist": "memory_dlllist",
            "handles": "memory_handles",
            "filescan": "memory_filescan",
            "driverscan": "memory_driverscan",
            "modules": "memory_modules",
            "svcscan": "memory_svcscan",
            "getsids": "memory_getsids",
            "envars": "memory_envars",
            "privileges": "memory_privileges",
            "mutantscan": "memory_mutantscan",
        }

        enriched_count = 0
        with open(techniques_file_path, 'a') as techniques_file:
            for filename in os.listdir(mem_dir):
                if filename.endswith('.json'):
                    # Extract plugin name from filename (e.g., "memory_windows.pslist.PsList.json")
                    basename = filename.replace('memory_', '').replace('.json', '')
                    # Try to match against known plugins
                    artefact_type = None
                    for plugin_name, mapped_type in plugin_to_artefact.items():
                        if plugin_name.lower() in basename.lower():
                            artefact_type = mapped_type
                            break

                    if artefact_type:
                        json_path = os.path.join(mem_dir, filename)
                        try:
                            if enrichment.enrich_json_file_streaming(json_path, techniques_file, artefact_type):
                                enriched_count += 1
                        except Exception:
                            pass

        if enriched_count > 0:
            print(" -> {} -> enriched {} memory artefact file(s) with MITRE techniques".format(
                datetime.now().isoformat().replace("T", " "),
                enriched_count
            ))

    except ImportError:
        # MITRE enrichment module not available
        pass
    except Exception as e:
        print(" -> {} -> warning: could not enrich memory artefacts with MITRE: {}".format(
            datetime.now().isoformat().replace("T", " "),
            str(e)[:100]
        ))
