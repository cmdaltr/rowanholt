"""
macOS-ATTACK-DATASET (Samir Bousseaden; GPL-3.0): macOS attacks recorded with Elastic Endpoint
Security, one JSON file each, filed by tactic only. The techniques below are Archer's reading of
each file's name; files it can't place with confidence are left out. GPL-3.0 keeps the data out
of Archer's (MIT) repository, so it's built on this machine only (INFO["local"]). See
src.mordor.telemetry.datasets.
"""

import os
from typing import Dict, Iterable, Optional, Tuple

from . import fetch
from .datasets import PARSER_VERSION, parse, summarise

NAME = "macos"
REPO = "sbousseaden/macOS-ATTACK-DATASET"
BRANCH = "main"
INFO = {"name": "macOS-ATTACK-DATASET", "url": f"https://github.com/{REPO}", "licence": "GPL-3.0", "local": True,
        "note": "macOS attacks recorded with Elastic Endpoint (2021). Built on this machine only: GPL-3.0"}

TECHNIQUES = {
    "collection_clipboard_osascript_pbpast": "T1115",
    "collection_discovery_bash_history_procexec": "T1552.003",
    "collection_screencapture_command_proc_file": "T1113",
    "credaccess_browsers_cookies_access": "T1539",
    "credaccess_cookies_crimes_chrome_debugging": "T1539",
    "credaccess_kerberos_credcache_kcc": "T1558",
    "credaccess_keychain_dumping_security": "T1555.001",
    "credaccess_keychain_pwd_retrieval_security": "T1555.001",
    "credaccess_phish_input_capture_applescript": "T1056.002",
    "credaccess_systemkey_hexdump": "T1555.001",
    "credaccess_tcc_bypass_sshd_scp_safari_cookies": "T1539",
    "credential_access_account_pwd_hash_read": "T1003",
    "evasion_deletion_quarantine_xattr": "T1553.001",
    "evasion_disable_securityupdates": "T1685",
    "evasion_envar_modif_launchctl_dylib_home": "T1574.006",
    "evasion_execution_electron_tcc_bypass_nodejs_childproc_osascript_apfell": "T1548",
    "evasion_install_root_trust_certificate": "T1553.004",
    "evasion_privesc_credaccess__persis_auth_modules_modif": "T1556.003",
    "evasion_remove_codesign": "T1553",
    "evasion_susp_zip_file_launchagent_for_office_sandbox_evasion": "T1543.001",
    "evasion_unloading_kext_kextunload": "T1685",
    "discovery_security_sw_little_snitch": "T1518.001",
    "discovery_system_profile_sw_vers": "T1082",
    "discovery_users_and_groups_dscl": "T1087.001",
    "execution_automator_workflow_template_jxa": "T1059.007",
    "execution_eggshell_default_tmp_path_base64_c2": "T1059",
    "execution_evasion_masquerading_and_hidden_file": "T1564.001",
    "execution_pkg_preinstall_shell_script_file_proc": "T1546.016",
    "execution_scripting_jxa_osascript_apfell_dwnld": "T1059.007",
    "execution_scripting_python": "T1059.006",
    "execution_suspicious_path_masquerading": "T1036",
    "lateral_movement_credaccess_kerberos_bifrost_procexec": "T1558",
    "lateral_movement_execution_reverse_shell": "T1059.004",
    "lateral_movement_prep_ssh_enabled": "T1021.004",
    "lateral_movement_ssh_from_python_procexec": "T1021.004",
    "lateral_movement_vpn_connection_cmdline": "T1021",
    "persistence_bashprofile_modify": "T1546.004",
    "persistence_calendar_event_action_procedure": "T1546",
    "persistence_create_local_account_hidden_logon": "T1136.001",
    "persistence_crontab_creation": "T1053.003",
    "persistence_crontab_runtime": "T1053.003",
    "persistence_docker_pref_modif_persistjxa": "T1543",
    "persistence_emond_process_execution": "T1546.014",
    "persistence_emond_rules_filemod": "T1546.014",
    "persistence_execution_hidden_launchd_childproc": "T1543.001",
    "persistence_execution_hidden_loginitem_creation_osascript": "T1547.015",
    "persistence_finder_plugin_sequence": "T1543",
    "persistence_launchagent_hidden_file": "T1543.001",
    "persistence_launchdaemon_file_creation": "T1543.004",
    "persistence_login_hook_process_execution": "T1037.002",
    "persistence_login_plist_script_filemod": "T1037.002",
    "persistence_periodic_job_fimemod": "T1053.003",
    "persistence_ssh_authorized_keys_filemod": "T1098.004",
    "persistence_vim_plugin_filemod": "T1546",
    "privesc_evasion_CVE-2020-9934_fake_tccdb_home_envar_manip": "T1068",
    "privesc_evasion_sudoers_modification": "T1548.003",
    "privesc_evasion_tccp_bypass_apfs_mount_cve-2020-9771": "T1068",
    "privesc_execution_enable_root_account": "T1078.003",
    "privesc_execution_setuid_chmod": "T1548.001",
    "privesc_runas_admin_applescript": "T1548.004",
    "privesc_seauthtrampoline_authorizationexecutewith_privs": "T1548.004",
    "privesc_user_added_to_admin_group": "T1098",
}


def datasets(previous: Dict[str, Dict], log=print) -> Iterable[Tuple[Dict, Optional[Dict], str]]:
    tree = fetch.tree(REPO, BRANCH)
    files = {t["path"]: t["sha"] for t in tree if t["type"] == "blob" and t["path"].endswith(".json")
             and os.path.basename(t["path"])[:-5] in TECHNIQUES}
    log(f"macOS-ATTACK-DATASET: {len(files)} recordings")

    def one(path):
        key = f"{PARSER_VERSION}:{files[path]}"
        name = os.path.basename(path)[:-5]
        did = f"macos:{name}"
        if previous.get(did, {}).get("key") == key:
            return previous[did]["summary"], None, key
        counts, values = summarise(parse(fetch.raw(REPO, path, BRANCH)))
        tid = TECHNIQUES[name]
        return {"id": did, "source": NAME, "title": f"{name.replace('_', ' ')} ({tid})", "techniques": [tid],
                "platform": ["macos"], "tools": [], "description": "", "events": counts,
                "url": f"https://github.com/{REPO}/blob/{BRANCH}/{path}"}, values, key

    yield from fetch.pool(one, sorted(files), log)
