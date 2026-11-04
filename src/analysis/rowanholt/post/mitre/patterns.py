#!/usr/bin/env python3 -tt
"""
MITRE ATT&CK Pattern Matcher

Content-based pattern matching for MITRE technique identification.
Extracts patterns from transforms.py to provide SIEM-independent technique detection.

This module scans JSON artefact content for indicators that map to specific
MITRE ATT&CK techniques, ensuring consistent results regardless of which
SIEM platform (or none) is used for analysis.

Author: Rowanholt DF Acceleration Suite
Version: 1.0.0
"""

import re
from typing import Dict, List, Set, Tuple, Optional


# Pattern categories and their corresponding JSON field mappings
# Format: "Category_|_pattern" -> "TechniqueID - TechniqueName|TechniqueID2 - TechniqueName2"
PATTERN_MAPPINGS = {
    # ============================================================
    # ARTEFACT/FILE PATH PATTERNS
    # Applied to: file paths, artefact locations, registry paths
    # ============================================================
    "Artefact": {
        r"/etc/profile|/etc/zshenv|/etc/zprofile|/etc/zlogin|profile\.d|bash_profile|bashrc|bash_login|bash_logout|zshrc|zshenv|zlogout|zlogin": ["T1546.004"],
        r"/print processors/|/print_processors/": ["T1547.012"],
        r"/security/policy/secrets": ["T1003.004"],
        r"/special/perf": ["T1337.002"],
        r"\.7z|\.arj|\.tar|\.tgz|\.zip|makecab|tar|xcopy|diantz": ["T1560.001"],
        r"\.key|\.p12|\.pfx|\.ppk": ["T1552.004"],
        r"\.chm|\.hh": ["T1218.001"],
        r"\.cpl|panel/cpls": ["T1218.002"],
        r"\.docm|\.xlsm|\.pptm": ["T1137.001", "T1203", "T1204.002", "T1559.001"],
        r"\.job|schtask": ["T1053.005"],
        r"\.ps1": ["T1059.001"],
        r"sc\.exe": ["T1007", "T1489", "T1543.003", "T1569.002"],
        r"active setup/installed components|active_setup/installed_components": ["T1547.014"],
        r"add-trusted-cert|trustroot|certmgr": ["T1553.004"],
        r"admin%24|admin\$|c%24|c\$|ipc%24|ipc\$": ["T1021.002", "T1570"],
        r"appcmd\.exe|inetsrv/config/applicationhost\.config": ["T1505.004"],
        r"at\.(?:exe|allow|deny)": ["T1053.002"],
        r"atbroker|displayswitch|magnify|narrator|osk\.|sethc|utilman": ["T1546.008"],
        r"authorizationexecutewithprivileges|security_authtrampoline": ["T1548.004"],
        r"authorized_keys|sshd_config|ssh-keygen": ["T1098.004"],
        r"reg add|reg delete|reg import": ["T1112"],
        r"backgrounditems\.btm": ["T1547.015"],
        r"bash_history": ["T1552.003"],
        r"bcdedit": ["T1553.006", "T1562.009"],
        r"bootcfg": ["T1562.009"],
        r"certutil": ["T1036.003", "T1140", "T1553.004"],
        r"pwpolicy|getaccountpolicies": ["T1201"],
        r"clipboard|pbpaste": ["T1115"],
        r"cmd |cmd_|cmd\.": ["T1059.003"],
        r"cmmgr32|cmstp|cmlua": ["T1218.003"],
        r"com\.apple\.quarantine|xattr|xttr": ["T1553.001", "T1564.009"],
        r"contentsofdirectoryatpath|pathextension": ["T1106"],
        r"csc\.exe|gcc |gcc_": ["T1027.004"],
        r"cscript|pubprn": ["T1216.001"],
        r"csrutil": ["T1553.006"],
        r"curl |curl_|wget |wget_": ["T1048.003", "T1553.001"],
        r"currentcontrolset/control/lsa": ["T1003.001", "T1547.002", "T1547.005", "T1556.002"],
        r"currentcontrolset/control/nls/language": ["T1614.001"],
        r"currentcontrolset/control/print/monitors": ["T1547.010"],
        r"currentcontrolset/control/safeboot/minimal": ["T1562.009"],
        r"currentcontrolset/control/session manager|currentcontrolset/control/session_manager": ["T1546.009", "T1547.001"],
        r"currentcontrolset/services/termservice/parameters": ["T1505.005"],
        r"currentcontrolset/services/w32time/timeproviders": ["T1547.003"],
        r"currentversion/app paths|software/classes/ms-settings/shell/open/command|currentversion/app_paths|software/classes/mscfile/shell/open/command|software/classes/exefile/shell/runas/command/isolatedcommand|eventvwr|sdclt": ["T1548.002"],
        r"currentversion/appcompatflags/installedsdb": ["T1546.011"],
        r"currentversion/explorer/fileexts": ["T1546.001"],
        r"currentversion/image file execution options|currentversion/image_file_execution_options": ["T1546.008", "T1546.012", "T1547.002", "T1547.005"],
        r"currentversion/policies/credui/enumerateadministrators": ["T1087.001", "T1087.002"],
        r"currentversion/run|currentversion/policies/explorer/run|currentversion/explorer/user/|currentversion/explorer/shell": ["T1547.001"],
        r"currentversion/windows|nt/currentversion/windows": ["T1546.010"],
        r"currentversion/winlogon/notify|currentversion/winlogon/userinit|currentversion/winlogon/shell": ["T1547.001", "T1547.004"],
        r"docker build|docker_build": ["T1612"],
        r"docker create|docker start|docker_create|docker_start": ["T1610"],
        r"docker exec|docker run|kubectl exec|kubectl run|docker_exec|docker_run|kubectl_exec|kubectl_run": ["T1609"],
        r"dscacheutil|ldapsearch": ["T1069.002", "T1087.002"],
        r"dscl": ["T1069.001", "T1564.002"],
        r"emond": ["T1546.014", "T1547.015"],
        r"environment/userinitmprlogonscript": ["T1037.001"],
        r"forwardingsmtpaddress|x-forwarded-to|x-mailfwdby|x-ms-exchange-organization-autoforwarded": ["T1114.003"],
        r"fsutil|fsinfo": ["T1120"],
        r"gpttmpl\.inf|scheduledtasks\.xml": ["T1484.001"],
        r"gsecdump|minidump|mimikatz|pwdumpx|secretsdump|reg save|net user|net\.exe user|net1 user|net1\.exe user": ["T1003.002"],
        r"histcontrol": ["T1562.003"],
        r"hostname |systeminfo|whoami": ["T1033"],
        r"launchagents": ["T1543.001"],
        r"launchctl": ["T1569.001"],
        r"launchdaemons": ["T1543.004"],
        r"lc_code_signature|lc_load_dylib": ["T1546.006", "T1574.004"],
        r"lc_load_weak_dylib|rpath|loader_path|executable_path|ottol": ["T1547.004"],
        r"ld_preload|dyld_insert_libraries|ld\.so\.preload": ["T1129", "T1547.006"],
        r"loginitems|loginwindow|smloginitemsetenabled|uielement|quarantine": ["T1547.015"],
        r"loginwindow|hide500users|dscl|uniqueid": ["T1564.002"],
        r"manager/safedllsearchmode|security/policy/secrets": ["T1003.001", "T1547.008"],
        r"mavinject\.exe": ["T1218.013"],
        r"microsoft/windows/softwareprotectionplatform/eventcachemanager|scvhost|svchast|svchust|svchest|lssas|lsasss|lsaas|cssrs|canhost|conhast|connhost|connhst|iexplorer|iexploror|iexplorar": ["T1036.004"],
        r"mmc\.exe|wbadmin\.msc": ["T1218.014"],
        r"insmod|kextload": ["T1547.006"],
        r"assembly\.load": ["T1620"],
        r"mshta": ["T1218.005"],
        r"netsh": ["T1049", "T1090.001", "T1135", "T1518.001"],
        r"normal\.dotm|personal\.xlsb": ["T1137.001"],
        r"nt/dnsclient": ["T1557.001"],
        r"ntds|ntdsutil|secretsdump": ["T1003.003"],
        r"odbcconf": ["T1218.008"],
        r"onedrive|1drv|azure|icloud|cloudrive|dropbox|drive\.google|\.box\.com|egnyte|mediafire|zippyshare|megaupload|4shared|pastebin": ["T1537", "T1567.002"],
        r"pam_unix\.so": ["T1556.003"],
        r"passwords?\.(?:txt|csv|xlsx?|docx?)|credentials\.(?:txt|csv|xml|json)": ["T1552.001"],
        r"\.kdbx|\.opvault|\.agilekeychain": ["T1555.005"],
        r"ping\.|ping |traceroute|ifconfig|ipconfig|dig |etc/host|etc/hosts|bonjour": ["T1016.001", "T1018"],
        r"policy\.vpol|vaultcmd|vcrd": ["T1555.004"],
        r"portopening": ["T1090.001"],
        r"powershell\.exe": ["T1059.001", "T1106"],
        r"profile\.d|bash_profile|bashrc|bash_login|bash_logout": ["T1546.004"],
        r"ps -|ps_-": ["T1057"],
        r"psexec": ["T1003.001", "T1569.002", "T1570"],
        r"python|\.py |\.py_": ["T1059.006"],
        r"rassfm\.dll": ["T1556.005"],
        r"rc\.local|rc\.common": ["T1037.004"],
        r"rm -|rm  -|rm_-|del|deletebucket|deletedbcluster|deleteglobalcluster|sdelete": ["T1070.004", "T1485"],
        r"scp\s.*:|sftp|downloadstring|invoke-webrequest|downloadfile|bitsadmin\s.*/transfer": ["T1105"],
        r"scrnsave": ["T1546.002"],
        r"software/microsoft/netsh": ["T1546.007"],
        r"software/microsoft/ole": ["T1546.015"],
        r"software/policies/microsoft/previousversions/disablelocalpage": ["T1490"],
        r"startupitems": ["T1037.002"],
        r"startupparameters": ["T1037.002", "T1037.005", "T1547.015"],
        r"sudo|timestamp_timeout|tty_tickets": ["T1548.003"],
        r"systemsetup|systeminfo|show  ?version|df  ?-ah": ["T1082"],
        r"sysvol/policies": ["T1615"],
        r"tasklist(?:\.exe)?\s": ["T1007", "T1518.001"],
        r"sleep\s+\d|start-sleep\s": ["T1497.003"],
        r"timer": ["T1053.006"],
        r"trap\s+['\"].+['\"]\s+\w+": ["T1546.005"],
        r"tscon": ["T1563.002"],
        r"u202e": ["T1036.002"],
        r"vbscript|wscript": ["T1059.005", "T1059.007"],
        r"verclsid": ["T1218.012"],
        r"winrs|enter-pssession|invoke-command\s.*-computername": ["T1021.006"],
        r"wmic|msxsl": ["T1047", "T1220"],
        r"xdg|autostart": ["T1547.013"],
        r"xwd|screencapture": ["T1113"],
        r"zwqueryeafile|zwseteafile": ["T1564.004"],
    },

    # ============================================================
    # COMMAND LINE PATTERNS
    # Applied to: command lines, process arguments, script content
    # ============================================================
    "Command": {
        r"-decode": ["T1140"],
        r"/\.secrets\.mkey|secrets\.ldb|/etc/krb5\.conf|kcc|kinit|klist|krb5ccname|ktutil": ["T1558"],
        r"/add": ["T1136.001", "T1136.002"],
        r"/delete": ["T1070.005"],
        r"/domain": ["T1087.002", "T1136.002"],
        r"\.ps1|invoke-command|start-process|system\.management\.automation": ["T1059.001"],
        r"add-mailboxpermission|createaccesskey|createkeypair|gcloud compute os-login ssh-keys add|gcloud iam service-accounts keys create|importkeypair|ip ssh pubkey-chain|sts:getfederationtoken": ["T1098.001"],
        r"add-mailboxpermission|set-casmailbox": ["T1098.002"],
        r"setnotifycmdline|bitsadmin": ["T1197"],
        r"addmonitor": ["T1547.010"],
        r"addprintprocessor|getprintprocessordirectory": ["T1547.012"],
        r"addsid|get-aduser|dsaddsidhistory": ["T1134.005"],
        r"allowreversiblepasswordencryption|userparameters|set-adaccountcontrol": ["T1556.005"],
        r"ammyyadmin|anydesk|logmein|screenconnect|team viewer|vnc": ["T1219"],
        r"attrib": ["T1564.001"],
        r"auditctl": ["T1562.012"],
        r"auditpol": ["T1562.002"],
        r"authentication packages|authentication_packages": ["T1547.002"],
        r"az vm list|describedbinstances|describeinstances|gcloud compute instances list|getpublicaccessblock|headbucket|listbuckets": ["T1580"],
        r"beingdebugged": ["T1622"],
        r"bootexecute": ["T1547.001"],
        r"clear-history": ["T1070.003"],
        r"connect-azaccount|connect-mggraph|gcloud  ?auth  ?login": ["T1021.007"],
        r"clear-history|historysavestyle|savenothing": ["T1562.003"],
        r"copyfromscreen": ["T1113"],
        r"cor_profiler": ["T1547.012"],
        r"cplapplet|dllentrypoint|control_rundll|controlrundllasuser": ["T1036.003", "T1218.011"],
        r"createfiletransacted|createtransaction|ntcreatethreadex|ntunmapviewofsection|virtualprotectex": ["T1055.013"],
        r"createpolicyversion|attachuserpolicy": ["T1098.003"],
        r"createremotethread": ["T1055.001", "T1055.011", "T1055.002", "T1055.005", "T1106"],
        r"debug only this process|debug process|ntsd": ["T1546.012"],
        r"describesecuritygroups": ["T1518.001"],
        r"dns-sd  ?-b  ?_ssh": ["T1046"],
        r"docker\.sock|unshare": ["T1611"],
        r"driverquery\.exe|enumdevicedrivers": ["T1652"],
        r"dsenumeratedomaintrusts|getalltrustrelationships|get-accepteddomain|nltest|dsquery|get-netdomaintrust|get-netforesttrust": ["T1482"],
        r"duo-sid": ["T1550.004"],
        r"enablemulticast": ["T1557.001"],
        r"execute-assembly|nscreateobjectfileimagefrommemory|memfd_create|execve": ["T1620"],
        r"filerecvwriterand": ["T1027.001"],
        r"find-avsignature": ["T1027.005"],
        r"gcloud compute instances create|runinstances": ["T1578.002"],
        r"gcloud compute instances delete|terminateinstances": ["T1578.003"],
        r"gcloud iam service-accounts list|gcloud projects get-iam-policy|get-adgroupmember|get-aduser|get-globaladdresslist|get-msolrolemember": ["T1087.004"],
        r"get-addefaultdomainpasswordpolicy": ["T1201"],
        r"get-globaladdresslist": ["T1087.003"],
        r"get-unattendedinstallfile|get-webconfig|get-applicationhost|get-sitelistpassword|get-cachedgpppassword|get-registryautologon": ["T1552.002"],
        r"getasynckeystate|setwindowshookex": ["T1056.001"],
        r"global/snapshots/|sourcesnapshot": ["T1578.002"],
        r"gpresult|get-domaingpo": ["T1615"],
        r"hklm/sam|hklm/system": ["T1003.002"],
        r"iam\.serviceaccounts\.actas|iam:passrole": ["T1648"],
        r"icacls|cacls|takeown|attrib": ["T1222.001"],
        r"iconenvironmentdatablock": ["T1027.010", "T1027.012"],
        r"installutil": ["T1218.004"],
        r"invoke-dosfucation|invoke-obfuscation|invoke-psimage|linker": ["T1027.010"],
        r"invoke-psimage": ["T1001.002"],
        r"itaskservice|itaskdefinition|itasksettings": ["T1559.001"],
        r"kernelcallbacktable|fncopydata|fndword": ["T1574.013"],
        r"libpcap|pcap_setfilter|setsockopt|so_attach_filter|winpcap": ["T1205"],
        r"lsadump|dcshadow": ["T1207"],
        r"mailboxexportrequest|x-ms-exchange-organization-autoforwarded|x-mailfwdby|x-forwarded-to|forwardingsmtpaddress": ["T1114.003"],
        r"mavinject|injectrunning": ["T1218.013"],
        r"microsoft\.office\.interop": ["T1559.001"],
        r"mmc ": ["T1564.008"],
        r"register-wmievent|__eventfilter|commandlineeventconsumer|activescripteventconsumer|filtertoconsumerbinding": ["T1546.003"],
        r"monitor capture|tcpdump": ["T1040"],
        r"msbuild": ["T1127.001", "T1569.002"],
        r"mshta": ["T1218.005"],
        r"msiexec(?:\.exe)?\s.*(?:https?://|\\\\)|alwaysinstallelevated": ["T1218.007"],
        r"mssaveblob|mssaveoropenblob": ["T1027.006"],
        r"net accounts|net\.exe accounts|net1 accounts|net1\.exe accounts": ["T1201"],
        r"net share|net\.exe share|net1 share|net1\.exe share": ["T1135"],
        r"net start|net\.exe start|net1 start|net1\.exe start|net stop|net\.exe stop|net1 stop|net1\.exe stop": ["T1007", "T1569.002"],
        r"net time|net\.exe time|net1 time|net1\.exe time": ["T1124"],
        r"net use|net\.exe use|net1 use|net1\.exe use": ["T1049", "T1070.005", "T1136.001", "T1136.002", "T1574.008"],
        r"net view|neighbours": ["T1018", "T1135"],
        r"netsh  ?wlan  ?show  ?profile|netsh wlan show profiles|security find-generic-password -wa wifiname|wlanapi\.dll": ["T1016.002"],
        r"netstat|net session|net\.exe session|net1 session|net1\.exe session": ["T1049"],
        r"new-gpoimmediatetask": ["T1484.001"],
        r"new-inboxrule|set-inboxrule": ["T1564.008"],
        r"nltest": ["T1482"],
        r"notonorafter|accesstokenlifetime|lifetimetokenpolicy|zmprov gdpak|assumerole|getfederationtoken": ["T1606.002"],
        r"nsapplescript|osacompile|osascript": ["T1059.002"],
        r"nsxpcconnection": ["T1559.003"],
        r"ntunmapviewofsection": ["T1055.012", "T1055.013"],
        r"performancecache|_vba_project": ["T1564.007"],
        r"plutil|lsuielement|lsenvironment|dfbundledisplayname|cfbundleidentifier": ["T1647"],
        r"policy\.vpol|vaultcmd|vcrd|listcreds|credenumeratea": ["T1555.004"],
        r"powercfg": ["T1653"],
        r"procdump|sekurlsa": ["T1003.001"],
        r"psinject|peinject|ntqueueapcthread|queueuserapc": ["T1055.004"],
        r"set-psreadlineoption": ["T1070.003", "T1562.003"],
        r"quser|query user|hostname ": ["T1033"],
        r"reg add|reg delete|reg import": ["T1112"],
        r"reg query": ["T1012", "T1518.001"],
        r"registermodule": ["T1505.004"],
        r"regsvcs|regasm|comregisterfunction|comunregisterfunction": ["T1218.009"],
        r"regsvr": ["T1218.008", "T1218.010"],
        r"schtask|\.job": ["T1053.005"],
        r"scvhost|svchast|svchust|svchest|lssas|lsasss|lsaas|cssrs|canhost|conhast|connhost|connhst|iexplorer|iexploror|iexplorar": ["T1036.004"],
        r"set-adaccountpassword": ["T1531"],
        r"set-casmailbox": ["T1098.005"],
        r"set-etwtraceprovider|zwopenprocess|getextendedtcptable": ["T1562.006"],
        r"setthreadcontext": ["T1055.003", "T1055.004", "T1055.005", "T1055.012", "T1055.013", "T1106"],
        r"setwindowshook|setwineventhook": ["T1056.004"],
        r"startupitems": ["T1037.005"],
        r"sts:getfederationtoken": ["T1550.001"],
        r"termsrv ": ["T1505.005"],
        r"testsigning": ["T1553.006"],
        r"update-msolfederateddomain|set federation|domain authentication": ["T1484.002"],
        r"updateprocthreadattribute": ["T1134.003", "T1134.004"],
        r"useradd": ["T1136.001"],
        r"msacpi_thermalzonetemperature": ["T1497.001"],  # vmtoolsd is every VM's own
        r"vssadmin|wbadmin|shadowcopy": ["T1006", "T1490", "T1553.006"],
        r"wevtutil|openeventlog|cleareventlog": ["T1070.001", "T1654"],
        r"-w(?:indowstyle)? +hidden": ["T1564.003"],
        r"winexec": ["T1106", "T1543.003", "T1546.009"],
        r"writeprocessmemory": ["T1055.001", "T1055.002", "T1055.003", "T1055.004", "T1055.005", "T1055.011", "T1055.012", "T1055.013", "T1106", "T1574.013"],
        r"zwunmapviewofsection": ["T1055.012"],
    },

    # ============================================================
    # WINDOWS EVENT ID PATTERNS
    # Applied to: Event IDs in Windows Event Logs
    # ============================================================
    "EventID": {
        r"^10|12|13$": ["T1218.003"],
        r"^1020$": ["T1557.003"],
        r"^106|140|141|4698|4700|4701$": ["T1053.002", "T1053.005"],
        r"^1063$": ["T1557.003"],
        r"^1074|6006$": ["T1529"],
        r"^1102$": ["T1070.001"],
        r"^1341$": ["T1557.003"],
        r"^1342$": ["T1557.003"],
        r"^17|18$": ["T1055.002"],
        r"^3033|3063$": ["T1547.008", "T1553.003"],
        r"^307|510$": ["T1484.002"],
        r"^400$": ["T1562.010"],
        r"^4624|4634$": ["T1558.001", "T1558.002"],
        r"^4625|4648|4771$": ["T1110.003"],
        r"^4657$": ["T1112", "T1557.001"],
        r"^4670$": ["T1098", "T1222.001"],
        r"^4672$": ["T1484.001", "T1558.001"],
        r"^4688$": ["T1027.010"],
        r"^4697|7045$": ["T1021.003"],
        r"^4704|5136|5137|5138|5139|5141$": ["T1484.001"],
        r"^4720$": ["T1136.001", "T1136.002"],
        r"^4723|4724|4726|4740$": ["T1531"],
        r"^4728|4738$": ["T1098"],
        r"^4768|4769$": ["T1550.002", "T1550.003", "T1558.003"],
        r"^4928|4929$": ["T1207"],
        r"^524$": ["T1490"],
        r"^5861$": ["T1546.003"],
        r"^7045$": ["T1021.003", "T1557.001"],
        r"^81$": ["T1553.003"],
    },

    # ============================================================
    # FILENAME PATTERNS
    # Applied to: filenames, executable names
    # ============================================================
    "Filename": {
        r"\.7z|\.arj|\.tar|\.tgz|\.zip|makecab|xcopy|diantz": ["T1560.001"],
        r"\.key|\.p12|\.pfx|\.ppk": ["T1552.004"],
        r"\.chm|\.hh": ["T1218.001"],
        r"\.cpl": ["T1218.002"],
        r"\.docm|\.xlsm|\.pptm": ["T1137.001", "T1203", "T1204.002", "T1559.001"],
        r"\.job": ["T1053.005"],
        r"\.ps1": ["T1059.001"],
        r"sc\.exe": ["T1007", "T1489", "T1543.003", "T1569.002"],
        r"appcmd\.exe|inetsrv/config/applicationhost\.config": ["T1505.004"],
        r"at\.(?:exe|allow|deny)": ["T1053.002"],
        r"atbroker|displayswitch|magnify|narrator|osk\.|sethc|utilman": ["T1546.008"],
        r"auditctl": ["T1562.012"],
        r"autoruns": ["T1112"],
        r"backgrounditems\.btm": ["T1547.015"],
        r"bash_history": ["T1552.003"],
        r"bcdedit": ["T1553.006", "T1562.009"],
        r"bootcfg": ["T1562.009"],
        r"certmgr": ["T1553.004"],
        r"certutil": ["T1036.003", "T1140", "T1553.004"],
        r"cmd |cmd_|cmd\.": ["T1059.003"],
        r"com\.apple\.quarantine": ["T1553.001"],
        r"csc\.exe": ["T1027.004"],
        r"cscript": ["T1216.001"],
        r"csrutil": ["T1553.006"],
        r"eventvwr|sdclt": ["T1548.002"],
        r"fsutil|fsinfo": ["T1120"],
        r"gpttmpl\.inf|scheduledtasks\.xml": ["T1484.001"],
        r"mavinject\.exe": ["T1218.013"],
        r"mmc\.exe|wbadmin\.msc": ["T1218.014"],
        r"assembly\.load": ["T1620"],
        r"mshta": ["T1218.005"],
        r"normal\.dotm|personal\.xlsb": ["T1137.001"],
        r"odbcconf": ["T1218.008"],
        r"pam_unix\.so": ["T1556.003"],
        r"policy\.vpol|vaultcmd|vcrd": ["T1555.004"],
        r"powershell\.exe": ["T1059.001"],
        r"profile\.d|bash_profile|bashrc|bash_login|bash_logout": ["T1546.004"],
        r"psexec": ["T1003.001", "T1569.002", "T1570"],
        r"pubprn": ["T1216.001"],
        r"python|\.py": ["T1059.006"],
        r"rassfm\.dll": ["T1556.005"],
        r"rc\.local|rc\.common": ["T1037.004"],
        r"reg\.exe": ["T1112"],
        r"sdelete|deletebucket|deletedbcluster|deleteglobalcluster": ["T1070.004", "T1485"],
        r"scrnsave": ["T1546.002"],
        r"timestamp_timeout|tty_tickets": ["T1548.003"],
        r"sysvol/policies": ["T1615"],
        r"tscon": ["T1563.002"],
        r"wmic|msxsl": ["T1047", "T1220"],
    },

    # ============================================================
    # NETWORK PORT PATTERNS (Foreign/Local)
    # Applied to: network connection ports
    # ============================================================
    "Port": {
        r"^110$|^143$|^465$|^993$|^995$": ["T1048.003", "T1071.003"],
        r"^135$": ["T1047", "T1048.003"],
        r"^137$": ["T1187", "T1557.001"],
        r"^139$": ["T1110.001", "T1110.003", "T1110.004", "T1133", "T1187"],
        r"^20$|^21$": ["T1041", "T1071.002", "T1048.003"],
        r"^22$|^23$": ["T1021.004", "T1048.003", "T1110.001", "T1110.003", "T1110.004", "T1133"],
        r"^2375$|^2376$": ["T1612"],
        r"^25$": ["T1041", "T1048.003", "T1071.003"],
        r"^3389$": ["T1021.001", "T1048.003", "T1210"],
        r"^389$|^88$|^1433$|^1521$|^3306$": ["T1110.001", "T1110.003", "T1110.004"],
        r"^443$": ["T1041", "T1048.001", "T1048.002", "T1071.001", "T1110.001", "T1110.003", "T1110.004", "T1187", "T1189"],
        r"^445$": ["T1021.002", "T1041", "T1110.001", "T1110.003", "T1110.004", "T1133", "T1187", "T1210"],
        r"^53$": ["T1041", "T1048.003", "T1071.002"],
        r"^5355$": ["T1048.003", "T1557.001"],
        r"^5800$|^5938$|^5984$|^8200$": ["T1048.003", "T1219"],
        r"^5900$": ["T1021.005", "T1219", "T1048.003"],
        r"^5985$|^5986$": ["T1021.006", "T1047"],
        r"^69$|^989$|^990$": ["T1071.002", "T1048.003"],
        r"^80$": ["T1041", "T1048.003", "T1071.001", "T1110.004", "T1110.001", "T1110.003", "T1187", "T1189"],
    },

    # ============================================================
    # PROCESS NAME PATTERNS
    # Applied to: process names, image paths
    # ============================================================
    "Process": {
        r"ammyyadmin|anydesk|logmein|screenconnect|team viewer|vnc": ["T1219"],
        r"at\.(exe|allow|deny)": ["T1053.002"],
        r"atbroker|displayswitch|magnify|narrator|osk\.|sethc|utilman": ["T1546.008"],
        r"attrib": ["T1564.001"],
        r"bcdedit": ["T1490", "T1553.006", "T1562.009"],
        r"certutil": ["T1036.003", "T1140", "T1553.004"],
        r"cmd |cmd_|cmd\.": ["T1059.003"],
        r"cmmgr32|cmstp|cmlua": ["T1218.003"],
        r"csc\.exe": ["T1027.004"],
        r"cscript": ["T1216.001"],
        r"curl |curl_|wget |wget_": ["T1048.003", "T1553.001"],
        r"dcsync": ["T1550.003"],
        r"dscl": ["T1069.001"],
        r"gsecdump|mimikatz|pwdumpx|secretsdump|reg save|net user|net\.exe user|net1 user|net1\.exe user": ["T1003.002"],
        r"hostname |net config|net\.exe config|net1 config|net1\.exe config|netuser-getinfo|query user|quser|systeminfo|whoami": ["T1033"],
        r"icacls|cacls|takeown|attrib": ["T1222.001"],
        r"installutil": ["T1218.004"],
        r"launchagents": ["T1543.001"],
        r"launchctl": ["T1569.001"],
        r"launchdaemons": ["T1543.004"],
        r"lsadump|dcshadow": ["T1207"],
        r"msbuild": ["T1127.001", "T1569.002"],
        r"mshta": ["T1218.005"],
        r"netsh": ["T1049", "T1090.001", "T1135", "T1518.001"],
        r"ntdsutil|secretsdump": ["T1003.003"],
        r"odbcconf": ["T1218.008"],
        r"powershell\.exe": ["T1059.001"],
        r"procdump|sekurlsa": ["T1003.001"],
        r"psexec": ["T1003.001", "T1569.002", "T1570"],
        r"python|\.py": ["T1059.006"],
        r"reg\.exe": ["T1112"],
        r"schtask|\.job": ["T1053.005"],
        r"wevtutil": ["T1070.001", "T1654"],
        r"wmic|invoke-wmi": ["T1047", "T1220"],
        r"wscript": ["T1059.005", "T1059.007"],
    },

    # ============================================================
    # PLIST PATTERNS (macOS)
    # Applied to: plist file content
    # ============================================================
    "Plist": {
        r"loginitems|loginwindow|smloginitemsetenabled|uielement|quarantine": ["T1547.015"],
        r"rulesactivestate|syncedrules|unsyncedrules|messagerules": ["T1564.008"],
        r"startupitems": ["T1037.002"],
        r"startupparameters": ["T1037.002", "T1037.005", "T1547.015"],
    },
}


def whole_words(pattern: str) -> str:
    """Each top-level alternative matched as a whole word on the sides it starts or ends with a
    letter or digit: "tar" no longer matches inside "start", nor "dir" inside "directory", while
    "\\.lnk" and "reg " match as before."""
    parts, depth, current, i = [], 0, "", 0
    while i < len(pattern):
        char = pattern[i]
        if char == "\\":
            current += pattern[i:i + 2]
            i += 2
            continue
        depth += char == "("
        depth -= char == ")"
        if char == "|" and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += char
        i += 1
    parts.append(current)
    # The word may end in a plural, a bitness or version, or an API's Ex/A/W: schtasks, regsvr32,
    # python3, SetWindowsHookExA
    end = "(?:s|ex|32|64|\\d)?[aw]?(?![a-z0-9])"
    return "|".join(("(?<![a-z0-9])" if p[:1].isalnum() else "") + p + (end if p[-1:].isalnum() else "")
                    for p in parts if p)


class MitrePatternMatcher:
    """
    Content-based MITRE ATT&CK technique pattern matcher.

    Scans artefact content for patterns that indicate specific techniques,
    providing consistent results independent of any SIEM platform.
    """

    def __init__(self):
        """Initialize pattern matcher with compiled regex patterns."""
        self._compiled_patterns: Dict[str, List[Tuple[re.Pattern, List[str]]]] = {}
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile all regex patterns for efficient matching."""
        for category, patterns in PATTERN_MAPPINGS.items():
            self._compiled_patterns[category] = []
            for pattern, techniques in patterns.items():
                try:
                    # "^4624|4634$" alternates before it anchors: 4634 matched inside 14634, and
                    # "^10|12|13$" matched any value with 12 in it. An ID is the whole value
                    if category == "EventID":
                        pattern = "^(?:" + pattern.strip("^$").replace("$|", "|").replace("|^", "|") + ")$"
                    elif category != "Port":
                        pattern = whole_words(pattern)
                    compiled = re.compile(pattern, re.IGNORECASE)
                    self._compiled_patterns[category].append((compiled, techniques))
                except re.error as e:
                    # Skip invalid patterns
                    print(f"Warning: Invalid regex pattern '{pattern}': {e}")

    def match_content(self, content: str, categories: Optional[List[str]] = None) -> Set[str]:
        """
        Match content against all patterns and return matching technique IDs.

        Args:
            content: The text content to scan
            categories: Optional list of categories to match against.
                       If None, matches against all categories.

        Returns:
            Set of matching MITRE technique IDs
        """
        if not content:
            return set()

        techniques = set()
        categories_to_check = categories or list(self._compiled_patterns.keys())

        for category in categories_to_check:
            if category not in self._compiled_patterns:
                continue

            for pattern, technique_ids in self._compiled_patterns[category]:
                if pattern.search(content):
                    techniques.update(technique_ids)

        return techniques

    def match_field(self, field_name: str, field_value: str) -> Set[str]:
        """
        Match a specific field against appropriate pattern categories.

        Args:
            field_name: Name of the JSON field
            field_value: Value of the field

        Returns:
            Set of matching MITRE technique IDs
        """
        if not field_value or not isinstance(field_value, str):
            return set()

        # Map field names to pattern categories
        field_lower = field_name.lower()

        # Determine which categories to apply based on field name
        categories = []

        # File/path related fields
        if any(x in field_lower for x in ['path', 'file', 'source', 'artefact', 'location', 'directory', 'folder', 'key', 'registry']):
            categories.extend(['Artefact', 'Filename'])

        # Command/process related fields
        if any(x in field_lower for x in ['command', 'cmd', 'process', 'executable', 'image', 'argument', 'cmdline', 'commandline']):
            categories.extend(['Command', 'Process'])

        # Event ID fields, by name: "id" is in pid, guid, uuid, hidden and valid
        if field_lower.endswith(('eventid', 'event_id')):
            categories.append('EventID')

        # Port numbers aren't matched: 443, 80 and 53 tagged eight techniques each for every
        # connection a memory image holds. The Port table stays for reference

        # Message/log fields
        if any(x in field_lower for x in ['message', 'msg', 'log', 'data', 'content', 'body', 'text', 'value']):
            categories.extend(['Artefact', 'Command', 'Filename'])

        # Plist specific
        if any(x in field_lower for x in ['plist', 'apple', 'launchd']):
            categories.append('Plist')

        # If no specific category matched, apply general patterns
        if not categories:
            categories = ['Artefact', 'Command', 'Filename']

        return self.match_content(field_value, list(set(categories)))

    def scan_record(self, record: Dict) -> Set[str]:
        """
        Scan a JSON record and return all matching technique IDs.

        Args:
            record: A dictionary representing a JSON record

        Returns:
            Set of matching MITRE technique IDs
        """
        techniques = set()

        for field_name, field_value in record.items():
            if isinstance(field_value, str):
                techniques.update(self.match_field(field_name, field_value))
            elif isinstance(field_value, list):
                for item in field_value:
                    if isinstance(item, str):
                        techniques.update(self.match_field(field_name, item))
                    elif isinstance(item, dict):
                        techniques.update(self.scan_record(item))
            elif isinstance(field_value, dict):
                techniques.update(self.scan_record(field_value))

        return techniques


# Global instance for efficiency
_pattern_matcher: Optional[MitrePatternMatcher] = None


def get_pattern_matcher() -> MitrePatternMatcher:
    """Get or create the global pattern matcher instance."""
    global _pattern_matcher
    if _pattern_matcher is None:
        _pattern_matcher = MitrePatternMatcher()
    return _pattern_matcher


def match_techniques(content: str, categories: Optional[List[str]] = None) -> Set[str]:
    """
    Convenience function to match content against MITRE patterns.

    Args:
        content: Text content to scan
        categories: Optional list of pattern categories

    Returns:
        Set of matching technique IDs
    """
    return get_pattern_matcher().match_content(content, categories)


def scan_json_record(record: Dict) -> Set[str]:
    """
    Convenience function to scan a JSON record for MITRE techniques.

    Args:
        record: Dictionary representing a JSON record

    Returns:
        Set of matching technique IDs
    """
    return get_pattern_matcher().scan_record(record)
