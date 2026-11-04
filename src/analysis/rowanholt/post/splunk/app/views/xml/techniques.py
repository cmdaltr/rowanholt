#!/usr/bin/env python3
"""
MITRE ATT&CK Technique Dashboard Generator for Splunk

This module generates individual XML dashboard views for each MITRE ATT&CK technique.
The dashboards provide detailed views of events mapped to specific techniques.
Updated for MITRE ATT&CK v18.1 with comprehensive technique coverage.
"""

# Complete technique definitions organized by tactic
# Format: {technique_id: (name, tactic, description)}
# Includes parent techniques and major sub-techniques

TECHNIQUES = {
    # ==================== RECONNAISSANCE ====================
    "T1595": ("Active Scanning", "Reconnaissance", "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting. Active scans are those where the adversary probes victim infrastructure via network traffic, as opposed to other forms of reconnaissance t..."),
    "T1595.001": ("Scanning IP Blocks", "Reconnaissance", "Adversaries may scan victim IP blocks to gather information that can be used during targeting. Public IP addresses may be allocated to organizations by block, or a range of sequential addresses. Adversaries may scan IP blocks in order to [Gather V..."),
    "T1595.002": ("Vulnerability Scanning", "Reconnaissance", "Adversaries may scan victims for vulnerabilities that can be used during targeting. Vulnerability scans typically check if the configuration of a target host/application (ex: software and version) potentially aligns with the target of a specific e..."),
    "T1595.003": ("Wordlist Scanning", "Reconnaissance", "Adversaries may iteratively probe infrastructure using brute-forcing and crawling techniques. While this technique employs similar methods to [Brute Force](https://attack.mitre.org/techniques/T1110), its goal is the identification of content and i..."),
    "T1592": ("Gather Victim Host Information", "Reconnaissance", "Adversaries may gather information about the victim's hosts that can be used during targeting. Information about hosts may include a variety of details, including administrative data (ex: name, assigned IP, functionality, etc.) as well as specific..."),
    "T1592.001": ("Hardware", "Reconnaissance", "Adversaries may gather information about the victim's host hardware that can be used during targeting. Information about hardware infrastructure may include a variety of details such as types and versions on specific hosts, as well as the presence..."),
    "T1592.002": ("Software", "Reconnaissance", "Adversaries may gather information about the victim's host software that can be used during targeting. Information about installed software may include a variety of details such as types and versions on specific hosts, as well as the presence of a..."),
    "T1592.003": ("Firmware", "Reconnaissance", "Adversaries may gather information about the victim's host firmware that can be used during targeting. Information about host firmware may include a variety of details such as type and versions on specific hosts, which may be used to infer more in..."),
    "T1592.004": ("Client Configurations", "Reconnaissance", "Adversaries may gather information about the victim's client configurations that can be used during targeting. Information about client configurations may include a variety of details and settings, including operating system/version, virtualizatio..."),
    "T1589": ("Gather Victim Identity Information", "Reconnaissance", "Adversaries may gather information about the victim's identity that can be used during targeting. Information about identities may include a variety of details, including personal data (ex: employee names, email addresses, security question respon..."),
    "T1589.001": ("Credentials", "Reconnaissance", "Adversaries may gather credentials that can be used during targeting. Account credentials gathered by adversaries may be those directly associated with the target victim organization or attempt to take advantage of the tendency for users to use th..."),
    "T1589.002": ("Email Addresses", "Reconnaissance", "Adversaries may gather email addresses that can be used during targeting. Even if internal instances exist, organizations may have public-facing email infrastructure and addresses for employees. Adversaries may easily gather email addresses, since..."),
    "T1589.003": ("Employee Names", "Reconnaissance", "Adversaries may gather employee names that can be used during targeting. Employee names be used to derive email addresses as well as to help guide other reconnaissance efforts and/or craft more-believable lures. Adversaries may easily gather emplo..."),
    "T1590": ("Gather Victim Network Information", "Reconnaissance", "Adversaries may gather information about the victim's networks that can be used during targeting. Information about networks may include a variety of details, including administrative data (ex: IP ranges, domain names, etc.) as well as specifics r..."),
    "T1590.001": ("Domain Properties", "Reconnaissance", "Adversaries may gather information about the victim's network domain(s) that can be used during targeting. Information about domains and their properties may include a variety of details, including what domain(s) the victim owns as well as adminis..."),
    "T1590.002": ("DNS", "Reconnaissance", "Adversaries may gather information about the victim's DNS that can be used during targeting. DNS information may include a variety of details, including registered name servers as well as records that outline addressing for a target’s subdomains, ..."),
    "T1590.003": ("Network Trust Dependencies", "Reconnaissance", "Adversaries may gather information about the victim's network trust dependencies that can be used during targeting. Information about network trusts may include a variety of details, including second or third-party organizations/domains (ex: manag..."),
    "T1590.004": ("Network Topology", "Reconnaissance", "Adversaries may gather information about the victim's network topology that can be used during targeting. Information about network topologies may include a variety of details, including the physical and/or logical arrangement of both external-fac..."),
    "T1590.005": ("IP Addresses", "Reconnaissance", "Adversaries may gather the victim's IP addresses that can be used during targeting. Public IP addresses may be allocated to organizations by block, or a range of sequential addresses. Information about assigned IP addresses may include a variety o..."),
    "T1590.006": ("Network Security Appliances", "Reconnaissance", "Adversaries may gather information about the victim's network security appliances that can be used during targeting. Information about network security appliances may include a variety of details, such as the existence and specifics of deployed fi..."),
    "T1591": ("Gather Victim Org Information", "Reconnaissance", "Adversaries may gather information about the victim's organization that can be used during targeting. Information about an organization may include a variety of details, including the names of divisions/departments, specifics of business operation..."),
    "T1591.001": ("Determine Physical Locations", "Reconnaissance", "Adversaries may gather the victim's physical location(s) that can be used during targeting. Information about physical locations of a target organization may include a variety of details, including where key resources and infrastructure are housed..."),
    "T1591.002": ("Business Relationships", "Reconnaissance", "Adversaries may gather information about the victim's business relationships that can be used during targeting. Information about an organization’s business relationships may include a variety of details, including second or third-party organizati..."),
    "T1591.003": ("Identify Business Tempo", "Reconnaissance", "Adversaries may gather information about the victim's business tempo that can be used during targeting. Information about an organization’s business tempo may include a variety of details, including operational hours/days of the week. This informa..."),
    "T1591.004": ("Identify Roles", "Reconnaissance", "Adversaries may gather information about identities and roles within the victim organization that can be used during targeting. Information about business roles may reveal a variety of targetable details, including identifiable information for key..."),
    "T1598": ("Phishing for Information", "Reconnaissance", "Adversaries may send phishing messages to elicit sensitive information that can be used during targeting. Phishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. P..."),
    "T1598.001": ("Spearphishing Service", "Reconnaissance", "Adversaries may send spearphishing messages via third-party services to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials..."),
    "T1598.002": ("Spearphishing Attachment", "Reconnaissance", "Adversaries may send spearphishing messages with a malicious attachment to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credenti..."),
    "T1598.003": ("Spearphishing Link", "Reconnaissance", "Adversaries may send spearphishing messages with a malicious link to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or..."),
    "T1597": ("Search Closed Sources", "Reconnaissance", "Adversaries may search and gather information about victims from closed (e.g., paid, private, or otherwise not freely available) sources that can be used during targeting. Information about victims may be available for purchase from reputable priv..."),
    "T1597.001": ("Threat Intel Vendors", "Reconnaissance", "Adversaries may search private data from threat intelligence vendors for information that can be used during targeting. Threat intelligence vendors may offer paid feeds or portals that offer more data than what is publicly reported. Although sensi..."),
    "T1597.002": ("Purchase Technical Data", "Reconnaissance", "Adversaries may purchase technical information about victims that can be used during targeting. Information about victims may be available for purchase within reputable private sources and databases, such as paid subscriptions to feeds of scan dat..."),
    "T1596": ("Search Open Technical Databases", "Reconnaissance", "Adversaries may search freely available technical databases for information about victims that can be used during targeting. Information about victims may be available in online databases and repositories, such as registrations of domains/certific..."),
    "T1596.001": ("DNS/Passive DNS", "Reconnaissance", "Adversaries may search DNS data for information about victims that can be used during targeting. DNS information may include a variety of details, including registered name servers as well as records that outline addressing for a target’s subdomai..."),
    "T1596.002": ("WHOIS", "Reconnaissance", "Adversaries may search public WHOIS data for information about victims that can be used during targeting. WHOIS data is stored by regional Internet registries (RIR) responsible for allocating and assigning Internet resources such as domain names. ..."),
    "T1596.003": ("Digital Certificates", "Reconnaissance", "Adversaries may search public digital certificate data for information about victims that can be used during targeting. Digital certificates are issued by a certificate authority (CA) in order to cryptographically verify the origin of signed conte..."),
    "T1596.004": ("CDNs", "Reconnaissance", "Adversaries may search content delivery network (CDN) data about victims that can be used during targeting. CDNs allow an organization to host content from a distributed, load balanced array of servers. CDNs may also allow organizations to customi..."),
    "T1596.005": ("Scan Databases", "Reconnaissance", "Adversaries may search within public scan databases for information about victims that can be used during targeting. Various online services continuously publish the results of Internet scans/surveys, often harvesting information such as active IP..."),
    "T1593": ("Search Open Websites/Domains", "Reconnaissance", "Adversaries may search freely available websites and/or domains for information about victims that can be used during targeting. Information about victims may be available in various online sites, such as social media, new sites, or those hosting ..."),
    "T1593.001": ("Social Media", "Reconnaissance", "Adversaries may search social media for information about victims that can be used during targeting. Social media sites may contain various information about a victim organization, such as business announcements as well as information about the ro..."),
    "T1593.002": ("Search Engines", "Reconnaissance", "Adversaries may use search engines to collect information about victims that can be used during targeting. Search engine services typical crawl online sites to index context and may provide users with specialized syntax to search for specific keyw..."),
    "T1593.003": ("Code Repositories", "Reconnaissance", "Adversaries may search public code repositories for information about victims that can be used during targeting. Victims may store code in repositories on various third-party websites such as GitHub, GitLab, SourceForge, and BitBucket. Users typic..."),
    "T1594": ("Search Victim-Owned Websites", "Reconnaissance", "Adversaries may search websites owned by the victim for information that can be used during targeting. Victim-owned websites may contain a variety of details, including names of departments/divisions, physical locations, and data about key employe..."),

    # ==================== RESOURCE DEVELOPMENT ====================
    "T1583": ("Acquire Infrastructure", "Resource Development", "Adversaries may buy, lease, rent, or obtain infrastructure that can be used during targeting. A wide variety of infrastructure exists for hosting and orchestrating adversary operations. Infrastructure solutions include physical or cloud servers, d..."),
    "T1583.001": ("Domains", "Resource Development", "Adversaries may acquire domains that can be used during targeting. Domain names are the human readable names used to represent one or more IP addresses. They can be purchased or, in some cases, acquired for free. Adversaries may use acquired domai..."),
    "T1583.002": ("DNS Server", "Resource Development", "Adversaries may set up their own Domain Name System (DNS) servers that can be used during targeting. During post-compromise activity, adversaries may utilize DNS traffic for various tasks, including for Command and Control (ex: [Application Layer ..."),
    "T1583.003": ("Virtual Private Server", "Resource Development", "Adversaries may rent Virtual Private Servers (VPSs) that can be used during targeting. There exist a variety of cloud service providers that will sell virtual machines/containers as a service. By utilizing a VPS, adversaries can make it difficult ..."),
    "T1583.004": ("Server", "Resource Development", "Adversaries may buy, lease, rent, or obtain physical servers that can be used during targeting. Use of servers allows an adversary to stage, launch, and execute an operation. During post-compromise activity, adversaries may utilize servers for var..."),
    "T1583.005": ("Botnet", "Resource Development", "Adversaries may buy, lease, or rent a network of compromised systems that can be used during targeting. A botnet is a network of compromised systems that can be instructed to perform coordinated tasks. Adversaries may purchase a subscription to us..."),
    "T1583.006": ("Web Services", "Resource Development", "Adversaries may register for web services that can be used during targeting. A variety of popular websites exist for adversaries to register for a web-based service that can be abused during later stages of the adversary lifecycle, such as during ..."),
    "T1583.007": ("Serverless", "Resource Development", "Adversaries may purchase and configure serverless cloud infrastructure, such as Cloudflare Workers, AWS Lambda functions, or Google Apps Scripts, that can be used during targeting. By utilizing serverless infrastructure, adversaries can make it mo..."),
    "T1583.008": ("Malvertising", "Resource Development", "Adversaries may purchase online advertisements that can be abused to distribute malware to victims. Ads can be purchased to plant as well as favorably position artifacts in specific locations online, such as prominently placed within search engine..."),
    "T1586": ("Compromise Accounts", "Resource Development", "Adversaries may compromise accounts with services that can be used during targeting. For operations incorporating social engineering, the utilization of an online persona may be important. Rather than creating and cultivating accounts (i.e. [Estab..."),
    "T1586.001": ("Social Media Accounts", "Resource Development", "Adversaries may compromise social media accounts that can be used during targeting. For operations incorporating social engineering, the utilization of an online persona may be important. Rather than creating and cultivating social media profiles ..."),
    "T1586.002": ("Email Accounts", "Resource Development", "Adversaries may compromise email accounts that can be used during targeting. Adversaries can use compromised email accounts to further their operations, such as leveraging them to conduct [Phishing for Information](https://attack.mitre.org/techniq..."),
    "T1586.003": ("Cloud Accounts", "Resource Development", "Adversaries may compromise cloud accounts that can be used during targeting. Adversaries can use compromised cloud accounts to further their operations, including leveraging cloud storage services such as Dropbox, Microsoft OneDrive, or AWS S3 buc..."),
    "T1584": ("Compromise Infrastructure", "Resource Development", "Adversaries may compromise third-party infrastructure that can be used during targeting. Infrastructure solutions include physical or cloud servers, domains, network devices, and third-party web and DNS services. Instead of buying, leasing, or ren..."),
    "T1584.001": ("Domains", "Resource Development", "Adversaries may hijack domains and/or subdomains that can be used during targeting. Domain registration hijacking is the act of changing the registration of a domain name without the permission of the original registrant. Adversaries may gain acce..."),
    "T1584.002": ("DNS Server", "Resource Development", "Adversaries may compromise third-party DNS servers that can be used during targeting. During post-compromise activity, adversaries may utilize DNS traffic for various tasks, including for Command and Control (ex: [Application Layer Protocol](https..."),
    "T1584.003": ("Virtual Private Server", "Resource Development", "Adversaries may compromise third-party Virtual Private Servers (VPSs) that can be used during targeting. There exist a variety of cloud service providers that will sell virtual machines/containers as a service. Adversaries may compromise VPSs purc..."),
    "T1584.004": ("Server", "Resource Development", "Adversaries may compromise third-party servers that can be used during targeting. Use of servers allows an adversary to stage, launch, and execute an operation. During post-compromise activity, adversaries may utilize servers for various tasks, in..."),
    "T1584.005": ("Botnet", "Resource Development", "Adversaries may compromise numerous third-party systems to form a botnet that can be used during targeting. A botnet is a network of compromised systems that can be instructed to perform coordinated tasks. Instead of purchasing/renting a botnet fr..."),
    "T1584.006": ("Web Services", "Resource Development", "Adversaries may compromise access to third-party web services that can be used during targeting. A variety of popular websites exist for legitimate users to register for web-based services, such as GitHub, Twitter, Dropbox, Google, SendGrid, etc. ..."),
    "T1584.007": ("Serverless", "Resource Development", "Adversaries may compromise serverless cloud infrastructure, such as Cloudflare Workers, AWS Lambda functions, or Google Apps Scripts, that can be used during targeting. By utilizing serverless infrastructure, adversaries can make it more difficult..."),
    "T1587": ("Develop Capabilities", "Resource Development", "Adversaries may build capabilities that can be used during targeting. Rather than purchasing, freely downloading, or stealing capabilities, adversaries may develop their own capabilities in-house. This is the process of identifying development req..."),
    "T1587.001": ("Malware", "Resource Development", "Adversaries may develop malware and malware components that can be used during targeting. Building malicious software can include the development of payloads, droppers, post-compromise tools, backdoors (including backdoored images), packers, C2 pr..."),
    "T1587.002": ("Code Signing Certificates", "Resource Development", "Adversaries may create self-signed code signing certificates that can be used during targeting. Code signing is the process of digitally signing executables and scripts to confirm the software author and guarantee that the code has not been altere..."),
    "T1587.003": ("Digital Certificates", "Resource Development", "Adversaries may create self-signed SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are designed to instill trust. They include information about the key, information about its owner's identity, and the digital signatur..."),
    "T1587.004": ("Exploits", "Resource Development", "Adversaries may develop exploits that can be used during targeting. An exploit takes advantage of a bug or vulnerability in order to cause unintended or unanticipated behavior to occur on computer hardware or software. Rather than finding/modifyin..."),
    "T1585": ("Establish Accounts", "Resource Development", "Adversaries may create and cultivate accounts with services that can be used during targeting. Adversaries can create accounts that can be used to build a persona to further operations. Persona development consists of the development of public inf..."),
    "T1585.001": ("Social Media Accounts", "Resource Development", "Adversaries may create and cultivate social media accounts that can be used during targeting. Adversaries can create social media accounts that can be used to build a persona to further operations. Persona development consists of the development o..."),
    "T1585.002": ("Email Accounts", "Resource Development", "Adversaries may create email accounts that can be used during targeting. Adversaries can use accounts created with email providers to further their operations, such as leveraging them to conduct [Phishing for Information](https://attack.mitre.org/..."),
    "T1585.003": ("Cloud Accounts", "Resource Development", "Adversaries may create accounts with cloud providers that can be used during targeting. Adversaries can use cloud accounts to further their operations, including leveraging cloud storage services such as Dropbox, MEGA, Microsoft OneDrive, or AWS S..."),
    "T1588": ("Obtain Capabilities", "Resource Development", "Adversaries may buy and/or steal capabilities that can be used during targeting. Rather than developing their own capabilities in-house, adversaries may purchase, freely download, or steal them. Activities may include the acquisition of malware, s..."),
    "T1588.001": ("Malware", "Resource Development", "Adversaries may buy, steal, or download malware that can be used during targeting. Malicious software can include payloads, droppers, post-compromise tools, backdoors, packers, and C2 protocols. Adversaries may acquire malware to support their ope..."),
    "T1588.002": ("Tool", "Resource Development", "Adversaries may buy, steal, or download software tools that can be used during targeting. Tools can be open or closed source, free or commercial. A tool can be used for malicious purposes by an adversary, but (unlike malware) were not intended to ..."),
    "T1588.003": ("Code Signing Certificates", "Resource Development", "Adversaries may buy and/or steal code signing certificates that can be used during targeting. Code signing is the process of digitally signing executables and scripts to confirm the software author and guarantee that the code has not been altered ..."),
    "T1588.004": ("Digital Certificates", "Resource Development", "Adversaries may buy and/or steal SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are designed to instill trust. They include information about the key, information about its owner's identity, and the digital signature ..."),
    "T1588.005": ("Exploits", "Resource Development", "Adversaries may buy, steal, or download exploits that can be used during targeting. An exploit takes advantage of a bug or vulnerability in order to cause unintended or unanticipated behavior to occur on computer hardware or software. Rather than ..."),
    "T1588.006": ("Vulnerabilities", "Resource Development", "Adversaries may acquire information about vulnerabilities that can be used during targeting. A vulnerability is a weakness in computer hardware or software that can, potentially, be exploited by an adversary to cause unintended or unanticipated be..."),
    "T1608": ("Stage Capabilities", "Resource Development", "Adversaries may upload, install, or otherwise set up capabilities that can be used during targeting. To support their operations, an adversary may need to take capabilities they developed ([Develop Capabilities](https://attack.mitre.org/techniques..."),
    "T1608.001": ("Upload Malware", "Resource Development", "Adversaries may upload malware to third-party or adversary controlled infrastructure to make it accessible during targeting. Malicious software can include payloads, droppers, post-compromise tools, backdoors, and a variety of other malicious cont..."),
    "T1608.002": ("Upload Tool", "Resource Development", "Adversaries may upload tools to third-party or adversary controlled infrastructure to make it accessible during targeting. Tools can be open or closed source, free or commercial. Tools can be used for malicious purposes by an adversary, but (unlik..."),
    "T1608.003": ("Install Digital Certificate", "Resource Development", "Adversaries may install SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are files that can be installed on servers to enable secure communications between systems. Digital certificates include information about the key..."),
    "T1608.004": ("Drive-by Target", "Resource Development", "Adversaries may prepare an operational environment to infect systems that visit a website over the normal course of browsing. Endpoint systems may be compromised through browsing to adversary controlled sites, as in [Drive-by Compromise](https://a..."),
    "T1608.005": ("Link Target", "Resource Development", "Adversaries may put in place resources that are referenced by a link that can be used during targeting. An adversary may rely upon a user clicking a malicious link in order to divulge information (including credentials) or to gain execution, as in..."),
    "T1608.006": ("SEO Poisoning", "Resource Development", "Adversaries may poison mechanisms that influence search engine optimization (SEO) to further lure staged capabilities towards potential victims. Search engines typically display results to users based on purchased ads as well as the site’s ranking..."),

    # ==================== INITIAL ACCESS ====================
    "T1659": ("Content Injection", "Initial Access", "Adversaries may gain access and continuously communicate with victims by injecting malicious content into systems through online network traffic. Rather than luring victims to malicious payloads hosted on a compromised website (i.e., [Drive-by Tar..."),
    "T1189": ("Drive-by Compromise", "Initial Access", "Adversaries may gain access to a system through a user visiting a website over the normal course of browsing. Multiple ways of delivering exploit code to a browser exist (i.e., [Drive-by Target](https://attack.mitre.org/techniques/T1608/004)), inc..."),
    "T1190": ("Exploit Public-Facing Application", "Initial Access", "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration. Exploited applications are often website..."),
    "T1133": ("External Remote Services", "Initial Access", "Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from ex..."),
    "T1200": ("Hardware Additions", "Initial Access", "Adversaries may physically introduce computer accessories, networking hardware, or other computing devices into a system or network that can be used as a vector to gain access. Rather than just connecting and distributing payloads via removable st..."),
    "T1566": ("Phishing", "Initial Access", "Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing. In spearphishing, a specific individual, company, or ..."),
    "T1566.001": ("Spearphishing Attachment", "Initial Access", "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems. Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearp..."),
    "T1566.002": ("Spearphishing Link", "Initial Access", "Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems. Spearphishing with a link is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs ..."),
    "T1566.003": ("Spearphishing via Service", "Initial Access", "Adversaries may send spearphishing messages via third-party services in an attempt to gain access to victim systems. Spearphishing via service is a specific variant of spearphishing. It is different from other forms of spearphishing in that it emp..."),
    "T1566.004": ("Spearphishing Voice", "Initial Access", "Adversaries may use voice communications to ultimately gain access to victim systems. Spearphishing voice is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of manipulating a user i..."),
    "T1091": ("Replication Through Removable Media", "Initial Access", "Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes. In the case of Lateral ..."),
    "T1195": ("Supply Chain Compromise", "Initial Access", "Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise. Supply chain compromise can take place at any stage of the supply chain including: * Manipulation..."),
    "T1195.001": ("Compromise Software Dependencies", "Initial Access", "Adversaries may manipulate software dependencies and development tools prior to receipt by a final consumer for the purpose of data or system compromise. Applications often depend on external software to function properly. Popular open source proj..."),
    "T1195.002": ("Compromise Software Supply Chain", "Initial Access", "Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise. Supply chain compromise of software can take place in a number of ways, including manipulation of the application so..."),
    "T1195.003": ("Compromise Hardware Supply Chain", "Initial Access", "Adversaries may manipulate hardware components in products prior to receipt by a final consumer for the purpose of data or system compromise. By modifying hardware or firmware in the supply chain, adversaries can insert a backdoor into consumer ne..."),
    "T1199": ("Trusted Relationship", "Initial Access", "Adversaries may breach or otherwise leverage organizations who have access to intended victims. Access through trusted third party relationship abuses an existing connection that may not be protected or receives less scrutiny than standard mechani..."),
    "T1078": ("Valid Accounts", "Initial Access", "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resource..."),
    "T1078.001": ("Default Accounts", "Initial Access", "Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Default accounts are those that are built-into an OS, such as the Guest or Administrator..."),
    "T1078.002": ("Domain Accounts", "Initial Access", "Adversaries may obtain and abuse credentials of a domain account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Domain accounts are those managed by Active Directory Domain Services where access and pe..."),
    "T1078.003": ("Local Accounts", "Initial Access", "Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Local accounts are those configured by an organization for use by users, remote support, s..."),
    "T1078.004": ("Cloud Accounts", "Initial Access", "Valid accounts in cloud environments may allow adversaries to perform actions to achieve Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Cloud accounts are those created and configured by an organization for use by users, re..."),

    # ==================== EXECUTION ====================
    "T1651": ("Cloud Administration Command", "Execution", "Adversaries may abuse cloud management services to execute commands within virtual machines. Resources such as AWS Systems Manager, Azure RunCommand, and Runbooks allow users to remotely run scripts in virtual machines by leveraging installed virt..."),
    "T1059": ("Command and Scripting Interpreter", "Execution", "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. Most system..."),
    "T1059.001": ("PowerShell", "Execution", "Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. Adversaries can use PowerShell to perform a number..."),
    "T1059.002": ("AppleScript", "Execution", "Adversaries may abuse AppleScript for execution. AppleScript is a macOS scripting language designed to control applications and parts of the OS via inter-application messages called AppleEvents. These AppleEvent messages can be sent independently ..."),
    "T1059.003": ("Windows Command Shell", "Execution", "Adversaries may abuse the Windows command shell for execution. The Windows command shell ([cmd](https://attack.mitre.org/software/S0106)) is the primary command prompt on Windows systems. The Windows command prompt can be used to control almost an..."),
    "T1059.004": ("Unix Shell", "Execution", "Adversaries may abuse Unix shell commands and scripts for execution. Unix shells are the primary command prompt on Linux, macOS, and ESXi systems, though many variations of the Unix shell exist (e.g. sh, ash, bash, zsh, etc.) depending on the spec..."),
    "T1059.005": ("Visual Basic", "Execution", "Adversaries may abuse Visual Basic (VB) for execution. VB is a programming language created by Microsoft with interoperability with many Windows technologies such as [Component Object Model](https://attack.mitre.org/techniques/T1559/001) and the [..."),
    "T1059.006": ("Python", "Execution", "Adversaries may abuse Python commands and scripts for execution. Python is a very popular scripting/programming language, with capabilities to perform many functions. Python can be executed interactively from the command-line (via the python.exe i..."),
    "T1059.007": ("JavaScript", "Execution", "Adversaries may abuse various implementations of JavaScript for execution. JavaScript (JS) is a platform-independent scripting language (compiled just-in-time at runtime) commonly associated with scripts in webpages, though JS can be executed in r..."),
    "T1059.008": ("Network Device CLI", "Execution", "Adversaries may abuse scripting or built-in command line interpreters (CLI) on network devices to execute malicious command and payloads. The CLI is the primary means through which users and administrators interact with the device in order to view..."),
    "T1059.009": ("Cloud API", "Execution", "Adversaries may abuse cloud APIs to execute malicious commands. APIs available in cloud environments provide various functionalities and are a feature-rich method for programmatic access to nearly all aspects of a tenant. These APIs may be utilize..."),
    "T1609": ("Container Administration Command", "Execution", "Adversaries may abuse a container administration service to execute commands within a container. A container administration service such as the Docker daemon, the Kubernetes API server, or the kubelet may allow remote management of containers with..."),
    "T1610": ("Deploy Container", "Execution", "Adversaries may deploy a container into an environment to facilitate execution or evade defenses. In some cases, adversaries may deploy a new container to execute processes associated with a particular image or deployment, such as processes that e..."),
    "T1203": ("Exploitation for Client Execution", "Execution", "Adversaries may exploit software vulnerabilities in client applications to execute code. Vulnerabilities can exist in software due to unsecure coding practices that can lead to unanticipated behavior. Adversaries can take advantage of certain vuln..."),
    "T1559": ("Inter-Process Communication", "Execution", "Adversaries may abuse inter-process communication (IPC) mechanisms for local code or command execution. IPC is typically used by processes to share data, communicate with each other, or synchronize execution. IPC is also commonly used to avoid sit..."),
    "T1559.001": ("Component Object Model", "Execution", "Adversaries may use the Windows Component Object Model (COM) for local code execution. COM is an inter-process communication (IPC) component of the native Windows application programming interface (API) that enables interaction between software ob..."),
    "T1559.002": ("Dynamic Data Exchange", "Execution", "Adversaries may use Windows Dynamic Data Exchange (DDE) to execute arbitrary commands. DDE is a client-server protocol for one-time and/or continuous inter-process communication (IPC) between applications. Once a link is established, applications ..."),
    "T1559.003": ("XPC Services", "Execution", "Adversaries can provide malicious content to an XPC service daemon for local code execution. macOS uses XPC services for basic inter-process communication between various processes, such as between the XPC Service daemon and third-party applicatio..."),
    "T1106": ("Native API", "Execution", "Adversaries may interact with the native OS application programming interface (API) to execute behaviors. Native APIs provide a controlled means of calling low-level OS services within the kernel, such as those involving hardware/devices, memory, ..."),
    "T1053": ("Scheduled Task/Job", "Execution", "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A t..."),
    "T1053.001": ("At", "Execution", "Adversaries may abuse the at utility."),
    "T1053.002": ("At (Windows)", "Execution", "Adversaries may abuse the [at](https://attack.mitre.org/software/S0110) utility to perform task scheduling for initial or recurring execution of malicious code. The [at](https://attack.mitre.org/software/S0110) utility exists as an executable with..."),
    "T1053.003": ("Cron", "Execution", "Adversaries may abuse the cron utility to perform task scheduling for initial or recurring execution of malicious code. The cron utility is a time-based job scheduler for Unix-like operating systems. The crontab file contains the schedule of cron ..."),
    "T1053.005": ("Scheduled Task", "Execution", "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The [schtasks](https://attack.mitre.org/software/S01..."),
    "T1053.006": ("Systemd Timers", "Execution", "Adversaries may abuse systemd timers to perform task scheduling for initial or recurring execution of malicious code. Systemd timers are unit files with file extension .timer that control services. Timers can be set to run on a calendar event or a..."),
    "T1053.007": ("Container Orchestration Job", "Execution", "Adversaries may abuse task scheduling functionality provided by container orchestration tools such as Kubernetes to schedule deployment of containers configured to execute malicious code. Container orchestration jobs run these automated tasks at a..."),
    "T1129": ("Shared Modules", "Execution", "Adversaries may execute malicious payloads via loading shared modules. Shared modules are executable files that are loaded into processes to provide access to reusable code, such as specific custom functions or invoking OS API functions (i.e., [Na..."),
    "T1072": ("Software Deployment Tools", "Execution", "Adversaries may gain access to and use centralized software suites installed within an enterprise to execute commands and move laterally through the network. Configuration management and software deployment applications may be used in an enterpris..."),
    "T1569": ("System Services", "Execution", "Adversaries may abuse system services or daemons to execute commands or programs. Adversaries can execute malicious content by interacting with or creating services either locally or remotely. Many services are set to run at boot, which can aid in..."),
    "T1569.001": ("Launchctl", "Execution", "Adversaries may abuse launchctl to execute commands or programs. Launchctl interfaces with launchd, the service management framework for macOS. Launchctl supports taking subcommands on the command-line, interactively, or even redirected from stand..."),
    "T1569.002": ("Service Execution", "Execution", "Adversaries may abuse the Windows service control manager to execute malicious commands or payloads. The Windows service control manager (services.exe) is an interface to manage and manipulate services. The service control manager is accessible to..."),
    "T1204": ("User Execution", "Execution", "An adversary may rely upon specific actions by a user in order to gain execution. Users may be subjected to social engineering to get them to execute malicious code by, for example, opening a malicious document file or link. These user actions wil..."),
    "T1204.001": ("Malicious Link", "Execution", "An adversary may rely upon a user clicking a malicious link in order to gain execution. Users may be subjected to social engineering to get them to click on a link that will lead to code execution. This user action will typically be observed as fo..."),
    "T1204.002": ("Malicious File", "Execution", "An adversary may rely upon a user opening a malicious file in order to gain execution. Users may be subjected to social engineering to get them to open a file that will lead to code execution. This user action will typically be observed as follow-..."),
    "T1204.003": ("Malicious Image", "Execution", "Adversaries may rely on a user running a malicious image to facilitate execution. Amazon Web Services (AWS) Amazon Machine Images (AMIs), Google Cloud Platform (GCP) Images, and Azure Images as well as popular container runtimes such as Docker can..."),
    "T1047": ("Windows Management Instrumentation", "Execution", "Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads. WMI is designed for programmers and is the infrastructure for management data and operations on Windows systems. WMI is an administration fe..."),

    # ==================== PERSISTENCE ====================
    "T1098": ("Account Manipulation", "Persistence", "Adversaries may manipulate accounts to maintain and/or elevate access to victim systems. Account manipulation may consist of any action that preserves or modifies adversary access to a compromised account, such as modifying credentials or permissi..."),
    "T1098.001": ("Additional Cloud Credentials", "Persistence", "Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access to victim accounts and instances within the environment. For example, adversaries may add credentials for Service Principals and Applications in ..."),
    "T1098.002": ("Additional Email Delegate Permissions", "Persistence", "Adversaries may grant additional permission levels to maintain persistent access to an adversary-controlled email account. For example, the Add-MailboxPermission [PowerShell](https://attack.mitre.org/techniques/T1059/001) cmdlet, available in on-p..."),
    "T1098.003": ("Additional Cloud Roles", "Persistence", "An adversary may add additional roles or permissions to an adversary-controlled cloud account to maintain persistent access to a tenant. For example, adversaries may update IAM policies in cloud-based environments or add a new global administrator..."),
    "T1098.004": ("SSH Authorized Keys", "Persistence", "Adversaries may modify the SSH authorized_keys file to maintain persistence on a victim host. Linux distributions, macOS, and ESXi hypervisors commonly use key-based authentication to secure the authentication process of SSH sessions for remote ma..."),
    "T1098.005": ("Device Registration", "Persistence", "Adversaries may register a device to an adversary-controlled account. Devices may be registered in a multifactor authentication (MFA) system, which handles authentication to the network, or in a device management system, which handles device acces..."),
    "T1098.006": ("Additional Container Cluster Roles", "Persistence", "An adversary may add additional roles or permissions to an adversary-controlled user or service account to maintain persistent access to a container orchestration system. For example, an adversary with sufficient permissions may create a RoleBindi..."),
    "T1197": ("BITS Jobs", "Persistence", "Adversaries may abuse BITS jobs to persistently execute code and perform various background tasks. Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through [Component Object Mo..."),
    "T1547": ("Boot or Logon Autostart Execution", "Persistence", "Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems. Operating systems may have mechanisms for automatically runnin..."),
    "T1547.001": ("Registry Run Keys / Startup Folder", "Persistence", "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the \"run keys\" in the Registry or startup folder will cause the program referenced to be executed when a user logs in. These programs will be executed under th..."),
    "T1547.002": ("Authentication Package", "Persistence", "Adversaries may abuse authentication packages to execute DLLs when the system boots. Windows authentication package DLLs are loaded by the Local Security Authority (LSA) process at system start. They provide support for multiple logon processes an..."),
    "T1547.003": ("Time Providers", "Persistence", "Adversaries may abuse time providers to execute DLLs when the system boots. The Windows Time service (W32Time) enables time synchronization across and within domains. W32Time time providers are responsible for retrieving time stamps from hardware/..."),
    "T1547.004": ("Winlogon Helper DLL", "Persistence", "Adversaries may abuse features of Winlogon to execute DLLs and/or executables when a user logs in. Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Del..."),
    "T1547.005": ("Security Support Provider", "Persistence", "Adversaries may abuse security support providers (SSPs) to execute DLLs when the system boots. Windows SSP DLLs are loaded into the Local Security Authority (LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted..."),
    "T1547.006": ("Kernel Modules and Extensions", "Persistence", "Adversaries may modify the kernel to automatically execute programs on system boot. Loadable Kernel Modules (LKMs) are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without ..."),
    "T1547.007": ("Re-opened Applications", "Persistence", "Adversaries may modify plist files to automatically run an application when a user logs in. When a user logs out or restarts via the macOS Graphical User Interface (GUI), a prompt is provided to the user with a checkbox to \"Reopen windows when logging back in\". When selected, all applications cur..."),
    "T1547.008": ("LSASS Driver", "Persistence", "Adversaries may modify or add LSASS drivers to obtain persistence on compromised systems. The Windows security subsystem is a set of components that manage and enforce the security policy for a computer or domain. The Local Security Authority (LSA..."),
    "T1547.009": ("Shortcut Modification", "Persistence", "Adversaries may create or modify shortcuts that can execute a program during system boot or user login. Shortcuts or symbolic links are used to reference other files or programs that will be opened or executed when the shortcut is clicked or execu..."),
    "T1547.010": ("Port Monitors", "Persistence", "Adversaries may use port monitors to run an adversary supplied DLL during system boot for persistence or privilege escalation. A port monitor can be set through the AddMonitor API call to set a DLL to be loaded at startup. This DLL can be located ..."),
    "T1547.012": ("Print Processors", "Persistence", "Adversaries may abuse print processors to run malicious DLLs during system boot for persistence and/or privilege escalation. Print processors are DLLs that are loaded by the print spooler service, `spoolsv.exe`, during boot. Adversaries may abuse ..."),
    "T1547.013": ("XDG Autostart Entries", "Persistence", "Adversaries may add or modify XDG Autostart Entries to execute malicious programs or commands when a user’s desktop environment is loaded at login. XDG Autostart entries are available for any XDG-compliant Linux system. XDG Autostart entries use D..."),
    "T1547.014": ("Active Setup", "Persistence", "Adversaries may achieve persistence by adding a Registry key to the Active Setup of the local machine. Active Setup is a Windows mechanism that is used to execute programs when a user logs in. The value stored in the Registry key will be executed ..."),
    "T1547.015": ("Login Items", "Persistence", "Adversaries may add login items to execute upon user login to gain persistence or escalate privileges. Login items are applications, documents, folders, or server connections that are automatically launched when a user logs in. Login items can be ..."),
    "T1037": ("Boot or Logon Initialization Scripts", "Persistence", "Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence. Initialization scripts can be used to perform administrative functions, which may often execute other programs or send information to an i..."),
    "T1037.001": ("Logon Script (Windows)", "Persistence", "Adversaries may use Windows logon scripts automatically executed at logon initialization to establish persistence. Windows allows logon scripts to be run whenever a specific user or group of users log into a system. This is done via adding a path ..."),
    "T1037.002": ("Login Hook", "Persistence", "Adversaries may use a Login Hook to establish persistence executed upon user logon. A login hook is a plist file that points to a specific script to execute with root privileges upon user logon. The plist file is located in the /Library/Preference..."),
    "T1037.003": ("Network Logon Script", "Persistence", "Adversaries may use network logon scripts automatically executed at logon initialization to establish persistence. Network logon scripts can be assigned using Active Directory or Group Policy Objects. These logon scripts run with the privileges of..."),
    "T1037.004": ("RC Scripts", "Persistence", "Adversaries may establish persistence by modifying RC scripts, which are executed during a Unix-like system’s startup. These files allow system administrators to map and start custom services at startup for different run levels. RC scripts require..."),
    "T1037.005": ("Startup Items", "Persistence", "Adversaries may use startup items automatically executed at boot initialization to establish persistence. Startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration..."),
    "T1176": ("Browser Extensions", "Persistence", "Adversaries may abuse software extensions to establish persistent access to victim systems. Software extensions are modular components that enhance or customize the functionality of software applications, including web browsers, Integrated Develop..."),
    "T1554": ("Compromise Client Software Binary", "Persistence", "Adversaries may modify host software binaries to establish persistent access to systems. Software binaries/executables provide a wide range of system commands or services, programs, and libraries. Common software binaries are SSH clients, FTP clie..."),
    "T1136": ("Create Account", "Persistence", "Adversaries may create an account to maintain access to victim systems. With a sufficient level of access, creating such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deplo..."),
    "T1136.001": ("Local Account", "Persistence", "Adversaries may create a local account to maintain access to victim systems. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service. For example, with ..."),
    "T1136.002": ("Domain Account", "Persistence", "Adversaries may create a domain account to maintain access to victim systems. Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domai..."),
    "T1136.003": ("Cloud Account", "Persistence", "Adversaries may create a cloud account to maintain access to victim systems. With a sufficient level of access, such accounts may be used to establish secondary credentialed access that does not require persistent remote access tools to be deploye..."),
    "T1543": ("Create or Modify System Process", "Persistence", "Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence. When operating systems boot up, they can start processes that perform background system functions. On Windows and Linux, these..."),
    "T1543.001": ("Launch Agent", "Persistence", "Adversaries may create or modify launch agents to repeatedly execute malicious payloads as part of persistence. When a user logs in, a per-user launchd process is started which loads the parameters for each launch-on-demand user agent from the pro..."),
    "T1543.002": ("Systemd Service", "Persistence", "Adversaries may create or modify systemd services to repeatedly execute malicious payloads as part of persistence. Systemd is a system and service manager commonly used for managing background daemon processes (also known as services) and other sy..."),
    "T1543.003": ("Windows Service", "Persistence", "Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions. Windows service ..."),
    "T1543.004": ("Launch Daemon", "Persistence", "Adversaries may create or modify Launch Daemons to execute malicious payloads as part of persistence. Launch Daemons are plist files used to interact with Launchd, the service management framework used by macOS. Launch Daemons require elevated pri..."),
    "T1546": ("Event Triggered Execution", "Persistence", "Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events. Various operating systems have means to monitor and subscribe to events such as logons or other user activity ..."),
    "T1546.001": ("Change Default File Association", "Persistence", "Adversaries may establish persistence by executing malicious content triggered by a file type association. When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association ..."),
    "T1546.002": ("Screensaver", "Persistence", "Adversaries may establish persistence by executing malicious content triggered by user inactivity. Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file e..."),
    "T1546.003": ("Windows Management Instrumentation Event Subscription", "Persistence", "Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription. WMI can be used to install event filters, providers, consumers, and bindings th..."),
    "T1546.004": ("Unix Shell Configuration Modification", "Persistence", "Adversaries may establish persistence through executing malicious commands triggered by a user’s shell. User [Unix Shell](https://attack.mitre.org/techniques/T1059/004)s execute several configuration scripts at different points throughout the sess..."),
    "T1546.005": ("Trap", "Persistence", "Adversaries may establish persistence by executing malicious content triggered by an interrupt signal. The trap command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a ..."),
    "T1546.006": ("LC_LOAD_DYLIB Addition", "Persistence", "Adversaries may establish persistence by executing malicious content triggered by the execution of tainted binaries. Mach-O binaries have a series of headers that are used to perform certain operations when a binary is loaded. The LC_LOAD_DYLIB he..."),
    "T1546.007": ("Netsh Helper DLL", "Persistence", "Adversaries may establish persistence by executing malicious content triggered by Netsh Helper DLLs. Netsh.exe (also referred to as Netshell) is a command-line scripting utility used to interact with the network configuration of a system. It conta..."),
    "T1546.008": ("Accessibility Features", "Persistence", "Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by accessibility features. Windows contains accessibility features that may be launched with a key combination before a user has logged in (ex..."),
    "T1546.009": ("AppCert DLLs", "Persistence", "Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppCert DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs Registry key under HKEY_LOCAL_MACHI..."),
    "T1546.010": ("AppInit DLLs", "Persistence", "Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppInit DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the AppInit_DLLs value in the Registry keys HKEY_LO..."),
    "T1546.011": ("Application Shimming", "Persistence", "Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims. The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow for bac..."),
    "T1546.012": ("Image File Execution Options Injection", "Persistence", "Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by Image File Execution Options (IFEO) debuggers. IFEOs enable a developer to attach a debugger to an application. When a process is created, ..."),
    "T1546.013": ("PowerShell Profile", "Persistence", "Adversaries may gain persistence and elevate privileges by executing malicious content triggered by PowerShell profiles. A PowerShell profile (profile.ps1) is a script that runs when [PowerShell](https://attack.mitre.org/techniques/T1059/001) star..."),
    "T1546.014": ("Emond", "Persistence", "Adversaries may gain persistence and elevate privileges by executing malicious content triggered by the Event Monitor Daemon (emond). Emond is a [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) that accepts events from various servic..."),
    "T1546.015": ("Component Object Model Hijacking", "Persistence", "Adversaries may establish persistence by executing malicious content triggered by hijacked references to Component Object Model (COM) objects. COM is a system within Windows to enable interaction between software components through the operating s..."),
    "T1546.016": ("Installer Packages", "Persistence", "Adversaries may establish persistence and elevate privileges by using an installer to trigger the execution of malicious content. Installer packages are OS specific and contain the resources an operating system needs to install applications on a s..."),
    "T1574": ("Hijack Execution Flow", "Persistence", "Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also us..."),
    "T1574.001": ("DLL Search Order Hijacking", "Persistence", "Adversaries may abuse dynamic-link library files (DLLs) in order to achieve persistence, escalate privileges, and evade defenses. DLLs are libraries that contain code and data that can be simultaneously utilized by multiple programs. While DLLs ar..."),
    "T1574.002": ("DLL Side-Loading", "Persistence", "Adversaries may side-load DLLs."),
    "T1574.004": ("Dylib Hijacking", "Persistence", "Adversaries may execute their own payloads by placing a malicious dynamic library (dylib) with an expected name in a path a victim application searches at runtime. The dynamic loader will try to find the dylibs based on the sequential order of the..."),
    "T1574.005": ("Executable Installer File Permissions Weakness", "Persistence", "Adversaries may execute their own malicious payloads by hijacking the binaries used by an installer. These processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the ..."),
    "T1574.006": ("Dynamic Linker Hijacking", "Persistence", "Adversaries may execute their own malicious payloads by hijacking environment variables the dynamic linker uses to load shared libraries. During the execution preparation phase of a program, the dynamic linker loads specified absolute paths of sha..."),
    "T1574.007": ("Path Interception by PATH Environment Variable", "Persistence", "Adversaries may execute their own malicious payloads by hijacking environment variables used to load libraries. The PATH environment variable contains a list of directories (User and System) that the OS searches sequentially through in search of t..."),
    "T1574.008": ("Path Interception by Search Order Hijacking", "Persistence", "Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs. Because some programs do not call other programs using the full path, adversaries may place their own file in the directory where the c..."),
    "T1574.009": ("Path Interception by Unquoted Path", "Persistence", "Adversaries may execute their own malicious payloads by hijacking vulnerable file path references. Adversaries can take advantage of paths that lack surrounding quotations by placing an executable in a higher level directory within the path, so th..."),
    "T1574.010": ("Services File Permissions Weakness", "Persistence", "Adversaries may execute their own malicious payloads by hijacking the binaries used by services. Adversaries may use flaws in the permissions of Windows services to replace the binary that is executed upon service start. These service processes ma..."),
    "T1574.011": ("Services Registry Permissions Weakness", "Persistence", "Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services. Flaws in the permissions for Registry keys related to services can allow adversaries to redirect the originally specified executable to one th..."),
    "T1574.012": ("COR_PROFILER", "Persistence", "Adversaries may leverage the COR_PROFILER environment variable to hijack the execution flow of programs that load the .NET CLR. The COR_PROFILER is a .NET Framework feature which allows developers to specify an unmanaged (or external of .NET) prof..."),
    "T1574.013": ("KernelCallbackTable", "Persistence", "Adversaries may abuse the KernelCallbackTable of a process to hijack its execution flow in order to run their own payloads. The KernelCallbackTable can be found in the Process Environment Block (PEB) and is initialized to an array of graphic funct..."),
    "T1574.014": ("AppDomainManager", "Persistence", "Adversaries may execute their own malicious payloads by hijacking how the .NET `AppDomainManager` loads assemblies. The .NET framework uses the `AppDomainManager` class to create and manage one or more isolated runtime environments (called applica..."),
    "T1525": ("Implant Internal Image", "Persistence", "Adversaries may implant cloud or container images with malicious code to establish persistence after gaining access to an environment. Amazon Web Services (AWS) Amazon Machine Images (AMIs), Google Cloud Platform (GCP) Images, and Azure Images as ..."),
    "T1556": ("Modify Authentication Process", "Persistence", "Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LS..."),
    "T1556.001": ("Domain Controller Authentication", "Persistence", "Adversaries may patch the authentication process on a domain controller to bypass the typical authentication mechanisms and enable access to accounts. Malware may be used to inject false credentials into the authentication process on a domain cont..."),
    "T1556.002": ("Password Filter DLL", "Persistence", "Adversaries may register malicious password filter dynamic link libraries (DLLs) into the authentication process to acquire user credentials as they are validated. Windows password filters are password policy enforcement mechanisms for both domain..."),
    "T1556.003": ("Pluggable Authentication Modules", "Persistence", "Adversaries may modify pluggable authentication modules (PAM) to access user credentials or enable otherwise unwarranted access to accounts. PAM is a modular system of configuration files, libraries, and executable files which guide authentication..."),
    "T1556.004": ("Network Device Authentication", "Persistence", "Adversaries may use [Patch System Image](https://attack.mitre.org/techniques/T1601/001) to hard code a password in the operating system, thus bypassing of native authentication mechanisms for local accounts on network devices. [Modify System Image..."),
    "T1556.005": ("Reversible Encryption", "Persistence", "An adversary may abuse Active Directory authentication encryption properties to gain access to credentials on Windows systems. The AllowReversiblePasswordEncryption property specifies whether reversible password encryption for an account is enable..."),
    "T1556.006": ("Multi-Factor Authentication", "Persistence", "Adversaries may disable or modify multi-factor authentication (MFA) mechanisms to enable persistent access to compromised accounts. Once adversaries have gained access to a network by either compromising an account lacking MFA or by employing an M..."),
    "T1556.007": ("Hybrid Identity", "Persistence", "Adversaries may patch, modify, or otherwise backdoor cloud authentication processes that are tied to on-premises user identities in order to bypass typical authentication mechanisms, access credentials, and enable persistent access to accounts. Ma..."),
    "T1556.008": ("Network Provider DLL", "Persistence", "Adversaries may register malicious network provider dynamic link libraries (DLLs) to capture cleartext user credentials during the authentication process. Network provider DLLs allow Windows to interface with specific network protocols and can als..."),
    "T1137": ("Office Application Startup", "Persistence", "Adversaries may leverage Microsoft Office-based applications for persistence between startups. Microsoft Office is a fairly common application suite on Windows-based operating systems within an enterprise network. There are multiple mechanisms tha..."),
    "T1137.001": ("Office Template Macros", "Persistence", "Adversaries may abuse Microsoft Office templates to obtain persistence on a compromised system. Microsoft Office contains templates that are part of common Office applications and are used to customize styles. The base templates within the applica..."),
    "T1137.002": ("Office Test", "Persistence", "Adversaries may abuse the Microsoft Office \"Office Test\" Registry key to obtain persistence on a compromised system. An Office Test Registry location exists that allows a user to specify an arbitrary DLL that will be executed every time an Office application is started. This Registry key is thoug..."),
    "T1137.003": ("Outlook Forms", "Persistence", "Adversaries may abuse Microsoft Outlook forms to obtain persistence on a compromised system. Outlook forms are used as templates for presentation and functionality in Outlook messages. Custom Outlook forms can be created that will execute code whe..."),
    "T1137.004": ("Outlook Home Page", "Persistence", "Adversaries may abuse Microsoft Outlook's Home Page feature to obtain persistence on a compromised system. Outlook Home Page is a legacy feature used to customize the presentation of Outlook folders. This feature allows for an internal or external..."),
    "T1137.005": ("Outlook Rules", "Persistence", "Adversaries may abuse Microsoft Outlook rules to obtain persistence on a compromised system. Outlook rules allow a user to define automated behavior to manage email messages. A benign rule might, for example, automatically move an email to a parti..."),
    "T1137.006": ("Add-ins", "Persistence", "Adversaries may abuse Microsoft Office add-ins to obtain persistence on a compromised system. Office add-ins can be used to add functionality to Office programs. There are different types of add-ins that can be used by the various Office products;..."),
    "T1653": ("Power Settings", "Persistence", "Adversaries may impair a system's ability to hibernate, reboot, or shut down in order to extend access to infected machines. When a computer enters a dormant state, some or all software and hardware may cease to operate which can disrupt malicious..."),
    "T1542": ("Pre-OS Boot", "Persistence", "Adversaries may abuse Pre-OS Boot mechanisms as a way to establish persistence on a system. During the booting process of a computer, firmware and various startup services are loaded before the operating system. These programs control flow of exec..."),
    "T1542.001": ("System Firmware", "Persistence", "Adversaries may modify system firmware to persist on systems.The BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) or Extensible Firmware Interface (EFI) are examples of system firmware that operate as the softw..."),
    "T1542.002": ("Component Firmware", "Persistence", "Adversaries may modify component firmware to persist on systems. Some adversaries may employ sophisticated means to compromise computer components and install malicious firmware that will execute adversary code outside of the operating system and ..."),
    "T1542.003": ("Bootkit", "Persistence", "Adversaries may use bootkits to persist on systems. A bootkit is a malware variant that modifies the boot sectors of a hard drive, allowing malicious code to execute before a computer's operating system has loaded. Bootkits reside at a layer below..."),
    "T1542.004": ("ROMMONkit", "Persistence", "Adversaries may abuse the ROM Monitor (ROMMON) by loading an unauthorized firmware with adversary code to provide persistent access and manipulate device behavior that is difficult to detect. ROMMON is a Cisco network device firmware that function..."),
    "T1542.005": ("TFTP Boot", "Persistence", "Adversaries may abuse netbooting to load an unauthorized network device operating system from a Trivial File Transfer Protocol (TFTP) server. TFTP boot (netbooting) is commonly used by network administrators to load configuration-controlled networ..."),
    "T1505": ("Server Software Component", "Persistence", "Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems. Enterprise server applications may include features that allow developers to write and install software or scripts to extend the..."),
    "T1505.001": ("SQL Stored Procedures", "Persistence", "Adversaries may abuse SQL stored procedures to establish persistent access to systems. SQL Stored Procedures are code that can be saved and reused so that database users do not waste time rewriting frequently used SQL queries. Stored procedures ca..."),
    "T1505.002": ("Transport Agent", "Persistence", "Adversaries may abuse Microsoft transport agents to establish persistent access to systems. Microsoft Exchange transport agents can operate on email messages passing through the transport pipeline to perform various tasks such as filtering spam, f..."),
    "T1505.003": ("Web Shell", "Persistence", "Adversaries may backdoor web servers with web shells to establish persistent access to systems. A Web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to access the Web server as a gateway into a networ..."),
    "T1505.004": ("IIS Components", "Persistence", "Adversaries may install malicious components that run on Internet Information Services (IIS) web servers to establish persistence. IIS provides several mechanisms to extend the functionality of the web servers. For example, Internet Server Applica..."),
    "T1505.005": ("Terminal Services DLL", "Persistence", "Adversaries may abuse components of Terminal Services to enable persistent access to systems. Microsoft Terminal Services, renamed to Remote Desktop Services in some Windows Server OSs as of 2022, enable remote terminal connections to hosts. Termi..."),
    "T1205": ("Traffic Signaling", "Persistence", "Adversaries may use traffic signaling to hide open ports or other malicious functionality used for persistence or command and control. Traffic signaling involves the use of a magic value or sequence that must be sent to a system to trigger a speci..."),
    "T1205.001": ("Port Knocking", "Persistence", "Adversaries may use port knocking to hide open ports used for persistence or command and control. To enable a port, an adversary sends a series of attempted connections to a predefined sequence of closed ports. After the sequence is completed, ope..."),
    "T1205.002": ("Socket Filters", "Persistence", "Adversaries may attach filters to a network socket to monitor then activate backdoors used for persistence or command and control. With elevated permissions, adversaries can use features such as the `libpcap` library to open sockets and install fi..."),

    # ==================== PRIVILEGE ESCALATION ====================
    "T1548": ("Abuse Elevation Control Mechanism", "Privilege Escalation", "Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machi..."),
    "T1548.001": ("Setuid and Setgid", "Privilege Escalation", "An adversary may abuse configurations where an application has the setuid or setgid bits set in order to get code running in a different (and possibly more privileged) user’s context. On Linux or macOS, when the setuid or setgid bits are set for a..."),
    "T1548.002": ("Bypass User Account Control", "Privilege Escalation", "Adversaries may bypass UAC mechanisms to elevate process privileges on system. Windows User Account Control (UAC) allows a program to elevate its privileges (tracked as integrity levels ranging from low to high) to perform a task under administrat..."),
    "T1548.003": ("Sudo and Sudo Caching", "Privilege Escalation", "Adversaries may perform sudo caching and/or use the sudoers file to elevate privileges. Adversaries may do this to execute commands as other users or spawn processes with higher privileges. Within Linux and MacOS systems, sudo (sometimes referred to as \"superuser do\") allows users to perform comm..."),
    "T1548.004": ("Elevated Execution with Prompt", "Privilege Escalation", "Adversaries may leverage the AuthorizationExecuteWithPrivileges API to escalate privileges by prompting the user for credentials. The purpose of this API is to give application developers an easy way to perform operations with root privileges, suc..."),
    "T1548.005": ("Temporary Elevated Cloud Access", "Privilege Escalation", "Adversaries may abuse permission configurations that allow them to gain temporarily elevated access to cloud resources. Many cloud environments allow administrators to grant user or service accounts permission to request just-in-time access to rol..."),
    "T1134": ("Access Token Manipulation", "Privilege Escalation", "Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls. Windows uses access tokens to determine the ownership of a running process. A user can manipulate acce..."),
    "T1134.001": ("Token Impersonation/Theft", "Privilege Escalation", "Adversaries may duplicate then impersonate another user's existing token to escalate privileges and bypass access controls. For example, an adversary can duplicate an existing token using `DuplicateToken` or `DuplicateTokenEx`. The token can then ..."),
    "T1134.002": ("Create Process with Token", "Privilege Escalation", "Adversaries may create a new process with an existing token to escalate privileges and bypass access controls. Processes can be created with the token and resulting security context of another user using features such as CreateProcessWithTokenW an..."),
    "T1134.003": ("Make and Impersonate Token", "Privilege Escalation", "Adversaries may make new tokens and impersonate users to escalate privileges and bypass access controls. For example, if an adversary has a username and password but the user is not logged onto the system the adversary can then create a logon sess..."),
    "T1134.004": ("Parent PID Spoofing", "Privilege Escalation", "Adversaries may spoof the parent process identifier (PPID) of a new process to evade process-monitoring defenses or to elevate privileges. New processes are typically spawned directly from their parent, or calling, process unless explicitly specif..."),
    "T1134.005": ("SID-History Injection", "Privilege Escalation", "Adversaries may use SID-History Injection to escalate privileges and bypass access controls. The Windows security identifier (SID) is a unique value that identifies a user or group account. SIDs are used by Windows security in both security descri..."),
    "T1484": ("Domain Policy Modification", "Privilege Escalation", "Adversaries may modify the configuration settings of a domain or identity tenant to evade defenses and/or escalate privileges in centrally managed environments. Such services provide a centralized means of managing identity resources such as devic..."),
    "T1484.001": ("Group Policy Modification", "Privilege Escalation", "Adversaries may modify Group Policy Objects (GPOs) to subvert the intended discretionary access controls for a domain, usually with the intention of escalating privileges on the domain. Group policy allows for centralized management of user and co..."),
    "T1484.002": ("Domain Trust Modification", "Privilege Escalation", "Adversaries may add new domain trusts, modify the properties of existing domain trusts, or otherwise change the configuration of trust relationships between domains and tenants to evade defenses and/or elevate privileges.Trust details, such as whe..."),
    "T1611": ("Escape to Host", "Privilege Escalation", "Adversaries may break out of a container or virtualized environment to gain access to the underlying host. This can allow an adversary access to other containerized or virtualized resources from the host level or to the host itself. In principle, ..."),
    "T1068": ("Exploitation for Privilege Escalation", "Privilege Escalation", "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system so..."),
    "T1055": ("Process Injection", "Privilege Escalation", "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in ..."),
    "T1055.001": ("Dynamic-link Library Injection", "Privilege Escalation", "Adversaries may inject dynamic-link libraries (DLLs) into processes in order to evade process-based defenses as well as possibly elevate privileges. DLL injection is a method of executing arbitrary code in the address space of a separate live proc..."),
    "T1055.002": ("Portable Executable Injection", "Privilege Escalation", "Adversaries may inject portable executables (PE) into processes in order to evade process-based defenses as well as possibly elevate privileges. PE injection is a method of executing arbitrary code in the address space of a separate live process. ..."),
    "T1055.003": ("Thread Execution Hijacking", "Privilege Escalation", "Adversaries may inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges. Thread Execution Hijacking is a method of executing arbitrary code in the address space of a separate li..."),
    "T1055.004": ("Asynchronous Procedure Call", "Privilege Escalation", "Adversaries may inject malicious code into processes via the asynchronous procedure call (APC) queue in order to evade process-based defenses as well as possibly elevate privileges. APC injection is a method of executing arbitrary code in the addr..."),
    "T1055.005": ("Thread Local Storage", "Privilege Escalation", "Adversaries may inject malicious code into processes via thread local storage (TLS) callbacks in order to evade process-based defenses as well as possibly elevate privileges. TLS callback injection is a method of executing arbitrary code in the ad..."),
    "T1055.008": ("Ptrace System Calls", "Privilege Escalation", "Adversaries may inject malicious code into processes via ptrace (process trace) system calls in order to evade process-based defenses as well as possibly elevate privileges. Ptrace system call injection is a method of executing arbitrary code in t..."),
    "T1055.009": ("Proc Memory", "Privilege Escalation", "Adversaries may inject malicious code into processes via the /proc filesystem in order to evade process-based defenses as well as possibly elevate privileges. Proc memory injection is a method of executing arbitrary code in the address space of a ..."),
    "T1055.011": ("Extra Window Memory Injection", "Privilege Escalation", "Adversaries may inject malicious code into process via Extra Window Memory (EWM) in order to evade process-based defenses as well as possibly elevate privileges. EWM injection is a method of executing arbitrary code in the address space of a separ..."),
    "T1055.012": ("Process Hollowing", "Privilege Escalation", "Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses. Process hollowing is a method of executing arbitrary code in the address space of a separate live process. Process hollowing is c..."),
    "T1055.013": ("Process Doppelgänging", "Privilege Escalation", "Adversaries may inject malicious code into process via process doppelgänging in order to evade process-based defenses as well as possibly elevate privileges. Process doppelgänging is a method of executing arbitrary code in the address space of a s..."),
    "T1055.014": ("VDSO Hijacking", "Privilege Escalation", "Adversaries may inject malicious code into processes via VDSO hijacking in order to evade process-based defenses as well as possibly elevate privileges. Virtual dynamic shared object (vdso) hijacking is a method of executing arbitrary code in the ..."),
    "T1055.015": ("ListPlanting", "Privilege Escalation", "Adversaries may abuse list-view controls to inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges. ListPlanting is a method of executing arbitrary code in the address space of..."),

    # ==================== DEFENSE EVASION ====================
    "T1612": ("Build Image on Host", "Defense Evasion", "Adversaries may build a container image directly on a host to bypass defenses that monitor for the retrieval of malicious images from a public registry. A remote build request may be sent to the Docker API that includes a Dockerfile that pulls a v..."),
    "T1622": ("Debugger Evasion", "Defense Evasion", "Adversaries may employ various means to detect and avoid debuggers. Debuggers are typically used by defenders to trace and/or analyze the execution of potential malware payloads. Debugger evasion may include changing behaviors based on the results..."),
    "T1140": ("Deobfuscate/Decode Files or Information", "Defense Evasion", "Adversaries may use [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027) to hide artifacts of an intrusion from analysis. They may require separate mechanisms to decode or deobfuscate that information depending on how they ..."),
    "T1610": ("Deploy Container", "Defense Evasion", "Adversaries may deploy a container into an environment to facilitate execution or evade defenses. In some cases, adversaries may deploy a new container to execute processes associated with a particular image or deployment, such as processes that e..."),
    "T1006": ("Direct Volume Access", "Defense Evasion", "Adversaries may directly access a volume to bypass file access controls and file system monitoring. Windows allows programs to have direct access to logical volumes. Programs with direct access may read and write files directly from the drive by a..."),
    "T1484": ("Domain Policy Modification", "Defense Evasion", "Adversaries may modify the configuration settings of a domain or identity tenant to evade defenses and/or escalate privileges in centrally managed environments. Such services provide a centralized means of managing identity resources such as devic..."),
    "T1480": ("Execution Guardrails", "Defense Evasion", "Adversaries may use execution guardrails to constrain execution or actions based on adversary supplied and environment specific conditions that are expected to be present on the target. Guardrails ensure that a payload only executes against an int..."),
    "T1480.001": ("Environmental Keying", "Defense Evasion", "Adversaries may environmentally key payloads or other features of malware to evade defenses and constraint execution to a specific target environment. Environmental keying uses cryptography to constrain execution or actions based on adversary supp..."),
    "T1211": ("Exploitation for Defense Evasion", "Defense Evasion", "Adversaries may exploit a system or application vulnerability to bypass security features. Exploitation of a vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system softwa..."),
    "T1222": ("File and Directory Permissions Modification", "Defense Evasion", "Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with t..."),
    "T1222.001": ("Windows File and Directory Permissions Modification", "Defense Evasion", "Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with t..."),
    "T1222.002": ("Linux and Mac File and Directory Permissions Modification", "Defense Evasion", "Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with t..."),
    "T1564": ("Hide Artifacts", "Defense Evasion", "Adversaries may attempt to hide artifacts associated with their behaviors to evade detection. Operating systems may have features to hide various artifacts, such as important system files and administrative task execution, to avoid disrupting user..."),
    "T1564.001": ("Hidden Files and Directories", "Defense Evasion", "Adversaries may set files and directories to be hidden to evade detection mechanisms. To prevent normal users from accidentally changing special files on a system, most operating systems have the concept of a ‘hidden’ file. These files don’t show ..."),
    "T1564.002": ("Hidden Users", "Defense Evasion", "Adversaries may use hidden users to hide the presence of user accounts they create or modify. Administrators may want to hide users when there are many user accounts on a given system or if they want to hide their administrative or other managemen..."),
    "T1564.003": ("Hidden Window", "Defense Evasion", "Adversaries may use hidden windows to conceal malicious activity from the plain sight of users. In some cases, windows that would typically be displayed when an application carries out an operation can be hidden. This may be utilized by system adm..."),
    "T1564.004": ("NTFS File Attributes", "Defense Evasion", "Adversaries may use NTFS file attributes to hide their malicious data in order to evade detection. Every New Technology File System (NTFS) formatted partition contains a Master File Table (MFT) that maintains a record for every file/directory on t..."),
    "T1564.005": ("Hidden File System", "Defense Evasion", "Adversaries may use a hidden file system to conceal malicious activity from users and security tools. File systems provide a structure to store and access data from physical storage. Typically, a user engages with a file system through application..."),
    "T1564.006": ("Run Virtual Instance", "Defense Evasion", "Adversaries may carry out malicious operations using a virtual instance to avoid detection. A wide variety of virtualization technologies exist that allow for the emulation of a computer or computing environment. By running malicious code inside o..."),
    "T1564.007": ("VBA Stomping", "Defense Evasion", "Adversaries may hide malicious Visual Basic for Applications (VBA) payloads embedded within MS Office documents by replacing the VBA source code with benign data. MS Office documents with embedded VBA content store source code inside of module str..."),
    "T1564.008": ("Email Hiding Rules", "Defense Evasion", "Adversaries may use email rules to hide inbound emails in a compromised user's mailbox. Many email clients allow users to create inbox rules for various email functions, including moving emails to other folders, marking emails as read, or deleting..."),
    "T1564.009": ("Resource Forking", "Defense Evasion", "Adversaries may abuse resource forks to hide malicious code or executables to evade detection and bypass security applications. A resource fork provides applications a structured way to store resources such as thumbnail images, menu definitions, i..."),
    "T1564.010": ("Process Argument Spoofing", "Defense Evasion", "Adversaries may attempt to hide process command-line arguments by overwriting process memory. Process command-line arguments are stored in the process environment block (PEB), a data structure used by Windows to store various information about/use..."),
    "T1564.011": ("Ignore Process Interrupts", "Defense Evasion", "Adversaries may evade defensive mechanisms by executing commands that hide from process interrupt signals. Many operating systems use signals to deliver messages to control process behavior. Command interpreters often include specific commands/fla..."),
    "T1562": ("Impair Defenses", "Defense Evasion", "Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms. This not only involves impairing preventative defenses, such as firewalls and anti-virus, but also detection capabilities tha..."),
    "T1562.001": ("Disable or Modify Tools", "Defense Evasion", "Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities. This may take many forms, such as killing security software processes or services, modifying / deleting Registry keys or config..."),
    "T1562.002": ("Disable Windows Event Logging", "Defense Evasion", "Adversaries may disable Windows event logging to limit data that can be leveraged for detections and audits. Windows event logs record user and system activity such as login attempts, process creation, and much more. This data is used by security ..."),
    "T1562.003": ("Impair Command History Logging", "Defense Evasion", "Adversaries may impair command history logging to hide commands they run on a compromised system. Various command interpreters keep track of the commands users type in their terminal so that users can retrace what they've done. On Linux and macOS,..."),
    "T1562.004": ("Disable or Modify System Firewall", "Defense Evasion", "Adversaries may disable or modify system firewalls in order to bypass controls limiting network usage. Changes could be disabling the entire mechanism as well as adding, deleting, or modifying particular rules. This can be done numerous ways depen..."),
    "T1562.006": ("Indicator Blocking", "Defense Evasion", "An adversary may attempt to block indicators or events typically captured by sensors from being gathered and analyzed. This could include maliciously redirecting or even disabling host-based sensors, such as Event Tracing for Windows (ETW), by tam..."),
    "T1562.007": ("Disable or Modify Cloud Firewall", "Defense Evasion", "Adversaries may disable or modify a firewall within a cloud environment to bypass controls that limit access to cloud resources. Cloud firewalls are separate from system firewalls that are described in [Disable or Modify System Firewall](https://a..."),
    "T1562.008": ("Disable Cloud Logs", "Defense Evasion", "An adversary may disable or modify cloud logging capabilities and integrations to limit what data is collected on their activities and avoid detection. Cloud environments allow for collection and analysis of audit and application logs that provide..."),
    "T1562.009": ("Safe Mode Boot", "Defense Evasion", "Adversaries may abuse Windows safe mode to disable endpoint defenses. Safe mode starts up the Windows operating system with a limited set of drivers and services. Third-party security software such as endpoint detection and response (EDR) tools ma..."),
    "T1562.010": ("Downgrade Attack", "Defense Evasion", "Adversaries may downgrade or use a version of system features that may be outdated, vulnerable, and/or does not support updated security controls. Downgrade attacks typically take advantage of a system’s backward compatibility to force it into les..."),
    "T1562.011": ("Spoof Security Alerting", "Defense Evasion", "Adversaries may spoof security alerting from tools, presenting false evidence to impair defenders’ awareness of malicious activity. Messages produced by defensive tools contain information about potential security events as well as the functioning..."),
    "T1562.012": ("Disable or Modify Linux Audit System", "Defense Evasion", "Adversaries may disable or modify the Linux audit system to hide malicious activity and avoid detection. Linux admins use the Linux Audit system to track security-relevant information on a system. The Linux Audit system operates at the kernel-leve..."),
    "T1656": ("Impersonation", "Defense Evasion", "Adversaries may impersonate a trusted person or organization in order to persuade and trick a target into performing some action on their behalf. For example, adversaries may communicate with victims (via [Phishing for Information](https://attack...."),
    "T1070": ("Indicator Removal", "Defense Evasion", "Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence or hinder defenses. Various artifacts may be created by an adversary or something that can be attributed to an adversary’s actions. Typically ..."),
    "T1070.001": ("Clear Windows Event Logs", "Defense Evasion", "Adversaries may clear Windows Event Logs to hide the activity of an intrusion. Windows Event Logs are a record of a computer's alerts and notifications. There are three system-defined sources of events: System, Application, and Security, with five..."),
    "T1070.002": ("Clear Linux or Mac System Logs", "Defense Evasion", "Adversaries may clear system logs to hide evidence of an intrusion. macOS and Linux both keep track of system or user-initiated actions via system logs. The majority of native system logging is stored under the /var/log/ directory. Subfolders in t..."),
    "T1070.003": ("Clear Command History", "Defense Evasion", "In addition to clearing system logs, an adversary may clear the command history of a compromised account to conceal the actions undertaken during an intrusion. Various command interpreters keep track of the commands users type in their terminal so..."),
    "T1070.004": ("File Deletion", "Defense Evasion", "Adversaries may delete files left behind by the actions of their intrusion activity. Malware, tools, or other non-native files dropped or created on a system by an adversary (ex: [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)) ..."),
    "T1070.005": ("Network Share Connection Removal", "Defense Evasion", "Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation. Windows shared drive and [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) connections can be removed when n..."),
    "T1070.006": ("Timestomp", "Defense Evasion", "Adversaries may modify file time attributes to hide new files or changes to existing files. Timestomping is a technique that modifies the timestamps of a file (the modify, access, create, and change times), often to mimic files that are in the sam..."),
    "T1070.007": ("Clear Network Connection History and Configurations", "Defense Evasion", "Adversaries may clear or remove evidence of malicious network connections in order to clean up traces of their operations. Configuration settings as well as various artifacts that highlight connection history may be created on a system and/or in a..."),
    "T1070.008": ("Clear Mailbox Data", "Defense Evasion", "Adversaries may modify mail and mail application data to remove evidence of their activity. Email applications allow users and other programs to export and delete mailbox data via command line tools or use of APIs. Mail application data can be ema..."),
    "T1070.009": ("Clear Persistence", "Defense Evasion", "Adversaries may clear artifacts associated with previously established persistence on a host system to remove evidence of their activity. This may involve various actions, such as removing services, deleting executables, [Modify Registry](https://..."),
    "T1202": ("Indirect Command Execution", "Defense Evasion", "Adversaries may abuse utilities that allow for command execution to bypass security restrictions that limit the use of command-line interpreters. Various Windows utilities may be used to execute commands, possibly without invoking [cmd](https://at..."),
    "T1036": ("Masquerading", "Defense Evasion", "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools. Masquerading occurs when the name or location of an object, legitimate or malicious, is manipulated or abuse..."),
    "T1036.001": ("Invalid Code Signature", "Defense Evasion", "Adversaries may attempt to mimic features of valid code signatures to increase the chance of deceiving a user, analyst, or tool. Code signing provides a level of authenticity on a binary from the developer and a guarantee that the binary has not b..."),
    "T1036.002": ("Right-to-Left Override", "Defense Evasion", "Adversaries may abuse the right-to-left override (RTLO or RLO) character (U+202E) to disguise a string and/or file name to make it appear benign. RTLO is a non-printing Unicode character that causes the text that follows it to be displayed in reve..."),
    "T1036.003": ("Rename System Utilities", "Defense Evasion", "Adversaries may rename legitimate / system utilities to try to evade security mechanisms concerning the usage of those utilities. Security monitoring and control mechanisms may be in place for legitimate utilities adversaries are capable of abusin..."),
    "T1036.004": ("Masquerade Task or Service", "Defense Evasion", "Adversaries may attempt to manipulate the name of a task or service to make it appear legitimate or benign. Tasks/services executed by the Task Scheduler or systemd will typically be given a name and/or description. Windows services will have a se..."),
    "T1036.005": ("Match Legitimate Name or Location", "Defense Evasion", "Adversaries may match or approximate the name or location of legitimate files, Registry keys, or other resources when naming/placing them. This is done for the sake of evading defenses and observation. This may be done by placing an executable in ..."),
    "T1036.006": ("Space after Filename", "Defense Evasion", "Adversaries can hide a program's true filetype by changing the extension of a file. With certain file types (specifically this does not work with .app extensions), appending a space to the end of a filename will change how the file is processed by..."),
    "T1036.007": ("Double File Extension", "Defense Evasion", "Adversaries may abuse a double extension in the filename as a means of masquerading the true file type. A file name may include a secondary file type extension that may cause only the first extension to be displayed (ex: File.txt.exe may render in..."),
    "T1036.008": ("Masquerade File Type", "Defense Evasion", "Adversaries may masquerade malicious payloads as legitimate files through changes to the payload's formatting, including the file’s signature, extension, icon, and contents. Various file types have a typical standard format, including how they are..."),
    "T1036.009": ("Break Process Trees", "Defense Evasion", "An adversary may attempt to evade process tree-based analysis by modifying executed malware's parent process ID (PPID). If endpoint protection software leverages the “parent-child\" relationship for detection, breaking this relationship could result in the adversary’s behavior not being associated..."),
    "T1556": ("Modify Authentication Process", "Defense Evasion", "Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LS..."),
    "T1578": ("Modify Cloud Compute Infrastructure", "Defense Evasion", "An adversary may attempt to modify a cloud account's compute service infrastructure to evade defenses. A modification to the compute service infrastructure can include the creation, deletion, or modification of one or more components such as compu..."),
    "T1578.001": ("Create Snapshot", "Defense Evasion", "An adversary may create a snapshot or data backup within a cloud account to evade defenses. A snapshot is a point-in-time copy of an existing cloud compute component such as a virtual machine (VM), virtual hard drive, or volume. An adversary may l..."),
    "T1578.002": ("Create Cloud Instance", "Defense Evasion", "An adversary may create a new instance or virtual machine (VM) within the compute service of a cloud account to evade defenses. Creating a new instance may allow an adversary to bypass firewall rules and permissions that exist on instances current..."),
    "T1578.003": ("Delete Cloud Instance", "Defense Evasion", "An adversary may delete a cloud instance after they have performed malicious activities in an attempt to evade detection and remove evidence of their presence. Deleting an instance or virtual machine can remove valuable forensic artifacts and othe..."),
    "T1578.004": ("Revert Cloud Instance", "Defense Evasion", "An adversary may revert changes made to a cloud instance after they have performed malicious activities in attempt to evade detection and remove evidence of their presence. In highly virtualized environments, such as cloud-based infrastructure, th..."),
    "T1578.005": ("Modify Cloud Compute Configurations", "Defense Evasion", "Adversaries may modify settings that directly affect the size, locations, and resources available to cloud compute infrastructure in order to evade defenses. These settings may include service quotas, subscription associations, tenant-wide policie..."),
    "T1112": ("Modify Registry", "Defense Evasion", "Adversaries may interact with the Windows Registry as part of a variety of other techniques to aid in defense evasion, persistence, and execution. Access to specific areas of the Registry depends on account permissions, with some keys requiring ad..."),
    "T1601": ("Modify System Image", "Defense Evasion", "Adversaries may make changes to the operating system of embedded network devices to weaken defenses and provide new capabilities for themselves. On such devices, the operating systems are typically monolithic and most of the device functionality a..."),
    "T1601.001": ("Patch System Image", "Defense Evasion", "Adversaries may modify the operating system of a network device to introduce new capabilities or weaken existing defenses. Some network devices are built with a monolithic architecture, where the entire operating system and most of the functionali..."),
    "T1601.002": ("Downgrade System Image", "Defense Evasion", "Adversaries may install an older version of the operating system of a network device to weaken security. Older operating system versions on network devices often have weaker encryption ciphers and, in general, fewer/less updated defensive features..."),
    "T1599": ("Network Boundary Bridging", "Defense Evasion", "Adversaries may bridge network boundaries by compromising perimeter network devices or internal devices responsible for network segmentation. Breaching these devices may enable an adversary to bypass restrictions on traffic routing that otherwise ..."),
    "T1599.001": ("Network Address Translation Traversal", "Defense Evasion", "Adversaries may bridge network boundaries by modifying a network device’s Network Address Translation (NAT) configuration. Malicious modifications to NAT may enable an adversary to bypass restrictions on traffic routing that otherwise separate tru..."),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion", "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms ..."),
    "T1027.001": ("Binary Padding", "Defense Evasion", "Adversaries may use binary padding to add junk data and change the on-disk representation of malware. This can be done without affecting the functionality or behavior of a binary, but can increase the size of the binary beyond what some security t..."),
    "T1027.002": ("Software Packing", "Defense Evasion", "Adversaries may perform software packing or virtual machine software protection to conceal their code. Software packing is a method of compressing or encrypting an executable. Packing an executable changes the file signature in an attempt to avoid..."),
    "T1027.003": ("Steganography", "Defense Evasion", "Adversaries may use steganography techniques in order to prevent the detection of hidden information. Steganographic techniques can be used to hide data in digital media such as images, audio tracks, video clips, or text files. [Duqu](https://atta..."),
    "T1027.004": ("Compile After Delivery", "Defense Evasion", "Adversaries may attempt to make payloads difficult to discover and analyze by delivering files to victims as uncompiled code. Text-based source code files may subvert analysis and scrutiny from protections targeting executables/binaries. These pay..."),
    "T1027.005": ("Indicator Removal from Tools", "Defense Evasion", "Adversaries may remove indicators from tools if they believe their malicious tool was detected, quarantined, or otherwise curtailed. They can modify the tool by removing the indicator and using the updated version that is no longer detected by the..."),
    "T1027.006": ("HTML Smuggling", "Defense Evasion", "Adversaries may smuggle data and files past content filters by hiding malicious payloads inside of seemingly benign HTML files. HTML documents can store large binary objects known as JavaScript Blobs (immutable data that represents raw bytes) that..."),
    "T1027.007": ("Dynamic API Resolution", "Defense Evasion", "Adversaries may obfuscate then dynamically resolve API functions called by their malware in order to conceal malicious functionalities and impair defensive analysis. Malware commonly uses various [Native API](https://attack.mitre.org/techniques/T1..."),
    "T1027.008": ("Stripped Payloads", "Defense Evasion", "Adversaries may attempt to make a payload difficult to analyze by removing symbols, strings, and other human readable information. Scripts and executables may contain variables names and other strings that help developers document code functionali..."),
    "T1027.009": ("Embedded Payloads", "Defense Evasion", "Adversaries may embed payloads within other files to conceal malicious content from defenses. Otherwise seemingly benign files (such as scripts and executables) may be abused to carry and obfuscate malicious payloads and content. In some cases, em..."),
    "T1027.010": ("Command Obfuscation", "Defense Evasion", "Adversaries may obfuscate content during command execution to impede detection. Command-line obfuscation is a method of making strings and patterns within commands and scripts more difficult to signature and analyze. This type of obfuscation can b..."),
    "T1027.011": ("Fileless Storage", "Defense Evasion", "Adversaries may store data in \"fileless\" formats to conceal malicious activity from defenses. Fileless storage can be broadly defined as any format other than a file. Common examples of non-volatile fileless storage in Windows systems include the Windows Registry, event logs, or WMI repository. S..."),
    "T1027.012": ("LNK Icon Smuggling", "Defense Evasion", "Adversaries may smuggle commands to download malicious payloads past content filters by hiding them within otherwise seemingly benign windows shortcut files. Windows shortcut files (.LNK) include many metadata fields, including an icon location fi..."),
    "T1647": ("Plist File Modification", "Defense Evasion", "Adversaries may modify property list files (plist files) to enable other malicious activity, while also potentially evading and bypassing system defenses. macOS applications use plist files, such as the info.plist file, to store properties and con..."),
    "T1620": ("Reflective Code Loading", "Defense Evasion", "Adversaries may reflectively load code into a process in order to conceal the execution of malicious payloads. Reflective loading involves allocating then executing payloads directly within the memory of the process, vice creating a thread or proc..."),
    "T1207": ("Rogue Domain Controller", "Defense Evasion", "Adversaries may register a rogue Domain Controller to enable manipulation of Active Directory data. DCShadow may be used to create a rogue Domain Controller (DC). DCShadow is a method of manipulating Active Directory (AD) data, including objects a..."),
    "T1014": ("Rootkit", "Defense Evasion", "Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components. Rootkits are programs that hide the existence of malware by intercepting/hooking and modifying operating sys..."),
    "T1553": ("Subvert Trust Controls", "Defense Evasion", "Adversaries may undermine security controls that will either warn users of untrusted activity or prevent execution of untrusted programs. Operating systems and security products may contain mechanisms to identify programs or websites as possessing..."),
    "T1553.001": ("Gatekeeper Bypass", "Defense Evasion", "Adversaries may modify file attributes and subvert Gatekeeper functionality to evade user prompts and execute untrusted programs. Gatekeeper is a set of technologies that act as layer of Apple’s security model to ensure only trusted applications a..."),
    "T1553.002": ("Code Signing", "Defense Evasion", "Adversaries may create, acquire, or steal code signing materials to sign their malware or tools. Code signing provides a level of authenticity on a binary from the developer and a guarantee that the binary has not been tampered with. The certifica..."),
    "T1553.003": ("SIP and Trust Provider Hijacking", "Defense Evasion", "Adversaries may tamper with SIP and trust provider components to mislead the operating system and application control tools when conducting signature validation checks. In user mode, Windows Authenticode digital signatures are used to verify a fil..."),
    "T1553.004": ("Install Root Certificate", "Defense Evasion", "Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers. Root certificates are used in public key cryptography to identify a root certificate authority (CA). When a r..."),
    "T1553.005": ("Mark-of-the-Web Bypass", "Defense Evasion", "Adversaries may abuse specific file formats to subvert Mark-of-the-Web (MOTW) controls. In Windows, when files are downloaded from the Internet, they are tagged with a hidden NTFS Alternate Data Stream (ADS) named Zone.Identifier with a specific v..."),
    "T1553.006": ("Code Signing Policy Modification", "Defense Evasion", "Adversaries may modify code signing policies to enable execution of unsigned or self-signed code. Code signing provides a level of authenticity on a program from a developer and a guarantee that the program has not been tampered with. Security con..."),
    "T1218": ("System Binary Proxy Execution", "Defense Evasion", "Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed, or otherwise trusted, binaries. Binaries used in this technique are often Microsoft-signed files, indicating that they have been..."),
    "T1218.001": ("Compiled HTML File", "Defense Evasion", "Adversaries may abuse Compiled HTML files (.chm) to conceal malicious code. CHM files are commonly distributed as part of the Microsoft HTML Help system. CHM files are compressed compilations of various content such as HTML documents, images, and ..."),
    "T1218.002": ("Control Panel", "Defense Evasion", "Adversaries may abuse control.exe to proxy execution of malicious payloads. The Windows Control Panel process binary (control.exe) handles execution of Control Panel items, which are utilities that allow users to view and adjust computer settings...."),
    "T1218.003": ("CMSTP", "Defense Evasion", "Adversaries may abuse CMSTP to proxy execution of malicious code. The Microsoft Connection Manager Profile Installer (CMSTP.exe) is a command-line program used to install Connection Manager service profiles. CMSTP.exe accepts an installation infor..."),
    "T1218.004": ("InstallUtil", "Defense Evasion", "Adversaries may use InstallUtil to proxy execution of code through a trusted Windows utility. InstallUtil is a command-line utility that allows for installation and uninstallation of resources by executing specific installer components specified i..."),
    "T1218.005": ("Mshta", "Defense Evasion", "Adversaries may abuse mshta.exe to proxy execution of malicious .hta files and Javascript or VBScript through a trusted Windows utility. There are several examples of different types of threats leveraging mshta.exe during initial compromise and fo..."),
    "T1218.007": ("Msiexec", "Defense Evasion", "Adversaries may abuse msiexec.exe to proxy execution of malicious payloads. Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi). The Msiexec.exe binary may a..."),
    "T1218.008": ("Odbcconf", "Defense Evasion", "Adversaries may abuse odbcconf.exe to proxy execution of malicious payloads. Odbcconf.exe is a Windows utility that allows you to configure Open Database Connectivity (ODBC) drivers and data source names. The Odbcconf.exe binary may be digitally s..."),
    "T1218.009": ("Regsvcs/Regasm", "Defense Evasion", "Adversaries may abuse Regsvcs and Regasm to proxy execution of code through a trusted Windows utility. Regsvcs and Regasm are Windows command-line utilities that are used to register .NET [Component Object Model](https://attack.mitre.org/technique..."),
    "T1218.010": ("Regsvr32", "Defense Evasion", "Adversaries may abuse Regsvr32.exe to proxy execution of malicious code. Regsvr32.exe is a command-line program used to register and unregister object linking and embedding controls, including dynamic link libraries (DLLs), on Windows systems. The..."),
    "T1218.011": ("Rundll32", "Defense Evasion", "Adversaries may abuse rundll32.exe to proxy execution of malicious code. Using rundll32.exe, vice executing directly (i.e. [Shared Modules](https://attack.mitre.org/techniques/T1129)), may avoid triggering security tools that may not monitor execu..."),
    "T1218.012": ("Verclsid", "Defense Evasion", "Adversaries may abuse verclsid.exe to proxy execution of malicious code. Verclsid.exe is known as the Extension CLSID Verification Host and is responsible for verifying each shell extension before they are used by Windows Explorer or the Windows S..."),
    "T1218.013": ("Mavinject", "Defense Evasion", "Adversaries may abuse mavinject.exe to proxy execution of malicious code. Mavinject.exe is the Microsoft Application Virtualization Injector, a Windows utility that can inject code into external processes as part of Microsoft Application Virtualiz..."),
    "T1218.014": ("MMC", "Defense Evasion", "Adversaries may abuse mmc.exe to proxy execution of malicious .msc files. Microsoft Management Console (MMC) is a binary that may be signed by Microsoft and is used in several ways in either its GUI or in a command prompt. MMC can be used to creat..."),
    "T1216": ("System Script Proxy Execution", "Defense Evasion", "Adversaries may use trusted scripts, often signed with certificates, to proxy the execution of malicious files. Several Microsoft signed scripts that have been downloaded from Microsoft or are default on Windows installations can be used to proxy ..."),
    "T1216.001": ("PubPrn", "Defense Evasion", "Adversaries may use PubPrn to proxy execution of malicious remote files. PubPrn.vbs is a [Visual Basic](https://attack.mitre.org/techniques/T1059/005) script that publishes a printer to Active Directory Domain Services. The script may be signed by..."),
    "T1216.002": ("SyncAppvPublishingServer", "Defense Evasion", "Adversaries may abuse SyncAppvPublishingServer.vbs to proxy execution of malicious [PowerShell](https://attack.mitre.org/techniques/T1059/001) commands. SyncAppvPublishingServer.vbs is a Visual Basic script associated with how Windows virtualizes ..."),
    "T1221": ("Template Injection", "Defense Evasion", "Adversaries may create or modify references in user document templates to conceal malicious code or force authentication attempts. For example, Microsoft’s Office Open XML (OOXML) specification defines an XML-based format for Office documents (.do..."),
    "T1127": ("Trusted Developer Utilities Proxy Execution", "Defense Evasion", "Adversaries may take advantage of trusted developer utilities to proxy execution of malicious payloads. There are many utilities used for software development related tasks that can be used to execute code in various forms to assist in development..."),
    "T1127.001": ("MSBuild", "Defense Evasion", "Adversaries may use MSBuild to proxy execution of code through a trusted Windows utility. MSBuild.exe (Microsoft Build Engine) is a software build platform used by Visual Studio. It handles XML formatted project files that define requirements for ..."),
    "T1535": ("Unused/Unsupported Cloud Regions", "Defense Evasion", "Adversaries may create cloud instances in unused geographic service regions in order to evade detection. Access is usually obtained through compromising accounts used to manage cloud infrastructure. Cloud service providers often provide infrastruc..."),
    "T1550": ("Use Alternate Authentication Material", "Defense Evasion", "Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls. Authentication processes ge..."),
    "T1550.001": ("Application Access Token", "Defense Evasion", "Adversaries may use stolen application access tokens to bypass the typical authentication process and access restricted accounts, information, or services on remote systems. These tokens are typically stolen from users or services and used in lieu..."),
    "T1550.002": ("Pass the Hash", "Defense Evasion", "Adversaries may “pass the hash” using stolen password hashes to move laterally within an environment, bypassing normal system access controls. Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartex..."),
    "T1550.003": ("Pass the Ticket", "Defense Evasion", "Adversaries may “pass the ticket” using stolen Kerberos tickets to move laterally within an environment, bypassing normal system access controls. Pass the ticket (PtT) is a method of authenticating to a system using Kerberos tickets without having..."),
    "T1550.004": ("Web Session Cookie", "Defense Evasion", "Adversaries can use stolen session cookies to authenticate to web applications and services. This technique bypasses some multi-factor authentication protocols since the session is already authenticated. Authentication cookies are commonly used in..."),
    "T1497": ("Virtualization/Sandbox Evasion", "Defense Evasion", "Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) o..."),
    "T1497.001": ("System Checks", "Defense Evasion", "Adversaries may employ various system checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment..."),
    "T1497.002": ("User Activity Based Checks", "Defense Evasion", "Adversaries may employ various user activity checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine envi..."),
    "T1497.003": ("Time Based Evasion", "Defense Evasion", "Adversaries may employ various time-based methods to detect virtualization and analysis environments, particularly those that attempt to manipulate time mechanisms to simulate longer elapses of time. This may include enumerating time-based propert..."),
    "T1600": ("Weaken Encryption", "Defense Evasion", "Adversaries may compromise a network device’s encryption capability in order to bypass encryption that would otherwise protect data communications. Encryption can be used to protect transmitted network traffic to maintain its confidentiality (prot..."),
    "T1600.001": ("Reduce Key Space", "Defense Evasion", "Adversaries may reduce the level of effort required to decrypt data transmitted over the network by reducing the cipher strength of encrypted communications. Adversaries can weaken the encryption software on a compromised network device by reducin..."),
    "T1600.002": ("Disable Crypto Hardware", "Defense Evasion", "Adversaries disable a network device’s dedicated hardware encryption, which may enable them to leverage weaknesses in software encryption in order to reduce the effort involved in collecting, manipulating, and exfiltrating transmitted data. Many n..."),
    "T1220": ("XSL Script Processing", "Defense Evasion", "Adversaries may bypass application control and obscure execution of code by embedding scripts inside XSL files. Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files. To supp..."),
    "T1642": ("Disable or Modify Cloud Firewall", "Defense Evasion", "Adversaries may disable or modify cloud firewall rules."),

    # ==================== CREDENTIAL ACCESS ====================
    "T1557": ("Adversary-in-the-Middle", "Credential Access", "Adversaries may attempt to position themselves between two or more networked devices using an adversary-in-the-middle (AiTM) technique to support follow-on behaviors such as [Network Sniffing](https://attack.mitre.org/techniques/T1040), [Transmitt..."),
    "T1557.001": ("LLMNR/NBT-NS Poisoning and SMB Relay", "Credential Access", "By responding to LLMNR/NBT-NS network traffic, adversaries may spoof an authoritative source for name resolution to force communication with an adversary controlled system. This activity may be used to collect or relay authentication materials. Li..."),
    "T1557.002": ("ARP Cache Poisoning", "Credential Access", "Adversaries may poison Address Resolution Protocol (ARP) caches to position themselves between the communication of two or more networked devices. This activity may be used to enable follow-on behaviors such as [Network Sniffing](https://attack.mi..."),
    "T1557.003": ("DHCP Spoofing", "Credential Access", "Adversaries may redirect network traffic to adversary-owned systems by spoofing Dynamic Host Configuration Protocol (DHCP) traffic and acting as a malicious DHCP server on the victim network. By achieving the adversary-in-the-middle (AiTM) positio..."),
    "T1110": ("Brute Force", "Credential Access", "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the p..."),
    "T1110.001": ("Password Guessing", "Credential Access", "Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. Without knowledge of the password for an account, an adversary may opt to systematically guess the pa..."),
    "T1110.002": ("Password Cracking", "Credential Access", "Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained. [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) can be u..."),
    "T1110.003": ("Password Spraying", "Credential Access", "Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials. Password spraying uses one password (e.g. 'Password01'), or a small list of commonly used passwo..."),
    "T1110.004": ("Credential Stuffing", "Credential Access", "Adversaries may use credentials obtained from breach dumps of unrelated accounts to gain access to target accounts through credential overlap. Occasionally, large numbers of username and password pairs are dumped online when a website or service i..."),
    "T1555": ("Credentials from Password Stores", "Credential Access", "Adversaries may search for common password storage locations to obtain user credentials. Passwords are stored in several places on a system, depending on the operating system or application holding the credentials. There are also specific applicat..."),
    "T1555.001": ("Keychain", "Credential Access", "Adversaries may acquire credentials from Keychain. Keychain (or Keychain Services) is the macOS credential management system that stores account names, passwords, private keys, certificates, sensitive application data, payment data, and secure not..."),
    "T1555.002": ("Securityd Memory", "Credential Access", "An adversary with root access may gather credentials by reading `securityd`’s memory. `securityd` is a service/daemon responsible for implementing security protocols such as encryption and authorization. A privileged adversary may be able to scan ..."),
    "T1555.003": ("Credentials from Web Browsers", "Credential Access", "Adversaries may acquire credentials from web browsers by reading files specific to the target browser. Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future. We..."),
    "T1555.004": ("Windows Credential Manager", "Credential Access", "Adversaries may acquire credentials from the Windows Credential Manager. The Credential Manager stores credentials for signing into websites, applications, and/or devices that request authentication through NTLM or Kerberos in Credential Lockers (..."),
    "T1555.005": ("Password Managers", "Credential Access", "Adversaries may acquire user credentials from third-party password managers. Password managers are applications designed to store user credentials, normally in an encrypted database. Credentials are typically accessible after a user provides a mas..."),
    "T1555.006": ("Cloud Secrets Management Stores", "Credential Access", "Adversaries may acquire credentials from cloud-native secret management solutions such as AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and Terraform Vault. Secrets managers support the secure centralized management of passwords, API k..."),
    "T1212": ("Exploitation for Credential Access", "Credential Access", "Adversaries may exploit software vulnerabilities in an attempt to collect credentials. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system s..."),
    "T1187": ("Forced Authentication", "Credential Access", "Adversaries may gather credential material by invoking or forcing a user to automatically provide authentication information through a mechanism in which they can intercept. The Server Message Block (SMB) protocol is commonly used in Windows netwo..."),
    "T1606": ("Forge Web Credentials", "Credential Access", "Adversaries may forge credential materials that can be used to gain access to web applications or Internet services. Web applications and services (hosted in cloud SaaS environments or on-premise servers) often use session cookies, tokens, or othe..."),
    "T1606.001": ("Web Cookies", "Credential Access", "Adversaries may forge web cookies that can be used to gain access to web applications or Internet services. Web applications and services (hosted in cloud SaaS environments or on-premise servers) often use session cookies to authenticate and autho..."),
    "T1606.002": ("SAML Tokens", "Credential Access", "An adversary may forge SAML tokens with any permissions claims and lifetimes if they possess a valid SAML token-signing certificate. The default lifetime of a SAML token is one hour, but the validity period can be specified in the NotOnOrAfter val..."),
    "T1056": ("Input Capture", "Credential Access", "Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal system usage, users often provide credentials to various different locations, such as login pages/portals or system dialog boxes. Input..."),
    "T1056.001": ("Keylogging", "Credential Access", "Adversaries may log user keystrokes to intercept credentials as the user types them. Keylogging is likely to be used to acquire credentials for new access opportunities when [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) effort..."),
    "T1056.002": ("GUI Input Capture", "Credential Access", "Adversaries may mimic common operating system GUI components to prompt users for credentials with a seemingly legitimate prompt. When programs are executed that need additional privileges than are present in the current user context, it is common ..."),
    "T1056.003": ("Web Portal Capture", "Credential Access", "Adversaries may install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. For example, a compromised login page may log provided user credentials before l..."),
    "T1056.004": ("Credential API Hooking", "Credential Access", "Adversaries may hook into Windows application programming interface (API) functions and Linux system functions to collect user credentials. Malicious hooking mechanisms may capture API or function calls that include parameters that reveal user aut..."),
    "T1040": ("Network Sniffing", "Credential Access", "Adversaries may passively sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture inform..."),
    "T1003": ("OS Credential Dumping", "Credential Access", "Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password. Credentials can be obtained from OS caches, memory, or structures. Credentials can then be used t..."),
    "T1003.001": ("LSASS Memory", "Credential Access", "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process ..."),
    "T1003.002": ("Security Account Manager", "Credential Access", "Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through in-memory techniques or through the Windows Registry where the SAM database is stored. The SAM is a database file that contains ..."),
    "T1003.003": ("NTDS", "Credential Access", "Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information, as well as obtain other information about domain members such as devices, users, and access rights. By default, th..."),
    "T1003.004": ("LSA Secrets", "Credential Access", "Adversaries with SYSTEM access to a host may attempt to access Local Security Authority (LSA) secrets, which can contain a variety of different credential materials, such as credentials for service accounts. LSA secrets are stored in the registry ..."),
    "T1003.005": ("Cached Domain Credentials", "Credential Access", "Adversaries may attempt to access cached domain credentials used to allow authentication to occur in the event a domain controller is unavailable. On Windows Vista and newer, the hash format is DCC2 (Domain Cached Credentials version 2) hash, also..."),
    "T1003.006": ("DCSync", "Credential Access", "Adversaries may attempt to access credentials and other sensitive information by abusing a Windows Domain Controller's application programming interface (API) to simulate the replication process from a remote domain controller using a technique ca..."),
    "T1003.007": ("Proc Filesystem", "Credential Access", "Adversaries may gather credentials from the proc filesystem or `/proc`. The proc filesystem is a pseudo-filesystem used as an interface to kernel data structures for Linux based systems managing virtual memory. For each process, the `/proc//maps` ..."),
    "T1003.008": ("/etc/passwd and /etc/shadow", "Credential Access", "Adversaries may attempt to dump the contents of /etc/passwd and /etc/shadow to enable offline password cracking. Most modern Linux operating systems use a combination of /etc/passwd and /etc/shadow to store user account information, including pass..."),
    "T1528": ("Steal Application Access Token", "Credential Access", "Adversaries can steal application access tokens as a means of acquiring credentials to access remote systems and resources. Application access tokens are used to make authorized API requests on behalf of a user or service and are commonly used as ..."),
    "T1649": ("Steal or Forge Authentication Certificates", "Credential Access", "Adversaries may steal or forge certificates used for authentication to access remote systems or resources. Digital certificates are often used to sign and encrypt messages and/or files. Certificates are also used as authentication material. For ex..."),
    "T1558": ("Steal or Forge Kerberos Tickets", "Credential Access", "Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003). Kerberos is an authentication protocol widely used in modern Windows dom..."),
    "T1558.001": ("Golden Ticket", "Credential Access", "Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT), also known as a golden ticket. Golden tickets enable adversaries to generate authentication material for any account in Active Directory. Using..."),
    "T1558.002": ("Silver Ticket", "Credential Access", "Adversaries who have the password hash of a target service account (e.g. SharePoint, MSSQL) may forge Kerberos ticket granting service (TGS) tickets, also known as silver tickets. Kerberos TGS tickets are also known as service tickets. Silver tick..."),
    "T1558.003": ("Kerberoasting", "Credential Access", "Adversaries may abuse a valid Kerberos ticket-granting ticket (TGT) or sniff network traffic to obtain a ticket-granting service (TGS) ticket that may be vulnerable to [Brute Force](https://attack.mitre.org/techniques/T1110). Service principal nam..."),
    "T1558.004": ("AS-REP Roasting", "Credential Access", "Adversaries may reveal credentials of accounts that have disabled Kerberos preauthentication by [Password Cracking](https://attack.mitre.org/techniques/T1110/002) Kerberos messages. Preauthentication offers protection against offline [Password Cra..."),
    "T1539": ("Steal Web Session Cookie", "Credential Access", "An adversary may steal web application or service session cookies and use them to gain access to web applications or Internet services as an authenticated user without needing credentials. Web applications and services often use session cookies as..."),
    "T1111": ("Multi-Factor Authentication Interception", "Credential Access", "Adversaries may target multi-factor authentication (MFA) mechanisms, (i.e., smart cards, token generators, etc.) to gain access to credentials that can be used to access systems, services, and network resources. Use of MFA is recommended and provi..."),
    "T1621": ("Multi-Factor Authentication Request Generation", "Credential Access", "Adversaries may attempt to bypass multi-factor authentication (MFA) mechanisms and gain access to accounts by generating MFA requests sent to users. Adversaries in possession of credentials to [Valid Accounts](https://attack.mitre.org/techniques/T..."),
    "T1552": ("Unsecured Credentials", "Credential Access", "Adversaries may search compromised systems to find and obtain insecurely stored credentials. These credentials can be stored and/or misplaced in many locations on a system, including plaintext files (e.g. [Shell History](https://attack.mitre.org/t..."),
    "T1552.001": ("Credentials In Files", "Credential Access", "Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configura..."),
    "T1552.002": ("Credentials in Registry", "Credential Access", "Adversaries may search the Registry on compromised systems for insecurely stored credentials. The Windows Registry stores configuration information that can be used by the system or other programs. Adversaries may query the Registry looking for cr..."),
    "T1552.003": ("Bash History", "Credential Access", "Adversaries may search the command history on compromised systems for insecurely stored credentials. On Linux and macOS systems, shells such as Bash and Zsh keep track of the commands users type on the command-line with the \"history\" utility. Once a user logs out, the history is flushed to the us..."),
    "T1552.004": ("Private Keys", "Credential Access", "Adversaries may search for private key certificate files on compromised systems for insecurely stored credentials. Private cryptographic keys and certificates are used for authentication, encryption/decryption, and digital signatures. Common key a..."),
    "T1552.005": ("Cloud Instance Metadata API", "Credential Access", "Adversaries may attempt to access the Cloud Instance Metadata API to collect credentials and other sensitive data. Most cloud service providers support a Cloud Instance Metadata API which is a service provided to running virtual instances that all..."),
    "T1552.006": ("Group Policy Preferences", "Credential Access", "Adversaries may attempt to find unsecured credentials in Group Policy Preferences (GPP). GPP are tools that allow administrators to create domain policies with embedded credentials. These policies allow administrators to set local accounts. These ..."),
    "T1552.007": ("Container API", "Credential Access", "Adversaries may gather credentials via APIs within a containers environment. APIs in these environments, such as the Docker API and Kubernetes APIs, allow a user to remotely manage their container resources and cluster components. An adversary may..."),
    "T1552.008": ("Chat Messages", "Credential Access", "Adversaries may directly collect unsecured credentials stored or passed through user communication services. Credentials may be sent and stored in user chat communication applications such as email, chat services like Slack or Teams, collaboration..."),

    # ==================== DISCOVERY ====================
    "T1087": ("Account Discovery", "Discovery", "Adversaries may attempt to get a listing of valid accounts, usernames, or email addresses on a system or within a compromised environment. This information can help adversaries determine which accounts exist, which can aid in follow-on behavior su..."),
    "T1087.001": ("Local Account", "Discovery", "Adversaries may attempt to get a listing of local system accounts. This information can help adversaries determine which local accounts exist on a system to aid in follow-on behavior. Commands such as net user and net localgroup of the [Net](https..."),
    "T1087.002": ("Domain Account", "Discovery", "Adversaries may attempt to get a listing of domain accounts. This information can help adversaries determine which domain accounts exist to aid in follow-on behavior such as targeting specific accounts which possess particular privileges. Commands..."),
    "T1087.003": ("Email Account", "Discovery", "Adversaries may attempt to get a listing of email addresses and accounts. Adversaries may try to dump Exchange address lists such as global address lists (GALs). In on-premises Exchange and Exchange Online, the Get-GlobalAddressList PowerShell cmd..."),
    "T1087.004": ("Cloud Account", "Discovery", "Adversaries may attempt to get a listing of cloud accounts. Cloud accounts are those created and configured by an organization for use by users, remote support, services, or for administration of resources within a cloud service provider or SaaS a..."),
    "T1010": ("Application Window Discovery", "Discovery", "Adversaries may attempt to get a listing of open application windows. Window listings could convey information about how the system is used. For example, information about application windows could be used identify potential data to collect as wel..."),
    "T1217": ("Browser Information Discovery", "Discovery", "Adversaries may enumerate information about browsers to learn more about compromised environments. Data saved by browsers (such as bookmarks, accounts, and browsing history) may reveal a variety of personal information about users (e.g., banking s..."),
    "T1580": ("Cloud Infrastructure Discovery", "Discovery", "An adversary may attempt to discover infrastructure and resources that are available within an infrastructure-as-a-service (IaaS) environment. This includes compute service resources such as instances, virtual machines, and snapshots as well as re..."),
    "T1538": ("Cloud Service Dashboard", "Discovery", "An adversary may use a cloud service dashboard GUI with stolen credentials to gain useful information from an operational cloud environment, such as specific services, resources, and features. For example, the GCP Command Center can be used to vie..."),
    "T1526": ("Cloud Service Discovery", "Discovery", "An adversary may attempt to enumerate the cloud services running on a system after gaining access. These methods can differ from platform-as-a-service (PaaS), to infrastructure-as-a-service (IaaS), or software-as-a-service (SaaS). Many services ex..."),
    "T1613": ("Container and Resource Discovery", "Discovery", "Adversaries may attempt to discover containers and other resources that are available within a containers environment. Other resources may include images, deployments, pods, nodes, and other information such as the status of a cluster. These resou..."),
    "T1652": ("Device Driver Discovery", "Discovery", "Adversaries may attempt to enumerate local device drivers on a victim host. Information about device drivers may highlight various insights that shape follow-on behaviors, such as the function/purpose of the host, present security tools (i.e. [Sec..."),
    "T1482": ("Domain Trust Discovery", "Discovery", "Adversaries may attempt to gather information on domain trust relationships that may be used to identify lateral movement opportunities in Windows multi-domain/forest environments. Domain trusts provide a mechanism for a domain to allow access to ..."),
    "T1083": ("File and Directory Discovery", "Discovery", "Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from [File and Directory Discovery](https://attack.mit..."),
    "T1615": ("Group Policy Discovery", "Discovery", "Adversaries may gather information on Group Policy settings to identify paths for privilege escalation, security measures applied within a domain, and to discover patterns in domain objects that can be manipulated or used to blend in the environme..."),
    "T1654": ("Log Enumeration", "Discovery", "Adversaries may enumerate system and service logs to find useful data. These logs may highlight various types of valuable insights for an adversary, such as user authentication records ([Account Discovery](https://attack.mitre.org/techniques/T1087..."),
    "T1046": ("Network Service Discovery", "Discovery", "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods to acquire this information include port,..."),
    "T1135": ("Network Share Discovery", "Discovery", "Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and to identify potential systems of interest for Lateral Movement. Networks often contai..."),
    "T1201": ("Password Policy Discovery", "Discovery", "Adversaries may attempt to access detailed information about the password policy used within an enterprise network or cloud environment. Password policies are a way to enforce complex passwords that are difficult to guess or crack through [Brute F..."),
    "T1120": ("Peripheral Device Discovery", "Discovery", "Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system. Peripheral devices could include auxiliary resources that support a variety of functionalities such as keyboards, printe..."),
    "T1069": ("Permission Groups Discovery", "Discovery", "Adversaries may attempt to discover group and permission settings. This information can help adversaries determine which user accounts and groups are available, the membership of users in particular groups, and which users and groups have elevated..."),
    "T1069.001": ("Local Groups", "Discovery", "Adversaries may attempt to find local system groups and permission settings. The knowledge of local system permission groups can help adversaries determine which groups exist and which users belong to a particular group. Adversaries may use this i..."),
    "T1069.002": ("Domain Groups", "Discovery", "Adversaries may attempt to find domain-level groups and permission settings. The knowledge of domain-level permission groups can help adversaries determine which groups exist and which users belong to a particular group. Adversaries may use this i..."),
    "T1069.003": ("Cloud Groups", "Discovery", "Adversaries may attempt to find cloud groups and permission settings. The knowledge of cloud permission groups can help adversaries determine the particular roles of users and groups within an environment, as well as which users are associated wit..."),
    "T1057": ("Process Discovery", "Discovery", "Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software/applications running on systems within the network. Administrator or otherwise elevated ..."),
    "T1012": ("Query Registry", "Discovery", "Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software. The Registry contains a significant amount of information about the operating system, configuration, software, and se..."),
    "T1018": ("Remote System Discovery", "Discovery", "Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enab..."),
    "T1518": ("Software Discovery", "Discovery", "Adversaries may attempt to get a listing of software and software versions that are installed on a system or in a cloud environment. Adversaries may use the information from [Software Discovery](https://attack.mitre.org/techniques/T1518) during au..."),
    "T1518.001": ("Security Software Discovery", "Discovery", "Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on a system or in a cloud environment. This may include things such as cloud monitoring agents and anti-virus. Adversari..."),
    "T1082": ("System Information Discovery", "Discovery", "An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. Adversaries may use this information to shape follow-on behaviors, including wheth..."),
    "T1614": ("System Location Discovery", "Discovery", "Adversaries may gather information in an attempt to calculate the geographical location of a victim host. Adversaries may use the information from [System Location Discovery](https://attack.mitre.org/techniques/T1614) during automated discovery to..."),
    "T1614.001": ("System Language Discovery", "Discovery", "Adversaries may attempt to gather information about the system language of a victim in order to infer the geographical location of that host. This information may be used to shape follow-on behaviors, including whether the adversary infects the ta..."),
    "T1016": ("System Network Configuration Discovery", "Discovery", "Adversaries may look for details about the network configuration and settings, such as IP and/or MAC addresses, of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that..."),
    "T1016.001": ("Internet Connection Discovery", "Discovery", "Adversaries may check for Internet connectivity on compromised systems. This may be performed during automated discovery and can be accomplished in numerous ways such as using [Ping](https://attack.mitre.org/software/S0097), tracert, and GET reque..."),
    "T1049": ("System Network Connections Discovery", "Discovery", "Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network. An adversary who gains access to a system that is p..."),
    "T1033": ("System Owner/User Discovery", "Discovery", "Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system. They may do this, for example, by retrieving account usernames or by using [O..."),
    "T1007": ("System Service Discovery", "Discovery", "Adversaries may try to gather information about registered local system services. Adversaries may obtain information about services using tools as well as OS utility commands such as sc query, tasklist /svc, systemctl --type=service, and net start..."),
    "T1124": ("System Time Discovery", "Discovery", "An adversary may gather the system time and/or time zone settings from a local or remote system. The system time is set and stored by services, such as the Windows Time Service on Windows or systemsetup on macOS. These time settings may also be sy..."),
    "T1497": ("Virtualization/Sandbox Evasion", "Discovery", "Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) o..."),

    # ==================== LATERAL MOVEMENT ====================
    "T1210": ("Exploitation of Remote Services", "Lateral Movement", "Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or wi..."),
    "T1534": ("Internal Spearphishing", "Lateral Movement", "After they already have access to accounts or systems within the environment, adversaries may use internal spearphishing to gain access to additional information or compromise other users within the same organization. Internal spearphishing is mul..."),
    "T1570": ("Lateral Tool Transfer", "Lateral Movement", "Adversaries may transfer tools or other files between systems in a compromised environment. Once brought into the victim environment (i.e., [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)) files may then be copied from one syste..."),
    "T1563": ("Remote Service Session Hijacking", "Lateral Movement", "Adversaries may take control of preexisting sessions with remote services to move laterally in an environment. Users may use valid credentials to log into a service specifically designed to accept remote connections, such as telnet, SSH, and RDP. ..."),
    "T1563.001": ("SSH Hijacking", "Lateral Movement", "Adversaries may hijack a legitimate user's SSH session to move laterally within an environment. Secure Shell (SSH) is a standard means of remote access on Linux and macOS systems. It allows a user to connect to another system via an encrypted tunn..."),
    "T1563.002": ("RDP Hijacking", "Lateral Movement", "Adversaries may hijack a legitimate user’s remote desktop session to move laterally within an environment. Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical..."),
    "T1021": ("Remote Services", "Lateral Movement", "Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into a service that accepts remote connections, such as telnet, SSH, and VNC. The adversary may then perform actions as the logged-on user. In an enterprise env..."),
    "T1021.001": ("Remote Desktop Protocol", "Lateral Movement", "Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user. Remote desktop is a common feature in ope..."),
    "T1021.002": ("SMB/Windows Admin Shares", "Lateral Movement", "Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user. SMB is a file, printer, and ser..."),
    "T1021.003": ("Distributed Component Object Model", "Lateral Movement", "Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to interact with remote machines by taking advantage of Distributed Component Object Model (DCOM). The adversary may then perform actions as the logged-on user. The Wi..."),
    "T1021.004": ("SSH", "Lateral Movement", "Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into remote machines using Secure Shell (SSH). The adversary may then perform actions as the logged-on user. SSH is a protocol that allows authorized users to o..."),
    "T1021.005": ("VNC", "Lateral Movement", "Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to remotely control machines using Virtual Network Computing (VNC). VNC is a platform-independent desktop sharing system that uses the RFB (“remote framebuffer”) proto..."),
    "T1021.006": ("Windows Remote Management", "Lateral Movement", "Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to interact with remote systems using Windows Remote Management (WinRM). The adversary may then perform actions as the logged-on user. WinRM is the name of both a Wind..."),
    "T1021.007": ("Cloud Services", "Lateral Movement", "Adversaries may log into accessible cloud services within a compromised environment using [Valid Accounts](https://attack.mitre.org/techniques/T1078) that are synchronized with or federated to on-premises user identities. The adversary may then pe..."),
    "T1021.008": ("Direct Cloud VM Connections", "Lateral Movement", "Adversaries may leverage [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log directly into accessible cloud hosted compute infrastructure through cloud native methods. Many cloud providers offer interactive connections to virtual in..."),
    "T1091": ("Replication Through Removable Media", "Lateral Movement", "Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes. In the case of Lateral ..."),
    "T1072": ("Software Deployment Tools", "Lateral Movement", "Adversaries may gain access to and use centralized software suites installed within an enterprise to execute commands and move laterally through the network. Configuration management and software deployment applications may be used in an enterpris..."),
    "T1080": ("Taint Shared Content", "Lateral Movement", "Adversaries may deliver payloads to remote systems by adding content to shared storage locations, such as network drives or internal code repositories. Content stored on network drives or in other shared locations may be tainted by adding maliciou..."),
    "T1550": ("Use Alternate Authentication Material", "Lateral Movement", "Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls. Authentication processes ge..."),

    # ==================== COLLECTION ====================
    "T1557": ("Adversary-in-the-Middle", "Collection", "Adversaries may attempt to position themselves between two or more networked devices using an adversary-in-the-middle (AiTM) technique to support follow-on behaviors such as [Network Sniffing](https://attack.mitre.org/techniques/T1040), [Transmitt..."),
    "T1560": ("Archive Collected Data", "Collection", "An adversary may compress and/or encrypt data that is collected prior to exfiltration. Compressing the data can help to obfuscate the collected data and minimize the amount of data sent over the network. Encryption can be used to hide information ..."),
    "T1560.001": ("Archive via Utility", "Collection", "Adversaries may use utilities to compress and/or encrypt collected data prior to exfiltration. Many utilities include functionalities to compress, encrypt, or otherwise package data into a format that is easier/more secure to transport. Adversarie..."),
    "T1560.002": ("Archive via Library", "Collection", "An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party libraries. Many libraries exist that can archive data, including [Python](https://attack.mitre.org/techniques/T1059/006) rarfile , libzip , and zlib ..."),
    "T1560.003": ("Archive via Custom Method", "Collection", "An adversary may compress or encrypt data that is collected prior to exfiltration using a custom method. Adversaries may choose to use custom archival methods, such as encryption with XOR or stream ciphers implemented with no external library or u..."),
    "T1123": ("Audio Capture", "Collection", "An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather informa..."),
    "T1119": ("Automated Collection", "Collection", "Once established within a system or network, an adversary may use automated techniques for collecting internal data. Methods for performing this technique could include use of a [Command and Scripting Interpreter](https://attack.mitre.org/techniqu..."),
    "T1185": ("Browser Session Hijacking", "Collection", "Adversaries may take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify user-behaviors, and intercept information as part of various browser session hijacking techniques. A specific examp..."),
    "T1115": ("Clipboard Data", "Collection", "Adversaries may collect data stored in the clipboard from users copying information within or between applications. For example, on Windows adversaries can access clipboard data by using clip.exe or Get-Clipboard. Additionally, adversaries may mon..."),
    "T1530": ("Data from Cloud Storage", "Collection", "Adversaries may access data from cloud storage. Many IaaS providers offer solutions for online data object storage such as Amazon S3, Azure Storage, and Google Cloud Storage. Similarly, SaaS enterprise platforms such as Office 365 and Google Works..."),
    "T1602": ("Data from Configuration Repository", "Collection", "Adversaries may collect data related to managed devices from configuration repositories. Configuration repositories are used by management systems in order to configure, manage, and control data on remote systems. Configuration repositories may al..."),
    "T1602.001": ("SNMP (MIB Dump)", "Collection", "Adversaries may target the Management Information Base (MIB) to collect and/or mine valuable information in a network managed using Simple Network Management Protocol (SNMP). The MIB is a configuration repository that stores variable information a..."),
    "T1602.002": ("Network Device Configuration Dump", "Collection", "Adversaries may access network configuration files to collect sensitive data about the device and the network. The network configuration is a file containing parameters that determine the operation of the device. The device typically stores an in-..."),
    "T1213": ("Data from Information Repositories", "Collection", "Adversaries may leverage information repositories to mine valuable information. Information repositories are tools that allow for storage of information, typically to facilitate collaboration or information sharing between users, and can store a w..."),
    "T1213.001": ("Confluence", "Collection", "Adversaries may leverage Confluence repositories to mine valuable information. Often found in development environments alongside Atlassian JIRA, Confluence is generally used to store development-related documentation, however, in general may conta..."),
    "T1213.002": ("Sharepoint", "Collection", "Adversaries may leverage the SharePoint repository as a source to mine valuable information. SharePoint will often contain useful information for an adversary to learn about the structure and functionality of the internal network and systems. For ..."),
    "T1213.003": ("Code Repositories", "Collection", "Adversaries may leverage code repositories to collect valuable information. Code repositories are tools/services that store source code and automate software builds. They may be hosted internally or privately on third party sites such as Github, G..."),
    "T1005": ("Data from Local System", "Collection", "Adversaries may search local system sources, such as file systems, configuration files, local databases, virtual machine files, or process memory, to find files of interest and sensitive data prior to Exfiltration. Adversaries may do this using a ..."),
    "T1039": ("Data from Network Shared Drive", "Collection", "Adversaries may search network shares on computers they have compromised to find files of interest. Sensitive data can be collected from remote systems via shared network drives (host shared directory, network file server, etc.) that are accessibl..."),
    "T1025": ("Data from Removable Media", "Collection", "Adversaries may search connected removable media on computers they have compromised to find files of interest. Sensitive data can be collected from any removable media (optical disk drive, USB memory, etc.) connected to the compromised system prio..."),
    "T1074": ("Data Staged", "Collection", "Adversaries may stage collected data in a central location or directory prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as [Archive Collected Data](https://attack.mitre.org/techniques/T15..."),
    "T1074.001": ("Local Data Staging", "Collection", "Adversaries may stage collected data in a central location or directory on the local system prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as [Archive Collected Data](https://attack.mitr..."),
    "T1074.002": ("Remote Data Staging", "Collection", "Adversaries may stage data collected from multiple systems in a central location or directory on one system prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as [Archive Collected Data](htt..."),
    "T1114": ("Email Collection", "Collection", "Adversaries may target user email to collect sensitive information. Emails may contain sensitive data, including trade secrets or personal information, that can prove valuable to adversaries. Emails may also contain details of ongoing incident res..."),
    "T1114.001": ("Local Email Collection", "Collection", "Adversaries may target user email on local systems to collect sensitive information. Files containing email data can be acquired from a user’s local system, such as Outlook storage or cache files. Outlook stores data locally in offline data files ..."),
    "T1114.002": ("Remote Email Collection", "Collection", "Adversaries may target an Exchange server, Office 365, or Google Workspace to collect sensitive information. Adversaries may leverage a user's credentials and interact directly with the Exchange server to acquire information from within a network...."),
    "T1114.003": ("Email Forwarding Rule", "Collection", "Adversaries may setup email forwarding rules to collect sensitive information. Adversaries may abuse email forwarding rules to monitor the activities of a victim, steal information, and further gain intelligence on the victim or the victim’s organ..."),
    "T1056": ("Input Capture", "Collection", "Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal system usage, users often provide credentials to various different locations, such as login pages/portals or system dialog boxes. Input..."),
    "T1113": ("Screen Capture", "Collection", "Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations. Taking a ..."),
    "T1125": ("Video Capture", "Collection", "An adversary can leverage a computer's peripheral devices (e.g., integrated cameras or webcams) or applications (e.g., video call services) to capture video recordings for the purpose of gathering information. Images may also be captured from devi..."),

    # ==================== COMMAND AND CONTROL ====================
    "T1071": ("Application Layer Protocol", "Command and Control", "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protoc..."),
    "T1071.001": ("Web Protocols", "Command and Control", "Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be em..."),
    "T1071.002": ("File Transfer Protocols", "Command and Control", "Adversaries may communicate using application layer protocols associated with transferring files to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, wil..."),
    "T1071.003": ("Mail Protocols", "Command and Control", "Adversaries may communicate using application layer protocols associated with electronic mail delivery to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those command..."),
    "T1071.004": ("DNS", "Command and Control", "Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be em..."),
    "T1092": ("Communication Through Removable Media", "Command and Control", "Adversaries can perform command and control between compromised hosts on potentially disconnected networks using removable media to transfer commands from system to system. Both systems would need to be compromised, with the likelihood that an Int..."),
    "T1659": ("Content Injection", "Command and Control", "Adversaries may gain access and continuously communicate with victims by injecting malicious content into systems through online network traffic. Rather than luring victims to malicious payloads hosted on a compromised website (i.e., [Drive-by Tar..."),
    "T1132": ("Data Encoding", "Command and Control", "Adversaries may encode data to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a standard data encoding system. Use of data encoding may adhere to existing protoco..."),
    "T1132.001": ("Standard Encoding", "Command and Control", "Adversaries may encode data with a standard data encoding system to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a standard data encoding system that adheres to..."),
    "T1132.002": ("Non-Standard Encoding", "Command and Control", "Adversaries may encode data with a non-standard data encoding system to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a non-standard data encoding system that di..."),
    "T1001": ("Data Obfuscation", "Command and Control", "Adversaries may obfuscate command and control traffic to make it more difficult to detect. Command and control (C2) communications are hidden (but not necessarily encrypted) in an attempt to make the content more difficult to discover or decipher ..."),
    "T1001.001": ("Junk Data", "Command and Control", "Adversaries may add junk data to protocols used for command and control to make detection more difficult. By adding random or meaningless data to the protocols used for command and control, adversaries can prevent trivial methods for decoding, dec..."),
    "T1001.002": ("Steganography", "Command and Control", "Adversaries may use steganographic techniques to hide command and control traffic to make detection efforts more difficult. Steganographic techniques can be used to hide data in digital messages that are transferred between systems. This hidden in..."),
    "T1001.003": ("Protocol Impersonation", "Command and Control", "Adversaries may impersonate legitimate protocols or web service traffic to disguise command and control activity and thwart analysis efforts. By impersonating legitimate protocols or web services, adversaries can make their command and control tra..."),
    "T1568": ("Dynamic Resolution", "Command and Control", "Adversaries may dynamically establish connections to command and control infrastructure to evade common detections and remediations. This may be achieved by using malware that shares a common algorithm with the infrastructure the adversary uses to..."),
    "T1568.001": ("Fast Flux DNS", "Command and Control", "Adversaries may use Fast Flux DNS to hide a command and control channel behind an array of rapidly changing IP addresses linked to a single domain resolution. This technique uses a fully qualified domain name, with multiple IP addresses assigned t..."),
    "T1568.002": ("Domain Generation Algorithms", "Command and Control", "Adversaries may make use of Domain Generation Algorithms (DGAs) to dynamically identify a destination domain for command and control traffic rather than relying on a list of static IP addresses or domains. This has the advantage of making it much ..."),
    "T1568.003": ("DNS Calculation", "Command and Control", "Adversaries may perform calculations on addresses returned in DNS results to determine which port and IP address to use for command and control, rather than relying on a predetermined port number or the actual returned IP address. A IP and/or port..."),
    "T1573": ("Encrypted Channel", "Command and Control", "Adversaries may employ an encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Despite the use of a secure algorithm, these implementations may be vulnera..."),
    "T1573.001": ("Symmetric Cryptography", "Command and Control", "Adversaries may employ a known symmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Symmetric encryption algorithms use the same key for plainte..."),
    "T1573.002": ("Asymmetric Cryptography", "Command and Control", "Adversaries may employ a known asymmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Asymmetric cryptography, also known as public key cryptogra..."),
    "T1008": ("Fallback Channels", "Command and Control", "Adversaries may use fallback or alternate communication channels if the primary channel is compromised or inaccessible in order to maintain reliable command and control and to avoid data transfer thresholds."),
    "T1105": ("Ingress Tool Transfer", "Command and Control", "Adversaries may transfer tools or other files from an external system into a compromised environment. Tools or files may be copied from an external adversary-controlled system to the victim network through the command and control channel or throug..."),
    "T1104": ("Multi-Stage Channels", "Command and Control", "Adversaries may create multiple stages for command and control that are employed under different conditions or for certain functions. Use of multiple stages may obfuscate the command and control channel to make detection more difficult. Remote acc..."),
    "T1095": ("Non-Application Layer Protocol", "Command and Control", "Adversaries may use an OSI non-application layer protocol for communication between host and C2 server or among infected hosts within a network. The list of possible protocols is extensive. Specific examples include use of network layer protocols,..."),
    "T1571": ("Non-Standard Port", "Command and Control", "Adversaries may communicate using a protocol and port pairing that are typically not associated. For example, HTTPS over port 8088 or port 587 as opposed to the traditional port 443. Adversaries may make changes to the standard port used by a prot..."),
    "T1572": ("Protocol Tunneling", "Command and Control", "Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems. Tunneling involves explicitly encapsulating a protocol..."),
    "T1090": ("Proxy", "Command and Control", "Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable..."),
    "T1090.001": ("Internal Proxy", "Command and Control", "Adversaries may use an internal proxy to direct command and control traffic between two or more systems in a compromised environment. Many tools exist that enable traffic redirection through proxies or port redirection, including [HTRAN](https://a..."),
    "T1090.002": ("External Proxy", "Command and Control", "Adversaries may use an external proxy to act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable traffic redirection through proxies or por..."),
    "T1090.003": ("Multi-hop Proxy", "Command and Control", "Adversaries may chain together multiple proxies to disguise the source of malicious traffic. Typically, a defender will be able to identify the last proxy traffic traversed before it enters their network; the defender may or may not be able to ide..."),
    "T1090.004": ("Domain Fronting", "Command and Control", "Adversaries may take advantage of routing schemes in Content Delivery Networks (CDNs) and other services which host multiple domains to obfuscate the intended destination of HTTPS traffic or traffic tunneled through HTTPS. Domain fronting involves..."),
    "T1219": ("Remote Access Software", "Command and Control", "An adversary may use legitimate remote access tools to establish an interactive command and control channel within a network. Remote access tools create a session between two trusted hosts through a graphical interface, a command line interaction,..."),
    "T1205": ("Traffic Signaling", "Command and Control", "Adversaries may use traffic signaling to hide open ports or other malicious functionality used for persistence or command and control. Traffic signaling involves the use of a magic value or sequence that must be sent to a system to trigger a speci..."),
    "T1102": ("Web Service", "Command and Control", "Adversaries may use an existing, legitimate external Web service as a means for relaying data to/from a compromised system. Popular websites, cloud services, and social media acting as a mechanism for C2 may give a significant amount of cover due ..."),
    "T1102.001": ("Dead Drop Resolver", "Command and Control", "Adversaries may use an existing, legitimate external Web service to host information that points to additional command and control (C2) infrastructure. Adversaries may post content, known as a dead drop resolver, on Web services with embedded (and..."),
    "T1102.002": ("Bidirectional Communication", "Command and Control", "Adversaries may use an existing, legitimate external Web service as a means for sending commands to and receiving output from a compromised system over the Web service channel. Compromised systems may leverage popular websites and social media to ..."),
    "T1102.003": ("One-Way Communication", "Command and Control", "Adversaries may use an existing, legitimate external Web service as a means for sending commands to a compromised system without receiving return output over the Web service channel. Compromised systems may leverage popular websites and social med..."),

    # ==================== EXFILTRATION ====================
    "T1020": ("Automated Exfiltration", "Exfiltration", "Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing after being gathered during Collection. When automated exfiltration is used, other exfiltration techniques likely apply as well to transfer the i..."),
    "T1020.001": ("Traffic Duplication", "Exfiltration", "Adversaries may leverage traffic mirroring in order to automate data exfiltration over compromised infrastructure. Traffic mirroring is a native feature for some devices, often used for network analysis. For example, devices may be configured to f..."),
    "T1030": ("Data Transfer Size Limits", "Exfiltration", "An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds. This approach may be used to avoid triggering network data transfer threshold alerts."),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration", "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. Alternate protocols..."),
    "T1048.001": ("Exfiltration Over Symmetric Encrypted Non-C2 Protocol", "Exfiltration", "Adversaries may steal data by exfiltrating it over a symmetrically encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control..."),
    "T1048.002": ("Exfiltration Over Asymmetric Encrypted Non-C2 Protocol", "Exfiltration", "Adversaries may steal data by exfiltrating it over an asymmetrically encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and contr..."),
    "T1048.003": ("Exfiltration Over Unencrypted Non-C2 Protocol", "Exfiltration", "Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. A..."),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration", "Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications."),
    "T1011": ("Exfiltration Over Other Network Medium", "Exfiltration", "Adversaries may attempt to exfiltrate data over a different network medium than the command and control channel. If the command and control network is a wired Internet connection, the exfiltration may occur, for example, over a WiFi connection, mo..."),
    "T1011.001": ("Exfiltration Over Bluetooth", "Exfiltration", "Adversaries may attempt to exfiltrate data over Bluetooth rather than the command and control channel. If the command and control network is a wired Internet connection, an adversary may opt to exfiltrate data using a Bluetooth communication chann..."),
    "T1052": ("Exfiltration Over Physical Medium", "Exfiltration", "Adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a physical medium or device introduced by a user. Such me..."),
    "T1052.001": ("Exfiltration over USB", "Exfiltration", "Adversaries may attempt to exfiltrate data over a USB connected physical device. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a USB device introduced by a user. The USB device could be used as th..."),
    "T1567": ("Exfiltration Over Web Service", "Exfiltration", "Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel. Popular Web services acting as an exfiltration mechanism may give a significant amount of cover due to the l..."),
    "T1567.001": ("Exfiltration to Code Repository", "Exfiltration", "Adversaries may exfiltrate data to a code repository rather than over their primary command and control channel. Code repositories are often accessible via an API (ex: https://api.github.com). Access to these APIs are often over HTTPS, which gives..."),
    "T1567.002": ("Exfiltration to Cloud Storage", "Exfiltration", "Adversaries may exfiltrate data to a cloud storage service rather than over their primary command and control channel. Cloud storage services allow for the storage, edit, and retrieval of data from a remote cloud storage server over the Internet. ..."),
    "T1567.003": ("Exfiltration to Text Storage Sites", "Exfiltration", "Adversaries may exfiltrate data to text storage sites instead of their primary command and control channel. Text storage sites, such as pastebin[.]com, are commonly used by developers to share code and other information. Text storage sites are oft..."),
    "T1567.004": ("Exfiltration Over Webhook", "Exfiltration", "Adversaries may exfiltrate data to a webhook endpoint rather than over their primary command and control channel. Webhooks are simple mechanisms for allowing a server to push data over HTTP/S to a client without the need for the client to continuo..."),
    "T1029": ("Scheduled Transfer", "Exfiltration", "Adversaries may schedule data exfiltration to be performed only at certain times of day or at certain intervals. This could be done to blend traffic patterns with normal activity or availability. When scheduled exfiltration is used, other exfiltra..."),
    "T1537": ("Transfer Data to Cloud Account", "Exfiltration", "Adversaries may exfiltrate data by transferring the data, including through sharing/syncing and creating backups of cloud environments, to another cloud account they control on the same service. A defender who is monitoring for large transfers to ..."),

    # ==================== IMPACT ====================
    "T1531": ("Account Access Removal", "Impact", "Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users. Accounts may be deleted, locked, or manipulated (ex: changed credentials, revoked permissions for SaaS platforms ..."),
    "T1485": ("Data Destruction", "Impact", "Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources. Data destruction is likely to render stored data irrecoverable by forensic technique..."),
    "T1486": ("Data Encrypted for Impact", "Impact", "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. They can attempt to render stored data inaccessible by encrypting files or data on local and remo..."),
    "T1565": ("Data Manipulation", "Impact", "Adversaries may insert, delete, or manipulate data in order to influence external outcomes or hide activity, thus threatening the integrity of the data. By manipulating data, adversaries may attempt to affect a business process, organizational und..."),
    "T1565.001": ("Stored Data Manipulation", "Impact", "Adversaries may insert, delete, or manipulate data at rest in order to influence external outcomes or hide activity, thus threatening the integrity of the data. By manipulating stored data, adversaries may attempt to affect a business process, org..."),
    "T1565.002": ("Transmitted Data Manipulation", "Impact", "Adversaries may alter data en route to storage or other systems in order to manipulate external outcomes or hide activity, thus threatening the integrity of the data. By manipulating transmitted data, adversaries may attempt to affect a business p..."),
    "T1565.003": ("Runtime Data Manipulation", "Impact", "Adversaries may modify systems in order to manipulate the data as it is accessed and displayed to an end user, thus threatening the integrity of the data. By manipulating runtime data, adversaries may attempt to affect a business process, organiza..."),
    "T1491": ("Defacement", "Impact", "Adversaries may modify visual content available internally or externally to an enterprise network, thus affecting the integrity of the original content. Reasons for [Defacement](https://attack.mitre.org/techniques/T1491) include delivering messagi..."),
    "T1491.001": ("Internal Defacement", "Impact", "An adversary may deface systems internal to an organization in an attempt to intimidate or mislead users, thus discrediting the integrity of the systems. This may take the form of modifications to internal websites or server login messages, or dir..."),
    "T1491.002": ("External Defacement", "Impact", "An adversary may deface systems external to an organization in an attempt to deliver messaging, intimidate, or otherwise mislead an organization or users. [External Defacement](https://attack.mitre.org/techniques/T1491/002) may ultimately cause us..."),
    "T1561": ("Disk Wipe", "Impact", "Adversaries may wipe or corrupt raw disk data on specific systems or in large numbers in a network to interrupt availability to system and network resources. With direct write access to a disk, adversaries may attempt to overwrite portions of disk..."),
    "T1561.001": ("Disk Content Wipe", "Impact", "Adversaries may erase the contents of storage devices on specific systems or in large numbers in a network to interrupt availability to system and network resources. Adversaries may partially or completely overwrite the contents of a storage devic..."),
    "T1561.002": ("Disk Structure Wipe", "Impact", "Adversaries may corrupt or wipe the disk data structures on a hard drive necessary to boot a system; targeting specific critical systems or in large numbers in a network to interrupt availability to system and network resources. Adversaries may at..."),
    "T1499": ("Endpoint Denial of Service", "Impact", "Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users. Endpoint DoS can be performed by exhausting the system resources those services are hosted on or exploiting the system to c..."),
    "T1499.001": ("OS Exhaustion Flood", "Impact", "Adversaries may launch a denial of service (DoS) attack targeting an endpoint's operating system (OS). A system's OS is responsible for managing the finite resources as well as preventing the entire system from being overwhelmed by excessive deman..."),
    "T1499.002": ("Service Exhaustion Flood", "Impact", "Adversaries may target the different network services provided by systems to conduct a denial of service (DoS). Adversaries often target the availability of DNS and web services, however others have been targeted as well. Web server software can b..."),
    "T1499.003": ("Application Exhaustion Flood", "Impact", "Adversaries may target resource intensive features of applications to cause a denial of service (DoS), denying availability to those applications. For example, specific features in web applications may be highly resource intensive. Repeated reques..."),
    "T1499.004": ("Application or System Exploitation", "Impact", "Adversaries may exploit software vulnerabilities that can cause an application or system to crash and deny availability to users. Some systems may automatically restart critical applications and services when crashes occur, but they can likely be ..."),
    "T1657": ("Financial Theft", "Impact", "Adversaries may steal monetary resources from targets through extortion, social engineering, technical theft, or other methods aimed at their own financial gain at the expense of the availability of these resources for victims. Financial theft is ..."),
    "T1495": ("Firmware Corruption", "Impact", "Adversaries may overwrite or corrupt the flash memory contents of system BIOS or other firmware in devices attached to a system in order to render them inoperable or unable to boot, thus denying the availability to use the devices and/or the syste..."),
    "T1490": ("Inhibit System Recovery", "Impact", "Adversaries may delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery. This may deny access to available backups and recovery options. Operating systems may contain features ..."),
    "T1498": ("Network Denial of Service", "Impact", "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users. Network DoS can be performed by exhausting the network bandwidth services rely on. Example resources include speci..."),
    "T1498.001": ("Direct Network Flood", "Impact", "Adversaries may attempt to cause a denial of service (DoS) by directly sending a high-volume of network traffic to a target. This DoS attack may also reduce the availability and functionality of the targeted system(s) and network. [Direct Network ..."),
    "T1498.002": ("Reflection Amplification", "Impact", "Adversaries may attempt to cause a denial of service (DoS) by reflecting a high-volume of network traffic to a target. This type of Network DoS takes advantage of a third-party server intermediary that hosts and will respond to a given spoofed sou..."),
    "T1496": ("Resource Hijacking", "Impact", "Adversaries may leverage the resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability. Resource hijacking may take a number of different forms. For example, adversaries may: * L..."),
    "T1489": ("Service Stop", "Impact", "Adversaries may stop or disable services on a system to render those services unavailable to legitimate users. Stopping critical services or processes can inhibit or stop response to an incident or aid in the adversary's overall objectives to caus..."),
    "T1529": ("System Shutdown/Reboot", "Impact", "Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems. Operating systems may contain commands to initiate a shutdown/reboot of a machine or network device. In some cases, these commands may als..."),
}

# Techniques that belong to multiple tactics (technique_id -> list of tactics)
# Based on MITRE ATT&CK Enterprise Matrix
MULTI_TACTIC_TECHNIQUES = {
    "T1659": ["Initial Access", "Command and Control"],
    "T1078": ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"],
    "T1133": ["Initial Access", "Persistence"],
    "T1091": ["Initial Access", "Lateral Movement"],
    "T1053": ["Execution", "Persistence", "Privilege Escalation"],
    "T1072": ["Execution", "Lateral Movement"],
    "T1569": ["Execution"],
    "T1047": ["Execution"],
    "T1059": ["Execution"],
    "T1106": ["Execution"],
    "T1204": ["Execution"],
    "T1098": ["Persistence", "Privilege Escalation"],
    "T1197": ["Persistence", "Defense Evasion"],
    "T1547": ["Persistence", "Privilege Escalation"],
    "T1037": ["Persistence", "Privilege Escalation"],
    "T1543": ["Persistence", "Privilege Escalation"],
    "T1546": ["Persistence", "Privilege Escalation"],
    "T1574": ["Persistence", "Privilege Escalation", "Defense Evasion"],
    "T1556": ["Persistence", "Credential Access", "Defense Evasion"],
    "T1542": ["Persistence", "Defense Evasion"],
    "T1205": ["Persistence", "Defense Evasion", "Command and Control"],
    "T1548": ["Privilege Escalation", "Defense Evasion"],
    "T1134": ["Privilege Escalation", "Defense Evasion"],
    "T1484": ["Privilege Escalation", "Defense Evasion"],
    "T1055": ["Privilege Escalation", "Defense Evasion"],
    "T1610": ["Execution", "Defense Evasion"],
    "T1622": ["Discovery", "Defense Evasion"],
    "T1564": ["Defense Evasion"],
    "T1562": ["Defense Evasion"],
    "T1070": ["Defense Evasion"],
    "T1036": ["Defense Evasion"],
    "T1027": ["Defense Evasion"],
    "T1218": ["Defense Evasion"],
    "T1216": ["Defense Evasion"],
    "T1553": ["Defense Evasion"],
    "T1550": ["Lateral Movement", "Defense Evasion"],
    "T1497": ["Discovery", "Defense Evasion"],
    "T1040": ["Discovery", "Credential Access"],
    "T1056": ["Collection", "Credential Access"],
    "T1557": ["Collection", "Credential Access"],
    "T1114": ["Collection"],
    "T1560": ["Collection"],
    "T1071": ["Command and Control"],
    "T1105": ["Command and Control"],
    "T1090": ["Command and Control"],
    "T1573": ["Command and Control"],
    "T1132": ["Command and Control"],
    "T1001": ["Command and Control"],
    "T1568": ["Command and Control"],
    "T1008": ["Command and Control"],
    "T1102": ["Command and Control"],
    "T1219": ["Command and Control"],
    "T1048": ["Exfiltration"],
    "T1041": ["Exfiltration"],
    "T1567": ["Exfiltration"],
    "T1020": ["Exfiltration"],
    "T1030": ["Exfiltration"],
    "T1486": ["Impact"],
    "T1485": ["Impact"],
    "T1490": ["Impact"],
    "T1491": ["Impact"],
    "T1561": ["Impact"],
    "T1499": ["Impact"],
}


def generate_technique_xml(technique_id, name, tactics, description):
    """Generate XML dashboard for a specific technique.

    Args:
        technique_id: The technique ID (e.g., T1659)
        name: The technique name
        tactics: Either a string (single tactic) or list of tactics
        description: The technique description
    """
    tid_lower = technique_id.lower().replace(".", "_")

    # Handle both string and list for tactics
    if isinstance(tactics, str):
        tactics_list = [tactics]
    else:
        tactics_list = tactics

    # Tactic colors - gradient from light blue (Reconnaissance) to dark red (Impact)
    # Based on MITRE ATT&CK kill chain order
    TACTIC_COLORS = {
        "Reconnaissance": "#64B5F6",        # Light blue
        "Resource Development": "#4FC3F7",  # Cyan
        "Initial Access": "#4DD0E1",        # Teal
        "Execution": "#4DB6AC",             # Green-teal
        "Persistence": "#81C784",           # Green
        "Privilege Escalation": "#AED581",  # Light green
        "Defense Evasion": "#DCE775",       # Yellow-green
        "Credential Access": "#FFF176",     # Yellow
        "Discovery": "#FFD54F",             # Amber
        "Lateral Movement": "#FFB74D",      # Orange
        "Collection": "#FF8A65",            # Deep orange
        "Command and Control": "#E57373",   # Red
        "Exfiltration": "#C62828",          # Dark red
        "Impact": "#8B0000",                # Darkest red
    }

    # Generate tactic badges HTML with colors
    tactic_badges = ' '.join(
        f'<span class="tactic-badge" style="background: {TACTIC_COLORS.get(t, "#26a69a")};">{t}</span>'
        for t in tactics_list
    )

    return f'''<form version="1.1" stylesheet="mitre.css" theme="dark">
  <label>{technique_id} - {name}</label>
  <description>{description}</description>
  <search id="base">
    <query>index=* host=* | dedup index host | table index host</query>
    <earliest>$time_tok.earliest$</earliest>
    <latest>$time_tok.latest$</latest>
  </search>
  <search id="technique_base">
    <query>index=$case_tok$ host=$host_tok$ mitre_technique_id="{technique_id}*"</query>
    <earliest>$time_tok.earliest$</earliest>
    <latest>$time_tok.latest$</latest>
  </search>
  <fieldset submitButton="true" autoRun="true">
    <input type="dropdown" token="case_tok" searchWhenChanged="false">
      <label>Case:</label>
      <choice value="*">All</choice>
      <default>*</default>
      <initialValue>*</initialValue>
      <fieldForLabel>index</fieldForLabel>
      <fieldForValue>index</fieldForValue>
      <search base="base">
        <query>| search host=$host_tok$ | dedup index | sort index</query>
      </search>
      <prefix>"</prefix>
      <suffix>"</suffix>
    </input>
    <input type="dropdown" token="host_tok" searchWhenChanged="false">
      <label>Host:</label>
      <choice value="*">All</choice>
      <default>*</default>
      <initialValue>*</initialValue>
      <fieldForLabel>host</fieldForLabel>
      <fieldForValue>host</fieldForValue>
      <search base="base">
        <query>| search index=$case_tok$ | dedup host | sort host</query>
      </search>
      <prefix>"</prefix>
      <suffix>"</suffix>
    </input>
    <input type="time" token="time_tok" searchWhenChanged="false">
      <label>Time Range:</label>
      <default>
        <earliest>0</earliest>
        <latest></latest>
      </default>
    </input>
    <html>
      <div class="tactic-badges">
        {tactic_badges}
      </div>
    </html>
  </fieldset>
  <row>
    <panel>
      <title>Sub-techniques Count</title>
      <single>
        <search>
          <query>| inputlookup mitre.csv | search id="{technique_id}*" | stats count</query>
        </search>
        <option name="colorBy">value</option>
        <option name="colorMode">block</option>
        <option name="drilldown">none</option>
        <option name="height">80</option>
        <option name="rangeColors">["0x53a051","0x0877a6","0xf8be34","0xf1813f","0xdc4e41"]</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    <panel>
      <title>Events Detected</title>
      <single>
        <search base="technique_base">
          <query>| stats count</query>
        </search>
        <option name="colorBy">value</option>
        <option name="colorMode">block</option>
        <option name="drilldown">none</option>
        <option name="height">80</option>
        <option name="rangeColors">["0x555555","0x6db7c6","0x65a637"]</option>
        <option name="rangeValues">[0,1]</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    <panel>
      <title>Unique Hosts</title>
      <single>
        <search base="technique_base">
          <query>| stats dc(host) AS hosts</query>
        </search>
        <option name="colorBy">value</option>
        <option name="colorMode">block</option>
        <option name="drilldown">none</option>
        <option name="height">80</option>
        <option name="rangeColors">["0x555555","0xf8be34","0xdc4e41"]</option>
        <option name="rangeValues">[0,1]</option>
        <option name="useColors">1</option>
      </single>
    </panel>
  </row>
  <row>
    <panel>
      <title>Events Timeline</title>
      <chart>
        <search base="technique_base">
          <query>| timechart count BY mitre_technique_name</query>
        </search>
        <option name="charting.chart">area</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.drilldown">none</option>
        <option name="charting.legend.placement">bottom</option>
        <option name="charting.chart.nullValueMode">zero</option>
        <option name="height">250</option>
        <option name="refresh.display">progressbar</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>Sub-Techniques Distribution</title>
      <chart>
        <search base="technique_base">
          <query>| stats count BY mitre_technique_id | sort -count | head 20</query>
        </search>
        <option name="charting.chart">pie</option>
        <option name="charting.drilldown">none</option>
        <option name="height">300</option>
        <option name="refresh.display">progressbar</option>
      </chart>
    </panel>
    <panel>
      <title>Affected Hosts</title>
      <chart>
        <search base="technique_base">
          <query>| stats count BY host | sort -count | head 20</query>
        </search>
        <option name="charting.chart">bar</option>
        <option name="charting.drilldown">none</option>
        <option name="height">300</option>
        <option name="refresh.display">progressbar</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>Event Details</title>
      <table>
        <search base="technique_base">
          <query>| `convert_time` | table Time index host mitre_technique_id mitre_technique_name logtype source | sort -Time | rename Time AS "Time" index AS "Case" host AS "Host" mitre_technique_id AS "Technique ID" mitre_technique_name AS "Technique" logtype AS "Log Type" source AS "Source"</query>
        </search>
        <option name="count">20</option>
        <option name="drilldown">cell</option>
        <option name="refresh.display">progressbar</option>
        <option name="wrap">false</option>
        <drilldown>
          <link target="_blank">/app/elrond/search?q=search%20index%3D$row.Case$%20host%3D$row.Host$%20mitre_technique_id%3D"$row.Technique ID$"</link>
        </drilldown>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>MITRE ATT&amp;CK Reference</title>
      <table>
        <search>
          <query>| inputlookup mitre.csv | search id="{technique_id}*" | table id name tactic platform procedure_example detection | rename id AS "ID" name AS "Name" tactic AS "Tactic" platform AS "Platform" procedure_example AS "Threat Groups" detection AS "Detection"</query>
        </search>
        <option name="count">10</option>
        <option name="drilldown">none</option>
        <option name="refresh.display">progressbar</option>
        <option name="wrap">true</option>
      </table>
    </panel>
  </row>
</form>'''


def create_all_technique_xmls(views_dir):
    """Generate all technique XML files in the specified directory."""
    import os
    count = 0

    # Build a merged technique dictionary with all tactics
    merged_techniques = {}
    for tid, (name, tactic, description) in TECHNIQUES.items():
        # Get base technique ID (without sub-technique suffix)
        base_tid = tid.split('.')[0]

        # Check if this technique has multiple tactics defined
        if tid in MULTI_TACTIC_TECHNIQUES:
            tactics = MULTI_TACTIC_TECHNIQUES[tid]
        elif base_tid in MULTI_TACTIC_TECHNIQUES:
            # Sub-technique inherits parent's tactics
            tactics = MULTI_TACTIC_TECHNIQUES[base_tid]
        else:
            tactics = [tactic]

        merged_techniques[tid] = (name, tactics, description)

    for tid, (name, tactics, description) in merged_techniques.items():
        xml_content = generate_technique_xml(tid, name, tactics, description)
        # Replace dots with underscores for sub-technique filenames
        filename = os.path.join(views_dir, f"{tid.lower().replace('.', '_')}.xml")
        with open(filename, 'w') as f:
            f.write(xml_content)
        count += 1
    return count


# Tactic-based generation functions for backwards compatibility
def create_initial_access_xml(sd):
    """Generate Initial Access technique XMLs."""
    techniques = {k: v for k, v in TECHNIQUES.items() if v[1] == "Initial Access"}
    for tid, (name, tactic, description) in techniques.items():
        xml_content = generate_technique_xml(tid, name, tactic, description)
        with open(f"{sd}{tid.lower().replace('.', '_')}.xml", 'w') as f:
            f.write(xml_content)


def create_execution_xml(sd):
    """Generate Execution technique XMLs."""
    techniques = {k: v for k, v in TECHNIQUES.items() if v[1] == "Execution"}
    for tid, (name, tactic, description) in techniques.items():
        xml_content = generate_technique_xml(tid, name, tactic, description)
        with open(f"{sd}{tid.lower().replace('.', '_')}.xml", 'w') as f:
            f.write(xml_content)


def create_persistence_xml(sd):
    """Generate Persistence technique XMLs."""
    techniques = {k: v for k, v in TECHNIQUES.items() if v[1] == "Persistence"}
    for tid, (name, tactic, description) in techniques.items():
        xml_content = generate_technique_xml(tid, name, tactic, description)
        with open(f"{sd}{tid.lower().replace('.', '_')}.xml", 'w') as f:
            f.write(xml_content)


def create_privilege_escalation_xml(sd):
    """Generate Privilege Escalation technique XMLs."""
    techniques = {k: v for k, v in TECHNIQUES.items() if v[1] == "Privilege Escalation"}
    for tid, (name, tactic, description) in techniques.items():
        xml_content = generate_technique_xml(tid, name, tactic, description)
        with open(f"{sd}{tid.lower().replace('.', '_')}.xml", 'w') as f:
            f.write(xml_content)


def create_defense_evasion_xml(sd):
    """Generate Defense Evasion technique XMLs."""
    techniques = {k: v for k, v in TECHNIQUES.items() if v[1] == "Defense Evasion"}
    for tid, (name, tactic, description) in techniques.items():
        xml_content = generate_technique_xml(tid, name, tactic, description)
        with open(f"{sd}{tid.lower().replace('.', '_')}.xml", 'w') as f:
            f.write(xml_content)


def create_credential_access_xml(sd):
    """Generate Credential Access technique XMLs."""
    techniques = {k: v for k, v in TECHNIQUES.items() if v[1] == "Credential Access"}
    for tid, (name, tactic, description) in techniques.items():
        xml_content = generate_technique_xml(tid, name, tactic, description)
        with open(f"{sd}{tid.lower().replace('.', '_')}.xml", 'w') as f:
            f.write(xml_content)


def create_discovery_xml(sd):
    """Generate Discovery technique XMLs."""
    techniques = {k: v for k, v in TECHNIQUES.items() if v[1] == "Discovery"}
    for tid, (name, tactic, description) in techniques.items():
        xml_content = generate_technique_xml(tid, name, tactic, description)
        with open(f"{sd}{tid.lower().replace('.', '_')}.xml", 'w') as f:
            f.write(xml_content)


def create_lateral_movement_xml(sd):
    """Generate Lateral Movement technique XMLs."""
    techniques = {k: v for k, v in TECHNIQUES.items() if v[1] == "Lateral Movement"}
    for tid, (name, tactic, description) in techniques.items():
        xml_content = generate_technique_xml(tid, name, tactic, description)
        with open(f"{sd}{tid.lower().replace('.', '_')}.xml", 'w') as f:
            f.write(xml_content)


def create_collection_xml(sd):
    """Generate Collection technique XMLs."""
    techniques = {k: v for k, v in TECHNIQUES.items() if v[1] == "Collection"}
    for tid, (name, tactic, description) in techniques.items():
        xml_content = generate_technique_xml(tid, name, tactic, description)
        with open(f"{sd}{tid.lower().replace('.', '_')}.xml", 'w') as f:
            f.write(xml_content)


def create_command_and_control_xml(sd):
    """Generate Command and Control technique XMLs."""
    techniques = {k: v for k, v in TECHNIQUES.items() if v[1] == "Command and Control"}
    for tid, (name, tactic, description) in techniques.items():
        xml_content = generate_technique_xml(tid, name, tactic, description)
        with open(f"{sd}{tid.lower().replace('.', '_')}.xml", 'w') as f:
            f.write(xml_content)


def create_exfiltration_xml(sd):
    """Generate Exfiltration technique XMLs."""
    techniques = {k: v for k, v in TECHNIQUES.items() if v[1] == "Exfiltration"}
    for tid, (name, tactic, description) in techniques.items():
        xml_content = generate_technique_xml(tid, name, tactic, description)
        with open(f"{sd}{tid.lower().replace('.', '_')}.xml", 'w') as f:
            f.write(xml_content)


def create_impact_xml(sd):
    """Generate Impact technique XMLs."""
    techniques = {k: v for k, v in TECHNIQUES.items() if v[1] == "Impact"}
    for tid, (name, tactic, description) in techniques.items():
        xml_content = generate_technique_xml(tid, name, tactic, description)
        with open(f"{sd}{tid.lower().replace('.', '_')}.xml", 'w') as f:
            f.write(xml_content)


def create_reconnaissance_xml(sd):
    """Generate Reconnaissance technique XMLs."""
    techniques = {k: v for k, v in TECHNIQUES.items() if v[1] == "Reconnaissance"}
    for tid, (name, tactic, description) in techniques.items():
        xml_content = generate_technique_xml(tid, name, tactic, description)
        with open(f"{sd}{tid.lower().replace('.', '_')}.xml", 'w') as f:
            f.write(xml_content)


def create_resource_development_xml(sd):
    """Generate Resource Development technique XMLs."""
    techniques = {k: v for k, v in TECHNIQUES.items() if v[1] == "Resource Development"}
    for tid, (name, tactic, description) in techniques.items():
        xml_content = generate_technique_xml(tid, name, tactic, description)
        with open(f"{sd}{tid.lower().replace('.', '_')}.xml", 'w') as f:
            f.write(xml_content)


if __name__ == "__main__":
    # Test generation
    import sys
    if len(sys.argv) > 1:
        output_dir = sys.argv[1]
    else:
        output_dir = "."

    count = create_all_technique_xmls(output_dir)
    print(f"Generated {count} technique dashboards")

    # Print technique counts by tactic
    tactics = {}
    for tid, (name, tactic, desc) in TECHNIQUES.items():
        tactics[tactic] = tactics.get(tactic, 0) + 1

    print("\nTechniques by tactic:")
    for tactic, count in sorted(tactics.items()):
        print(f"  {tactic}: {count}")
