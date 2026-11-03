# How Rivendell compares

Rivendell sits among a well-established set of DFIR tools, free and commercial. This page compares what each does, says where Rivendell is strong and where it isn't, and lists what nothing else does in the same way. It was written in October 2026 from each project's public documentation, release notes and published prices; vendors ship often, so if a row is out of date, open an issue and it'll be corrected.

**Legend:** ✓ built in · ◐ partial, an add-on, or one platform only · — not offered, or not found in the public documentation

## Free and open-source tools

| | Rivendell | Velociraptor | Autopsy | KAPE + EZ Tools | Plaso + Timesketch | Dissect |
|---|---|---|---|---|---|---|
| Remote collection | ✓ Windows, Linux, macOS; agentless (SSH, PowerShell remoting) | ✓ agent-based, fleet scale | — | ◐ Windows | — | ◐ `acquire` |
| Disk images (E01, raw, VMDK) | ✓ | ✓ raw and E01 | ✓ | ✓ mounted | ✓ | ✓ |
| Memory analysis | ✓ Volatility 3 | ◐ collection | ◐ Volatility module | — | — | — |
| Super-timeline | ✓ Plaso | ◐ | ✓ | ◐ CSV | ✓ | ◐ |
| ATT&CK mapping of findings | ✓ 600+ techniques, Navigator layer | ◐ built-in Sigma rules | — | — | ◐ Sigma analyser | — |
| Stacking across hosts | ✓ with a reason per row | ✓ hunts | — | — | — | — |
| Threat intelligence matching | ✓ STIX 2.1, TAXII 2.1, MITRESaw, watchlists | ◐ IOC and YARA hunts | ◐ hash sets | — | ◐ analysers | ◐ YARA |
| Containers and Kubernetes | ✓ Docker, static pods, audit logs | ◐ | — | — | ◐ Docker logs | ✓ Docker containers as targets |
| Cloud | ◐ CloudTrail, Azure Activity, GCP Logging, EKS/AKS/GKE audit | — | — | — | ◐ CloudTrail, Azure Activity, GCP logs | — |
| AI analyst | ✓ local model (Ollama), and fixed answers without one | — | — | — | ◐ agentic features announced (Sec-Gemini) | — |
| Several analysts on one case | ✓ findings, notes, host assignment, sharing, SSO | ✓ notebooks | ✓ multi-user cases | — | ✓ | — |
| SIEM export | ✓ Splunk, Elasticsearch | ✓ | — | — | — | ◐ `rdump` to Splunk |
| Mobile devices | — | — | ◐ Android and iOS extractions (ALEAPP, iLEAPP) | — | ◐ some parsers | — |
| File system and file viewer | ◐ case tables, no hex or file viewer | ✓ VFS | ✓ | ◐ Explorer tools | ◐ timeline only | ◐ shell |
| Licence | MIT | AGPL-3.0 | Apache 2.0 | KAPE: free for non-commercial use only, enterprise licence for client or business work; EZ Tools: free | Apache 2.0 | AGPL-3.0 |

Hayabusa and Chainsaw aren't in the table because they do one job, Windows event logs against Sigma rules, and do it very well. They sit beside any of these tools rather than competing with them.

## Commercial tools

| | Rivendell | Binalyze AIR | Cyber Triage | Magnet AXIOM Cyber | Belkasoft X Corporate | X-Ways Forensics |
|---|---|---|---|---|---|---|
| Remote collection | ✓ agentless | ✓ agent; Windows, Linux, macOS, ESXi, ChromeOS | ◐ Windows-focused | ✓ agent | ✓ Belkasoft R | ◐ with F-Response |
| Disk images | ✓ | ◐ | ✓ | ✓ | ✓ | ✓ |
| Memory analysis | ✓ | ◐ acquisition | ✓ Windows | ✓ | ✓ | ◐ |
| Super-timeline | ✓ | ✓ multi-user | ✓ | ✓ | ✓ | ✓ |
| ATT&CK mapping of findings | ✓ | ✓ ATT&CK Analyzer | ✓ with Navigator export | ✓ Sigma rules, Windows and Linux | ◐ Sigma rules on event logs | — |
| Stacking or baselining | ✓ | ◐ | ✓ baselining | — | — | — |
| Threat intelligence matching | ✓ | ◐ YARA, Sigma, IOCs | ◐ reputation lookups | ◐ hash sets, YARA | ◐ hash sets | ◐ hash sets |
| Containers and Kubernetes | ✓ | — | — | — | — | — |
| Cloud | ◐ | ✓ | — | ✓ AWS, Azure, Microsoft 365, Slack, Teams | ◐ cloud accounts | — |
| AI analyst | ✓ local | — | — | ✓ Magnet.AI, Copilot | ✓ BelkaGPT, offline | — |
| Several analysts on one case | ✓ | ✓ | ✓ team edition | ◐ | ◐ | ◐ |
| SIEM export | ✓ | ✓ integrations | — | — | — | — |
| Mobile devices | — | — | — | ✓ | ✓ | ◐ |
| File system and file viewer | ◐ | ◐ | ✓ | ✓ | ✓ | ✓ |
| Court track record and validation | — | ◐ | ◐ | ✓ | ✓ | ✓ |
| Vendor support and training | — community | ✓ | ✓ | ✓ | ✓ | ✓ |
| Price | Free | Quote, per endpoint | Lite free; paid from about $3,500 a year per investigator | Quote | Quote | About $4,000 perpetual, or a yearly licence |

Prices are the vendors' own where published; check with them before relying on a figure.

## Where Rivendell stands

Rivendell is an automation platform rather than a viewer. Point it at a host, a disk or memory image, a Gandalf collection or a set of cloud logs, and it runs the whole chain: collect, verify, parse with 30+ tools, map to ATT&CK, stack across hosts, match against threat intelligence, and hand the result to an analyst, a team or a SIEM. The closest commercial equivalents are Binalyze AIR and Cyber Triage; the closest free one is Velociraptor feeding Plaso and Timesketch, which takes three tools and the glue between them to cover the same ground.

It isn't a replacement for a forensic suite when the job is reviewing one device in depth: there's no hex or file viewer, no carving review, and no mobile support. Nor is it a fleet-scale hunting agent like Velociraptor or AIR; Gandalf collects host by host. It has no court track record or third-party validation yet, it's maintained by one person, and it wants 16 GB of RAM to run comfortably. The cloud modules have had less lab time than the host analysis.

## What sets it apart

**One free, self-hosted pipeline from collection to report.** Acquisition, analysis, ATT&CK mapping, threat intelligence, stacking, collaboration and an AI analyst in one install, under MIT. The commercial tools that cover this much are quoted per endpoint or per investigator.

**Evidence never leaves the building.** Eru runs on a local model through Ollama, and answers its fixed questions straight from the case files when there's no model at all. Nothing is sent to a hosted AI service, which matters for air-gapped labs and for evidence under legal hold.

**Attribution that says how sure it is.** Pippin ranks threat groups by what matched and labels the basis of each: atomic indicators, specific procedures, common tooling, or technique overlap only. Elements dozens of groups share are marked common, and built-in commands never match, so a shared PowerShell switch never reads like attribution.

**Stacking that explains itself.** Rare processes, services, tasks, autoruns, WMI consumers and kernel modules across hosts, each row with its reasons. Hosts are compared only with the same operating system, Linux hosts only with the same distribution family, nothing counts as rare on fewer than three, and at equal score persistence ranks above programs.

**Containers and Kubernetes from the disk.** Container configurations, the writable layer (listed and hashed, its executables copied), static pods and the API server's audit log, from a disk image or a collection, mapped to the container techniques such as **T1611** and **T1609**. Dissect also opens a disk image's Docker containers as evidence of their own; none of the tools above documents reading Kubernetes static pods or the audit log from dead-box evidence, or mapping either to ATT&CK.

**Integrity checked at both ends.** Gandalf collects in order of volatility and hashes everything with SHA-256 into `log.meta`; Elrond re-checks every hash on arrival before it parses anything.

**Measured against ground truth.** The test lab plants known artefacts on Windows, Linux and macOS targets and checks each case against what was planted, and the Mordor datasets carry recorded attack telemetry. Detection quality is a number, not a claim.

## Using it alongside other tools

Rivendell's output is CSV and JSON per artefact, a Plaso timeline, an ATT&CK Navigator layer, and Splunk or Elasticsearch indices. A suite such as AXIOM or X-Ways can take the same image for in-depth review of one device; Timesketch can take the Plaso timeline; and Hayabusa or Chainsaw can run over the same event logs for a second opinion from Sigma.
