#!/usr/bin/env python3 -tt
import glob
import os
from datetime import datetime
from typing import List, Optional

from rowanholt.audit import write_audit_log_entry
from rowanholt.post.siem import memory_outputs, siem_hosts

# Every table Rowanholt writes is JSON Lines with the same envelope (docs/OUTPUT_FORMAT.md), so
# one sourcetype takes them all
SOURCETYPE = "rowanholt_jsonl"
TABLES = r"\.jsonl$"

# TIME_FORMAT is left unset: the envelope's timestamp is ISO 8601 UTC with or without a fraction
# (2026-10-29T14:03:11Z, 2026-10-29T14:03:11.25Z), which Splunk recognises by itself, where one
# strptime format would miss whichever shape it didn't name. MAX_DAYS_AGO and _HENCE are at
# Splunk's limits: evidence years old would otherwise be refused its own time.
# TRUNCATE = 0: a nested event log record is longer than the default 10,000 bytes, and a cut
# record isn't JSON any more.
PROPS = (
    "[" + SOURCETYPE + "]\n"
    "INDEXED_EXTRACTIONS = json\n"
    "KV_MODE = none\n"
    "AUTO_KV_JSON = false\n"
    "SHOULD_LINEMERGE = false\n"
    "LINE_BREAKER = ([\\r\\n]+)\n"
    "TRUNCATE = 0\n"
    "TIMESTAMP_FIELDS = timestamp\n"
    "TZ = UTC\n"
    "MAX_DAYS_AGO = 10951\n"
    "MAX_DAYS_HENCE = 10950\n"
    "NO_BINARY_CHECK = true\n"
    "TRANSFORMS-rowanholt_time = rowanholt_time\n"
    "{reports}\n"
    "category = Structured\n"
    "description = Rowanholt's tables: JSON Lines, one record per line, envelope first\n"
    "disabled = false\n"
    "pulldown_type = true\n\n"
)

# A record with no time (timestamp null: startup items, sudoers, hosts) would otherwise take the
# time of the record before it in the same file; it's given the time it was indexed instead, and
# time_source says which, so a timeline can leave those records out. The envelope is written
# first and in order, so null followed by the techniques list is the envelope's own timestamp.
TIME_TRANSFORM = (
    "[rowanholt_time]\n"
    "INGEST_EVAL = time_source=if(match(_raw, \"\\\"timestamp\\\": null, \\\"techniques\\\": [[]\"), "
    "\"indexed\", \"record\"), _time=if(time_source==\"indexed\", time(), _time)\n\n"
)

# logtype comes from the envelope's artefact (evt/Security, registry/SYSTEM, logs/syslog) rather
# than the source path, where the case's or host's own folder names (a "log" or "memory" in
# them) matched first. Records with no artefact (an older case's memory output, the audit log)
# are named from the source; an artefact the list doesn't name is its own logtype.
LOGTYPE_TRANSFORM = (
    "[logtype_make]\n"
    "REGEX = (?<logtype>(?:registry|evt|shimcache|jumplists|usb|log|plist|service|journal|browser|analysis|timeline|memory|audit))\n"
    "SOURCE_KEY = artefact\n\n"
)
LOGTYPE_EVAL = (
    "EVAL-logtype = case(match(source, \"/analysis/\"), \"analysis\", isnotnull(logtype), logtype, "
    "match(source, \"memory_\"), \"memory\", match(source, \"audit\"), \"audit\", true(), artefact)"
)


INPUTS_HEADER = "\n# Auto-generated inputs for case: {}\n"


def monitor_stanza(path: str, host: str, index: str, sourcetype: str, whitelist: Optional[str] = None,
                   salt: str = "") -> str:
    """One inputs.conf monitor stanza; a directory with a whitelist is monitored recursively.
    Splunk knows a file it has read by its path (crcSalt <SOURCE>); a new ``salt`` has it read the
    files again, into a replaced index."""
    lines = [f"[monitor://{path}]", "disabled = false", f"crcSalt = <SOURCE>{salt}", f"host = {host}",
             f"sourcetype = {sourcetype}", f"index = {index}"]
    if whitelist:
        lines.append(f"whitelist = {whitelist}")
    return "\n".join(lines) + "\n\n"


def drop_case_inputs(inputs: str, case: str) -> str:
    """inputs.conf without the blocks an earlier run wrote for ``case`` (each run appends its own)."""
    header = INPUTS_HEADER.format(case)
    while header in inputs:
        start = inputs.index(header)
        following = inputs.find("\n# Auto-generated inputs for case: ", start + len(header))
        inputs = inputs[:start] + (inputs[following:] if following >= 0 else "")
    return inputs


def host_monitors(host_dir: str, host: str, index: str, salt: str = "") -> List[str]:
    """The monitors for one host's tables: artefacts/cooked/ and analysis/ recursively for every
    .jsonl (so each artefact is indexed, not only those named one by one), the Plaso timeline,
    and Volatility's memory_* output beside artefacts/ (.jsonl, or an older case's .json).

    host is the host's own name, which is also every record's host field.
    """
    host_dir = host_dir.rstrip("/")
    stanzas = []
    for folder in ("artefacts/cooked", "analysis"):
        if os.path.isdir(f"{host_dir}/{folder}"):
            stanzas.append(monitor_stanza(f"{host_dir}/{folder}", host, index, SOURCETYPE, TABLES, salt=salt))
    if os.path.isfile(f"{host_dir}/artefacts/plaso_timeline.jsonl"):
        stanzas.append(monitor_stanza(f"{host_dir}/artefacts/plaso_timeline.jsonl", host, index, SOURCETYPE, salt=salt))
    memory = memory_outputs(host_dir)
    if any(path.endswith(".jsonl") for path in memory):
        stanzas.append(monitor_stanza(f"{host_dir}/memory_*.jsonl", host, index, SOURCETYPE, salt=salt))
    elif memory:
        stanzas.append(monitor_stanza(f"{host_dir}/memory_*.json", host, index, "json", salt=salt))
    if glob.glob(f"{host_dir}/artefacts/cooked/memory/*.json"):
        stanzas.append(monitor_stanza(f"{host_dir}/artefacts/cooked/memory/*.json", host, index, "json", salt=salt))
    return stanzas


def indexed_tables(host_dir: str) -> List[str]:
    """What host_monitors will index for a host, relative to its folder, for the audit log."""
    host_dir = host_dir.rstrip("/")
    found = []
    for folder in ("artefacts/cooked", "analysis"):
        for root, dirs, files in os.walk(f"{host_dir}/{folder}"):
            dirs.sort()
            found.extend(os.path.relpath(os.path.join(root, name), host_dir)
                         for name in sorted(files) if name.endswith(".jsonl"))
    if os.path.isfile(f"{host_dir}/artefacts/plaso_timeline.jsonl"):
        found.append("artefacts/plaso_timeline.jsonl")
    found.extend(os.path.basename(path) for path in memory_outputs(host_dir))
    return found


def ingest_splunk_data(
    verbosity,
    output_directory,
    case,
    stage,
    allimgs,
    postpath,
):
    seen = set()
    for img_name, img in siem_hosts(allimgs):
        if "vss" in img.split("::")[1]:
            vssimage, vsstext = "'" + img_name + "' (" + img.split("::")[
                1
            ].split("_")[1].replace(
                "vss", "volume shadow copy #"
            ) + ")", " from " + img.split(
                "::"
            )[
                1
            ].split(
                "_"
            )[
                1
            ].replace(
                "vss", "volume shadow copy #"
            )
        else:
            vssimage, vsstext = "'" + img_name + "'", ""
        print()
        print("     Indexing artefacts into Splunk for {}...".format(vssimage))
        entry, prnt = "{},{}{},{},indexing\n".format(
            datetime.now().isoformat(), img_name, vsstext, stage
        ), " -> {} -> indexing artfacts into {} for {}{}".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            vssimage,
            vsstext,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        host_dir = os.path.realpath(output_directory + img_name)
        # A host's shadow copies are in its own cooked/ (cooked/vssN/): monitored once, with it
        first = img_name not in seen
        seen.add(img_name)
        with open(
            "/" + postpath + "splunk/etc/apps/elrond/default/inputs.conf", "a"
        ) as inputsconf:
            if first and os.path.isdir(host_dir):
                for atftfile in sorted(os.listdir(host_dir)):
                    if atftfile.endswith(".audit"):
                        inputsconf.write(
                            "[monitor://{}]\ndisabled = false\nhost = {}\nsourcetype = elrondCSV\nindex = {}\n\n".format(
                                host_dir + "/" + atftfile,
                                img_name,
                                case,
                            )
                        )
                # cooked/, analysis/ and Volatility's output, whatever the host is
                for stanza in host_monitors(host_dir, img_name, case):
                    inputsconf.write(stanza)
                for memory_dir in (host_dir, host_dir + "/artefacts/cooked/memory"):
                    if os.path.exists(memory_dir + "/timeliner.csv"):
                        inputsconf.write(
                            "[monitor://{}/timeliner.csv]\ndisabled = false\nhost = {}\nsourcetype = elrondCSV\nindex = {}\n\n".format(
                                memory_dir,
                                img_name,
                                case,
                            )
                        )
                    if os.path.exists(memory_dir + "/iehistory"):
                        inputsconf.write(
                            "[monitor://{}/iehistory]\ndisabled = false\nhost = {}\nsourcetype = elrond_\nindex = {}\n\n".format(
                                memory_dir,
                                img_name,
                                case,
                            )
                        )
        with open(
            "/" + postpath + "splunk/etc/apps/elrond/default/tags.conf", "a"
        ) as tagsconf:
            if (
                img_name.endswith(".E01")
                or img_name.endswith(".e01")
                or img_name.endswith(".VMDK.raw")
                or img_name.endswith(".vmdk.raw")
                or img_name.endswith(".dd.raw")
            ):
                imgtype = "\ndisk = enabled"
            else:
                imgtype = "\nmemory = enabled"
            if "Windows" in img.split("::")[1]:
                imgtype = imgtype + "\nWindows = enabled\n\n"
            elif "mac" in img.split("::")[1] or "Mac" in img.split("::")[1]:
                imgtype = imgtype + "\nmacOS = enabled\n\n"
            elif "Linux" in img.split("::")[1]:
                imgtype = imgtype + "\nLinux = enabled\n\n"
            tagsconf.write("[host={}]{}".format(img_name, imgtype))
        output_directory = os.path.dirname(output_directory) + "/"
        if os.path.exists(
            "/" + postpath + "splunk/etc/apps/elrond/default/tags.conf.orig.pre41"
        ):
            os.remove("/" + postpath + "splunk/etc/apps/elrond/default/tags.conf")
            os.rename(
                r"/" + postpath + "splunk/etc/apps/elrond/default/tags.conf.orig.pre41",
                r"/" + postpath + "splunk/etc/apps/elrond/default/tags.conf",
            )

        print("     Splunk indexing completed for {}".format(vssimage))
        entry, prnt = "{},{},{},completed\n".format(
            datetime.now().isoformat(), vssimage, stage
        ), " -> {} -> indexed artfacts into {} for {}".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
