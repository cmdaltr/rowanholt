#!/usr/bin/env python3 -tt

import json
import os
import re
import struct
import time
from datetime import datetime
from pathlib import Path

from rowanholt.audit import write_audit_log_entry
from rowanholt.analysis.iocs import compare_iocs
from rowanholt.analysis.ntfs_ads import known_stream_note, mft_alternate_data_streams
from rowanholt.process.extractions.artemis import _record_techniques


def _analyse_artemis_mft_from_status_log(ar, f, stage, vssimage, anysd, verbosity, output_directory, analyse_mft_json_func):
    """
    Parse Artemis status.log to find MFT artifact files and analyze them.

    Artemis outputs files with UUID names (e.g., 68330d32-c35e-4d43-8655-1cb5e9d90b83.jsonl)
    and creates a status.log mapping file in the format:
    "artifact_name:uuid.jsonl"

    This function finds MFT/rawfiles artifacts and analyzes them.
    """
    try:
        status_log_path = os.path.join(ar, f)
        print(" -> {} -> found Artemis status.log, checking for MFT data...".format(
            datetime.now().isoformat().replace("T", " ")
        ))
        with open(status_log_path, 'r', encoding='utf-8', errors='replace') as log_file:
            for line in log_file:
                line = line.strip()
                if not line:
                    continue
                # Format: "mft:uuid.jsonl" or "rawfiles:uuid.jsonl"
                if ':' in line:
                    artifact_type, filename = line.split(':', 1)
                    # Look for MFT-related artifacts
                    if artifact_type.lower() in ('mft', 'rawfiles', 'filelisting'):
                        artifact_path = os.path.join(ar, filename.strip('"').strip())
                        if os.path.exists(artifact_path):
                            print(" -> {} -> found MFT artifact: {}".format(
                                datetime.now().isoformat().replace("T", " "),
                                os.path.basename(artifact_path)
                            ))
                            analyse_mft_json_func(stage, vssimage, artifact_path, anysd, verbosity, output_directory)
                        else:
                            # Try looking for the file in subdirectories
                            for root, _, files in os.walk(ar):
                                for potential_file in files:
                                    if potential_file.endswith('.jsonl') or potential_file.endswith('.json'):
                                        potential_path = os.path.join(root, potential_file)
                                        if os.path.exists(potential_path):
                                            print(" -> {} -> found potential MFT file: {}".format(
                                                datetime.now().isoformat().replace("T", " "),
                                                potential_file
                                            ))
                                            analyse_mft_json_func(stage, vssimage, potential_path, anysd, verbosity, output_directory)
                                            break
    except Exception as e:
        print(" -> {} -> error parsing status.log: {}".format(
            datetime.now().isoformat().replace("T", " "),
            str(e)[:100]
        ))


VSS_DIR = re.compile(r"^vss\d+$")

# Extended attributes Windows itself writes (code integrity, kernel caches, WSL)
BENIGN_EA = re.compile(r"^(\$KERNEL\.|\$CI\.CATALOGHINT$|\$LX(UID|GID|MOD|DEV)$|APPLICENSING$)", re.I)
# Where a timestomped implant is worth flagging: user-writable, not OS-managed
TIMESTOMP_LOCATIONS = re.compile(r"^\.?[\\/](users|programdata|windows[\\/]temp|\$recycle\.bin|perflogs)[\\/]", re.I)
# Windows setup copies these with their original $SI times, so they read as
# timestomping on a clean install. Still reported, but marked as safe to ignore.
SETUP_COPIED = re.compile(r"^\.?[\\/](programdata[\\/]microsoft|users[\\/]default)[\\/]", re.I)
SETUP_COPIED_NOTE = "likely benign: Windows setup copies files here with their original times"
EXECUTABLE = re.compile(r"\.(exe|dll|sys|scr|ps1|psm1|bat|cmd|vbs|vbe|js|jse|hta|wsf|lnk|msi)$", re.I)
MFT_JSON_NAMES = ("mft.json", "mft.jsonl", "rawfiles.json", "rawfiles.jsonl", "journal_mft.json")


def iter_json_records(f, chunk=1 << 20):
    """Records from a JSON array or JSON Lines file, without loading it whole
    (an Artemis MFT export is several GB)."""
    first = f.read(chunk)
    if not first.lstrip().startswith("["):
        rest = first
        while True:
            lines = rest.split("\n")
            rest = lines.pop()
            for line in lines:
                if line.strip():
                    try:
                        yield json.loads(line)
                    except ValueError:
                        pass
            more = f.read(chunk)
            if not more:
                if rest.strip():
                    try:
                        yield json.loads(rest)
                    except ValueError:
                        pass
                return
            rest += more
    decoder = json.JSONDecoder()
    buf, eof = first.lstrip()[1:], False
    while True:
        buf = buf.lstrip().lstrip(",").lstrip()
        if buf.startswith("]") or (not buf and eof):
            return
        try:
            record, end = decoder.raw_decode(buf)
        except ValueError:
            if eof:
                return
            more = f.read(chunk)
            eof = not more
            buf += more
            continue
        yield record
        buf = buf[end:]
        if len(buf) < chunk and not eof:
            more = f.read(chunk)
            eof = not more
            buf += more


def mft_findings(record):
    """(analysis type, value) findings for one Artemis MFT record. ADS names
    aren't in Artemis's MFT output, so only EAs and timestomping are checked."""
    findings = []
    if not isinstance(record, dict) or not record.get("is_file", True):
        return findings
    for attribute in record.get("attribute_list") or []:
        if isinstance(attribute, dict) and "data_size" in attribute and "name" in attribute:
            if not BENIGN_EA.match(str(attribute["name"])):
                findings.append(("ExtendedAttributes", str(attribute["name"])))
    for stream in record.get("ads_info") or []:
        findings.append(("AlternateDataStream", stream.get("name", "unknown") if isinstance(stream, dict) else str(stream)))
    path = str(record.get("full_path") or record.get("filename") or "")
    si_created, fn_created = record.get("created"), record.get("filename_created")
    if (
        si_created and fn_created and type(si_created) is type(fn_created) and si_created < fn_created
        and TIMESTOMP_LOCATIONS.match(path) and EXECUTABLE.search(path)
    ):
        value = "$SI: {}|$FN: {}".format(si_created, fn_created)
        if SETUP_COPIED.match(path):
            value += "|" + SETUP_COPIED_NOTE
        findings.append(("Timestomp", value))
    return findings


def volume_artefact_dirs(artefacts_dir, mnt, vssimage):
    """[(directory, skip_vss_subdirs)] holding one volume's collected artefacts.

    Shadow copy N's artefacts live under artefacts/raw/vssN and
    artefacts/cooked/vssN; the live volume's are everything else under raw/ and
    cooked/ (so its walk skips the vssN directories).
    """
    if not os.path.isdir(artefacts_dir):
        return []
    match = re.search(r"vss(\d+)$", mnt.rstrip("/")) or re.search(r"shadow copy #(\d+)", vssimage or "")
    if match:
        dirs = [os.path.join(artefacts_dir, part, "vss" + match.group(1)) for part in ("raw", "cooked")]
        return [(d, False) for d in dirs if os.path.isdir(d)]
    return [(artefacts_dir, True)]


def analyse_artefacts(
    verbosity, output_directory, img, mnt, analysis, magicbytes, extractiocs, iocsfile, vssimage
):
    def analyse_mft_json(stage, vssimage, filepath, anysd, verbosity, output_directory):
        """Analyse Artemis MFT JSON for extended attributes and timestomping,
        streaming it record by record."""
        print(" -> {} -> analysing MFT for Extended Attributes & Timestomping...".format(
            datetime.now().isoformat().replace("T", " ")
        ))
        counts = {"ExtendedAttributes": 0, "AlternateDataStream": 0, "Timestomp": 0}
        records_processed = 0
        setup_copied = 0
        audit_text = {
            "ExtendedAttributes": "extended attribute",
            "AlternateDataStream": "alternate data stream",
            "Timestomp": "evidence of timestomping",
        }
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for record in iter_json_records(f):
                    records_processed += 1
                    findings = mft_findings(record)
                    if not findings:
                        continue
                    filename = str(record.get("full_path") or record.get("filename") or "unknown")
                    short = filename.replace("\\", "/").split("/")[-1]
                    if not os.path.exists(anysd + "/analysis.csv"):
                        with open(anysd + "/analysis.csv", "a") as analysisfile:
                            analysisfile.write("LastWriteTime,elrond_host,Filename,AnalysisType,AnalysisValue\n")
                    with open(anysd + "/analysis.csv", "a") as analysisfile:
                        for kind, value in findings:
                            counts[kind] += 1
                            if value.endswith(SETUP_COPIED_NOTE):
                                setup_copied += 1
                            analysisfile.write("{},{},{},{},{}\n".format(
                                datetime.now().isoformat(), vssimage.replace("'", ""),
                                filename.replace(",", "%2C"), kind, value.replace(",", "%2C"),
                            ))
                            entry, prnt = "{},{},{},{} found in '{}'\n".format(
                                datetime.now().isoformat(), vssimage, stage, audit_text[kind], short
                            ), " -> {} -> {} found in '{}' for {}".format(
                                datetime.now().isoformat().replace("T", " "), audit_text[kind], short, vssimage
                            )
                            write_audit_log_entry(verbosity, output_directory, entry, prnt)
        except (OSError, ValueError) as e:
            print(" -> {} -> warning: could not analyse MFT JSON: {}".format(
                datetime.now().isoformat().replace("T", " "), str(e)[:100]
            ))
        now = datetime.now().isoformat().replace("T", " ")
        print(" -> {} -> MFT analysis complete: {} records processed".format(now, records_processed))
        print(" -> {} ->   Extended Attributes (not Windows' own): {} files".format(now, counts["ExtendedAttributes"]))
        print(" -> {} ->   Timestomping indicators ($SI before $FN, executables in user-writable paths): {} files".format(now, counts["Timestomp"]))
        if setup_copied:
            print(" -> {} ->     of which {} under Users\\Default or ProgramData\\Microsoft ({})".format(now, setup_copied, SETUP_COPIED_NOTE))
        if counts["AlternateDataStream"]:
            print(" -> {} ->   Alternate Data Streams: {} files".format(now, counts["AlternateDataStream"]))

    def analyse_mft_ads(stage, vssimage, filepath, anysd, verbosity, output_directory):
        """Alternate data streams from the raw $MFT Gandalf collects (Artemis's
        MFT JSON has no stream names)."""
        print(" -> {} -> analysing raw $MFT for Alternate Data Streams...".format(
            datetime.now().isoformat().replace("T", " ")
        ))
        total = benign = 0
        try:
            streams = list(mft_alternate_data_streams(Path(filepath)))
        except (OSError, ValueError, struct.error) as e:
            print(" -> {} -> warning: could not parse raw $MFT: {}".format(
                datetime.now().isoformat().replace("T", " "), str(e)[:100]
            ))
            return
        if streams and not os.path.exists(anysd + "/analysis.csv"):
            with open(anysd + "/analysis.csv", "a") as analysisfile:
                analysisfile.write("LastWriteTime,elrond_host,Filename,AnalysisType,AnalysisValue\n")
        with open(anysd + "/analysis.csv", "a") as analysisfile:
            for path, stream, size in streams:
                total += 1
                note = known_stream_note(stream)
                value = "{} ({} bytes)".format(stream, size)
                if note:
                    benign += 1
                    value += "|" + note
                analysisfile.write("{},{},{},AlternateDataStream,{}\n".format(
                    datetime.now().isoformat(), vssimage.replace("'", ""),
                    path.replace(",", "%2C"), value.replace(",", "%2C"),
                ))
                if not note:
                    short = path.split("\\")[-1]
                    entry, prnt = "{},{},{},alternate data stream '{}' found in '{}'\n".format(
                        datetime.now().isoformat(), vssimage, stage, stream, short
                    ), " -> {} -> alternate data stream '{}' found in '{}' for {}".format(
                        datetime.now().isoformat().replace("T", " "), stream, short, vssimage
                    )
                    write_audit_log_entry(verbosity, output_directory, entry, prnt)
        if total > benign:
            _record_techniques(os.path.join(output_directory, "mitre_techniques.txt"), ["T1564.004"])
        now = datetime.now().isoformat().replace("T", " ")
        print(" -> {} ->   Alternate Data Streams: {} files ({} likely benign: Mark of the Web, compression and similar)".format(now, total, benign))

    def analyse_disk_images(stage, vssimage, ar, f, anysd):
        print()
        print(
            "     Analysing MFT for Extended Attributes, Alternate Data Streams & Timestomping for {}...".format(
                vssimage
            )
        )
        with open(ar + "/" + f) as afh:
            for line in afh:
                mftinfo = re.findall(
                    r"[^\,]*\,[^\,]*\,[^\,]*\,([^\,]*)\,[^\,]*\,[^\,]*\,[^\,]*\,([^\,]*)\,([^\,]*)\,[^\,]*\,[^\,]*\,[^\,]*\,([^\,]*)\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,([^\,]*)\,([^\,]*)\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,([^\,]*)\,[^\,]*\,[^\,]*\,[^\,]*",
                    line,
                )
                if len(mftinfo) > 0 and (
                    (
                        mftinfo[0][0] == "File"
                        and mftinfo[0][1] != "NoFNRecord"
                        and (
                            mftinfo[0][4] == "True"
                            or mftinfo[0][5] == "True"
                            or mftinfo[0][6] == "Y"
                        )
                    )
                    or (
                        mftinfo[0][0] == "file"
                        and mftinfo[0][1] != "nofnrecord"
                        and (
                            mftinfo[0][4] == "true"
                            or mftinfo[0][5] == "true"
                            or mftinfo[0][6] == "y"
                        )
                    )
                ):
                    if not os.path.exists(anysd + "/analysis.csv"):
                        with open(anysd + "/analysis.csv", "a") as analysisfile:
                            analysisfile.write(
                                "LastWriteTime,elrond_host,Filename,AnalysisType,AnalysisValue\n"
                            )
                    else:
                        with open(anysd + "/analysis.csv", "a") as analysisfile:
                            if (mftinfo[0][4] == "True" or mftinfo[0][5] == "True") or (
                                mftinfo[0][4] == "true" or mftinfo[0][5] == "true"
                            ):
                                analysisfile.write(
                                    "{},{},{},ExtendedAttributes,Yes\n".format(
                                        datetime.now().isoformat(),
                                        vssimage.replace("'", ""),
                                        mftinfo[0][1],
                                    )
                                )
                                (
                                    entry,
                                    prnt,
                                ) = "{},{},{},extended attribute found in '{}'\n".format(
                                    datetime.now().isoformat(),
                                    vssimage,
                                    stage,
                                    mftinfo[0][1].split("/")[-1],
                                ), " -> {} -> extended attribute found in '{}' for {}".format(
                                    datetime.now().isoformat().replace("T", " "),
                                    mftinfo[0][1].split("/")[-1],
                                    vssimage,
                                )
                                write_audit_log_entry(
                                    verbosity, output_directory, entry, prnt
                                )
                            elif mftinfo[0][6] == "Y" or mftinfo[0][6] == "y":
                                analysisfile.write(
                                    "{},{},{},AlternateDataStream,Yes\n".format(
                                        datetime.now().isoformat(),
                                        vssimage.replace("'", ""),
                                        mftinfo[0][1],
                                    )
                                )
                                (
                                    entry,
                                    prnt,
                                ) = "{},{},{},alternate data stream found in '{}'\n".format(
                                    datetime.now().isoformat(),
                                    vssimage,
                                    stage,
                                    mftinfo[0][1].split("/")[-1],
                                ), " -> {} -> alternate data stream found in '{}' for {}".format(
                                    datetime.now().isoformat().replace("T", " "),
                                    mftinfo[0][1].split("/")[-1],
                                    vssimage,
                                )
                                write_audit_log_entry(
                                    verbosity, output_directory, entry, prnt
                                )
                            if (
                                mftinfo[0][2].split(".")[0]
                                != mftinfo[0][3].split(".")[0]
                            ):
                                stdepoch, fnepoch = int(
                                    time.mktime(
                                        time.strptime(
                                            mftinfo[0][2].split(".")[0],
                                            strpformat,
                                        )
                                    )
                                ), int(
                                    time.mktime(
                                        time.strptime(
                                            mftinfo[0][3].split(".")[0],
                                            strpformat,
                                        )
                                    )
                                )
                                if (
                                    stdepoch < fnepoch
                                    or mftinfo[0][2][20:] == "000000"
                                    or mftinfo[0][3][20:] == "000000"
                                ):
                                    with open(
                                        anysd + "/analysis.csv", "a"
                                    ) as analysisfile:
                                        analysisfile.write(
                                            "{},{},{},Timestomp,$SI: {}|$FN: {}\n".format(
                                                datetime.now().isoformat(),
                                                vssimage.replace("'", ""),
                                                mftinfo[0][1],
                                                stdepoch,
                                                fnepoch,
                                            )
                                        )
                                    (
                                        entry,
                                        prnt,
                                    ) = "{},{},{},evidence of timestomping found in '{}'\n".format(
                                        datetime.now().isoformat(),
                                        vssimage,
                                        stage,
                                        mftinfo[0][1].split("/")[-1],
                                    ), " -> {} -> evidence of timestomping found in '{}' for {}".format(
                                        datetime.now().isoformat().replace("T", " "),
                                        mftinfo[0][1].split("/")[-1],
                                        vssimage,
                                    )
                                    write_audit_log_entry(
                                        verbosity, output_directory, entry, prnt
                                    )
        print(
            "     Completed analysis of Extended Attributes, Alternate Data Streams & Timestomping for {}...".format(
                vssimage
            )
        )
        print()

    stage = "analysing"
    # Safe parsing of img - handle both "image::type" and plain "image" formats
    # Extract basename since img may contain full path
    img_parts = img.split("::")
    img_name = img_parts[0].split("/")[-1]
    img_type = img_parts[1] if len(img_parts) > 1 else ""

    atftd = output_directory + img_name + "/artefacts/cooked/"
    anysd = output_directory + img_name + "/analysis/"
    strpformat = "%Y-%m-%d %H:%M:%S"
    if analysis:
        if "vss" in img_type:
            vss_part = img_type.split("_")[1] if "_" in img_type else img_type
            atftd, vssimage = (
                output_directory
                + img_name
                + "/artefacts/cooked/"
                + vss_part,
                "'"
                + img_name
                + "' ("
                + vss_part.replace("vss", "volume shadow copy #")
                + ")",
            )
        else:
            atftd, vssimage = (
                output_directory + img_name + "/artefacts/cooked/",
                "'" + img_name + "'",
            )
        print("    Analsying artefacts for {}...".format(vssimage))
        entry, prnt = "{},{},{},commenced\n".format(
            datetime.now().isoformat(), vssimage.replace("'", ""), stage
        ), " -> {} -> {} artefacts for {}".format(
            datetime.now().isoformat().replace("T", " "), stage, vssimage
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        if not os.path.exists(anysd):
            os.mkdir(anysd)
        with open(anysd + "/analysis.csv", "a") as analysisfile:
            analysisfile.write(
                "LastWriteTime,hostname,Filename,analysis_type,analysis_value\n"
            )
        if magicbytes:
            print(
                "     Analysing files for file-signature (magic-byte) discrepencies for {}...".format(
                    vssimage
                ), flush=True
            )
            # Check if mount point exists and warn if not
            if not os.path.exists(mnt) or not os.path.isdir(mnt):
                print(
                    " -> {} -> WARNING: Mount point '{}' not available for magic-byte analysis".format(
                        datetime.now().isoformat().replace("T", " "), mnt
                    ), flush=True
                )
            for root, _, files in os.walk(mnt):
                for f in files:
                    try:
                        if 0 < os.stat(os.path.join(root, f)).st_size < 10000000:  # 10MB
                            if (
                                os.path.join(root, f) != "/mnt/elrond_mount/hiberfil.sys"
                                and os.path.join(root, f)
                                != "/mnt/elrond_mount/pagefile.sys"
                                and os.path.join(root, f)
                                != "/mnt/elrond_mount1/hiberfil.sys"
                                and os.path.join(root, f)
                                != "/mnt/elrond_mount1/pagefile.sys"
                                and os.path.join(root, f)
                                != "/mnt/elrond_mount2/hiberfil.sys"
                                and os.path.join(root, f)
                                != "/mnt/elrond_mount2/pagefile.sys"
                                and os.path.join(root, f)
                                != "/mnt/elrond_mount3/hiberfil.sys"
                                and os.path.join(root, f)
                                != "/mnt/elrond_mount3/pagefile.sys"
                                and os.path.join(root, f)
                                != "/mnt/elrond_mount4/hiberfil.sys"
                                and os.path.join(root, f)
                                != "/mnt/elrond_mount4/pagefile.sys"
                                and os.path.join(root, f)
                                != "/mnt/elrond_mount5/hiberfil.sys"
                                and os.path.join(root, f)
                                != "/mnt/elrond_mount5/pagefile.sys"
                            ) and (
                                "." in f
                                and (
                                    f.endswith(".cab")
                                    or f.endswith(".elf")
                                    or f.endswith(".doc")
                                    or f.endswith(".xls")
                                    or f.endswith(".ppt")
                                    or f.endswith(".pdf")
                                    or f.endswith(".odt")
                                    or f.endswith(".odp")
                                    or f.endswith(".ott")
                                    or f.endswith(".zip")
                                    or f.endswith(".rar")
                                    or f.endswith(".7z")
                                    or f.endswith(".chm")
                                    or f.endswith(".docx")
                                    or f.endswith(".xlsx")
                                    or f.endswith(".pptx")
                                    or f.endswith(".com")
                                    or f.endswith(".dll")
                                    or f.endswith(".exe")
                                    or f.endswith(".sys")
                                    or f.endswith(".gif")
                                    or f.endswith(".jpg")
                                    or f.endswith(".jpeg")
                                    or f.endswith(".png")
                                )
                            ):
                                try:
                                    with open(os.path.join(root, f), "rb") as magic_file:
                                        # The checks below only look at the first
                                        # few bytes; reading whole files cost
                                        # 52 min on a Windows volume.
                                        file_hdr = magic_file.read(16)
                                except:
                                    file_hdr = "0000000000"
                                if (
                                    file_hdr != "0000000000"
                                    and str(file_hdr)[2:10] != "'"
                                    and (
                                        (
                                            f.endswith(".cab")
                                            and str(file_hdr)[2:10] != "\\x4d\\x53"
                                            and str(file_hdr)[2:10] != "MSCF\\x00"
                                        )
                                        or (
                                            f.endswith(".elf")
                                            and str(file_hdr)[2:10] != "\\x7f\\x45"
                                            and str(file_hdr)[2:10] != "\\x7fELF\\"
                                        )
                                        or (
                                            (
                                                f.endswith(".com")
                                                or f.endswith(".dll")
                                                or f.endswith(".exe")
                                                or f.endswith(".sys")
                                            )
                                            and (
                                                str(file_hdr)[2:10] != "\\x4d\\x5a"
                                                and str(file_hdr)[2:10] != "MZ\\x90\\x"
                                                and str(file_hdr)[2:10] != "MZ\\x00\\x"
                                                and str(file_hdr)[2:10] != "MZx\\x00\\"
                                                and str(file_hdr)[2:10] != "MZ\\x9f\\x"
                                                and str(file_hdr)[2:10] != "\\x00\\x02"
                                                and str(file_hdr)[2:10] != "\\x02\\x00"
                                                and str(file_hdr)[2:9] != "DCH\\x01"
                                                and str(file_hdr)[2:9] != "DCD\\x01"
                                                and str(file_hdr)[2:9] != "DCN\\x01"
                                                and str(file_hdr)[2:9] != "DCN\\x01"
                                            )
                                        )
                                        or (
                                            (
                                                f.endswith(".docx")
                                                or f.endswith(".xlsx")
                                                or f.endswith(".pptx")
                                            )
                                            and str(file_hdr)[2:10] != "\\x50\\x4b"
                                            and str(file_hdr)[2:10] != "PK\\x03\\x"
                                        )
                                        or (
                                            (
                                                f.endswith(".doc")
                                                or f.endswith(".xls")
                                                or f.endswith(".ppt")
                                            )
                                            and (str(file_hdr)[2:10] != "\\x50\\x4b")
                                            and str(file_hdr)[2:10] != "\\xd0\\xcf"
                                        )
                                        or (
                                            (
                                                f.endswith(".odt")
                                                or f.endswith(".odp")
                                                or f.endswith(".ott")
                                            )
                                            and str(file_hdr)[2:10] != "\\x50\\x4b"
                                            and str(file_hdr)[2:10] != "PK\\x03\\x"
                                        )
                                        or (
                                            f.endswith(".pdf")
                                            and (
                                                str(file_hdr)[2:9] != "%PDF-1."
                                                and str(file_hdr)[2:10] != "\\x25\\x50"
                                            )
                                        )
                                        or (
                                            f.endswith(".7z")
                                            and (
                                                str(file_hdr)[2:10] != "7z\\xbc\\x"
                                                and str(file_hdr)[2:10] != "\\x37\\x7a"
                                            )
                                        )
                                        or (
                                            (f.endswith(".jar") or f.endswith(".zip"))
                                            and str(file_hdr)[2:10] != "\\x50\\x4b"
                                            and str(file_hdr)[2:10] != "PK\\x03\\x"
                                            and str(file_hdr)[2:9] != "PK\\x03"
                                        )
                                        or (
                                            f.endswith(".rar")
                                            and (
                                                str(file_hdr)[2:10] != "Rar!\\x1a"
                                                and str(file_hdr)[2:10] != "\\x52\\x61"
                                            )
                                        )
                                        or (
                                            (f.endswith(".jpg") or f.endswith(".jpeg"))
                                            and (str(file_hdr)[2:10] != "\\xff\\xd8")
                                            and str(file_hdr)[2:10] != "GIF89a\\x"
                                            and str(file_hdr)[2:9] != "DCH\\x01"
                                        )
                                        or (
                                            f.endswith(".gif")
                                            and (
                                                str(file_hdr)[2:8] != "GIF89a"
                                                and str(file_hdr)[2:8] != "GIF87a"
                                                and str(file_hdr)[2:10] != "\\x47\\x49"
                                            )
                                        )
                                        or (
                                            f.endswith(".png")
                                            and (
                                                str(file_hdr)[2:10] != "\\x89\\x50"
                                                and str(file_hdr)[2:10] != "\\x89PNG\\"
                                                and str(file_hdr)[2:10] != "\\xff\\xd8"
                                            )
                                        )
                                        or (
                                            f.endswith(".chm")
                                            and (
                                                str(file_hdr)[2:10] != "ITSF\\x03"
                                                and str(file_hdr)[2:10] != "\\x49\\x54"
                                            )
                                        )
                                    )
                                ):
                                    with open(anysd + "/analysis.csv", "a") as analysisfile:
                                        analysisfile.write(
                                            "{},{},{},File-signature (magic-byte) Discrepency,'{}'\n".format(
                                                datetime.now().isoformat(),
                                                vssimage.replace("'", ""),
                                                f,
                                                str(file_hdr)[2:10],
                                            )
                                        )
                                    (
                                        entry,
                                        prnt,
                                    ) = "{},{},{},file-signature (magic-byte) discrepency of '{}' for '{}'\n".format(
                                        datetime.now().isoformat(),
                                        vssimage,
                                        stage,
                                        str(file_hdr)[2:10],
                                        f,
                                    ), " -> {} -> identified file-signature (magic-byte) discrepency of '{}' from '{}' for {}".format(
                                        datetime.now().isoformat().replace("T", " "),
                                        str(file_hdr)[2:10],
                                        f,
                                        vssimage,
                                    )
                                    write_audit_log_entry(
                                        verbosity, output_directory, entry, prnt
                                    )
                    except:
                        pass
        # Analyze MFT data for Extended Attributes, Alternate Data Streams, and Timestomping
        print(" -> {} -> scanning for MFT data to analyse for '{}'...".format(
            datetime.now().isoformat().replace("T", " "), img_name
        ))
        mft_files_found = False
        # ADS come from the raw $MFT (raw/ or raw/vssN/), which the cooked walk below doesn't see
        img_mount = img.split("::")[1] if "::" in img else ""
        vss_part = img_mount.split("_")[1] if "vss" in img_mount.lower() and "_" in img_mount else ""
        raw_mft = os.path.join(output_directory + img_name, "artefacts", "raw", vss_part, "$MFT")
        if os.path.isfile(raw_mft):
            mft_files_found = True
            analyse_mft_ads(stage, vssimage, raw_mft, anysd, verbosity, output_directory)
        for ar, _, af in os.walk(atftd):
            for f in af:
                # Handle both legacy CSV format and new Artemis JSON format
                img_parts = img.split("::")
                img_mount = img_parts[1] if len(img_parts) > 1 else ""

                # Check if this is a VSS path or regular cooked directory
                is_vss_path = "vss" in img_mount.lower()
                is_cooked_dir = "cooked" in ar.lower()

                if is_vss_path:
                    vss_part = img_mount.split("_")[1] if "_" in img_mount else ""
                    if vss_part in atftd:
                        if f.endswith("MFT.csv"):
                            mft_files_found = True
                            analyse_disk_images(stage, vssimage, ar, f, anysd)
                        elif f.lower() in MFT_JSON_NAMES:
                            mft_files_found = True
                            analyse_mft_json(stage, vssimage, os.path.join(ar, f), anysd, verbosity, output_directory)
                        # Handle Artemis UUID-named output files
                        elif f == "status.log":
                            mft_files_found = True
                            _analyse_artemis_mft_from_status_log(ar, f, stage, vssimage, anysd, verbosity, output_directory, analyse_mft_json)
                elif is_cooked_dir:
                    if f.endswith("MFT.csv"):
                        mft_files_found = True
                        analyse_disk_images(stage, vssimage, ar, f, anysd)
                    elif f.lower() in MFT_JSON_NAMES:
                        mft_files_found = True
                        analyse_mft_json(stage, vssimage, os.path.join(ar, f), anysd, verbosity, output_directory)
                    # Handle Artemis UUID-named output files via status.log
                    elif f == "status.log":
                        mft_files_found = True
                        _analyse_artemis_mft_from_status_log(ar, f, stage, vssimage, anysd, verbosity, output_directory, analyse_mft_json)
                    # Also scan any JSONL files that might be Artemis MFT output (UUID-named)
                    elif f.endswith(".jsonl") and len(f) > 30:  # UUID-named files are typically 36+ chars
                        # Check if this looks like an MFT output by sampling content
                        try:
                            filepath = os.path.join(ar, f)
                            with open(filepath, 'r', encoding='utf-8', errors='replace') as sample_file:
                                first_line = sample_file.readline()
                                if first_line:
                                    sample_data = json.loads(first_line)
                                    # Check for MFT-related fields
                                    if any(key in sample_data for key in ['filename', 'full_path', 'created', 'modified', 'ads_info', 'attributes']):
                                        print(" -> {} -> found potential MFT data in '{}'".format(
                                            datetime.now().isoformat().replace("T", " "), f
                                        ))
                                        mft_files_found = True
                                        analyse_mft_json(stage, vssimage, filepath, anysd, verbosity, output_directory)
                        except:
                            pass

        if not mft_files_found:
            print(" -> {} -> no Extended Attributes found for '{}'".format(
                datetime.now().isoformat().replace("T", " "), img_name
            ))
            print(" -> {} -> no Alternate Data Streams found for '{}'".format(
                datetime.now().isoformat().replace("T", " "), img_name
            ))
            print(" -> {} -> no evidence of Timestomping found for '{}'".format(
                datetime.now().isoformat().replace("T", " "), img_name
            ))
    if extractiocs:
        iocfilelist, lineno, previous = [], 0, 0.0
        print(
            "     Assessing readable files to extract IOCs from, for '{}'...".format(
                img_name
            ), flush=True
        )
        # Check if mount point exists and warn if not
        if not os.path.exists(mnt) or not os.path.isdir(mnt):
            print(
                " -> {} -> WARNING: Mount point '{}' not available for IOC extraction from disk".format(
                    datetime.now().isoformat().replace("T", " "), mnt
                ), flush=True
            )
        # This volume only: its mount plus its own collected artefacts. Walking the
        # whole artefacts/ tree rescanned every shadow copy on every copy's pass.
        for scan_root, skip_vss in [(mnt, False)] + volume_artefact_dirs(
            os.path.join(output_directory, img_name, "artefacts"), mnt, vssimage
        ):
            for root, dirs, files in os.walk(scan_root):
                if skip_vss:
                    dirs[:] = [d for d in dirs if not VSS_DIR.match(d)]
                for f in files:
                    try:
                        if 0 < os.stat(os.path.join(root, f)).st_size < 10000000:  # 10MB
                            with open(os.path.join(root, f), "rb") as filetest:
                                if b"\x00" in filetest.read(8192):
                                    continue  # binary (jumplists, databases): noise as text
                            iocfilelist.append(os.path.join(root, f))
                    except:
                        pass
        print("       Done.")
        iocfiles = list(set(iocfilelist))
        if not os.path.exists(anysd):
            os.mkdir(anysd)
        if not os.path.exists(
            output_directory + img_name + "/analysis/iocs.csv"
        ):
            with open(
                output_directory + img_name + "/analysis/iocs.csv",
                "w",
            ) as ioccsv:
                ioccsv.write(
                    "CreationTime,LastAccessTime,LastWriteTime,Filename,ioc,indicator_type,line_number,resolvable,watchlist_match\n"
                )
        # Get watchlist file path if provided (iocsfile is a list from argparse)
        watchlist_file = iocsfile[0] if iocsfile else None
        compare_iocs(
            output_directory,
            verbosity,
            img,
            stage,
            vssimage,
            iocfiles,
            lineno,
            previous,
            watchlist_file=watchlist_file,
        )
    entry, prnt = "{},{},{},completed\n".format(
        datetime.now().isoformat(), vssimage, stage
    ), " -> {} -> analysis completed for {}".format(
        datetime.now().isoformat().replace("T", " "), vssimage
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    print(" -> Completed Analysis Phase for {}".format(vssimage), flush=True)
    print(flush=True)
