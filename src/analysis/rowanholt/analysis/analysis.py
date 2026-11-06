#!/usr/bin/env python3 -tt

import json
import os
import re
import stat
import struct
from datetime import datetime
from pathlib import Path

from rowanholt.audit import write_audit_log_entry
from rowanholt.analysis.iocs import compare_iocs
from rowanholt.analysis.ntfs_ads import known_stream_note, mft_alternate_data_streams
from rowanholt.process.extractions.artemis import _record_techniques


def _analyse_artemis_mft_from_status_log(ar, f, stage, vssimage, anysd, verbosity, output_directory, analyse_mft_json_func):
    """
    Analyse the MFT outputs an Artemis status.log names; True if there was one.

    Artemis names its outputs by UUID (68330d32-c35e-4d43-8655-1cb5e9d90b83.jsonl) and maps
    them in status.log, a line per output: "artifact_name:uuid.jsonl".
    """
    found = False
    try:
        with open(os.path.join(ar, f), 'r', encoding='utf-8', errors='replace') as log_file:
            for line in log_file:
                artifact_type, _, filename = line.strip().partition(':')
                if artifact_type.lower() not in ('mft', 'rawfiles'):
                    continue
                artifact_path = os.path.join(ar, filename.strip('"').strip())
                if os.path.isfile(artifact_path):
                    print(" -> {} -> found MFT artifact: {}".format(
                        datetime.now().isoformat().replace("T", " "), os.path.basename(artifact_path)
                    ))
                    analyse_mft_json_func(stage, vssimage, artifact_path, anysd, verbosity, output_directory)
                    found = True
    except OSError as e:
        print(" -> {} -> error parsing status.log: {}".format(
            datetime.now().isoformat().replace("T", " "),
            str(e)[:100]
        ))
    return found


VSS_DIR = re.compile(r"^vss\d+$")

# Extended attributes Windows itself writes (code integrity, kernel caches, WSL)
BENIGN_EA = re.compile(r"^(\$KERNEL\.|\$CI\.CATALOGHINT$|\$LX(UID|GID|MOD|DEV)$|APPLICENSING$)", re.I)
# Where a timestomped implant is worth flagging: user-writable, not OS-managed
TIMESTOMP_LOCATIONS = re.compile(r"^\.?[\\/](users|programdata|windows[\\/]temp|\$recycle\.bin|perflogs)[\\/]", re.I)
# Windows setup copies these with their original $SI times, so they read as
# timestomping on a clean install. Still reported, but marked as safe to ignore.
SETUP_COPIED = re.compile(r"^\.?[\\/](programdata[\\/]microsoft|users[\\/]default)[\\/]", re.I)
SETUP_COPIED_NOTE = "likely benign: Windows setup copies files here with their original times"
# What's worth backdating: what runs, and what stages or carries it (archives, disk images)
TIMESTOMP_TYPES = re.compile(
    r"\.(exe|dll|sys|scr|ps1|psm1|bat|cmd|vbs|vbe|js|jse|hta|wsf|lnk|msi|py|jar"
    r"|zip|7z|rar|cab|iso|img|vhd|vhdx)$", re.I)
# Artemis's $STANDARD_INFORMATION times and the $FILE_NAME ones they're checked against.
# Tools that backdate a file rewrite $SI; $FN keeps when the file really arrived. Only the
# created time: a copy or an extracted file keeps its modified time and gets a new $FN, so
# $SI modified before $FN is every copied file (502 of 664 hits on a real Windows 7 image)
TIMESTOMP_PAIRS = (("created", "filename_created"),)
# Installers and archive tools set the same old times on everything they lay down; a backdated
# implant is one file. This many in one folder with the same $SI created time is an installation
BULK_TIMESTOMP = 3
BULK_TIMESTOMP_NOTE = "likely benign: {} files in this folder carry the same times (installed or extracted together)"
MFT_JSON_NAMES = ("mft.json", "mft.jsonl", "rawfiles.json", "rawfiles.jsonl", "journal_mft.json", "journal_mft.jsonl")
# Keys only Artemis's MFT records have, to know an unnamed .jsonl for one (prefetch and others
# also have filename, created and modified)
MFT_ONLY_KEYS = ("filename_created", "attribute_list", "ads_info")
ANALYSIS_HEADER = "LastWriteTime,hostname,Filename,analysis_type,analysis_value\n"

# What each extension's file starts with. Windows' delta-compressed copies (WinSxS, updates) keep
# the extension of what they expand to; an image saved under another image's extension (a web
# cache's .png that's a JPEG) is still an image. A .doc in RTF or ZIP is reported: a renamed RTF
# is how CVE-2017-11882 documents arrive
_PE = (b"MZ", b"DCM\x01", b"DCN\x01", b"DCD\x01", b"DCH\x01", b"DCS\x01", b"PA30", b"PA31",
       b"\x00\x02", b"\x02\x00")
_ZIP = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_IMAGE = (b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n", b"GIF87a", b"GIF89a", b"BM", b"RIFF", b"\x00\x00\x01\x00",
          b"DCH\x01")
SIGNATURES = {
    # Not .com: a COM program is raw code with no header (Windows' own etfsboot.com)
    **dict.fromkeys(("exe", "dll", "sys"), _PE),
    **dict.fromkeys(("docx", "xlsx", "pptx", "odt", "odp", "ott", "zip", "jar"), _ZIP),
    **dict.fromkeys(("doc", "xls", "ppt"), (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",)),
    **dict.fromkeys(("jpg", "jpeg", "png", "gif"), _IMAGE),
    "cab": (b"MSCF", b"ISc("), "elf": (b"\x7fELF",), "7z": (b"7z\xbc\xaf\x27\x1c",), "rar": (b"Rar!\x1a\x07",),
    "chm": (b"ITSF",),
}
HEADER_BYTES = 1024  # a PDF's %PDF- may come anywhere in its first 1024 bytes
# Files whose extension isn't their format by design: the paging and hibernation files, the
# Recycle Bin's $I records (named for what was deleted) and the Windows Installer's cached
# product icons (ICO files called ARPPRODUCTICON.exe)
SIGNATURE_EXEMPT = re.compile(
    r"^/(pagefile|hiberfil|swapfile)\.sys$|^/\$recycle\.bin/[^/]+/\$i[^/]*$"
    r"|^/windows/installer/[^/]+/arpproducticon\.exe$", re.I)


def signature_mismatch(name, header):
    """True when a file's first bytes aren't what its extension says it is."""
    extension = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if not header:
        return False
    if extension == "pdf":
        return b"%PDF-" not in header[:HEADER_BYTES]
    expected = SIGNATURES.get(extension)
    return bool(expected) and not header.startswith(expected)


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
    # Artemis writes a record per $FILE_NAME: a file's 8.3 name ("Dos") is the same file again
    if record.get("namespace") != "Dos" and TIMESTOMP_LOCATIONS.match(path) and TIMESTOMP_TYPES.search(path):
        # Artemis writes fixed-width ISO 8601 UTC, so the strings order as the times do
        earlier = [(si, fn) for si, fn in ((record.get(s), record.get(f)) for s, f in TIMESTOMP_PAIRS)
                   if si and fn and type(si) is type(fn) and si < fn]
        if earlier:
            value = "|".join("$SI: {}|$FN: {}".format(si, fn) for si, fn in earlier)
            if SETUP_COPIED.match(path):
                value += "|" + SETUP_COPIED_NOTE
            findings.append(("Timestomp", value))
    return findings


def bulk_timestomps(candidates):
    """{index: size of its group} for the timestomp candidates, (path, $SI created) pairs, that
    share their folder and $SI created time with BULK_TIMESTOMP or more others."""
    groups = {}
    for index, (path, created) in enumerate(candidates):
        folder = str(path).replace("\\", "/").rsplit("/", 1)[0].lower()
        groups.setdefault((folder, created), []).append(index)
    return {i: len(members) for members in groups.values() if len(members) >= BULK_TIMESTOMP for i in members}


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
        benign = {SETUP_COPIED_NOTE: 0, BULK_TIMESTOMP_NOTE: 0}
        records_processed = 0
        audit_text = {
            "ExtendedAttributes": "extended attribute",
            "AlternateDataStream": "alternate data stream",
            "Timestomp": "evidence of timestomping",
        }

        def write_findings(filename, findings):
            short = filename.replace("\\", "/").split("/")[-1]
            with open(anysd + "/analysis.csv", "a") as analysisfile:
                for kind, value in findings:
                    counts[kind] += 1
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

        # Timestomp findings wait for the whole MFT, to know which files came in a batch
        timestomps = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for record in iter_json_records(f):
                    records_processed += 1
                    findings = mft_findings(record)
                    if not findings:
                        continue
                    filename = str(record.get("full_path") or record.get("filename") or "unknown")
                    timestomps.extend((filename, v, record.get("created")) for k, v in findings if k == "Timestomp")
                    others = [(k, v) for k, v in findings if k != "Timestomp"]
                    if others:
                        write_findings(filename, others)
            batches = bulk_timestomps([(path, created) for path, _, created in timestomps])
            for index, (filename, value, _) in enumerate(timestomps):
                if value.endswith(SETUP_COPIED_NOTE):
                    benign[SETUP_COPIED_NOTE] += 1
                elif index in batches:
                    value += "|" + BULK_TIMESTOMP_NOTE.format(batches[index])
                    benign[BULK_TIMESTOMP_NOTE] += 1
                write_findings(filename, [("Timestomp", value)])
        except (OSError, ValueError) as e:
            print(" -> {} -> warning: could not analyse MFT JSON: {}".format(
                datetime.now().isoformat().replace("T", " "), str(e)[:100]
            ))
        # The technique comes from what was found, not from the MFT having been parsed
        if counts["Timestomp"] > sum(benign.values()):
            _record_techniques(os.path.join(output_directory, "mitre_techniques.txt"), ["T1070.006"])
        now = datetime.now().isoformat().replace("T", " ")
        print(" -> {} -> MFT analysis complete: {} records processed".format(now, records_processed))
        print(" -> {} ->   Extended Attributes (not Windows' own): {} files".format(now, counts["ExtendedAttributes"]))
        print(" -> {} ->   Timestomping indicators ($SI created before $FN; executables, scripts and archives in user-writable paths): {} files".format(now, counts["Timestomp"]))
        if benign[SETUP_COPIED_NOTE]:
            print(" -> {} ->     of which {} under Users\\Default or ProgramData\\Microsoft ({})".format(now, benign[SETUP_COPIED_NOTE], SETUP_COPIED_NOTE))
        if benign[BULK_TIMESTOMP_NOTE]:
            print(" -> {} ->     of which {} installed or extracted {} or more to a folder with the same times".format(now, benign[BULK_TIMESTOMP_NOTE], BULK_TIMESTOMP))
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

    stage = "analysing"
    # Safe parsing of img - handle both "image::type" and plain "image" formats
    # Extract basename since img may contain full path
    img_parts = img.split("::")
    img_name = img_parts[0].split("/")[-1]
    img_type = img_parts[1] if len(img_parts) > 1 else ""

    atftd = output_directory + img_name + "/artefacts/cooked/"
    anysd = output_directory + img_name + "/analysis/"
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
        if not os.path.exists(anysd + "/analysis.csv"):
            with open(anysd + "/analysis.csv", "w") as analysisfile:
                analysisfile.write(ANALYSIS_HEADER)
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
                    extension = f.rsplit(".", 1)[-1].lower() if "." in f else ""
                    if extension not in SIGNATURES and extension != "pdf":
                        continue
                    full = os.path.join(root, f)
                    try:
                        # Regular files only: a mounted image's symlinks point at the host, a FIFO blocks
                        if not stat.S_ISREG(os.lstat(full).st_mode):
                            continue
                        with open(full, "rb") as magic_file:
                            file_hdr = magic_file.read(HEADER_BYTES)
                    except OSError:
                        continue
                    path = "/" + os.path.relpath(full, mnt)
                    if not signature_mismatch(f, file_hdr) or SIGNATURE_EXEMPT.match(path):
                        continue
                    with open(anysd + "/analysis.csv", "a") as analysisfile:
                        analysisfile.write(
                            "{},{},{},File-signature (magic-byte) Discrepency,{}\n".format(
                                datetime.now().isoformat(),
                                vssimage.replace("'", ""),
                                path.replace(",", "%2C"),
                                file_hdr[:8].hex(" "),
                            )
                        )
                    entry, prnt = "{},{},{},file-signature (magic-byte) discrepency of '{}' for '{}'\n".format(
                        datetime.now().isoformat(), vssimage, stage, file_hdr[:8].hex(" "), f,
                    ), " -> {} -> identified file-signature (magic-byte) discrepency of '{}' from '{}' for {}".format(
                        datetime.now().isoformat().replace("T", " "), file_hdr[:8].hex(" "), f, vssimage,
                    )
                    write_audit_log_entry(verbosity, output_directory, entry, prnt)
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
                        if f.lower() in MFT_JSON_NAMES:
                            mft_files_found = True
                            analyse_mft_json(stage, vssimage, os.path.join(ar, f), anysd, verbosity, output_directory)
                        # Handle Artemis UUID-named output files
                        elif f == "status.log":
                            if _analyse_artemis_mft_from_status_log(ar, f, stage, vssimage, anysd, verbosity, output_directory, analyse_mft_json):
                                mft_files_found = True
                elif is_cooked_dir:
                    if f.lower() in MFT_JSON_NAMES:
                        mft_files_found = True
                        analyse_mft_json(stage, vssimage, os.path.join(ar, f), anysd, verbosity, output_directory)
                    # Handle Artemis UUID-named output files via status.log
                    elif f == "status.log":
                        if _analyse_artemis_mft_from_status_log(ar, f, stage, vssimage, anysd, verbosity, output_directory, analyse_mft_json):
                            mft_files_found = True
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
                                    if isinstance(sample_data, dict) and any(key in sample_data for key in MFT_ONLY_KEYS):
                                        print(" -> {} -> found potential MFT data in '{}'".format(
                                            datetime.now().isoformat().replace("T", " "), f
                                        ))
                                        mft_files_found = True
                                        analyse_mft_json(stage, vssimage, filepath, anysd, verbosity, output_directory)
                        except:
                            pass

        if not mft_files_found:
            # Not checked isn't the same as nothing found: say which it was
            print(" -> {} -> no $MFT for '{}': Extended Attributes, Alternate Data Streams and Timestomping not checked".format(
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
                        # lstat: an image's absolute symlinks resolve to the analysis host's own files
                        info = os.lstat(os.path.join(root, f))
                        if stat.S_ISREG(info.st_mode) and 0 < info.st_size < 10000000:  # 10MB
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
