#!/usr/bin/env python3 -tt
import json
import os
import shlex
import subprocess
from datetime import datetime

from rowanholt.audit import write_audit_log_entry
from rowanholt.core.records import SUFFIX, write_records
from rowanholt.process.extractions.mitre_tagger import tag_mitre_technique


def journal_records(output: bytes):
    """journalctl --output=json's records: it writes one JSON object per line already. A field
    journald couldn't store as text comes as a list of byte values; it's decoded where it can be."""
    for line in output.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        for key, value in record.items():
            if isinstance(value, list) and all(isinstance(b, int) and 0 <= b < 256 for b in value):
                record[key] = bytes(value).decode("utf-8", errors="replace")
        yield record


def process_journal(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
):
    cooked = output_directory + img.split("::")[0] + "/artefacts/cooked" + vss_path_insert
    journal_outfile = cooked + "journalctl" + SUFFIX
    if not os.path.exists(journal_outfile):
        os.makedirs(cooked, exist_ok=True)
        journal_command = shlex.split(
            'journalctl -D {} --all --output=json'.format(
                "/".join(artefact.split("/")[0:-1])
            )
        )
        journal_command_output = subprocess.Popen(
            journal_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()[0]
        entry, prnt = "{},{},{},systemd journals\n".format(
            datetime.now().isoformat(),
            vssimage.replace("'", ""),
            stage,
        ), " -> {} -> {} systemd journals from {}".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        journal_dir = "/".join(artefact.split("/")[0:-1])
        raw = journal_dir.find("/artefacts/")
        # __REALTIME_TIMESTAMP: when journald received the entry, in microseconds since the epoch
        write_records(journal_outfile, journal_records(journal_command_output), host=img.split("::")[0],
                      artefact="journalctl", source_path=journal_dir[raw + 1:] if raw >= 0 else journal_dir,
                      time_field="__REALTIME_TIMESTAMP")
        # Tag MITRE technique for journal processing
        tag_mitre_technique(output_directory, img, "journal")
