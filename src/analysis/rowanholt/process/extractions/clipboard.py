#!/usr/bin/env python3 -tt
"""Windows clipboard history and activity: the SmartLookup view of ActivitiesCache.db, one record
per row, written as cooked/clipboard/<file>.jsonl."""
import json
import sqlite3
from datetime import datetime
from typing import Any, Dict, List

from rowanholt.audit import write_audit_log_entry
from rowanholt.core.records import SUFFIX, write_records

COLUMNS = ("AppId", "PackageIdHash", "AppActivityId", "ActivityType", "ActivityStatus", "ParentActivityId",
           "LastModifiedTime", "ExpirationTime", "Payload", "Priority", "IsLocalOnly", "PlatformDeviceId",
           "CreatedInCloud", "StartTime", "EndTime", "LastModifiedOnClient", "UserActionState", "ClipboardPayload",
           "IsRead", "ETag")


def _value(column: str, value: Any) -> Any:
    """A SmartLookup value as JSON can hold it: IDs as hex, payloads as their JSON or text."""
    if isinstance(value, bytes):
        if column == "ParentActivityId":
            return "0x" + value.hex()
        value = value.decode("utf-8", errors="replace")
    if column in ("Payload", "ClipboardPayload") and isinstance(value, str) and value[:1] in ("{", "["):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def clipboard_rows(database: str) -> List[Dict[str, Any]]:
    """Every row of the SmartLookup view, its columns named as Windows names them."""
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        rows = connection.execute(f"SELECT {', '.join('SmartLookup.' + c for c in COLUMNS)} FROM SmartLookup;").fetchall()
    finally:
        connection.close()
    return [{column: _value(column, value) for column, value in zip(COLUMNS, row)} for row in rows]


def extract_clipboard(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
    jsondict,
    jsonlist,
    clipjsonlist,
):
    entry, prnt = "{},{},{},'{}' ({}) clipboard evidence\n".format(
        datetime.now().isoformat(),
        vssimage.replace("'", ""),
        stage,
        artefact.split("/")[-1].split("_")[-1],
        artefact.split("/")[-1].split("+")[0],
    ), " -> {} -> {} '{}' ({}) for {}".format(
        datetime.now().isoformat().replace("T", " "),
        stage,
        artefact.split("/")[-1].split("_")[-1],
        artefact.split("/")[-1].split("+")[0],
        vssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    table = (output_directory + img.split("::")[0] + "/artefacts/cooked" + vss_path_insert + "clipboard/"
             + artefact.split("/")[-1])
    raw = artefact.find("/artefacts/")
    write_records(table + SUFFIX, clipboard_rows(artefact), host=img.split("::")[0],
                  artefact="clipboard/" + artefact.split("/")[-1],
                  source_path=artefact[raw + 1:] if raw >= 0 else artefact, time_field="LastModifiedTime")
    clipjsonlist.clear()
    jsonlist.clear()
