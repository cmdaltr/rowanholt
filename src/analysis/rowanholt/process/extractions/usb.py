#!/usr/bin/env python3 -tt
import json
import re

from rowanholt.core.records import write_cooked


def extract_usb(
    output_directory,
    img,
    vss_path_insert,
    jsondict,
    jsonlist,
    setupdata,
    source="",
):
    """setupapi.dev.log's device installs, one record per section, into cooked/usb.log.jsonl."""
    for session in setupdata.split("[Boot Session: ")[0][21:-14].split("     "):
        for eachkv in re.findall(r"^(?P<k>[^\=]+)\ \=\ (?P<v>[\S]+)", session):
            kv = list(eachkv)
            if len(kv) > 0:
                jsondict[kv[0]] = kv[1]
    if len(jsondict) > 0:
        jsonlist.append(json.dumps(jsondict))
        jsondict.clear()
    for session in setupdata.split("[Boot Session: ")[1:]:
        for section in session.split(">>>  ["):
            jsondict["BootDateStart"], jsondict["BootTimeStart"] = (
                session[0:10],
                session[11:23],
            )
            if len(section) > 26:
                (
                    jsondict["Artefact"],
                    jsondict["Status"],
                    jsondict["StartDate"],
                    jsondict["StartTime"],
                ) = (
                    section.split(">>>  ")[0][0:-2],
                    section.split("<<<  ")[-1].split(": ")[1][0:-4],
                    section.split(">>>  ")[1].split("<<<  ")[0][14:24],
                    section.split(">>>  ")[1].split("<<<  ")[0][25:37],
                )
                try:
                    (
                        jsondict["SectionEndDate"],
                        jsondict["SectionEndTime"],
                    ) = (
                        section.split(">>>  ")[1].split("<<<  ")[1][12:][0:10],
                        section.split(">>>  ")[1].split("<<<  ")[1][12:][11:23],
                    )
                except:
                    pass
                for eachinfo in (
                    section.split(">>>  ")[1].split("<<<  ")[0][38:].split("\n")
                ):
                    for eachkv in re.findall(
                        r"^\ +(?P<ActionInstruction>[A-Za-z]+)\:\ +(?P<ActionObject>[\S\ ]+)",
                        eachinfo.replace("!", "")
                        .replace("__", "_")
                        .replace("__", "_")
                        .strip("."),
                    ):
                        kv = list(eachkv)
                        if len(kv) > 0:
                            (
                                jsondict["ActionObject"],
                                jsondict["ActionInstruction"],
                            ) = (kv[1], kv[0])
                    for eachkv in re.findall(
                        r"\ (?P<ActionTime>\d{2}\:\d{2}\:\d{2}\.\d{3})",
                        eachinfo.replace("__", "_").replace("__", "_").strip("."),
                    ):
                        jsondict["ActionTime"] = eachkv
                    if len(jsondict) > 8:
                        jsonlist.append(json.dumps(jsondict))
                        jsondict.clear()
    records = []
    for each in jsonlist:
        record = json.loads(each)
        if record.get("StartDate") and record.get("StartTime"):
            record["LastWriteTime"] = f"{record['StartDate']} {record['StartTime']}"
        records.append(record)
    jsonlist.clear()
    write_cooked(output_directory + img.split("::")[0] + "/artefacts/cooked" + vss_path_insert + "usb.log",
                 records, source, "LastWriteTime")
