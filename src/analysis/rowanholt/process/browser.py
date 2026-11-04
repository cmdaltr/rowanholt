#!/usr/bin/env python3 -tt
import json
import os
import re
import sqlite3
from datetime import datetime

from rowanholt.audit import write_audit_log_entry

# Track which browser directories have been processed to avoid duplicates
_processed_browser_dirs = set()

# MITRE ATT&CK mappings for browser artefacts
BROWSER_MITRE_MAPPING = {
    "browser_history": {
        "technique_id": "T1071.001",
        "technique_name": "Web Protocols",
        "tactics": ["Command and Control"],
        "groups": ["APT28", "APT29", "Turla", "OilRig", "Kimsuky"]
    },
    "browser_download": {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactics": ["Command and Control"],
        "groups": ["APT1", "APT28", "APT29", "OilRig", "Scattered Spider", "Lazarus Group"]
    },
}


def process_browser_index(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
):
    """Process Internet Explorer index.dat files and output as JSON."""
    # Create a unique key for this browser directory to avoid reprocessing
    browser_dir_key = output_directory + img.split("::")[0] + "/artefacts/raw" + vss_path_insert + "browsers"
    if browser_dir_key in _processed_browser_dirs:
        return
    _processed_browser_dirs.add(browser_dir_key)

    browsers_output_dir = (
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "browsers"
    )
    os.makedirs(browsers_output_dir, exist_ok=True)

    browsers_raw_dir = (
        output_directory
        + img.split("::")[0]
        + "/artefacts/raw"
        + vss_path_insert
        + "browsers"
    )

    if not os.path.exists(browsers_raw_dir):
        return

    for indexuser in os.listdir(browsers_raw_dir):
        index_dat_path = os.path.join(browsers_raw_dir, indexuser, "ie/History.IE5/index.dat")
        if os.path.exists(index_dat_path):
            entry, prnt = "{},{},{},({}) '{}' browser artefact\n".format(
                datetime.now().isoformat(),
                vssimage.replace("'", ""),
                stage,
                artefact.split("/")[-1],
                indexuser,
            ), " -> {} -> {} browser artefact '{}' ({}) from {}".format(
                datetime.now().isoformat().replace("T", " "),
                stage,
                artefact.split("/")[-1],
                indexuser,
                vssimage,
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)

            ie_output_dir = os.path.join(browsers_output_dir, "ie")
            os.makedirs(ie_output_dir, exist_ok=True)

            output_file = os.path.join(ie_output_dir, f"{indexuser}+index.dat.json")

            history_entries = []
            try:
                with open(artefact, encoding="ISO-8859-1") as indexdat:
                    indexdata = indexdat.read()

                cleaned_data = re.sub(
                    r"[^A-Za-z\d\_\-\ \.\,\;\:\"\'\/\?\!\<\>\@\(\)\[\]\{\}\&\=\+\*\%\#\^\~\`\\\|\$\£\€]",
                    r",",
                    indexdata,
                )

                for eachindex in str(cleaned_data).split("Visited:")[1:]:
                    try:
                        indexentry = (
                            str(
                                re.sub(
                                    r"<\|>\S\S<\|>[^A-Za-z\d\-]",
                                    r"<|>",
                                    str(
                                        str(
                                            eachindex.split("@")[0]
                                            + "<|>"
                                            + eachindex.split("@")[1]
                                            .split("URL")[0]
                                            .split("@")[0]
                                            .replace("\\", "/")
                                        )
                                        .strip()
                                        .strip(",")
                                    )
                                    .replace(",,,,,,,,,,,,,,,,", "")
                                    .replace(",,", "<|>")
                                    .replace(",,", "<|>")
                                    .replace(",,", "<|>")
                                    .replace("<|><|>", "<|>")
                                    .replace("<|><|>", "<|>")
                                    .replace("<|><|>", "<|>"),
                                )
                            )
                            + "<|>-<|>-"
                        )
                        parts = indexentry.split("<|>")
                        profile = parts[0].lower() if len(parts) > 0 else ""

                        protocol = ""
                        site = ""
                        if len(parts) > 1:
                            url_part = parts[1]
                            protocol = url_part.split(":")[0] if ":" in url_part else ""
                            site_parts = url_part.split(":")[1:] if ":" in url_part else []
                            site = (
                                str(site_parts)
                                .replace("///", "")
                                .replace("//", "")
                                .replace("['", "")
                                .replace("', '", ":")
                                .strip("']")
                                .strip(";")
                                .split(",")[0]
                            )

                        details = parts[2] if len(parts) > 2 else "-"
                        description = parts[3] if len(parts) > 3 else "-"

                        # Clean up details and description
                        details = re.sub(r"(\S),(\S)", r"\1\2", details).strip(",").replace(", ,", " ")
                        description = re.sub(r"(\S),(\S)", r"\1\2", description).strip(",").replace(", ,", " ")

                        if len(details) < 5:
                            details = "-"
                        if len(description) < 5:
                            description = "-"

                        if "/" in site:
                            details = site
                            site = (
                                details.replace("https://", "")
                                .replace("http://", "")
                                .split("/")[0]
                            )

                        history_entries.append({
                            "user": profile,
                            "protocol": protocol,
                            "domain": site,
                            "url": details,
                            "description": description,
                            "browser": "Internet Explorer",
                            "artifact_type": "browser_history",
                            "mitre_technique_id": BROWSER_MITRE_MAPPING["browser_history"]["technique_id"],
                            "mitre_technique_name": BROWSER_MITRE_MAPPING["browser_history"]["technique_name"],
                            "mitre_tactics": BROWSER_MITRE_MAPPING["browser_history"]["tactics"],
                            "mitre_groups": BROWSER_MITRE_MAPPING["browser_history"]["groups"],
                        })
                    except:
                        pass
            except Exception as e:
                if verbosity != "":
                    print(f"     Warning: Error processing index.dat: {e}")

            # Write JSON output
            with open(output_file, "w") as f:
                json.dump(history_entries, f, indent=2)

            # Write technique ID to techniques file for Navigator at CASE level
            if history_entries:
                techniques_file_path = os.path.join(
                    output_directory,
                    "mitre_techniques.txt"
                )
                try:
                    with open(techniques_file_path, 'a') as tf:
                        tf.write(f"{BROWSER_MITRE_MAPPING['browser_history']['technique_id']}\n")
                except:
                    pass


def process_browser(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
):
    """Process browser history databases (Chrome, Edge, Firefox, Safari) and output as JSON."""
    browsers_output_dir = (
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "browsers"
    )
    os.makedirs(browsers_output_dir, exist_ok=True)

    # Determine browser type
    if "Edge" in artefact:
        browser_name = "Edge"
        browser_type = "edge"
    elif "chrome" in artefact:
        browser_name = "Chrome"
        browser_type = "chrome"
    elif "safari" in artefact:
        browser_name = "Safari"
        browser_type = "safari"
    elif "firefox" in artefact:
        browser_name = "Firefox"
        browser_type = "firefox"
    else:
        browser_name = "Unknown"
        browser_type = "unknown"


    entry, prnt = "{},{},{},'{}' ({}) {} browser artefact\n".format(
        datetime.now().isoformat(),
        vssimage.replace("'", ""),
        stage,
        artefact.split("/")[-1],
        artefact.split("/")[-3],
        artefact.split("/")[-2],
    ), " -> {} -> {} {} browser artefact '{}' ({}) from {}".format(
        datetime.now().isoformat().replace("T", " "),
        stage,
        artefact.split("/")[-2],
        artefact.split("/")[-1],
        artefact.split("/")[-3],
        vssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)

    # Create browser-specific output directory
    browser_subdir = artefact.split("/raw/")[1].split("/")[2] if "/raw/" in artefact else browser_type
    browser_output_dir = os.path.join(browsers_output_dir, browser_subdir)
    os.makedirs(browser_output_dir, exist_ok=True)

    # Determine output filename
    user_profile = artefact.split("/raw/")[1].split("/")[1] if "/raw/" in artefact else "default"
    artifact_name = artefact.split("/")[-1]

    history_entries = []
    download_entries = []

    try:
        if artefact.endswith("/Edge/History") or artefact.endswith("/chrome/History"):
            # Chrome/Edge SQLite processing
            conn = sqlite3.connect(artefact)
            cursor = conn.cursor()

            # Get history
            try:
                cursor.execute(
                    """SELECT urls.id, urls.url, urls.title, urls.visit_count,
                       datetime(urls.last_visit_time / 1000000 + (strftime('%s', '1601-01-01')), 'unixepoch', 'localtime')
                       FROM urls;"""
                )
                url_items = cursor.fetchall()

                cursor.execute("SELECT visits.id, visits.from_visit FROM visits;")
                visits = cursor.fetchall()
                visit_dict = {v[0]: v[1] for v in visits}

                for item in url_items:
                    url_id, url, title, visit_count, last_visit = item
                    from_visit = visit_dict.get(url_id, 0)

                    history_entries.append({
                        "url": url or "",
                        "title": title or "",
                        "visit_count": visit_count or 0,
                        "from_visit": from_visit,
                        "timestamp": last_visit or "",
                        "browser": browser_name,
                        "user": user_profile,
                        "artifact_type": "browser_history",
                        "mitre_technique_id": BROWSER_MITRE_MAPPING["browser_history"]["technique_id"],
                        "mitre_technique_name": BROWSER_MITRE_MAPPING["browser_history"]["technique_name"],
                        "mitre_tactics": BROWSER_MITRE_MAPPING["browser_history"]["tactics"],
                        "mitre_groups": BROWSER_MITRE_MAPPING["browser_history"]["groups"],
                    })
            except Exception as e:
                if verbosity != "":
                    print(f"     Warning: Error reading history: {e}")

            # Get downloads
            try:
                cursor.execute(
                    """SELECT downloads.url, downloads.full_path, downloads.start_time,
                       downloads.end_time, downloads.received_bytes, downloads.total_bytes
                       FROM downloads;"""
                )
                downloads = cursor.fetchall()

                for dl in downloads:
                    url, path, start_time, end_time, received, total = dl
                    download_entries.append({
                        "url": url or "",
                        "file_path": (path or "").replace("\\", "/"),
                        "start_time": str(start_time) if start_time else "",
                        "end_time": str(end_time) if end_time else "",
                        "received_bytes": received or 0,
                        "total_bytes": total or 0,
                        "browser": browser_name,
                        "user": user_profile,
                        "artifact_type": "browser_download",
                        "mitre_technique_id": BROWSER_MITRE_MAPPING["browser_download"]["technique_id"],
                        "mitre_technique_name": BROWSER_MITRE_MAPPING["browser_download"]["technique_name"],
                        "mitre_tactics": BROWSER_MITRE_MAPPING["browser_download"]["tactics"],
                        "mitre_groups": BROWSER_MITRE_MAPPING["browser_download"]["groups"],
                    })
            except:
                pass

            conn.close()

        elif artefact.endswith("places.sqlite"):
            # Firefox SQLite processing
            conn = sqlite3.connect(artefact)
            cursor = conn.cursor()

            # Get history
            try:
                cursor.execute(
                    """SELECT moz_places.id, moz_places.url, moz_places.title,
                       moz_places.visit_count, moz_places.last_visit_date
                       FROM moz_places;"""
                )
                places = cursor.fetchall()

                cursor.execute(
                    "SELECT moz_historyvisits.id, moz_historyvisits.from_visit FROM moz_historyvisits;"
                )
                visits = cursor.fetchall()
                visit_dict = {v[0]: v[1] for v in visits}

                for place in places:
                    place_id, url, title, visit_count, last_visit = place
                    from_visit = visit_dict.get(place_id, 0)

                    # Convert Firefox timestamp (microseconds since epoch)
                    timestamp = ""
                    if last_visit:
                        try:
                            timestamp = str(datetime.fromtimestamp(float(last_visit) / 1000000))
                        except:
                            pass

                    history_entries.append({
                        "url": url or "",
                        "title": title or "",
                        "visit_count": visit_count or 0,
                        "from_visit": from_visit,
                        "timestamp": timestamp,
                        "browser": browser_name,
                        "user": user_profile,
                        "artifact_type": "browser_history",
                        "mitre_technique_id": BROWSER_MITRE_MAPPING["browser_history"]["technique_id"],
                        "mitre_technique_name": BROWSER_MITRE_MAPPING["browser_history"]["technique_name"],
                        "mitre_tactics": BROWSER_MITRE_MAPPING["browser_history"]["tactics"],
                        "mitre_groups": BROWSER_MITRE_MAPPING["browser_history"]["groups"],
                    })
            except Exception as e:
                if verbosity != "":
                    print(f"     Warning: Error reading Firefox history: {e}")

            # Get downloads from moz_annos
            try:
                cursor.execute(
                    """SELECT moz_annos.place_id, moz_annos.content, moz_annos.type,
                       moz_annos.dateAdded, moz_annos.lastModified
                       FROM moz_annos;"""
                )
                annos = cursor.fetchall()

                for anno in annos:
                    place_id, content, anno_type, date_added, last_modified = anno
                    download_entries.append({
                        "place_id": place_id,
                        "content": content or "",
                        "type": anno_type,
                        "date_added": str(date_added) if date_added else "",
                        "last_modified": str(last_modified) if last_modified else "",
                        "browser": browser_name,
                        "user": user_profile,
                        "artifact_type": "browser_download",
                        "mitre_technique_id": BROWSER_MITRE_MAPPING["browser_download"]["technique_id"],
                        "mitre_technique_name": BROWSER_MITRE_MAPPING["browser_download"]["technique_name"],
                        "mitre_tactics": BROWSER_MITRE_MAPPING["browser_download"]["tactics"],
                        "mitre_groups": BROWSER_MITRE_MAPPING["browser_download"]["groups"],
                    })
            except:
                pass

            conn.close()

        elif "safari" in artefact and artefact.endswith("History.db"):
            # Safari SQLite processing
            conn = sqlite3.connect(artefact)
            cursor = conn.cursor()

            try:
                cursor.execute(
                    "SELECT history_items.id, history_items.url, history_items.visit_count FROM history_items;"
                )
                items = cursor.fetchall()

                cursor.execute(
                    """SELECT history_visits.history_item, history_visits.title,
                       history_visits.origin, history_visits.visit_time
                       FROM history_visits;"""
                )
                visits = cursor.fetchall()

                visit_dict = {}
                for v in visits:
                    visit_dict[v[0]] = {"title": v[1], "origin": v[2], "visit_time": v[3]}

                for item in items:
                    item_id, url, visit_count = item
                    visit_info = visit_dict.get(item_id, {})

                    # Convert Safari timestamp (seconds since 2001-01-01)
                    timestamp = ""
                    visit_time = visit_info.get("visit_time")
                    if visit_time:
                        try:
                            timestamp = str(datetime.fromtimestamp(int(visit_time) + 978307200))
                        except:
                            pass

                    history_entries.append({
                        "url": url or "",
                        "title": visit_info.get("title", ""),
                        "visit_count": visit_count or 0,
                        "from_visit": visit_info.get("origin", 0),
                        "timestamp": timestamp,
                        "browser": browser_name,
                        "user": user_profile,
                        "artifact_type": "browser_history",
                        "mitre_technique_id": BROWSER_MITRE_MAPPING["browser_history"]["technique_id"],
                        "mitre_technique_name": BROWSER_MITRE_MAPPING["browser_history"]["technique_name"],
                        "mitre_tactics": BROWSER_MITRE_MAPPING["browser_history"]["tactics"],
                        "mitre_groups": BROWSER_MITRE_MAPPING["browser_history"]["groups"],
                    })
            except Exception as e:
                if verbosity != "":
                    print(f"     Warning: Error reading Safari history: {e}")

            conn.close()

    except Exception as e:
        if verbosity != "":
            print(f"     Warning: Error processing browser database: {e}")

    # Write history JSON
    history_output = os.path.join(browser_output_dir, f"{user_profile}+{artifact_name}.json")
    with open(history_output, "w") as f:
        json.dump(history_entries, f, indent=2)

    # Write technique IDs to techniques file for Navigator at CASE level
    techniques_file_path = os.path.join(
        output_directory,
        "mitre_techniques.txt"
    )
    try:
        with open(techniques_file_path, 'a') as tf:
            if history_entries:
                tf.write(f"{BROWSER_MITRE_MAPPING['browser_history']['technique_id']}\n")
            if download_entries:
                tf.write(f"{BROWSER_MITRE_MAPPING['browser_download']['technique_id']}\n")
    except:
        pass

    # Write downloads JSON if there are any
    if download_entries:
        downloads_output = os.path.join(browser_output_dir, f"{user_profile}+{artifact_name}_downloads.json")
        with open(downloads_output, "w") as f:
            json.dump(download_entries, f, indent=2)
