import subprocess
import json
import xml.etree.ElementTree as ET
from datetime import datetime

from rowanholt.audit import write_audit_log_entry


def extract_wmi(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
    jsondict,
    jsonlist,
    wmijsonlist,
):
    entry, prnt = "{},{},{},'{}' wmi evidence\n".format(
        datetime.now().isoformat(),
        vssimage.replace("'", ""),
        stage,
        artefact.split("/")[-1].split("_")[-1],
    ), " -> {} -> {} '{}' for {}".format(
        datetime.now().isoformat().replace("T", " "),
        stage,
        artefact.split("/")[-1].split("_")[-1],
        vssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)

    # Output paths
    output_xml = (
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "wmi/."
        + artefact.split("/")[-1]
        + ".xml"
    )
    output_json = (
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "wmi/"
        + artefact.split("/")[-1]
        + ".json"
    )

    try:
        # Run etl2xml to convert WMI ETL to XML
        result = subprocess.Popen(
            [
                "python3",
                "/opt/elrond/elrond/tools/etl-parser/bin/etl2xml",
                "-i",
                artefact,
                "-o",
                output_xml,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()

        # Parse XML and convert to JSON
        wmi_data = {
            "source": artefact.split("/")[-1],
            "extraction_time": datetime.now().isoformat(),
            "events": []
        }

        try:
            # Try to parse the XML output
            tree = ET.parse(output_xml)
            root = tree.getroot()

            # Extract events from XML
            for event in root.findall(".//Event"):
                event_data = {}
                for child in event:
                    if child.text:
                        event_data[child.tag] = child.text
                    # Handle nested elements
                    for subchild in child:
                        if subchild.text:
                            event_data[f"{child.tag}_{subchild.tag}"] = subchild.text

                if event_data:
                    wmi_data["events"].append(event_data)

        except ET.ParseError as e:
            wmi_data["error"] = f"XML parsing failed: {str(e)}"
            wmi_data["note"] = "etl2xml completed but output could not be parsed"
        except FileNotFoundError:
            wmi_data["error"] = "XML file not created by etl2xml"
            wmi_data["note"] = "etl2xml may have failed silently"

        # Write JSON output
        with open(output_json, "w") as wmijson:
            json.dump(wmi_data, wmijson, indent=2)

    except Exception as e:
        # Create error placeholder if WMI extraction fails
        error_data = {
            "error": f"WMI extraction failed: {str(e)}",
            "source": artefact.split("/")[-1],
            "extraction_time": datetime.now().isoformat()
        }
        with open(output_json, "w") as wmijson:
            json.dump(error_data, wmijson, indent=2)

        if verbosity != "":
            print(f"     Warning: WMI extraction failed for {artefact.split('/')[-1]}: {e}")

    # Clear lists after processing
    wmijsonlist.clear()
    jsonlist.clear()
