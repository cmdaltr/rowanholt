#!/usr/bin/env python3 -tt
import csv
import glob
import json
import os
import re
import shlex
import shutil
import subprocess
import time
import urllib.request
import urllib.error
import ssl
import base64
from datetime import datetime
from io import StringIO

from rivendell.audit import write_audit_log_entry
from rivendell.post.siem import memory_outputs, siem_hosts


def normalize_timestamp(record):
    """
    Normalize timestamp fields to @timestamp for Kibana compatibility.
    Looks for common timestamp field names and copies to @timestamp.
    """
    if isinstance(record, dict):
        # Already has @timestamp, skip
        if '@timestamp' in record and record['@timestamp']:
            return record

        # List of possible timestamp field names (in priority order)
        timestamp_fields = [
            'timestamp',
            'LastWriteTime',
            'SystemTime',
            'LastWrite',
            'Time',
            'DateTime',
            'EventTime',
            'Created',
            'Modified',
            'modified',      # MFT/filesystem artifacts (lowercase)
            'created',
            'accessed',
            'changed',
            'start_time',    # Process/execution artifacts
            'end_time',
            'last_run',
            'run_time',
        ]

        for field in timestamp_fields:
            if field in record and record[field]:
                record['@timestamp'] = record[field]
                break

    return record


def split_large_csv_files(root_dir):
    for atftroot, _, atftfiles in os.walk(root_dir):
        for (
            atftfile
        ) in (
            atftfiles
        ):  # spliting the large csv files into smaller chunks for easing ingestion
            if os.path.exists(os.path.join(atftroot, atftfile)):
                if os.path.getsize(
                    os.path.join(atftroot, atftfile)
                ) > 52427769 and atftfile.endswith(".csv"):
                    subprocess.Popen(
                        [
                            "split",
                            "-C",
                            "20m",
                            "--numeric-suffixes",
                            os.path.join(atftroot, atftfile),
                            "{}-split".format(os.path.join(atftroot, atftfile[0:-4])),
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).communicate()[0]
    time.sleep(0.2)


def prepare_csv_to_ndjson(root_dir):
    for atftroot, _, atftfiles in os.walk(root_dir):
        for atftfile in atftfiles:  # renaming the split files with the .csv extension
            if "-split" in atftfile:
                os.rename(
                    os.path.join(atftroot, atftfile),
                    os.path.join(atftroot, atftfile + ".csv"),
                )
    for atftroot, _, atftfiles in os.walk(root_dir):
        for atftfile in atftfiles:  # adding header to split csv files
            if (
                "-split" in atftfile
                and "journal_mft" in atftfile
                and atftfile.endswith(".csv")
                and "00" not in atftfile
            ):
                with open(
                    os.path.join(atftroot, ".adding_header_" + atftfile),
                    "a",
                ) as adding_header:
                    adding_header.write(
                        "record,state,active,record_type,seq_number,parent_file_record,parent_file_record_seq,std_info_creation_date,std_info_modification_date,std_info_access_date,std_info_entry_date,object_id,birth_volume_id,birth_object_id,birth_domain_id,std_info,attribute_list,has_filename,has_object_id,volume_name,volume_info,data,index_root,index_allocation,bitmap,reparse_point,ea_information,ea,property_set,logged_utility_stream,log/notes,stf_fn_shift,usec_zero,ads,possible_copy,possible_volume_move,Filename,fn_info_creation_date,fn_info_modification_date,fn_info_access_date,fn_info_entry_date,LastWriteTime\n"
                    )
                    with open(os.path.join(atftroot, atftfile)) as read_split_file:
                        for eachcsvrow in read_split_file:
                            adding_header.write(eachcsvrow)
                os.remove(os.path.join(atftroot, atftfile))
    for atftroot, _, atftfiles in os.walk(root_dir):
        for atftfile in atftfiles:  # renaming the split files, with headers
            if (
                "-split" in atftfile
                and ".adding_header_" in atftfile
                and "journal_mft" in atftfile
                and atftfile.endswith(".csv")
            ):
                os.rename(
                    os.path.join(atftroot, atftfile),
                    os.path.join(atftroot, atftfile.split(".adding_header_")[-1]),
                )
    time.sleep(0.2)


def convert_csv_to_ndjson(output_directory, case, img, root_dir):
    for atftroot, _, atftfiles in os.walk(root_dir):
        for atftfile in atftfiles:  # converting csv files to ndjson
            if (
                os.path.getsize(os.path.join(atftroot, atftfile)) > 0
                and atftfile.endswith(".csv")
                and os.path.getsize(os.path.join(atftroot, atftfile)) < 52427770
            ):
                if atftfile.endswith(".csv"):
                    with open(
                        os.path.join(atftroot, atftfile), encoding="utf-8"
                    ) as read_csv:
                        # try/catch with file-reading error
                        csv_results = csv.DictReader(read_csv)
                        with open(
                            os.path.join(atftroot, atftfile)[0:-4] + ".ndjson",
                            "a",
                            encoding="utf-8",
                        ) as write_json:
                            for result in csv_results:
                                data = (
                                    str(result)[2:]
                                    .replace("': '", '": "')
                                    .replace("', '", '", "')
                                    .replace("'}", '"}')
                                    .replace("': None", '": None')
                                    .replace("\": None, '", '": None, "')
                                    .replace("': \"", '": "')
                                    .replace("\", '", '", "')
                                    .replace('"-": "-", ', "")
                                    .replace('"": "", ', "")
                                )
                                if "+index.dat" in atftfile:
                                    malformed_indexdat_data = re.findall(
                                        r"(.*\"Domain\": \")([\S\s]+)(\"url\".*)",
                                        data,
                                    )
                                    reformed_data = (
                                        malformed_indexdat_data[0][1]
                                        .replace("(", "%28")
                                        .replace(")", "%29")
                                        .replace("{", "%7B")
                                        .replace("}", "%7D")
                                        .replace('"', "%22")
                                    )
                                    reformed_data = re.sub(
                                        r'(Description": "[^"]+)(\}$)',
                                        r'\1"\2',
                                        reformed_data,
                                    )
                                    if reformed_data.endswith("%22, "):
                                        reformed_data = reformed_data.replace(
                                            "%22, ", '", '
                                        )
                                    reformed_data.replace("\" ', ", '"').replace(
                                        "\\\\\\", "\\\\"
                                    )
                                    data = "{}{}{}".format(
                                        malformed_indexdat_data[0][0],
                                        reformed_data.replace("\\\\\\", "\\\\").replace(
                                            "\\\\\\", "\\\\"
                                        ),
                                        malformed_indexdat_data[0][2],
                                    )
                                # inserting timestamp now() as no timestamp exists
                                if (
                                    "_index" not in data
                                    and "LastWrite" not in data
                                    and "@timestamp" not in data
                                ):
                                    time_insert = '", "@timestamp": "{}'.format(
                                        datetime.now().isoformat().replace("T", " ")
                                    )
                                else:
                                    time_insert = ""
                                data = '{{"index": {{"_index": "{}"}}}}\n{{"hostname": "{}", "artefact": "{}{}", "{}\n\n'.format(
                                    case.lower(),
                                    img.split("::")[0],
                                    atftfile,
                                    time_insert,
                                    data.replace("SystemTime", "@timestamp")
                                    .replace("LastWriteTime", "@timestamp")
                                    .replace("LastWrite Time", "@timestamp")
                                    .replace('"LastWrite": "', '"@timestamp": "')
                                    .replace(
                                        '"@timestamp": "@timestamp ',
                                        '"@timestamp": "',
                                    ),
                                )
                                data = re.sub(r'(": )(None)([,:\}])', r'\1"\2"\3', data)
                                data = data.replace("', None: ['", '", "None": ["')
                                data = re.sub(r'(": \["[^\']+)\'(\])', r'\1"\2', data)
                                converted_timestamp = convert_timestamps(data)
                                write_json.write(
                                    re.sub(
                                        r'([^\{\[ ])"([^:,\}])',
                                        r"\1%22\2",
                                        re.sub(
                                            r'([^:,] )"([^:,])',
                                            r"\1%22\2",
                                            converted_timestamp,
                                        ),
                                    )
                                )
                        prepare_elastic_ndjson(
                            output_directory,
                            img,
                            case.lower(),
                            os.path.join(atftroot, atftfile)[0:-4] + ".ndjson",
                        )
    time.sleep(0.2)


def convert_json_to_ndjson(output_directory, case, img, root_dir):
    for atftroot, _, atftfiles in os.walk(root_dir):
        for atftfile in atftfiles:  # converting json files to ndjson
            if os.path.getsize(
                os.path.join(atftroot, atftfile)
            ) > 0 and atftfile.endswith(".json"):
                try:
                    with open(os.path.join(atftroot, atftfile)) as read_json:
                        json_content = read_json.read()
                    in_json = StringIO(json_content)
                    results = [json.dumps(record) for record in json.load(in_json)]
                    with open(
                        os.path.join(atftroot, atftfile)[0:-5] + ".ndjson", "w"
                    ) as write_json:
                        for result in results:
                            if result != "{}":
                                data = '{{"index": {{"_index": "{}"}}}}\n{{"hostname": "{}", "artefact": "{}", {}\n\n'.format(
                                    case.lower(),
                                    img.split("::")[0],
                                    atftfile,
                                    result[1:]
                                    .replace("SystemTime", "@timestamp")
                                    .replace("LastWriteTime", "@timestamp")
                                    .replace("LastWrite Time", "@timestamp")
                                    .replace('"LastWrite": "', '"@timestamp": "')
                                    .replace(
                                        '"@timestamp": "@timestamp ',
                                        '"@timestamp": "',
                                    ),
                                )
                                data = re.sub(r'(": )(None)([,:\}])', r'\1"\2"\3', data)
                                converted_timestamp = convert_timestamps(data)
                                write_json.write(converted_timestamp)
                    prepare_elastic_ndjson(
                        output_directory,
                        img,
                        case.lower(),
                        os.path.join(atftroot, atftfile)[0:-5] + ".ndjson",
                    )
                except:
                    print(
                        "       Could not ingest\t'{}'\t- perhaps the json did not format correctly?".format(
                            atftfile
                        )
                    )
    time.sleep(0.2)


def convert_timestamps(data):
    # yyyy/MM/dd HH:mm:ss.SSS
    converted_timestamp_formats = re.sub(
        r"(@timestamp\": \"\d{4})/(\d{2})/(\d{2}) (\d{2}:\d{2}:\d{2}\.\d{3}[^\d])",
        r"\1-\2-\3 \4 000",
        data,
    )
    # yyyy-MM-dd HH:mm:ssZ/yyyy-MM-dd HH:mm:ss
    converted_timestamp_formats = re.sub(
        r"(@timestamp\": \"\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})Z?",
        r"\1 \2\.000000",
        converted_timestamp_formats,
    )
    # MM/dd/yy HH:mm:ss
    converted_timestamp_formats = re.sub(
        r"(@timestamp\": \"\d{2})/(\d{2})/(\d{2}) (\d{2}:\d{2}:\d{2})",
        r"\1-\2-\3 \4\.000000",
        converted_timestamp_formats,
    )
    # evtx files and $I30
    return (
        converted_timestamp_formats.replace(" 000", "000")
        .replace("000000.", ".")
        .replace("\\.000000", ".000000")
        .replace("\\..", ".")
    )


def ingest_elastic_ndjson(case, ndjsonfile):
    ingest_data_command = shlex.split(
        'curl -s -H "Content-Type: application/x-ndjson" -XPOST localhost:9200/{}/_doc/_bulk?pretty --data-binary @"{}"'.format(
            case.lower(), ndjsonfile
        )
    )
    ingested_data = subprocess.Popen(
        ingest_data_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()[0]
    if "Unexpected character" in str(ingested_data) or 'failed" : 1' in str(
        ingested_data
    ):
        print(
            "       Could not ingest\t'{}'\t- perhaps the json did not format correctly?".format(
                ndjsonfile.split("/")[-1]
            )
        )


def prepare_elastic_ndjson(output_directory, img, case, source_location):
    if not os.path.exists(
        os.path.join(output_directory + img.split("::")[0] + "/elastic/")
    ):
        os.makedirs(os.path.join(output_directory + img.split("::")[0] + "/elastic/"))
        os.makedirs(
            os.path.join(output_directory + img.split("::")[0] + "/elastic/documents/")
        )
    if "/vss" in source_location:
        vss_path_insert = "/vss{}".format(
            source_location.split("/vss")[1].split("/")[0]
        )
        if not os.path.exists(
            os.path.join(
                output_directory
                + img.split("::")[0]
                + "/elastic/documents{}".format(vss_path_insert)
            )
        ):
            os.makedirs(
                os.path.join(
                    output_directory
                    + img.split("::")[0]
                    + "/elastic/documents{}".format(vss_path_insert)
                )
            )
    else:
        vss_path_insert = ""
    ndjsonfile = os.path.join(
        output_directory + img.split("::")[0] + "/elastic/documents{}/{}"
    ).format(vss_path_insert, source_location.split("/")[-1])
    shutil.move(source_location, ndjsonfile)
    try:
        ingest_elastic_ndjson(case, ndjsonfile)
    except:
        print(
            "       Could not ingest\t'{}'\t- perhaps the json did not format correctly?".format(
                ndjsonfile.split("/")[-1]
            )
        )


def ingest_elastic_data(
    verbosity,
    output_directory,
    case,
    stage,
    allimgs,
):
    imgs_to_ingest = []
    for _, img in allimgs.items():
        if img not in imgs_to_ingest:
            imgs_to_ingest.append(img)
        if not os.path.exists(output_directory + img.split("::")[0] + "/elastic/"):
            os.makedirs(
                os.path.join(output_directory + img.split("::")[0] + "/elastic")
            )
            os.makedirs(
                os.path.join(
                    output_directory + img.split("::")[0] + "/elastic/documents/"
                )
            )
    # creating index based on case name in elasticsearch
    make_index = shlex.split(
        'curl -X PUT "localhost:9200/{}?pretty" -H "Content-Type: application/json" -d\'{{"mappings": {{"properties": {{"@timestamp": {{"type": "date", "format": "strict_date_optional_time||yyyy-MM-dd HH:mm:ss.SSSSSS||yyyy-MM-dd HH:mm:ss||yyyy-MM-dd\'T\'HH:mm:ss.SSS\'Z\'||yyyy-MM-dd\'T\'HH:mm:ss||epoch_millis"}}}}}}}}\''.format(
            case.lower()
        )
    )
    subprocess.Popen(
        make_index,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()[0]
    # increasing field limitations in elasticsearch
    increase_index_limit = shlex.split(
        'curl -X PUT  -H "Content-Type: application/x-ndjson" localhost:9200/{}/_settings?pretty -d \'{{"index.mapping.total_fields.limit": 1000000}}\''.format(
            case.lower()
        )
    )
    subprocess.Popen(
        increase_index_limit, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).communicate()[0]
    # creating index pattern to ensure data is mapped correctly in Kibana
    make_index_pattern = shlex.split(
        'curl -X POST "localhost:5601/api/saved_objects/index-pattern/{}" -H "kbn-xsrf: true" -H "Content-Type: application/json" -d \'{{"attributes":{{"fieldAttrs":"{{}}","title":"{}*","timeFieldName":"@timestamp","fields":"[]","typeMeta":"{{}}","runtimeFieldMap":"{{}}"}}}}\''.format(
            case.lower(), case.lower()
        )
    )
    subprocess.Popen(
        make_index_pattern, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).communicate()[0]
    time.sleep(0.2)
    for img in imgs_to_ingest:
        # Handle image name format: "imagename::mountpoint" or just "imagename"
        img_parts = img.split("::")
        img_name = img_parts[0]
        img_mount = img_parts[1] if len(img_parts) > 1 else ""

        if "vss" in img_mount:
            vss_part = img_mount.split("_")[1] if "_" in img_mount else img_mount
            vssimage = "'" + img_name + "' (" + vss_part.replace("vss", "volume shadow copy #") + ")"
            vsstext = " from " + vss_part.replace("vss", "volume shadow copy #")
        else:
            vssimage, vsstext = "'" + img_name + "'", ""
        print()
        print("     Ingesting artefacts into elasticsearch for {}...".format(vssimage))
        entry, prnt = "{},{}{},{},ingesting\n".format(
            datetime.now().isoformat(), img_name, vsstext, stage
        ), " -> {} -> ingesting artfacts into {} for {}{}".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            vssimage,
            vsstext,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        directories_with_data = [
            os.path.realpath(os.path.join(output_directory, img_name)),
            os.path.realpath(
                os.path.join(output_directory, img_name, "/artefacts/cooked/")
            ),
        ]
        if os.path.exists(
            os.path.join(output_directory, img_name, "/artefacts/cooked/")
        ):
            for sub_dir in os.listdir(
                os.path.realpath(
                    output_directory + img_name + "/artefacts/cooked/"
                )
            ):
                if "vss" in sub_dir:
                    directories_with_data.append(
                        os.path.realpath(
                            os.path.join(
                                output_directory
                                + img_name
                                + "/artefacts/cooked",
                                sub_dir,
                            )
                        )
                    )
        for each_dir in directories_with_data:
            if os.path.exists(each_dir):
                split_large_csv_files(each_dir)
                prepare_csv_to_ndjson(each_dir)
                convert_csv_to_ndjson(output_directory, case, img, each_dir)
                convert_json_to_ndjson(output_directory, case, img, each_dir)

        print("     elasticsearch ingestion completed for {}".format(vssimage))
        entry, prnt = "{},{},{},completed\n".format(
            datetime.now().isoformat(), vssimage, stage
        ), " -> {} -> ingested artfacts into {} for {}".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)

    # Generate and deploy Kibana dashboards
    try:
        from rivendell.post.elastic.dashboards import generate_all_dashboards, export_dashboards_to_ndjson
        print("\n     Generating Kibana dashboards...")
        dashboards = generate_all_dashboards(case, index_pattern=case.lower(), parent_only=True)
        dashboard_path = os.path.join(output_directory, "kibana_dashboards.ndjson")
        export_dashboards_to_ndjson(dashboards, dashboard_path)
        print(f"     Generated {len(dashboards)} dashboards -> {dashboard_path}")
        print("     Import dashboards via: Kibana > Stack Management > Saved Objects > Import")
    except ImportError:
        print("     Note: Dashboard generation module not available")
    except Exception as e:
        print(f"     Warning: Could not generate dashboards: {e}")


def send_bulk_to_elastic(bulk_data, elastic_url, auth_header, ssl_context, case):
    """Send bulk data to Elasticsearch"""
    if not bulk_data:
        return True

    bulk_url = "{}/_bulk".format(elastic_url)
    bulk_body = '\n'.join(bulk_data) + '\n'

    req = urllib.request.Request(bulk_url, data=bulk_body.encode('utf-8'), method='POST')
    req.add_header('Content-Type', 'application/x-ndjson')
    if auth_header:
        req.add_header('Authorization', auth_header)

    try:
        urllib.request.urlopen(req, context=ssl_context, timeout=120)
        return True
    except urllib.error.HTTPError as e:
        return False
    except Exception as e:
        return False


def ingest_elastic_data_remote(
    verbosity,
    output_directory,
    case,
    stage,
    allimgs,
    elastic_host,
    elastic_port,
    elastic_user,
    elastic_pswd,
    kibana_host,
    kibana_port,
):
    """Ingest data to a remote Elasticsearch instance (containerized environment)"""

    # Create SSL context that doesn't verify certificates (for self-signed)
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    # Build auth header
    auth_header = None
    if elastic_user and elastic_pswd:
        credentials = '{}:{}'.format(elastic_user, elastic_pswd)
        encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        auth_header = 'Basic {}'.format(encoded_credentials)

    elastic_url = "http://{}:{}".format(elastic_host, elastic_port)
    kibana_url = "http://{}:{}".format(kibana_host, kibana_port)

    # Batch size for bulk ingestion (number of records per batch)
    BATCH_SIZE = 1000
    # Large file threshold (50MB) - files larger than this use streaming
    LARGE_FILE_THRESHOLD = 50 * 1024 * 1024

    imgs_to_ingest = siem_hosts(allimgs)

    # Create index in Elasticsearch
    print("     Creating Elasticsearch index '{}'...".format(case.lower()))
    try:
        index_url = "{}/{}".format(elastic_url, case.lower())
        index_mapping = json.dumps({
            "mappings": {
                "properties": {
                    "@timestamp": {
                        "type": "date",
                        "format": "strict_date_optional_time||yyyy-MM-dd HH:mm:ss.SSSSSS||yyyy-MM-dd HH:mm:ss||yyyy-MM-dd'T'HH:mm:ss.SSS'Z'||yyyy-MM-dd'T'HH:mm:ss||epoch_millis"
                    }
                }
            }
        }).encode('utf-8')

        req = urllib.request.Request(index_url, data=index_mapping, method='PUT')
        req.add_header('Content-Type', 'application/json')
        if auth_header:
            req.add_header('Authorization', auth_header)

        try:
            response = urllib.request.urlopen(req, context=ssl_context, timeout=30)
            print("     Index '{}' created successfully".format(case.lower()))
        except urllib.error.HTTPError as e:
            if e.code == 400:
                print("     Index '{}' already exists".format(case.lower()))
            else:
                print("     Warning: Could not create index: {} {}".format(e.code, e.reason))
    except Exception as e:
        print("     Warning: Could not create index: {}".format(e))

    # Increase field limit
    try:
        settings_url = "{}/_settings".format(index_url)
        settings_data = json.dumps({"index.mapping.total_fields.limit": 1000000}).encode('utf-8')
        req = urllib.request.Request(settings_url, data=settings_data, method='PUT')
        req.add_header('Content-Type', 'application/json')
        if auth_header:
            req.add_header('Authorization', auth_header)
        urllib.request.urlopen(req, context=ssl_context, timeout=30)
    except Exception as e:
        pass  # Non-critical

    # Create index pattern in Kibana
    print("     Creating Kibana index pattern...")
    try:
        pattern_url = "{}/api/saved_objects/index-pattern/{}".format(kibana_url, case.lower())
        pattern_data = json.dumps({
            "attributes": {
                "title": "{}*".format(case.lower()),
                "timeFieldName": "@timestamp"
            }
        }).encode('utf-8')

        req = urllib.request.Request(pattern_url, data=pattern_data, method='POST')
        req.add_header('Content-Type', 'application/json')
        req.add_header('kbn-xsrf', 'true')
        if auth_header:
            req.add_header('Authorization', auth_header)

        try:
            urllib.request.urlopen(req, context=ssl_context, timeout=30)
            print("     Index pattern created")
        except urllib.error.HTTPError as e:
            if e.code == 409:
                print("     Index pattern already exists")
            else:
                print("     Warning: Could not create index pattern: {} {}".format(e.code, e.reason))
    except Exception as e:
        print("     Warning: Could not create index pattern: {}".format(e))

    # Ingest data for each image
    for img_name, img in imgs_to_ingest:
        # img is "<name>::<platform>[_vssN]"; img_name is the host's output folder
        img_parts = img.split("::")
        img_mount = img_parts[1] if len(img_parts) > 1 else ""

        if "vss" in img_mount:
            vssimage = "'" + img_name + "' (volume shadow copy)"
        else:
            vssimage = "'" + img_name + "'"

        entry, prnt = "{},{},indexing artefacts for {}\n".format(
            datetime.now().isoformat(), stage, vssimage
        ), " -> {} -> indexing artefacts for {}".format(
            datetime.now().isoformat().replace("T", " "), vssimage
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)

        # Find all JSON and CSV files in cooked directory
        cooked_path = os.path.join(output_directory, img_name, "artefacts", "cooked")

        memory_files = memory_outputs(os.path.join(output_directory, img_name))
        if not os.path.exists(cooked_path) and not memory_files:
            print("     No cooked artefacts found for {}".format(vssimage))
            continue

        # Collect all files to ingest: cooked artefacts, and Volatility's output beside them
        files_to_ingest = list(memory_files)
        files_to_ingest.extend(glob.glob(os.path.join(cooked_path, "*.json")))
        files_to_ingest.extend(glob.glob(os.path.join(cooked_path, "*.csv")))
        files_to_ingest.extend(glob.glob(os.path.join(cooked_path, "**", "*.json"), recursive=True))
        files_to_ingest.extend(glob.glob(os.path.join(cooked_path, "**", "*.csv"), recursive=True))

        # Remove duplicates
        files_to_ingest = list(set(files_to_ingest))

        for filepath in files_to_ingest:
            filename = os.path.basename(filepath)
            file_size = os.path.getsize(filepath)

            try:
                bulk_data = []
                records_processed = 0

                if filepath.endswith('.json'):
                    # Check if file is large - use streaming for large files
                    if file_size > LARGE_FILE_THRESHOLD:
                        # Stream large JSON files line by line
                        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                            # Try to detect if it's a JSON array by peeking
                            first_char = f.read(1)
                            f.seek(0)

                            if first_char == '[':
                                # JSON array - use ijson-style streaming (manual parsing)
                                # Read in chunks and extract objects
                                buffer = ""
                                depth = 0
                                in_string = False
                                escape_next = False
                                obj_start = -1

                                for chunk in iter(lambda: f.read(8192), ''):
                                    for i, char in enumerate(chunk):
                                        if escape_next:
                                            escape_next = False
                                            continue
                                        if char == '\\' and in_string:
                                            escape_next = True
                                            continue
                                        if char == '"' and not escape_next:
                                            in_string = not in_string
                                            continue
                                        if in_string:
                                            continue

                                        if char == '{':
                                            if depth == 0:
                                                obj_start = len(buffer) + i
                                            depth += 1
                                        elif char == '}':
                                            depth -= 1
                                            if depth == 0 and obj_start >= 0:
                                                # Extract object
                                                obj_str = buffer[obj_start:] + chunk[:i+1]
                                                try:
                                                    record = json.loads(obj_str)
                                                    record['hostname'] = img_name
                                                    record['artefact'] = filename
                                                    normalize_timestamp(record)
                                                    bulk_data.append(json.dumps({"index": {"_index": case.lower()}}))
                                                    bulk_data.append(json.dumps(record))
                                                    records_processed += 1

                                                    # Send batch when full
                                                    if len(bulk_data) >= BATCH_SIZE * 2:
                                                        send_bulk_to_elastic(bulk_data, elastic_url, auth_header, ssl_context, case)
                                                        bulk_data = []
                                                except:
                                                    pass
                                                obj_start = -1
                                                buffer = ""
                                                continue

                                    buffer += chunk
                                    # Trim buffer if no object in progress
                                    if obj_start == -1:
                                        buffer = ""
                            else:
                                # JSON lines format - read line by line
                                for line in f:
                                    if line.strip():
                                        try:
                                            record = json.loads(line)
                                            record['hostname'] = img_name
                                            record['artefact'] = filename
                                            normalize_timestamp(record)
                                            bulk_data.append(json.dumps({"index": {"_index": case.lower()}}))
                                            bulk_data.append(json.dumps(record))
                                            records_processed += 1

                                            # Send batch when full
                                            if len(bulk_data) >= BATCH_SIZE * 2:
                                                send_bulk_to_elastic(bulk_data, elastic_url, auth_header, ssl_context, case)
                                                bulk_data = []
                                        except:
                                            pass
                    else:
                        # Small files - load entirely
                        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                            try:
                                content = f.read()
                                # Handle JSON lines format
                                if '\n' in content and not content.strip().startswith('['):
                                    for line in content.strip().split('\n'):
                                        if line.strip():
                                            try:
                                                record = json.loads(line)
                                                record['hostname'] = img_name
                                                record['artefact'] = filename
                                                normalize_timestamp(record)
                                                bulk_data.append(json.dumps({"index": {"_index": case.lower()}}))
                                                bulk_data.append(json.dumps(record))
                                                records_processed += 1
                                            except:
                                                pass
                                else:
                                    # Regular JSON array
                                    records = json.loads(content)
                                    if isinstance(records, list):
                                        for record in records:
                                            if isinstance(record, dict):
                                                record['hostname'] = img_name
                                                record['artefact'] = filename
                                                normalize_timestamp(record)
                                                bulk_data.append(json.dumps({"index": {"_index": case.lower()}}))
                                                bulk_data.append(json.dumps(record))
                                                records_processed += 1
                                    elif isinstance(records, dict):
                                        records['hostname'] = img_name
                                        records['artefact'] = filename
                                        normalize_timestamp(records)
                                        bulk_data.append(json.dumps({"index": {"_index": case.lower()}}))
                                        bulk_data.append(json.dumps(records))
                                        records_processed += 1
                            except json.JSONDecodeError:
                                pass

                elif filepath.endswith('.csv'):
                    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                        try:
                            reader = csv.DictReader(f)
                            for row in reader:
                                row['hostname'] = img_name
                                row['artefact'] = filename
                                # Add timestamp if not present
                                if '@timestamp' not in row and 'LastWriteTime' not in row:
                                    row['@timestamp'] = datetime.now().isoformat()
                                bulk_data.append(json.dumps({"index": {"_index": case.lower()}}))
                                bulk_data.append(json.dumps(row))
                                records_processed += 1

                                # Send batch when full
                                if len(bulk_data) >= BATCH_SIZE * 2:
                                    send_bulk_to_elastic(bulk_data, elastic_url, auth_header, ssl_context, case)
                                    bulk_data = []
                        except:
                            pass

                # Send remaining bulk data
                if bulk_data:
                    send_bulk_to_elastic(bulk_data, elastic_url, auth_header, ssl_context, case)

                # Log successful indexing
                entry, prnt = "{},{},indexed '{}' for {}\n".format(
                    datetime.now().isoformat(), stage, filename, img_name
                ), " -> {} -> indexed '{}' for '{}'".format(
                    datetime.now().isoformat().replace("T", " "), filename, img_name
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)

            except Exception as e:
                print("       Warning: Could not process {}: {}".format(filename, str(e)[:50]))

        entry, prnt = "{},{},completed indexing for {}\n".format(
            datetime.now().isoformat(), stage, vssimage
        ), " -> {} -> completed indexing for {}".format(
            datetime.now().isoformat().replace("T", " "), vssimage
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)

    print("     Elasticsearch ingestion complete")
