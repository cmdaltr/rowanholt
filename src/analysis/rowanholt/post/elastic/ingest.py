#!/usr/bin/env python3 -tt
import base64
import json
import os
import shlex
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime
from functools import lru_cache
from typing import Any, Callable, Dict, Iterator, List, Tuple

from rowanholt.audit import write_audit_log_entry
from rowanholt.core.records import ENVELOPE, SUFFIX, iso_timestamp, iter_json, read_records
from rowanholt.post.siem import memory_outputs, siem_hosts

# Records per bulk request: Elasticsearch refuses a body over http.max_content_length (100 MB)
BATCH_SIZE = 1000
OLD_SUFFIXES = (".csv", ".json")


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


def _artefact_of(path: str, folder: str) -> str:
    return os.path.splitext(os.path.relpath(path, folder))[0].replace(os.sep, "/")


def host_tables(host_dir: str) -> List[Tuple[str, str]]:
    """(path, artefact) for every table of a host's to index: artefacts/cooked/** and analysis/**,
    artefacts/plaso_timeline, and Volatility's memory_* output beside artefacts/.

    JSON Lines only, unless the host has none: then it's a case processed before the change, and
    its CSV and JSON tables are indexed instead (never both, which would index a table twice).
    """
    new: List[Tuple[str, str]] = []
    old: List[Tuple[str, str]] = []
    for folder in (os.path.join(host_dir, "artefacts", "cooked"), os.path.join(host_dir, "analysis")):
        for root, dirs, files in os.walk(folder):
            dirs.sort()
            for name in sorted(files):
                if name.startswith("._"):
                    continue
                path = os.path.join(root, name)
                suffix = os.path.splitext(name)[1].lower()
                if suffix == SUFFIX:
                    new.append((path, _artefact_of(path, folder)))
                elif suffix in OLD_SUFFIXES:
                    old.append((path, _artefact_of(path, folder)))
    for suffix in (SUFFIX,) + OLD_SUFFIXES:
        timeline = os.path.join(host_dir, "artefacts", f"plaso_timeline{suffix}")
        if os.path.isfile(timeline):
            (new if suffix == SUFFIX else old).append((timeline, "plaso_timeline"))
    for path in memory_outputs(host_dir):
        (new if path.endswith(SUFFIX) else old).append((path, os.path.splitext(os.path.basename(path))[0]))
    return new or old


def table_records(path: str) -> Iterator[Dict[str, Any]]:
    """Each record of a table, streamed: JSON Lines, or an older case's CSV or JSON array."""
    if path.lower().endswith(".json"):
        with open(path, encoding="utf-8", errors="replace") as fh:
            for record in iter_json(fh):  # an old MFT array is several GB: not read whole
                if isinstance(record, dict):
                    yield record
        return
    for _, record in read_records(path):
        if set(record) != {"unparsed"}:  # a line that isn't JSON isn't a document
            yield record


@lru_cache(maxsize=None)
def _technique_info(technique_id: str) -> Dict[str, Any]:
    try:
        from rowanholt.post.mitre.attack_data import enrich_technique
        return enrich_technique(technique_id) or {}
    except Exception:  # without the ATT&CK data the IDs still go in
        return {}


def _union(values: List[Any]) -> List[Any]:
    out: List[Any] = []
    for value in values:
        for item in value if isinstance(value, list) else [value]:
            if item not in (None, "") and item not in out:
                out.append(item)
    return out


def fill_technique_fields(doc: Dict[str, Any]) -> Dict[str, Any]:
    """The technique fields Kibana's dashboards chart (mitre_technique_id, _name, _tactics, _groups,
    _software), from the envelope's techniques, where ATT&CK enrichment hasn't already set them."""
    ids = [t for t in doc.get("techniques") or [] if isinstance(t, str) and t]
    if not ids or doc.get("mitre_technique_id"):
        return doc
    info = [_technique_info(t) for t in ids]
    # Several IDs go in as an array, so a terms chart counts the record under each technique
    doc["mitre_technique_id"] = ids[0] if len(ids) == 1 else ids
    names = _union([i.get("mitre_technique_name") for i in info])
    if names:
        doc["mitre_technique_name"] = names[0] if len(names) == 1 else names
    for field in ("mitre_tactics", "mitre_groups", "mitre_software"):
        values = _union([i.get(field) for i in info])
        if values:
            doc[field] = values
    return doc


def to_document(record: Dict[str, Any], host: str, artefact: str) -> Dict[str, Any]:
    """A record as an Elasticsearch document: hostname and artefact as the dashboards use them,
    @timestamp from the envelope's timestamp, and the technique fields filled in.

    A JSON Lines record whose timestamp is null gets no @timestamp: its writer chose the
    artefact's time field, so any other field would be a guess, and a value Elasticsearch can't
    parse as a date gets the whole document refused. An older case's record has no envelope, so
    its time is looked for as before (normalize_timestamp), and kept only when it parses.
    """
    doc = dict(record)
    doc["hostname"] = record.get("host") or host
    if not doc.get("artefact"):
        doc["artefact"] = artefact
    if all(field in record for field in ENVELOPE):
        stamp = iso_timestamp(record.get("timestamp"))
    else:
        stamp = iso_timestamp(normalize_timestamp(dict(record)).get("@timestamp"))
    if stamp:
        doc["@timestamp"] = stamp
    else:
        doc.pop("@timestamp", None)
    return fill_technique_fields(doc)


def index_table(path: str, host: str, artefact: str, index: str,
                send: Callable[[List[str]], bool]) -> Tuple[int, bool]:
    """Bulk-post every record of one table to ``index`` through ``send``, BATCH_SIZE at a time;
    (records sent, whether every batch was accepted)."""
    action = json.dumps({"index": {"_index": index}})
    batch: List[str] = []
    sent, ok = 0, True
    for record in table_records(path):
        batch.append(action)
        batch.append(json.dumps(to_document(record, host, artefact), default=str))
        sent += 1
        if len(batch) >= BATCH_SIZE * 2:
            ok = send(batch) and ok
            batch = []
    if batch:
        ok = send(batch) and ok
    return sent, ok


def ingest_host_tables(host_dir: str, host: str, index: str,
                       send: Callable[[List[str]], bool]) -> List[Tuple[str, int, bool]]:
    """Index every table of one host's; (artefact, records sent, all accepted) for each."""
    results = []
    for path, artefact in host_tables(host_dir):
        try:
            sent, ok = index_table(path, host, artefact, index, send)
        except (OSError, ValueError):
            sent, ok = 0, False
        results.append((artefact, sent, ok))
    return results


def ingest_elastic_data(
    verbosity,
    output_directory,
    case,
    stage,
    allimgs,
):
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
    seen = set()
    for img_name, img in siem_hosts(allimgs):
        img_mount = img.split("::")[1] if "::" in img else ""

        if "vss" in img_mount:
            vss_part = img_mount.split("_")[1] if "_" in img_mount else img_mount
            vssimage = "'" + img_name + "' (" + vss_part.replace("vss", "volume shadow copy #") + ")"
            vsstext = " from " + vss_part.replace("vss", "volume shadow copy #")
        else:
            vssimage, vsstext = "'" + img_name + "'", ""
        # A host's shadow copies are in its own cooked/ (cooked/vssN/) and go in with it
        if img_name in seen:
            continue
        seen.add(img_name)
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
        results = ingest_host_tables(
            os.path.join(output_directory, img_name), img_name, case.lower(),
            lambda batch: send_bulk_to_elastic(batch, "http://localhost:9200", None, None, case),
        )
        for artefact, _, ok in results:
            if not ok:
                print(
                    "       Could not ingest\t'{}'\t- perhaps the json did not format correctly?".format(
                        artefact
                    )
                )

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
        from rowanholt.post.elastic.dashboards import generate_all_dashboards, export_dashboards_to_ndjson
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
    """Send bulk data to Elasticsearch: False when the request, or any document in it, is refused"""
    if not bulk_data:
        return True

    bulk_url = "{}/_bulk".format(elastic_url)
    bulk_body = '\n'.join(bulk_data) + '\n'

    req = urllib.request.Request(bulk_url, data=bulk_body.encode('utf-8'), method='POST')
    req.add_header('Content-Type', 'application/x-ndjson')
    if auth_header:
        req.add_header('Authorization', auth_header)

    try:
        with urllib.request.urlopen(req, context=ssl_context, timeout=120) as response:
            reply = response.read()
    except Exception:
        return False
    # A bulk request is accepted as a whole even when documents in it are refused
    try:
        return not json.loads(reply).get("errors")
    except (ValueError, AttributeError):
        return True


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
    seen = set()
    for img_name, img in imgs_to_ingest:
        # img is "<name>::<platform>[_vssN]"; img_name is the host's output folder
        img_parts = img.split("::")
        img_mount = img_parts[1] if len(img_parts) > 1 else ""

        if "vss" in img_mount:
            vssimage = "'" + img_name + "' (volume shadow copy)"
        else:
            vssimage = "'" + img_name + "'"
        # A host's shadow copies are in its own cooked/ (cooked/vssN/) and go in with it
        if img_name in seen:
            continue
        seen.add(img_name)

        entry, prnt = "{},{},indexing artefacts for {}\n".format(
            datetime.now().isoformat(), stage, vssimage
        ), " -> {} -> indexing artefacts for {}".format(
            datetime.now().isoformat().replace("T", " "), vssimage
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)

        host_dir = os.path.join(output_directory, img_name)
        if not host_tables(host_dir):
            print("     No cooked artefacts found for {}".format(vssimage))
            continue

        results = ingest_host_tables(
            host_dir, img_name, case.lower(),
            lambda batch: send_bulk_to_elastic(batch, elastic_url, auth_header, ssl_context, case),
        )
        for artefact, records, ok in results:
            if ok:
                entry, prnt = "{},{},indexed '{}' for {}\n".format(
                    datetime.now().isoformat(), stage, artefact, img_name
                ), " -> {} -> indexed '{}' for '{}'".format(
                    datetime.now().isoformat().replace("T", " "), artefact, img_name
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
            else:
                print("       Warning: Could not index all of {} ({} records sent)".format(artefact, records))

        entry, prnt = "{},{},completed indexing for {}\n".format(
            datetime.now().isoformat(), stage, vssimage
        ), " -> {} -> completed indexing for {}".format(
            datetime.now().isoformat().replace("T", " "), vssimage
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)

    print("     Elasticsearch ingestion complete")
