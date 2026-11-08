"""Index a case Elrond has already processed into Splunk, Elastic, OpenSearch, Timesketch and the ATT&CK Navigator, without
mounting, extracting or processing anything again (elrond.py --Index).

The hosts and their platforms come from the case folder: the audit log's "identified platform"
entries, else a Gandalf host's artefacts/host.info. Memory-only hosts aren't indexed this way.

The case's index in each SIEM is replaced, not added to: indexing again into the same index put
every record in twice, and Elastic kept the old index's field mappings.
"""

import base64
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple

from rowanholt.audit import write_audit_log_entry
from rowanholt.core.identify import parse_gandalf_host_info

AUDIT_LOG = "rowanholt_audit.log"


class IndexOnlyError(ValueError):
    """A folder with no processed hosts to index."""


REPOINT = ("     WARNING: anything saved against the old index (searches, dashboards, alerts, Kibana objects\n"
           "     tied to its data) may need re-pointing at the new one")


def _request(url: str, user: str, password: str, method: str, data: Optional[Dict[str, str]] = None) -> int:
    """The HTTP status of one authenticated request (self-signed certificates accepted)."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    body = urllib.parse.urlencode(data).encode() if data else None
    request = urllib.request.Request(url, data=body, method=method)
    request.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode())
    try:
        with urllib.request.urlopen(request, context=context, timeout=30) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def replace_elastic_index(case: str, request: Callable[[str, str, str, str], int] = _request) -> Optional[str]:
    """Delete the case's Elasticsearch index, so it's created afresh with this version's mapping;
    what happened, or None for a local install (not replaced)."""
    host = os.environ.get("ELASTICSEARCH_HOST", "")
    if not host:
        return None
    url = f"http://{host}:{os.environ.get('ELASTICSEARCH_PORT', '9200')}/{case.lower()}"
    status = request(url, os.environ.get("ELASTIC_USERNAME", "elastic"), os.environ.get("ELASTIC_PASSWORD", ""), "DELETE")
    if status == 404:
        return "new"
    if status >= 300:
        raise IndexOnlyError(f"Elasticsearch wouldn't delete index '{case.lower()}' ({status})")
    return "replaced"


def _splunk() -> Tuple[str, str, str]:
    base = f"https://{os.environ['SPLUNK_HOST']}:{os.environ.get('SPLUNK_PORT', '8089')}/services/data/indexes"
    return base, os.environ.get("SPLUNK_USERNAME", "admin"), os.environ.get("SPLUNK_PASSWORD", "")


def replace_splunk_index(case: str, request: Callable[..., int] = _request, wait: float = 120,
                         sleep: Callable[[float], None] = time.sleep, settle: float = 5) -> Optional[str]:
    """Delete the case's Splunk index and create it afresh; what happened, or None for a local
    install (not replaced).

    Splunk drops a deleted index from its REST listing before it has finished removing it, and the
    removal's last step takes the index's stanza out of indexes.conf: an index created as soon as
    the listing said 404 was erased 43 ms later and the restart found none, so every event read was
    dropped (7 November 2026). So the index is created here, after a pause, and only counted once
    it is still there ``settle`` seconds later."""
    if not os.environ.get("SPLUNK_HOST"):
        return None
    base, user, password = _splunk()
    name = case.lower()  # as Splunk stores it
    url = f"{base}/{name}"
    status = request(url, user, password, "DELETE")
    if status >= 300 and status != 404:
        raise IndexOnlyError(f"Splunk wouldn't delete index '{name}' ({status})")
    outcome = "new" if status == 404 else "replaced"
    waited = 0.0
    while outcome == "replaced" and request(url, user, password, "GET") != 404:
        if waited >= wait:
            raise IndexOnlyError(f"Splunk was still removing index '{name}' after {wait:.0f}s; run --Index again shortly")
        sleep(2)
        waited += 2
    for _ in range(3):
        sleep(settle)
        created = request(base, user, password, "POST", {"name": name})
        if created not in (201, 409):
            raise IndexOnlyError(f"Splunk wouldn't create index '{name}' ({created})")
        sleep(settle)
        if request(url, user, password, "GET") == 200:
            return outcome
    raise IndexOnlyError(f"Splunk kept losing the new index '{name}' (its removal still finishing); run --Index again shortly")


def confirm_splunk_index(case: str, request: Callable[..., int] = _request, wait: float = 300,
                         sleep: Callable[[float], None] = time.sleep) -> None:
    """After the restart that loads the case's monitors: its index is there, or the run fails
    (Splunk drops every event for an index it doesn't have)."""
    if not os.environ.get("SPLUNK_HOST"):
        return
    base, user, password = _splunk()
    sleep(30)  # the restart was only requested; before it, the index answers from the old process
    waited = 30.0
    while True:
        try:
            status = request(f"{base}/{case.lower()}", user, password, "GET")
        except OSError:
            status = 0  # down while it restarts
        if status == 200:
            return
        if status == 404:
            raise IndexOnlyError(f"Splunk restarted without index '{case.lower()}': the events it reads are dropped; run --Index again")
        if waited >= wait:  # still restarting
            raise IndexOnlyError(f"Splunk didn't come back within {wait:.0f}s to confirm index '{case.lower()}'")
        sleep(5)
        waited += 5


def _replace(name: str, index: str, replace: Callable[[], Optional[str]]) -> None:
    outcome = replace()
    if outcome == "replaced":
        print(f"     Replaced {name} index '{index}': the old one is deleted and the case indexed afresh")
        print(REPOINT)
    elif outcome is None:
        print(f"     {name} is a local install: its index '{index}' is added to, not replaced")


def _audit_platforms(output_directory: str) -> Dict[str, str]:
    platforms: Dict[str, str] = {}
    audit = os.path.join(output_directory, AUDIT_LOG)
    if not os.path.isfile(audit):
        return platforms
    with open(audit, encoding="utf-8", errors="replace") as log:
        for line in log:
            parts = line.rstrip("\n").split(",", 3)
            if len(parts) == 4 and parts[2] == "identified platform" and parts[3]:
                platforms[parts[1]] = parts[3]  # the latest identification wins
    return platforms


def case_hosts(output_directory: str) -> Tuple[Dict[str, str], List[str]]:
    """allimgs for a processed case ({<host>/artefacts/raw: "<host>::<platform>"}, as the ingest
    registers them), and the host folders whose platform nothing records."""
    platforms = _audit_platforms(output_directory)
    allimgs: Dict[str, str] = {}
    unknown: List[str] = []
    for name in sorted(os.listdir(output_directory)):
        host_dir = os.path.join(output_directory, name)
        if name.startswith(".") or not os.path.isdir(os.path.join(host_dir, "artefacts", "cooked")):
            continue  # .previous/ (earlier extractions), files, and folders that aren't hosts
        platform = platforms.get(name, "")
        host_info = os.path.join(host_dir, "artefacts", "host.info")
        if not platform and os.path.isfile(host_info):
            with open(host_info, encoding="utf-8", errors="replace") as info:
                platform = parse_gandalf_host_info(info.readline().strip())[1]
        if platform:
            allimgs[os.path.join(host_dir, "artefacts", "raw")] = f"{name}::{platform}"
        else:
            unknown.append(name)
    return allimgs, unknown


def export_targets(output_directory: str, case: str, verbosity: str, opensearch: bool,
                   timesketch: bool) -> List[str]:
    """The case's processed hosts into OpenSearch (its index replaced) and Timesketch (hosts already
    in its sketch left alone), once for the whole case, after a run or from --Index; the targets
    that failed."""
    from rowanholt.post import opensearch as opensearch_export
    from rowanholt.post import timesketch as timesketch_export

    output_directory = os.path.join(output_directory, "")
    allimgs, _ = case_hosts(output_directory)
    failed: List[str] = []
    for name, on, export in (("OpenSearch", opensearch, opensearch_export.export_case),
                             ("Timesketch", timesketch, timesketch_export.export_case)):
        if not on:
            continue
        print(f"\n  -> \033[1;36mCommencing {name} Phase...\033[1;m\n  ----------------------------------------")
        try:
            if not allimgs:
                raise IndexOnlyError(f"no processed hosts in {output_directory}")
            sent = export(output_directory, case, allimgs)
            outcome = f"exported {len(sent)} host(s) to {name}"
        except Exception as error:  # report it and go on to the other target
            print(f"     ERROR: {name} export failed: {error}")
            failed.append(name)
            outcome = f"{name} export failed: {error}"
        write_audit_log_entry(
            verbosity, output_directory,
            f"{datetime.now().isoformat()},{case},{name.lower()},{outcome.replace(',', ';')}\n",
            f" -> {datetime.now().isoformat().replace('T', ' ')} -> {outcome}",
        )
        print(f"  ----------------------------------------\n  -> Completed {name} Phase.\n")
    return failed


def index_case(output_directory: str, case: str, verbosity: str, splunk: bool, elastic: bool,
               navigator: bool, opensearch: bool = False, timesketch: bool = False) -> List[str]:
    """Index the case's processed hosts; the targets that failed (each is tried, whatever the
    others do)."""
    from rowanholt.post.elastic.config import configure_elastic_stack
    from rowanholt.post.mitre.nav_config import configure_navigator
    from rowanholt.post.splunk.config import configure_splunk_stack

    output_directory = os.path.join(output_directory, "")  # the SIEM writers join onto a trailing /
    allimgs, unknown = case_hosts(output_directory)
    for name in unknown:
        print(f"   No platform recorded for '{name}'; not indexing it")
    if not allimgs:
        raise IndexOnlyError(f"no processed hosts in {output_directory} (a host folder holds artefacts/cooked/)")
    hosts = ", ".join(value.split("::")[0] for value in allimgs.values())
    print(f"   Indexing {len(allimgs)} processed host(s): {hosts}")

    failed: List[str] = []
    usercred = pswdcred = None
    if splunk:
        print("\n  -> \033[1;36mCommencing Splunk Phase...\033[1;m\n  ----------------------------------------")
        try:
            _replace("Splunk", case, lambda: replace_splunk_index(case))
            salt = datetime.now().strftime(":%Y%m%dT%H%M%S")  # Splunk reads the case's files again
            usercred, pswdcred = configure_splunk_stack(verbosity, output_directory, case, "splunk", allimgs, salt)
            confirm_splunk_index(case)
        except Exception as error:  # report it and go on to the other targets
            print(f"     ERROR: Splunk indexing failed: {error}")
            failed.append("Splunk")
        print("  ----------------------------------------\n  -> Completed Splunk Phase.\n")
    if elastic:
        print("\n  -> \033[1;36mCommencing Elastic Phase...\033[1;m\n  ----------------------------------------")
        try:
            _replace("Elastic", case.lower(), lambda: replace_elastic_index(case))
            configure_elastic_stack(verbosity, output_directory, case, "elastic", allimgs)
        except Exception as error:
            print(f"     ERROR: Elastic indexing failed: {error}")
            failed.append("Elastic")
        print("  ----------------------------------------\n  -> Completed Elastic Phase.\n")
    failed += export_targets(output_directory, case, verbosity, opensearch, timesketch)
    if navigator:
        print("\n  -> \033[1;36mCommencing Navigator Phase...\033[1;m\n  ----------------------------------------")
        try:
            configure_navigator(verbosity, case, splunk, elastic, usercred, pswdcred, output_directory)
        except Exception as error:
            print(f"     ERROR: Navigator layer failed: {error}")
            failed.append("Navigator")
        print("  ----------------------------------------\n  -> Completed Navigator Phase.\n")

    targets = [t for t, on in (("Splunk", splunk), ("Elastic", elastic), ("OpenSearch", opensearch),
                               ("Timesketch", timesketch), ("Navigator", navigator)) if on]
    outcome = f"indexed into {', '.join(targets)}" + (f"; {', '.join(failed)} failed" if failed else "")
    write_audit_log_entry(
        verbosity, output_directory,
        f"{datetime.now().isoformat()},{case},index only,{outcome.replace(',', ';')} ({hosts.replace(',', ';')})\n",
        f" -> {datetime.now().isoformat().replace('T', ' ')} -> {outcome}, without processing again",
    )
    return failed
