#!/usr/bin/env python3 -tt
"""Pre-flight reachability checks for remote SIEM export targets."""
import base64
import glob
import logging
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)


class SIEMUnavailableError(Exception):
    """Raised when SIEM export is requested but the remote SIEM cannot be reached."""


# Splunk takes a minute or two to accept connections after its container starts, so
# a refused or timed-out connection is retried; a name that doesn't resolve isn't.
RETRY_DELAYS = (2, 4, 8, 16, 30, 60)


def _check_reachable(name: str, host: str, port: str, timeout: float, delays=RETRY_DELAYS) -> None:
    for attempt, delay in enumerate((*delays, None), 1):
        try:
            with socket.create_connection((host, int(port)), timeout=timeout):
                return
        except socket.gaierror as e:
            raise SIEMUnavailableError(
                f"{name} export requested but {host} doesn't resolve ({e}): its container isn't "
                "running or isn't on this network. Under Docker Compose, start the SIEM stack with "
                "`docker compose --profile siem up -d`."
            ) from e
        except (OSError, ValueError) as e:
            if isinstance(e, ValueError) or delay is None:
                raise SIEMUnavailableError(
                    f"{name} export requested but {host}:{port} is unreachable after "
                    f"{attempt} attempt{'s' if attempt != 1 else ''} ({e}). If it's still starting, "
                    "re-run once it accepts connections; under Docker Compose, start the SIEM stack "
                    "with `docker compose --profile siem up -d`."
                ) from e
            logger.warning("%s at %s:%s not accepting connections yet (%s); retrying in %ds",
                           name, host, port, e, delay)
            time.sleep(delay)


def _check_splunk_login(host: str, port: str, user: str, password: str, timeout: float) -> None:
    """Splunk refusing the login fails the run here: its config code only warned (a 401 on every
    call) and the run reported success with nothing indexed (7 November 2026)."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Splunk's management port has its own self-signed certificate
    request = urllib.request.Request(f"https://{host}:{port}/services/server/info")
    request.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode())
    try:
        urllib.request.urlopen(request, context=context, timeout=timeout).close()
    except urllib.error.HTTPError as e:
        if e.code not in (401, 403):
            return  # reachable and answering; anything else is the config code's to report
        said = re.search(r"<msg[^>]*>([^<]+)</msg>", e.read().decode("utf-8", "replace"))
        raise SIEMUnavailableError(
            f"Splunk export requested but Splunk refused the login for '{user}' ({e.code}"
            f"{': ' + said.group(1).strip() if said else ''}). Check SPLUNK_USERNAME and SPLUNK_PASSWORD."
        ) from e
    except (OSError, ValueError):
        return  # the connection itself was checked just before


def ensure_remote_siem_reachable(splunk: bool, elastic: bool, timeout: float = 5.0) -> None:
    """Fail fast if a requested remote SIEM (SPLUNK_HOST / ELASTICSEARCH_HOST) is not reachable.

    Local installs (host env var unset) are left to the existing SIEMInstaller path.
    Without this, the remote-mode config code swallows connection errors and the
    job reports success with nothing exported.
    """
    if splunk and os.environ.get("SPLUNK_HOST"):
        _check_reachable(
            "Splunk",
            os.environ["SPLUNK_HOST"],
            os.environ.get("SPLUNK_PORT", "8089"),
            timeout,
        )
        _check_splunk_login(os.environ["SPLUNK_HOST"], os.environ.get("SPLUNK_PORT", "8089"),
                            os.environ.get("SPLUNK_USERNAME", "admin"), os.environ.get("SPLUNK_PASSWORD", ""),
                            timeout)
    if elastic and os.environ.get("ELASTICSEARCH_HOST"):
        _check_reachable(
            "Elasticsearch",
            os.environ["ELASTICSEARCH_HOST"],
            os.environ.get("ELASTICSEARCH_PORT", "9200"),
            timeout,
        )


def ensure_export_targets(opensearch: bool, timesketch: bool, timeout: float = 5.0) -> None:
    """Fail before processing if OpenSearch or Timesketch was asked for and isn't configured,
    reachable, or accepting the configured login."""
    import urllib.parse

    if opensearch:
        from rowanholt.post.opensearch import OpenSearchError, OpenSearchTarget, http_request
        try:
            target = OpenSearchTarget.from_env()
        except OpenSearchError as e:
            raise SIEMUnavailableError(f"OpenSearch export requested but {e}") from e
        url = urllib.parse.urlsplit(target.url)
        _check_reachable("OpenSearch", url.hostname or "", str(url.port or (443 if url.scheme == "https" else 9200)),
                         timeout, delays=(2, 4))
        try:
            status, _ = http_request(target)("GET", f"{target.url}/", None, {})
        except OSError as e:  # a TLS failure: the certificate isn't trusted (OPENSEARCH_CA)
            raise SIEMUnavailableError(f"OpenSearch at {target.url} couldn't be reached over TLS ({e})") from e
        if status in (401, 403):
            raise SIEMUnavailableError(f"OpenSearch at {target.url} refused the login ({status}): check OPENSEARCH_USERNAME and OPENSEARCH_PASSWORD")
    if timesketch:
        from rowanholt.post.timesketch import TimesketchClient, TimesketchError, TimesketchTarget
        try:
            client = TimesketchClient(TimesketchTarget.from_env())
            client.login()
        except TimesketchError as e:
            raise SIEMUnavailableError(f"Timesketch export requested but {e}") from e
        except OSError as e:
            raise SIEMUnavailableError(f"Timesketch export requested but it couldn't be reached ({e})") from e


def siem_hosts(allimgs) -> list:
    """[(host folder, '<name>::<platform>')] for each allimgs entry, once each. Memory
    images carry their name in the key and a directory as the value, so reading the
    value alone sent their output nowhere."""
    from rowanholt.post.clean import output_folder_name
    hosts = []
    for key, value in allimgs.items():
        label = value if "::" in str(value) else key
        if all(label != seen for _, seen in hosts):
            hosts.append((output_folder_name(key, value), label))
    return hosts


def memory_outputs(host_dir: str) -> list:
    """Volatility's output for a host: <host>/memory_<plugin>.jsonl (or an older case's .json),
    beside artefacts/."""
    found = glob.glob(os.path.join(host_dir, "memory_*.jsonl")) + glob.glob(os.path.join(host_dir, "memory_*.json"))
    return sorted(found)
