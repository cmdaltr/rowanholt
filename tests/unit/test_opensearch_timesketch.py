"""--OpenSearch (OpenSearch or Wazuh's indexer) and --Timesketch: the documents and events a case
becomes, the index replaced, the sketch reused, and Timesketch's login and chunked upload against
a stand-in server speaking its web API."""
import email.parser
import email.policy
import io
import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import pytest

sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.core.records import write_records  # noqa: E402
from rowanholt.post import index_only, opensearch, timesketch  # noqa: E402

ALLIMGS = {"/case/LAB-WIN11/artefacts/raw": "LAB-WIN11::Windows10"}


def make_host(case: Path) -> Path:
    host = case / "LAB-WIN11"
    write_records(host / "artefacts" / "cooked" / "evt" / "Security.jsonl",
                  [{"EventID": 4624, "LastWriteTime": "2026-10-29 14:03:11", "message": "a logon"},
                   {"EventID": 4625, "LastWriteTime": ""}],
                  host="LAB-WIN11", artefact="evt/Security", source_path="raw/evt/Security.evtx",
                  time_field="LastWriteTime", techniques=["T1078"])
    write_records(host / "artefacts" / "plaso_timeline.jsonl",
                  [{"message": "Plaso's own line", "datetime": "2026-10-29T14:03:12+00:00", "timestamp": 1}],
                  host="LAB-WIN11", artefact="plaso_timeline", source_path="", time_field="datetime")
    return host


# OpenSearch

def test_settings_from_the_environment():
    target = opensearch.OpenSearchTarget.from_env({"OPENSEARCH_URL": "https://wazuh:9200/", "OPENSEARCH_VERIFY": "false",
                                                   "OPENSEARCH_INDEX_PREFIX": "DFIR-"})
    assert target.url == "https://wazuh:9200" and not target.verify and target.index("CASE-1") == "dfir-case-1"
    assert opensearch.OpenSearchTarget.from_env({"OPENSEARCH_URL": "http://o:9200"}).index("X") == "rowanholt-x"
    with pytest.raises(opensearch.OpenSearchError):
        opensearch.OpenSearchTarget.from_env({})


class FakeOpenSearch:
    def __init__(self, refuse_bulk: bool = False, existed: bool = True) -> None:
        self.calls = []
        self.docs = []
        self.refuse_bulk = refuse_bulk
        self.existed = existed

    def __call__(self, method, url, body, headers):
        self.calls.append((method, url, headers))
        if method == "DELETE":
            return (200 if self.existed else 404), b"{}"
        if method == "PUT":
            self.mapping = json.loads(body)
            return 200, b"{}"
        if url.endswith("/_bulk"):
            lines = body.decode().splitlines()
            self.docs += [json.loads(line) for line in lines[1::2]]
            assert all(json.loads(a) == {"index": {"_index": "rowanholt-case-1"}} for a in lines[::2])
            return 200, json.dumps({"errors": self.refuse_bulk}).encode()
        return 200, b"{}"


def test_the_case_replaces_its_index(tmp_path):
    make_host(tmp_path)
    fake = FakeOpenSearch()
    target = opensearch.OpenSearchTarget(url="http://o:9200", dashboards_url="http://d:5601")
    sent = opensearch.export_case(str(tmp_path), "CASE-1", ALLIMGS, target, fake)
    assert sent == {"LAB-WIN11": 3}
    assert [c[0] for c in fake.calls[:2]] == ["DELETE", "PUT"] and fake.calls[0][1] == "http://o:9200/rowanholt-case-1"
    assert fake.mapping["mappings"]["date_detection"] is False  # Elastic's mapping, as is
    assert fake.mapping["settings"]["index.mapping.total_fields.limit"] == 1000000
    logon = next(d for d in fake.docs if d.get("EventID") == 4624)
    assert logon["hostname"] == "LAB-WIN11" and logon["mitre_technique_id"] == "T1078"
    assert logon["@timestamp"].startswith("2026-10-29T14:03:11")
    pattern = fake.calls[-1]
    assert pattern[1] == "http://d:5601/api/saved_objects/index-pattern/rowanholt-case-1?overwrite=true"
    assert pattern[2]["osd-xsrf"] == "true"


def test_refused_records_fail_the_export_after_sending_the_rest(tmp_path):
    make_host(tmp_path)
    fake = FakeOpenSearch(refuse_bulk=True)
    with pytest.raises(opensearch.OpenSearchError, match="refused records"):
        opensearch.export_case(str(tmp_path), "CASE-1", ALLIMGS, opensearch.OpenSearchTarget(url="http://o:9200"), fake)
    assert len(fake.docs) == 3


def test_an_index_that_wont_go_stops_the_export(tmp_path):
    def refuse(method, url, body, headers):
        return (403, b"no") if method == "DELETE" else (200, b"{}")
    with pytest.raises(opensearch.OpenSearchError, match="wouldn't delete"):
        opensearch.export_case(str(tmp_path), "CASE-1", ALLIMGS, opensearch.OpenSearchTarget(url="http://o:9200"), refuse)


def test_certificates_are_checked_unless_turned_off(tmp_path):
    checked = opensearch.OpenSearchTarget(url="https://o:9200").context()
    assert checked.verify_mode.name == "CERT_REQUIRED" and checked.check_hostname
    unchecked = opensearch.OpenSearchTarget(url="https://o:9200", verify=False).context()
    assert unchecked.verify_mode.name == "CERT_NONE"
    assert opensearch.OpenSearchTarget(url="http://o:9200").context() is None


# Timesketch events

def test_events_carry_time_host_and_technique():
    record = {"host": "LAB-WIN11", "artefact": "evt/Security", "source_path": "raw/evt/Security.evtx",
              "timestamp": "2026-10-29 14:03:11", "techniques": ["T1078"], "EventID": 4624,
              "Data": {"LogonType": 3}, "message": "", "tag": "x", "_id": "dropped"}
    event = timesketch.to_event(record, "LAB-WIN11", "evt/Security")
    assert event["datetime"].endswith("Z") and event["datetime"].startswith("2026-10-29T14:03:11")
    assert event["timestamp_desc"] == "evt/Security" and event["hostname"] == "LAB-WIN11"
    assert event["mitre_technique_id"] == "T1078"
    assert event["EventID"] == "4624" and event["Data"] == '{"LogonType": 3}'  # one type per field
    assert event["record_timestamp"] == "2026-10-29 14:03:11" and event["record_tag"] == "x"
    assert "timestamp" not in event and "_id" not in event and "@timestamp" not in event
    assert event["message"].startswith("evt/Security: EventID=4624")


def test_an_event_whose_envelope_lost_its_time_keeps_its_own():
    """Cases processed on Python 3.10 before 8 November 2026: Artemis's times null in the envelope."""
    record = {"host": "LAB-WIN11", "artefact": "evt/Microsoft-Windows-PowerShell%4Operational", "source_path": "",
              "timestamp": None, "techniques": ["T1059.001"], "orig_timestamp": "2026-11-05T10:35:12.667746000Z"}
    event = timesketch.to_event(record, "LAB-WIN11", record["artefact"])
    assert event["datetime"].startswith("2026-11-05T10:35:12") and event["mitre_technique_id"] == "T1059.001"
    assert timesketch.to_event(dict(record, orig_timestamp=None), "LAB-WIN11", "x") is None


def test_plaso_keeps_its_message_and_untimed_records_are_counted(tmp_path):
    host = make_host(tmp_path)
    out = io.BytesIO()
    written, untimed = timesketch.write_timeline(str(host), "LAB-WIN11", out)
    assert (written, untimed) == (2, 1)
    events = [json.loads(line) for line in out.getvalue().splitlines()]
    assert {e["message"] for e in events} == {"a logon", "Plaso's own line"}
    plaso = next(e for e in events if e["artefact"] == "plaso_timeline")
    assert plaso["datetime"] == "2026-10-29T14:03:12Z"  # iso_timestamp, as Elastic gets it


# Timesketch's web API, stood in for

class StandIn(BaseHTTPRequestHandler):
    token = "tok3n"
    state = {}

    def log_message(self, *args):
        pass

    def _send(self, status, body=b"", content_type="application/json", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _signed_in(self):
        return "session=ok" in (self.headers.get("Cookie") or "") and self.headers.get("X-CSRFToken") == self.token

    def do_GET(self):
        if self.path == "/":
            return self._send(200, b"<html>sketches</html>", "text/html")
        if self.path.startswith("/login/"):
            page = f'<form><input id="csrf_token" name="csrf_token" type="hidden" value="{self.token}"></form>'
            return self._send(200, page.encode(), "text/html")
        if not self._signed_in():
            return self._send(401)
        if self.path == "/api/v1/sketches/":
            return self._send(200, json.dumps({"objects": self.state["sketches"]}).encode())
        match = re.fullmatch(r"/api/v1/sketches/(\d+)/", self.path)
        if match:
            timelines = [{"name": n} for n in self.state["timelines"].get(int(match.group(1)), [])]
            return self._send(200, json.dumps({"objects": [{"timelines": timelines}]}).encode())
        self._send(404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        if self.path.startswith("/login/"):
            form = dict(p.split("=", 1) for p in body.decode().split("&"))
            if form.get("password") != "right" or form.get("csrf_token") != self.token:
                return self._send(302, headers={"Location": "/login/"})  # back to the form
            return self._send(302, headers={"Location": "/", "Set-Cookie": "session=ok; Path=/"})
        if not self._signed_in():
            return self._send(401)
        if self.path == "/api/v1/sketches/":
            made = {"id": 7, "name": json.loads(body)["name"]}
            self.state["sketches"].append(made)
            return self._send(201, json.dumps({"objects": [made]}).encode())
        if self.path == "/api/v1/upload/":
            message = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
                f"Content-Type: {self.headers['Content-Type']}\r\n\r\n".encode() + body)
            fields = {}
            for part in message.iter_parts():
                name = part.get_param("name", header="content-disposition")
                content = part.get_payload(decode=True)
                fields[name] = content if name == "file" else content.decode()
            self.state["uploads"].append(fields)
            return self._send(201, b'{"objects": [], "meta": {}}')
        self._send(404)

    def do_HEAD(self):
        self._send(200)


@pytest.fixture
def server():
    StandIn.state = {"sketches": [], "timelines": {}, "uploads": []}
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), StandIn)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()


def test_sign_in_and_send_a_timeline_per_host(tmp_path, server):
    make_host(tmp_path)
    target = timesketch.TimesketchTarget(url=server, username="analyst", password="right")
    sent = timesketch.export_case(str(tmp_path), "CASE-1", ALLIMGS, target)
    assert sent == {"LAB-WIN11": (2, 1)}
    assert StandIn.state["sketches"] == [{"id": 7, "name": "CASE-1"}]
    upload, = StandIn.state["uploads"]
    assert upload["name"] == "LAB-WIN11" and upload["sketch_id"] == "7" and upload["provider"] == "Rowanholt"
    assert int(upload["total_file_size"]) == len(upload["file"]) and "chunk_index" not in upload
    assert len(upload["file"].splitlines()) == 2


def test_a_wrong_password_is_refused(tmp_path, server):
    target = timesketch.TimesketchTarget(url=server, username="analyst", password="wrong")
    with pytest.raises(timesketch.TimesketchError, match="refused the sign-in"):
        timesketch.export_case(str(tmp_path), "CASE-1", ALLIMGS, target)


def test_a_host_already_in_the_sketch_is_left_alone(tmp_path, server):
    make_host(tmp_path)
    StandIn.state["sketches"].append({"id": 3, "name": "CASE-1"})
    StandIn.state["timelines"][3] = ["LAB-WIN11"]
    target = timesketch.TimesketchTarget(url=server, username="analyst", password="right")
    assert timesketch.export_case(str(tmp_path), "CASE-1", ALLIMGS, target) == {}
    assert StandIn.state["uploads"] == [] and len(StandIn.state["sketches"]) == 1


def test_a_large_timeline_goes_in_chunks(tmp_path, server):
    make_host(tmp_path)
    target = timesketch.TimesketchTarget(url=server, username="analyst", password="right")
    with mock.patch.object(timesketch, "CHUNK", 100):
        timesketch.export_case(str(tmp_path), "CASE-1", ALLIMGS, target)
    uploads = StandIn.state["uploads"]
    assert len(uploads) > 1
    assert [int(u["chunk_index"]) for u in uploads] == list(range(len(uploads)))
    assert {u["chunk_total_chunks"] for u in uploads} == {str(len(uploads))}
    assert len({u["chunk_index_name"] for u in uploads}) == 1
    assert [int(u["chunk_byte_offset"]) for u in uploads] == [i * 100 for i in range(len(uploads))]
    whole = b"".join(u["file"] for u in uploads)
    assert len(whole) == int(uploads[0]["total_file_size"]) and len(whole.splitlines()) == 2


# Wiring

def test_export_targets_runs_each_and_reports_failures(tmp_path):
    case = tmp_path / "CASE-1"
    (case / "LAB-WIN11" / "artefacts" / "cooked").mkdir(parents=True)
    (case / "LAB-WIN11" / "artefacts" / "host.info").write_text("LAB-WIN11::Windows10\n")
    with mock.patch.object(opensearch, "export_case", return_value={"LAB-WIN11": 3}) as os_export, \
            mock.patch.object(timesketch, "export_case", side_effect=timesketch.TimesketchError("down")):
        failed = index_only.export_targets(str(case), "CASE-1", "veryverbose", True, True)
    assert failed == ["Timesketch"]
    assert os_export.call_args.args[2] == {f"{case}/LAB-WIN11/artefacts/raw": "LAB-WIN11::Windows10"}
    audit = (case / "rowanholt_audit.log").read_text()
    assert "exported 1 host(s) to OpenSearch" in audit and "Timesketch export failed: down" in audit
