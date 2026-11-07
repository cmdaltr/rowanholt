"""SIEM pre-flight: retry while the SIEM starts, fail at once when its name doesn't resolve."""
import socket
import sys
from pathlib import Path

import pytest

# Appended, not prepended: src/analysis/platform would shadow the stdlib module.
sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.post import siem  # noqa: E402


class Conn:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def connector(outcomes):
    calls = []

    def connect(address, timeout):
        calls.append(address)
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return Conn()
    return connect, calls


def test_refused_is_retried_until_the_siem_accepts(monkeypatch):
    connect, calls = connector([ConnectionRefusedError(), ConnectionRefusedError(), "ok"])
    monkeypatch.setattr(siem.socket, "create_connection", connect)
    monkeypatch.setattr(siem.time, "sleep", lambda _: None)
    siem._check_reachable("Splunk", "splunk", "8089", 1, delays=(1, 1, 1))
    assert len(calls) == 3


def test_dns_failure_is_not_retried(monkeypatch):
    connect, calls = connector([socket.gaierror(-2, "Name or service not known")])
    monkeypatch.setattr(siem.socket, "create_connection", connect)
    with pytest.raises(siem.SIEMUnavailableError, match="doesn't resolve"):
        siem._check_reachable("Splunk", "splunk", "8089", 1, delays=(1, 1))
    assert len(calls) == 1


def test_gives_up_after_the_last_delay(monkeypatch):
    connect, calls = connector([ConnectionRefusedError()] * 3)
    monkeypatch.setattr(siem.socket, "create_connection", connect)
    monkeypatch.setattr(siem.time, "sleep", lambda _: None)
    with pytest.raises(siem.SIEMUnavailableError, match="after 3 attempts"):
        siem._check_reachable("Splunk", "splunk", "8089", 1, delays=(1, 1))


def test_memory_hosts_are_named_from_their_key(tmp_path):
    allimgs = {"/mnt/elrond_mount00": "WIN.E01::Windows",
               "/mnt/elrond_mount01": "WIN.E01::Windows_vss1",
               "mem.raw::Win10x64_19041": "/evidence/case1"}
    assert siem.siem_hosts(allimgs) == [("WIN.E01", "WIN.E01::Windows"),
                                        ("WIN.E01", "WIN.E01::Windows_vss1"),
                                        ("mem.raw", "mem.raw::Win10x64_19041")]


def test_memory_outputs_are_found_beside_artefacts(tmp_path):
    (tmp_path / "memory_pslist.json").write_text("[]")
    (tmp_path / "artefacts").mkdir()
    assert [Path(p).name for p in siem.memory_outputs(str(tmp_path))] == ["memory_pslist.json"]


def test_memory_outputs_in_json_lines_too(tmp_path):
    (tmp_path / "memory_pslist.jsonl").write_text('{"PID": 4}\n')
    (tmp_path / "memory_netscan.json").write_text("[]")
    assert [Path(p).name for p in siem.memory_outputs(str(tmp_path))] == [
        "memory_netscan.json", "memory_pslist.jsonl"]


def test_a_refused_splunk_login_fails_the_run(monkeypatch):
    """Splunk refusing admin's remote login (its default password) only warned, and the run
    reported success with nothing indexed (7 November 2026)."""
    import io
    import urllib.error
    body = b'<response><messages><msg type="WARN">Remote login has been disabled for admin</msg></messages></response>'

    def refuse(request, context, timeout):
        raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", {}, io.BytesIO(body))
    monkeypatch.setattr(siem.urllib.request, "urlopen", refuse)
    with pytest.raises(siem.SIEMUnavailableError, match="refused the login for 'admin' .401: Remote login has been disabled"):
        siem._check_splunk_login("splunk", "8089", "admin", "x", 1)


def test_an_accepted_or_unreadable_splunk_answer_lets_the_run_go_on(monkeypatch):
    import io
    import urllib.error

    class Answer:
        def close(self):
            pass
    monkeypatch.setattr(siem.urllib.request, "urlopen", lambda request, context, timeout: Answer())
    siem._check_splunk_login("splunk", "8089", "admin", "x", 1)

    def broken(request, context, timeout):
        raise urllib.error.HTTPError(request.full_url, 503, "Unavailable", {}, io.BytesIO(b""))
    monkeypatch.setattr(siem.urllib.request, "urlopen", broken)
    siem._check_splunk_login("splunk", "8089", "admin", "x", 1)
