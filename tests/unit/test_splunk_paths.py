"""Splunk monitors the worker's own output path, and says when it can't see it (E10)."""
import sys
from pathlib import Path

# Appended, not prepended: src/analysis/platform would shadow the stdlib module.
sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.post.splunk.config import monitor_roots, splunk_can_see  # noqa: E402


def test_default_and_custom_destinations_are_visible(monkeypatch):
    monkeypatch.delenv("SPLUNK_MONITOR_ROOTS", raising=False)
    assert splunk_can_see("/tmp/elrond/output/CASE-1/host")
    assert splunk_can_see("/Volumes/Portable6TB/Data/rowanholt/claude_testing/win_full/host")


def test_paths_outside_the_mounts_are_not(monkeypatch):
    monkeypatch.delenv("SPLUNK_MONITOR_ROOTS", raising=False)
    assert not splunk_can_see("/data/cases/CASE-1/host")
    assert not splunk_can_see("/Volumesx/host")


def test_roots_are_configurable(monkeypatch):
    monkeypatch.setenv("SPLUNK_MONITOR_ROOTS", "/data/cases, /tmp/elrond/output")
    assert monitor_roots() == ["/data/cases", "/tmp/elrond/output"]
    assert splunk_can_see("/data/cases/CASE-1/host")
