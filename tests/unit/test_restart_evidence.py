"""A fresh restart removes the job's output directory, never a source inside it (tasks._sources_inside)."""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "web" / "backend"))

import tasks  # noqa: E402


def test_sources_inside_the_output_are_found(tmp_path):
    out = tmp_path / "CASE-1"
    (out / "evidence").mkdir(parents=True)
    image = out / "evidence" / "disk.E01"
    image.write_text("x")
    outside = tmp_path / "uploads" / "host.zip"
    outside.parent.mkdir()
    outside.write_text("x")
    assert tasks._sources_inside(SimpleNamespace(source_paths=[str(outside), str(image)]), out) == str(image)
    assert tasks._sources_inside(SimpleNamespace(source_paths=[str(out)]), out) == str(out)
    assert tasks._sources_inside(SimpleNamespace(source_paths=[str(outside)]), out) is None
    # A sibling whose name starts the same isn't inside
    assert tasks._sources_inside(SimpleNamespace(source_paths=[str(tmp_path / "CASE-10" / "x.zip")]), out) is None
