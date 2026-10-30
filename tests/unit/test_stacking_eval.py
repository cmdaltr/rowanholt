"""The lab's stacking evaluation (lab/lib/stacking_eval.py): plants from expected.json, precision and
ranks from stacking.csv, and the row it adds to the README's table."""
import importlib.util
import json
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "lab" / "lib" / "stacking_eval.py"
spec = importlib.util.spec_from_file_location("stacking_eval", SCRIPT)
stacking_eval = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stacking_eval)

HEADER = "Rank,Score,Family,Value,Hosts With It,Hosts In Case,Hosts,Reasons,Artefact,Example\n"


def lab_run(tmp_path: Path, rows: str) -> Path:
    (tmp_path / "acq" / "lab-ubuntu").mkdir(parents=True)
    (tmp_path / "acq" / "lab-ubuntu-clean1").mkdir()
    (tmp_path / "acq" / "lab-ubuntu" / "expected.json").write_text(json.dumps(
        {"seeded": [], "stacking": ["lab-sync.service", "lab-agent.service", "lab updater"]}))
    (tmp_path / "out" / "CASE").mkdir(parents=True)
    (tmp_path / "out" / "CASE" / "stacking.csv").write_text(HEADER + rows)
    readme = tmp_path / "README.md"
    readme.write_text("| Date | Hosts | Rows | P@4 | P@8 | P@20 | Plant ranks |\n|---|---|---|---|---|---|---|\n"
                      f"{stacking_eval.TABLE_END}\n")
    return readme


def run(tmp_path: Path, monkeypatch, *extra: str) -> int:
    monkeypatch.setattr(sys, "argv", ["stacking_eval.py", str(tmp_path / "out"), str(tmp_path / "acq"), *extra])
    return stacking_eval.main()


def test_scores_and_records(tmp_path, monkeypatch, capsys):
    readme = lab_run(tmp_path,
                     '1,1.0,"service (systemd), debian",lab-sync.service,1,3,lab-ubuntu,rare,x,lab-sync.service\n'
                     '2,1.0,process,/usr/bin/odd,1,3,lab-ubuntu,rare,x,\n'
                     '3,1.0,"autorun (Linux), debian",lab updater,1,3,lab-ubuntu,rare,x,/tmp/.x/update.sh\n'
                     '4,1.0,"autorun (Linux), debian",lab-agent.service,1,3,lab-ubuntu,rare,x,\n'
                     '5,1.0,process,/usr/bin/odder,1,3,lab-ubuntu,rare,x,\n')
    assert run(tmp_path, monkeypatch, "--readme", str(readme), "--label", "synthetic") == 0
    out = capsys.readouterr().out
    assert "5 rows" in out and "precision@4: 0.75" in out and "precision@8: 0.60" in out
    rows = readme.read_text().splitlines()
    assert rows[-2].endswith("| synthetic | 5 | 0.75 | 0.60 | 0.60 | 1, 3, 4 |")
    assert rows[-1] == stacking_eval.TABLE_END


def test_missing_plant_fails(tmp_path, monkeypatch, capsys):
    lab_run(tmp_path, '1,1.0,"service (systemd), debian",lab-sync.service,1,3,lab-ubuntu,rare,x,\n')
    assert run(tmp_path, monkeypatch) == 1
    assert "lab updater: NOT FOUND" in capsys.readouterr().out
