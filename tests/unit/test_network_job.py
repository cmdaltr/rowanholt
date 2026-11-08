"""The web app's Network evidence source becomes elrond.py --Network (tasks_docker.build_elrond_command)."""
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

# tasks_docker opens the job store on import: SQLite here, not the stack's Postgres
os.environ.setdefault("DATABASE_URL", f"sqlite:///{tempfile.mkdtemp(prefix='rowanholt-network-job-')}/jobs.db")
sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "web" / "backend"))

import tasks_docker as tasks  # noqa: E402  (the worker compose runs: tasks_docker.celery_app)
from models.job import AnalysisOptions  # noqa: E402


def command(tmp_path, **options):
    job = SimpleNamespace(case_number="NETCASE01", source_paths=[str(tmp_path / "lab.pcap")],
                          destination_path=str(tmp_path / "out"), options=AnalysisOptions(**options))
    return tasks.build_elrond_command(job)


def test_network_jobs_run_elrond_with_network(tmp_path):
    cmd = command(tmp_path, local=False, network=True, extract_iocs=True)
    assert "--Network" in cmd and "--Collect" not in cmd and "--Gandalf" not in cmd
    assert "--extractIocs" in cmd


def test_other_jobs_unchanged(tmp_path):
    assert "--Collect" in command(tmp_path) and "--Network" not in command(tmp_path)
    assert "--Gandalf" in command(tmp_path, local=False, gandalf=True)


def test_a_gandalf_case_goes_beside_its_acquisitions_not_in_them(tmp_path):
    """--Gandalf reads every folder in acquisitions/ as a host, so the case can't be one of them."""
    acquisitions = tmp_path / "acquisitions"
    acquisitions.mkdir()
    job = SimpleNamespace(case_number="WINSTACK", source_paths=[str(acquisitions)], destination_path=None,
                          options=AnalysisOptions(local=False, gandalf=True))
    assert tasks._resolve_destination(job) == tmp_path / "WINSTACK"
    job.options = AnalysisOptions()
    assert tasks._resolve_destination(job) == acquisitions / "WINSTACK"
