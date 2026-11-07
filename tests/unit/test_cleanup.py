"""End-of-run cleanup (post/clean.py): processed output tidied, collected artefacts kept (E15, E20, E25)."""
import sys
from pathlib import Path

# Appended, not prepended: src/analysis/platform would shadow the stdlib module.
sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.post.clean import (  # noqa: E402
    cleanup_small_files_and_empty_dirs, output_folder_name, tidy_processed_output)


def write(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    return path


def test_every_kind_of_entry_names_its_case_folder():
    # Disk image: keyed by mount point (E20: the old cleanup used the key, elrond_mount00)
    assert output_folder_name("/mnt/elrond_mount00", "WIN-DC01.E01::Windows") == "WIN-DC01.E01"
    # Gandalf host: keyed by its raw/ directory
    assert output_folder_name("/out/lab-win11/artefacts/raw", "lab-win11::Windows") == "lab-win11"
    # Memory: the name is the key, the value the dump's directory
    assert output_folder_name("mem.raw::Win10x64_19041", "/evidence/case1") == "mem.raw"


def test_tidy_drops_empty_processed_output_but_not_raw(tmp_path):
    host = tmp_path / "host"
    empty_cooked = write(host / "artefacts" / "cooked" / "registry" / "a.json", "[]")
    write(host / "artefacts" / "cooked" / "registry" / "b.json", "[" + "1," * 100 + "1]")
    empty_analysis = write(host / "analysis" / "iocs.csv", "ioc\n")
    history = write(host / "artefacts" / "raw" / "user_profiles" / "root+.bash_history", "")
    tidy_processed_output(str(host))
    assert not empty_cooked.exists() and not empty_analysis.exists()
    assert history.exists()


def test_a_lone_old_format_file_is_lifted_with_its_own_extension(tmp_path):
    host = tmp_path / "host"
    write(host / "artefacts" / "cooked" / "usnjrnl" / "journal.json", "[" + "1," * 100 + "1]")
    write(host / "artefacts" / "cooked" / "prefetch" / "prefetch.csv", "Filename\n" + "x" * 200 + "\n")
    write(host / "artefacts" / "cooked" / "tasks" / "tasks.jsonl", '{"host": "h"}\n')
    tidy_processed_output(str(host))
    cooked = host / "artefacts" / "cooked"
    assert (cooked / "usnjrnl.json").is_file()
    assert (cooked / "prefetch.csv").is_file()  # was renamed prefetch.json
    assert (cooked / "tasks" / "tasks.jsonl").is_file()  # records say artefact "tasks/tasks": not moved


def test_tables_with_no_records_go_however_small_the_rest(tmp_path):
    host = tmp_path / "host"
    one = write(host / "artefacts" / "cooked" / "hosts.jsonl", '{"host": "h", "Name": "x"}\n')
    blank = write(host / "artefacts" / "cooked" / "sudoers.jsonl", "\n\n")
    header = write(host / "analysis" / "iocs.csv", "ioc,Filename,LastWriteTime,Source,Context,Extra,More,Fields\n")
    tidy_processed_output(str(host))
    assert one.is_file()  # one record is under 100 bytes, and is kept
    assert not blank.exists() and not header.exists()  # the header's over 100 bytes, but empty


def test_one_walk_removes_small_files_and_nested_empty_dirs(tmp_path):
    write(tmp_path / "h" / "artefacts" / "cooked" / "a" / "b" / "tiny.json", "[]")
    write(tmp_path / "h" / "._meta", "x" * 50)
    kept = write(tmp_path / "h" / "artefacts" / "raw" / "crontab", "")
    files, dirs = cleanup_small_files_and_empty_dirs(str(tmp_path))
    assert files == 2
    assert not (tmp_path / "h" / "artefacts" / "cooked").exists()
    assert kept.exists() and tmp_path.is_dir()


def test_the_case_archive_is_in_the_case_and_survives_deletion(tmp_path):
    from rowanholt.post.clean import archive_artefacts, delete_artefacts
    import zipfile
    case = tmp_path / "CASE-1"
    write(case / "host" / "artefacts" / "raw" / "crontab", "* * * * * x")
    write(case / "rowanholt_audit.log", "")
    archive_artefacts("", str(case) + "/")
    delete_artefacts("", str(case) + "/")
    archive = case / "CASE-1.zip"
    assert archive.is_file() and not (tmp_path / "CASE-1.zip").exists()
    with zipfile.ZipFile(archive) as z:
        assert "host/artefacts/raw/crontab" in z.namelist()
        assert "CASE-1.zip" not in z.namelist()
