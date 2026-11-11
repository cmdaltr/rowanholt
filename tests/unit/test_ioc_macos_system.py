"""IOC extraction leaves a macOS image's sealed system volume out unless asked
(analysis/iocs.py macos_system_volume_included gives the reasoning), and a job's
ioc_system_volume option asks for it with elrond.py --iocsSystemVolume."""
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("DATABASE_URL", f"sqlite:///{tempfile.mkdtemp(prefix='rowanholt-ioc-macos-')}/jobs.db")
REPO = Path(__file__).resolve().parents[2]
# The backend first: with src/analysis on the path, its imports would find elrond.py, which parses argv
sys.path.append(str(REPO / "src" / "web" / "backend"))
import tasks_docker as tasks  # noqa: E402
from models.job import AnalysisOptions  # noqa: E402

sys.path.append(str(REPO / "src" / "analysis"))
from rowanholt.analysis import iocs  # noqa: E402


def walked(top: Path, tops) -> set:
    """Every file os.walk reaches under top, with macos_system_dirs pruning as analysis.py does."""
    seen = set()
    for root, dirs, files in os.walk(top):
        iocs.macos_system_dirs(root, dirs, tops)
        seen.update(str(Path(root, f).relative_to(top)) for f in files)
    return seen


def tree(base: Path, paths) -> None:
    for rel in paths:
        (base / rel).parent.mkdir(parents=True, exist_ok=True)
        (base / rel).write_text("x")


MAC = ["System/Library/Perl/Encode.pm", "bin/zsh", "sbin/launchd", "usr/share/locale/ga.po",
       "usr/lib/libz.dylib", "usr/local/bin/implant.sh", "Library/LaunchDaemons/evil.plist",
       "Users/admin/.zsh_history", "private/tmp/stage.sh", "Applications/Helper.app/x", "opt/tool/run"]


def test_the_sealed_system_volume_is_left_out_and_everything_else_read(tmp_path):
    tree(tmp_path, MAC)
    seen = walked(tmp_path, [str(tmp_path), str(tmp_path / "root")])
    assert seen == {"usr/local/bin/implant.sh", "Library/LaunchDaemons/evil.plist", "Users/admin/.zsh_history",
                    "private/tmp/stage.sh", "Applications/Helper.app/x", "opt/tool/run"}


def test_apfs_fuse_puts_the_system_under_root_and_it_is_pruned_there_too(tmp_path):
    tree(tmp_path / "root", MAC)
    seen = walked(tmp_path, [str(tmp_path), str(tmp_path / "root")])
    assert "root/usr/local/bin/implant.sh" in seen and "root/Library/LaunchDaemons/evil.plist" in seen
    assert not {s for s in seen if s.startswith(("root/System/", "root/bin/", "root/sbin/", "root/usr/share/"))}


def test_only_the_system_root_is_pruned_not_folders_of_the_same_name_deeper_down(tmp_path):
    tree(tmp_path, ["Users/admin/System/notes.txt", "Users/admin/usr/share/x.txt", "Library/bin/tool"])
    assert walked(tmp_path, [str(tmp_path)]) == {"Users/admin/System/notes.txt", "Users/admin/usr/share/x.txt",
                                                 "Library/bin/tool"}


def test_reading_the_system_volume_is_off_unless_asked():
    with mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop("ROWANHOLT_MACOS_SYSTEM_IOCS", None)
        assert not iocs.macos_system_volume_included()
    for value in ("1", "true", "yes", "on"):
        with mock.patch.dict(os.environ, {"ROWANHOLT_MACOS_SYSTEM_IOCS": value}):
            assert iocs.macos_system_volume_included()
    with mock.patch.dict(os.environ, {"ROWANHOLT_MACOS_SYSTEM_IOCS": "0"}):
        assert not iocs.macos_system_volume_included()


def command(tmp_path, **options):
    job = SimpleNamespace(case_number="MACCASE01", source_paths=[str(tmp_path / "disk.img")],
                          destination_path=str(tmp_path / "out"), options=AnalysisOptions(**options))
    return tasks.build_elrond_command(job)


def test_a_job_asks_for_the_system_volume_only_with_ioc_extraction(tmp_path):
    assert "--iocsSystemVolume" not in command(tmp_path, extract_iocs=True)
    assert "--iocsSystemVolume" in command(tmp_path, extract_iocs=True, ioc_system_volume=True)
    assert "--iocsSystemVolume" not in command(tmp_path, ioc_system_volume=True)  # nothing to read it for
