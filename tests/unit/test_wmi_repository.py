"""WMI event subscriptions carved from OBJECTS.DATA (synthetic, laid out as the lab's)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.process.wmi_repository import wmi_subscriptions  # noqa: E402

SID = bytes.fromhex("1c0000000105000000000005150000008959115568eadd4857af4f11e8030000")


def objects_data(*chunks: bytes) -> bytes:
    filler = b"\x01\x02noise\x00" * 40
    return filler + filler.join(chunks) + filler


def consumer(cls: str, name: str, *values: str) -> bytes:
    body = b"".join(b"\x00" + v.encode() + b"\x00" for v in values)
    return b"\x00\x00\x80\x00" + cls.encode() + b"\x00" + body + SID + b"\x00" + name.encode() + b"\x00" * 64


def event_filter(name: str, query: str) -> bytes:
    return b"\x00__EventFilter\x00" + SID + b"root\\cimv2\x00\x00" + name.encode() + b"\x00\x00" + query.encode() + b"\x00WQL\x00" + b"\x00" * 32


def binding(cls: str, consumer_name: str, filter_name: str) -> bytes:
    return (b"__FilterToConsumerBinding\x00\x00" + f'{cls}.Name="{consumer_name}"'.encode() + b"\x00"
            + SID + f'__EventFilter.Name="{filter_name}"'.encode() + b"\x00")


def test_subscription_is_carved_with_payload_and_query(tmp_path: Path) -> None:
    path = tmp_path / "OBJECTS.DATA"
    path.write_bytes(objects_data(
        consumer("CommandLineEventConsumer", "Updater", "powershell -enc AAAA"),
        event_filter("UpdaterFilter", "SELECT * FROM __InstanceModificationEvent WITHIN 60"),
        binding("CommandLineEventConsumer", "Updater", "UpdaterFilter"),
        binding("CommandLineEventConsumer", "Updater", "UpdaterFilter"),
    ))
    assert wmi_subscriptions(path) == [{
        "filter_name": "UpdaterFilter",
        "filter_query": "SELECT * FROM __InstanceModificationEvent WITHIN 60",
        "consumer_class": "CommandLineEventConsumer",
        "consumer_name": "Updater",
        "consumer_values": ["powershell -enc AAAA"],
    }]


def test_windows_own_subscription_is_marked_benign(tmp_path: Path) -> None:
    path = tmp_path / "OBJECTS.DATA"
    path.write_bytes(objects_data(binding("NTEventLogEventConsumer", "SCM Event Log Consumer", "SCM Event Log Filter")))
    [record] = wmi_subscriptions(path)
    assert record["note"].startswith("likely benign")


def test_no_bindings(tmp_path: Path) -> None:
    path = tmp_path / "OBJECTS.DATA"
    path.write_bytes(objects_data(consumer("CommandLineEventConsumer", "Orphan", "cmd /c x")))
    assert wmi_subscriptions(path) == []


def test_carved_subscriptions_become_the_wbem_table(tmp_path: Path) -> None:
    """process/windows.py's carve, end to end: wbem.jsonl with the envelope, T1546.003 on the
    subscription Windows didn't make, and the table enriched (it once named a variable that didn't exist)."""
    from rowanholt.core.records import check_file, read_records
    from rowanholt.process import windows
    out = str(tmp_path / "out") + "/"
    wbem_dir = tmp_path / "out" / "HOST" / "artefacts" / "raw" / "wmi"
    wbem_dir.mkdir(parents=True)
    (tmp_path / "out" / "HOST" / "artefacts" / "cooked").mkdir()
    (wbem_dir / "OBJECTS.DATA").write_bytes(objects_data(
        consumer("CommandLineEventConsumer", "Updater", "powershell -enc AAAA"),
        event_filter("UpdaterFilter", "SELECT * FROM __InstanceModificationEvent WITHIN 60"),
        binding("CommandLineEventConsumer", "Updater", "UpdaterFilter"),
        binding("NTEventLogEventConsumer", "SCM Event Log Consumer", "SCM Event Log Filter"),
    ))
    windows.carve_wmi_subscriptions("", "'HOST'", out, "HOST::Windows", "/", "processing", str(wbem_dir))
    table = tmp_path / "out" / "HOST" / "artefacts" / "cooked" / "wbem.jsonl"
    assert check_file(table) == []
    records = {r["consumer_name"]: r for _, r in read_records(table)}
    assert "T1546.003" in records["Updater"]["techniques"]
    assert records["SCM Event Log Consumer"]["techniques"] == []
    assert records["Updater"]["source_path"] == "artefacts/raw/wmi/OBJECTS.DATA"
