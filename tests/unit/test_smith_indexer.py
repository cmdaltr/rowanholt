"""The Smith CLI's indexer (rowanholt/ai/indexer.py) reads the case as Elrond writes it: hosts'
analysis and cooked tables, the Plaso timeline and the case's own tables, in any format."""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.append(str(REPO / "src" / "analysis"))

import rowanholt.ai.indexer as indexer  # noqa: E402
from rowanholt.core.records import write_records  # noqa: E402


class Store:
    def __init__(self):
        self.documents = []

    def add_documents(self, documents):
        self.documents.extend(documents)

    def persist(self):
        pass


class Document:
    def __init__(self, page_content, metadata):
        self.page_content, self.metadata = page_content, metadata


def test_index_all_reads_the_case_layout(tmp_path, monkeypatch):
    monkeypatch.setattr(indexer, "Document", Document, raising=False)
    host = tmp_path / "HOST"
    write_records(host / "artefacts" / "cooked" / "services" / "lab-sync.jsonl", [{"Name": "lab-sync", "ExecStart": "/tmp/x"}],
                  host="HOST", artefact="services/lab-sync", techniques=["T1543.002"])
    write_records(host / "analysis" / "iocs.jsonl", [{"ioc": "198.51.100.23", "indicator_type": "IPv4 address",
                                                      "Filename": "auth.log", "watchlist_match": "threat intel: APT34"}],
                  host="HOST", artefact="iocs")
    (host / "artefacts" / "cooked" / "old.csv").write_text("User,Command\nbob,curl http://x\n")
    write_records(tmp_path / "stacking.jsonl", [{"Value": "lab-sync"}], host="", artefact="stacking")
    (tmp_path / "vector_db").mkdir()

    index = indexer.ForensicDataIndexer.__new__(indexer.ForensicDataIndexer)
    index.case_id, index.vectorstore, index.logger = "C1", Store(), indexer.logging.getLogger("t")
    counts = index.index_all(str(tmp_path))

    assert counts == {"iocs": 1, "services/lab-sync": 1, "old": 1, "stacking": 1}
    by_type = {d.metadata["type"]: d for d in index.vectorstore.documents}
    assert by_type["ioc"].metadata["value"] == "198.51.100.23" and by_type["ioc"].metadata["severity"] == "watchlist"
    service = by_type["services/lab-sync"]
    assert "ExecStart: /tmp/x" in service.page_content and "host:" not in service.page_content
    assert service.metadata["techniques"] == "T1543.002" and service.metadata["row_ref"] == "1"
    assert json.dumps(by_type["old"].metadata)  # metadata stays plain for the vector store
