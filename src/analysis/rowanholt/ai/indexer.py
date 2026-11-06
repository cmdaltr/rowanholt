#!/usr/bin/env python3
"""
Forensic Data Indexer

Index forensic artifacts for AI-powered querying using vector embeddings.

Author: Rowanholt DF Acceleration Suite
Version: 2.1.0
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path

try:
    from langchain.embeddings import HuggingFaceEmbeddings
    from langchain.vectorstores import Chroma
    from langchain.text_splitter import RecursiveCharacterTextSplitter
    from langchain.schema import Document

    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

from rowanholt.core.records import ENVELOPE, TABLE_SUFFIXES, read_records, table_path

MAX_ROWS_PER_TABLE = 5000  # embedding runs on the CPU: an MFT or a busy event log would take days
MAX_FIELD = 300


class ForensicDataIndexer:
    """
    Index forensic artifacts for AI querying.

    Indexes various artifact types:
    - Timeline events
    - IOCs (Indicators of Compromise)
    - Process information
    - Network connections
    - Registry keys
    - File listings
    - Cloud audit logs
    """

    def __init__(self, case_id: str, output_dir: str, config: Optional[Dict] = None):
        """
        Initialize forensic data indexer.

        Args:
            case_id: Case identifier
            output_dir: Output directory for vector database
            config: Optional configuration dict
        """
        if not LANGCHAIN_AVAILABLE:
            raise ImportError(
                "LangChain required for AI indexing. Install with: "
                "pip install langchain chromadb sentence-transformers"
            )

        self.case_id = case_id
        self.output_dir = output_dir
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Vector DB directory
        self.vector_db_dir = os.path.join(output_dir, "vector_db")
        os.makedirs(self.vector_db_dir, exist_ok=True)

        # Initialize embedding model
        embedding_model = self.config.get(
            "embedding_model", "sentence-transformers/all-MiniLM-L6-v2"
        )
        self.embeddings = HuggingFaceEmbeddings(
            model_name=embedding_model, model_kwargs={"device": self.config.get("device", "cpu")}
        )

        # Initialize vector store
        self.vectorstore = Chroma(
            collection_name=f"case_{case_id}",
            embedding_function=self.embeddings,
            persist_directory=self.vector_db_dir,
        )

        # Text splitter for large documents
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000, chunk_overlap=200, length_function=len
        )

        self.logger.info(f"Initialized indexer for case {case_id}")

    def index_timeline(self, timeline_csv: str) -> int:
        """
        Index timeline events for querying.

        Args:
            timeline_csv: Path to timeline CSV file

        Returns:
            Number of events indexed
        """
        if not os.path.exists(timeline_csv):
            self.logger.warning(f"Timeline file not found: {timeline_csv}")
            return 0

        try:
            rows = self._rows(timeline_csv)
            self.logger.info(f"Indexing {len(rows)} timeline events...")

            documents = []
            for row in rows:
                # Create document text
                doc_text = f"""
Timestamp: {row.get('timestamp', 'N/A')}
Event Type: {row.get('event_type', row.get('type', 'N/A'))}
Source: {row.get('source', 'N/A')}
Description: {row.get('description', row.get('desc', 'N/A'))}
User: {row.get('user', row.get('username', 'N/A'))}
Process: {row.get('process', row.get('process_name', 'N/A'))}
File: {row.get('file', row.get('filename', row.get('path', 'N/A')))}
"""

                # Create metadata
                metadata = {
                    "type": "timeline",
                    "timestamp": str(row.get("timestamp", "N/A")),
                    "source": str(row.get("source", "N/A")),
                    "event_type": str(row.get("event_type", row.get("type", "N/A"))),
                    "case_id": self.case_id,
                }

                documents.append(Document(page_content=doc_text, metadata=metadata))

            # Add to vector store
            if documents:
                self.vectorstore.add_documents(documents)
                self.vectorstore.persist()

            self.logger.info(f"Indexed {len(documents)} timeline events")
            return len(documents)

        except Exception as e:
            self.logger.error(f"Error indexing timeline: {e}")
            return 0

    def index_iocs(self, iocs_csv: str) -> int:
        """
        Index IOCs for querying.

        Args:
            iocs_csv: Path to IOCs CSV file

        Returns:
            Number of IOCs indexed
        """
        if not os.path.exists(iocs_csv):
            self.logger.warning(f"IOCs file not found: {iocs_csv}")
            return 0

        try:
            rows = self._rows(iocs_csv)
            self.logger.info(f"Indexing {len(rows)} IOCs...")

            documents = []
            for row in rows:
                doc_text = f"""
IOC Type: {row.get('indicator_type', 'N/A')}
Value: {row.get('ioc', 'N/A')}
Found In: {row.get('Filename', 'N/A')} line {row.get('line_number', 'N/A')}
Host: {row.get('host', row.get('hostname', 'N/A'))}
Resolvable: {row.get('resolvable', 'N/A')}
Watchlist: {row.get('watchlist_match') or 'none'}
"""

                metadata = {
                    "type": "ioc",
                    "ioc_type": str(row.get("indicator_type", "N/A")),
                    "value": str(row.get("ioc", "N/A")),
                    "severity": "watchlist" if row.get("watchlist_match") else "unknown",
                    "case_id": self.case_id,
                }

                documents.append(Document(page_content=doc_text, metadata=metadata))

            if documents:
                self.vectorstore.add_documents(documents)
                self.vectorstore.persist()

            self.logger.info(f"Indexed {len(documents)} IOCs")
            return len(documents)

        except Exception as e:
            self.logger.error(f"Error indexing IOCs: {e}")
            return 0

    def index_processes(self, processes_csv: str) -> int:
        """
        Index process information.

        Args:
            processes_csv: Path to processes CSV file

        Returns:
            Number of processes indexed
        """
        if not os.path.exists(processes_csv):
            self.logger.warning(f"Processes file not found: {processes_csv}")
            return 0

        try:
            rows = self._rows(processes_csv)
            self.logger.info(f"Indexing {len(rows)} processes...")

            documents = []
            for row in rows:
                doc_text = f"""
Process Name: {row.get('name', row.get('process_name', 'N/A'))}
PID: {row.get('pid', 'N/A')}
Parent PID: {row.get('ppid', row.get('parent_pid', 'N/A'))}
Command Line: {row.get('cmdline', row.get('command_line', 'N/A'))}
User: {row.get('user', row.get('username', 'N/A'))}
Path: {row.get('path', row.get('exe_path', 'N/A'))}
Start Time: {row.get('start_time', row.get('creation_time', 'N/A'))}
"""

                metadata = {
                    "type": "process",
                    "name": str(row.get("name", row.get("process_name", "N/A"))),
                    "pid": str(row.get("pid", "N/A")),
                    "case_id": self.case_id,
                }

                documents.append(Document(page_content=doc_text, metadata=metadata))

            if documents:
                self.vectorstore.add_documents(documents)
                self.vectorstore.persist()

            self.logger.info(f"Indexed {len(documents)} processes")
            return len(documents)

        except Exception as e:
            self.logger.error(f"Error indexing processes: {e}")
            return 0

    def index_network(self, network_csv: str) -> int:
        """
        Index network connections.

        Args:
            network_csv: Path to network CSV file

        Returns:
            Number of connections indexed
        """
        if not os.path.exists(network_csv):
            self.logger.warning(f"Network file not found: {network_csv}")
            return 0

        try:
            rows = self._rows(network_csv)
            self.logger.info(f"Indexing {len(rows)} network connections...")

            documents = []
            for row in rows:
                doc_text = f"""
Local Address: {row.get('local_address', row.get('src_ip', 'N/A'))}
Local Port: {row.get('local_port', row.get('src_port', 'N/A'))}
Remote Address: {row.get('remote_address', row.get('dst_ip', 'N/A'))}
Remote Port: {row.get('remote_port', row.get('dst_port', 'N/A'))}
Protocol: {row.get('protocol', 'N/A')}
State: {row.get('state', 'N/A')}
Process: {row.get('process', row.get('process_name', 'N/A'))}
PID: {row.get('pid', 'N/A')}
"""

                metadata = {
                    "type": "network",
                    "remote_address": str(row.get("remote_address", row.get("dst_ip", "N/A"))),
                    "protocol": str(row.get("protocol", "N/A")),
                    "case_id": self.case_id,
                }

                documents.append(Document(page_content=doc_text, metadata=metadata))

            if documents:
                self.vectorstore.add_documents(documents)
                self.vectorstore.persist()

            self.logger.info(f"Indexed {len(documents)} network connections")
            return len(documents)

        except Exception as e:
            self.logger.error(f"Error indexing network connections: {e}")
            return 0

    def index_registry(self, registry_csv: str) -> int:
        """
        Index Windows registry keys.

        Args:
            registry_csv: Path to registry CSV file

        Returns:
            Number of registry keys indexed
        """
        if not os.path.exists(registry_csv):
            self.logger.warning(f"Registry file not found: {registry_csv}")
            return 0

        try:
            rows = self._rows(registry_csv)
            self.logger.info(f"Indexing {len(rows)} registry keys...")

            documents = []
            for row in rows:
                doc_text = f"""
Registry Key: {row.get('key', row.get('path', 'N/A'))}
Value Name: {row.get('value_name', row.get('name', 'N/A'))}
Value Data: {row.get('value_data', row.get('data', 'N/A'))}
Value Type: {row.get('value_type', row.get('type', 'N/A'))}
Last Modified: {row.get('last_modified', row.get('modified', 'N/A'))}
"""

                metadata = {
                    "type": "registry",
                    "key": str(row.get("key", row.get("path", "N/A"))),
                    "case_id": self.case_id,
                }

                documents.append(Document(page_content=doc_text, metadata=metadata))

            if documents:
                self.vectorstore.add_documents(documents)
                self.vectorstore.persist()

            self.logger.info(f"Indexed {len(documents)} registry keys")
            return len(documents)

        except Exception as e:
            self.logger.error(f"Error indexing registry: {e}")
            return 0

    def index_files(self, files_csv: str) -> int:
        """
        Index file listings.

        Args:
            files_csv: Path to files CSV file

        Returns:
            Number of files indexed
        """
        if not os.path.exists(files_csv):
            self.logger.warning(f"Files listing not found: {files_csv}")
            return 0

        try:
            rows = self._rows(files_csv)
            self.logger.info(f"Indexing {len(rows)} files...")

            documents = []
            for row in rows:
                doc_text = f"""
File Path: {row.get('path', row.get('file_path', 'N/A'))}
File Name: {row.get('name', row.get('filename', 'N/A'))}
Size: {row.get('size', 'N/A')} bytes
Created: {row.get('created', row.get('creation_time', 'N/A'))}
Modified: {row.get('modified', row.get('modification_time', 'N/A'))}
Accessed: {row.get('accessed', row.get('access_time', 'N/A'))}
Hash MD5: {row.get('md5', 'N/A')}
Hash SHA256: {row.get('sha256', 'N/A')}
"""

                metadata = {
                    "type": "file",
                    "path": str(row.get("path", row.get("file_path", "N/A"))),
                    "name": str(row.get("name", row.get("filename", "N/A"))),
                    "case_id": self.case_id,
                }

                documents.append(Document(page_content=doc_text, metadata=metadata))

            if documents:
                self.vectorstore.add_documents(documents)
                self.vectorstore.persist()

            self.logger.info(f"Indexed {len(documents)} files")
            return len(documents)

        except Exception as e:
            self.logger.error(f"Error indexing files: {e}")
            return 0

    def index_cloud_logs(self, logs_json: str, provider: str) -> int:
        """
        Index cloud audit logs.

        Args:
            logs_json: Path to cloud logs JSON file
            provider: Cloud provider (aws, azure, gcp)

        Returns:
            Number of log entries indexed
        """
        if not os.path.exists(logs_json):
            self.logger.warning(f"Cloud logs file not found: {logs_json}")
            return 0

        try:
            with open(logs_json, "r") as f:
                logs = json.load(f)

            if not isinstance(logs, list):
                logs = [logs]

            self.logger.info(f"Indexing {len(logs)} cloud log entries...")

            documents = []
            for log in logs:
                # Format based on provider
                if provider == "aws":
                    doc_text = self._format_aws_log(log)
                elif provider == "azure":
                    doc_text = self._format_azure_log(log)
                elif provider == "gcp":
                    doc_text = self._format_gcp_log(log)
                else:
                    doc_text = json.dumps(log, indent=2)

                metadata = {"type": "cloud_log", "provider": provider, "case_id": self.case_id}

                documents.append(Document(page_content=doc_text, metadata=metadata))

            if documents:
                self.vectorstore.add_documents(documents)
                self.vectorstore.persist()

            self.logger.info(f"Indexed {len(documents)} cloud log entries")
            return len(documents)

        except Exception as e:
            self.logger.error(f"Error indexing cloud logs: {e}")
            return 0

    def _format_aws_log(self, log: Dict) -> str:
        """Format AWS CloudTrail log."""
        return f"""
Event Name: {log.get('event_name', log.get('eventName', 'N/A'))}
Event Time: {log.get('event_time', log.get('eventTime', 'N/A'))}
User: {log.get('user_identity', {}).get('userName', 'N/A')}
Source IP: {log.get('source_ip_address', log.get('sourceIPAddress', 'N/A'))}
User Agent: {log.get('user_agent', log.get('userAgent', 'N/A'))}
AWS Region: {log.get('aws_region', log.get('awsRegion', 'N/A'))}
Request Parameters: {json.dumps(log.get('request_parameters', log.get('requestParameters', {})))}
Response: {json.dumps(log.get('response_elements', log.get('responseElements', {})))}
"""

    def _format_azure_log(self, log: Dict) -> str:
        """Format Azure Activity Log."""
        return f"""
Operation Name: {log.get('operation_name', log.get('operationName', 'N/A'))}
Event Timestamp: {log.get('event_timestamp', log.get('eventTimestamp', 'N/A'))}
Caller: {log.get('caller', 'N/A')}
Resource: {log.get('resource_id', log.get('resourceId', 'N/A'))}
Status: {log.get('status', {}).get('value', 'N/A')}
Subscription: {log.get('subscription_id', log.get('subscriptionId', 'N/A'))}
Properties: {json.dumps(log.get('properties', {}))}
"""

    def _format_gcp_log(self, log: Dict) -> str:
        """Format GCP Cloud Logging entry."""
        proto_payload = log.get("proto_payload", {})
        return f"""
Method Name: {proto_payload.get('method_name', proto_payload.get('methodName', 'N/A'))}
Service Name: {proto_payload.get('service_name', proto_payload.get('serviceName', 'N/A'))}
Timestamp: {log.get('timestamp', 'N/A')}
Caller IP: {proto_payload.get('caller_ip', 'N/A')}
Resource Name: {proto_payload.get('resource_name', proto_payload.get('resourceName', 'N/A'))}
Request: {json.dumps(proto_payload.get('request', {}))}
Response: {json.dumps(proto_payload.get('response', {}))}
"""

    def _rows(self, path: str) -> List[Dict[str, Any]]:
        """A table's records (JSON Lines, or an old case's CSV or JSON), up to MAX_ROWS_PER_TABLE."""
        rows = []
        for _, record in read_records(path):
            if len(rows) >= MAX_ROWS_PER_TABLE:
                self.logger.warning(f"{path}: indexed the first {MAX_ROWS_PER_TABLE} records only")
                break
            rows.append(record)
        return rows

    def index_table(self, path: str, host: str, artefact: str) -> int:
        """Index one of Elrond's tables, one document per record: its own fields as text, with the
        host, artefact, row and time as metadata (so an answer can name where it came from)."""
        try:
            documents = []
            for ref, record in read_records(path):
                if len(documents) >= MAX_ROWS_PER_TABLE:
                    self.logger.warning(f"{path}: indexed the first {MAX_ROWS_PER_TABLE} records only")
                    break
                fields = []
                for key, value in record.items():
                    if key in ENVELOPE or value in (None, "", [], {}):
                        continue
                    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
                    fields.append(f"{key}: {text[:MAX_FIELD]}")
                if not fields:
                    continue
                metadata = {
                    "type": artefact,
                    "host": host,
                    "file": path,
                    "row_ref": ref,
                    "timestamp": str(record.get("timestamp") or "N/A"),
                    "techniques": ", ".join(record.get("techniques") or []),
                    "case_id": self.case_id,
                }
                documents.append(Document(page_content=f"{artefact} on {host}\n" + "\n".join(fields), metadata=metadata))
            if documents:
                self.vectorstore.add_documents(documents)
                self.vectorstore.persist()
            return len(documents)
        except Exception as e:
            self.logger.error(f"Error indexing {path}: {e}")
            return 0

    def index_all(self, case_dir: str) -> Dict[str, int]:
        """
        Index an Elrond case: every host's analysis tables (IOCs as IOCs), its cooked artefacts and its
        Plaso timeline, and the case's own tables (stacking, threat groups).

        Args:
            case_dir: The case's output directory (holding a folder per host), or one host's folder

        Returns:
            Dictionary with counts of indexed documents by artefact
        """
        self.logger.info(f"Indexing all artifacts from {case_dir}...")
        root = Path(case_dir)
        hosts = [root] if (root / "artefacts").is_dir() else sorted(
            d for d in root.iterdir() if d.is_dir() and (d / "artefacts").is_dir())
        counts: Dict[str, int] = {}

        def add(name: str, count: int) -> None:
            if count:
                counts[name] = counts.get(name, 0) + count

        for host in hosts:
            iocs = table_path(host / "analysis", "iocs")
            if iocs.is_file():
                add("iocs", self.index_iocs(str(iocs)))
            for folder, prefix in ((host / "analysis", "analysis/"), (host / "artefacts" / "cooked", "")):
                for path in sorted(folder.rglob("*")) if folder.is_dir() else []:
                    if path.suffix.lower() not in TABLE_SUFFIXES or path.stem == "iocs" or not path.is_file():
                        continue
                    artefact = prefix + str(path.relative_to(folder).with_suffix(""))
                    add(artefact, self.index_table(str(path), host.name, artefact))
            timeline = table_path(host / "artefacts", "plaso_timeline")
            if timeline.is_file():
                add("plaso_timeline", self.index_table(str(timeline), host.name, "plaso_timeline"))
        if root not in hosts:
            for name in ("stacking", "threat_groups"):
                table = table_path(root, name)
                if table.is_file():
                    add(name, self.index_table(str(table), "(case)", name))

        self.logger.info(f"Indexing complete. Total counts: {counts}")
        return counts

    def get_collection_info(self) -> Dict[str, Any]:
        """
        Get information about the indexed collection.

        Returns:
            Dictionary with collection statistics
        """
        try:
            collection = self.vectorstore._collection
            count = collection.count()

            return {
                "case_id": self.case_id,
                "collection_name": f"case_{self.case_id}",
                "document_count": count,
                "vector_db_dir": self.vector_db_dir,
                "embedding_model": self.config.get(
                    "embedding_model", "sentence-transformers/all-MiniLM-L6-v2"
                ),
            }
        except Exception as e:
            self.logger.error(f"Error getting collection info: {e}")
            return {}
