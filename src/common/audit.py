"""
Unified audit logging for Dernvale DF Acceleration Suite

Provides consistent audit trail logging across acquisition and analysis modules.
Eliminates duplicate audit logging code found in 7+ files.

Replaces:
- acquisition/python/collect_artefacts-py: audit_log()
- analysis/dernvale/audit.py: write_audit_log_entry()
- acquisition/bash/gandalf.sh: log_audit()
"""

import csv
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime

from .time_utils import get_audit_timestamp
from .hashing import calculate_sha256


class AuditLogger:
    """
    Unified audit logger for forensic operations.

    Maintains CSV-formatted audit logs with consistent schema across
    acquisition and analysis phases.
    """

    # Standard audit log schema
    AUDIT_HEADERS = ["datetime", "hostname", "artefact", "status"]
    META_HEADERS = ["hostname", "file_path", "sha256_hash"]

    def __init__(
        self,
        audit_log_path: str,
        meta_log_path: Optional[str] = None,
        hostname: Optional[str] = None,
    ):
        """
        Initialize audit logger.

        Args:
            audit_log_path: Path to audit log CSV file
            meta_log_path: Path to metadata log CSV file (optional)
            hostname: Hostname for audit entries
        """
        self.audit_log_path = Path(audit_log_path)
        self.meta_log_path = Path(meta_log_path) if meta_log_path else None
        self.hostname = hostname

        # Initialize audit log
        self._init_audit_log()

        # Initialize metadata log if provided
        if self.meta_log_path:
            self._init_meta_log()

    def _init_audit_log(self):
        """Initialize audit log file with headers."""
        if not self.audit_log_path.exists():
            self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.audit_log_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(self.AUDIT_HEADERS)

    def _init_meta_log(self):
        """Initialize metadata log file with headers."""
        if not self.meta_log_path.exists():
            self.meta_log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.meta_log_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(self.META_HEADERS)

    def log_event(
        self,
        artefact: str,
        status: str = "collected",
        hostname: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ):
        """
        Log an audit event.

        Args:
            artefact: Artifact name or path being processed
            status: Status of operation (default: "collected")
            hostname: Override hostname (uses instance hostname if not provided)
            timestamp: Override timestamp (uses current time if not provided)

        Example:
            >>> logger = AuditLogger("/tmp/audit.log", hostname="HOST01")
            >>> logger.log_event("/etc/passwd", "collected")
        """
        hostname = hostname or self.hostname or "unknown"
        timestamp_str = get_audit_timestamp(timestamp)

        with open(self.audit_log_path, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([timestamp_str, hostname, artefact, status])

    def log_collection(self, artefact: str, hostname: Optional[str] = None):
        """
        Log artifact collection event.

        Convenience method for logging collected artifacts.

        Args:
            artefact: Artifact name or path being collected
            hostname: Override hostname
        """
        self.log_event(artefact, status="collected", hostname=hostname)

    def log_error(self, artefact: str, error_msg: str, hostname: Optional[str] = None):
        """
        Log error event.

        Args:
            artefact: Artifact that caused error
            error_msg: Error message
            hostname: Override hostname
        """
        status = f"error: {error_msg}"
        self.log_event(artefact, status=status, hostname=hostname)

    def log_file_with_hash(
        self, filepath: str, hostname: Optional[str] = None, calculate_hash: bool = True
    ):
        """
        Log file collection with SHA256 hash to both audit and metadata logs.

        Args:
            filepath: Path to file being collected
            hostname: Override hostname
            calculate_hash: Whether to calculate and log hash (default True)

        Example:
            >>> logger = AuditLogger("/tmp/audit.log", "/tmp/meta.log", "HOST01")
            >>> logger.log_file_with_hash("/etc/passwd")
        """
        hostname = hostname or self.hostname or "unknown"

        # Log to audit log
        self.log_collection(filepath, hostname)

        # Log to metadata log with hash
        if self.meta_log_path and calculate_hash:
            try:
                hash_value = calculate_sha256(filepath)
                self.log_metadata(filepath, hash_value, hostname)
            except Exception as e:
                # If hashing fails, log to audit but skip metadata
                self.log_error(filepath, f"hash_failed: {str(e)}", hostname)

    def log_metadata(self, filepath: str, sha256_hash: str, hostname: Optional[str] = None):
        """
        Log file metadata (hash) to metadata log.

        Args:
            filepath: Path to file
            sha256_hash: SHA256 hash of file
            hostname: Override hostname
        """
        if not self.meta_log_path:
            return

        hostname = hostname or self.hostname or "unknown"

        with open(self.meta_log_path, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([hostname, filepath, sha256_hash])

    def log_batch(self, artifacts: list, status: str = "collected", hostname: Optional[str] = None):
        """
        Log multiple artifacts efficiently.

        Args:
            artifacts: List of artifact paths/names
            status: Status for all artifacts
            hostname: Override hostname

        Example:
            >>> logger = AuditLogger("/tmp/audit.log", hostname="HOST01")
            >>> logger.log_batch(["/etc/passwd", "/etc/shadow", "/etc/group"])
        """
        hostname = hostname or self.hostname or "unknown"
        timestamp_str = get_audit_timestamp()

        with open(self.audit_log_path, "a", newline="") as f:
            writer = csv.writer(f)
            for artifact in artifacts:
                writer.writerow([timestamp_str, hostname, artifact, status])

    def read_audit_log(self) -> list:
        """
        Read all audit log entries.

        Returns:
            List of dictionaries with audit entries

        Example:
            >>> logger = AuditLogger("/tmp/audit.log")
            >>> entries = logger.read_audit_log()
            >>> entries[0]
            {'datetime': '2025-11-12T...', 'hostname': 'HOST01', ...}
        """
        entries = []
        with open(self.audit_log_path, "r", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                entries.append(row)
        return entries

    def read_meta_log(self) -> list:
        """
        Read all metadata log entries.

        Returns:
            List of dictionaries with metadata entries
        """
        if not self.meta_log_path or not self.meta_log_path.exists():
            return []

        entries = []
        with open(self.meta_log_path, "r", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                entries.append(row)
        return entries

    def get_artifact_hash(self, filepath: str) -> Optional[str]:
        """
        Retrieve stored hash for an artifact.

        Args:
            filepath: Path to artifact

        Returns:
            SHA256 hash or None if not found
        """
        entries = self.read_meta_log()
        for entry in entries:
            if entry.get("file_path") == filepath:
                return entry.get("sha256_hash")
        return None

    def verify_integrity(self, filepath: str) -> bool:
        """
        Verify file integrity against stored hash.

        Args:
            filepath: Path to file to verify

        Returns:
            True if hash matches, False otherwise
        """
        stored_hash = self.get_artifact_hash(filepath)
        if not stored_hash:
            return False

        try:
            current_hash = calculate_sha256(filepath)
            return current_hash == stored_hash
        except Exception:
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about audit log.

        Returns:
            Dictionary with statistics

        Example:
            >>> logger = AuditLogger("/tmp/audit.log")
            >>> stats = logger.get_statistics()
            >>> stats
            {'total_entries': 42, 'collected': 40, 'error': 2, ...}
        """
        entries = self.read_audit_log()
        stats = {
            "total_entries": len(entries),
            "unique_artifacts": len(set(e["artefact"] for e in entries)),
            "unique_hosts": len(set(e["hostname"] for e in entries)),
        }

        # Count by status
        status_counts = {}
        for entry in entries:
            status = entry.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

        stats.update(status_counts)
        return stats


# Convenience functions for quick usage


def create_audit_logger(output_dir: str, hostname: str, with_metadata: bool = True) -> AuditLogger:
    """
    Create audit logger with standard paths.

    Args:
        output_dir: Output directory for logs
        hostname: Hostname for audit entries
        with_metadata: Create metadata log (default True)

    Returns:
        Configured AuditLogger instance

    Example:
        >>> logger = create_audit_logger("/tmp/evidence", "HOST01")
        >>> logger.log_collection("/etc/passwd")
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    audit_path = output_path / "log.audit"
    meta_path = output_path / "log.meta" if with_metadata else None

    return AuditLogger(str(audit_path), str(meta_path), hostname)


def log_quick_event(audit_log_path: str, artifact: str, hostname: str, status: str = "collected"):
    """
    Quick function to log a single event without creating logger instance.

    Args:
        audit_log_path: Path to audit log
        artifact: Artifact name/path
        hostname: Hostname
        status: Status

    Example:
        >>> log_quick_event("/tmp/audit.log", "/etc/passwd", "HOST01")
    """
    logger = AuditLogger(audit_log_path, hostname=hostname)
    logger.log_event(artifact, status, hostname)
