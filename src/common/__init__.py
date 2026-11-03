"""
Common utilities for Dernvale DF Acceleration Suite

Provides unified implementations of frequently-used operations across
acquisition and analysis modules.

Usage:
    from common import audit, hashing, crypto
    from common.audit import AuditLogger
    from common.time_utils import get_iso_timestamp
"""

# Expose main classes and functions for easy import
from .audit import AuditLogger, create_audit_logger, log_quick_event
from .hashing import (
    calculate_sha256,
    calculate_md5,
    calculate_hash,
    calculate_multiple_hashes,
    verify_hash,
    HashRegistry,
)
from .time_utils import (
    get_iso_timestamp,
    get_audit_timestamp,
    get_splunk_timestamp,
    get_elastic_timestamp,
    get_filename_timestamp,
    parse_iso_timestamp,
    format_duration,
)
from .crypto import (
    CryptoManager,
    encrypt_archive_with_key,
    encrypt_archive_with_password,
    decrypt_archive_with_key,
    decrypt_archive_with_password,
    generate_key_file,
)
from .file_ops import (
    ensure_directory,
    safe_copy_file,
    safe_copy_tree,
    collect_with_hash,
    make_artifact_structure,
    safe_remove,
    get_file_info,
    sanitize_filename,
    find_files_by_pattern,
    calculate_directory_size,
    format_size,
)
from .archiving import (
    create_archive,
    create_evidence_archive,
    extract_archive,
    validate_archive,
    list_archive_contents,
)

__all__ = [
    # Audit
    "AuditLogger",
    "create_audit_logger",
    "log_quick_event",
    # Hashing
    "calculate_sha256",
    "calculate_md5",
    "calculate_hash",
    "calculate_multiple_hashes",
    "verify_hash",
    "HashRegistry",
    # Time utilities
    "get_iso_timestamp",
    "get_audit_timestamp",
    "get_splunk_timestamp",
    "get_elastic_timestamp",
    "get_filename_timestamp",
    "parse_iso_timestamp",
    "format_duration",
    # Cryptography
    "CryptoManager",
    "encrypt_archive_with_key",
    "encrypt_archive_with_password",
    "decrypt_archive_with_key",
    "decrypt_archive_with_password",
    "generate_key_file",
    # File operations
    "ensure_directory",
    "safe_copy_file",
    "safe_copy_tree",
    "collect_with_hash",
    "make_artifact_structure",
    "safe_remove",
    "get_file_info",
    "sanitize_filename",
    "find_files_by_pattern",
    "calculate_directory_size",
    "format_size",
    # Archiving
    "create_archive",
    "create_evidence_archive",
    "extract_archive",
    "validate_archive",
    "list_archive_contents",
]

__version__ = "2.0.0"
