"""
Unified archiving utilities for Rowanholt DF Acceleration Suite

Provides consistent archive creation with encryption support.
Eliminates duplicate archiving code found in acquisition modules.

Replaces:
- acquisition/python/collect_artefacts-py: create_zip()
- acquisition/bash/gandalf.sh: create_archive()
"""

import os
import tarfile
import zipfile
from pathlib import Path
from typing import Optional, Literal
from datetime import datetime

from .crypto import encrypt_archive_with_key, encrypt_archive_with_password
from .file_ops import calculate_directory_size, format_size


ArchiveFormat = Literal["zip", "tar", "tar.gz", "tar.bz2", "tar.xz"]
EncryptionMethod = Literal["key", "password", "none"]


def create_archive(
    source_dir: str,
    output_path: Optional[str] = None,
    format: ArchiveFormat = "tar.gz",
    compression_level: int = 6,
    handle_old_timestamps: bool = True,
) -> str:
    """
    Create archive from directory.

    Args:
        source_dir: Directory to archive
        output_path: Output archive path (auto-generated if None)
        format: Archive format (zip, tar, tar.gz, tar.bz2, tar.xz)
        compression_level: Compression level (0-9)
        handle_old_timestamps: Handle pre-1980 timestamps (for zip)

    Returns:
        Path to created archive

    Raises:
        FileNotFoundError: If source directory doesn't exist
        ValueError: If format is unsupported

    Example:
        >>> archive = create_archive("/tmp/evidence", format='tar.gz')
        >>> archive
        '/tmp/evidence.tar.gz'
    """
    source_path = Path(source_dir)

    if not source_path.exists():
        raise FileNotFoundError(f"Source directory not found: {source_dir}")

    # Auto-generate output path if not provided
    if output_path is None:
        output_path = f"{source_dir}.{format}"

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Create archive based on format
    if format == "zip":
        _create_zip(source_path, output_file, compression_level, handle_old_timestamps)
    elif format.startswith("tar"):
        _create_tar(source_path, output_file, format, compression_level)
    else:
        raise ValueError(f"Unsupported archive format: {format}")

    return str(output_file)


def _create_zip(
    source_path: Path, output_file: Path, compression_level: int, handle_old_timestamps: bool
):
    """Create ZIP archive."""
    compression = zipfile.ZIP_DEFLATED

    with zipfile.ZipFile(
        output_file, "w", compression=compression, compresslevel=compression_level
    ) as zipf:
        for root, dirs, files in os.walk(source_path):
            for file in files:
                file_path = Path(root) / file
                arc_name = file_path.relative_to(source_path.parent)

                try:
                    zipf.write(file_path, arc_name)
                except ValueError as e:
                    # Handle pre-1980 timestamp error
                    if (
                        handle_old_timestamps
                        and "ZIP does not support timestamps before 1980" in str(e)
                    ):
                        # Read file and write with current timestamp
                        with open(file_path, "rb") as f:
                            data = f.read()
                        zipf.writestr(str(arc_name), data)
                    else:
                        raise


def _create_tar(source_path: Path, output_file: Path, format: str, compression_level: int):
    """Create TAR archive."""
    # Determine compression mode
    if format == "tar":
        mode = "w"
    elif format == "tar.gz":
        mode = "w:gz"
    elif format == "tar.bz2":
        mode = "w:bz2"
    elif format == "tar.xz":
        mode = "w:xz"
    else:
        raise ValueError(f"Unsupported tar format: {format}")

    with tarfile.open(output_file, mode) as tar:
        tar.add(source_path, arcname=source_path.name)


def create_evidence_archive(
    source_dir: str,
    hostname: str,
    output_dir: Optional[str] = None,
    format: ArchiveFormat = "tar.gz",
    encryption: EncryptionMethod = "none",
    password: Optional[str] = None,
    key_path: Optional[str] = None,
) -> dict:
    """
    Create forensic evidence archive with optional encryption.

    High-level function that combines archiving and encryption.

    Args:
        source_dir: Directory containing evidence
        hostname: Hostname for archive naming
        output_dir: Output directory (uses source parent if None)
        format: Archive format
        encryption: Encryption method (key, password, none)
        password: Password for encryption (if encryption='password')
        key_path: Path to save/load key (if encryption='key')

    Returns:
        Dictionary with archive info:
        {
            'archive_path': '/path/to/archive.tar.gz',
            'encrypted': True/False,
            'key_path': '/path/to/key' (if applicable),
            'size': 1048576,
            'size_formatted': '1.00 MB'
        }

    Example:
        >>> result = create_evidence_archive(
        ...     "/tmp/acquisitions/HOST01",
        ...     "HOST01",
        ...     encryption='password',
        ...     password='SecurePass123'
        ... )
        >>> result['archive_path']
        '/tmp/HOST01.tar.gz.enc'
    """
    source_path = Path(source_dir)

    # Determine output directory
    if output_dir is None:
        output_dir = str(source_path.parent)

    # Create base archive name
    archive_name = f"{hostname}.{format}"
    archive_path = str(Path(output_dir) / archive_name)

    # Create archive
    archive_path = create_archive(source_dir, archive_path, format)

    result = {
        "archive_path": archive_path,
        "encrypted": False,
        "size": Path(archive_path).stat().st_size,
    }

    # Apply encryption if requested
    if encryption == "key":
        if key_path is None:
            key_path = str(Path(output_dir) / "shadowfax.key")

        encrypted_path, key_file = encrypt_archive_with_key(archive_path, key_path)

        # Remove unencrypted archive
        Path(archive_path).unlink()

        result["archive_path"] = encrypted_path
        result["encrypted"] = True
        result["encryption_method"] = "key"
        result["key_path"] = key_file

    elif encryption == "password":
        if password is None:
            raise ValueError("Password required for password encryption")

        encrypted_path = encrypt_archive_with_password(archive_path, password)

        # Remove unencrypted archive
        Path(archive_path).unlink()

        result["archive_path"] = encrypted_path
        result["encrypted"] = True
        result["encryption_method"] = "password"

    # Add formatted size
    result["size"] = Path(result["archive_path"]).stat().st_size
    result["size_formatted"] = format_size(result["size"])

    return result


def extract_archive(
    archive_path: str, output_dir: Optional[str] = None, format: Optional[ArchiveFormat] = None
) -> str:
    """
    Extract archive to directory.

    Args:
        archive_path: Path to archive file
        output_dir: Output directory (auto-generated if None)
        format: Archive format (auto-detected if None)

    Returns:
        Path to extraction directory

    Example:
        >>> extract_dir = extract_archive("/tmp/evidence.tar.gz")
        >>> extract_dir
        '/tmp/evidence'
    """
    archive_file = Path(archive_path)

    if not archive_file.exists():
        raise FileNotFoundError(f"Archive not found: {archive_path}")

    # Auto-detect format if not specified
    if format is None:
        if archive_path.endswith(".tar.gz") or archive_path.endswith(".tgz"):
            format = "tar.gz"
        elif archive_path.endswith(".tar.bz2"):
            format = "tar.bz2"
        elif archive_path.endswith(".tar.xz"):
            format = "tar.xz"
        elif archive_path.endswith(".tar"):
            format = "tar"
        elif archive_path.endswith(".zip"):
            format = "zip"
        else:
            raise ValueError(f"Cannot detect archive format: {archive_path}")

    # Auto-generate output directory
    if output_dir is None:
        # Remove all archive extensions
        output_dir = str(archive_file)
        for ext in [".tar.gz", ".tar.bz2", ".tar.xz", ".tar", ".zip", ".tgz"]:
            if output_dir.endswith(ext):
                output_dir = output_dir[: -len(ext)]
                break

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Extract based on format
    if format == "zip":
        with zipfile.ZipFile(archive_file, "r") as zipf:
            zipf.extractall(output_path)
    elif format.startswith("tar"):
        mode = "r" if format == "tar" else f'r:{format.split(".")[-1]}'
        with tarfile.open(archive_file, mode) as tar:
            tar.extractall(output_path)
    else:
        raise ValueError(f"Unsupported archive format: {format}")

    return str(output_path)


def validate_archive(archive_path: str) -> bool:
    """
    Validate archive integrity.

    Args:
        archive_path: Path to archive file

    Returns:
        True if archive is valid, False otherwise

    Example:
        >>> validate_archive("/tmp/evidence.tar.gz")
        True
    """
    archive_file = Path(archive_path)

    if not archive_file.exists():
        return False

    try:
        if archive_path.endswith(".zip"):
            with zipfile.ZipFile(archive_file, "r") as zipf:
                return zipf.testzip() is None
        elif ".tar" in archive_path:
            with tarfile.open(archive_file, "r") as tar:
                # Try to read all members
                for member in tar.getmembers():
                    pass
                return True
        else:
            return False
    except Exception:
        return False


def list_archive_contents(archive_path: str, detailed: bool = False) -> list:
    """
    List contents of archive.

    Args:
        archive_path: Path to archive file
        detailed: Return detailed info (size, date, etc.)

    Returns:
        List of file paths (or dicts if detailed=True)

    Example:
        >>> contents = list_archive_contents("/tmp/evidence.tar.gz")
        >>> contents[0]
        'evidence/host.info'
    """
    archive_file = Path(archive_path)

    if not archive_file.exists():
        raise FileNotFoundError(f"Archive not found: {archive_path}")

    contents = []

    try:
        if archive_path.endswith(".zip"):
            with zipfile.ZipFile(archive_file, "r") as zipf:
                for info in zipf.infolist():
                    if detailed:
                        contents.append(
                            {
                                "path": info.filename,
                                "size": info.file_size,
                                "compressed_size": info.compress_size,
                                "date_time": datetime(*info.date_time),
                            }
                        )
                    else:
                        contents.append(info.filename)

        elif ".tar" in archive_path:
            with tarfile.open(archive_file, "r") as tar:
                for member in tar.getmembers():
                    if detailed:
                        contents.append(
                            {
                                "path": member.name,
                                "size": member.size,
                                "mode": member.mode,
                                "mtime": datetime.fromtimestamp(member.mtime),
                            }
                        )
                    else:
                        contents.append(member.name)

    except Exception:
        pass

    return contents
