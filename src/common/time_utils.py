"""
Unified timestamp utilities for Dernvale DF Acceleration Suite

Provides consistent timestamp formatting across acquisition and analysis modules.
Eliminates duplicate timestamp code found in 57+ files.
"""

from datetime import datetime, timezone
from typing import Optional


def get_iso_timestamp(dt: Optional[datetime] = None, use_utc: bool = True) -> str:
    """
    Get ISO 8601 formatted timestamp.

    Args:
        dt: Datetime object to format, defaults to current time
        use_utc: Use UTC timezone (default True)

    Returns:
        ISO 8601 formatted string (e.g., "2025-11-12T14:30:45.123456Z")

    Example:
        >>> get_iso_timestamp()
        '2025-11-12T14:30:45.123456Z'
    """
    if dt is None:
        dt = datetime.now(timezone.utc) if use_utc else datetime.now()

    timestamp = dt.isoformat()

    # Ensure UTC indicator for UTC times
    if use_utc and not timestamp.endswith("Z"):
        if "+" in timestamp or timestamp.endswith("+00:00"):
            timestamp = timestamp.split("+")[0] + "Z"
        else:
            timestamp += "Z"

    return timestamp


def get_audit_timestamp(dt: Optional[datetime] = None) -> str:
    """
    Get timestamp formatted for audit logs.

    Standardizes the format used in acquisition and analysis audit trails.
    Format: "2025-11-12T14:30:45.123456Z"

    Args:
        dt: Datetime object to format, defaults to current UTC time

    Returns:
        Audit-formatted timestamp string

    Example:
        >>> get_audit_timestamp()
        '2025-11-12T14:30:45.123456Z'
    """
    return get_iso_timestamp(dt, use_utc=True)


def get_splunk_timestamp(dt: Optional[datetime] = None) -> str:
    """
    Get timestamp formatted for Splunk ingestion.

    Format: "2025-11-12 14:30:45.123456"

    Args:
        dt: Datetime object to format, defaults to current time

    Returns:
        Splunk-formatted timestamp string
    """
    if dt is None:
        dt = datetime.now(timezone.utc)

    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")


def get_elastic_timestamp(dt: Optional[datetime] = None) -> str:
    """
    Get timestamp formatted for Elasticsearch ingestion.

    Format: ISO 8601 with timezone (e.g., "2025-11-12T14:30:45.123Z")

    Args:
        dt: Datetime object to format, defaults to current UTC time

    Returns:
        Elasticsearch-compatible timestamp
    """
    if dt is None:
        dt = datetime.now(timezone.utc)

    # Elasticsearch prefers milliseconds, not microseconds
    timestamp = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

    return timestamp + "Z"


def get_filename_timestamp(dt: Optional[datetime] = None) -> str:
    """
    Get timestamp safe for use in filenames.

    Format: "20251112_143045"

    Args:
        dt: Datetime object to format, defaults to current time

    Returns:
        Filename-safe timestamp string

    Example:
        >>> get_filename_timestamp()
        '20251112_143045'
    """
    if dt is None:
        dt = datetime.now()

    return dt.strftime("%Y%m%d_%H%M%S")


def parse_iso_timestamp(timestamp_str: str) -> datetime:
    """
    Parse ISO 8601 timestamp string to datetime object.

    Handles various ISO formats including those with/without timezone.

    Args:
        timestamp_str: ISO 8601 formatted timestamp

    Returns:
        Datetime object

    Example:
        >>> dt = parse_iso_timestamp("2025-11-12T14:30:45.123456Z")
        >>> isinstance(dt, datetime)
        True
    """
    # Remove Z suffix and handle as UTC
    if timestamp_str.endswith("Z"):
        timestamp_str = timestamp_str[:-1] + "+00:00"

    # Try multiple formats
    formats = [
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(timestamp_str, fmt)
        except ValueError:
            continue

    raise ValueError(f"Unable to parse timestamp: {timestamp_str}")


def get_epoch_timestamp(dt: Optional[datetime] = None) -> int:
    """
    Get Unix epoch timestamp (seconds since 1970-01-01).

    Args:
        dt: Datetime object to convert, defaults to current time

    Returns:
        Unix epoch timestamp as integer

    Example:
        >>> epoch = get_epoch_timestamp()
        >>> epoch > 1700000000
        True
    """
    if dt is None:
        dt = datetime.now(timezone.utc)

    return int(dt.timestamp())


def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to human-readable string.

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted duration string

    Example:
        >>> format_duration(3665)
        '1h 1m 5s'
        >>> format_duration(45)
        '45s'
    """
    if seconds < 60:
        return f"{seconds:.1f}s"

    minutes = int(seconds // 60)
    seconds = int(seconds % 60)

    if minutes < 60:
        return f"{minutes}m {seconds}s"

    hours = int(minutes // 60)
    minutes = int(minutes % 60)

    return f"{hours}h {minutes}m {seconds}s"
