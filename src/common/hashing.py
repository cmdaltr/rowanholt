"""
Unified hashing utilities for Rowanholt DF Acceleration Suite

Provides consistent file hashing across acquisition and analysis modules.
Eliminates duplicate SHA256 code found in 10+ files.
"""

import hashlib
from pathlib import Path
from typing import Optional, Dict, BinaryIO


# Standard chunk size used across the codebase (256KB)
DEFAULT_CHUNK_SIZE = 262144


def calculate_sha256(filepath: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """
    Calculate SHA256 hash of a file.

    Unified implementation replacing duplicate code in:
    - acquisition/python/collect_artefacts-py
    - analysis/rowanholt/meta.py
    - acquisition/bash/gandalf.sh (via sha256sum)

    Args:
        filepath: Path to file to hash
        chunk_size: Size of chunks to read (default 262144 bytes = 256KB)

    Returns:
        Hexadecimal SHA256 hash string

    Raises:
        FileNotFoundError: If file doesn't exist
        IOError: If file cannot be read

    Example:
        >>> hash_value = calculate_sha256("/path/to/file.txt")
        >>> len(hash_value)
        64
    """
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        while True:
            buffer = f.read(chunk_size)
            if not buffer:
                break
            sha256.update(buffer)

    return sha256.hexdigest()


def calculate_md5(filepath: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """
    Calculate MD5 hash of a file.

    Args:
        filepath: Path to file to hash
        chunk_size: Size of chunks to read

    Returns:
        Hexadecimal MD5 hash string

    Example:
        >>> hash_value = calculate_md5("/path/to/file.txt")
        >>> len(hash_value)
        32
    """
    md5 = hashlib.md5()

    with open(filepath, "rb") as f:
        while True:
            buffer = f.read(chunk_size)
            if not buffer:
                break
            md5.update(buffer)

    return md5.hexdigest()


def calculate_hash(
    filepath: str, algorithm: str = "sha256", chunk_size: int = DEFAULT_CHUNK_SIZE
) -> str:
    """
    Calculate hash of a file using specified algorithm.

    Args:
        filepath: Path to file to hash
        algorithm: Hash algorithm (sha256, md5, sha1, sha512, etc.)
        chunk_size: Size of chunks to read

    Returns:
        Hexadecimal hash string

    Raises:
        ValueError: If algorithm is not supported

    Example:
        >>> calculate_hash("/path/to/file.txt", "sha256")
        'abc123...'
        >>> calculate_hash("/path/to/file.txt", "md5")
        'def456...'
    """
    try:
        hasher = hashlib.new(algorithm)
    except ValueError:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    with open(filepath, "rb") as f:
        while True:
            buffer = f.read(chunk_size)
            if not buffer:
                break
            hasher.update(buffer)

    return hasher.hexdigest()


def calculate_multiple_hashes(
    filepath: str, algorithms: list = None, chunk_size: int = DEFAULT_CHUNK_SIZE
) -> Dict[str, str]:
    """
    Calculate multiple hashes of a file in a single pass.

    More efficient than calling calculate_hash multiple times.

    Args:
        filepath: Path to file to hash
        algorithms: List of algorithms (default: ['sha256', 'md5'])
        chunk_size: Size of chunks to read

    Returns:
        Dictionary mapping algorithm names to hash values

    Example:
        >>> hashes = calculate_multiple_hashes("/path/to/file.txt")
        >>> hashes
        {'sha256': 'abc123...', 'md5': 'def456...'}
    """
    if algorithms is None:
        algorithms = ["sha256", "md5"]

    # Initialize all hashers
    hashers = {}
    for algo in algorithms:
        try:
            hashers[algo] = hashlib.new(algo)
        except ValueError:
            raise ValueError(f"Unsupported hash algorithm: {algo}")

    # Read file once and update all hashers
    with open(filepath, "rb") as f:
        while True:
            buffer = f.read(chunk_size)
            if not buffer:
                break
            for hasher in hashers.values():
                hasher.update(buffer)

    # Return all hash values
    return {algo: hasher.hexdigest() for algo, hasher in hashers.items()}


def verify_hash(filepath: str, expected_hash: str, algorithm: str = "sha256") -> bool:
    """
    Verify a file's hash matches expected value.

    Args:
        filepath: Path to file to verify
        expected_hash: Expected hash value (case-insensitive)
        algorithm: Hash algorithm used

    Returns:
        True if hashes match, False otherwise

    Example:
        >>> verify_hash("/path/to/file.txt", "abc123...", "sha256")
        True
    """
    actual_hash = calculate_hash(filepath, algorithm)
    return actual_hash.lower() == expected_hash.lower()


def hash_string(data: str, algorithm: str = "sha256") -> str:
    """
    Calculate hash of a string.

    Args:
        data: String to hash
        algorithm: Hash algorithm to use

    Returns:
        Hexadecimal hash string

    Example:
        >>> hash_string("password123")
        'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f'
    """
    hasher = hashlib.new(algorithm)
    hasher.update(data.encode("utf-8"))
    return hasher.hexdigest()


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """
    Calculate hash of bytes.

    Args:
        data: Bytes to hash
        algorithm: Hash algorithm to use

    Returns:
        Hexadecimal hash string

    Example:
        >>> hash_bytes(b"data")
        '3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7'
    """
    hasher = hashlib.new(algorithm)
    hasher.update(data)
    return hasher.hexdigest()


def hash_stream(
    stream: BinaryIO, algorithm: str = "sha256", chunk_size: int = DEFAULT_CHUNK_SIZE
) -> str:
    """
    Calculate hash of a binary stream.

    Useful for hashing data without writing to disk first.

    Args:
        stream: Binary stream to hash
        algorithm: Hash algorithm to use
        chunk_size: Size of chunks to read

    Returns:
        Hexadecimal hash string

    Example:
        >>> import io
        >>> stream = io.BytesIO(b"test data")
        >>> hash_stream(stream)
        '916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9'
    """
    hasher = hashlib.new(algorithm)

    while True:
        buffer = stream.read(chunk_size)
        if not buffer:
            break
        hasher.update(buffer)

    return hasher.hexdigest()


class HashRegistry:
    """
    Registry for tracking hashes of multiple files.

    Useful for creating metadata logs during acquisition.
    """

    def __init__(self):
        self.hashes: Dict[str, Dict[str, str]] = {}

    def add_file(self, filepath: str, algorithms: list = None) -> Dict[str, str]:
        """
        Add a file to the registry and calculate its hashes.

        Args:
            filepath: Path to file
            algorithms: List of algorithms to use

        Returns:
            Dictionary of calculated hashes
        """
        hashes = calculate_multiple_hashes(filepath, algorithms)
        self.hashes[filepath] = hashes
        return hashes

    def get_hash(self, filepath: str, algorithm: str = "sha256") -> Optional[str]:
        """
        Get stored hash for a file.

        Args:
            filepath: Path to file
            algorithm: Hash algorithm

        Returns:
            Hash value or None if not found
        """
        if filepath in self.hashes:
            return self.hashes[filepath].get(algorithm)
        return None

    def verify_file(self, filepath: str, algorithm: str = "sha256") -> bool:
        """
        Verify a file's current hash matches stored hash.

        Args:
            filepath: Path to file
            algorithm: Hash algorithm

        Returns:
            True if hashes match, False otherwise
        """
        stored_hash = self.get_hash(filepath, algorithm)
        if stored_hash is None:
            return False

        current_hash = calculate_hash(filepath, algorithm)
        return current_hash == stored_hash

    def export_csv(self) -> str:
        """
        Export registry as CSV format.

        Returns:
            CSV string with format: filepath,algorithm,hash

        Example:
            >>> registry = HashRegistry()
            >>> registry.add_file("/path/to/file.txt")
            >>> csv = registry.export_csv()
            >>> print(csv)
            filepath,algorithm,hash
            /path/to/file.txt,sha256,abc123...
        """
        lines = ["filepath,algorithm,hash"]
        for filepath, hashes in self.hashes.items():
            for algo, hash_value in hashes.items():
                lines.append(f"{filepath},{algo},{hash_value}")
        return "\n".join(lines)
