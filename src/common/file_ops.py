"""
Unified file operations for Rowanholt DF Acceleration Suite

Provides safe file handling with consistent error handling and permissions.
Eliminates duplicate file operation code found across acquisition modules.

Replaces:
- acquisition/python/collect_artefacts-py: copy_file(), copy_dir(), make_artefact_dir()
- acquisition/bash/gandalf.sh: collect_file(), collect_directory()
"""

import os
import shutil
import stat
from pathlib import Path
from typing import Optional, List, Callable

from .hashing import calculate_sha256


def ensure_directory(path: str, mode: int = 0o755) -> Path:
    """
    Ensure directory exists, create if it doesn't.

    Args:
        path: Directory path
        mode: Directory permissions (default: 0o755)

    Returns:
        Path object

    Example:
        >>> ensure_directory("/tmp/evidence/logs")
        PosixPath('/tmp/evidence/logs')
    """
    dir_path = Path(path)
    dir_path.mkdir(parents=True, exist_ok=True, mode=mode)
    return dir_path


def safe_copy_file(
    src: str,
    dst: str,
    preserve_metadata: bool = True,
    follow_symlinks: bool = False,
    handle_permissions: bool = True,
) -> bool:
    """
    Safely copy a file with error handling.

    Handles permission errors gracefully, making it suitable for forensic
    artifact collection where some files may not be readable.

    Args:
        src: Source file path
        dst: Destination file path
        preserve_metadata: Preserve timestamps and permissions
        follow_symlinks: Follow symbolic links
        handle_permissions: Handle permission errors gracefully

    Returns:
        True if successful, False otherwise

    Example:
        >>> safe_copy_file("/etc/passwd", "/tmp/evidence/passwd")
        True
    """
    try:
        # Ensure destination directory exists
        ensure_directory(str(Path(dst).parent))

        # Copy file
        if preserve_metadata:
            shutil.copy2(src, dst, follow_symlinks=follow_symlinks)
        else:
            shutil.copy(src, dst, follow_symlinks=follow_symlinks)

        return True

    except PermissionError:
        if handle_permissions:
            try:
                # Try to copy without preserving metadata
                shutil.copyfile(src, dst)
                return True
            except Exception:
                return False
        return False

    except Exception:
        return False


def safe_copy_tree(
    src: str,
    dst: str,
    max_depth: Optional[int] = None,
    follow_symlinks: bool = False,
    ignore_patterns: Optional[List[str]] = None,
) -> int:
    """
    Safely copy directory tree with depth limit.

    Args:
        src: Source directory
        dst: Destination directory
        max_depth: Maximum depth to traverse (None = unlimited)
        follow_symlinks: Follow symbolic links
        ignore_patterns: List of patterns to ignore (glob style)

    Returns:
        Number of files successfully copied

    Example:
        >>> count = safe_copy_tree("/var/log", "/tmp/evidence/logs", max_depth=2)
        >>> count
        42
    """
    src_path = Path(src)
    dst_path = Path(dst)
    copied_count = 0

    if not src_path.exists():
        return 0

    # Create destination directory
    ensure_directory(str(dst_path))

    # Walk directory tree
    for root, dirs, files in os.walk(src, followlinks=follow_symlinks):
        # Calculate current depth
        current_depth = str(root).count(os.sep) - str(src).count(os.sep)

        # Check depth limit
        if max_depth is not None and current_depth >= max_depth:
            dirs.clear()  # Don't descend further
            continue

        # Create corresponding destination directory
        rel_root = Path(root).relative_to(src_path)
        dest_root = dst_path / rel_root
        ensure_directory(str(dest_root))

        # Copy files
        for file in files:
            src_file = Path(root) / file
            dst_file = dest_root / file

            if safe_copy_file(str(src_file), str(dst_file)):
                copied_count += 1

    return copied_count


def collect_with_hash(
    src: str,
    dst: str,
    meta_callback: Optional[Callable[[str, str, str], None]] = None,
    preserve_metadata: bool = True,
) -> Optional[str]:
    """
    Copy file and calculate hash in one operation.

    Optimized for forensic collection where both copy and hash are needed.

    Args:
        src: Source file path
        dst: Destination file path
        meta_callback: Callback function(hostname, filepath, hash)
        preserve_metadata: Preserve file metadata

    Returns:
        SHA256 hash if successful, None otherwise

    Example:
        >>> def log_hash(host, path, hash):
        ...     print(f"{path}: {hash}")
        >>> hash_val = collect_with_hash("/etc/passwd", "/tmp/passwd", log_hash)
    """
    # Copy file
    if not safe_copy_file(src, dst, preserve_metadata):
        return None

    try:
        # Calculate hash of destination file
        hash_value = calculate_sha256(dst)

        # Call metadata callback if provided
        if meta_callback:
            meta_callback("unknown", src, hash_value)

        return hash_value

    except Exception:
        return None


def make_artifact_structure(base_dir: str, subdirs: Optional[List[str]] = None) -> Path:
    """
    Create standard artifact directory structure.

    Args:
        base_dir: Base directory path
        subdirs: List of subdirectories to create

    Returns:
        Path to base directory

    Example:
        >>> make_artifact_structure(
        ...     "/tmp/evidence",
        ...     ["memory", "logs", "registry", "browsers"]
        ... )
    """
    base_path = ensure_directory(base_dir)

    if subdirs:
        for subdir in subdirs:
            ensure_directory(str(base_path / subdir))

    return base_path


def safe_remove(path: str, recursive: bool = False) -> bool:
    """
    Safely remove file or directory.

    Args:
        path: Path to remove
        recursive: Remove directory recursively

    Returns:
        True if successful, False otherwise

    Example:
        >>> safe_remove("/tmp/test_file.txt")
        True
        >>> safe_remove("/tmp/test_dir", recursive=True)
        True
    """
    try:
        path_obj = Path(path)

        if not path_obj.exists():
            return True

        if path_obj.is_file():
            path_obj.unlink()
        elif path_obj.is_dir():
            if recursive:
                shutil.rmtree(path)
            else:
                path_obj.rmdir()

        return True

    except Exception:
        return False


def get_file_info(filepath: str) -> dict:
    """
    Get file information including size, timestamps, and permissions.

    Args:
        filepath: Path to file

    Returns:
        Dictionary with file information

    Example:
        >>> info = get_file_info("/etc/passwd")
        >>> info['size']
        2847
    """
    path = Path(filepath)

    if not path.exists():
        return {}

    stat_info = path.stat()

    return {
        "path": str(path),
        "name": path.name,
        "size": stat_info.st_size,
        "mode": stat.filemode(stat_info.st_mode),
        "uid": stat_info.st_uid,
        "gid": stat_info.st_gid,
        "atime": stat_info.st_atime,
        "mtime": stat_info.st_mtime,
        "ctime": stat_info.st_ctime,
        "is_file": path.is_file(),
        "is_dir": path.is_dir(),
        "is_symlink": path.is_symlink(),
    }


def sanitize_filename(filename: str, replacement: str = "_") -> str:
    """
    Sanitize filename for safe storage.

    Replaces path separators and special characters with safe alternatives.

    Args:
        filename: Original filename
        replacement: Character to replace special chars with

    Returns:
        Sanitized filename

    Example:
        >>> sanitize_filename("/etc/apache2/sites-available/default")
        'etc_apache2_sites-available_default'
        >>> sanitize_filename("C:\\Windows\\System32\\config\\SAM")
        'C__Windows_System32_config_SAM'
    """
    # Replace path separators
    sanitized = filename.replace("/", replacement).replace("\\", replacement)

    # Replace other problematic characters
    problematic_chars = [":", "*", "?", '"', "<", ">", "|"]
    for char in problematic_chars:
        sanitized = sanitized.replace(char, replacement)

    # Remove leading/trailing spaces and dots
    sanitized = sanitized.strip(". ")

    return sanitized


def find_files_by_pattern(
    directory: str, pattern: str = "*", recursive: bool = True, max_depth: Optional[int] = None
) -> List[str]:
    """
    Find files matching pattern in directory.

    Args:
        directory: Directory to search
        pattern: Glob pattern (default: "*")
        recursive: Search recursively
        max_depth: Maximum depth to search

    Returns:
        List of matching file paths

    Example:
        >>> files = find_files_by_pattern("/var/log", "*.log", max_depth=2)
        >>> len(files)
        15
    """
    dir_path = Path(directory)

    if not dir_path.exists():
        return []

    matching_files = []

    if recursive:
        pattern_str = f"**/{pattern}" if "/" not in pattern else pattern
        for file_path in dir_path.glob(pattern_str):
            if file_path.is_file():
                # Check depth if specified
                if max_depth is not None:
                    depth = len(file_path.relative_to(dir_path).parts) - 1
                    if depth > max_depth:
                        continue

                matching_files.append(str(file_path))
    else:
        for file_path in dir_path.glob(pattern):
            if file_path.is_file():
                matching_files.append(str(file_path))

    return matching_files


def calculate_directory_size(directory: str) -> int:
    """
    Calculate total size of directory.

    Args:
        directory: Directory path

    Returns:
        Total size in bytes

    Example:
        >>> size = calculate_directory_size("/tmp/evidence")
        >>> size
        1048576
    """
    total_size = 0

    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = Path(root) / file
            try:
                total_size += file_path.stat().st_size
            except Exception:
                continue

    return total_size


def format_size(size_bytes: int) -> str:
    """
    Format byte size to human-readable string.

    Args:
        size_bytes: Size in bytes

    Returns:
        Formatted string (e.g., "1.5 GB")

    Example:
        >>> format_size(1536000000)
        '1.43 GB'
        >>> format_size(2048)
        '2.00 KB'
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0

    return f"{size_bytes:.2f} PB"
