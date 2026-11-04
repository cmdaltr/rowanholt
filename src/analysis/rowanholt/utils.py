#!/usr/bin/env python3 -tt
"""
Utility functions for Elrond
"""
import os
import re
import sys
from pathlib import Path
from typing import List, Iterator


def is_noninteractive():
    """
    Check if running in non-interactive mode (e.g., web interface, automation)

    Non-interactive mode is ALWAYS enabled by default unless explicitly disabled.
    This ensures clean output for web interfaces and automation.

    Returns:
        bool: True if running in non-interactive mode (default), False only if explicitly disabled
    """
    # Check if explicitly set to '0' to disable non-interactive mode
    # Otherwise, default to non-interactive (True)
    env_value = os.environ.get('ELROND_NONINTERACTIVE', '1')
    return env_value != '0'


def strip_ansi_codes(text):
    """
    Remove ANSI color codes and escape sequences from text

    Args:
        text: String that may contain ANSI codes

    Returns:
        String with ANSI codes removed
    """
    ansi_escape = re.compile(r'\033\[[0-9;]*m')
    return ansi_escape.sub('', text)


def safe_print(text, use_colors=True):
    """
    Print text with optional ANSI color code stripping for non-interactive mode

    Args:
        text: Text to print
        use_colors: If False or in non-interactive mode, strip ANSI codes
    """
    if is_noninteractive() or not use_colors:
        text = strip_ansi_codes(text)
    # Filter out visual noise in non-interactive mode
    if is_noninteractive():
        # Skip empty lines, separator lines, and ASCII art
        if text.strip() in ['', '----------------------------------------', '-' * 40]:
            return
        # Skip lines that are just visual formatting
        if all(c in ' -=_.|/\\' for c in text.strip()):
            return
    print(text)


def safe_input(prompt, default="y"):
    """
    Wrapper for input() that handles non-interactive mode.

    When ELROND_NONINTERACTIVE environment variable is set,
    returns the default value without prompting.

    Args:
        prompt: The prompt to display to the user
        default: The default value to return in non-interactive mode (default: "y")

    Returns:
        User input string or default value
    """
    if is_noninteractive():
        # In non-interactive mode, return default without prompting
        # Print the prompt and default to log for debugging
        prompt_clean = strip_ansi_codes(prompt)
        print(f"{prompt_clean}[auto: {default}]")
        return default
    else:
        # In interactive mode, use regular input
        return input(prompt)


def safe_listdir(path: str) -> List[str]:
    """
    Safely list directory contents, working around macOS Docker VirtioFS/gRPC-FUSE issues.

    On macOS with Docker Desktop, the VirtioFS filesystem can cause os.listdir() to fail
    with FileNotFoundError even when the directory exists. This function uses a file
    descriptor-based workaround that resolves the issue.

    Args:
        path: Directory path to list

    Returns:
        List of directory entry names

    Raises:
        FileNotFoundError: If the directory truly doesn't exist
        NotADirectoryError: If path is not a directory
    """
    try:
        # Try standard listdir first (works in most cases)
        return os.listdir(path)
    except FileNotFoundError:
        # If standard listdir fails but path might exist (VirtioFS bug),
        # try using file descriptor approach
        try:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                return os.listdir(fd)
            finally:
                os.close(fd)
        except FileNotFoundError:
            # If both methods fail, directory truly doesn't exist
            raise


def safe_iterdir(path: str) -> Iterator[os.DirEntry]:
    """
    Safely iterate directory contents using scandir, with VirtioFS workaround.

    Similar to safe_listdir but yields DirEntry objects for more efficient
    attribute access (like is_dir(), is_file()).

    Args:
        path: Directory path to iterate

    Yields:
        os.DirEntry objects for each directory entry

    Raises:
        FileNotFoundError: If the directory truly doesn't exist
        NotADirectoryError: If path is not a directory
    """
    try:
        # Try standard scandir first
        with os.scandir(path) as entries:
            for entry in entries:
                yield entry
    except FileNotFoundError:
        # Use file descriptor workaround for VirtioFS
        try:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                # listdir(fd) gives us names, but we need to construct DirEntry-like info
                for name in os.listdir(fd):
                    # Yield pseudo-DirEntry using scandir on parent
                    full_path = os.path.join(path, name)
                    # Create a simple object with DirEntry-like interface
                    yield _SimpleDirEntry(name, full_path)
            finally:
                os.close(fd)
        except FileNotFoundError:
            raise


class _SimpleDirEntry:
    """Simple DirEntry-like class for VirtioFS workaround"""
    def __init__(self, name: str, path: str):
        self.name = name
        self.path = path

    def is_dir(self, follow_symlinks=True):
        if follow_symlinks:
            return os.path.isdir(self.path)
        return os.path.isdir(self.path) and not os.path.islink(self.path)

    def is_file(self, follow_symlinks=True):
        if follow_symlinks:
            return os.path.isfile(self.path)
        return os.path.isfile(self.path) and not os.path.islink(self.path)

    def is_symlink(self):
        return os.path.islink(self.path)

    def stat(self, follow_symlinks=True):
        if follow_symlinks:
            return os.stat(self.path)
        return os.lstat(self.path)
