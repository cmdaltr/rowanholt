#!/usr/bin/env python3
"""
Run Rivendell Tests

This module defines test scenarios for various forensic image processing combinations.
Each test case specifies source images and processing options to validate.

Usage:
    python tests/scripts/run_test.py --list                    # List all test cases
    python tests/scripts/run_test.py --status                  # Show job status (running/pending/completed/failed)
    python tests/scripts/run_test.py --pause <job_id>          # SIGSTOP a running job's Elrond process group
    python tests/scripts/run_test.py --resume <job_id>         # SIGCONT a paused job
    python tests/scripts/run_test.py --run <name>              # Run specific test
    python tests/scripts/run_test.py --run <name> -y           # Run and auto-confirm overwrite
    python tests/scripts/run_test.py --run <name> --wait       # Run and wait for completion
    python tests/scripts/run_test.py --queue <n1> <n2> <n3>    # Queue multiple tests
    python tests/scripts/run_test.py --run-tags <tag>          # Run all tests with tag
    python tests/scripts/run_test.py --generate-jobs           # Generate job JSON files for Web UI

Examples:
    # Check job status
    python tests/scripts/run_test.py --status

    # Run a single test with auto-confirm
    python tests/scripts/run_test.py --run win_brisk -y

    # Queue several tests (returns immediately, jobs run sequentially)
    python tests/scripts/run_test.py --queue win_brisk win_archive win_keywords -y

    # Queue all Windows tests
    python tests/scripts/run_test.py --run-tags windows -y

Test images should be placed in the path specified by TEST_IMAGES_PATH environment variable,
or defaults to /Volumes/Media5TB/rivendell_imgs/
"""

import os
import sys
import json
import shutil
import argparse
import time
from dataclasses import dataclass, field, asdict
from typing import List, Optional
from datetime import datetime

try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# Default test images path - override with TEST_IMAGES_PATH env var
# Checks multiple locations in order of preference
def _find_images_path():
    """Find the first existing test images path that contains actual forensic images.

    Checks platform-specific locations:
    - macOS: /Volumes/*/rivendell_imgs, /Volumes/*/rivendell, /Volumes/*/*/rivendell (external drives)
    - Linux: /mnt/*/rivendell_imgs, /media/*/rivendell_imgs (mount points)
    - Windows: [A-Z]:/rivendell_imgs (drive letters)
    - All: /tmp/rivendell (fallback)
    """
    if os.environ.get("TEST_IMAGES_PATH"):
        return os.environ["TEST_IMAGES_PATH"]

    import glob as glob_module
    import platform

    # Platform-specific search patterns
    search_patterns = []

    system = platform.system()
    if system == "Darwin":  # macOS
        search_patterns.extend([
            "/Volumes/*/rivendell_imgs",  # External drives
            "/Volumes/*/rivendell",
            "/Volumes/*/*/rivendell",     # e.g. /Volumes/Portable6TB/Data/rivendell
            "/tmp/rivendell",
        ])
    elif system == "Linux":
        search_patterns.extend([
            "/mnt/*/rivendell_imgs",     # Common mount point
            "/media/*/rivendell_imgs",   # Ubuntu/Debian style mounts
            "/mnt/rivendell_imgs",       # Direct mount
            "/media/rivendell_imgs",     # Direct mount
            "/tmp/rivendell",
        ])
    elif system == "Windows":
        # Check all drive letters (A-Z)
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            search_patterns.append(f"{letter}:/rivendell_imgs")
        search_patterns.append("C:/temp/rivendell")
    else:
        # Unknown system - just use temp
        search_patterns.append("/tmp/rivendell")

    candidates = []
    for pattern in search_patterns:
        if '*' in pattern:
            # Expand wildcard patterns
            candidates.extend(glob_module.glob(pattern))
        else:
            candidates.append(pattern)

    # Check for paths that actually contain forensic images (E01, vmdk, raw files)
    image_extensions = ('.E01', '.e01', '.vmdk', '.raw', '.dd', '.img')
    for path in candidates:
        if os.path.isdir(path):
            try:
                # Verify this path contains at least one forensic image
                for f in os.listdir(path):
                    if any(f.endswith(ext) for ext in image_extensions):
                        return path
            except PermissionError:
                # Skip directories we can't read
                continue

    # Return platform-specific default if none exist
    if system == "Windows":
        return "C:/temp/rivendell"
    else:
        return "/tmp/rivendell"

TEST_IMAGES_PATH = _find_images_path()

# Test output path - override with TEST_OUTPUT_PATH env var
# Defaults to a 'tests' subdirectory under the images path
TEST_OUTPUT_PATH = os.environ.get("TEST_OUTPUT_PATH", f"{TEST_IMAGES_PATH}/tests")

# API URL - override with RIVENDELL_API_URL env var
API_URL = os.environ.get("RIVENDELL_API_URL", "http://localhost:5688")

# Sample files for testing: the repo's fixtures/, which docker-compose.yml mounts
# read-only into the worker at /tmp/rivendell/fixtures
CONTAINER_FILES_PATH = "/tmp/rivendell/fixtures"
SAMPLE_KEYWORDS_FILE = f"{CONTAINER_FILES_PATH}/keywords.txt"
SAMPLE_YARA_DIR = f"{CONTAINER_FILES_PATH}/yara_rules"
SAMPLE_IOCS_FILE = f"{CONTAINER_FILES_PATH}/iocs.txt"

# Gandalf pre-collected artifacts paths (override with env vars). Elrond's
# --Gandalf reader requires the path to end in /acquisitions/ (lab/lab.sh lays
# collections out that way).
GANDALF_POWERSHELL_PATH = os.environ.get(
    "GANDALF_POWERSHELL_PATH", f"{TEST_IMAGES_PATH}/gandalf/powershell_collection/acquisitions/"
)
GANDALF_PYTHON_PATH = os.environ.get(
    "GANDALF_PYTHON_PATH", f"{TEST_IMAGES_PATH}/gandalf/python_collection/acquisitions/"
)
GANDALF_BASH_PATH = os.environ.get(
    "GANDALF_BASH_PATH", f"{TEST_IMAGES_PATH}/gandalf/bash_collection/acquisitions/"
)

# Cloud-hosted image paths (override with env vars)
# Format: s3://bucket/path or azure://container/path
AWS_S3_DISK_IMAGE = os.environ.get("AWS_S3_DISK_IMAGE", "s3://rivendell-test-images/win10.E01")
AWS_S3_MEMORY_IMAGE = os.environ.get("AWS_S3_MEMORY_IMAGE", "s3://rivendell-test-images/win10.mem")
AZURE_BLOB_DISK_IMAGE = os.environ.get(
    "AZURE_BLOB_DISK_IMAGE", "azure://rivendell-images/linux_server.raw"
)
AZURE_BLOB_MEMORY_IMAGE = os.environ.get(
    "AZURE_BLOB_MEMORY_IMAGE", "azure://rivendell-images/linux_server.mem"
)

# Mordor dataset paths (https://github.com/OTRF/mordor)
MORDOR_DATASETS_PATH = os.environ.get("MORDOR_DATASETS_PATH", f"{TEST_IMAGES_PATH}/mordor")

# Local files path (mounted to container via docker-compose, fallback to copy)
LOCAL_FILES_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "fixtures")

# Track if samples have been copied to container this session
_samples_copied = False


def copy_samples_to_container():
    """Copy analysis files (keywords, yara rules, IOC watchlists) to the Docker container.

    Note: docker-compose.yml mounts ./fixtures to /tmp/rivendell/fixtures (read-only),
    so this function is a fallback for cases where the volume mount isn't available.
    """
    global _samples_copied
    if _samples_copied:
        return True

    import subprocess

    # Try different container names (most common first)
    container_names = [
        "rivendell-celery-worker",
        "rivendell-celery-worker-1",
        "rivendell-web-celery-worker-1",
    ]

    container_name = None
    for name in container_names:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
        )
        if name in result.stdout:
            container_name = name
            break

    if not container_name:
        print("  WARNING: Could not find celery-worker container")
        print("  Keywords, YARA, and IOC tests may fail")
        return False

    # Check if local files directory exists
    if not os.path.isdir(LOCAL_FILES_PATH):
        print(f"  WARNING: files directory not found: {LOCAL_FILES_PATH}")
        return False

    # Already there through the compose mount (read-only, so docker cp would fail)
    mounted = subprocess.run(
        ["docker", "exec", container_name, "test", "-f", SAMPLE_KEYWORDS_FILE],
        capture_output=True,
    )
    if mounted.returncode == 0:
        _samples_copied = True
        return True

    # Create target directory in container
    subprocess.run(
        ["docker", "exec", container_name, "mkdir", "-p", CONTAINER_FILES_PATH],
        capture_output=True,
    )

    # Copy files to container
    result = subprocess.run(
        ["docker", "cp", f"{LOCAL_FILES_PATH}/.", f"{container_name}:{CONTAINER_FILES_PATH}/"],
        capture_output=True,
        text=True,
    )

    if result.returncode == 0:
        print(f"  Analysis files copied to container at {CONTAINER_FILES_PATH}")
        _samples_copied = True
        return True
    else:
        print(f"  WARNING: Could not copy files to container: {result.stderr}")
        return False


@dataclass
class TestCase:
    """Represents a single test case for image processing."""

    name: str
    description: str
    images: List[str]
    options: dict = field(default_factory=dict)
    expected_outputs: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    estimated_duration_minutes: int = 30

    def to_job_options(self) -> dict:
        """Convert to job options format for Web UI (matches AnalysisOptions model)."""
        opts = {
            # Main operation modes
            "local": not self.options.get("gandalf", False),
            "gandalf": self.options.get("gandalf", False),
            # Analysis options
            "analysis": self.options.get("analysis", False),
            "extract_iocs": self.options.get("extract_iocs", False),
            "misplaced_binaries": self.options.get("misplaced_binaries", False),
            "masquerading": self.options.get("masquerading", False),
            "timeline": self.options.get("timeline", False),
            "memory": self.options.get("memory", False),
            "memory_timeline": self.options.get("memory_timeline", False),
            # Advanced processing options
            "keywords": bool(self.options.get("keywords_file")),
            "keywords_file": self.options.get("keywords_file"),
            "yara": bool(self.options.get("yara_dir")),
            "yara_dir": self.options.get("yara_dir"),
            "collectFiles": self.options.get("collect_files", False),
            "collectFiles_filter": self.options.get("collect_files_filter"),
            # Speed/Quality modes
            "brisk": self.options.get("brisk", False),
            "mordor": self.options.get("mordor", False),
            # Collection options
            "vss": self.options.get("vss", False),
            "userprofiles": self.options.get("userprofiles", False),
            # Collect files presets (matching file selection menu)
            "collect_files_all": self.options.get("collect_files_all", False),
            "collect_files_hidden": self.options.get("collect_files_hidden", False),
            "collect_files_bin": self.options.get("collect_files_bin", False),
            "collect_files_docs": self.options.get("collect_files_docs", False),
            "collect_files_archive": self.options.get("collect_files_archive", False),
            "collect_files_scripts": self.options.get("collect_files_scripts", False),
            "collect_files_lnk": self.options.get("collect_files_lnk", False),
            "collect_files_web": self.options.get("collect_files_web", False),
            "collect_files_mail": self.options.get("collect_files_mail", False),
            "collect_files_virtual": self.options.get("collect_files_virtual", False),
            "collect_files_unalloc": self.options.get("collect_files_unalloc", False),
            # Verification options
            "hash_collected": self.options.get("hash_collected", False),
            "hash_all": self.options.get("hash_all", False),
            "last_access_times": self.options.get("last_access_times", False),
            # Output options
            "splunk": self.options.get("splunk", False),
            "elastic": self.options.get("elastic", False),
            "navigator": self.options.get("navigator", False),
            "archive": self.options.get("archive", False),
            # Debug/Logging options
            "debug": self.options.get("debug", False),
        }
        # Remove None values
        return {k: v for k, v in opts.items() if v is not None}


# =============================================================================
# TEST IMAGE DEFINITIONS
# =============================================================================

# Windows test images
WIN_DISK_IMAGE = "win7-64-nfury-c-drive.E01"
WIN_MEMORY_IMAGE = "win7-64-nfury-memory-raw.001"
# WIN_DISK_IMAGE = "win7-32-nromanoff-c-drive.E01"
# WIN_DISK_IMAGE = "Win10.vmdk.raw"
# WIN_MEMORY_IMAGE = "BlackEnergy_DESKTOP-GDNS4LP-20210602-121741.raw"
# WIN_MEMORY_IMAGE = "Dridex_DESKTOP-GDNS4LP-20210602-103614.raw"

# Linux test images
LINUX_DISK_IMAGE = "Linux_mail.vmdk.raw"
LINUX_MEMORY_IMAGE = "5.8.0-44-generic.mem"
# LINUX_DISK_IMAGE = "SIFT-Onedrive.vmdk"
# LINUX_MEMORY_IMAGE = "4.4.0-97-generic.mem"

# macOS test images
MAC_DISK_IMAGE = "MacintoshHD_disk5.E01"
MAC_MEMORY_IMAGE = "macOS1013.raw"


# =============================================================================
# TEST CASES: WINDOWS DISK IMAGE
# =============================================================================

WINDOWS_TESTS = [
    # TestCase(
    #     name="win_analysis",
    #     description="Windows disk image with Automated Analysis",
    #     images=[WIN_DISK_IMAGE],
    #     options={
    #         "analysis": True,
    #     },
    #     expected_outputs=["artefacts/cooked/", "analysis/"],
    #     tags=["windows", "analysis"],
    #     estimated_duration_minutes=30,
    # ),
    TestCase(
        name="win_archive",
        description="Windows disk image with Archive output",
        images=[WIN_DISK_IMAGE],
        options={
            "archive": True,
        },
        expected_outputs=[".zip"],
        tags=["windows", "archive"],
        estimated_duration_minutes=45,
    ),
    # TestCase(
    #     name="win_basic",
    #     description="Windows disk image - Basic processing (no options)",
    #     images=[WIN_DISK_IMAGE],
    #     options={},
    #     expected_outputs=["artefacts/cooked/", "artefacts/raw/"],
    #     tags=["windows", "basic", "quick"],
    #     estimated_duration_minutes=15,
    # ),
    TestCase(
        name="win_brisk",
        description="Windows disk image with Brisk mode (fast processing)",
        images=[WIN_DISK_IMAGE],
        options={
            "brisk": True,
        },
        expected_outputs=["artefacts/cooked/"],
        tags=["windows", "brisk", "quick"],
        estimated_duration_minutes=10,
    ),
    TestCase(
        name="win_collect_files_all",
        description="Windows disk image - Collect ALL file types",
        images=[WIN_DISK_IMAGE],
        options={
            "collect_files_all": True,
        },
        expected_outputs=["files/"],
        tags=["windows", "collect_files", "slow"],
        estimated_duration_minutes=90,
    ),
    TestCase(
        name="win_collect_files_archive",
        description="Windows disk image - Collect archive files",
        images=[WIN_DISK_IMAGE],
        options={
            "collect_files_archive": True,
        },
        expected_outputs=["files/"],
        tags=["windows", "collect_files", "archives"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="win_collect_files_bin",
        description="Windows disk image - Collect binary/executable files",
        images=[WIN_DISK_IMAGE],
        options={
            "collect_files_bin": True,
        },
        expected_outputs=["files/"],
        tags=["windows", "collect_files", "executables"],
        estimated_duration_minutes=45,
    ),
    TestCase(
        name="win_collect_files_docs",
        description="Windows disk image - Collect document files",
        images=[WIN_DISK_IMAGE],
        options={
            "collect_files_docs": True,
        },
        expected_outputs=["files/"],
        tags=["windows", "collect_files", "documents"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="win_collect_files_hidden",
        description="Windows disk image - Collect hidden files",
        images=[WIN_DISK_IMAGE],
        options={
            "collect_files_hidden": True,
        },
        expected_outputs=["files/"],
        tags=["windows", "collect_files", "hidden"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="win_collect_files_lnk",
        description="Windows disk image - Collect LNK shortcut files",
        images=[WIN_DISK_IMAGE],
        options={
            "collect_files_lnk": True,
        },
        expected_outputs=["files/"],
        tags=["windows", "collect_files", "lnk"],
        estimated_duration_minutes=20,
    ),
    TestCase(
        name="win_collect_files_mail",
        description="Windows disk image - Collect email files (PST, OST, etc.)",
        images=[WIN_DISK_IMAGE],
        options={
            "collect_files_mail": True,
        },
        expected_outputs=["files/"],
        tags=["windows", "collect_files", "mail"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="win_collect_files_scripts",
        description="Windows disk image - Collect script files",
        images=[WIN_DISK_IMAGE],
        options={
            "collect_files_scripts": True,
        },
        expected_outputs=["files/"],
        tags=["windows", "collect_files", "scripts"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="win_carve_unalloc",
        description="Windows disk image - Carve unallocated space",
        images=[WIN_DISK_IMAGE],
        options={
            "collect_files_unalloc": True,
        },
        expected_outputs=["files/carved/"],
        tags=["windows", "collect_files", "carving", "slow"],
        estimated_duration_minutes=120,
    ),
    TestCase(
        name="win_collect_files_virtual",
        description="Windows disk image - Collect virtual machine files",
        images=[WIN_DISK_IMAGE],
        options={
            "collect_files_virtual": True,
        },
        expected_outputs=["files/"],
        tags=["windows", "collect_files", "virtual"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="win_collect_files_web",
        description="Windows disk image - Collect web-related files",
        images=[WIN_DISK_IMAGE],
        options={
            "collect_files_web": True,
        },
        expected_outputs=["files/"],
        tags=["windows", "collect_files", "web"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="win_verbose",
        description="Windows disk image with Verbose logging",
        images=[WIN_DISK_IMAGE],
        options={
            "verbose": True,
        },
        expected_outputs=["artefacts/cooked/"],
        tags=["windows", "verbose"],
        estimated_duration_minutes=20,
    ),
    # TestCase(
    #     name="win_elastic",
    #     description="Windows disk image with Elastic ingestion",
    #     images=[WIN_DISK_IMAGE],
    #     options={
    #         "analysis": True,
    #         "elastic": True,
    #     },
    #     expected_outputs=["analysis/"],
    #     tags=["windows", "elastic", "siem"],
    #     estimated_duration_minutes=45,
    # ),
    TestCase(
        name="win_extract_iocs",
        description="Windows disk image with Extract IOCs and IOC watchlist",
        images=[WIN_DISK_IMAGE],
        options={
            "analysis": True,
            "extract_iocs": True,
            "iocs_file": SAMPLE_IOCS_FILE,
        },
        expected_outputs=["analysis/", "iocs.json"],
        tags=["windows", "iocs", "analysis"],
        estimated_duration_minutes=45,
    ),
    TestCase(
        name="win_full",
        description="Windows disk image with ALL options (exhaustive)",
        images=[WIN_DISK_IMAGE],
        options={
            "analysis": True,
            "extract_iocs": True,
            "vss": True,
            "userprofiles": True,
            "splunk": True,
            "elastic": True,
            "navigator": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/", "artefacts/cooked/vss1/"],
        tags=["windows", "exhaustive", "slow"],
        estimated_duration_minutes=180,
    ),
    # TestCase(
    #     name="win_hash_collected",
    #     description="Windows disk image with Hash Collected files",
    #     images=[WIN_DISK_IMAGE],
    #     options={
    #         "hash_collected": True,
    #     },
    #     expected_outputs=["meta_audit.log"],
    #     tags=["windows", "hashing"],
    #     estimated_duration_minutes=60,
    # ),
    TestCase(
        name="win_keywords",
        description="Windows disk image with Keywords search",
        images=[WIN_DISK_IMAGE],
        options={
            "keywords_file": SAMPLE_KEYWORDS_FILE,
        },
        expected_outputs=["artefacts/cooked/", "keywords/"],
        tags=["windows", "keywords"],
        estimated_duration_minutes=45,
    ),
    # SKIPPED - Feature not implemented in web backend (last_access_times not wired up)
    # TestCase(
    #     name="win_last_access",
    #     description="Windows disk image with Last Access Times preserved",
    #     images=[WIN_DISK_IMAGE],
    #     options={
    #         "preserve_access_times": True,
    #     },
    #     expected_outputs=["artefacts/cooked/"],
    #     tags=["windows", "access_times"],
    #     estimated_duration_minutes=20,
    # ),
    # TestCase(
    #     name="win_navigator",
    #     description="Windows disk image with ATT&CK Navigator",
    #     images=[WIN_DISK_IMAGE],
    #     options={
    #         "analysis": True,
    #         "navigator": True,
    #     },
    #     expected_outputs=["analysis/", "navigator/"],
    #     tags=["windows", "navigator", "mitre"],
    #     estimated_duration_minutes=45,
    # ),
    # TestCase(
    #     name="win_nsrl",
    #     description="Windows disk image with NSRL hash comparison",
    #     images=[WIN_DISK_IMAGE],
    #     options={
    #         "hash_collected": True,
    #         "nsrl": True,
    #     },
    #     expected_outputs=["meta_audit.log"],
    #     tags=["windows", "nsrl", "hashing", "cli_only"],
    #     estimated_duration_minutes=90,
    # ),
    # SKIPPED - Use combined win_splunk_elastic_nav test instead
    # TestCase(
    #     name="win_splunk",
    #     description="Windows disk image with Splunk ingestion",
    #     images=[WIN_DISK_IMAGE],
    #     options={
    #         "analysis": True,
    #         "splunk": True,
    #     },
    #     expected_outputs=["analysis/"],
    #     tags=["windows", "splunk", "siem"],
    #     estimated_duration_minutes=45,
    # ),
    TestCase(
        name="win_splunk_elastic_nav",
        description="Windows disk image with Splunk + Elastic + Navigator exports",
        images=[WIN_DISK_IMAGE],
        options={
            "analysis": True,
            "splunk": True,
            "elastic": True,
            "navigator": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/", "navigator/"],
        tags=["windows", "splunk", "elastic", "navigator", "siem", "siem_dashboard"],
        estimated_duration_minutes=60,
    ),
    TestCase(
        name="win_timeline",
        description="Windows disk image with Plaso Timeline",
        images=[WIN_DISK_IMAGE],
        options={
            "timeline": True,
        },
        expected_outputs=["artefacts/plaso_timeline.csv"],
        tags=["windows", "timeline", "slow"],
        estimated_duration_minutes=120,
    ),
    TestCase(
        name="win_userprofiles",
        description="Windows disk image with User Profiles collection",
        images=[WIN_DISK_IMAGE],
        options={
            "userprofiles": True,
        },
        expected_outputs=["artefacts/raw/user_profiles/"],
        tags=["windows", "userprofiles"],
        estimated_duration_minutes=45,
    ),
    TestCase(
        name="win_vss",
        description="Windows disk image with VSS (Volume Shadow Copies)",
        images=[WIN_DISK_IMAGE],
        options={
            "vss": True,
        },
        expected_outputs=["artefacts/cooked/vss1/", "artefacts/cooked/vss2/"],
        tags=["windows", "vss", "slow"],
        estimated_duration_minutes=60,
    ),
    TestCase(
        name="win_yara",
        description="Windows disk image with YARA rules",
        images=[WIN_DISK_IMAGE],
        options={
            "yara_dir": SAMPLE_YARA_DIR,
        },
        expected_outputs=["artefacts/cooked/", "analysis/yara.csv"],
        tags=["windows", "yara"],
        estimated_duration_minutes=60,
    ),
    TestCase(
        name="win_mordor_mode",
        description="Windows disk image with Mordor mode (aggressive threat hunting)",
        images=[WIN_DISK_IMAGE],
        options={
            "mordor": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/", "iocs.json", "navigator/"],
        tags=["windows", "mordor_mode", "threat_hunting", "siem"],
        estimated_duration_minutes=90,
    ),
]


# =============================================================================
# TEST CASES: WINDOWS MEMORY IMAGE
# =============================================================================

MEMORY_TESTS = [
    TestCase(
        name="linux_disk_and_memory",
        description="Linux disk + memory image combined",
        images=[LINUX_DISK_IMAGE, LINUX_MEMORY_IMAGE],
        options={
            "analysis": True,
            "memory": True,
        },
        expected_outputs=["artefacts/cooked/", "linux.pslist.PsList.json"],
        tags=["linux", "memory", "disk", "combined"],
        estimated_duration_minutes=45,
    ),
    TestCase(
        name="linux_mem_splunk_elastic_nav",
        description="Linux memory image with Splunk + Elastic + Navigator exports",
        images=[LINUX_MEMORY_IMAGE],
        options={
            "memory": True,
            "splunk": True,
            "elastic": True,
            "navigator": True,
        },
        expected_outputs=["memory/", "navigator/"],
        tags=["linux", "memory", "splunk", "elastic", "navigator", "siem", "siem_dashboard"],
        estimated_duration_minutes=45,
    ),
    TestCase(
        name="mac_disk_and_memory",
        description="macOS disk + memory image combined",
        images=[MAC_DISK_IMAGE, MAC_MEMORY_IMAGE],
        options={
            "analysis": True,
            "memory": True,
        },
        expected_outputs=["artefacts/cooked/", "memory_mac.info.Info.json"],
        tags=["macos", "memory", "disk", "combined"],
        estimated_duration_minutes=45,
    ),
    TestCase(
        name="mac_mem_splunk_elastic_nav",
        description="macOS memory image with Splunk + Elastic + Navigator exports",
        images=[MAC_MEMORY_IMAGE],
        options={
            "memory": True,
            "splunk": True,
            "elastic": True,
            "navigator": True,
        },
        expected_outputs=["memory/", "navigator/"],
        tags=["macos", "memory", "splunk", "elastic", "navigator", "siem", "siem_dashboard"],
        estimated_duration_minutes=45,
    ),
    TestCase(
        name="win_disk_and_memory",
        description="Windows disk + memory image combined",
        images=[WIN_DISK_IMAGE, WIN_MEMORY_IMAGE],
        options={
            "analysis": True,
            "memory": True,
        },
        expected_outputs=["artefacts/cooked/", "memory_windows.info.Info.json"],
        tags=["windows", "memory", "disk", "combined"],
        estimated_duration_minutes=45,
    ),
    TestCase(
        name="win_memory_basic",
        description="Windows memory image - Basic Volatility processing",
        images=[WIN_MEMORY_IMAGE],
        options={
            "memory": True,
        },
        expected_outputs=["memory_windows.info.Info.json"],
        tags=["windows", "memory", "volatility"],
        estimated_duration_minutes=15,
    ),
    TestCase(
        name="win_mem_splunk_elastic_nav",
        description="Windows memory image with Splunk + Elastic + Navigator exports",
        images=[WIN_MEMORY_IMAGE],
        options={
            "memory": True,
            "splunk": True,
            "elastic": True,
            "navigator": True,
        },
        expected_outputs=["memory/", "navigator/"],
        tags=["windows", "memory", "splunk", "elastic", "navigator", "siem", "siem_dashboard"],
        estimated_duration_minutes=45,
    ),
    TestCase(
        name="win_memory_timeline",
        description="Windows memory image with memory timeline",
        images=[WIN_MEMORY_IMAGE],
        options={
            "memory": True,
            "memory_timeline": True,
        },
        expected_outputs=["memory_timeliner.Timeliner.json"],
        tags=["windows", "memory", "timeline"],
        estimated_duration_minutes=30,
    ),
]


# =============================================================================
# TEST CASES: LINUX DISK IMAGE
# =============================================================================

LINUX_TESTS = [
    TestCase(
        name="linux_analysis",
        description="Linux disk image with Automated Analysis",
        images=[LINUX_DISK_IMAGE],
        options={
            "analysis": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/"],
        tags=["linux", "analysis"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="linux_archive",
        description="Linux disk image with Archive output",
        images=[LINUX_DISK_IMAGE],
        options={
            "archive": True,
        },
        expected_outputs=[".zip"],
        tags=["linux", "archive"],
        estimated_duration_minutes=45,
    ),
    TestCase(
        name="linux_basic",
        description="Linux disk image - Basic processing",
        images=[LINUX_DISK_IMAGE],
        options={},
        expected_outputs=["artefacts/cooked/", "artefacts/raw/"],
        tags=["linux", "basic", "quick"],
        estimated_duration_minutes=15,
    ),
    TestCase(
        name="linux_collect_files_all",
        description="Linux disk image - Collect ALL file types",
        images=[LINUX_DISK_IMAGE],
        options={
            "collect_files_all": True,
        },
        expected_outputs=["files/"],
        tags=["linux", "collect_files", "slow"],
        estimated_duration_minutes=90,
    ),
    TestCase(
        name="linux_collect_files_archive",
        description="Linux disk image - Collect archive files",
        images=[LINUX_DISK_IMAGE],
        options={
            "collect_files_archive": True,
        },
        expected_outputs=["files/"],
        tags=["linux", "collect_files", "archives"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="linux_collect_files_bin",
        description="Linux disk image - Collect binary/executable files",
        images=[LINUX_DISK_IMAGE],
        options={
            "collect_files_bin": True,
        },
        expected_outputs=["files/"],
        tags=["linux", "collect_files", "executables"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="linux_collect_files_docs",
        description="Linux disk image - Collect document files",
        images=[LINUX_DISK_IMAGE],
        options={
            "collect_files_docs": True,
        },
        expected_outputs=["files/"],
        tags=["linux", "collect_files", "documents"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="linux_collect_files_hidden",
        description="Linux disk image - Collect hidden files (dot-prefixed)",
        images=[LINUX_DISK_IMAGE],
        options={
            "collect_files_hidden": True,
        },
        expected_outputs=["files/"],
        tags=["linux", "collect_files", "hidden"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="linux_collect_files_lnk",
        description="Linux disk image - Collect symbolic link files",
        images=[LINUX_DISK_IMAGE],
        options={
            "collect_files_lnk": True,
        },
        expected_outputs=["files/"],
        tags=["linux", "collect_files", "lnk"],
        estimated_duration_minutes=20,
    ),
    TestCase(
        name="linux_collect_files_mail",
        description="Linux disk image - Collect email files (mbox, etc.)",
        images=[LINUX_DISK_IMAGE],
        options={
            "collect_files_mail": True,
        },
        expected_outputs=["files/"],
        tags=["linux", "collect_files", "mail"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="linux_collect_files_scripts",
        description="Linux disk image - Collect script files",
        images=[LINUX_DISK_IMAGE],
        options={
            "collect_files_scripts": True,
        },
        expected_outputs=["files/"],
        tags=["linux", "collect_files", "scripts"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="linux_carve_unalloc",
        description="Linux disk image - Carve unallocated space",
        images=[LINUX_DISK_IMAGE],
        options={
            "collect_files_unalloc": True,
        },
        expected_outputs=["files/carved/"],
        tags=["linux", "collect_files", "carving", "slow"],
        estimated_duration_minutes=120,
    ),
    TestCase(
        name="linux_collect_files_virtual",
        description="Linux disk image - Collect virtual machine files",
        images=[LINUX_DISK_IMAGE],
        options={
            "collect_files_virtual": True,
        },
        expected_outputs=["files/"],
        tags=["linux", "collect_files", "virtual"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="linux_collect_files_web",
        description="Linux disk image - Collect web-related files",
        images=[LINUX_DISK_IMAGE],
        options={
            "collect_files_web": True,
        },
        expected_outputs=["files/"],
        tags=["linux", "collect_files", "web"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="linux_debug",
        description="Linux disk image with Debug logging",
        images=[LINUX_DISK_IMAGE],
        options={
            "debug": True,
        },
        expected_outputs=["artefacts/cooked/"],
        tags=["linux", "debug"],
        estimated_duration_minutes=20,
    ),
    # TestCase(
    #     name="linux_elastic",
    #     description="Linux disk image with Elastic ingestion",
    #     images=[LINUX_DISK_IMAGE],
    #     options={
    #         "analysis": True,
    #         "elastic": True,
    #     },
    #     expected_outputs=["analysis/"],
    #     tags=["linux", "elastic", "siem"],
    #     estimated_duration_minutes=45,
    # ),
    TestCase(
        name="linux_extract_iocs",
        description="Linux disk image with Extract IOCs",
        images=[LINUX_DISK_IMAGE],
        options={
            "analysis": True,
            "extract_iocs": True,
        },
        expected_outputs=["analysis/", "iocs.json"],
        tags=["linux", "iocs"],
        estimated_duration_minutes=45,
    ),
    TestCase(
        name="linux_full",
        description="Linux disk image with ALL options",
        images=[LINUX_DISK_IMAGE],
        options={
            "analysis": True,
            "extract_iocs": True,
            "userprofiles": True,
            "splunk": True,
            "elastic": True,
            "navigator": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/"],
        tags=["linux", "exhaustive", "slow"],
        estimated_duration_minutes=90,
    ),
    TestCase(
        name="linux_hash_collected",
        description="Linux disk image with Hash Collected files",
        images=[LINUX_DISK_IMAGE],
        options={
            "hash_collected": True,
        },
        expected_outputs=["meta_audit.log"],
        tags=["linux", "hashing"],
        estimated_duration_minutes=60,
    ),
    TestCase(
        name="linux_keywords",
        description="Linux disk image with Keywords search",
        images=[LINUX_DISK_IMAGE],
        options={
            "keywords_file": SAMPLE_KEYWORDS_FILE,
        },
        expected_outputs=["artefacts/cooked/", "keywords/"],
        tags=["linux", "keywords"],
        estimated_duration_minutes=45,
    ),
    # SKIPPED - Feature not implemented in web backend (last_access_times not wired up)
    # TestCase(
    #     name="linux_last_access",
    #     description="Linux disk image with Last Access Times preserved",
    #     images=[LINUX_DISK_IMAGE],
    #     options={
    #         "preserve_access_times": True,
    #     },
    #     expected_outputs=["artefacts/cooked/"],
    #     tags=["linux", "access_times"],
    #     estimated_duration_minutes=20,
    # ),
    TestCase(
        name="linux_memory",
        description="Linux disk + memory image with Memory Collection",
        images=[LINUX_DISK_IMAGE, LINUX_MEMORY_IMAGE],
        options={
            "memory": True,
        },
        expected_outputs=["linux.pslist.PsList.json"],
        tags=["linux", "memory"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="linux_memory_timeline",
        description="Linux disk + memory image with Memory Collection & memory timeline",
        images=[LINUX_DISK_IMAGE, LINUX_MEMORY_IMAGE],
        options={
            "memory": True,
            "memory_timeline": True,
        },
        expected_outputs=["memory_timeliner.Timeliner.json"],
        tags=["linux", "memory", "timeline"],
        estimated_duration_minutes=45,
    ),
    # TestCase(
    #     name="linux_navigator",
    #     description="Linux disk image with ATT&CK Navigator",
    #     images=[LINUX_DISK_IMAGE],
    #     options={
    #         "analysis": True,
    #         "navigator": True,
    #     },
    #     expected_outputs=["analysis/", "navigator/"],
    #     tags=["linux", "navigator", "mitre"],
    #     estimated_duration_minutes=45,
    # ),
    # TestCase(
    #     name="linux_nsrl",
    #     description="Linux disk image with NSRL hash comparison",
    #     images=[LINUX_DISK_IMAGE],
    #     options={
    #         "hash_collected": True,
    #         "nsrl": True,
    #     },
    #     expected_outputs=["meta_audit.log"],
    #     tags=["linux", "nsrl", "hashing", "cli_only"],
    #     estimated_duration_minutes=90,
    # ),
    # SKIPPED - Use combined linux_splunk_elastic_nav test instead
    # TestCase(
    #     name="linux_splunk",
    #     description="Linux disk image with Splunk ingestion",
    #     images=[LINUX_DISK_IMAGE],
    #     options={
    #         "analysis": True,
    #         "splunk": True,
    #     },
    #     expected_outputs=["analysis/"],
    #     tags=["linux", "splunk", "siem"],
    #     estimated_duration_minutes=45,
    # ),
    TestCase(
        name="linux_splunk_elastic_nav",
        description="Linux disk image with Splunk + Elastic + Navigator exports",
        images=[LINUX_DISK_IMAGE],
        options={
            "analysis": True,
            "splunk": True,
            "elastic": True,
            "navigator": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/", "navigator/"],
        tags=["linux", "splunk", "elastic", "navigator", "siem", "siem_dashboard"],
        estimated_duration_minutes=60,
    ),
    # SKIPPED - Symlinks removed from Web UI (still available via CLI)
    # TestCase(
    #     name="linux_symlinks",
    #     description="Linux disk image with Symlinks followed",
    #     images=[LINUX_DISK_IMAGE],
    #     options={
    #         "symlinks": True,
    #     },
    #     expected_outputs=["artefacts/cooked/"],
    #     tags=["linux", "symlinks"],
    #     estimated_duration_minutes=20,
    # ),
    TestCase(
        name="linux_timeline",
        description="Linux disk image with Plaso Timeline",
        images=[LINUX_DISK_IMAGE],
        options={
            "timeline": True,
        },
        expected_outputs=["artefacts/plaso_timeline.csv"],
        tags=["linux", "timeline", "slow"],
        estimated_duration_minutes=120,
    ),
    TestCase(
        name="linux_userprofiles",
        description="Linux disk image with User Profiles",
        images=[LINUX_DISK_IMAGE],
        options={
            "userprofiles": True,
        },
        expected_outputs=["artefacts/raw/user_profiles/"],
        tags=["linux", "userprofiles"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="linux_yara",
        description="Linux disk image with YARA rules",
        images=[LINUX_DISK_IMAGE],
        options={
            "yara_dir": SAMPLE_YARA_DIR,
        },
        expected_outputs=["artefacts/cooked/", "analysis/yara.csv"],
        tags=["linux", "yara"],
        estimated_duration_minutes=60,
    ),
    TestCase(
        name="linux_mordor_mode",
        description="Linux disk image with Mordor mode (aggressive threat hunting)",
        images=[LINUX_DISK_IMAGE],
        options={
            "mordor": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/", "iocs.json", "navigator/"],
        tags=["linux", "mordor_mode", "threat_hunting", "siem"],
        estimated_duration_minutes=75,
    ),
]


# =============================================================================
# TEST CASES: MACOS DISK IMAGE
# =============================================================================

MACOS_TESTS = [
    TestCase(
        name="mac_analysis",
        description="macOS disk image with Automated Analysis",
        images=[MAC_DISK_IMAGE],
        options={
            "analysis": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/"],
        tags=["macos", "analysis"],
        estimated_duration_minutes=45,
    ),
    TestCase(
        name="mac_archive",
        description="macOS disk image with Archive output",
        images=[MAC_DISK_IMAGE],
        options={
            "archive": True,
        },
        expected_outputs=[".zip"],
        tags=["macos", "archive"],
        estimated_duration_minutes=45,
    ),
    TestCase(
        name="mac_basic",
        description="macOS disk image - Basic processing",
        images=[MAC_DISK_IMAGE],
        options={},
        expected_outputs=["artefacts/cooked/", "artefacts/raw/"],
        tags=["macos", "basic", "quick"],
        estimated_duration_minutes=20,
    ),
    TestCase(
        name="mac_collect_files_all",
        description="macOS disk image - Collect ALL file types",
        images=[MAC_DISK_IMAGE],
        options={
            "collect_files_all": True,
        },
        expected_outputs=["files/"],
        tags=["macos", "collect_files", "slow"],
        estimated_duration_minutes=90,
    ),
    TestCase(
        name="mac_collect_files_archive",
        description="macOS disk image - Collect archive files",
        images=[MAC_DISK_IMAGE],
        options={
            "collect_files_archive": True,
        },
        expected_outputs=["files/"],
        tags=["macos", "collect_files", "archives"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="mac_collect_files_bin",
        description="macOS disk image - Collect binary/executable files",
        images=[MAC_DISK_IMAGE],
        options={
            "collect_files_bin": True,
        },
        expected_outputs=["files/"],
        tags=["macos", "collect_files", "executables"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="mac_collect_files_docs",
        description="macOS disk image - Collect document files",
        images=[MAC_DISK_IMAGE],
        options={
            "collect_files_docs": True,
        },
        expected_outputs=["files/"],
        tags=["macos", "collect_files", "documents"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="mac_collect_files_hidden",
        description="macOS disk image - Collect hidden files (dot-prefixed)",
        images=[MAC_DISK_IMAGE],
        options={
            "collect_files_hidden": True,
        },
        expected_outputs=["files/"],
        tags=["macos", "collect_files", "hidden"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="mac_collect_files_lnk",
        description="macOS disk image - Collect symbolic link and alias files",
        images=[MAC_DISK_IMAGE],
        options={
            "collect_files_lnk": True,
        },
        expected_outputs=["files/"],
        tags=["macos", "collect_files", "lnk"],
        estimated_duration_minutes=20,
    ),
    TestCase(
        name="mac_collect_files_mail",
        description="macOS disk image - Collect email files (emlx, mbox, etc.)",
        images=[MAC_DISK_IMAGE],
        options={
            "collect_files_mail": True,
        },
        expected_outputs=["files/"],
        tags=["macos", "collect_files", "mail"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="mac_collect_files_scripts",
        description="macOS disk image - Collect script files",
        images=[MAC_DISK_IMAGE],
        options={
            "collect_files_scripts": True,
        },
        expected_outputs=["files/"],
        tags=["macos", "collect_files", "scripts"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="mac_carve_unalloc",
        description="macOS disk image - Carve unallocated space",
        images=[MAC_DISK_IMAGE],
        options={
            "collect_files_unalloc": True,
        },
        expected_outputs=["files/carved/"],
        tags=["macos", "collect_files", "carving", "slow"],
        estimated_duration_minutes=120,
    ),
    TestCase(
        name="mac_collect_files_virtual",
        description="macOS disk image - Collect virtual machine files",
        images=[MAC_DISK_IMAGE],
        options={
            "collect_files_virtual": True,
        },
        expected_outputs=["files/"],
        tags=["macos", "collect_files", "virtual"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="mac_collect_files_web",
        description="macOS disk image - Collect web-related files",
        images=[MAC_DISK_IMAGE],
        options={
            "collect_files_web": True,
        },
        expected_outputs=["files/"],
        tags=["macos", "collect_files", "web"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="mac_debug",
        description="macOS disk image with Debug logging",
        images=[MAC_DISK_IMAGE],
        options={
            "debug": True,
        },
        expected_outputs=["artefacts/cooked/"],
        tags=["macos", "debug"],
        estimated_duration_minutes=20,
    ),
    # TestCase(
    #     name="mac_elastic",
    #     description="macOS disk image with Elastic ingestion",
    #     images=[MAC_DISK_IMAGE],
    #     options={
    #         "analysis": True,
    #         "elastic": True,
    #     },
    #     expected_outputs=["analysis/"],
    #     tags=["macos", "elastic", "siem"],
    #     estimated_duration_minutes=45,
    # ),
    TestCase(
        name="mac_extract_iocs",
        description="macOS disk image with Extract IOCs",
        images=[MAC_DISK_IMAGE],
        options={
            "analysis": True,
            "extract_iocs": True,
        },
        expected_outputs=["analysis/", "iocs.json"],
        tags=["macos", "iocs"],
        estimated_duration_minutes=60,
    ),
    TestCase(
        name="mac_full",
        description="macOS disk image with ALL options",
        images=[MAC_DISK_IMAGE],
        options={
            "analysis": True,
            "extract_iocs": True,
            "userprofiles": True,
            "splunk": True,
            "elastic": True,
            "navigator": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/"],
        tags=["macos", "exhaustive", "slow"],
        estimated_duration_minutes=120,
    ),
    TestCase(
        name="mac_hash_collected",
        description="macOS disk image with Hash Collected files",
        images=[MAC_DISK_IMAGE],
        options={
            "hash_collected": True,
        },
        expected_outputs=["meta_audit.log"],
        tags=["macos", "hashing"],
        estimated_duration_minutes=60,
    ),
    TestCase(
        name="mac_keywords",
        description="macOS disk image with Keywords search",
        images=[MAC_DISK_IMAGE],
        options={
            "keywords_file": SAMPLE_KEYWORDS_FILE,
        },
        expected_outputs=["artefacts/cooked/", "keywords/"],
        tags=["macos", "keywords"],
        estimated_duration_minutes=45,
    ),
    # SKIPPED - Feature not implemented in web backend (last_access_times not wired up)
    # TestCase(
    #     name="mac_last_access",
    #     description="macOS disk image with Last Access Times preserved",
    #     images=[MAC_DISK_IMAGE],
    #     options={
    #         "preserve_access_times": True,
    #     },
    #     expected_outputs=["artefacts/cooked/"],
    #     tags=["macos", "access_times"],
    #     estimated_duration_minutes=20,
    # ),
    TestCase(
        name="mac_memory",
        description="macOS disk image with Memory Collection",
        images=[MAC_DISK_IMAGE],
        options={
            "memory": True,
        },
        expected_outputs=["memory_mac.info.Info.json"],
        tags=["macos", "memory"],
        estimated_duration_minutes=30,
    ),
    TestCase(
        name="mac_memory_timeline",
        description="macOS disk image with Memory Collection & memory timeline",
        images=[MAC_DISK_IMAGE],
        options={
            "memory": True,
            "memory_timeline": True,
        },
        expected_outputs=["memory_timeliner.Timeliner.json"],
        tags=["macos", "memory", "timeline"],
        estimated_duration_minutes=45,
    ),
    # TestCase(
    #     name="mac_navigator",
    #     description="macOS disk image with ATT&CK Navigator",
    #     images=[MAC_DISK_IMAGE],
    #     options={
    #         "analysis": True,
    #         "navigator": True,
    #     },
    #     expected_outputs=["analysis/", "navigator/"],
    #     tags=["macos", "navigator", "mitre"],
    #     estimated_duration_minutes=45,
    # ),
    # TestCase(
    #     name="mac_nsrl",
    #     description="macOS disk image with NSRL hash comparison",
    #     images=[MAC_DISK_IMAGE],
    #     options={
    #         "hash_collected": True,
    #         "nsrl": True,
    #     },
    #     expected_outputs=["meta_audit.log"],
    #     tags=["macos", "nsrl", "hashing", "cli_only"],
    #     estimated_duration_minutes=90,
    # ),
    # SKIPPED - Use combined mac_splunk_elastic_nav test instead
    # TestCase(
    #     name="mac_splunk",
    #     description="macOS disk image with Splunk ingestion",
    #     images=[MAC_DISK_IMAGE],
    #     options={
    #         "analysis": True,
    #         "splunk": True,
    #     },
    #     expected_outputs=["analysis/"],
    #     tags=["macos", "splunk", "siem"],
    #     estimated_duration_minutes=45,
    # ),
    TestCase(
        name="mac_splunk_elastic_nav",
        description="macOS disk image with Splunk + Elastic + Navigator exports",
        images=[MAC_DISK_IMAGE],
        options={
            "analysis": True,
            "splunk": True,
            "elastic": True,
            "navigator": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/", "navigator/"],
        tags=["macos", "splunk", "elastic", "navigator", "siem", "siem_dashboard"],
        estimated_duration_minutes=60,
    ),
    TestCase(
        name="mac_timeline",
        description="macOS disk image with Plaso Timeline",
        images=[MAC_DISK_IMAGE],
        options={
            "timeline": True,
        },
        expected_outputs=["artefacts/plaso_timeline.csv"],
        tags=["macos", "timeline", "slow"],
        estimated_duration_minutes=120,
    ),
    TestCase(
        name="mac_userprofiles",
        description="macOS disk image with User Profiles",
        images=[MAC_DISK_IMAGE],
        options={
            "userprofiles": True,
        },
        expected_outputs=["artefacts/raw/user_profiles/"],
        tags=["macos", "userprofiles"],
        estimated_duration_minutes=45,
    ),
    TestCase(
        name="mac_yara",
        description="macOS disk image with YARA rules",
        images=[MAC_DISK_IMAGE],
        options={
            "yara_dir": SAMPLE_YARA_DIR,
        },
        expected_outputs=["artefacts/cooked/", "analysis/yara.csv"],
        tags=["macos", "yara"],
        estimated_duration_minutes=60,
    ),
    TestCase(
        name="mac_mordor_mode",
        description="macOS disk image with Mordor mode (aggressive threat hunting)",
        images=[MAC_DISK_IMAGE],
        options={
            "mordor": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/", "iocs.json", "navigator/"],
        tags=["macos", "mordor_mode", "threat_hunting", "siem"],
        estimated_duration_minutes=90,
    ),
]


# =============================================================================
# TEST CASES: MULTI-IMAGE COMBINATIONS
# =============================================================================

MULTI_IMAGE_TESTS = [
    TestCase(
        name="multi_all_platforms",
        description="Windows + Linux + macOS disk images",
        images=[WIN_DISK_IMAGE, LINUX_DISK_IMAGE, MAC_DISK_IMAGE],
        options={
            "analysis": True,
        },
        expected_outputs=["artefacts/cooked/"],
        tags=["multi", "windows", "linux", "macos", "slow"],
        estimated_duration_minutes=90,
    ),
    TestCase(
        name="multi_all_with_memory",
        description="All disk images + Windows memory",
        images=[WIN_DISK_IMAGE, LINUX_DISK_IMAGE, MAC_DISK_IMAGE, WIN_MEMORY_IMAGE],
        options={
            "analysis": True,
            "memory": True,
        },
        expected_outputs=["artefacts/cooked/", "memory_windows.info.Info.json"],
        tags=["multi", "exhaustive", "memory", "slow"],
        estimated_duration_minutes=120,
    ),
    TestCase(
        name="multi_full_exhaustive",
        description="All images with exhaustive options (STRESS TEST)",
        images=[WIN_DISK_IMAGE, LINUX_DISK_IMAGE, MAC_DISK_IMAGE, WIN_MEMORY_IMAGE],
        options={
            "analysis": True,
            "extract_iocs": True,
            "vss": True,
            "userprofiles": True,
            "memory": True,
            "splunk": True,
            "elastic": True,
            "navigator": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/", "artefacts/cooked/vss1/"],
        tags=["multi", "exhaustive", "stress", "very_slow"],
        estimated_duration_minutes=300,
    ),
    TestCase(
        name="multi_win_linux",
        description="Windows + Linux disk images",
        images=[WIN_DISK_IMAGE, LINUX_DISK_IMAGE],
        options={
            "analysis": True,
        },
        expected_outputs=["artefacts/cooked/"],
        tags=["multi", "windows", "linux"],
        estimated_duration_minutes=60,
    ),
    TestCase(
        name="multi_win_mac",
        description="Windows + macOS disk images",
        images=[WIN_DISK_IMAGE, MAC_DISK_IMAGE],
        options={
            "analysis": True,
        },
        expected_outputs=["artefacts/cooked/"],
        tags=["multi", "windows", "macos"],
        estimated_duration_minutes=60,
    ),
]


# =============================================================================
# TEST CASES: GANDALF MODE (PRE-COLLECTED)
# =============================================================================

GANDALF_TESTS = [
    TestCase(
        name="gandalf_bash_analysis",
        description="Gandalf mode - Bash collection with Automated Analysis",
        images=[GANDALF_BASH_PATH],
        options={
            "gandalf": True,
            "analysis": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/"],
        tags=["gandalf", "bash", "linux", "macos", "analysis"],
        estimated_duration_minutes=45,
    ),
    TestCase(
        name="gandalf_bash_basic",
        description="Gandalf mode - Process Bash-collected Linux/macOS artefacts",
        images=[GANDALF_BASH_PATH],
        options={
            "gandalf": True,
        },
        expected_outputs=["artefacts/cooked/"],
        tags=["gandalf", "bash", "linux", "macos"],
        estimated_duration_minutes=20,
    ),
    TestCase(
        name="gandalf_bash_timeline",
        description="Gandalf mode - Bash collection with Timeline generation",
        images=[GANDALF_BASH_PATH],
        options={
            "gandalf": True,
            "analysis": True,
            "timeline": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/", "timeline/"],
        tags=["gandalf", "bash", "linux", "macos", "timeline"],
        estimated_duration_minutes=90,
    ),
    TestCase(
        name="gandalf_powershell_analysis",
        description="Gandalf mode - PowerShell collection with Automated Analysis",
        images=[GANDALF_POWERSHELL_PATH],
        options={
            "gandalf": True,
            "analysis": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/"],
        tags=["gandalf", "powershell", "windows", "analysis"],
        estimated_duration_minutes=45,
    ),
    TestCase(
        name="gandalf_powershell_basic",
        description="Gandalf mode - Process PowerShell-collected Windows artefacts",
        images=[GANDALF_POWERSHELL_PATH],  # Path to pre-collected artefacts
        options={
            "gandalf": True,
        },
        expected_outputs=["artefacts/cooked/"],
        tags=["gandalf", "powershell", "windows"],
        estimated_duration_minutes=20,
    ),
    TestCase(
        name="gandalf_powershell_elastic",
        description="Gandalf mode - PowerShell collection with Elastic export",
        images=[GANDALF_POWERSHELL_PATH],
        options={
            "gandalf": True,
            "analysis": True,
            "elastic": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/"],
        tags=["gandalf", "powershell", "windows", "elastic"],
        estimated_duration_minutes=50,
    ),
    TestCase(
        name="gandalf_powershell_splunk",
        description="Gandalf mode - PowerShell collection with Splunk export",
        images=[GANDALF_POWERSHELL_PATH],
        options={
            "gandalf": True,
            "analysis": True,
            "splunk": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/"],
        tags=["gandalf", "powershell", "windows", "splunk"],
        estimated_duration_minutes=50,
    ),
    TestCase(
        name="gandalf_python_analysis",
        description="Gandalf mode - Python collection with Automated Analysis",
        images=[GANDALF_PYTHON_PATH],
        options={
            "gandalf": True,
            "analysis": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/"],
        tags=["gandalf", "python", "cross-platform", "analysis"],
        estimated_duration_minutes=45,
    ),
    TestCase(
        name="gandalf_python_basic",
        description="Gandalf mode - Process Python-collected artefacts (cross-platform)",
        images=[GANDALF_PYTHON_PATH],
        options={
            "gandalf": True,
        },
        expected_outputs=["artefacts/cooked/"],
        tags=["gandalf", "python", "cross-platform"],
        estimated_duration_minutes=20,
    ),
    TestCase(
        name="gandalf_python_full_siem",
        description="Gandalf mode - Python collection with full SIEM export",
        images=[GANDALF_PYTHON_PATH],
        options={
            "gandalf": True,
            "analysis": True,
            "splunk": True,
            "elastic": True,
            "navigator": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/"],
        tags=["gandalf", "python", "cross-platform", "splunk", "elastic", "navigator"],
        estimated_duration_minutes=60,
    ),
]


# =============================================================================
# TEST CASES: CLOUD-HOSTED IMAGE ANALYSIS
# =============================================================================

CLOUD_ANALYSIS_TESTS = [
    TestCase(
        name="cloud_aws_disk_analysis",
        description="Cloud analysis - AWS S3 hosted disk image with analysis",
        images=[AWS_S3_DISK_IMAGE],
        options={
            "analysis": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/"],
        tags=["cloud", "aws", "s3", "disk", "analysis"],
        estimated_duration_minutes=90,
    ),
    TestCase(
        name="cloud_aws_disk_basic",
        description="Cloud analysis - AWS S3 hosted disk image (basic processing)",
        images=[AWS_S3_DISK_IMAGE],
        options={},
        expected_outputs=["artefacts/cooked/", "artefacts/raw/"],
        tags=["cloud", "aws", "s3", "disk"],
        estimated_duration_minutes=60,
    ),
    TestCase(
        name="cloud_aws_disk_memory_combined",
        description="Cloud analysis - AWS S3 hosted disk + memory images",
        images=[AWS_S3_DISK_IMAGE, AWS_S3_MEMORY_IMAGE],
        options={
            "analysis": True,
            "memory": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/"],
        tags=["cloud", "aws", "s3", "disk", "memory", "exhaustive"],
        estimated_duration_minutes=180,
    ),
    TestCase(
        name="cloud_aws_full_pipeline",
        description="Cloud analysis - AWS S3 with full SIEM pipeline",
        images=[AWS_S3_DISK_IMAGE, AWS_S3_MEMORY_IMAGE],
        options={
            "analysis": True,
            "memory": True,
            "timeline": True,
            "splunk": True,
            "elastic": True,
            "navigator": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/", "timeline/"],
        tags=["cloud", "aws", "s3", "exhaustive", "siem", "very_slow"],
        estimated_duration_minutes=300,
    ),
    TestCase(
        name="cloud_aws_memory",
        description="Cloud analysis - AWS S3 hosted memory image",
        images=[AWS_S3_MEMORY_IMAGE],
        options={
            "memory": True,
        },
        expected_outputs=["artefacts/cooked/"],
        tags=["cloud", "aws", "s3", "memory"],
        estimated_duration_minutes=120,
    ),
    TestCase(
        name="cloud_azure_disk_analysis",
        description="Cloud analysis - Azure Blob hosted disk image with analysis",
        images=[AZURE_BLOB_DISK_IMAGE],
        options={
            "analysis": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/"],
        tags=["cloud", "azure", "blob", "disk", "analysis"],
        estimated_duration_minutes=90,
    ),
    TestCase(
        name="cloud_azure_disk_basic",
        description="Cloud analysis - Azure Blob hosted disk image (basic processing)",
        images=[AZURE_BLOB_DISK_IMAGE],
        options={},
        expected_outputs=["artefacts/cooked/", "artefacts/raw/"],
        tags=["cloud", "azure", "blob", "disk"],
        estimated_duration_minutes=60,
    ),
    TestCase(
        name="cloud_azure_disk_mem",
        description="Cloud analysis - Azure Blob hosted disk + memory images",
        images=[AZURE_BLOB_DISK_IMAGE, AZURE_BLOB_MEMORY_IMAGE],
        options={
            "analysis": True,
            "memory": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/"],
        tags=["cloud", "azure", "blob", "disk", "memory", "exhaustive"],
        estimated_duration_minutes=180,
    ),
    TestCase(
        name="cloud_azure_full_pipeline",
        description="Cloud analysis - Azure Blob with full SIEM pipeline",
        images=[AZURE_BLOB_DISK_IMAGE, AZURE_BLOB_MEMORY_IMAGE],
        options={
            "analysis": True,
            "memory": True,
            "timeline": True,
            "splunk": True,
            "elastic": True,
            "navigator": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/", "timeline/"],
        tags=["cloud", "azure", "blob", "exhaustive", "siem", "very_slow"],
        estimated_duration_minutes=300,
    ),
    TestCase(
        name="cloud_azure_memory",
        description="Cloud analysis - Azure Blob hosted memory image",
        images=[AZURE_BLOB_MEMORY_IMAGE],
        options={
            "memory": True,
        },
        expected_outputs=["artefacts/cooked/"],
        tags=["cloud", "azure", "blob", "memory"],
        estimated_duration_minutes=120,
    ),
    TestCase(
        name="cloud_multi_aws_azure",
        description="Cloud analysis - Mixed AWS and Azure hosted images",
        images=[AWS_S3_DISK_IMAGE, AZURE_BLOB_DISK_IMAGE],
        options={
            "analysis": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/"],
        tags=["cloud", "aws", "azure", "multi-cloud", "exhaustive"],
        estimated_duration_minutes=150,
    ),
]


# =============================================================================
# TEST CASES: MORDOR SECURITY DATASET INTEGRATION
# =============================================================================

# Mordor datasets (https://github.com/OTRF/mordor) provide pre-recorded
# security events for testing detection capabilities
MORDOR_TESTS = [
    TestCase(
        name="mordor_apt29_day1",
        description="Mordor - APT29 Day 1 simulation dataset analysis",
        images=[f"{MORDOR_DATASETS_PATH}/apt29/day1/acquisitions/"],
        options={
            "gandalf": True,
            "analysis": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/"],
        tags=["mordor", "apt29", "apt", "simulation", "gandalf"],
        estimated_duration_minutes=60,
    ),
    TestCase(
        name="mordor_apt29_day2",
        description="Mordor - APT29 Day 2 simulation dataset analysis",
        images=[f"{MORDOR_DATASETS_PATH}/apt29/day2/acquisitions/"],
        options={
            "gandalf": True,
            "analysis": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/"],
        tags=["mordor", "apt29", "apt", "simulation", "gandalf"],
        estimated_duration_minutes=60,
    ),
    TestCase(
        name="mordor_apt29_full",
        description="Mordor - APT29 full simulation (Day 1 + Day 2) with SIEM",
        images=[f"{MORDOR_DATASETS_PATH}/apt29/day1/acquisitions/", f"{MORDOR_DATASETS_PATH}/apt29/day2/acquisitions/"],
        options={
            "gandalf": True,
            "analysis": True,
            "splunk": True,
            "elastic": True,
            "navigator": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/"],
        tags=["mordor", "apt29", "apt", "simulation", "gandalf", "siem", "exhaustive"],
        estimated_duration_minutes=120,
    ),
    TestCase(
        name="mordor_atomic_cred_access",
        description="Mordor - Atomic Red Team credential access techniques",
        images=[f"{MORDOR_DATASETS_PATH}/atomic/credential_access/acquisitions/"],
        options={
            "gandalf": True,
            "analysis": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/"],
        tags=["mordor", "atomic", "credential_access", "gandalf"],
        estimated_duration_minutes=45,
    ),
    TestCase(
        name="mordor_atomic_defense_evasion",
        description="Mordor - Atomic Red Team defense evasion techniques",
        images=[f"{MORDOR_DATASETS_PATH}/atomic/defense_evasion/acquisitions/"],
        options={
            "gandalf": True,
            "analysis": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/"],
        tags=["mordor", "atomic", "defense_evasion", "gandalf"],
        estimated_duration_minutes=45,
    ),
    TestCase(
        name="mordor_atomic_lateral_movement",
        description="Mordor - Atomic Red Team lateral movement techniques",
        images=[f"{MORDOR_DATASETS_PATH}/atomic/lateral_movement/acquisitions/"],
        options={
            "gandalf": True,
            "analysis": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/"],
        tags=["mordor", "atomic", "lateral_movement", "gandalf"],
        estimated_duration_minutes=45,
    ),
    TestCase(
        name="mordor_atomic_persistence",
        description="Mordor - Atomic Red Team persistence techniques",
        images=[f"{MORDOR_DATASETS_PATH}/atomic/persistence/acquisitions/"],
        options={
            "gandalf": True,
            "analysis": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/"],
        tags=["mordor", "atomic", "persistence", "gandalf"],
        estimated_duration_minutes=45,
    ),
    TestCase(
        name="mordor_full_detection_test",
        description="Mordor - Full detection capability test with all SIEM outputs",
        images=[
            f"{MORDOR_DATASETS_PATH}/apt29/day1/acquisitions/",
            f"{MORDOR_DATASETS_PATH}/atomic/credential_access/acquisitions/",
        ],
        options={
            "gandalf": True,
            "analysis": True,
            "yara_dir": SAMPLE_YARA_DIR,
            "keywords_file": SAMPLE_KEYWORDS_FILE,
            "splunk": True,
            "elastic": True,
            "navigator": True,
        },
        expected_outputs=["artefacts/cooked/", "analysis/"],
        tags=["mordor", "exhaustive", "detection", "siem", "gandalf", "very_slow"],
        estimated_duration_minutes=180,
    ),
    # No malware/* tests: OTRF Security-Datasets doesn't publish Cobalt Strike, Emotet or
    # TrickBot datasets (P11). Lab recordings (./lab/lab.sh mordor-dataset) can stand in.
]


# =============================================================================
# ALL TEST CASES
# =============================================================================

ALL_TESTS = (
    WINDOWS_TESTS
    + MEMORY_TESTS
    + LINUX_TESTS
    + MACOS_TESTS
    + MULTI_IMAGE_TESTS
    + GANDALF_TESTS
    + CLOUD_ANALYSIS_TESTS
    + MORDOR_TESTS
)

TEST_LOOKUP = {test.name: test for test in ALL_TESTS}


# =============================================================================
# TEST RUNNER
# =============================================================================


def list_tests(filter_tags: Optional[List[str]] = None):
    """List all available test cases."""
    print("\n" + "=" * 80)
    print("RIVENDELL IMAGE COMBINATION TESTS")
    print("=" * 80 + "\n")

    for test in ALL_TESTS:
        if filter_tags:
            if not any(tag in test.tags for tag in filter_tags):
                continue

        tags_str = ", ".join(test.tags)
        print(f"  {test.name:<30} [{tags_str}]")
        print(f"      {test.description}")
        print(f"      Images: {', '.join(test.images) or 'None (Gandalf mode)'}")
        print(f"      Est. duration: {test.estimated_duration_minutes} min")
        print()

    print("=" * 80)
    print(f"Total: {len(ALL_TESTS)} test cases")
    print("\nTags: " + ", ".join(sorted(set(tag for test in ALL_TESTS for tag in test.tags))))
    print()


def generate_job_json(test: TestCase, output_dir: str):
    """Generate a job JSON file for the Web UI."""
    job_data = {
        "case_number": f"TEST_{test.name}"[:30],
        "source_paths": [os.path.join(TEST_IMAGES_PATH, img) for img in test.images],
        "destination_path": os.path.join(TEST_OUTPUT_PATH, test.name),
        "options": test.to_job_options(),
        "metadata": {
            "test_name": test.name,
            "description": test.description,
            "tags": test.tags,
            "estimated_duration_minutes": test.estimated_duration_minutes,
            "generated_at": datetime.now().isoformat(),
        },
    }

    output_file = os.path.join(output_dir, f"{test.name}.json")
    with open(output_file, "w") as f:
        json.dump(job_data, f, indent=2)

    return output_file


def generate_all_jobs(output_dir: str):
    """Generate job JSON files for all test cases."""
    os.makedirs(output_dir, exist_ok=True)

    print(f"\nGenerating job files in: {output_dir}\n")

    for test in ALL_TESTS:
        output_file = generate_job_json(test, output_dir)
        print(f"  Created: {output_file}")

    print(f"\nGenerated {len(ALL_TESTS)} job files")


def validate_test_images():
    """Check if test images exist."""
    print(f"\nChecking test images in: {TEST_IMAGES_PATH}\n")

    all_images = set()
    for test in ALL_TESTS:
        all_images.update(test.images)

    missing = []
    found = []

    for img in all_images:
        path = os.path.join(TEST_IMAGES_PATH, img)
        if os.path.exists(path):
            size_gb = os.path.getsize(path) / (1024**3)
            found.append((img, size_gb))
        else:
            missing.append(img)

    print("Found images:")
    for img, size in found:
        print(f"  [OK] {img} ({size:.2f} GB)")

    if missing:
        print("\nMissing images:")
        for img in missing:
            print(f"  [MISSING] {img}")

    print(f"\nTotal: {len(found)} found, {len(missing)} missing")

    return len(missing) == 0


def run_test(test: TestCase, api_url: str, wait: bool = False, yes: bool = False, retries: int = 3) -> dict:
    """Submit a test job via the API."""
    if not HAS_REQUESTS:
        print("ERROR: 'requests' library required. Install with: pip install requests")
        sys.exit(1)

    # Copy samples to container if test needs keywords or yara
    if test.options.get("keywords_file") or test.options.get("yara_dir"):
        copy_samples_to_container()

    # Build job payload
    destination_path = os.path.join(TEST_OUTPUT_PATH, test.name)
    job_data = {
        "case_number": f"TEST_{test.name}"[:30],
        "source_paths": [os.path.join(TEST_IMAGES_PATH, img) for img in test.images],
        "destination_path": destination_path,
        "options": test.to_job_options(),
    }

    # Check if output directory already exists
    if os.path.exists(destination_path):
        print(f"\n  Warning: Output directory already exists: {destination_path}")
        if yes:
            print("  Auto-confirming overwrite (-y flag).")
            confirm = 'y'
        else:
            confirm = input("  Overwrite existing directory? [Y/n] ").strip().lower()
        if confirm == 'n':
            print("  Aborted.")
            return {"status": "aborted", "reason": "directory_exists"}
        # Set force_overwrite option to remove existing directory
        job_data["options"]["force_overwrite"] = True
        print("  Will overwrite existing directory.")

    start_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"  Description: {test.description}")
    print(f"  Images: {', '.join(test.images) or 'None (Gandalf mode)'}")
    print(f"  API URL: {api_url}")

    last_error = None
    for attempt in range(retries):
        try:
            response = requests.post(
                f"{api_url}/api/jobs",
                json=job_data,
                headers={"Content-Type": "application/json"},
                timeout=120,  # Increased timeout to 2 minutes
            )
            response.raise_for_status()
            job = response.json()
            print(f"  Job ID: {job['id']}")

            if wait:
                # Use at least 90 minutes timeout, or test estimate if longer
                timeout = max(90, test.estimated_duration_minutes)
                return wait_for_job(job["id"], api_url, timeout)

            return job

        except requests.exceptions.ConnectionError as e:
            last_error = e
            if attempt < retries - 1:
                print(f"  Connection error (attempt {attempt + 1}/{retries}), retrying in 5s...")
                time.sleep(5)
            else:
                print(f"  ERROR: Could not connect to API at {api_url}")
                print("  Make sure the Rivendell backend is running (docker-compose up)")
                return {"status": "connection_error", "error": str(e)}

        except requests.exceptions.Timeout as e:
            last_error = e
            if attempt < retries - 1:
                print(f"  Timeout (attempt {attempt + 1}/{retries}), retrying in 10s...")
                time.sleep(10)
            else:
                print(f"  ERROR: Request timed out after {retries} attempts")
                return {"status": "timeout", "error": str(e)}

        except requests.exceptions.HTTPError as e:
            print(f"  ERROR: API returned error: {e}")
            if hasattr(e, "response") and e.response is not None:
                try:
                    print(f"  Details: {e.response.json()}")
                except Exception:
                    print(f"  Response: {e.response.text}")
            return {"status": "http_error", "error": str(e)}

    return {"status": "failed", "error": str(last_error)}


def wait_for_job(job_id: str, api_url: str, timeout_minutes: int = 60) -> dict:
    """Wait for a job to complete."""
    print(f"\n  Waiting for job to complete (timeout: {timeout_minutes} min)...")

    start_time = time.time()
    timeout_seconds = timeout_minutes * 60
    last_progress = -1

    while True:
        elapsed = time.time() - start_time
        if elapsed > timeout_seconds:
            print(f"\n  TIMEOUT: Job did not complete within {timeout_minutes} minutes")
            return {"status": "timeout", "id": job_id}

        try:
            response = requests.get(f"{api_url}/api/jobs/{job_id}", timeout=10)
            response.raise_for_status()
            job = response.json()

            status = job.get("status", "unknown")
            progress = job.get("progress", 0)

            if progress != last_progress:
                print(f"  [{int(elapsed)}s] Status: {status}, Progress: {progress}%")
                last_progress = progress

            if status in ("completed", "failed", "cancelled"):
                elapsed_minutes = int(elapsed / 60)
                elapsed_seconds = int(elapsed % 60)

                print(f"\n  Duration: {elapsed_minutes}m {elapsed_seconds}s")
                if status == "failed":
                    print(f"  Error: {job.get('error', 'Unknown error')}")
                return job

            time.sleep(10)  # Poll every 10 seconds

        except requests.exceptions.RequestException as e:
            print(f"  Warning: API error during polling: {e}")
            time.sleep(10)


def queue_tests(test_names: List[str], api_url: str, yes: bool = False):
    """Queue multiple tests for sequential execution. Returns immediately."""
    if not HAS_REQUESTS:
        print("ERROR: 'requests' library required. Install with: pip install requests")
        sys.exit(1)

    # Validate all test names first
    valid_tests = []
    invalid_names = []
    for name in test_names:
        if name in TEST_LOOKUP:
            valid_tests.append(TEST_LOOKUP[name])
        else:
            invalid_names.append(name)

    if invalid_names:
        print(f"ERROR: Unknown test(s): {', '.join(invalid_names)}")
        print("Use --list to see available tests")
        sys.exit(1)

    if not valid_tests:
        print("ERROR: No tests specified")
        sys.exit(1)

    # Check for existing output directories
    existing_dirs = []
    for test in valid_tests:
        dest_path = os.path.join(TEST_OUTPUT_PATH, test.name)
        if os.path.exists(dest_path):
            existing_dirs.append((test.name, dest_path))

    force_overwrite = False
    if existing_dirs:
        print(f"\nWarning: {len(existing_dirs)} output director(y/ies) already exist:")
        for name, path in existing_dirs:
            print(f"  - {name}: {path}")
        if yes:
            print("\nAuto-confirming overwrite (-y flag).")
            confirm = 'y'
        else:
            confirm = input("\nOverwrite existing directories? [Y/n] ").strip().lower()
        if confirm == 'n':
            print("Aborted.")
            return []
        force_overwrite = True
        print("Will overwrite existing directories.\n")

    total_duration = sum(t.estimated_duration_minutes for t in valid_tests)
    print(f"\nQueueing {len(valid_tests)} test(s)...")
    print(f"Estimated total duration: {total_duration} minutes ({total_duration / 60:.1f} hours)\n")

    results = []
    for test in valid_tests:
        # Build job payload
        destination_path = os.path.join(TEST_OUTPUT_PATH, test.name)
        job_data = {
            "case_number": f"TEST_{test.name}"[:30],
            "source_paths": [os.path.join(TEST_IMAGES_PATH, img) for img in test.images],
            "destination_path": destination_path,
            "options": test.to_job_options(),
        }

        # Set force_overwrite if directory exists and user confirmed
        if force_overwrite and os.path.exists(destination_path):
            job_data["options"]["force_overwrite"] = True

        try:
            response = requests.post(
                f"{api_url}/api/jobs",
                json=job_data,
                headers={"Content-Type": "application/json"},
                timeout=30,
            )
            response.raise_for_status()
            job = response.json()
            results.append({
                "test": test.name,
                "job_id": job["id"],
                "status": "queued",
            })
            print(f"  [QUEUED] {test.name:<30} Job ID: {job['id']}")

        except requests.exceptions.RequestException as e:
            results.append({
                "test": test.name,
                "job_id": None,
                "status": "failed",
                "error": str(e),
            })
            print(f"  [FAILED] {test.name:<30} Error: {e}")

    # Print summary
    queued = sum(1 for r in results if r["status"] == "queued")
    failed = sum(1 for r in results if r["status"] == "failed")

    print(f"\n{'=' * 60}")
    print(f"QUEUE SUMMARY: {queued} queued, {failed} failed")
    print(f"{'=' * 60}")

    if queued > 0:
        print("\nJobs will be processed by Celery worker.")
        print("Monitor progress at: http://localhost:5687")
        print("\nCheck queue status:")
        print("  docker logs -f rivendell-celery-worker")

    return results


def show_job_status(api_url: str):
    """Show status of all jobs from the API."""
    if not HAS_REQUESTS:
        print("ERROR: 'requests' library required. Install with: pip install requests")
        sys.exit(1)

    try:
        response = requests.get(f"{api_url}/api/jobs", timeout=10)
        response.raise_for_status()
        data = response.json()
        jobs = data.get("jobs", []) if isinstance(data, dict) else data
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Could not connect to API at {api_url}")
        print(f"  {e}")
        sys.exit(1)

    if not jobs:
        print("\nNo jobs found.")
        return

    # Group jobs by status
    pending = [j for j in jobs if j.get("status") == "pending"]
    running = [j for j in jobs if j.get("status") == "running"]
    paused = [j for j in jobs if j.get("status") == "paused"]
    completed = [j for j in jobs if j.get("status") == "completed"]
    failed = [j for j in jobs if j.get("status") == "failed"]

    print(f"\n{'='*70}")
    print(f"  JOB STATUS SUMMARY")
    print(f"{'='*70}")
    print(f"  Running: {len(running)}  |  Paused: {len(paused)}  |  Pending: {len(pending)}  |  Completed: {len(completed)}  |  Failed: {len(failed)}")
    print(f"{'='*70}\n")

    def format_duration(job):
        if job.get("duration"):
            mins = job["duration"] // 60
            secs = job["duration"] % 60
            if mins > 0:
                return f"{mins}m {secs}s"
            return f"{secs}s"
        return "-"

    def format_progress(job):
        progress = job.get("progress", 0)
        return f"{progress}%"

    # Show running jobs first
    if running:
        print("  RUNNING:")
        for job in running:
            case = job.get("case_number", "Unknown")
            progress = format_progress(job)
            print(f"    🔄 {case:<35} {progress:>6}  {job.get('id', '')}")
        print()

    if paused:
        print("  PAUSED:")
        for job in paused:
            case = job.get("case_number", "Unknown")
            progress = format_progress(job)
            print(f"    ⏸️  {case:<35} {progress:>6}  {job.get('id', '')}")
        print()

    # Show pending jobs
    if pending:
        print("  PENDING:")
        for job in pending:
            case = job.get("case_number", "Unknown")
            print(f"    ⏳ {case:<35}")
        print()

    # Show completed jobs (last 10)
    if completed:
        print("  COMPLETED (last 10):")
        for job in completed[-10:]:
            case = job.get("case_number", "Unknown")
            duration = format_duration(job)
            print(f"    ✅ {case:<35} {duration:>10}")
        print()

    # Show failed jobs
    if failed:
        print("  FAILED:")
        for job in failed:
            case = job.get("case_number", "Unknown")
            duration = format_duration(job)
            print(f"    ❌ {case:<35} {duration:>10}")
        print()


def run_tests_by_tags(tags: List[str], api_url: str, wait: bool = False, yes: bool = False):
    """Run all tests matching the given tags."""
    matching_tests = [test for test in ALL_TESTS if any(tag in test.tags for tag in tags)]

    if not matching_tests:
        print(f"No tests found matching tags: {', '.join(tags)}")
        return

    print(f"\nFound {len(matching_tests)} tests matching tags: {', '.join(tags)}")

    total_duration = sum(t.estimated_duration_minutes for t in matching_tests)
    print(f"Total estimated duration: {total_duration} minutes ({total_duration / 60:.1f} hours)")

    if yes:
        print("\nAuto-confirming (-y flag).")
        confirm = "y"
    else:
        confirm = input("\nProceed with running these tests? [y/N] ")
    if confirm.lower() != "y":
        print("Aborted.")
        return

    results = []
    for test in matching_tests:
        result = run_test(test, api_url, wait=wait, yes=yes)
        results.append({"test": test.name, "result": result})

    print("\n" + "=" * 60)
    print("TEST RUN SUMMARY")
    print("=" * 60)
    for r in results:
        result = r["result"] or {}
        status = result.get("status", "submitted")
        print(f"  {r['test']:<30} {status}")

    return results


def _resolve_output_dir(job: dict) -> Optional[str]:
    """Return the output directory for a job, or None if not set."""
    result = job.get("result") or {}
    return result.get("output_directory") or job.get("destination_path")


def delete_all_jobs(api_url: str):
    """Delete all completed, failed, and cancelled jobs from the DB and purge their output dirs."""
    if not HAS_REQUESTS:
        print("ERROR: 'requests' library required. Install with: pip install requests")
        sys.exit(1)

    try:
        response = requests.get(f"{api_url}/api/jobs", timeout=30)
        response.raise_for_status()
        jobs = response.json().get("jobs", [])

        eligible = [
            job for job in jobs
            if job.get("status", "").lower() in ("completed", "failed", "cancelled")
        ]

        if not eligible:
            print("No completed/failed/cancelled jobs to delete.")
            return

        print(f"Found {len(eligible)} jobs to delete...")

        # Remove output directories from disk first
        for job in eligible:
            output_dir = _resolve_output_dir(job)
            if output_dir and os.path.isdir(output_dir):
                print(f"  Purging {output_dir}")
                shutil.rmtree(output_dir, ignore_errors=True)

        # Remove DB records
        to_delete = [job["id"] for job in eligible]
        response = requests.post(
            f"{api_url}/api/jobs/bulk/delete",
            json=to_delete,
            headers={"Content-Type": "application/json"},
            timeout=60,
        )
        response.raise_for_status()
        result = response.json()

        deleted = sum(1 for r in result.get("results", []) if r.get("success"))
        print(f"Successfully deleted {deleted}/{len(to_delete)} jobs.")

        for r in result.get("results", []):
            if not r.get("success"):
                print(f"  Failed to delete {r.get('job_id')}: {r.get('error')}")

    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to delete jobs: {e}")
        sys.exit(1)


def rerun_failed_jobs(api_url: str, wait: bool = False):
    """Restart all failed jobs."""
    if not HAS_REQUESTS:
        print("ERROR: 'requests' library required. Install with: pip install requests")
        sys.exit(1)

    try:
        response = requests.get(f"{api_url}/api/jobs", timeout=30)
        response.raise_for_status()
        jobs = response.json().get("jobs", [])

        to_restart = [
            job["id"] for job in jobs
            if job.get("status", "").lower() == "failed"
        ]

        if not to_restart:
            print("No failed jobs to restart.")
            return

        print(f"Found {len(to_restart)} failed jobs to restart...")
        # fresh: the failed run's partial output is removed first, not run over
        response = requests.post(
            f"{api_url}/api/jobs/bulk/restart",
            params={"fresh": "true"},
            json=to_restart,
            headers={"Content-Type": "application/json"},
            timeout=60,
        )
        response.raise_for_status()
        result = response.json()

        restarted = sum(1 for r in result.get("results", []) if r.get("success"))
        print(f"Successfully restarted {restarted}/{len(to_restart)} jobs.")

        for r in result.get("results", []):
            if not r.get("success"):
                print(f"  Failed to restart {r.get('job_id')}: {r.get('error')}")

        if wait and restarted > 0:
            print("\nWaiting for restarted jobs to complete...")
            _wait_for_jobs(to_restart, api_url)

    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to restart jobs: {e}")
        sys.exit(1)


def _wait_for_jobs(job_ids: list, api_url: str):
    """Poll until all specified jobs reach a terminal state."""
    import time
    terminal = {"completed", "failed", "cancelled", "timeout"}
    pending = set(job_ids)
    while pending:
        time.sleep(10)
        try:
            response = requests.get(f"{api_url}/api/jobs", timeout=30)
            response.raise_for_status()
            jobs = {j["id"]: j for j in response.json().get("jobs", [])}
        except requests.exceptions.RequestException:
            continue
        done = {jid for jid in pending if jobs.get(jid, {}).get("status", "").lower() in terminal}
        for jid in done:
            status = jobs[jid].get("status", "?")
            print(f"  {jid}: {status}")
        pending -= done


def cancel_all_jobs(api_url: str):
    """Cancel all running and pending jobs."""
    if not HAS_REQUESTS:
        print("ERROR: 'requests' library required. Install with: pip install requests")
        sys.exit(1)

    try:
        # Get all jobs
        response = requests.get(f"{api_url}/api/jobs", timeout=30)
        response.raise_for_status()
        jobs = response.json().get("jobs", [])

        # Filter for running and pending jobs
        to_cancel = [
            job["id"] for job in jobs
            if job.get("status", "").lower() in ("running", "paused", "pending")
        ]

        if not to_cancel:
            print("No running or pending jobs to cancel.")
            return

        print(f"Found {len(to_cancel)} jobs to cancel...")

        # Cancel all jobs
        response = requests.post(
            f"{api_url}/api/jobs/bulk/cancel",
            json=to_cancel,
            headers={"Content-Type": "application/json"},
            timeout=60,
        )
        response.raise_for_status()
        result = response.json()

        cancelled = sum(1 for r in result.get("results", []) if r.get("success"))
        print(f"Successfully cancelled {cancelled}/{len(to_cancel)} jobs.")

        # Show any failures
        for r in result.get("results", []):
            if not r.get("success"):
                print(f"  Failed to cancel {r.get('job_id')}: {r.get('error')}")

    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to cancel jobs: {e}")
        sys.exit(1)


def cancel_jobs(api_url: str, job_ids: List[str]):
    """Cancel specific jobs by ID, leaving every other job untouched."""
    if not HAS_REQUESTS:
        print("ERROR: 'requests' library required. Install with: pip install requests")
        sys.exit(1)

    failed = 0
    for job_id in job_ids:
        try:
            response = requests.post(f"{api_url}/api/jobs/{job_id}/cancel", timeout=30)
            if response.status_code == 400:
                # Jobs parked on a sudo prompt only accept /cancel-sudo
                response = requests.post(f"{api_url}/api/jobs/{job_id}/cancel-sudo", timeout=30)
            print(f"  {job_id}: HTTP {response.status_code}")
            if not response.ok:
                failed += 1
        except requests.exceptions.RequestException as e:
            print(f"  {job_id}: ERROR {e}")
            failed += 1

    print(f"Cancelled {len(job_ids) - failed}/{len(job_ids)} jobs.")
    if failed:
        sys.exit(1)


def signal_jobs(api_url: str, job_ids: List[str], action: str):
    """Pause or resume specific jobs by ID."""
    if not HAS_REQUESTS:
        print("ERROR: 'requests' library required. Install with: pip install requests")
        sys.exit(1)

    failed = 0
    for job_id in job_ids:
        try:
            response = requests.post(f"{api_url}/api/jobs/{job_id}/{action}", timeout=30)
            detail = "" if response.ok else f" - {response.json().get('detail', response.text)}"
            print(f"  {job_id}: HTTP {response.status_code}{detail}")
            if not response.ok:
                failed += 1
        except (requests.exceptions.RequestException, ValueError) as e:
            print(f"  {job_id}: ERROR {e}")
            failed += 1

    verb = "Paused" if action == "pause" else "Resumed"
    print(f"{verb} {len(job_ids) - failed}/{len(job_ids)} jobs.")
    if failed:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Rivendell Image Combination Tests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument("--list", "-l", action="store_true", help="List all test cases")
    parser.add_argument("--tags", "-t", nargs="+", help="Filter tests by tags")
    parser.add_argument(
        "--generate-jobs", "-g", action="store_true", help="Generate job JSON files for Web UI"
    )
    parser.add_argument(
        "--output-dir", "-o", default="tests/jobs", help="Output directory for generated jobs"
    )
    parser.add_argument(
        "--validate", "-v", action="store_true", help="Validate that test images exist"
    )
    parser.add_argument(
        "--status", action="store_true", help="Show status of all jobs (running, pending, completed, failed)"
    )
    parser.add_argument(
        "--show", "-s", metavar="NAME", help="Show details for a specific test case"
    )
    parser.add_argument(
        "--run", "-r", metavar="NAME", help="Run a specific test by name (submits job via API)"
    )
    parser.add_argument(
        "--queue", "-q", nargs="+", metavar="NAME",
        help="Queue multiple tests (e.g., --queue win_brisk win_archive win_keywords)"
    )
    parser.add_argument(
        "--run-tags", nargs="+", metavar="TAG", help="Run all tests matching the given tags"
    )
    parser.add_argument(
        "--wait", "-w", action="store_true", help="Wait for job to complete when using --run"
    )
    parser.add_argument(
        "--yes", "-y", action="store_true", help="Auto-confirm overwrite of existing directories"
    )
    parser.add_argument(
        "--cancel-all", action="store_true", help="Cancel all running and pending jobs"
    )
    parser.add_argument(
        "--cancel", nargs="+", metavar="JOB_ID", help="Cancel only the given job IDs"
    )
    parser.add_argument(
        "--pause", nargs="+", metavar="JOB_ID", help="Pause the given running jobs (SIGSTOP)"
    )
    parser.add_argument(
        "--resume", nargs="+", metavar="JOB_ID", help="Resume the given paused jobs (SIGCONT)"
    )
    parser.add_argument(
        "--delete-all", action="store_true", help="Delete all completed/failed/cancelled jobs"
    )
    parser.add_argument(
        "--rerun-failed", action="store_true", help="Restart all failed jobs"
    )
    parser.add_argument("--api-url", default=API_URL, help=f"API URL (default: {API_URL})")

    args = parser.parse_args()

    if args.cancel_all:
        cancel_all_jobs(args.api_url)
    elif args.cancel:
        cancel_jobs(args.api_url, args.cancel)
    elif args.pause:
        signal_jobs(args.api_url, args.pause, "pause")
    elif args.resume:
        signal_jobs(args.api_url, args.resume, "resume")
    elif args.delete_all:
        delete_all_jobs(args.api_url)
    elif args.rerun_failed:
        rerun_failed_jobs(args.api_url, wait=args.wait)
    elif args.list:
        list_tests(args.tags)
    elif args.generate_jobs:
        generate_all_jobs(args.output_dir)
    elif args.validate:
        validate_test_images()
    elif args.status:
        show_job_status(args.api_url)
    elif args.show:
        if args.show in TEST_LOOKUP:
            test = TEST_LOOKUP[args.show]
            print(f"\nTest: {test.name}")
            print(f"Description: {test.description}")
            print(f"Images: {test.images}")
            print(f"Options: {json.dumps(test.options, indent=2)}")
            print(f"Expected outputs: {test.expected_outputs}")
            print(f"Tags: {test.tags}")
            print(f"Est. duration: {test.estimated_duration_minutes} min")
        else:
            print(f"Test '{args.show}' not found")
            sys.exit(1)
    elif args.run:
        if args.run in TEST_LOOKUP:
            test = TEST_LOOKUP[args.run]
            result = run_test(test, args.api_url, wait=args.wait, yes=args.yes)
            # Exit with non-zero code if test failed
            if result and result.get("status") in ("failed", "timeout", "connection_error", "http_error"):
                sys.exit(1)
        else:
            print(f"Test '{args.run}' not found")
            print("Use --list to see available tests")
            sys.exit(1)
    elif args.queue:
        queue_tests(args.queue, args.api_url, yes=args.yes)
    elif args.run_tags:
        _FAILURE_STATUSES = {"failed", "timeout", "connection_error", "http_error"}
        tag_results = run_tests_by_tags(args.run_tags, args.api_url, wait=args.wait, yes=args.yes)
        if tag_results and any(
            (r.get("result") or {}).get("status") in _FAILURE_STATUSES
            for r in tag_results
        ):
            sys.exit(1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
