#!/usr/bin/env python3
"""
Artifact Models and Definitions

Centralized artifact type definitions, collection path mappings,
and ATT&CK technique associations for the Dernvale DF Acceleration Suite.

This module provides a unified interface for:
- Artifact type enumeration
- Collection path definitions by platform
- ATT&CK technique mappings
- Severity classifications

Author: Dernvale DF Acceleration Suite
Version: 2.1.0
"""

from enum import Enum
from typing import Dict, List, Set, Optional
from dataclasses import dataclass


class Platform(Enum):
    """Supported operating system platforms."""

    WINDOWS = "Windows"
    MACOS = "macOS"
    LINUX = "Linux"
    UNKNOWN = "Unknown"


class ArtifactType(Enum):
    """Enumeration of all supported artifact types."""

    # Windows Artifacts
    WMI_EVENT_CONSUMER = "wmi_event_consumer"
    WMI_EVENT_FILTER = "wmi_event_filter"
    WMI_BINDING = "wmi_binding"
    WMI_NAMESPACE = "wmi_namespace"
    POWERSHELL_HISTORY = "powershell_history"
    REGISTRY_KEY = "registry_key"
    EVENT_LOG = "event_log"
    PREFETCH = "prefetch"
    MFT = "mft"
    USN_JOURNAL = "usn_journal"

    # macOS Artifacts
    UNIFIED_LOG = "unified_log"
    COREDUET_APP_USAGE = "coreduet_app_usage"
    COREDUET_APP_INSTALL = "coreduet_app_install"
    TCC_PERMISSION = "tcc_permission"
    FSEVENT = "fsevent"
    QUARANTINE_EVENT = "quarantine_event"
    PLIST = "plist"
    LAUNCH_AGENT = "launch_agent"
    LAUNCH_DAEMON = "launch_daemon"

    # Linux Artifacts
    SYSTEMD_JOURNAL = "systemd_journal"
    AUDIT_EXECVE = "audit_execve"
    AUDIT_USER = "audit_user"
    AUDIT_AUTH = "audit_auth"
    AUDIT_FILE = "audit_file"
    AUDIT_NETWORK = "audit_network"
    DOCKER_CONTAINER = "docker_container"
    DOCKER_IMAGE = "docker_image"
    DOCKER_VOLUME = "docker_volume"
    BASH_HISTORY = "bash_history"
    ZSH_HISTORY = "zsh_history"
    PYTHON_HISTORY = "python_history"
    PACKAGE_INSTALL = "package_install"

    # Common Artifacts
    BROWSER_HISTORY = "browser_history"
    NETWORK_CONNECTION = "network_connection"
    PROCESS = "process"
    USER_ACCOUNT = "user_account"
    SCHEDULED_TASK = "scheduled_task"
    SERVICE = "service"
    FILE_METADATA = "file_metadata"


@dataclass
class ArtifactDefinition:
    """
    Definition of an artifact type including its characteristics.

    Attributes:
        artifact_type: Type of artifact
        platforms: Platforms where this artifact is found
        attck_techniques: MITRE ATT&CK technique IDs
        severity: Default severity level (low, medium, high, critical)
        description: Human-readable description
        collection_paths: Dictionary of platform -> collection paths
    """

    artifact_type: ArtifactType
    platforms: Set[Platform]
    attck_techniques: List[str]
    severity: str
    description: str
    collection_paths: Dict[Platform, List[str]]


# Windows Artifact Definitions
WINDOWS_ARTIFACTS: Dict[ArtifactType, ArtifactDefinition] = {
    ArtifactType.WMI_EVENT_CONSUMER: ArtifactDefinition(
        artifact_type=ArtifactType.WMI_EVENT_CONSUMER,
        platforms={Platform.WINDOWS},
        attck_techniques=["T1546.003", "T1047"],
        severity="high",
        description="WMI Event Consumer for persistence",
        collection_paths={
            Platform.WINDOWS: [
                "/Windows/System32/wbem/Repository/OBJECTS.DATA",
                "/Windows/System32/wbem/Repository/INDEX.BTR",
                "/Windows/System32/wbem/Repository/FS/",
            ]
        },
    ),
    ArtifactType.WMI_EVENT_FILTER: ArtifactDefinition(
        artifact_type=ArtifactType.WMI_EVENT_FILTER,
        platforms={Platform.WINDOWS},
        attck_techniques=["T1546.003", "T1047"],
        severity="high",
        description="WMI Event Filter for persistence",
        collection_paths={
            Platform.WINDOWS: [
                "/Windows/System32/wbem/Repository/OBJECTS.DATA",
                "/Windows/System32/wbem/Repository/INDEX.BTR",
            ]
        },
    ),
    ArtifactType.WMI_BINDING: ArtifactDefinition(
        artifact_type=ArtifactType.WMI_BINDING,
        platforms={Platform.WINDOWS},
        attck_techniques=["T1546.003", "T1047"],
        severity="high",
        description="WMI Filter-to-Consumer Binding",
        collection_paths={
            Platform.WINDOWS: [
                "/Windows/System32/wbem/Repository/OBJECTS.DATA",
            ]
        },
    ),
    ArtifactType.POWERSHELL_HISTORY: ArtifactDefinition(
        artifact_type=ArtifactType.POWERSHELL_HISTORY,
        platforms={Platform.WINDOWS},
        attck_techniques=["T1059.001", "T1047"],
        severity="medium",
        description="PowerShell command history",
        collection_paths={
            Platform.WINDOWS: [
                "/Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
                "/Users/*/Documents/PowerShell_transcript.*.txt",
            ]
        },
    ),
}


# macOS Artifact Definitions
MACOS_ARTIFACTS: Dict[ArtifactType, ArtifactDefinition] = {
    ArtifactType.UNIFIED_LOG: ArtifactDefinition(
        artifact_type=ArtifactType.UNIFIED_LOG,
        platforms={Platform.MACOS},
        attck_techniques=["T1070.002"],
        severity="medium",
        description="macOS Unified Logging (tracev3)",
        collection_paths={
            Platform.MACOS: [
                "/private/var/db/diagnostics/",
                "/private/var/db/uuidtext/",
            ]
        },
    ),
    ArtifactType.COREDUET_APP_USAGE: ArtifactDefinition(
        artifact_type=ArtifactType.COREDUET_APP_USAGE,
        platforms={Platform.MACOS},
        attck_techniques=["T1083", "T1087"],
        severity="low",
        description="Application usage tracking via CoreDuet",
        collection_paths={
            Platform.MACOS: [
                "/private/var/db/CoreDuet/Knowledge/knowledgeC.db",
            ]
        },
    ),
    ArtifactType.COREDUET_APP_INSTALL: ArtifactDefinition(
        artifact_type=ArtifactType.COREDUET_APP_INSTALL,
        platforms={Platform.MACOS},
        attck_techniques=["T1105"],
        severity="medium",
        description="Application installation tracking",
        collection_paths={
            Platform.MACOS: [
                "/private/var/db/CoreDuet/Knowledge/knowledgeC.db",
            ]
        },
    ),
    ArtifactType.TCC_PERMISSION: ArtifactDefinition(
        artifact_type=ArtifactType.TCC_PERMISSION,
        platforms={Platform.MACOS},
        attck_techniques=["T1123", "T1125", "T1005"],
        severity="high",
        description="Privacy permission grants (camera, mic, files)",
        collection_paths={
            Platform.MACOS: [
                "/Library/Application Support/com.apple.TCC/TCC.db",
                "/Users/*/Library/Application Support/com.apple.TCC/TCC.db",
            ]
        },
    ),
    ArtifactType.FSEVENT: ArtifactDefinition(
        artifact_type=ArtifactType.FSEVENT,
        platforms={Platform.MACOS},
        attck_techniques=["T1083", "T1070.004"],
        severity="medium",
        description="File system event logs",
        collection_paths={
            Platform.MACOS: [
                "/.fseventsd/",
                "/Users/*/.fseventsd/",
            ]
        },
    ),
    ArtifactType.QUARANTINE_EVENT: ArtifactDefinition(
        artifact_type=ArtifactType.QUARANTINE_EVENT,
        platforms={Platform.MACOS},
        attck_techniques=["T1105", "T1566"],
        severity="medium",
        description="Downloaded file quarantine tracking",
        collection_paths={
            Platform.MACOS: [
                "/Users/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2",
            ]
        },
    ),
}


# Linux Artifact Definitions
LINUX_ARTIFACTS: Dict[ArtifactType, ArtifactDefinition] = {
    ArtifactType.SYSTEMD_JOURNAL: ArtifactDefinition(
        artifact_type=ArtifactType.SYSTEMD_JOURNAL,
        platforms={Platform.LINUX},
        attck_techniques=["T1070.002"],
        severity="medium",
        description="Systemd journal logs",
        collection_paths={
            Platform.LINUX: [
                "/var/log/journal/",
                "/run/log/journal/",
            ]
        },
    ),
    ArtifactType.AUDIT_EXECVE: ArtifactDefinition(
        artifact_type=ArtifactType.AUDIT_EXECVE,
        platforms={Platform.LINUX},
        attck_techniques=["T1059", "T1059.004"],
        severity="high",
        description="Command execution via auditd",
        collection_paths={
            Platform.LINUX: [
                "/var/log/audit/audit.log",
                "/var/log/audit/audit.log.*",
            ]
        },
    ),
    ArtifactType.AUDIT_USER: ArtifactDefinition(
        artifact_type=ArtifactType.AUDIT_USER,
        platforms={Platform.LINUX},
        attck_techniques=["T1136", "T1087"],
        severity="high",
        description="User account changes via auditd",
        collection_paths={
            Platform.LINUX: [
                "/var/log/audit/audit.log",
            ]
        },
    ),
    ArtifactType.AUDIT_AUTH: ArtifactDefinition(
        artifact_type=ArtifactType.AUDIT_AUTH,
        platforms={Platform.LINUX},
        attck_techniques=["T1078", "T1110"],
        severity="high",
        description="Authentication events via auditd",
        collection_paths={
            Platform.LINUX: [
                "/var/log/audit/audit.log",
            ]
        },
    ),
    ArtifactType.DOCKER_CONTAINER: ArtifactDefinition(
        artifact_type=ArtifactType.DOCKER_CONTAINER,
        platforms={Platform.LINUX},
        attck_techniques=["T1610", "T1613", "T1611"],
        severity="high",
        description="Docker container artifacts",
        collection_paths={
            Platform.LINUX: [
                "/var/lib/docker/containers/",
                "/var/lib/docker/image/",
            ]
        },
    ),
    ArtifactType.BASH_HISTORY: ArtifactDefinition(
        artifact_type=ArtifactType.BASH_HISTORY,
        platforms={Platform.LINUX, Platform.MACOS},
        attck_techniques=["T1059.004", "T1070.003"],
        severity="medium",
        description="Bash command history",
        collection_paths={
            Platform.LINUX: [
                "/home/*/.bash_history",
                "/root/.bash_history",
            ],
            Platform.MACOS: [
                "/Users/*/.bash_history",
                "/var/root/.bash_history",
            ],
        },
    ),
    ArtifactType.PACKAGE_INSTALL: ArtifactDefinition(
        artifact_type=ArtifactType.PACKAGE_INSTALL,
        platforms={Platform.LINUX},
        attck_techniques=["T1072", "T1105"],
        severity="medium",
        description="Package installation logs",
        collection_paths={
            Platform.LINUX: [
                "/var/log/dpkg.log",
                "/var/log/apt/history.log",
                "/var/log/yum.log",
                "/var/log/dnf.log",
            ]
        },
    ),
}


# All artifacts combined
ALL_ARTIFACTS: Dict[ArtifactType, ArtifactDefinition] = {
    **WINDOWS_ARTIFACTS,
    **MACOS_ARTIFACTS,
    **LINUX_ARTIFACTS,
}


# Collection path mappings by platform
COLLECTION_PATHS: Dict[Platform, Dict[str, str]] = {
    Platform.WINDOWS: {
        # WMI
        "/Windows/System32/wbem/Repository/": "wmi_repo",
        "/Windows/System32/wbem/Repository/FS/": "wmi_repo",
        "/Windows/System32/wbem/AutoRecover/": "wmi_autorecover",
        # PowerShell
        "/Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/": "powershell_history",
        # Registry
        "/Windows/System32/config/": "registry",
        # Event Logs
        "/Windows/System32/winevt/Logs/": "event_logs",
        # Prefetch
        "/Windows/Prefetch/": "prefetch",
        # File System
        "/$MFT": "mft",
        "/$LogFile": "logfile",
        "/$UsnJrnl": "usn_journal",
    },
    Platform.MACOS: {
        # Unified Logging
        "/private/var/db/diagnostics/": "unified_logs",
        "/private/var/db/uuidtext/": "unified_logs",
        # Application Usage
        "/private/var/db/CoreDuet/Knowledge/knowledgeC.db": "coreduet",
        # Privacy Permissions
        "/Library/Application Support/com.apple.TCC/TCC.db": "tcc",
        "/Users/*/Library/Application Support/com.apple.TCC/TCC.db": "tcc",
        # File System Events
        "/.fseventsd/": "fseventsd",
        "/Users/*/.fseventsd/": "fseventsd",
        # Quarantine
        "/Users/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2": "quarantine",
        # Network Configuration
        "/Library/Preferences/SystemConfiguration/": "network_config",
        "/private/var/db/dhcpclient/": "dhcp_leases",
        # Spotlight
        "/.Spotlight-V100/": "spotlight",
        # Keychains
        "/Users/*/Library/Keychains/": "keychains",
        "/Library/Keychains/": "keychains",
        # System Logs
        "/var/log/system.log": "system_log",
        "/var/log/install.log": "install_log",
        "/Library/Logs/DiagnosticReports/": "crash_reports",
    },
    Platform.LINUX: {
        # Systemd
        "/var/log/journal/": "journal",
        "/lib/systemd/system/": "systemd_units",
        "/etc/systemd/": "systemd_config",
        # Audit
        "/var/log/audit/": "audit",
        # Docker
        "/var/lib/docker/containers/": "docker_containers",
        "/var/lib/docker/volumes/": "docker_volumes",
        "/var/lib/docker/overlay2/": "docker_overlay",
        # Command History
        "/home/*/.bash_history": "bash_history",
        "/root/.bash_history": "bash_history",
        "/home/*/.zsh_history": "zsh_history",
        "/home/*/.python_history": "python_history",
        # Package Management
        "/var/log/dpkg.log": "package_log",
        "/var/log/apt/": "package_log",
        "/var/log/yum.log": "package_log",
        "/var/log/dnf.log": "package_log",
        # Network
        "/proc/net/tcp": "network_connections",
        "/proc/modules": "kernel_modules",
        # Authentication
        "/var/log/wtmp": "login_records",
        "/var/log/btmp": "failed_logins",
        "/var/log/auth.log": "auth_log",
        "/var/log/secure": "secure_log",
        # Cron
        "/var/spool/cron/": "cron_jobs",
        "/etc/cron.d/": "cron",
        "/etc/crontab": "cron",
    },
}


def get_artifact_definition(artifact_type: ArtifactType) -> Optional[ArtifactDefinition]:
    """
    Get the definition for a specific artifact type.

    Args:
        artifact_type: The artifact type to look up

    Returns:
        ArtifactDefinition if found, None otherwise
    """
    return ALL_ARTIFACTS.get(artifact_type)


def get_artifacts_by_platform(platform: Platform) -> List[ArtifactDefinition]:
    """
    Get all artifact definitions for a specific platform.

    Args:
        platform: The platform to filter by

    Returns:
        List of artifact definitions for the platform
    """
    return [
        artifact_def
        for artifact_def in ALL_ARTIFACTS.values()
        if platform in artifact_def.platforms
    ]


def get_artifacts_by_technique(technique_id: str) -> List[ArtifactDefinition]:
    """
    Get all artifact definitions associated with a MITRE ATT&CK technique.

    Args:
        technique_id: MITRE ATT&CK technique ID (e.g., 'T1546.003')

    Returns:
        List of artifact definitions associated with the technique
    """
    return [
        artifact_def
        for artifact_def in ALL_ARTIFACTS.values()
        if technique_id in artifact_def.attck_techniques
    ]


def get_collection_paths(platform: Platform) -> Dict[str, str]:
    """
    Get collection paths for a specific platform.

    Args:
        platform: The platform to get paths for

    Returns:
        Dictionary mapping paths to artifact types
    """
    return COLLECTION_PATHS.get(platform, {})


def get_attck_techniques(artifact_type: ArtifactType) -> List[str]:
    """
    Get ATT&CK techniques associated with an artifact type.

    Args:
        artifact_type: The artifact type

    Returns:
        List of ATT&CK technique IDs
    """
    artifact_def = ALL_ARTIFACTS.get(artifact_type)
    return artifact_def.attck_techniques if artifact_def else []
