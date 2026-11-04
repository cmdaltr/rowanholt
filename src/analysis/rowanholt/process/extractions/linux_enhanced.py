#!/usr/bin/env python3
"""
Enhanced Linux Artifact Parsers

Comprehensive parsers for Linux-specific artifacts including:
- Systemd Journal
- Audit logs
- Docker/Container artifacts
- Extended command histories
- Package management logs
- Network artifacts

Author: Rowanholt DF Acceleration Suite
Version: 2.1.0
"""

import os
import re
import struct
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging


class SystemdJournalParser:
    """
    Parse systemd journal files.

    Systemd journal replaced traditional syslog in many Linux distributions.
    Located at /var/log/journal/ and /run/log/journal/

    ATT&CK Mapping:
    - T1070.002: Clear Linux or Mac System Logs
    - T1562.001: Disable or Modify Tools
    """

    def __init__(self):
        """Initialize systemd journal parser."""
        self.logger = logging.getLogger(__name__)

    def parse_journal_files(self, journal_dir: str) -> List[Dict[str, Any]]:
        """
        Parse systemd journal files.

        Args:
            journal_dir: Path to journal directory

        Returns:
            List of journal entries
        """
        entries = []

        if not os.path.exists(journal_dir):
            return entries

        try:
            # Journal files are binary, typically need journalctl to parse
            # This is a simplified approach looking for readable strings

            for root, dirs, files in os.walk(journal_dir):
                for file in files:
                    if file.endswith(".journal"):
                        file_path = os.path.join(root, file)
                        try:
                            file_entries = self._parse_journal_file(file_path)
                            entries.extend(file_entries)
                        except Exception as e:
                            self.logger.debug(f"Error parsing {file_path}: {e}")

        except Exception as e:
            self.logger.error(f"Error parsing journal directory: {e}")

        return entries

    def _parse_journal_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Parse individual journal file.

        Note: For production, use systemd-python or journalctl export.

        Args:
            file_path: Path to journal file

        Returns:
            List of entries
        """
        entries = []

        try:
            with open(file_path, "rb") as f:
                data = f.read()

            # Extract readable strings
            strings = re.findall(rb"[\x20-\x7E]{20,200}", data)

            for string in strings:
                try:
                    text = string.decode("utf-8")
                    if any(
                        keyword in text.lower()
                        for keyword in ["systemd", "kernel", "login", "error"]
                    ):
                        entries.append(
                            {
                                "source_file": file_path,
                                "message": text,
                                "artifact_type": "systemd_journal",
                                "attck_techniques": ["T1070.002"],
                            }
                        )
                except:
                    pass

        except Exception as e:
            self.logger.debug(f"Error reading journal file: {e}")

        return entries


class AuditLogParser:
    """
    Parse Linux audit logs (auditd).

    Audit logs track security-relevant system events.
    Located at /var/log/audit/

    ATT&CK Mapping:
    - T1087: Account Discovery
    - T1136: Create Account
    - T1078: Valid Accounts
    - T1070.002: Clear Linux or Mac System Logs
    """

    def __init__(self):
        """Initialize audit log parser."""
        self.logger = logging.getLogger(__name__)

    def parse_audit_logs(self, audit_dir: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Parse audit log directory.

        Args:
            audit_dir: Path to /var/log/audit/

        Returns:
            Dictionary with categorized audit events
        """
        results = {
            "user_commands": [],
            "account_changes": [],
            "authentication": [],
            "file_access": [],
            "network": [],
            "errors": [],
        }

        if not os.path.exists(audit_dir):
            return results

        try:
            for filename in os.listdir(audit_dir):
                if filename.startswith("audit.log"):
                    file_path = os.path.join(audit_dir, filename)

                    try:
                        file_results = self._parse_audit_file(file_path)
                        for category, events in file_results.items():
                            if category in results:
                                results[category].extend(events)
                    except Exception as e:
                        results["errors"].append(f"Error parsing {filename}: {e}")

        except Exception as e:
            self.logger.error(f"Error parsing audit directory: {e}")
            results["errors"].append(str(e))

        return results

    def _parse_audit_file(self, file_path: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Parse individual audit log file.

        Args:
            file_path: Path to audit.log file

        Returns:
            Dictionary with categorized events
        """
        results = {
            "user_commands": [],
            "account_changes": [],
            "authentication": [],
            "file_access": [],
            "network": [],
        }

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    # Parse audit log line
                    if "type=EXECVE" in line:  # Command execution
                        results["user_commands"].append(
                            {
                                "line": line.strip(),
                                "artifact_type": "audit_execve",
                                "attck_techniques": ["T1059"],
                            }
                        )

                    elif "type=USER_" in line:  # User account events
                        results["account_changes"].append(
                            {
                                "line": line.strip(),
                                "artifact_type": "audit_user_account",
                                "attck_techniques": ["T1136", "T1087"],
                            }
                        )

                    elif "type=USER_AUTH" in line or "type=USER_LOGIN" in line:
                        results["authentication"].append(
                            {
                                "line": line.strip(),
                                "artifact_type": "audit_authentication",
                                "attck_techniques": ["T1078"],
                            }
                        )

                    elif "type=PATH" in line or "type=SYSCALL" in line:
                        results["file_access"].append(
                            {
                                "line": line.strip(),
                                "artifact_type": "audit_file_access",
                                "attck_techniques": ["T1005", "T1083"],
                            }
                        )

        except Exception as e:
            self.logger.debug(f"Error parsing audit file: {e}")

        return results


class DockerArtifactParser:
    """
    Parse Docker/container artifacts.

    Docker artifacts include container logs, configurations, and metadata.
    Located at /var/lib/docker/

    ATT&CK Mapping:
    - T1610: Deploy Container
    - T1611: Escape to Host
    - T1613: Container and Resource Discovery
    """

    def __init__(self):
        """Initialize Docker parser."""
        self.logger = logging.getLogger(__name__)

    def parse_docker_artifacts(self, docker_dir: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Parse Docker directory for container artifacts.

        Args:
            docker_dir: Path to /var/lib/docker/

        Returns:
            Dictionary with Docker artifacts
        """
        results = {"containers": [], "images": [], "volumes": [], "networks": [], "errors": []}

        if not os.path.exists(docker_dir):
            return results

        try:
            # Parse container configs
            containers_dir = os.path.join(docker_dir, "containers")
            if os.path.exists(containers_dir):
                results["containers"] = self._parse_containers(containers_dir)

            # Parse volumes
            volumes_dir = os.path.join(docker_dir, "volumes")
            if os.path.exists(volumes_dir):
                results["volumes"] = self._parse_volumes(volumes_dir)

        except Exception as e:
            self.logger.error(f"Error parsing Docker artifacts: {e}")
            results["errors"].append(str(e))

        return results

    def _parse_containers(self, containers_dir: str) -> List[Dict[str, Any]]:
        """
        Parse Docker container configurations.

        Args:
            containers_dir: Path to containers directory

        Returns:
            List of container artifacts
        """
        containers = []

        try:
            for container_id in os.listdir(containers_dir):
                container_path = os.path.join(containers_dir, container_id)

                # Parse config.v2.json
                config_file = os.path.join(container_path, "config.v2.json")
                if os.path.exists(config_file):
                    try:
                        import json

                        with open(config_file, "r") as f:
                            config = json.load(f)

                        containers.append(
                            {
                                "container_id": container_id,
                                "image": config.get("Config", {}).get("Image"),
                                "command": config.get("Path"),
                                "args": config.get("Args"),
                                "created": config.get("Created"),
                                "artifact_type": "docker_container",
                                "attck_techniques": ["T1610", "T1613"],
                                "severity": "medium",
                            }
                        )

                    except Exception as e:
                        self.logger.debug(f"Error parsing container config: {e}")

        except Exception as e:
            self.logger.debug(f"Error reading containers directory: {e}")

        return containers

    def _parse_volumes(self, volumes_dir: str) -> List[Dict[str, Any]]:
        """
        Parse Docker volumes.

        Args:
            volumes_dir: Path to volumes directory

        Returns:
            List of volume artifacts
        """
        volumes = []

        try:
            for volume_name in os.listdir(volumes_dir):
                volume_path = os.path.join(volumes_dir, volume_name)

                if os.path.isdir(volume_path):
                    volumes.append(
                        {
                            "volume_name": volume_name,
                            "path": volume_path,
                            "artifact_type": "docker_volume",
                            "attck_techniques": ["T1610"],
                        }
                    )

        except Exception as e:
            self.logger.debug(f"Error reading volumes directory: {e}")

        return volumes


class ExtendedHistoryParser:
    """
    Parse extended command histories from multiple shells.

    Supports bash, zsh, python, mysql, and other shell histories.

    ATT&CK Mapping:
    - T1059: Command and Scripting Interpreter
    - T1552.003: Credentials In Files
    """

    HISTORY_FILES = {
        ".bash_history": "bash",
        ".zsh_history": "zsh",
        ".python_history": "python",
        ".mysql_history": "mysql",
        ".psql_history": "postgresql",
        ".sqlite_history": "sqlite",
        ".node_repl_history": "nodejs",
    }

    def __init__(self):
        """Initialize extended history parser."""
        self.logger = logging.getLogger(__name__)

    def parse_all_histories(self, mount_point: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Parse all command histories from mounted image.

        Args:
            mount_point: Path to mounted Linux image

        Returns:
            Dictionary with history entries by shell type
        """
        results = {}

        # Search in common locations
        search_paths = [
            "root",
            "home/*",
        ]

        for search_path in search_paths:
            full_pattern = os.path.join(mount_point, search_path)

            try:
                from glob import glob

                for user_dir in glob(full_pattern):
                    if not os.path.isdir(user_dir):
                        continue

                    # Check for each history file type
                    for hist_file, shell_type in self.HISTORY_FILES.items():
                        hist_path = os.path.join(user_dir, hist_file)

                        if os.path.exists(hist_path):
                            username = os.path.basename(user_dir)
                            entries = self._parse_history_file(hist_path, shell_type, username)

                            if shell_type not in results:
                                results[shell_type] = []
                            results[shell_type].extend(entries)

            except Exception as e:
                self.logger.debug(f"Error searching histories: {e}")

        return results

    def _parse_history_file(
        self, file_path: str, shell_type: str, username: str
    ) -> List[Dict[str, Any]]:
        """
        Parse individual history file.

        Args:
            file_path: Path to history file
            shell_type: Type of shell
            username: Username

        Returns:
            List of command entries
        """
        entries = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    # Check for suspicious patterns
                    suspicious = any(
                        pattern in line.lower()
                        for pattern in [
                            "password",
                            "passwd",
                            "secret",
                            "api_key",
                            "token",
                            "curl",
                            "wget",
                            "nc ",
                            "netcat",
                            "/dev/tcp",
                            "base64",
                            "chmod +x",
                            "sudo",
                            "su -",
                        ]
                    )

                    entries.append(
                        {
                            "username": username,
                            "shell_type": shell_type,
                            "line_number": line_num,
                            "command": line,
                            "file_path": file_path,
                            "suspicious": suspicious,
                            "artifact_type": f"{shell_type}_history",
                            "attck_techniques": (
                                ["T1059.004"] if shell_type in ["bash", "zsh"] else ["T1059"]
                            ),
                            "severity": "high" if suspicious else "low",
                        }
                    )

        except Exception as e:
            self.logger.debug(f"Error parsing history file: {e}")

        return entries


class PackageManagementParser:
    """
    Parse package management logs.

    Tracks software installation and updates.

    ATT&CK Mapping:
    - T1072: Software Deployment Tools
    - T1105: Ingress Tool Transfer
    """

    def __init__(self):
        """Initialize package management parser."""
        self.logger = logging.getLogger(__name__)

    def parse_package_logs(self, log_dir: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Parse package management logs.

        Args:
            log_dir: Path to /var/log/

        Returns:
            Dictionary with package events
        """
        results = {
            "dpkg": [],  # Debian/Ubuntu
            "apt": [],
            "yum": [],  # RHEL/CentOS
            "dnf": [],
            "errors": [],
        }

        if not os.path.exists(log_dir):
            return results

        # Parse dpkg.log
        dpkg_log = os.path.join(log_dir, "dpkg.log")
        if os.path.exists(dpkg_log):
            try:
                with open(dpkg_log, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if "install" in line.lower() or "remove" in line.lower():
                            results["dpkg"].append(
                                {
                                    "line": line.strip(),
                                    "artifact_type": "dpkg_log",
                                    "attck_techniques": ["T1072", "T1105"],
                                }
                            )
            except Exception as e:
                results["errors"].append(f"Error parsing dpkg.log: {e}")

        # Parse apt logs
        apt_dir = os.path.join(log_dir, "apt")
        if os.path.exists(apt_dir):
            try:
                for filename in os.listdir(apt_dir):
                    if filename.startswith("history.log"):
                        apt_log = os.path.join(apt_dir, filename)
                        with open(apt_log, "r", encoding="utf-8", errors="ignore") as f:
                            for line in f:
                                if "Install:" in line or "Remove:" in line:
                                    results["apt"].append(
                                        {
                                            "line": line.strip(),
                                            "artifact_type": "apt_history",
                                            "attck_techniques": ["T1072", "T1105"],
                                        }
                                    )
            except Exception as e:
                results["errors"].append(f"Error parsing apt logs: {e}")

        # Parse yum.log
        yum_log = os.path.join(log_dir, "yum.log")
        if os.path.exists(yum_log):
            try:
                with open(yum_log, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if "Installed:" in line or "Removed:" in line:
                            results["yum"].append(
                                {
                                    "line": line.strip(),
                                    "artifact_type": "yum_log",
                                    "attck_techniques": ["T1072", "T1105"],
                                }
                            )
            except Exception as e:
                results["errors"].append(f"Error parsing yum.log: {e}")

        return results


# Linux Artifact Collection Paths
LINUX_ARTIFACTS_EXTENDED = {
    # Systemd Journal
    "/var/log/journal/": "journal",
    "/run/log/journal/": "journal",
    # Audit Logs
    "/var/log/audit/": "audit",
    # Command History (all users)
    "/home/*/.bash_history": "bash_history",
    "/home/*/.zsh_history": "zsh_history",
    "/home/*/.python_history": "python_history",
    "/root/.bash_history": "bash_history",
    "/root/.zsh_history": "zsh_history",
    # SSH
    "/home/*/.ssh/": "ssh_keys",
    "/root/.ssh/": "ssh_keys",
    "/etc/ssh/": "ssh_config",
    "/var/log/auth.log": "auth_log",
    "/var/log/secure": "auth_log",  # RHEL/CentOS
    # Docker/Containers
    "/var/lib/docker/containers/": "docker_containers",
    "/var/lib/docker/volumes/": "docker_volumes",
    "/var/log/docker.log": "docker_log",
    # Package Management
    "/var/log/dpkg.log": "package_log",
    "/var/log/apt/": "package_log",
    "/var/log/yum.log": "package_log",
    "/var/log/dnf.log": "package_log",
    # Network
    "/proc/net/tcp": "network_connections",
    "/proc/net/udp": "network_connections",
    # Kernel Modules
    "/proc/modules": "kernel_modules",
    "/sys/module/": "kernel_modules",
    # User Activity
    "/var/log/wtmp": "login_records",
    "/var/log/btmp": "failed_logins",
    "/var/log/lastlog": "last_login",
    # Scheduled Tasks
    "/var/spool/cron/": "cron_jobs",
    "/etc/cron.d/": "cron_jobs",
    "/etc/crontab": "cron_jobs",
}


# Convenience function


def parse_all_linux_artifacts(mount_point: str) -> Dict[str, Any]:
    """
    Parse all enhanced Linux artifacts.

    Args:
        mount_point: Path to mounted Linux image

    Returns:
        Dictionary with all parsed artifacts
    """
    results = {
        "systemd_journal": [],
        "audit_logs": {},
        "docker": {},
        "command_histories": {},
        "package_logs": {},
        "errors": [],
    }

    # Systemd Journal
    journal_parser = SystemdJournalParser()
    journal_path = os.path.join(mount_point, "var/log/journal")
    if os.path.exists(journal_path):
        results["systemd_journal"] = journal_parser.parse_journal_files(journal_path)

    # Audit Logs
    audit_parser = AuditLogParser()
    audit_path = os.path.join(mount_point, "var/log/audit")
    if os.path.exists(audit_path):
        results["audit_logs"] = audit_parser.parse_audit_logs(audit_path)

    # Docker
    docker_parser = DockerArtifactParser()
    docker_path = os.path.join(mount_point, "var/lib/docker")
    if os.path.exists(docker_path):
        results["docker"] = docker_parser.parse_docker_artifacts(docker_path)

    # Command Histories
    history_parser = ExtendedHistoryParser()
    results["command_histories"] = history_parser.parse_all_histories(mount_point)

    # Package Logs
    package_parser = PackageManagementParser()
    log_path = os.path.join(mount_point, "var/log")
    if os.path.exists(log_path):
        results["package_logs"] = package_parser.parse_package_logs(log_path)

    return results
