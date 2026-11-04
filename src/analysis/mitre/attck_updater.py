"""
MITRE ATT&CK Framework Auto-Updater

Automatically fetches and updates MITRE ATT&CK framework data from official sources.
Ensures Rowanholt always uses the latest techniques, tactics, and mappings.

Author: Rowanholt DF Acceleration Suite
Version: 2.1.0
"""

import os
import json
import requests
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging

from common.time_utils import get_iso_timestamp
from build.defaults import DEFAULT_TEMP_DIR


class MitreAttackUpdater:
    """
    Automatically fetch and update MITRE ATT&CK framework data.

    Features:
    - Download latest ATT&CK STIX data from official GitHub repository
    - Parse and cache locally
    - Version tracking and comparison
    - Automatic weekly updates
    - Backward compatibility with old versions
    - Changelog generation
    """

    # Official MITRE ATT&CK STIX sources
    SOURCES = {
        "enterprise": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        "mobile": "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
        "ics": "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
    }

    # Fallback sources
    FALLBACK_SOURCES = {
        "enterprise": "https://attack.mitre.org/stix/enterprise-attack.json",
        "mobile": "https://attack.mitre.org/stix/mobile-attack.json",
        "ics": "https://attack.mitre.org/stix/ics-attack.json",
    }

    def __init__(self, cache_dir: Optional[str] = None):
        """
        Initialize MITRE ATT&CK updater.

        Args:
            cache_dir: Directory to cache ATT&CK data (default: /opt/rowanholt/data/mitre)
        """
        self.cache_dir = Path(cache_dir) if cache_dir else Path(DEFAULT_TEMP_DIR) / "data" / "mitre"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Set up logging
        self.logger = logging.getLogger(__name__)

        # Current version info
        self.current_version = self._get_current_version()
        self.current_modified = self._get_current_modified()

        # Loaded data
        self.data = {}
        self.techniques = {}
        self.tactics = {}
        self.mitigations = {}
        self.groups = {}
        self.software = {}

    def _get_current_version(self) -> Optional[str]:
        """Get current cached version."""
        version_file = self.cache_dir / "version.json"
        if version_file.exists():
            try:
                with open(version_file, "r") as f:
                    data = json.load(f)
                    return data.get("version")
            except Exception as e:
                self.logger.error(f"Error reading version file: {e}")
        return None

    def _get_current_modified(self) -> Optional[str]:
        """Get current cached modification date."""
        version_file = self.cache_dir / "version.json"
        if version_file.exists():
            try:
                with open(version_file, "r") as f:
                    data = json.load(f)
                    return data.get("modified")
            except Exception:
                pass
        return None

    def check_for_updates(self, domain: str = "enterprise") -> Tuple[bool, Optional[str]]:
        """
        Check if new version is available.

        Args:
            domain: ATT&CK domain (enterprise, mobile, ics)

        Returns:
            Tuple of (has_updates, new_version)
        """
        try:
            # Download latest data
            response = requests.head(self.SOURCES[domain], timeout=10)

            if response.status_code == 200:
                # Get ETag or Last-Modified
                etag = response.headers.get("ETag", "")
                last_modified = response.headers.get("Last-Modified", "")

                # Check if different from cached version
                if etag and etag != self.current_version:
                    return True, etag
                elif last_modified and last_modified != self.current_modified:
                    return True, last_modified

            return False, None

        except Exception as e:
            self.logger.error(f"Error checking for updates: {e}")
            return False, None

    def download_latest(
        self, domain: str = "enterprise", use_fallback: bool = False
    ) -> Optional[dict]:
        """
        Download latest ATT&CK data.

        Args:
            domain: ATT&CK domain to download
            use_fallback: Use fallback source if primary fails

        Returns:
            Downloaded STIX data as dictionary
        """
        source = self.FALLBACK_SOURCES[domain] if use_fallback else self.SOURCES[domain]

        try:
            self.logger.info(f"Downloading ATT&CK {domain} data from {source}")

            response = requests.get(source, timeout=60)
            response.raise_for_status()

            data = response.json()

            # Save raw data
            raw_file = self.cache_dir / f"{domain}-attack-raw.json"
            with open(raw_file, "w") as f:
                json.dump(data, f, indent=2)

            self.logger.info(f"Successfully downloaded {domain} ATT&CK data")
            return data

        except requests.RequestException as e:
            self.logger.error(f"Error downloading from {source}: {e}")

            # Try fallback if primary failed
            if not use_fallback:
                self.logger.info("Trying fallback source...")
                return self.download_latest(domain, use_fallback=True)

            return None

        except Exception as e:
            self.logger.error(f"Unexpected error downloading ATT&CK data: {e}")
            return None

    def parse_stix_data(self, data: dict, domain: str = "enterprise") -> dict:
        """
        Parse STIX 2.0 formatted ATT&CK data.

        Args:
            data: Raw STIX data
            domain: ATT&CK domain

        Returns:
            Parsed data organized by type
        """
        parsed = {
            "version": None,
            "modified": None,
            "techniques": {},
            "tactics": {},
            "mitigations": {},
            "groups": {},
            "software": {},
            "relationships": [],
        }

        try:
            # Extract objects
            objects = data.get("objects", [])

            for obj in objects:
                obj_type = obj.get("type")

                # Extract version from x-mitre-collection
                if obj_type == "x-mitre-collection":
                    parsed["version"] = obj.get("x_mitre_version", obj.get("spec_version"))
                    parsed["modified"] = obj.get("modified")

                # Parse attack patterns (techniques)
                elif obj_type == "attack-pattern":
                    technique_id = self._extract_external_id(obj)
                    if technique_id:
                        parsed["techniques"][technique_id] = {
                            "id": technique_id,
                            "name": obj.get("name"),
                            "description": obj.get("description"),
                            "kill_chain_phases": self._extract_kill_chain_phases(obj),
                            "tactics": self._extract_tactics(obj),
                            "platforms": obj.get("x_mitre_platforms", []),
                            "data_sources": obj.get("x_mitre_data_sources", []),
                            "detection": obj.get("x_mitre_detection", ""),
                            "is_subtechnique": "." in technique_id,
                            "deprecated": obj.get("x_mitre_deprecated", False),
                            "revoked": obj.get("revoked", False),
                            "created": obj.get("created"),
                            "modified": obj.get("modified"),
                            "stix_id": obj.get("id"),
                        }

                # Parse tactics (x-mitre-tactic)
                elif obj_type == "x-mitre-tactic":
                    tactic_id = self._extract_external_id(obj)
                    if tactic_id:
                        parsed["tactics"][tactic_id] = {
                            "id": tactic_id,
                            "name": obj.get("name"),
                            "description": obj.get("description"),
                            "shortname": obj.get("x_mitre_shortname"),
                            "stix_id": obj.get("id"),
                        }

                # Parse mitigations (course-of-action)
                elif obj_type == "course-of-action":
                    mitigation_id = self._extract_external_id(obj)
                    if mitigation_id:
                        parsed["mitigations"][mitigation_id] = {
                            "id": mitigation_id,
                            "name": obj.get("name"),
                            "description": obj.get("description"),
                            "deprecated": obj.get("x_mitre_deprecated", False),
                            "stix_id": obj.get("id"),
                        }

                # Parse groups (intrusion-set)
                elif obj_type == "intrusion-set":
                    group_id = self._extract_external_id(obj)
                    if group_id:
                        parsed["groups"][group_id] = {
                            "id": group_id,
                            "name": obj.get("name"),
                            "description": obj.get("description"),
                            "aliases": obj.get("aliases", []),
                            "stix_id": obj.get("id"),
                        }

                # Parse software (malware, tool)
                elif obj_type in ["malware", "tool"]:
                    software_id = self._extract_external_id(obj)
                    if software_id:
                        parsed["software"][software_id] = {
                            "id": software_id,
                            "name": obj.get("name"),
                            "description": obj.get("description"),
                            "type": obj_type,
                            "platforms": obj.get("x_mitre_platforms", []),
                            "aliases": obj.get("x_mitre_aliases", []),
                            "stix_id": obj.get("id"),
                        }

                # Parse relationships
                elif obj_type == "relationship":
                    parsed["relationships"].append(
                        {
                            "source": obj.get("source_ref"),
                            "target": obj.get("target_ref"),
                            "type": obj.get("relationship_type"),
                            "description": obj.get("description"),
                        }
                    )

            # Save parsed data
            parsed_file = self.cache_dir / f"{domain}-attack-parsed.json"
            with open(parsed_file, "w") as f:
                json.dump(parsed, f, indent=2)

            self.logger.info(
                f"Parsed {len(parsed['techniques'])} techniques, "
                f"{len(parsed['tactics'])} tactics, "
                f"{len(parsed['mitigations'])} mitigations"
            )

            return parsed

        except Exception as e:
            self.logger.error(f"Error parsing STIX data: {e}")
            return parsed

    def _extract_external_id(self, obj: dict) -> Optional[str]:
        """Extract MITRE ATT&CK ID from external references."""
        external_refs = obj.get("external_references", [])
        for ref in external_refs:
            if ref.get("source_name") in [
                "mitre-attack",
                "mitre-mobile-attack",
                "mitre-ics-attack",
            ]:
                return ref.get("external_id")
        return None

    def _extract_kill_chain_phases(self, obj: dict) -> List[str]:
        """Extract kill chain phases."""
        phases = obj.get("kill_chain_phases", [])
        return [phase.get("phase_name") for phase in phases]

    def _extract_tactics(self, obj: dict) -> List[str]:
        """Extract tactic names from kill chain phases."""
        phases = self._extract_kill_chain_phases(obj)
        # Convert phase names to tactic names (e.g., "initial-access" -> "Initial Access")
        return [phase.replace("-", " ").title() for phase in phases]

    def update_local_cache(self, domain: str = "enterprise", force: bool = False) -> bool:
        """
        Update local cache with latest ATT&CK data.

        Args:
            domain: ATT&CK domain to update
            force: Force update even if no changes detected

        Returns:
            True if updated successfully, False otherwise
        """
        try:
            # Check for updates unless forced
            if not force:
                has_updates, new_version = self.check_for_updates(domain)
                if not has_updates:
                    self.logger.info(f"No updates available for {domain}")
                    return False

            # Download latest data
            data = self.download_latest(domain)
            if not data:
                self.logger.error("Failed to download ATT&CK data")
                return False

            # Parse data
            parsed = self.parse_stix_data(data, domain)

            # Update version info
            version_info = {
                "domain": domain,
                "version": parsed.get("version", "unknown"),
                "modified": parsed.get("modified", get_iso_timestamp()),
                "updated": get_iso_timestamp(),
                "technique_count": len(parsed["techniques"]),
                "tactic_count": len(parsed["tactics"]),
            }

            version_file = self.cache_dir / "version.json"
            with open(version_file, "w") as f:
                json.dump(version_info, f, indent=2)

            # Generate changelog
            self._generate_changelog(domain, parsed)

            self.logger.info(
                f"Successfully updated {domain} ATT&CK cache to version {version_info['version']}"
            )
            return True

        except Exception as e:
            self.logger.error(f"Error updating cache: {e}")
            return False

    def _generate_changelog(self, domain: str, new_data: dict):
        """Generate changelog comparing old and new versions."""
        try:
            # Load old data
            old_file = self.cache_dir / f"{domain}-attack-parsed.json"
            if not old_file.exists():
                self.logger.info("No previous version found, skipping changelog")
                return

            with open(old_file, "r") as f:
                old_data = json.load(f)

            # Compare versions
            changelog = {
                "date": get_iso_timestamp(),
                "old_version": old_data.get("version"),
                "new_version": new_data.get("version"),
                "added_techniques": [],
                "removed_techniques": [],
                "modified_techniques": [],
                "added_tactics": [],
                "removed_tactics": [],
            }

            # Find added/removed techniques
            old_techniques = set(old_data["techniques"].keys())
            new_techniques = set(new_data["techniques"].keys())

            changelog["added_techniques"] = list(new_techniques - old_techniques)
            changelog["removed_techniques"] = list(old_techniques - new_techniques)

            # Find modified techniques
            for tech_id in old_techniques & new_techniques:
                old_tech = old_data["techniques"][tech_id]
                new_tech = new_data["techniques"][tech_id]

                if old_tech.get("modified") != new_tech.get("modified"):
                    changelog["modified_techniques"].append(
                        {
                            "id": tech_id,
                            "name": new_tech["name"],
                            "old_modified": old_tech.get("modified"),
                            "new_modified": new_tech.get("modified"),
                        }
                    )

            # Find added/removed tactics
            old_tactics = set(old_data["tactics"].keys())
            new_tactics = set(new_data["tactics"].keys())

            changelog["added_tactics"] = list(new_tactics - old_tactics)
            changelog["removed_tactics"] = list(old_tactics - new_tactics)

            # Save changelog
            changelog_file = (
                self.cache_dir / f"changelog_{get_iso_timestamp().replace(':', '-')}.json"
            )
            with open(changelog_file, "w") as f:
                json.dump(changelog, f, indent=2)

            self.logger.info(
                f"Changelog: +{len(changelog['added_techniques'])} techniques, "
                f"-{len(changelog['removed_techniques'])} techniques, "
                f"~{len(changelog['modified_techniques'])} modified"
            )

        except Exception as e:
            self.logger.error(f"Error generating changelog: {e}")

    def load_cached_data(self, domain: str = "enterprise") -> Optional[dict]:
        """
        Load cached ATT&CK data.

        Args:
            domain: ATT&CK domain to load

        Returns:
            Parsed ATT&CK data
        """
        try:
            parsed_file = self.cache_dir / f"{domain}-attack-parsed.json"

            if not parsed_file.exists():
                self.logger.warning(f"No cached data found for {domain}")
                return None

            with open(parsed_file, "r") as f:
                data = json.load(f)

            self.logger.info(f"Loaded cached {domain} ATT&CK data (version: {data.get('version')})")
            return data

        except Exception as e:
            self.logger.error(f"Error loading cached data: {e}")
            return None

    def get_technique_by_id(self, technique_id: str, domain: str = "enterprise") -> Optional[dict]:
        """
        Get technique details by ID.

        Args:
            technique_id: ATT&CK technique ID (e.g., "T1059.001")
            domain: ATT&CK domain

        Returns:
            Technique details or None if not found
        """
        if not self.data:
            self.data = self.load_cached_data(domain)

        if not self.data:
            return None

        return self.data.get("techniques", {}).get(technique_id)

    def get_techniques_by_tactic(self, tactic: str, domain: str = "enterprise") -> List[dict]:
        """
        Get all techniques for a specific tactic.

        Args:
            tactic: Tactic name (e.g., "Execution")
            domain: ATT&CK domain

        Returns:
            List of techniques
        """
        if not self.data:
            self.data = self.load_cached_data(domain)

        if not self.data:
            return []

        techniques = []
        for tech_id, tech_data in self.data.get("techniques", {}).items():
            if tactic in tech_data.get("tactics", []):
                techniques.append(tech_data)

        return techniques

    def get_all_tactics(self, domain: str = "enterprise") -> Dict[str, dict]:
        """Get all tactics."""
        if not self.data:
            self.data = self.load_cached_data(domain)

        if not self.data:
            return {}

        return self.data.get("tactics", {})

    def get_statistics(self, domain: str = "enterprise") -> dict:
        """
        Get statistics about cached ATT&CK data.

        Args:
            domain: ATT&CK domain

        Returns:
            Statistics dictionary
        """
        if not self.data:
            self.data = self.load_cached_data(domain)

        if not self.data:
            return {}

        techniques = self.data.get("techniques", {})

        stats = {
            "version": self.data.get("version"),
            "modified": self.data.get("modified"),
            "total_techniques": len(techniques),
            "subtechniques": sum(1 for t in techniques.values() if t.get("is_subtechnique")),
            "deprecated_techniques": sum(1 for t in techniques.values() if t.get("deprecated")),
            "revoked_techniques": sum(1 for t in techniques.values() if t.get("revoked")),
            "total_tactics": len(self.data.get("tactics", {})),
            "total_mitigations": len(self.data.get("mitigations", {})),
            "total_groups": len(self.data.get("groups", {})),
            "total_software": len(self.data.get("software", {})),
        }

        # Techniques by platform
        platforms = {}
        for tech in techniques.values():
            for platform in tech.get("platforms", []):
                platforms[platform] = platforms.get(platform, 0) + 1

        stats["techniques_by_platform"] = platforms

        return stats


# Convenience functions


def update_mitre_attack(domain: str = "enterprise", force: bool = False) -> bool:
    """
    Convenience function to update MITRE ATT&CK data.

    Args:
        domain: ATT&CK domain to update
        force: Force update

    Returns:
        True if successful
    """
    updater = MitreAttackUpdater()
    return updater.update_local_cache(domain, force=force)


def load_mitre_attack(domain: str = "enterprise") -> Optional[dict]:
    """
    Convenience function to load cached MITRE ATT&CK data.

    Args:
        domain: ATT&CK domain

    Returns:
        Parsed ATT&CK data
    """
    updater = MitreAttackUpdater()
    return updater.load_cached_data(domain)
