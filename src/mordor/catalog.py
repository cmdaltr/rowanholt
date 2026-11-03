"""OTRF Security Datasets catalog management."""

import json
import os
import yaml
import requests
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import (
    MordorDataset,
    CatalogIndex,
    AttackMapping,
    DatasetFile,
    Simulation,
    SimulationTool,
    Contributor,
    Notebook,
)

GITHUB_API = "https://api.github.com/repos/OTRF/Security-Datasets"
RAW_GITHUB = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master"
CACHE_TTL_HOURS = 24
DEFAULT_CACHE_DIR = "/tmp/dernvale/mordor/cache"


class MordorCatalog:
    """Manages the OTRF Security Datasets catalog."""

    def __init__(self, cache_dir: Optional[str] = None, github_token: Optional[str] = None):
        """
        Initialize the Mordor catalog.

        Args:
            cache_dir: Directory for caching catalog data
            github_token: GitHub API token for higher rate limits (optional)
        """
        self.cache_dir = Path(cache_dir or DEFAULT_CACHE_DIR)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "catalog_index.json"
        self._index: Optional[CatalogIndex] = None
        self.github_token = github_token or os.environ.get("MORDOR_GITHUB_TOKEN")

    def _get_headers(self) -> Dict[str, str]:
        """Get headers for GitHub API requests."""
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        return headers

    def _load_cache(self) -> Optional[CatalogIndex]:
        """Load catalog from cache if fresh."""
        if not self.cache_file.exists():
            return None

        try:
            with open(self.cache_file, "r") as f:
                data = json.load(f)

            index = CatalogIndex(**data)

            # Check if cache is still fresh
            age = datetime.now() - index.last_updated
            if age < timedelta(hours=CACHE_TTL_HOURS):
                return index
        except Exception as e:
            print(f"Warning: Failed to load cache: {e}")

        return None

    def _save_cache(self, index: CatalogIndex):
        """Save catalog to cache."""
        try:
            with open(self.cache_file, "w") as f:
                json.dump(index.model_dump(), f, default=str, indent=2)
        except Exception as e:
            print(f"Warning: Failed to save cache: {e}")

    def _fetch_metadata_files(self) -> List[str]:
        """Fetch list of metadata YAML files from GitHub."""
        metadata_urls = []

        for dataset_type in ["atomic", "compound"]:
            url = f"{GITHUB_API}/contents/datasets/{dataset_type}/_metadata"
            try:
                response = requests.get(url, headers=self._get_headers(), timeout=30)

                if response.status_code == 200:
                    files = response.json()
                    for f in files:
                        if f["name"].endswith(".yaml") or f["name"].endswith(".yml"):
                            metadata_urls.append(f["download_url"])
                elif response.status_code == 403:
                    print(f"Warning: Rate limited by GitHub API. Consider using MORDOR_GITHUB_TOKEN.")
                    break
            except Exception as e:
                print(f"Warning: Failed to fetch metadata list for {dataset_type}: {e}")

        return metadata_urls

    def _parse_metadata_file(self, url: str) -> Optional[MordorDataset]:
        """Parse a single metadata YAML file."""
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()

            data = yaml.safe_load(response.text)

            if not data or not isinstance(data, dict):
                return None

            # Extract attack mappings
            attack_mappings = []
            for mapping in data.get("attack_mappings", []):
                if isinstance(mapping, dict):
                    am = AttackMapping(
                        technique=mapping.get("technique", ""),
                        sub_technique=mapping.get("sub_technique"),
                        tactics=mapping.get("tactics", []),
                    )
                    attack_mappings.append(am)

            # Parse files
            files = []
            for f in data.get("files", []):
                if isinstance(f, dict):
                    files.append(
                        DatasetFile(
                            type=f.get("type", "Unknown"),
                            link=f.get("link", ""),
                        )
                    )

            # Parse simulation
            simulation = None
            sim_data = data.get("simulation")
            if sim_data and isinstance(sim_data, dict):
                tools = []
                for t in sim_data.get("tools", []):
                    if isinstance(t, dict):
                        tools.append(
                            SimulationTool(
                                type=t.get("type", ""),
                                name=t.get("name", ""),
                                module=t.get("module"),
                                script=t.get("script"),
                            )
                        )
                simulation = Simulation(
                    environment=sim_data.get("environment"),
                    tools=tools,
                    permissions_required=sim_data.get("permissions_required", []),
                    adversary_view=sim_data.get("adversary_view"),
                )

            # Parse contributors
            contributors = []
            for c in data.get("contributors", []):
                if isinstance(c, dict):
                    contributors.append(
                        Contributor(
                            name=c.get("name", ""),
                            twitter=c.get("twitter"),
                            website=c.get("website"),
                        )
                    )

            # Parse notebooks
            notebooks = []
            for n in data.get("notebooks", []):
                if isinstance(n, dict):
                    notebooks.append(
                        Notebook(
                            project=n.get("project"),
                            name=n.get("name"),
                            link=n.get("link"),
                        )
                    )

            dataset = MordorDataset(
                id=data.get("id", ""),
                title=data.get("title", "Untitled"),
                description=data.get("description"),
                platform=data.get("platform", "Unknown"),
                type=data.get("type", "atomic"),
                attack_mappings=attack_mappings,
                files=files,
                simulation=simulation,
                contributors=contributors,
                tags=data.get("tags", []),
                notebooks=notebooks,
                references=data.get("references", []),
                source_url=url,
                creation_date=data.get("creation_date"),
                modification_date=data.get("modification_date"),
            )

            # Derive tactics and techniques
            dataset.derive_tactics_techniques()

            return dataset

        except Exception as e:
            print(f"Warning: Failed to parse {url}: {e}")
            return None

    def refresh(self, force: bool = False) -> int:
        """
        Refresh catalog from OTRF GitHub repository.

        Args:
            force: Force refresh even if cache is fresh

        Returns:
            Number of datasets indexed
        """
        if not force:
            cached = self._load_cache()
            if cached:
                self._index = cached
                return cached.total_count

        print("Fetching metadata file list from OTRF...")
        metadata_urls = self._fetch_metadata_files()

        if not metadata_urls:
            print("Warning: No metadata files found. Using cached data if available.")
            cached = self._load_cache()
            if cached:
                self._index = cached
                return cached.total_count
            return 0

        print(f"Parsing {len(metadata_urls)} metadata files...")
        datasets = []

        # Parallel fetching with progress
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self._parse_metadata_file, url): url
                for url in metadata_urls
            }

            completed = 0
            for future in as_completed(futures):
                completed += 1
                if completed % 50 == 0:
                    print(f"  Processed {completed}/{len(metadata_urls)} files...")

                result = future.result()
                if result:
                    datasets.append(result)

        self._index = CatalogIndex(
            last_updated=datetime.now(),
            datasets=datasets,
            total_count=len(datasets),
        )
        self._index.compute_statistics()

        self._save_cache(self._index)
        print(f"Catalog refreshed: {len(datasets)} datasets indexed")
        return len(datasets)

    def list_datasets(
        self,
        platform: Optional[str] = None,
        tactic: Optional[str] = None,
        technique: Optional[str] = None,
        search: Optional[str] = None,
        tags: Optional[List[str]] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[MordorDataset]:
        """
        List datasets with optional filtering.

        Args:
            platform: Filter by platform (windows, linux, aws)
            tactic: Filter by MITRE tactic
            technique: Filter by MITRE technique ID
            search: Search in title/description
            tags: Filter by tags
            limit: Maximum number of results
            offset: Starting offset

        Returns:
            List of matching datasets
        """
        if not self._index:
            self.refresh()

        if not self._index:
            return []

        datasets = self._index.datasets

        # Apply filters
        if platform:
            datasets = [d for d in datasets if d.platform.lower() == platform.lower()]

        if tactic:
            datasets = [
                d for d in datasets if tactic.lower() in [t.lower() for t in d.tactics]
            ]

        if technique:
            datasets = [
                d
                for d in datasets
                if technique.upper() in [t.upper() for t in d.techniques]
            ]

        if search:
            search_lower = search.lower()
            datasets = [
                d
                for d in datasets
                if search_lower in d.title.lower()
                or (d.description and search_lower in d.description.lower())
                or d.dataset_id.lower().startswith(search_lower)
            ]

        if tags:
            tags_lower = [t.lower() for t in tags]
            datasets = [
                d
                for d in datasets
                if any(t.lower() in tags_lower for t in d.tags)
            ]

        return datasets[offset : offset + limit]

    def get_dataset(self, dataset_id: str) -> Optional[MordorDataset]:
        """
        Get a specific dataset by ID.

        Args:
            dataset_id: OTRF dataset ID (e.g., SDWIN-190518182022)

        Returns:
            Dataset if found, None otherwise
        """
        if not self._index:
            self.refresh()

        if not self._index:
            return None

        for ds in self._index.datasets:
            if ds.dataset_id == dataset_id:
                return ds

        return None

    def get_statistics(self) -> Dict[str, any]:
        """Get catalog statistics."""
        if not self._index:
            self.refresh()

        if not self._index:
            return {"total": 0, "platforms": {}, "tactics": {}}

        return {
            "total": self._index.total_count,
            "platforms": self._index.platforms,
            "tactics": self._index.tactics,
            "techniques": self._index.techniques,
            "last_updated": self._index.last_updated.isoformat(),
        }

    @property
    def is_cached(self) -> bool:
        """Check if catalog is cached."""
        return self.cache_file.exists()

    @property
    def cache_age_hours(self) -> Optional[float]:
        """Get cache age in hours."""
        if not self._index:
            cached = self._load_cache()
            if cached:
                self._index = cached

        if self._index:
            age = datetime.now() - self._index.last_updated
            return age.total_seconds() / 3600

        return None
