"""Local storage management for Mordor datasets."""

import json
import os
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

from .models import MordorDataset, DatasetStatus, DatasetVerifyResult

DEFAULT_STORAGE_DIR = "/tmp/rowanholt/mordor"


class MordorStorage:
    """Manages locally downloaded Mordor datasets."""

    def __init__(self, storage_dir: Optional[str] = None):
        """
        Initialize the storage manager.

        Args:
            storage_dir: Directory for storing datasets
        """
        self.storage_dir = Path(storage_dir or DEFAULT_STORAGE_DIR)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def get_dataset_path(self, dataset_id: str) -> Path:
        """Get the local path for a dataset."""
        return self.storage_dir / dataset_id

    def dataset_exists(self, dataset_id: str) -> bool:
        """Check if a dataset is downloaded locally."""
        dataset_path = self.get_dataset_path(dataset_id)
        metadata_path = dataset_path / "metadata.json"
        return metadata_path.exists()

    def get_dataset_info(self, dataset_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a locally downloaded dataset.

        Args:
            dataset_id: OTRF dataset ID

        Returns:
            Dictionary with dataset info, or None if not found
        """
        dataset_path = self.get_dataset_path(dataset_id)
        metadata_path = dataset_path / "metadata.json"

        if not metadata_path.exists():
            return None

        try:
            with open(metadata_path, "r") as f:
                metadata = json.load(f)

            # Add local status info
            metadata["status"] = DatasetStatus.DOWNLOADED.value
            metadata["local_path"] = str(dataset_path)

            # Get actual size on disk
            total_size = 0
            for file_info in metadata.get("files", []):
                file_path = Path(file_info.get("path", ""))
                if file_path.exists():
                    total_size += file_path.stat().st_size
            metadata["actual_size"] = total_size

            return metadata

        except Exception as e:
            print(f"Warning: Failed to read metadata for {dataset_id}: {e}")
            return None

    def list_local_datasets(
        self,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        List locally downloaded datasets.

        Args:
            status: Filter by status (downloaded, downloading, failed)
            limit: Maximum number of results
            offset: Starting offset

        Returns:
            List of dataset info dictionaries
        """
        datasets = []

        if not self.storage_dir.exists():
            return datasets

        for item in sorted(self.storage_dir.iterdir()):
            if not item.is_dir():
                continue

            # Skip cache directory
            if item.name == "cache":
                continue

            metadata_path = item / "metadata.json"
            if not metadata_path.exists():
                continue

            try:
                with open(metadata_path, "r") as f:
                    metadata = json.load(f)

                dataset_info = {
                    "dataset_id": metadata.get("dataset_id", item.name),
                    "title": metadata.get("title", "Unknown"),
                    "description": metadata.get("description"),
                    "platform": metadata.get("platform", "Unknown"),
                    "tactics": metadata.get("tactics", []),
                    "techniques": metadata.get("techniques", []),
                    "status": DatasetStatus.DOWNLOADED.value,
                    "local_path": str(item),
                    "total_size": metadata.get("total_size", 0),
                    "downloaded_at": metadata.get("downloaded_at"),
                    "files_count": len(metadata.get("files", [])),
                }

                datasets.append(dataset_info)

            except Exception as e:
                print(f"Warning: Failed to read metadata from {item}: {e}")
                continue

        # Apply status filter if specified
        if status:
            datasets = [d for d in datasets if d.get("status") == status]

        return datasets[offset : offset + limit]

    def delete_dataset(self, dataset_id: str) -> bool:
        """
        Delete a locally downloaded dataset.

        Args:
            dataset_id: OTRF dataset ID

        Returns:
            True if deleted successfully, False otherwise
        """
        dataset_path = self.get_dataset_path(dataset_id)

        if not dataset_path.exists():
            return False

        try:
            shutil.rmtree(dataset_path)
            return True
        except Exception as e:
            print(f"Error: Failed to delete {dataset_id}: {e}")
            return False

    def verify_dataset(self, dataset_id: str) -> DatasetVerifyResult:
        """
        Verify the integrity of a downloaded dataset.

        Args:
            dataset_id: OTRF dataset ID

        Returns:
            DatasetVerifyResult with verification status
        """
        from .downloader import MordorDownloader

        dataset_path = self.get_dataset_path(dataset_id)

        if not dataset_path.exists():
            return DatasetVerifyResult(
                dataset_id=dataset_id,
                valid=False,
                errors=["Dataset not found"],
            )

        downloader = MordorDownloader()
        return downloader.verify(dataset_id, str(dataset_path))

    def get_storage_stats(self) -> Dict[str, Any]:
        """
        Get storage statistics.

        Returns:
            Dictionary with storage statistics
        """
        datasets = self.list_local_datasets(limit=1000)

        total_size = sum(d.get("total_size", 0) for d in datasets)
        total_files = sum(d.get("files_count", 0) for d in datasets)

        # Platform breakdown
        platforms: Dict[str, int] = {}
        for d in datasets:
            platform = d.get("platform", "Unknown")
            platforms[platform] = platforms.get(platform, 0) + 1

        return {
            "total_datasets": len(datasets),
            "total_size": total_size,
            "total_size_human": self._format_size(total_size),
            "total_files": total_files,
            "platforms": platforms,
            "storage_path": str(self.storage_dir),
        }

    def _format_size(self, size_bytes: int) -> str:
        """Format bytes to human-readable string."""
        if size_bytes == 0:
            return "0 B"

        units = ["B", "KB", "MB", "GB", "TB"]
        unit_index = 0
        size = float(size_bytes)

        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1

        return f"{size:.1f} {units[unit_index]}"

    def cleanup_incomplete(self) -> int:
        """
        Clean up incomplete downloads (datasets without metadata.json).

        Returns:
            Number of incomplete downloads cleaned up
        """
        cleaned = 0

        if not self.storage_dir.exists():
            return cleaned

        for item in self.storage_dir.iterdir():
            if not item.is_dir():
                continue

            # Skip cache directory
            if item.name == "cache":
                continue

            metadata_path = item / "metadata.json"
            if not metadata_path.exists():
                try:
                    shutil.rmtree(item)
                    cleaned += 1
                    print(f"Cleaned up incomplete download: {item.name}")
                except Exception as e:
                    print(f"Warning: Failed to clean up {item}: {e}")

        return cleaned

    def export_dataset_list(self, output_path: str) -> bool:
        """
        Export list of local datasets to JSON file.

        Args:
            output_path: Path for output JSON file

        Returns:
            True if exported successfully
        """
        datasets = self.list_local_datasets(limit=1000)

        try:
            with open(output_path, "w") as f:
                json.dump(
                    {
                        "exported_at": datetime.now().isoformat(),
                        "total_datasets": len(datasets),
                        "datasets": datasets,
                    },
                    f,
                    indent=2,
                    default=str,
                )
            return True
        except Exception as e:
            print(f"Error: Failed to export dataset list: {e}")
            return False
