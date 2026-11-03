"""Dataset download management."""

import hashlib
import json
import os
import requests
from pathlib import Path
from typing import Optional, Callable, Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import MordorDataset, DatasetDownloadResult, DatasetVerifyResult
from .catalog import MordorCatalog

DEFAULT_OUTPUT_DIR = "/tmp/dernvale/mordor"


class MordorDownloader:
    """Downloads Mordor datasets from OTRF repository."""

    def __init__(self, catalog: Optional[MordorCatalog] = None):
        """
        Initialize the downloader.

        Args:
            catalog: MordorCatalog instance (creates new one if not provided)
        """
        self.catalog = catalog or MordorCatalog()

    def _download_file(
        self,
        url: str,
        output_path: Path,
        progress_callback: Optional[Callable] = None,
    ) -> Dict[str, Any]:
        """
        Download a single file with progress tracking.

        Args:
            url: URL to download
            output_path: Local path to save file
            progress_callback: Callback for progress updates (downloaded_bytes, total_bytes)

        Returns:
            Dictionary with download results
        """
        response = requests.get(url, stream=True, timeout=120)
        response.raise_for_status()

        total_size = int(response.headers.get("content-length", 0))
        downloaded = 0
        hasher = hashlib.sha256()

        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    hasher.update(chunk)
                    downloaded += len(chunk)

                    if progress_callback and total_size:
                        progress_callback(downloaded, total_size)

        return {
            "path": str(output_path),
            "size": downloaded,
            "checksum": hasher.hexdigest(),
            "filename": output_path.name,
        }

    def download(
        self,
        dataset_id: str,
        output_dir: Optional[str] = None,
        progress_callback: Optional[Callable] = None,
        parallel: bool = False,
    ) -> DatasetDownloadResult:
        """
        Download a complete dataset.

        Args:
            dataset_id: OTRF dataset ID
            output_dir: Target directory for downloaded files
            progress_callback: Callback for progress updates
            parallel: Download files in parallel (faster but uses more connections)

        Returns:
            DatasetDownloadResult with download status and file info
        """
        dataset = self.catalog.get_dataset(dataset_id)
        if not dataset:
            return DatasetDownloadResult(
                dataset_id=dataset_id,
                success=False,
                error=f"Dataset not found: {dataset_id}",
            )

        output_path = Path(output_dir or f"{DEFAULT_OUTPUT_DIR}/{dataset_id}")
        output_path.mkdir(parents=True, exist_ok=True)

        downloaded_files: List[Dict[str, Any]] = []
        total_size = 0
        errors: List[str] = []

        # Track overall progress
        total_files = len(dataset.files)
        files_completed = 0

        def file_progress(file_idx: int, downloaded: int, total: int):
            """Progress callback for individual file."""
            if progress_callback:
                # Calculate overall progress
                file_progress_pct = (downloaded / total) if total > 0 else 0
                overall_pct = ((files_completed + file_progress_pct) / total_files) * 100
                progress_callback(int(overall_pct), 100)

        if parallel and len(dataset.files) > 1:
            # Parallel download
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {}
                for idx, file_info in enumerate(dataset.files):
                    if not file_info.link:
                        continue
                    filename = file_info.link.split("/")[-1]
                    file_path = output_path / file_info.type / filename

                    futures[
                        executor.submit(
                            self._download_file,
                            file_info.link,
                            file_path,
                            lambda d, t, i=idx: file_progress(i, d, t),
                        )
                    ] = file_info

                for future in as_completed(futures):
                    file_info = futures[future]
                    try:
                        result = future.result()
                        downloaded_files.append(
                            {
                                "type": file_info.type,
                                "filename": result["filename"],
                                "path": result["path"],
                                "size": result["size"],
                                "checksum": result["checksum"],
                                "url": file_info.link,
                            }
                        )
                        total_size += result["size"]
                        files_completed += 1
                    except Exception as e:
                        errors.append(f"Failed to download {file_info.link}: {e}")
        else:
            # Sequential download
            for idx, file_info in enumerate(dataset.files):
                if not file_info.link:
                    continue

                filename = file_info.link.split("/")[-1]
                file_path = output_path / file_info.type / filename

                try:
                    result = self._download_file(
                        file_info.link,
                        file_path,
                        lambda d, t: file_progress(idx, d, t),
                    )

                    downloaded_files.append(
                        {
                            "type": file_info.type,
                            "filename": result["filename"],
                            "path": result["path"],
                            "size": result["size"],
                            "checksum": result["checksum"],
                            "url": file_info.link,
                        }
                    )
                    total_size += result["size"]
                    files_completed += 1

                except Exception as e:
                    errors.append(f"Failed to download {file_info.link}: {e}")

        # Save metadata alongside downloaded files
        metadata_path = output_path / "metadata.json"
        metadata = {
            "dataset_id": dataset_id,
            "title": dataset.title,
            "description": dataset.description,
            "platform": dataset.platform,
            "tactics": dataset.tactics,
            "techniques": dataset.techniques,
            "files": downloaded_files,
            "total_size": total_size,
            "downloaded_at": str(os.popen("date -Iseconds").read().strip()),
        }

        try:
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2, default=str)
        except Exception as e:
            errors.append(f"Failed to save metadata: {e}")

        success = len(downloaded_files) > 0 and len(errors) == 0

        return DatasetDownloadResult(
            dataset_id=dataset_id,
            success=success,
            local_path=str(output_path),
            files=downloaded_files,
            total_size=total_size,
            error="; ".join(errors) if errors else None,
        )

    def verify(self, dataset_id: str, local_path: str) -> DatasetVerifyResult:
        """
        Verify downloaded dataset integrity.

        Args:
            dataset_id: OTRF dataset ID
            local_path: Local path where dataset was downloaded

        Returns:
            DatasetVerifyResult with verification status
        """
        result = DatasetVerifyResult(
            dataset_id=dataset_id,
            valid=True,
            files_checked=0,
            total_files=0,
            errors=[],
        )

        metadata_path = Path(local_path) / "metadata.json"
        if not metadata_path.exists():
            result.valid = False
            result.errors.append("Metadata file not found")
            return result

        try:
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
        except Exception as e:
            result.valid = False
            result.errors.append(f"Failed to read metadata: {e}")
            return result

        files = metadata.get("files", [])
        result.total_files = len(files)

        for file_info in files:
            file_path = Path(file_info.get("path", ""))

            if not file_path.exists():
                result.valid = False
                result.errors.append(f"Missing file: {file_info.get('filename', 'unknown')}")
                continue

            # Verify size
            actual_size = file_path.stat().st_size
            expected_size = file_info.get("size", 0)
            if expected_size and actual_size != expected_size:
                result.valid = False
                result.errors.append(
                    f"Size mismatch for {file_info.get('filename')}: "
                    f"expected {expected_size}, got {actual_size}"
                )
                continue

            # Verify checksum if available
            expected_checksum = file_info.get("checksum")
            if expected_checksum:
                hasher = hashlib.sha256()
                with open(file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        hasher.update(chunk)

                if hasher.hexdigest() != expected_checksum:
                    result.valid = False
                    result.errors.append(
                        f"Checksum mismatch for {file_info.get('filename')}"
                    )
                    continue

            result.files_checked += 1

        return result

    def get_download_size(self, dataset_id: str) -> Optional[int]:
        """
        Estimate total download size for a dataset.

        Args:
            dataset_id: OTRF dataset ID

        Returns:
            Estimated size in bytes, or None if unknown
        """
        dataset = self.catalog.get_dataset(dataset_id)
        if not dataset:
            return None

        total_size = 0
        for file_info in dataset.files:
            if not file_info.link:
                continue

            try:
                # HEAD request to get content-length
                response = requests.head(file_info.link, timeout=10)
                size = int(response.headers.get("content-length", 0))
                total_size += size
            except Exception:
                pass

        return total_size if total_size > 0 else None
