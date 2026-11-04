"""FastAPI routes for Mordor dataset management."""

import hashlib
import json
import logging
import os
import shutil
import yaml
import httpx
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field

try:
    from .lab_routes import _agent as _lab_agent, require_lab_admin
except ImportError:
    from lab_routes import _agent as _lab_agent, require_lab_admin

router = APIRouter(prefix="/api/mordor", tags=["mordor"])
logger = logging.getLogger(__name__)

# Configuration
GITHUB_API = "https://api.github.com/repos/OTRF/Security-Datasets"
RAW_GITHUB = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master"
CACHE_TTL_HOURS = 24
CACHE_DIR = Path("/tmp/elrond/output/mordor/cache")
STORAGE_DIR = Path("/tmp/elrond/output/mordor")


# ============================================
# Pydantic Models
# ============================================

class DatasetListItem(BaseModel):
    """Dataset list item for API responses."""
    dataset_id: str
    title: str
    description: Optional[str] = None
    platform: str = "Unknown"
    tactics: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)
    status: str = "available"
    total_size: Optional[int] = None
    files_count: int = 0
    local_path: Optional[str] = None
    downloaded_at: Optional[str] = None


class DatasetListResponse(BaseModel):
    """Response for dataset list endpoints."""
    datasets: List[DatasetListItem]
    total: int
    platforms: Dict[str, int] = Field(default_factory=dict)
    tactics: Dict[str, int] = Field(default_factory=dict)


class DatasetDetail(BaseModel):
    """Detailed dataset information."""
    dataset_id: str
    title: str
    description: Optional[str] = None
    platform: str = "Unknown"
    dataset_type: str = "atomic"
    tactics: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)
    files: List[dict] = Field(default_factory=list)
    simulation: Optional[dict] = None
    contributors: List[dict] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    status: str = "available"
    local_path: Optional[str] = None
    download_progress: int = 0
    downloaded_at: Optional[str] = None


class DownloadRequest(BaseModel):
    """Request to download a dataset."""
    output_dir: Optional[str] = None


class DownloadResponse(BaseModel):
    """Response for download request."""
    dataset_id: str
    status: str
    message: str
    task_id: Optional[str] = None
    local_path: Optional[str] = None


class VerifyResponse(BaseModel):
    """Response for verification request."""
    dataset_id: str
    valid: bool
    files_checked: int = 0
    total_files: int = 0
    errors: List[str] = Field(default_factory=list)


# ============================================
# Catalog Management
# ============================================

class MordorCatalog:
    """Manages the OTRF Security Datasets catalog."""

    def __init__(self):
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self.cache_file = CACHE_DIR / "catalog_index.json"
        self._index: Optional[Dict] = None
        self.github_token = os.environ.get("MORDOR_GITHUB_TOKEN")

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        return headers

    def _load_cache(self) -> Optional[Dict]:
        if not self.cache_file.exists():
            return None
        try:
            with open(self.cache_file, "r") as f:
                data = json.load(f)
            last_updated = datetime.fromisoformat(data.get("last_updated", "2000-01-01"))
            if datetime.now() - last_updated < timedelta(hours=CACHE_TTL_HOURS):
                return data
        except Exception as e:
            print(f"Warning: Failed to load cache: {e}")
        return None

    def _save_cache(self, data: Dict):
        try:
            with open(self.cache_file, "w") as f:
                json.dump(data, f, default=str, indent=2)
        except Exception as e:
            print(f"Warning: Failed to save cache: {e}")

    def _fetch_metadata_files(self) -> List[str]:
        metadata_urls = []
        for dataset_type in ["atomic", "compound"]:
            url = f"{GITHUB_API}/contents/datasets/{dataset_type}/_metadata"
            try:
                response = httpx.get(url, headers=self._get_headers(), timeout=30.0)
                if response.status_code == 200:
                    files = response.json()
                    for f in files:
                        if f["name"].endswith(".yaml") or f["name"].endswith(".yml"):
                            metadata_urls.append(f["download_url"])
                elif response.status_code == 403:
                    print("Warning: Rate limited by GitHub API")
                    break
            except Exception as e:
                print(f"Warning: Failed to fetch metadata list: {e}")
        return metadata_urls

    def _parse_metadata_file(self, url: str) -> Optional[Dict]:
        try:
            response = httpx.get(url, timeout=30.0)
            response.raise_for_status()
            data = yaml.safe_load(response.text)
            if not data or not isinstance(data, dict):
                return None

            # Extract attack mappings
            tactics = set()
            techniques = set()
            for mapping in data.get("attack_mappings", []):
                if isinstance(mapping, dict):
                    if mapping.get("technique"):
                        techniques.add(mapping["technique"])
                    tactics.update(mapping.get("tactics", []))

            # Parse files
            files = []
            for f in data.get("files", []):
                if isinstance(f, dict):
                    files.append({
                        "type": f.get("type", "Unknown"),
                        "link": f.get("link", ""),
                    })

            # Normalize platform (can be a string or list in OTRF metadata)
            platform = data.get("platform", "Unknown")
            if isinstance(platform, list):
                platform = platform[0] if platform else "Unknown"

            return {
                "dataset_id": data.get("id", ""),
                "title": data.get("title", "Untitled"),
                "description": data.get("description"),
                "platform": platform,
                "dataset_type": data.get("type", "atomic"),
                "tactics": sorted(list(tactics)),
                "techniques": sorted(list(techniques)),
                "files": files,
                "tags": data.get("tags", []),
                "references": data.get("references", []),
                "source_url": url,
                "creation_date": data.get("creation_date"),
            }
        except Exception as e:
            print(f"Warning: Failed to parse {url}: {e}")
            return None

    def refresh(self, force: bool = False) -> int:
        if not force:
            cached = self._load_cache()
            if cached:
                self._index = cached
                return cached.get("total_count", 0)

        print("Fetching metadata from OTRF...")
        metadata_urls = self._fetch_metadata_files()

        if not metadata_urls:
            cached = self._load_cache()
            if cached:
                self._index = cached
                return cached.get("total_count", 0)
            return 0

        print(f"Parsing {len(metadata_urls)} metadata files...")
        datasets = []

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._parse_metadata_file, url): url for url in metadata_urls}
            for future in as_completed(futures):
                result = future.result()
                if result and result.get("dataset_id"):
                    datasets.append(result)

        # Compute statistics
        platforms = {}
        tactics = {}
        for ds in datasets:
            platforms[ds["platform"]] = platforms.get(ds["platform"], 0) + 1
            for tactic in ds.get("tactics", []):
                tactics[tactic] = tactics.get(tactic, 0) + 1

        self._index = {
            "last_updated": datetime.now().isoformat(),
            "datasets": datasets,
            "total_count": len(datasets),
            "platforms": platforms,
            "tactics": tactics,
        }

        self._save_cache(self._index)
        return len(datasets)

    def list_datasets(self, platform=None, tactic=None, technique=None, search=None, limit=50, offset=0) -> List[Dict]:
        if not self._index:
            self.refresh()
        if not self._index:
            return []

        datasets = self._index.get("datasets", [])

        if platform:
            datasets = [d for d in datasets if d.get("platform", "").lower() == platform.lower()]
        if tactic:
            datasets = [d for d in datasets if tactic.lower() in [t.lower() for t in d.get("tactics", [])]]
        if technique:
            datasets = [d for d in datasets if technique.upper() in [t.upper() for t in d.get("techniques", [])]]
        if search:
            search_lower = search.lower()
            datasets = [d for d in datasets if search_lower in d.get("title", "").lower()
                       or search_lower in (d.get("description") or "").lower()
                       or d.get("dataset_id", "").lower().startswith(search_lower)]

        return datasets[offset:offset + limit]

    def get_dataset(self, dataset_id: str) -> Optional[Dict]:
        if not self._index:
            self.refresh()
        if not self._index:
            return None
        for ds in self._index.get("datasets", []):
            if ds.get("dataset_id") == dataset_id:
                return ds
        return None

    def get_statistics(self) -> Dict:
        if not self._index:
            self.refresh()
        if not self._index:
            return {"total": 0, "platforms": {}, "tactics": {}}
        return {
            "total": self._index.get("total_count", 0),
            "platforms": self._index.get("platforms", {}),
            "tactics": self._index.get("tactics", {}),
            "last_updated": self._index.get("last_updated"),
        }


# ============================================
# Storage Management
# ============================================

class MordorStorage:
    """Manages locally downloaded Mordor datasets."""

    def __init__(self):
        STORAGE_DIR.mkdir(parents=True, exist_ok=True)

    def get_dataset_path(self, dataset_id: str) -> Path:
        return STORAGE_DIR / dataset_id

    def dataset_exists(self, dataset_id: str) -> bool:
        metadata_path = self.get_dataset_path(dataset_id) / "metadata.json"
        return metadata_path.exists()

    def get_dataset_info(self, dataset_id: str) -> Optional[Dict]:
        dataset_path = self.get_dataset_path(dataset_id)
        metadata_path = dataset_path / "metadata.json"
        if not metadata_path.exists():
            return None
        try:
            with open(metadata_path, "r") as f:
                return json.load(f)
        except Exception:
            return None

    def list_local_datasets(self, status=None, limit=100, offset=0) -> List[Dict]:
        datasets = []
        if not STORAGE_DIR.exists():
            return datasets

        for item in sorted(STORAGE_DIR.iterdir()):
            if not item.is_dir() or item.name == "cache":
                continue
            metadata_path = item / "metadata.json"
            if not metadata_path.exists():
                continue
            try:
                with open(metadata_path, "r") as f:
                    metadata = json.load(f)
                datasets.append({
                    "dataset_id": metadata.get("dataset_id", item.name),
                    "title": metadata.get("title", "Unknown"),
                    "description": metadata.get("description"),
                    "platform": metadata.get("platform", "Unknown"),
                    "tactics": metadata.get("tactics", []),
                    "techniques": metadata.get("techniques", []),
                    "status": "downloaded",
                    "local_path": str(item),
                    "total_size": metadata.get("total_size", 0),
                    "downloaded_at": metadata.get("downloaded_at"),
                    "files_count": len(metadata.get("files", [])),
                })
            except Exception:
                continue

        return datasets[offset:offset + limit]

    def delete_dataset(self, dataset_id: str) -> bool:
        dataset_path = self.get_dataset_path(dataset_id)
        if not dataset_path.exists():
            return False
        try:
            shutil.rmtree(dataset_path)
            return True
        except Exception:
            return False

    def verify_dataset(self, dataset_id: str) -> Dict:
        result = {"valid": True, "files_checked": 0, "total_files": 0, "errors": []}
        dataset_path = self.get_dataset_path(dataset_id)
        metadata_path = dataset_path / "metadata.json"

        if not metadata_path.exists():
            result["valid"] = False
            result["errors"].append("Metadata file not found")
            return result

        try:
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
        except Exception as e:
            result["valid"] = False
            result["errors"].append(f"Failed to read metadata: {e}")
            return result

        files = metadata.get("files", [])
        result["total_files"] = len(files)

        for file_info in files:
            file_path = Path(file_info.get("path", ""))
            if not file_path.exists():
                result["valid"] = False
                result["errors"].append(f"Missing file: {file_info.get('filename', 'unknown')}")
                continue
            result["files_checked"] += 1

        return result


# ============================================
# Downloader
# ============================================

def download_dataset(catalog: MordorCatalog, storage: MordorStorage, dataset_id: str, output_dir: Optional[str] = None) -> Dict:
    """Download a dataset."""
    ds = catalog.get_dataset(dataset_id)
    if not ds:
        return {"success": False, "error": f"Dataset not found: {dataset_id}"}

    output_path = Path(output_dir) if output_dir else storage.get_dataset_path(dataset_id)
    output_path.mkdir(parents=True, exist_ok=True)

    downloaded_files = []
    total_size = 0
    errors = []

    for file_info in ds.get("files", []):
        link = file_info.get("link")
        if not link:
            continue

        filename = link.split("/")[-1]
        file_type = file_info.get("type", "Unknown")
        file_path = output_path / file_type / filename

        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)

            size = 0
            hasher = hashlib.sha256()
            with httpx.stream("GET", link, timeout=120.0) as response:
                response.raise_for_status()
                with open(file_path, "wb") as f:
                    for chunk in response.iter_bytes(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            hasher.update(chunk)
                            size += len(chunk)

            downloaded_files.append({
                "type": file_type,
                "filename": filename,
                "path": str(file_path),
                "size": size,
                "checksum": hasher.hexdigest(),
                "url": link,
            })
            total_size += size

        except Exception as e:
            errors.append(f"Failed to download {filename}: {e}")

    # Save metadata
    metadata = {
        "dataset_id": dataset_id,
        "title": ds.get("title"),
        "description": ds.get("description"),
        "platform": ds.get("platform"),
        "tactics": ds.get("tactics", []),
        "techniques": ds.get("techniques", []),
        "files": downloaded_files,
        "total_size": total_size,
        "downloaded_at": datetime.now().isoformat(),
    }

    metadata_path = output_path / "metadata.json"
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)

    return {
        "success": len(downloaded_files) > 0 and len(errors) == 0,
        "dataset_id": dataset_id,
        "local_path": str(output_path),
        "files": downloaded_files,
        "total_size": total_size,
        "errors": errors,
    }


# ============================================
# Initialize Components
# ============================================

catalog = MordorCatalog()
storage = MordorStorage()


# ============================================
# API Routes
# ============================================

@router.get("/catalog", response_model=DatasetListResponse)
async def get_catalog(
    platform: Optional[str] = Query(None, description="Filter by platform"),
    tactic: Optional[str] = Query(None, description="Filter by MITRE tactic"),
    technique: Optional[str] = Query(None, description="Filter by MITRE technique"),
    search: Optional[str] = Query(None, description="Search in title/description"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """Get available Mordor datasets from OTRF catalog."""
    try:
        datasets = catalog.list_datasets(
            platform=platform,
            tactic=tactic,
            technique=technique,
            search=search,
            limit=limit,
            offset=offset,
        )

        items = []
        for ds in datasets:
            local_info = storage.get_dataset_info(ds["dataset_id"])
            items.append(DatasetListItem(
                dataset_id=ds["dataset_id"],
                title=ds.get("title", "Unknown"),
                description=ds.get("description"),
                platform=ds.get("platform", "Unknown"),
                tactics=ds.get("tactics", []),
                techniques=ds.get("techniques", []),
                status="downloaded" if local_info else "available",
                total_size=local_info.get("total_size") if local_info else None,
                files_count=len(ds.get("files", [])),
                local_path=local_info.get("local_path") if local_info else None,
                downloaded_at=local_info.get("downloaded_at") if local_info else None,
            ))

        stats = catalog.get_statistics()

        return DatasetListResponse(
            datasets=items,
            total=stats.get("total", len(items)),
            platforms=stats.get("platforms", {}),
            tactics=stats.get("tactics", {}),
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/catalog/refresh")
async def refresh_catalog(force: bool = Query(False)):
    """Refresh the dataset catalog from OTRF GitHub repository."""
    try:
        count = catalog.refresh(force=force)
        stats = catalog.get_statistics()

        return {
            "success": True,
            "message": f"Catalog refreshed: {count} datasets indexed",
            "total_datasets": count,
            "platforms": stats.get("platforms", {}),
            "last_updated": stats.get("last_updated"),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/datasets", response_model=DatasetListResponse)
async def get_local_datasets(
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """Get locally downloaded Mordor datasets."""
    try:
        local_datasets = storage.list_local_datasets(status=status, limit=limit, offset=offset)

        items = [DatasetListItem(**d) for d in local_datasets]

        platforms = {}
        for d in local_datasets:
            p = d.get("platform", "Unknown")
            platforms[p] = platforms.get(p, 0) + 1

        return DatasetListResponse(
            datasets=items,
            total=len(local_datasets),
            platforms=platforms,
            tactics={},
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/datasets/{dataset_id}", response_model=DatasetDetail)
async def get_dataset(dataset_id: str):
    """Get detailed information about a specific dataset."""
    try:
        ds = catalog.get_dataset(dataset_id)
        local_info = storage.get_dataset_info(dataset_id)

        if not ds and not local_info:
            raise HTTPException(status_code=404, detail="Dataset not found")

        if ds:
            return DatasetDetail(
                dataset_id=ds["dataset_id"],
                title=ds.get("title", "Unknown"),
                description=ds.get("description"),
                platform=ds.get("platform", "Unknown"),
                dataset_type=ds.get("dataset_type", "atomic"),
                tactics=ds.get("tactics", []),
                techniques=ds.get("techniques", []),
                files=ds.get("files", []),
                tags=ds.get("tags", []),
                references=ds.get("references", []),
                status="downloaded" if local_info else "available",
                local_path=local_info.get("local_path") if local_info else None,
                download_progress=100 if local_info else 0,
                downloaded_at=local_info.get("downloaded_at") if local_info else None,
            )
        else:
            return DatasetDetail(
                dataset_id=dataset_id,
                title=local_info.get("title", "Unknown"),
                description=local_info.get("description"),
                platform=local_info.get("platform", "Unknown"),
                dataset_type="unknown",
                tactics=local_info.get("tactics", []),
                techniques=local_info.get("techniques", []),
                files=local_info.get("files", []),
                status="downloaded",
                local_path=local_info.get("local_path"),
                download_progress=100,
                downloaded_at=local_info.get("downloaded_at"),
            )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/datasets/{dataset_id}/download", response_model=DownloadResponse)
async def download_dataset_endpoint(
    dataset_id: str,
    request: DownloadRequest,
    background_tasks: BackgroundTasks,
):
    """Start downloading a dataset."""
    try:
        ds = catalog.get_dataset(dataset_id)
        if not ds:
            raise HTTPException(status_code=404, detail="Dataset not found in catalog")

        if storage.dataset_exists(dataset_id):
            local_info = storage.get_dataset_info(dataset_id)
            return DownloadResponse(
                dataset_id=dataset_id,
                status="downloaded",
                message="Dataset already downloaded",
                local_path=local_info.get("local_path") if local_info else None,
            )

        def run_download():
            download_dataset(catalog, storage, dataset_id, request.output_dir)

        background_tasks.add_task(run_download)

        return DownloadResponse(
            dataset_id=dataset_id,
            status="downloading",
            message="Download started",
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/datasets/{dataset_id}")
async def delete_dataset_endpoint(dataset_id: str):
    """Delete a locally downloaded dataset."""
    try:
        if not storage.dataset_exists(dataset_id):
            raise HTTPException(status_code=404, detail="Dataset not found locally")

        if storage.delete_dataset(dataset_id):
            return {"success": True, "message": f"Dataset {dataset_id} deleted successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to delete dataset")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/datasets/{dataset_id}/verify", response_model=VerifyResponse)
async def verify_dataset_endpoint(dataset_id: str):
    """Verify the integrity of a downloaded dataset."""
    try:
        if not storage.dataset_exists(dataset_id):
            raise HTTPException(status_code=404, detail="Dataset not found locally")

        result = storage.verify_dataset(dataset_id)

        return VerifyResponse(
            dataset_id=dataset_id,
            valid=result["valid"],
            files_checked=result["files_checked"],
            total_files=result["total_files"],
            errors=result.get("errors", []),
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# Recorded attack telemetry (src/mordor/telemetry, ported from Archer)
# ============================================
# Which logs record each ATT&CK technique, from OTRF Security-Datasets, Splunk
# attack_data, EVTX-to-MITRE-Attack and the lab's own recordings
# (./lab.sh mordor-record), plus Microsoft GUIDE's Defender XDR alerting.
# Reading is open; Update (a rebuild from the sources) is admin-only.

TELEMETRY_ROOT = os.environ.get("ROWANHOLT_SRC_ROOT", "/opt/rowanholt")


def _telemetry():
    """(check, datasets), reloading the data if a build has rewritten it since. A build in this
    process clears the caches itself; this catches the CLI's and the lab agent's."""
    import sys

    if TELEMETRY_ROOT not in sys.path:
        sys.path.append(TELEMETRY_ROOT)  # appended: /app's modules keep priority
    try:
        from src.mordor.telemetry import check, datasets as ds
    except ImportError as e:
        raise HTTPException(status_code=503, detail=f"Telemetry package not mounted at {TELEMETRY_ROOT}: {e}")
    if _build_job["state"] == "running":
        return check, ds  # a build rewrites the files as it goes; keep the loaded data till it's done
    stamp = tuple(os.path.getmtime(p) if os.path.exists(p) else 0
                  for p in (ds.SUMMARY_PATH, ds.VALUES_PATH, ds.LOCAL_SUMMARY_PATH, ds.LOCAL_VALUES_PATH))
    if ds._cache.get("stamp") != stamp:
        ds._cache.clear()
        ds._cache["stamp"] = stamp
    return check, ds


def _telemetry_filters(ds, collections: str, platforms: str):
    picked_collections = [c for c in (collections or "").split(",") if c in ds.COLLECTIONS] or None
    picked_platforms = [p for p in (platforms or "").split(",") if p in ds.PLATFORMS] or None
    return picked_collections, picked_platforms


class TelemetryDetection(BaseModel):
    """A detection to check against the recordings: indicators by kind (cmd, file, reg, network, ...)."""
    technique_id: str
    name: str = ""
    indicators: Dict[str, List[str]] = Field(default_factory=dict)


class TelemetryNoisyRequest(BaseModel):
    indicators: List[str] = Field(default_factory=list)
    technique_id: Optional[str] = None


def _guide():
    from src.mordor.telemetry import guide

    return guide


@router.get("/telemetry/status")
async def telemetry_status():
    """The sources built, how many recordings and techniques, whether field values are here,
    Microsoft GUIDE's summary, and the state of an Update."""
    _, ds = _telemetry()
    summary = ds.load()
    g = _guide().load()
    lab_runs = sorted({d["id"].split(":", 1)[1].split("/", 1)[0] for d in summary["datasets"] if d["source"] == "lab"})
    return {"sources": summary.get("sources", {}), "datasets": len(summary["datasets"]),
            "techniques": len(ds.covered()), "values": ds.values() is not None,
            "per_source": {k: sum(1 for d in summary["datasets"] if d["source"] == k) for k in summary.get("sources", {})},
            "lab_runs": lab_runs,
            "guide": {**g["source"], "techniques": len(g["techniques"])} if g else None,
            "build": {**_build_job, "log": list(_build_log)[-40:]}}


# Update: one rebuild at a time, in a thread, its log polled through /telemetry/status
import threading  # noqa: E402
from collections import deque  # noqa: E402

_build_job: Dict[str, Any] = {"state": "idle", "started": None, "finished": None, "error": None, "sources": []}
_build_log: deque = deque(maxlen=400)
_build_lock = threading.Lock()


def _buildable_sources() -> List[str]:
    """The public sources this backend can rebuild. EVTX-to-MITRE-Attack's files are binary .evtx,
    which need the evtx package; without it a rebuild would drop those recordings, so it's left out.
    macOS-ATTACK-DATASET is GPL-3.0 and local-only; it's rebuilt from the CLI if wanted."""
    try:
        import evtx  # noqa: F401
        return ["splunk", "otrf", "evtx"]
    except ImportError:
        return ["splunk", "otrf"]


@router.post("/telemetry/build")
async def telemetry_build(user: dict = Depends(require_lab_admin)):
    """Fetch what the public sources changed since the last build and rebuild (admin)."""
    check, ds = _telemetry()
    sources = _buildable_sources()
    with _build_lock:
        if _build_job["state"] == "running":
            raise HTTPException(status_code=409, detail="An update is already running")
        _build_job.update(state="running", started=datetime.utcnow().isoformat() + "Z", finished=None,
                          error=None, sources=sources)
        _build_log.clear()

    def say(line: str):
        _build_log.append(f"{datetime.now().strftime('%H:%M:%S')}  {line}")

    def work():
        from src.mordor.telemetry.__main__ import build

        try:
            say(f"Updating {', '.join(sources)} (only what changed is fetched)")
            build(tuple(sources), log=say)
            check._haystack.clear()
            _build_job.update(state="done", finished=datetime.utcnow().isoformat() + "Z")
        except Exception as e:  # noqa: BLE001 — a failed fetch must not take the API down
            _build_job.update(state="error", finished=datetime.utcnow().isoformat() + "Z", error=str(e))
            say(f"Failed: {e}")

    threading.Thread(target=work, daemon=True).start()
    return {"started": True, "sources": sources, "by": user.get("username")}


@router.get("/telemetry/techniques")
async def telemetry_techniques(collections: str = Query(""), platforms: str = Query("")):
    """Every recorded technique, one row each."""
    check, ds = _telemetry()
    picked = _telemetry_filters(ds, collections, platforms)
    return {"techniques": check.overview(*picked), "collections": ds.COLLECTIONS, "platforms": ds.PLATFORMS}


@router.get("/telemetry/technique/{technique_id}")
async def telemetry_technique(technique_id: str, collections: str = Query(""), platforms: str = Query("")):
    """A technique's recordings, the event types they hold and the Defender/UDM sources they need."""
    check, ds = _telemetry()
    tid = technique_id[:20]
    return {**check.technique(tid, *_telemetry_filters(ds, collections, platforms)),
            "defender": _guide().for_technique(tid)}


@router.get("/telemetry/data-sources")
async def telemetry_data_sources(collections: str = Query(""), platforms: str = Query("")):
    """For each Defender table / UDM event type, the techniques it records."""
    check, ds = _telemetry()
    return check.by_data_source(*_telemetry_filters(ds, collections, platforms))


@router.get("/telemetry/search")
async def telemetry_search(q: str = Query(..., min_length=3)):
    """{technique: [logs]} whose recorded events hold a field value containing q ('…' for a gap)."""
    check, _ = _telemetry()
    found = check.search(q[:200])
    if found is None:
        raise HTTPException(status_code=404, detail="No field values on this machine (run --build)")
    return {"techniques": found}


@router.post("/telemetry/check")
async def telemetry_check(detection: TelemetryDetection):
    """A detection's indicators against its technique's recordings and everyone else's."""
    check, _ = _telemetry()
    return check.check(detection.model_dump())


@router.post("/telemetry/noisy")
async def telemetry_noisy(req: TelemetryNoisyRequest):
    """Which indicators also turn up while many unrelated techniques ran."""
    check, _ = _telemetry()
    return check.noisy(indicators=req.indicators or None, technique_id=req.technique_id or "")


# ============================================
# Mordor lab: the machines recordings run on (src/mordor/lab, ported from Archer)
# ============================================
# Docker, Tart and UTM are on the host, so these proxy to the lab agent (lab/agent/mordor_api.py),
# admin-only like the rest of the lab. Slow actions start an agent run; poll /api/lab/runs/{id}.


class MordorLabRequest(BaseModel):
    engine: str = ""
    name: str = ""
    action: str = ""
    snapshot: str = ""
    template: str = ""
    new_name: str = ""
    os: str = ""
    step: str = ""
    path: str = ""
    techniques: str = ""
    run_name: str = ""
    revert_to: str = ""
    settle: int = 20
    timeout: int = 120
    execute: bool = False


@router.get("/lab/overview")
async def mordor_lab_overview(_: dict = Depends(require_lab_admin)):
    """This host, the machines it can create, the machines there are, and any running job."""
    return await _lab_agent("GET", "/mordor/overview")


@router.get("/lab/logs")
async def mordor_lab_logs(engine: str, name: str, _: dict = Depends(require_lab_admin)):
    return await _lab_agent("GET", "/mordor/logs", params={"engine": engine, "name": name})


@router.get("/lab/provision-steps")
async def mordor_lab_provision_steps(os: str, _: dict = Depends(require_lab_admin)):
    return await _lab_agent("GET", "/mordor/provision-steps", params={"os": os})


@router.post("/lab/{verb}")
async def mordor_lab_post(verb: str, req: MordorLabRequest, user: dict = Depends(require_lab_admin)):
    """create, action, adopt, clone, verify-iso, provision, record."""
    if verb not in ("create", "action", "adopt", "clone", "verify-iso", "provision", "record"):
        raise HTTPException(status_code=404, detail="Unknown lab action")
    if verb != "verify-iso" and not (verb == "record" and not req.execute):
        logger.info(f"Mordor lab {verb} by {user.get('username')}: {req.engine} {req.name} {req.action}".strip())
    return await _lab_agent("POST", f"/mordor/{verb}", json=req.model_dump())
