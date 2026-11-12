"""
Job Models

Database models for analysis jobs and results.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator


class JobStatus(str, Enum):
    """Job status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"  # Elrond process group stopped with SIGSTOP
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ARCHIVED = "archived"
    AWAITING_CONFIRMATION = "awaiting_confirmation"  # Removing the old output failed: retry or give up?
    REMOVING = "removing"  # The worker is removing the old output, confirmed (output_removal.py)


class AnalysisOptions(BaseModel):
    """Analysis options configuration."""
    # Main operation modes (mutually exclusive)
    # local: Collect artifacts from disk image and process (default)
    # gandalf: Process pre-collected Gandalf artifacts (no collection)
    # network: Process network evidence: PCAP through Zeek, Zeek logs, NetFlow exports
    local: bool = True  # Default mode - collect from disk image
    gandalf: bool = False  # Alternative mode - process pre-collected artifacts
    network: bool = False  # PCAPs, Zeek logs and NetFlow exports (elrond.py --Network)
    mobile: bool = False  # Phones: iTunes/Finder and ADB backups, bug reports, file system extractions (--Mobile)

    # Analysis options
    analysis: bool = False
    extract_iocs: bool = False
    # With extract_iocs on a macOS image, read the sealed system volume too (--iocsSystemVolume): left out
    # by default, as analysis/iocs.py macos_system_volume_included explains
    ioc_system_volume: bool = False
    iocs_file: Optional[str] = None  # Optional IOC watchlist file
    misplaced_binaries: bool = False  # Find system binaries in unexpected locations (T1036.005)
    masquerading: bool = False  # Detect masquerading: RLO, double ext, spaces, renamed utils (T1036)
    clamav: bool = False  # ClamAV over collected files and user-writable folders (post/clam.py)
    timeline: bool = False
    memory: bool = False
    memory_timeline: bool = False

    # Advanced processing options
    keywords: bool = False
    keywords_file: Optional[str] = None
    yara: bool = False
    yara_dir: Optional[str] = None
    collectFiles: bool = False
    collectFiles_filter: Optional[str] = None

    # Speed/Quality modes (merged into analysis)
    brisk: bool = False
    mordor: bool = False  # Aggressive threat-hunting mode

    # Collection options
    vss: bool = False
    userprofiles: bool = False
    # Collect files options (matching file selection menu)
    collect_files_all: bool = False  # Collect ALL file types
    collect_files_archive: bool = False  # Collect archive files
    collect_files_bin: bool = False  # Collect binary/executable files
    collect_files_docs: bool = False  # Collect document files
    collect_files_hidden: bool = False  # Collect hidden files
    collect_files_lnk: bool = False  # Collect LNK/shortcut files
    collect_files_mail: bool = False  # Collect email files
    collect_files_scripts: bool = False  # Collect script files
    collect_files_unalloc: bool = False  # Carve unallocated space
    collect_files_virtual: bool = False  # Collect virtual machine files
    collect_files_web: bool = False  # Collect web-related files

    # Verification options
    nsrl: bool = False
    hash_collected: bool = False
    hash_all: bool = False

    # Output options
    splunk: bool = False
    elastic: bool = False
    opensearch: bool = False  # OpenSearch or Wazuh's indexer (OPENSEARCH_URL)
    timesketch: bool = False  # a timeline per host in Timesketch (TIMESKETCH_URL)
    navigator: bool = False
    threat_intel: bool = False  # match the case against the stored threat intelligence indicators

    # Post-processing
    delete: bool = False
    archive: bool = False
    save_template: bool = False  # Save options as template to output directory

    # Internal options
    force_overwrite: bool = False
    # Set by the API only (whatever a request sends is replaced): the job whose output folder this
    # one may remove, once the API has checked the caller may manage it, and whether the job was
    # created since output folders carry a marker (output_removal.py). Jobs from before have neither
    replaces_output_of: Optional[str] = None
    output_marker: bool = False

    # Logging options
    debug: bool = False  # Enable verbose debug messages in job log


class JobCreate(BaseModel):
    """Job creation request."""
    case_number: str = Field(..., description="Investigation/Case/Incident Number")
    source_paths: list[str] = Field(..., description="List of source paths to disk/memory images")
    destination_path: Optional[str] = Field(None, description="Destination directory for output")
    options: AnalysisOptions = Field(default_factory=AnalysisOptions)
    # An encrypted phone backup's password: handed to the worker through Redis (backup_secrets.py),
    # never stored with the job, never in its dumps or its repr
    backup_password: Optional[SecretStr] = Field(None, exclude=True, repr=False,
                                                 description="Password of an encrypted phone backup (Mobile jobs)")


class PendingAction(BaseModel):
    """Pending action awaiting user confirmation."""
    action_type: str  # "remove_output" ("sudo_remove_directory" before 12 November 2026)
    target_path: str  # Path to act on
    message: str  # Message to show user


class Job(BaseModel):
    """Analysis job."""
    id: str = Field(..., description="Unique job ID")
    case_number: str
    source_paths: list[str]
    destination_path: Optional[str]
    options: AnalysisOptions
    status: JobStatus = JobStatus.PENDING
    progress: int = Field(0, ge=0, le=100, description="Progress percentage")
    log: list[str] = Field(default_factory=list, description="Job log messages")
    result: Optional[Dict[str, Any]] = Field(None, description="Job results")
    error: Optional[str] = Field(None, description="Error message if failed")
    celery_task_id: Optional[str] = Field(None, description="Celery task ID for job control")
    pending_action: Optional[PendingAction] = Field(None, description="Action awaiting user confirmation")
    created_at: datetime = Field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    # From the job_access table, filled in by the API (server mode)
    owner: Optional[str] = Field(None, description="Username of the job's creator")
    shared_with: list[str] = Field(default_factory=list, description="Usernames it's shared with")

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


# Set by the worker or a job's own routes, never through PATCH: `status` would skip what cancel,
# pause and the removal routes do (kill the process group, release the image locks, audit), and
# `result` names the output folder a removal and the SIEM export fall back on
WORKER_FIELDS = ("status", "progress", "result", "error")


class JobUpdate(BaseModel):
    """What a client may change through `PATCH /api/jobs/{id}`: a note added to the job's log,
    by its owner or an admin. Status changes go through the job's own routes."""
    model_config = ConfigDict(extra="forbid")

    log_message: str = Field(..., min_length=1, max_length=2000)

    @model_validator(mode="before")
    @classmethod
    def _refuse_worker_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            taken = [name for name in WORKER_FIELDS if name in data]
            if taken:
                raise ValueError(
                    f"{', '.join(taken)} can't be set by a client: they're the worker's. Change a job's "
                    "status with POST /api/jobs/{id}/cancel, pause, resume, restart, archive or unarchive")
        return data


class JobListResponse(BaseModel):
    """Job list response."""
    jobs: list[Job]
    total: int


class FileSystemItem(BaseModel):
    """File system item (file or directory)."""
    name: str
    path: str
    is_directory: bool
    size: Optional[int] = None
    modified: Optional[datetime] = None
    is_image: bool = False

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class FileSystemBrowseResponse(BaseModel):
    """Response for file system browse endpoint."""
    items: List[FileSystemItem]
    current_path: str
    permission_warning: Optional[str] = None
    skipped_count: int = 0
