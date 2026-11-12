"""
Where a job may write, and removing a job's old output: the only folder Rowanholt ever deletes.

A fresh run (`force_overwrite` on a new job, a fresh restart) wipes the job's output folder first.
The worker mounts evidence read-write, because output is written beside the images, so a delete
aimed at the wrong folder destroys evidence. Every path the API accepts goes through `contained`,
and every removal through `check_removal`, in the worker, just before it deletes:

- the folder is inside one of the allowed folders, never one of them or above one, with no
  symbolic link below the allowed folder and no `..` (`contained`);
- it is Rowanholt's: the marker the worker writes when it creates a job's output folder names this
  job (or the one it replaces, which the API checked the caller may manage), or, for output from
  before the marker, it's the job's own recorded destination and holds the job's log
  (`owner_refusal`);
- nothing in it is evidence (any job's source), an allowed folder, another job's output, or a
  mount (an image Elrond mounted, a bind mount): compared by path, with the spellings of one host
  folder treated as one (`ALIASES`), and again by device and inode while walking it;
- no job that's still going writes inside it, at it or around it.

`remove_tree` then deletes without following symbolic links or crossing onto another device, and
the folder must be gone afterwards. Run the checks in the worker, which is the container that
deletes: the backend may not see the folder at all (finding 8 of the 12 November 2026 review).
"""

import json
import logging
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

# Written by the worker into each output folder it creates: {"job_id": ...}
MARKER = ".rowanholt-output"
# The worker's spool of the whole job log, at the top of every output folder since it was added:
# how output from before the marker is recognised
JOB_LOG = "rowanholt_job.log"

# Statuses of a job that's still going, or waiting to: its output must be left alone
ACTIVE_STATUSES = ("pending", "running", "paused", "awaiting_confirmation", "removing")

# One host folder, three spellings: the compose file mounts the host's /tmp/rowanholt at
# /tmp/rowanholt (read-only in the backend), at /host/tmp/rowanholt (the backend) and at
# /tmp/elrond/output (both). Paths are compared after mapping each to the last.
ALIASES = (("/host/tmp/rowanholt", "/tmp/elrond/output"), ("/tmp/rowanholt", "/tmp/elrond/output"))

# Where Elrond mounts images and shadow copies in the worker (rowanholt/core): never an output
ELROND_MOUNTS = ("elrond_mount", "shadow_mount", "vss", "ewf_mount")


class PathRefused(ValueError):
    """A path Rowanholt won't read, write or remove; the message says why, for the person."""


class RemovalFailed(OSError):
    """The removal ran but the folder is still there."""


def translate_path_for_worker(path_str: str) -> str:
    """The worker's spelling of a path the backend accepted. Both containers mount the uploads
    volume at /tmp/elrond/uploads; the host's /tmp/rowanholt is /host/tmp/rowanholt in the backend
    and /tmp/elrond/output in the worker. Anything else is the same in both."""
    path_str = str(path_str)
    if path_str.startswith("/tmp/elrond/uploads/"):
        return path_str
    if path_str == "/host/tmp/rowanholt" or path_str.startswith("/host/tmp/rowanholt/"):
        return "/tmp/elrond/output" + path_str[len("/host/tmp/rowanholt"):]
    return path_str


def _normal(path) -> PurePosixPath:
    return PurePosixPath(os.path.normpath(str(path)))


def place(path) -> PurePosixPath:
    """A path as compared with others: normalised, with the aliases of one host folder made one."""
    normal = _normal(path)
    for alias, canonical in ALIASES:
        if normal == PurePosixPath(alias) or normal.is_relative_to(alias):
            return PurePosixPath(canonical) / normal.relative_to(alias)
    return normal


def _overlap(a: PurePosixPath, b: PurePosixPath) -> bool:
    return a == b or a.is_relative_to(b) or b.is_relative_to(a)


def _spellings(root: str) -> List[Path]:
    """A configured folder as written and as resolved (macOS's /tmp is /private/tmp)."""
    lexical = Path(os.path.normpath(os.path.abspath(root)))
    try:
        real = lexical.resolve()
    except (OSError, RuntimeError):
        real = lexical
    return [lexical] if real == lexical else [lexical, real]


def contained(path, roots: Iterable[str], *, allow_root: bool = False, must_exist: bool = False) -> Path:
    """The path, normalised, when it's inside one of the allowed folders; PathRefused otherwise.

    Not a prefix match (`/tmp/rowanholtX` isn't inside `/tmp/rowanholt`), no `..` anywhere, and
    no symbolic link below the allowed folder, where whoever can write evidence could plant one
    (the allowed folders themselves are configuration, and trusted). Unless `allow_root` (a source
    may be a whole allowed folder: reading it destroys nothing), the path may be neither an allowed
    folder nor above one. `must_exist` refuses a path that isn't there."""
    text = str(path or "")
    if not text or "\x00" in text:
        raise PathRefused("No path given")
    raw = Path(text)
    if not raw.is_absolute():
        raise PathRefused(f"{text} isn't an absolute path")
    if ".." in raw.parts:
        raise PathRefused(f"{text}: '..' isn't allowed in a path")
    candidate = Path(os.path.normpath(text))
    roots = [root for root in roots if root]
    best: Optional[Path] = None
    for root in roots:
        for spelling in _spellings(root):
            if not allow_root and spelling.is_relative_to(candidate):
                what = "one of the allowed folders" if spelling == candidate else f"above the allowed folder {spelling}"
                raise PathRefused(f"{text} is {what}: choose a folder inside it")
            if candidate.is_relative_to(spelling) and (best is None or len(spelling.parts) > len(best.parts)):
                best = spelling
    if best is None:
        raise PathRefused(f"{text} is outside the folders Rowanholt may use ({', '.join(roots)})")
    current = best
    for part in candidate.relative_to(best).parts:
        current = current / part
        if current.is_symlink():
            raise PathRefused(f"{text}: {current} is a symbolic link")
        if not current.exists():
            break  # nothing below a missing folder can be a link yet
    if must_exist and not candidate.exists():
        raise PathRefused(f"{text} doesn't exist")
    return candidate


def in_elrond_mount(path) -> bool:
    """Whether the path is in a folder Elrond mounts an image or shadow copy at."""
    parts = _normal(path).parts
    return len(parts) >= 3 and parts[1] == "mnt" and parts[2].startswith(ELROND_MOUNTS)


def recorded_output(job, translate: Callable[[str], str] = lambda p: p) -> Optional[PurePosixPath]:
    """Where the job writes, as recorded at creation (or by its last run), in `translate`'s spelling."""
    path = job.destination_path or ((job.result or {}).get("output_directory"))
    return _normal(translate(path)) if path else None


def _status(job) -> str:
    return getattr(job.status, "value", job.status)


def _options(job, name: str, default=None):
    return getattr(job.options, name, default)


def destination_refusal(destination, job_id: Optional[str], sources: Sequence[str], jobs: Iterable,
                        translate: Callable[[str], str] = lambda p: p) -> Optional[str]:
    """Why a job (job_id; None for a new one) mustn't write to this destination, or None: it
    would hold evidence (its own sources or another job's), it's a folder Elrond mounts images at,
    or another job that's still going writes at, in or around it. Compared by path; the worker
    compares by device and inode as well, before it removes anything."""
    target = place(translate(str(destination)))
    if in_elrond_mount(destination):
        return f"{destination} is where Elrond mounts images"
    for source in sources:
        where = place(translate(source))
        if where == target or where.is_relative_to(target):
            return f"{destination} would hold the evidence {source}: choose a folder beside it"
    for other in jobs:
        if other.id == job_id:
            continue
        for source in other.source_paths or []:
            where = place(translate(source))
            if where == target or where.is_relative_to(target):
                return f"{destination} holds the evidence of case {other.case_number}"
        output = recorded_output(other, translate)
        if output is None:
            continue
        output = place(output)
        if _status(other) in ACTIVE_STATUSES and _overlap(output, target):
            return f"{destination} overlaps the output of case {other.case_number}, which is {_status(other)}"
    return None


# ── Who an output folder belongs to ──────────────────────────────────────────

def read_marker(folder) -> Optional[str]:
    """The job ID in the folder's marker, or None (no marker, a link, unreadable)."""
    path = Path(folder) / MARKER
    try:
        if path.is_symlink() or not path.is_file():
            return None
        job_id = json.loads(path.read_text(encoding="utf-8")[:4096]).get("job_id")
    except (OSError, ValueError, AttributeError):
        return None
    return str(job_id) if job_id else None


def write_marker(folder, job_id: str) -> None:
    """Mark the folder as this job's output. Raises OSError when it can't be written."""
    (Path(folder) / MARKER).write_text(
        json.dumps({"job_id": job_id, "written": datetime.now().isoformat(timespec="seconds")}) + "\n",
        encoding="utf-8")


def legacy_owner(folder, jobs: Iterable, translate: Callable[[str], str] = lambda p: p) -> Optional[str]:
    """For a folder from before the marker: the most recent job from before the marker whose
    recorded output it is, when it holds a job log; None otherwise."""
    if not (Path(folder) / JOB_LOG).is_file():
        return None
    folder_place = place(translate(str(folder)))
    candidates = [job for job in jobs if not _options(job, "output_marker", False)
                  and recorded_output(job, translate) is not None
                  and place(recorded_output(job, translate)) == folder_place]
    if not candidates:
        return None
    return max(candidates, key=lambda job: job.created_at).id


def folder_owner(folder, jobs: Iterable, translate: Callable[[str], str] = lambda p: p) -> Optional[str]:
    """The job an existing output folder belongs to: its marker's, else (from before the marker)
    the job whose recorded output it is. None when it isn't Rowanholt's."""
    jobs = list(jobs)
    marked = read_marker(folder)
    if marked:
        # A marker copied into another folder doesn't make it that job's: its record must agree
        # (a job since deleted has no record to ask, so the API leaves that one to an admin)
        marker_job = next((job for job in jobs if job.id == marked), None)
        if marker_job is not None and not _records(marker_job, folder, translate):
            return None
        return marked
    return legacy_owner(folder, jobs, translate)


def _records(job, folder, translate: Callable[[str], str]) -> bool:
    """Whether the folder is the job's recorded output."""
    output = recorded_output(job, translate)
    return output is not None and place(output) == place(translate(str(folder)))


def owner_refusal(folder, job, jobs: Dict[str, object], translate: Callable[[str], str] = lambda p: p) -> Optional[str]:
    """Why this job mustn't remove the folder as its own output, or None. Accepted: a marker
    naming the job or the job it replaces (options.replaces_output_of, set only by the API after
    checking the caller may manage that job); or, with no marker, a job log in the folder and the
    folder recorded as the output of one of those jobs from before the marker."""
    accepted = [job.id]
    replaced = _options(job, "replaces_output_of")
    if replaced:
        accepted.append(replaced)
    marked = read_marker(folder)
    if marked is not None:
        if marked not in accepted:
            return f"{folder} is the output of another job ({marked})"
        # The folder came from this job's own record; the job it replaces must have recorded it too
        replaced_job = jobs.get(marked) if marked != job.id else None
        if replaced_job is not None and not _records(replaced_job, folder, translate):
            return f"{folder} isn't the recorded output folder of the job it replaces"
        return None
    candidates = [candidate for candidate in (job, jobs.get(replaced) if replaced else None)
                  if candidate is not None and not _options(candidate, "output_marker", False)]
    if not candidates:
        return f"{folder} has no {MARKER} naming this job, so it isn't this job's output"
    if not (Path(folder) / JOB_LOG).is_file():
        return f"{folder} isn't a Rowanholt output folder (no {MARKER} or {JOB_LOG} in it)"
    folder_place = place(folder)
    if not any(recorded_output(candidate, translate) is not None
               and place(recorded_output(candidate, translate)) == folder_place for candidate in candidates):
        return f"{folder} isn't the recorded output folder of this job"
    return None


# ── Checking and removing ────────────────────────────────────────────────────

_lstat = os.lstat  # one name, so tests can stand in another device for a folder


def _unescape_mount(field: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), field)


def mount_points() -> List[str]:
    """Every mount point this process sees (Linux's /proc/self/mounts; none elsewhere). A bind
    mount of a folder on the same file system has the same device number, so this, not the
    walk's device check, is what finds one."""
    try:
        with open("/proc/self/mounts", encoding="utf-8") as mounts:
            return [_unescape_mount(line.split()[1]) for line in mounts if len(line.split()) > 1]
    except OSError:
        return []


@dataclass
class Plan:
    """What a removal will take: checked, not yet done."""
    path: str
    device: int
    files: int
    bytes: int


def _identity(path) -> Optional[Tuple[int, int]]:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return st.st_dev, st.st_ino


def _protected(job, jobs: Iterable, roots: Iterable[str], target_place: PurePosixPath,
               translate: Callable[[str], str]) -> Dict[Tuple[int, int], str]:
    """Device and inode of everything a removal mustn't touch, with what it is."""
    found: Dict[Tuple[int, int], str] = {}

    def add(path, what: str) -> None:
        key = _identity(path)
        if key is not None:
            found.setdefault(key, what)

    for root in roots:
        for spelling in _spellings(root):
            add(spelling, f"the allowed folder {spelling}")
    for other in jobs:
        for source in other.source_paths or []:
            add(translate(source), f"evidence of case {other.case_number} ({source})")
        if other.id == job.id:
            continue
        output = recorded_output(other, translate)
        # Another finished job recorded at this very folder is this folder's earlier run (the
        # marker decides whose it is); one inside it, or one still going anywhere near, isn't
        if output is not None and (_status(other) in ACTIVE_STATUSES or place(output) != target_place):
            add(output, f"the output of case {other.case_number}")
    return found


def check_removal(target, job, jobs: Sequence, roots: Iterable[str],
                  translate: Callable[[str], str] = translate_path_for_worker) -> Plan:
    """Everything that must hold before the job's output folder is removed (the module's
    docstring), or PathRefused saying which doesn't. `target` is the worker's spelling of the
    job's recorded destination, derived from the job record, never from what a request named."""
    roots = list(roots)
    jobs = [job] + [other for other in jobs if other.id != job.id]  # its own sources count too
    path = contained(target, roots, must_exist=True)
    if in_elrond_mount(path):
        raise PathRefused(f"{path} is where Elrond mounts images")
    try:
        resolved = path.resolve(strict=True)
        top = _lstat(path)
    except OSError as exc:
        raise PathRefused(f"{path} can't be checked: {exc}") from exc
    if stat.S_ISLNK(top.st_mode) or not stat.S_ISDIR(top.st_mode):
        raise PathRefused(f"{path} isn't a folder")
    by_id = {other.id: other for other in jobs}
    refusal = owner_refusal(path, job, by_id, translate)
    if refusal:
        raise PathRefused(refusal)
    sources = list(job.source_paths or [])
    refusal = destination_refusal(path, job.id, sources, jobs, translate)
    if refusal:
        raise PathRefused(refusal)
    target_place = place(path)
    for other in jobs:
        output = recorded_output(other, translate)
        if other.id != job.id and output is not None and place(output) != target_place \
                and place(output).is_relative_to(target_place):
            raise PathRefused(f"{path} holds the output of case {other.case_number}")
    for mount in mount_points():
        mounted = _normal(mount)
        if mounted == _normal(path) or mounted.is_relative_to(_normal(path)) \
                or mounted == _normal(resolved) or mounted.is_relative_to(_normal(resolved)):
            raise PathRefused(f"{path} is or holds the mount point {mount}")
    if os.path.ismount(path):
        raise PathRefused(f"{path} is a mount point")

    protected = _protected(job, jobs, roots, target_place, translate)
    key = (top.st_dev, top.st_ino)
    if key in protected:
        raise PathRefused(f"{path} is {protected[key]}")
    # Running jobs' output above this folder (the same folder by another spelling is caught above)
    active = {_identity(recorded_output(other, translate)): other for other in jobs
              if other.id != job.id and _status(other) in ACTIVE_STATUSES and recorded_output(other, translate)}
    active.pop(None, None)
    for parent in path.parents:
        other = active.get(_identity(parent))
        if other is not None:
            raise PathRefused(f"{path} is inside the output of case {other.case_number}, which is {_status(other)}")

    files = size = 0
    stack = [str(path)]
    while stack:
        folder = stack.pop()
        try:
            with os.scandir(folder) as entries:
                names = [entry.path for entry in entries]
        except OSError as exc:
            raise PathRefused(f"{folder} can't be read, so it can't be checked: {exc}") from exc
        for name in names:
            try:
                st = _lstat(name)
            except FileNotFoundError:
                continue
            key = (st.st_dev, st.st_ino)
            if key in protected:
                raise PathRefused(f"{path} holds {protected[key]} ({name})")
            if stat.S_ISDIR(st.st_mode):
                if st.st_dev != top.st_dev:
                    raise PathRefused(f"{path} holds another file system, mounted at {name}")
                stack.append(name)
            else:
                files += 1
                size += st.st_size
    return Plan(path=str(path), device=top.st_dev, files=files, bytes=size)


def remove_tree(path, device: int) -> None:
    """Delete the folder and everything in it, deepest first, never following a symbolic link
    (a link is removed, not what it points at) and never onto another device: a mount that
    appeared since the check stops it there. Raises OSError (or PathRefused) on the first failure."""
    stack: List[Tuple[str, bool]] = [(str(path), False)]
    while stack:
        folder, emptied = stack.pop()
        if emptied:
            os.rmdir(folder)
            continue
        stack.append((folder, True))
        with os.scandir(folder) as entries:
            names = [entry.path for entry in entries]
        for name in names:
            st = _lstat(name)
            if stat.S_ISDIR(st.st_mode):
                if st.st_dev != device:
                    raise PathRefused(f"{name} is on another file system; nothing below it was removed")
                stack.append((name, False))
            else:
                os.unlink(name)


def remove_output(target, job, jobs: Sequence, roots: Iterable[str],
                  translate: Callable[[str], str] = translate_path_for_worker,
                  remover: Optional[Callable[[str, int], None]] = None) -> Plan:
    """Check, remove and verify: the plan that was carried out. PathRefused when it mustn't be
    removed (nothing was), OSError when the removal failed part way, RemovalFailed when the
    folder is still there afterwards."""
    plan = check_removal(target, job, jobs, roots, translate)
    (remover or remove_tree)(plan.path, plan.device)
    if os.path.lexists(plan.path):
        raise RemovalFailed(f"{plan.path} is still there after the removal")
    return plan


def size_text(count: int) -> str:
    """Bytes for a person: 1.5 GB."""
    value = float(count)
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{int(value)} bytes" if unit == "bytes" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{count} bytes"
