"""Public forensic images as ready cases: the catalogue (catalogue.json), resumable downloads
checked against their publishers' hashes, unpacking, and the job each becomes.

A file is kept under its own name only once its hash has matched (until then it's <name>.part,
and a mismatch leaves <name>.bad), so a file being there means it was checked. Its SHA-256 goes
into SHA256SUMS in the samples folder; a file whose publisher gives no hash is checked against
that from its first download on. Stdlib only: the CLI runs on the host (Python 3.8+), the worker
fetches for Aragorn, the backend reads the status.
"""

import hashlib
import json
import logging
import os
import shutil
import subprocess
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

CATALOGUE = Path(__file__).resolve().parent / "catalogue.json"
DEFAULT_DIR = "/tmp/rowanholt/samples"
SUMS = "SHA256SUMS"
DIGITAL_CORPORA = "https://search.digitalcorpora.org/search/api?q={q}"
USER_AGENT = "Rowanholt samples (https://github.com/cmdaltr/rowanholt)"
TIMEOUT = 120
ARCHIVES = (".zip", ".7z", ".tar.gz", ".tgz", ".tar")
UNPACKED = ".rowanholt-unpacked"

# progress(file name, bytes so far, total or 0)
Progress = Callable[[str, int, int], None]


class SampleError(Exception):
    """A sample that couldn't be fetched, checked, unpacked or found."""


def catalogue() -> List[Dict]:
    """Every sample in the catalogue."""
    return json.loads(CATALOGUE.read_text(encoding="utf-8"))["samples"]


def sample(sample_id: str) -> Dict:
    """One sample by id."""
    found = next((s for s in catalogue() if s["id"] == sample_id), None)
    if found is None:
        raise SampleError(f"No sample {sample_id}: rowanholt samples list")
    return found


def samples_dir(override: Optional[str] = None) -> Path:
    """Where samples live: the given folder, ROWANHOLT_SAMPLES_DIR, or /tmp/rowanholt/samples."""
    return Path(override or os.environ.get("ROWANHOLT_SAMPLES_DIR") or DEFAULT_DIR)


def _open(url: str, start: int = 0):
    if not url.startswith("https://"):
        raise SampleError(f"Not HTTPS: {url}")
    headers = {"User-Agent": USER_AGENT}
    if start:
        headers["Range"] = f"bytes={start}-"
    response = urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=TIMEOUT)
    if not response.geturl().startswith("https://"):
        response.close()
        raise SampleError(f"Redirected off HTTPS: {response.geturl()}")
    return response


def published_hash(entry: Dict) -> Optional[Tuple[str, str]]:
    """(algorithm, digest) the file's publisher gives, or None when it gives none."""
    for algorithm in ("sha256", "md5"):
        if entry.get(algorithm):
            return algorithm, entry[algorithm].lower()
    if entry.get("sha256_from") == "digitalcorpora":
        with _open(DIGITAL_CORPORA.format(q=urllib.parse.quote(entry["name"]))) as response:
            rows = json.load(response)
        digest = next((r["sha2_256"] for r in rows
                       if str(r.get("s3key") or r.get("key", "")).endswith(entry["name"]) and r.get("sha2_256")), None)
        if not digest:
            raise SampleError(f"Digital Corpora publishes no SHA-256 for {entry['name']}")
        return "sha256", digest.lower()
    return None


def _digest(path: Path, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(4 << 20), b""):
            h.update(block)
    return h.hexdigest()


def recorded(root: Path, relative: str) -> Optional[str]:
    """The SHA-256 SHA256SUMS holds for a file (relative to the samples folder)."""
    try:
        lines = (root / SUMS).read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        digest, _, name = line.partition("  ")
        if name.strip() == relative:
            return digest.strip().lower()
    return None


def _record(root: Path, relative: str, digest: str) -> None:
    if recorded(root, relative) != digest:
        with open(root / SUMS, "a", encoding="utf-8") as fh:
            fh.write(f"{digest}  {relative}\n")


def _download(url: str, part: Path, progress: Optional[Progress]) -> None:
    start = part.stat().st_size if part.exists() else 0
    response = _open(url, start)
    with response:
        resumed = start and response.status == 206
        total = int(response.headers.get("Content-Length") or 0) + (start if resumed else 0)
        with open(part, "ab" if resumed else "wb") as out:
            done = start if resumed else 0
            for block in iter(lambda: response.read(4 << 20), b""):
                out.write(block)
                done += len(block)
                if progress:
                    progress(part.name[:-5], done, total)


def fetch_file(sample_: Dict, entry: Dict, root: Path, progress: Optional[Progress] = None) -> Path:
    """One of a sample's files, downloaded (resuming a .part) and checked; kept as is if it's
    already there (it was checked when it got its name)."""
    folder = root / sample_["folder"]
    target = folder / entry["name"]
    relative = f"{sample_['folder']}/{entry['name']}"
    if target.is_file():
        return target
    folder.mkdir(parents=True, exist_ok=True)
    expected = published_hash(entry)
    part = target.with_name(target.name + ".part")
    logger.info("Fetching %s from %s", relative, entry["url"])
    _download(entry["url"], part, progress)
    digest = _digest(part, "sha256")
    if expected:
        algorithm, want = expected
        got = digest if algorithm == "sha256" else _digest(part, algorithm)
        if got != want:
            part.replace(target.with_name(target.name + ".bad"))
            raise SampleError(f"{relative}: {algorithm} {got} is not the published {want} (kept as {target.name}.bad)")
    else:
        earlier = recorded(root, relative)
        if earlier and earlier != digest:
            part.replace(target.with_name(target.name + ".bad"))
            raise SampleError(f"{relative}: SHA-256 {digest} differs from the first download's {earlier}")
        logger.info("%s: no hash published; SHA-256 %s recorded", relative, digest)
    part.replace(target)
    _record(root, relative, digest)
    return target


def _safe(name: str) -> bool:
    path = PurePosixPath(name.replace("\\", "/"))
    return not path.is_absolute() and ".." not in path.parts


def _unpack(archive: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    name = archive.name.lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            bad = [m for m in zf.namelist() if not _safe(m)]
            if bad:
                raise SampleError(f"{archive.name}: unsafe paths ({bad[0]})")
            zf.extractall(dest)
    elif name.endswith((".tar.gz", ".tgz", ".tar")):
        with tarfile.open(archive) as tf:
            members = [m for m in tf.getmembers() if (m.isfile() or m.isdir()) and _safe(m.name)]
            tf.extractall(dest, members=members)
    elif name.endswith(".7z"):
        if not shutil.which("7z"):
            raise SampleError("7z isn't installed (brew install p7zip, or apt install p7zip-full)")
        subprocess.run(["7z", "x", "-y", f"-o{dest}", str(archive)], check=True, stdout=subprocess.DEVNULL)
    else:
        raise SampleError(f"Can't unpack {archive.name}")
    (dest / UNPACKED).write_text("", encoding="utf-8")


def _stem(archive: Path) -> str:
    name = archive.name
    for suffix in ARCHIVES:
        if name.lower().endswith(suffix):
            return name[: -len(suffix)]
    return name


def images(sample_: Dict, root: Path) -> List[Path]:
    """The sample's evidence in its folder: what each of its image patterns finds, once."""
    folder = root / sample_["folder"]
    found: List[Path] = []
    for pattern in sample_["images"]:
        for path in sorted(folder.rglob(pattern)) if folder.is_dir() else []:
            if path not in found and not path.name.endswith((".part", ".bad")):
                found.append(path)
    return found


def unpack(sample_: Dict, root: Path) -> List[Path]:
    """The sample's archives unpacked beside them (unless its evidence is already there), then
    any inner archives it names; returns its evidence."""
    if images(sample_, root):
        return images(sample_, root)
    folder = root / sample_["folder"]
    for entry in sample_["files"]:
        archive = folder / entry["name"]
        dest = folder / _stem(archive)
        if archive.is_file() and archive.name.lower().endswith(ARCHIVES) and not (dest / UNPACKED).exists():
            logger.info("Unpacking %s", archive.name)
            _unpack(archive, dest)
    for inner in sample_.get("unpack", []):
        for archive in folder.rglob(inner):
            dest = archive.with_name(_stem(archive))
            if not (dest / UNPACKED).exists():
                logger.info("Unpacking %s", archive.name)
                _unpack(archive, dest)
    found = images(sample_, root)
    if not found:
        raise SampleError(f"{sample_['id']}: nothing matching {', '.join(sample_['images'])} once unpacked")
    return found


def status(sample_: Dict, root: Path) -> Dict:
    """Which of the sample's files are there (checked), part-downloaded or bad, and its evidence."""
    folder = root / sample_["folder"]
    files = []
    for entry in sample_["files"]:
        target = folder / entry["name"]
        part = target.with_name(target.name + ".part")
        state = ("ready" if target.is_file() else "bad" if target.with_name(target.name + ".bad").exists()
                 else "partial" if part.exists() else "missing")
        size = target.stat().st_size if target.is_file() else part.stat().st_size if part.exists() else 0
        files.append({"name": entry["name"], "state": state, "bytes": size})
    found = images(sample_, root)
    return {"id": sample_["id"], "files": files, "images": [str(p) for p in found],
            "ready": bool(found) or all(f["state"] == "ready" for f in files)}


def job_request(sample_: Dict, sources: List[Path], force: bool = False) -> Dict:
    """The POST /api/jobs body for a sample: a case named after it, its options, its evidence."""
    options = dict(sample_.get("options", {}))
    if force:
        options["force_overwrite"] = True
    body = {"case_number": "SAMPLE-" + sample_["id"].upper(), "source_paths": [str(p) for p in sources],
            "options": options}
    if sample_.get("backup_password"):
        body["backup_password"] = sample_["backup_password"]
    return body


def create_job(body: Dict, api: str, token: Optional[str] = None) -> Dict:
    """Start the job through Rowanholt's API, as the web app's form does."""
    headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(api.rstrip("/") + "/api/jobs", data=json.dumps(body).encode(),
                                     headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        try:
            detail = json.loads(detail).get("detail", detail)
        except ValueError:
            pass
        raise SampleError(f"Rowanholt refused the job ({exc.code}): {detail}")
