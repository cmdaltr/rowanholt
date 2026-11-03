#!/usr/bin/env python3
"""Download the OTRF Security-Datasets (Mordor) the Dernvale tests reference.

Uses a sparse, blob-less git clone, so only the folders asked for are fetched
(no GitHub API rate limits, no token). Each dataset is laid out as

    <MORDOR_ROOT>/<test path>/acquisitions/<dataset>.zip   (what Elrond's --Mordor/--Gandalf path reads)
    <MORDOR_ROOT>/<test path>/json/<dataset>.json          (extracted, for inspection or a future ingest)

and a manifest.json records what came from where. Test paths with no matching
OTRF folder are reported, not invented.

Usage:
    download_datasets.py --root DIR [--list] [--only apt29/day1 atomic/persistence ...]
"""

import argparse
import json
import shutil
import subprocess
import sys
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

REPO = "https://github.com/OTRF/Security-Datasets.git"

# Test path (relative to MORDOR_DATASETS_PATH in tests/scripts/run_test.py) -> how to find it in OTRF.
# "dir" is a repo folder; "search" is matched against every folder name when no fixed path exists.
TARGETS: Dict[str, Dict[str, str]] = {
    "apt29/day1": {"dir": "datasets/compound/apt29/day1"},
    "apt29/day2": {"dir": "datasets/compound/apt29/day2"},
    "atomic/credential_access": {"dir": "datasets/atomic/windows/credential_access"},
    "atomic/defense_evasion": {"dir": "datasets/atomic/windows/defense_evasion"},
    "atomic/lateral_movement": {"dir": "datasets/atomic/windows/lateral_movement"},
    "atomic/persistence": {"dir": "datasets/atomic/windows/persistence"},
    "malware/cobalt_strike": {"search": "cobalt"},
    "malware/emotet": {"search": "emotet"},
    "malware/trickbot": {"search": "trickbot"},
}


def git(args: List[str], cwd: Optional[Path] = None) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


def ensure_clone(cache: Path) -> Path:
    repo = cache / "Security-Datasets"
    if (repo / ".git").exists():
        print("[*] Updating OTRF clone")
        git(["fetch", "--depth", "1", "--filter=blob:none", "origin"], repo)
        git(["reset", "--hard", "origin/HEAD"], repo)
    else:
        print("[*] Cloning OTRF/Security-Datasets (sparse, metadata only)")
        cache.mkdir(parents=True, exist_ok=True)
        git(["clone", "--depth", "1", "--filter=blob:none", "--sparse", REPO, str(repo)])
    return repo


def all_dirs(repo: Path) -> List[str]:
    files = git(["ls-tree", "-r", "--name-only", "HEAD", "datasets"], repo).splitlines()
    dirs = set()
    for f in files:
        parts = f.split("/")[:-1]
        for i in range(2, len(parts) + 1):
            dirs.add("/".join(parts[:i]))
    return sorted(dirs)


def resolve(repo: Path, dirs: List[str]) -> Dict[str, Optional[str]]:
    resolved: Dict[str, Optional[str]] = {}
    for test_path, rule in TARGETS.items():
        if "dir" in rule:
            resolved[test_path] = rule["dir"] if rule["dir"] in dirs else None
        else:
            hits = [d for d in dirs if rule["search"] in d.split("/")[-1].lower()]
            resolved[test_path] = min(hits, key=len) if hits else None
    return resolved


def place(repo: Path, src_dir: str, dest: Path) -> List[dict]:
    acq = dest / "acquisitions"
    js = dest / "json"
    acq.mkdir(parents=True, exist_ok=True)
    js.mkdir(parents=True, exist_ok=True)
    placed = []
    archives = sorted(
        p for p in (repo / src_dir).rglob("*")
        if p.is_file() and (p.name.endswith(".zip") or p.name.endswith((".tar.gz", ".tgz")))
    )
    for z in archives:
        if z.name.endswith(".zip"):
            target = acq / z.name
            shutil.copy2(z, target)
            try:
                with zipfile.ZipFile(z) as zf:
                    for member in zf.namelist():
                        if member.endswith(".json") and not member.startswith("__MACOSX"):
                            out = js / Path(member).name
                            with zf.open(member) as src, open(out, "wb") as dst:
                                shutil.copyfileobj(src, dst)
            except zipfile.BadZipFile:
                print(f"[!] {z.name} is not a valid zip; kept as downloaded")
        else:
            # A few OTRF sets are tarballs; Elrond reads zips, so repack them.
            # Members are written by basename only, so a hostile path can't escape.
            target = acq / (z.name[:-len(".tar.gz")] if z.name.endswith(".tar.gz") else z.name[:-len(".tgz")])
            target = target.with_name(target.name + ".zip")
            try:
                with tarfile.open(z, "r:gz") as tf, zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
                    for member in tf.getmembers():
                        name = Path(member.name).name
                        if not member.isfile() or not name or name.startswith("._"):
                            continue
                        data = tf.extractfile(member).read()
                        zf.writestr(name, data)
                        if name.endswith(".json"):
                            (js / name).write_bytes(data)
            except (tarfile.TarError, OSError) as e:
                print(f"[!] {z.name} couldn't be repacked ({e}); skipped")
                target.unlink(missing_ok=True)
                continue
        placed.append({"file": target.name, "bytes": target.stat().st_size, "source": str(z.relative_to(repo))})
    return placed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", required=True, help="MORDOR_DATASETS_PATH (e.g. $TEST_IMAGES_PATH/mordor)")
    ap.add_argument("--cache", help="Where to keep the sparse clone (default: <root>/.otrf-cache)")
    ap.add_argument("--only", nargs="*", help="Test paths to fetch (default: all)")
    ap.add_argument("--list", action="store_true", help="Show what each test path maps to and exit")
    args = ap.parse_args()

    if not shutil.which("git"):
        print("[x] git is required (xcode-select --install)")
        return 1
    root = Path(args.root).expanduser()
    repo = ensure_clone(Path(args.cache).expanduser() if args.cache else root / ".otrf-cache")
    mapping = resolve(repo, all_dirs(repo))
    wanted = args.only or list(TARGETS)

    print()
    for tp in wanted:
        print(f"  {tp:<28} <- {mapping.get(tp) or 'NOT IN OTRF'}")
    print()
    if args.list:
        return 0

    available = [mapping[tp] for tp in wanted if mapping.get(tp)]
    if available:
        print("[*] Fetching dataset files (this can take a while for APT29)")
        git(["sparse-checkout", "set", "--no-cone", *[f"/{d}/" for d in available]], repo)

    manifest = {"source": REPO, "downloaded": datetime.now(timezone.utc).isoformat(), "datasets": {}}
    missing = []
    for tp in wanted:
        src = mapping.get(tp)
        if not src:
            missing.append(tp)
            continue
        placed = place(repo, src, root / tp)
        manifest["datasets"][tp] = {"otrf_path": src, "files": placed}
        print(f"[+] {tp}: {len(placed)} archive(s)")

    root.mkdir(parents=True, exist_ok=True)
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"\n[+] Manifest: {root / 'manifest.json'}")
    if missing:
        print("[!] No OTRF dataset for: " + ", ".join(missing))
        print("    These tests need data from elsewhere (or their own lab run: ./lab.sh -> Mordor -> generate).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
