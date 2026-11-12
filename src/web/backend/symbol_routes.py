"""
Volatility symbol tables for memory images (Aragorn's Settings): the tables Rowanholt has, and
adding one from files an administrator brings.

The tables are the repository's symbols/linux and symbols/mac, mounted here and in the worker
(Elrond's memory/symbols keeps their index). A debug package, a vmlinux, or a
macOS kernel and its dSYM DWARF file from a Kernel Debug Kit, goes to the worker, which has
dwarf2json, as `rowanholt symbols add` would.
"""

import importlib.util
import logging
import os
import re
import shutil
import uuid
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

try:
    from . import busy
    from .auth.access import require_admin
    from .case_files import _elrond_sources
except ImportError:
    import busy
    from auth.access import require_admin
    from case_files import _elrond_sources

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/symbols", tags=["symbols"])

SYMBOLS_DIR = Path(os.environ.get("ROWANHOLT_SYMBOLS_DIR", "/opt/rowanholt/symbols"))
INCOMING = "incoming"
TABLE = re.compile(r"\.json(\.xz)?$")
PACKAGE = re.compile(r"\.(d?deb|rpm)$", re.IGNORECASE)
LOG_LINES = 50
_cache = None


def symbols_cache():
    """Elrond's rowanholt/memory/symbols/cache.py (the index), loaded by path as case_files does."""
    global _cache
    if _cache is None:
        for src in _elrond_sources():
            path = Path(src, "rowanholt", "memory", "symbols", "cache.py")
            if path.is_file():
                spec = importlib.util.spec_from_file_location("rowanholt_symbols_cache", path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                _cache = module
                break
        else:
            raise HTTPException(status_code=503, detail="rowanholt/memory/symbols isn't mounted in the backend")
    return _cache


def _downloads() -> bool:
    return os.environ.get("ROWANHOLT_SYMBOL_DOWNLOADS", "on").strip().lower() not in ("off", "0", "false", "no")


@router.get("")
async def list_symbols(_: dict = Depends(require_admin)) -> dict:
    """Every table in the linux and mac folders, with its index entry when it has one, and the
    folders' audit logs' last lines."""
    cache = symbols_cache()
    tables, log = [], []
    for os_name in ("linux", "mac"):
        folder = SYMBOLS_DIR / os_name
        indexed = {e["file"]: e for e in cache.entries(os_name, SYMBOLS_DIR)}
        for table in sorted(folder.glob("*.json*")) if folder.is_dir() else []:
            entry = indexed.get(table.name, {})
            tables.append({"os": os_name, "file": table.name, "size": table.stat().st_size,
                           "banner": entry.get("banner", ""), "source": entry.get("source", ""),
                           "sha256": entry.get("sha256", ""), "added": entry.get("added", "")})
        try:
            log += (folder / cache.LOG).read_text(encoding="utf-8").splitlines()[-LOG_LINES:]
        except OSError:
            pass
    return {"downloads": _downloads(), "tables": tables, "log": sorted(log)[-LOG_LINES:],
            "fetch_command": "rowanholt symbols fetch <image>"}


def _save(upload: UploadFile, target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "wb") as out:
        shutil.copyfileobj(upload.file, out, 1 << 20)
    return target


def _name(upload: Optional[UploadFile]) -> str:
    return Path(upload.filename or "").name if upload else ""


@router.post("/add")
async def add_symbols(
    kind: str = Form(..., pattern="^(package|table|vmlinux|kdk)$"),
    file: UploadFile = File(...),
    system_map: Optional[UploadFile] = File(None),
    dwarf: Optional[UploadFile] = File(None),
    user: dict = Depends(require_admin),
) -> dict:
    """Add a table: kind package (a kernel's debug package, .ddeb, .deb or .rpm), table (an ISF,
    .json or .json.xz), vmlinux (with System.map if there is one), or kdk (file: the KDK's kernel,
    dwarf: its kernel.dSYM/Contents/Resources/DWARF file)."""
    work = SYMBOLS_DIR / INCOMING / uuid.uuid4().hex
    try:
        if kind == "package":
            if not PACKAGE.search(_name(file)):
                raise HTTPException(status_code=400, detail="A debug package is a .ddeb, .deb or .rpm file")
            args = ["--package", str(_save(file, work / _name(file)))]
        elif kind == "table":
            if not TABLE.search(_name(file)):
                raise HTTPException(status_code=400, detail="A symbol table is a .json or .json.xz file")
            args = ["--table", str(_save(file, work / _name(file)))]
        elif kind == "vmlinux":
            args = ["--vmlinux", str(_save(file, work / "vmlinux"))]
            if system_map:
                args += ["--system-map", str(_save(system_map, work / "System.map"))]
        else:
            if not dwarf:
                raise HTTPException(status_code=400, detail="A KDK build needs the kernel and its dSYM DWARF file")
            # Laid out as a KDK, so the worker builds it as rowanholt symbols add --kdk does
            kernels = work / "System" / "Library" / "Kernels"
            _save(file, kernels / "kernel")
            _save(dwarf, kernels / "kernel.dSYM" / "Contents" / "Resources" / "DWARF" / "kernel")
            args = ["--kdk", str(work)]
    except HTTPException:
        shutil.rmtree(work, ignore_errors=True)
        raise
    try:
        from tasks_docker import add_symbol_table
    except ImportError:
        shutil.rmtree(work, ignore_errors=True)
        raise HTTPException(status_code=503, detail="The worker's task queue isn't available")
    task = add_symbol_table.delay(args, str(work))
    busy.side_tasks.add(task.id)
    logger.info("Symbol table %s upload by %s queued as %s", kind, user.get("username"), task.id)
    return {"task_id": task.id}


@router.get("/tasks/{task_id}")
async def symbol_task(task_id: str, _: dict = Depends(require_admin)) -> dict:
    """An upload's build: pending until the worker has run it, then its output."""
    from tasks_docker import celery_app

    result = celery_app.AsyncResult(task_id)
    if not result.ready():
        return {"state": "pending"}
    value = result.result if isinstance(result.result, dict) else {"ok": False, "output": str(result.result)}
    return {"state": "done", **value}
