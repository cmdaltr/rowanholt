"""Threat intelligence: importing indicators, browsing them, and what they say about one value.

Reading is open to every signed-in user; importing, TAXII pulls, deleting a source and changing
an indicator's expiry are admin-only on a team server (auth/access.py), as Mordor's are. Online
lookups (threat_intel_lookup.py) are for any analyst, never for Eru.
"""

import logging
import os
import tempfile
import threading
from typing import Optional

from fastapi import APIRouter, File, HTTPException, Query, Request, UploadFile
from pydantic import BaseModel, Field

try:
    from . import threat_intel_lookup as online
    from .auth import access
    from .threat_intel_store import ThreatIntelUnavailable, store, threat_intel
except ImportError:
    import threat_intel_lookup as online
    from auth import access
    from threat_intel_store import ThreatIntelUnavailable, store, threat_intel

router = APIRouter(prefix="/api/threat-intel", tags=["Threat intelligence"])
logger = logging.getLogger(__name__)

MAX_UPLOAD_BYTES = 200 << 20
UPLOAD_SUFFIXES = (".xlsx", ".xlsm", ".csv", ".json", ".txt")

# The value index Eru and /enrich use, rebuilt when the stored indicators change
_index = {"version": None, "index": None}
_index_lock = threading.Lock()


def _package():
    try:
        return threat_intel()
    except ThreatIntelUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))


def value_index():
    """The indicators as a ThreatIntelIndex for single values, cached until they change."""
    package = _package()
    version = store().version()
    with _index_lock:
        if _index["version"] != version:
            _index["index"] = package.ThreatIntelIndex(store().indicators(), scope="value")
            _index["version"] = version
        return _index["index"]


class ValidityRequest(BaseModel):
    valid_until: Optional[str] = None  # ISO date or time (UTC); null: no expiry


class LookupRequest(BaseModel):
    value: str = Field(..., min_length=3, max_length=300)


AGENT_HEADERS = ("X-Dernvale-Agent", "X-Rivendell-Agent")


class TaxiiRequest(BaseModel):
    url: str
    username: str = ""
    password: str = ""
    added_after: str = ""


@router.get("")
async def summary():
    """How many indicators there are, from which sources, about how many groups."""
    return store().counts()


@router.get("/indicators")
async def indicators(q: str = "", source: str = "", limit: int = Query(100, le=500), offset: int = Query(0, ge=0)):
    return store().search(q, source, limit, offset)


@router.post("/import")
async def import_file(file: UploadFile = File(...)):
    """Indicators from an uploaded file: the Iran APT workbook, a STIX bundle,
    MITRESaw's procedures, Dernvale's own CSV or a text watchlist."""
    package = _package()
    name = os.path.basename(file.filename or "upload")
    if not name.lower().endswith(UPLOAD_SUFFIXES):
        raise HTTPException(status_code=400, detail=f"{name}: upload XLSX, CSV, JSON or a .txt watchlist")
    with tempfile.TemporaryDirectory() as folder:
        path = os.path.join(folder, name)
        size = 0
        with open(path, "wb") as out:
            while chunk := await file.read(1 << 20):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="Threat intelligence files are limited to 200 MB")
                out.write(chunk)
        try:
            loaded, validity = package.load_with_validity(path)
        except (ValueError, OSError) as exc:  # UnsupportedIntel, IntelFormatError, WorkbookError
            raise HTTPException(status_code=400, detail=str(exc))
    added, duplicates = store().add(loaded, validity)
    sources = sorted({i.source_type for i in loaded})
    logger.info("Threat intelligence: %s indicators added from %s (%s already there)", added, name, duplicates)
    return {"file": name, "read": len(loaded), "added": added, "duplicates": duplicates, "sources": sources}


@router.post("/taxii")
async def import_taxii(request: TaxiiRequest):
    """Every object in a TAXII 2.1 collection (or those added after a date), as indicators."""
    _package()
    from dernvale.threat_intel.stix import IntelFormatError, import_taxii_with_validity as pull
    try:
        loaded, validity = pull(request.url, request.username, request.password, request.added_after)
    except IntelFormatError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except OSError as exc:  # URLError, HTTPError, timeouts
        raise HTTPException(status_code=502, detail=f"Couldn't read the TAXII collection: {exc}")
    added, duplicates = store().add(loaded, validity)
    return {"collection": request.url, "read": len(loaded), "added": added, "duplicates": duplicates}


@router.put("/indicators/{indicator_id}/validity")
async def set_validity(indicator_id: int, request: ValidityRequest):
    """Extend an indicator's expiry, or clear it (no expiry); an expired one matches again once extended."""
    _package()
    from dernvale.threat_intel.validity import parse_time
    until = None
    if request.valid_until:
        until = parse_time(request.valid_until)
        if until is None:
            raise HTTPException(status_code=400, detail="valid_until is an ISO date or time, or null for no expiry")
    try:
        return store().set_validity(indicator_id, until)
    except KeyError:
        raise HTTPException(status_code=404, detail="No such indicator")


@router.delete("/sources/{source:path}")
async def delete_source(source: str):
    removed = store().delete_source(source)
    if not removed:
        raise HTTPException(status_code=404, detail="No indicators from that source")
    return {"source": source, "removed": removed}


@router.get("/enrich")
async def enrich(value: str = Query(..., min_length=3, max_length=20000)):
    """What the indicators say about one process name, command line, path, IP, domain or hash."""
    package = _package()
    return {"value": value, "matches": package.enrich_artefact(value, value_index())}


def enrich_value(value: str) -> Optional[list]:
    """For Eru: the same as /enrich, or None when there's no threat intelligence."""
    try:
        if not store().version()[0]:
            return None
        return threat_intel().enrich_artefact(value, value_index())
    except (ThreatIntelUnavailable, RuntimeError):
        return None


@router.get("/lookup")
async def lookup_status():
    """Whether online lookups are on, and which provider they go to."""
    name = online.provider()
    return {"enabled": bool(name), "provider": name or None}


@router.post("/lookup")
async def lookup(request: LookupRequest, http: Request):
    """What the online provider says about one IP, domain or hash. Sends the value outside Dernvale,
    so it's an analyst's call only: refused to an eru-mcp token and to Eru's MCP server."""
    if access.token_scope(http) == "eru-mcp" or any(http.headers.get(h) for h in AGENT_HEADERS):
        raise HTTPException(status_code=403, detail="Online lookups are an analyst's, not Eru's")
    user = getattr(http.state, "user", None) or {}
    try:
        return online.lookup(request.value, user.get("username", "unknown"))
    except online.LookupRefused as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except online.LookupFailed as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
