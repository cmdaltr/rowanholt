"""Report brands: the store, cleaning an uploaded logo, and which brand a case's Word report gets.

A brand is a name, a primary and an optional secondary colour, who the report is "Prepared for", and
up to three logos (cover, header, client). Rowanholt keeps its accounts in a JSON file, not the
database, so brands live beside it the same way: brands.json next to USERS_FILE (or the path in
ROWANHOLT_BRANDS), with each brand's logos as cleaned PNGs in brands/<id>/. The store also holds the
installation's brand and the brand each case names (a case number is a client engagement).

Which brand a report gets is decided when the report is built, never when a brand is saved:
the case's own brand under brand-library (Services), else the installation's under report-branding
(Pro and Services), else Rowanholt's own style. So a brand saved on one licence is kept when the
licence changes, and only what's rendered differs. Every change is an admin's and goes in the audit
log.

An uploaded logo is untrusted, so it's never stored or served as sent (as ostraka's reports/brands.py):
Pillow reads only PNG and JPEG (no SVG, which can carry script and external references), refuses
anything with more pixels than a logo needs before decoding it, and redraws the result as a fresh PNG
at most LOGO_MAX pixels a side, leaving metadata and anything appended to the file behind.
"""

from __future__ import annotations

import io
import json
import logging
import os
import re
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

try:
    from . import licence
except ImportError:
    import licence

logger = logging.getLogger(__name__)

SLOTS = ("cover", "header", "client")
UPLOAD_LIMIT = 2 * 1024 * 1024  # bytes
LOGO_MAX = 1200  # pixels a side, stored
PIXEL_LIMIT = 4096 * 4096  # refused before decoding: a decompression bomb is small on disk
HEX = re.compile(r"^#[0-9a-fA-F]{6}$")
BRAND_ID = re.compile(r"^[0-9a-f]{12}$")
_lock = threading.Lock()


class BrandProblem(ValueError):
    """A brand or logo that can't be saved, with a reason to show."""


def store_path() -> Path:
    """Read at each call, so a test (or ROWANHOLT_BRANDS set after import) takes effect."""
    explicit = os.environ.get("ROWANHOLT_BRANDS")
    if explicit:
        return Path(explicit)
    return Path(os.environ.get("USERS_FILE", "/app/data/users.json")).parent / "brands.json"


def _logo_dir(brand_id: str) -> Path:
    if not BRAND_ID.match(brand_id):  # the id becomes a folder name
        raise BrandProblem("No such brand.")
    return store_path().parent / "brands" / brand_id


def load() -> Dict:
    """{"brands": {id: brand}, "installation": id or None, "cases": {case number: id}}."""
    try:
        data = json.loads(store_path().read_text())
    except FileNotFoundError:
        data = {}
    except (OSError, ValueError) as exc:
        logger.error("Ignoring the brand store at %s: %s", store_path(), exc)
        data = {}
    return {"brands": data.get("brands") or {}, "installation": data.get("installation"),
            "cases": data.get("cases") or {}}


def _save(data: Dict) -> None:
    path = store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, path)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _colours(primary: str, secondary: str) -> None:
    if not HEX.match(primary or ""):
        raise BrandProblem("The primary colour must be like #1f6feb.")
    if secondary and not HEX.match(secondary):
        raise BrandProblem("The secondary colour must be like #1f6feb, or left empty.")


def create(name: str, primary: str, secondary: str = "", prepared_for: str = "") -> Dict:
    name = name.strip()
    if not name:
        raise BrandProblem("A brand needs a name.")
    _colours(primary, secondary)
    brand = {"id": secrets.token_hex(6), "name": name[:120], "primary": primary.lower(),
             "secondary": secondary.lower(), "prepared_for": prepared_for.strip()[:200],
             "logos": {slot: False for slot in SLOTS}, "created": _now(), "updated": _now()}
    with _lock:
        data = load()
        data["brands"][brand["id"]] = brand
        _save(data)
    return brand


def update(brand_id: str, **fields) -> Optional[Dict]:
    with _lock:
        data = load()
        brand = data["brands"].get(brand_id)
        if not brand:
            return None
        changed = {k: (v or "").strip() for k, v in fields.items()
                   if k in ("name", "primary", "secondary", "prepared_for") and v is not None}
        if "name" in changed and not changed["name"]:
            raise BrandProblem("A brand needs a name.")
        _colours(changed.get("primary", brand["primary"]), changed.get("secondary", brand["secondary"]))
        for key in ("primary", "secondary"):
            if key in changed:
                changed[key] = changed[key].lower()
        brand.update(changed, updated=_now())
        _save(data)
        return brand


def delete(brand_id: str) -> bool:
    """Remove a brand, its logos, and every choice that named it (those fall back as if unset)."""
    with _lock:
        data = load()
        if data["brands"].pop(brand_id, None) is None:
            return False
        if data["installation"] == brand_id:
            data["installation"] = None
        data["cases"] = {case: b for case, b in data["cases"].items() if b != brand_id}
        _save(data)
    folder = _logo_dir(brand_id)
    for slot in SLOTS:
        (folder / f"{slot}.png").unlink(missing_ok=True)
    try:
        folder.rmdir()
    except OSError:
        pass
    return True


def choose_installation(brand_id: Optional[str]) -> None:
    with _lock:
        data = load()
        if brand_id and brand_id not in data["brands"]:
            raise BrandProblem("No such brand.")
        data["installation"] = brand_id or None
        _save(data)


def choose_for_case(case_number: str, brand_id: Optional[str]) -> None:
    with _lock:
        data = load()
        if brand_id and brand_id not in data["brands"]:
            raise BrandProblem("No such brand.")
        if brand_id:
            data["cases"][case_number] = brand_id
        else:
            data["cases"].pop(case_number, None)
        _save(data)


# ── Logos ────────────────────────────────────────────────────────────────────


def clean_logo(data: bytes) -> bytes:
    """The upload redrawn as a PNG with a transparent ground, or BrandProblem."""
    try:
        from PIL import Image, UnidentifiedImageError
    except ImportError as exc:  # the backend image ships Pillow; a bare checkout may not
        raise BrandProblem("Logo uploads need Pillow on the server (pip install pillow).") from exc
    if len(data) > UPLOAD_LIMIT:
        raise BrandProblem("That file is over 2 MB. A logo needs far less: export it smaller.")
    try:
        img = Image.open(io.BytesIO(data), formats=["PNG", "JPEG"])
    except (UnidentifiedImageError, OSError) as exc:
        raise BrandProblem("Upload a PNG or JPEG. SVG and other formats aren't accepted.") from exc
    if img.width * img.height > PIXEL_LIMIT:
        raise BrandProblem("That image is too large: keep a logo under 4096 pixels a side.")
    try:
        img.load()
    except (OSError, Image.DecompressionBombError) as exc:
        raise BrandProblem("That image couldn't be read. Export it again as a PNG.") from exc
    img = img.convert("RGBA")
    box = img.getbbox()
    if box:  # trim transparent margins so sizing on the page is predictable
        img = img.crop(box)
    img.thumbnail((LOGO_MAX, LOGO_MAX), Image.LANCZOS)
    out = io.BytesIO()
    Image.frombytes("RGBA", img.size, img.tobytes()).save(out, format="PNG", optimize=True)
    return out.getvalue()


def set_logo(brand_id: str, slot: str, upload: Optional[bytes]) -> Dict:
    """Store a cleaned logo in a slot, or clear the slot (upload None)."""
    if slot not in SLOTS:
        raise BrandProblem(f"A logo goes in one of: {', '.join(SLOTS)}.")
    cleaned = clean_logo(upload) if upload is not None else None
    with _lock:
        data = load()
        brand = data["brands"].get(brand_id)
        if not brand:
            raise BrandProblem("No such brand.")
        path = _logo_dir(brand_id) / f"{slot}.png"
        if cleaned is None:
            path.unlink(missing_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(cleaned)
        brand["logos"][slot] = cleaned is not None
        brand["updated"] = _now()
        _save(data)
        return brand


def logo(brand_id: str, slot: str) -> Optional[bytes]:
    if slot not in SLOTS:
        return None
    try:
        return (_logo_dir(brand_id) / f"{slot}.png").read_bytes()
    except (FileNotFoundError, BrandProblem):
        return None


# ── Which brand a report gets ────────────────────────────────────────────────


def brand_for(case_number: str, standing: Optional[licence.Standing] = None) -> Optional[Dict]:
    """The brand a case's report is drawn in now, or None for Rowanholt's own style."""
    standing = standing or licence.current()
    if not standing.has(licence.REPORT_BRANDING) and not standing.has(licence.BRAND_LIBRARY):
        return None
    data = load()
    if standing.has(licence.BRAND_LIBRARY):
        chosen = data["brands"].get(data["cases"].get(case_number) or "")
        if chosen:
            return chosen
    if standing.has(licence.REPORT_BRANDING):
        return data["brands"].get(data["installation"] or "")
    return None


def theme_for(case_number: str, package, standing: Optional[licence.Standing] = None):
    """The report package's Theme for a case (package: case_files.report_package()), or None."""
    brand = brand_for(case_number, standing)
    if not brand:
        return None
    return package.brand_theme(brand["primary"], brand.get("secondary", ""),
                               cover_logo=logo(brand["id"], "cover"), header_logo=logo(brand["id"], "header"),
                               client_logo=logo(brand["id"], "client"), prepared_for=brand.get("prepared_for", ""),
                               brand=brand["name"])


def notes_for(brand: Dict) -> List[str]:
    """What the report changes about a brand's colours to keep them readable, for the admin page."""
    try:
        from rowanholt_report.theme import derive  # loaded by case_files.report_package()
    except ImportError:
        return []
    try:
        return derive(brand["primary"], brand.get("secondary", ""))[1]
    except ValueError:
        return []
