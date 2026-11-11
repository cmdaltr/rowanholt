"""
Branding Routes

Report brands, for admins: the brand library, each brand's logos, the installation's brand, and the
brand a case names. Saving any of it is open on every edition, so nothing configured is lost when a
licence changes; whether a report uses it is decided when the report is built (branding.brand_for),
and this API says what the current licence will do with it. Every change goes in the audit log.
"""

from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from fastapi.responses import Response
from pydantic import BaseModel, Field

try:
    from . import branding, case_files, licence
    from .auth import access
except ImportError:
    import branding
    import case_files
    import licence
    from auth import access

router = APIRouter(prefix="/api/brands", tags=["branding"])
case_router = APIRouter(prefix="/api/jobs/{job_id}/case", tags=["branding"])
_jobs = None


def configure(storage) -> None:
    """The backend's JobStorage, to find a job's case number (main.py does)."""
    global _jobs
    _jobs = storage


class BrandIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    primary: str = Field(pattern=r"^#[0-9a-fA-F]{6}$")
    secondary: str = Field(default="", max_length=7)
    prepared_for: str = Field(default="", max_length=200)


class BrandEdit(BaseModel):
    name: Optional[str] = Field(default=None, max_length=120)
    primary: Optional[str] = Field(default=None, max_length=7)
    secondary: Optional[str] = Field(default=None, max_length=7)
    prepared_for: Optional[str] = Field(default=None, max_length=200)


class Choice(BaseModel):
    brand_id: Optional[str] = None


def _ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


def _notes(brand: Dict) -> List[str]:
    try:
        return case_files.report_package().derive(brand["primary"], brand.get("secondary", ""))[1]
    except (ImportError, ValueError):
        return []


def _with_notes(brand: Dict) -> Dict:
    return {**brand, "notes": _notes(brand)}


def _what_reports_do() -> Dict:
    """What the current licence does with the brands, for the admin page."""
    st = licence.current()
    branding_on, library_on = st.has(licence.REPORT_BRANDING), st.has(licence.BRAND_LIBRARY)
    if library_on:
        says = "Reports use the case's brand, or the installation's when the case names none."
    elif branding_on:
        says = ("Reports use the installation's brand. A brand per case needs the Services edition: "
                "brands chosen for cases are kept, but not used.")
    else:
        says = (f"This is the {st.edition.value.title()} edition: reports are in Rowanholt's own style. "
                "Brands saved here are kept, and used once a Pro or Services licence is installed.")
    return {"report_branding": branding_on, "brand_library": library_on, "says": says}


def _problem(exc: branding.BrandProblem) -> HTTPException:
    return HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))


@router.get("")
async def list_brands(admin: dict = Depends(access.require_admin)) -> Dict:
    data = branding.load()
    return {"brands": [_with_notes(b) for b in sorted(data["brands"].values(), key=lambda b: b["name"].lower())],
            "installation": data["installation"], "cases": data["cases"], **_what_reports_do()}


@router.post("")
async def create_brand(body: BrandIn, request: Request, admin: dict = Depends(access.require_admin)) -> Dict:
    try:
        brand = branding.create(body.name, body.primary, body.secondary, body.prepared_for)
    except branding.BrandProblem as exc:
        raise _problem(exc)
    licence.audit("brand_created", admin, _ip(request), resource_type="brand", resource_id=brand["id"],
                  name=brand["name"], primary=brand["primary"], secondary=brand["secondary"])
    return _with_notes(brand)


@router.patch("/{brand_id}")
async def edit_brand(brand_id: str, body: BrandEdit, request: Request,
                     admin: dict = Depends(access.require_admin)) -> Dict:
    try:
        brand = branding.update(brand_id, **body.dict())
    except branding.BrandProblem as exc:
        raise _problem(exc)
    if not brand:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such brand")
    licence.audit("brand_changed", admin, _ip(request), resource_type="brand", resource_id=brand_id,
                  **{k: v for k, v in body.dict().items() if v is not None})
    return _with_notes(brand)


@router.delete("/{brand_id}")
async def delete_brand(brand_id: str, request: Request, admin: dict = Depends(access.require_admin)) -> Dict:
    try:
        deleted = branding.delete(brand_id)
    except branding.BrandProblem:
        deleted = False
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such brand")
    licence.audit("brand_deleted", admin, _ip(request), resource_type="brand", resource_id=brand_id)
    return {"deleted": brand_id}


@router.put("/{brand_id}/logos/{slot}")
async def upload_logo(brand_id: str, slot: str, request: Request, file: UploadFile = File(...),
                      admin: dict = Depends(access.require_admin)) -> Dict:
    """A logo for one slot (cover, header or client): cleaned and redrawn as PNG before it's kept."""
    data = await file.read(branding.UPLOAD_LIMIT + 1)
    try:
        brand = branding.set_logo(brand_id, slot, data)
    except branding.BrandProblem as exc:
        raise _problem(exc)
    licence.audit("brand_logo_set", admin, _ip(request), resource_type="brand", resource_id=brand_id, slot=slot)
    return _with_notes(brand)


@router.delete("/{brand_id}/logos/{slot}")
async def clear_logo(brand_id: str, slot: str, request: Request, admin: dict = Depends(access.require_admin)) -> Dict:
    try:
        brand = branding.set_logo(brand_id, slot, None)
    except branding.BrandProblem as exc:
        raise _problem(exc)
    licence.audit("brand_logo_cleared", admin, _ip(request), resource_type="brand", resource_id=brand_id, slot=slot)
    return _with_notes(brand)


@router.get("/{brand_id}/logos/{slot}")
async def get_logo(brand_id: str, slot: str, admin: dict = Depends(access.require_admin)) -> Response:
    data = branding.logo(brand_id, slot)
    if data is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No logo there")
    # Always the PNG Rowanholt redrew, never the upload; nosniff keeps it an image
    return Response(content=data, media_type="image/png", headers={"X-Content-Type-Options": "nosniff"})


@router.put("/installation")
async def choose_installation_brand(body: Choice, request: Request,
                                    admin: dict = Depends(access.require_admin)) -> Dict:
    try:
        branding.choose_installation(body.brand_id)
    except branding.BrandProblem as exc:
        raise _problem(exc)
    licence.audit("brand_installation_chosen", admin, _ip(request), resource_type="brand",
                  resource_id=body.brand_id, scope="installation")
    return await list_brands(admin)


def _case_number(job_id: str) -> str:
    job = _jobs.get_job(job_id) if _jobs else None
    if not job:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Job not found")
    return job.case_number


@case_router.get("/brand")
async def case_brand(job_id: str, admin: dict = Depends(access.require_admin)) -> Dict:
    """The brand this job's case names, and the one its report would use now."""
    case = _case_number(job_id)
    data = branding.load()
    used = branding.brand_for(case)
    return {"case_number": case, "brand_id": data["cases"].get(case), "used": used["id"] if used else None,
            "brands": [{"id": b["id"], "name": b["name"]} for b in data["brands"].values()], **_what_reports_do()}


@case_router.put("/brand")
async def choose_case_brand(job_id: str, body: Choice, request: Request,
                            admin: dict = Depends(access.require_admin)) -> Dict:
    """Name a brand for the case (every job with this case number), or none. Kept whatever the
    licence; used under brand-library."""
    case = _case_number(job_id)
    try:
        branding.choose_for_case(case, body.brand_id)
    except branding.BrandProblem as exc:
        raise _problem(exc)
    licence.audit("brand_case_chosen", admin, _ip(request), resource_type="brand", resource_id=body.brand_id,
                  case_number=case)
    return await case_brand(job_id, admin)
