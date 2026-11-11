"""
Licence Routes

A team server's licence, for admins: what's installed and how many places are taken, checking a
licence before installing it, the commercial terms installing it accepts, and removing it. Every
install and removal goes in the audit log with the terms version. Local mode is one analyst and
needs no licence, so there's nothing here for it.
"""

from datetime import date, datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

try:
    from .config import settings
    from .auth import access
    from .auth.users import load_users
    from . import licence
except ImportError:
    from config import settings
    from auth import access
    from auth.users import load_users
    import licence

router = APIRouter(prefix="/api/licence", tags=["licence"])


class LicenceText(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


class LicenceIn(LicenceText):
    accept_terms: bool = False
    terms_version: str = Field(default="", max_length=16)  # the version the admin was shown


class LicencePreview(BaseModel):
    """What a pasted licence says, before it's installed."""
    licence_id: str
    licensee: str
    edition: str
    seats: Optional[int]
    features: List[str]
    not_before: Optional[date]
    expires: Optional[date]
    state: str


class TermsOut(BaseModel):
    version: str
    text: str


class Acceptance(BaseModel):
    by: str
    at: datetime
    terms_version: str


class LicenceOut(BaseModel):
    edition: str
    state: str  # free, pending, active, grace, lapsed
    licensee: str
    licence_id: str
    seats: Optional[int]  # None: unlimited
    features: List[str]
    places_held: int
    free_seats: int  # what the server falls back to without a licence
    not_before: Optional[date]
    expires: Optional[date]
    grace_ends: Optional[date]
    terms_version: str  # the version an install accepts now
    accepted: Optional[Acceptance]  # for the installed licence


def _server_only() -> None:
    if not settings.rowanholt_server_mode:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            "Local mode is one analyst and needs no licence; licences are for a team server.")


def _licence_out() -> LicenceOut:
    st = licence.current()
    lic = st.licence
    record = licence.installed() if lic else None
    accepted = (Acceptance(by=record["accepted_by_name"], at=record["accepted_at"],
                           terms_version=record["terms_version"])
                if record and record.get("accepted_at") else None)
    return LicenceOut(
        edition=st.edition.value,
        state=st.state,
        licensee=lic.licensee if lic else "",
        licence_id=lic.licence_id if lic else "",
        seats=st.seats,
        features=sorted(st.features),
        places_held=licence.places_held(load_users()),
        free_seats=licence.FREE_SEATS,
        not_before=lic.not_before if lic else None,
        expires=lic.expires if lic else None,
        grace_ends=licence.grace_ends(lic) if lic else None,
        terms_version=licence.terms()[0],
        accepted=accepted,
    )


def _parsed(text: str) -> licence.Licence:
    try:
        lic = licence.parse(text)
    except licence.LicenceProblem as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))
    if licence.standing(lic).state == "lapsed":
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"That licence ran out on {lic.expires}.")
    return lic


def _ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


@router.get("", response_model=LicenceOut)
async def get_licence(admin: dict = Depends(access.require_admin)) -> LicenceOut:
    _server_only()
    return _licence_out()


@router.get("/terms", response_model=TermsOut)
async def get_terms(admin: dict = Depends(access.require_admin)) -> TermsOut:
    """The commercial terms an admin accepts when installing a licence."""
    _server_only()
    version, text = licence.terms()
    return TermsOut(version=version, text=text)


@router.post("/check", response_model=LicencePreview)
async def check_licence(body: LicenceText, admin: dict = Depends(access.require_admin)) -> LicencePreview:
    """What a licence says, so the admin knows whom they're accepting the terms for. Installs nothing."""
    _server_only()
    lic = _parsed(body.text)
    return LicencePreview(
        licence_id=lic.licence_id,
        licensee=lic.licensee,
        edition=lic.edition.value,
        seats=lic.seats,
        features=sorted(licence.EDITION_FEATURES[lic.edition] | set(lic.features)),
        not_before=lic.not_before,
        expires=lic.expires,
        state=licence.standing(lic).state,
    )


@router.put("", response_model=LicenceOut)
async def install_licence(body: LicenceIn, request: Request,
                          admin: dict = Depends(access.require_admin)) -> LicenceOut:
    """Install a licence. The admin must have accepted the current commercial terms on the
    licensee's behalf; who, when and which version are kept with it."""
    _server_only()
    lic = _parsed(body.text)
    version = licence.terms()[0]
    if not body.accept_terms:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"Accept the commercial licence terms for {lic.licensee} to install this licence.")
    if body.terms_version != version:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"The commercial licence terms are now version {version}. Read them, then accept again.")
    name = admin.get("full_name") or admin.get("username")
    licence.record_install(body.text, accepted_by=admin.get("id"),
                           accepted_by_name=f"{name} <{admin.get('email') or admin.get('username')}>")
    licence.audit("licence_installed", admin, _ip(request), licence=lic.licence_id, edition=lic.edition.value,
                  licensee=lic.licensee, seats=lic.seats,
                  expires=lic.expires.isoformat() if lic.expires else "perpetual", terms_version=version)
    return _licence_out()


@router.delete("", response_model=LicenceOut)
async def remove_licence(request: Request, admin: dict = Depends(access.require_admin)) -> LicenceOut:
    """Back to the free edition. Nobody is deactivated; past the free limit, nobody new can be added."""
    _server_only()
    had = licence.current().licence
    if licence.remove():
        licence.audit("licence_removed", admin, _ip(request), licence=had.licence_id if had else None)
    return _licence_out()
