"""
Pairing Routes

Pairing with Ostraka in one step (docs/suite/INTEGRATION.md, "Pairing" and "Rowanholt"). An admin makes a
pairing link here (`<public URL>/pair#pair_…`), and an Ostraka admin pastes it into Ostraka, which claims it.
The claim makes an API token with the `ostraka` scope, owned by the admin who made the code, and a webhook to
Ostraka for job.completed, job.failed and finding.confirmed, and answers with the token and the webhook's
secret: they're in that answer and nowhere else.

A code is `pair_` and 43 random characters, works once within ten minutes, and is kept only as its SHA-256
(the pairing_codes table, beside api_tokens), as account links are. The claim needs no sign-in, since the code
is the credential, and it's one conditional UPDATE, so of two claims at once only one wins. A code whose admin
has been deactivated or is no longer an admin reads as never valid. Removing the token or the webhook undoes
the pairing; there's nothing else to remove.

Making, listing and withdrawing codes are for admins on a team server, as API tokens are: on an analyst's own
machine the API needs no token. Every step is audited, the code and the link never.
"""

import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

try:
    from . import webhooks
    from .auth import access, reset_access, tokens
    from .auth.users import load_users, public
    from .config import settings
except ImportError:
    import webhooks
    from auth import access, reset_access, tokens
    from auth.users import load_users, public
    from config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/pairing", tags=["pairing"])

PREFIX = "pair_"
PATH = "/pair"
MINUTES = 10
TOKEN_NAME = "Ostraka (paired)"
TOKEN_DAYS = 365
EVENTS = ["job.completed", "job.failed", "finding.confirmed"]
INVALID = "This pairing link isn't valid. Ask for a new one."
EXPIRED = "This pairing link has expired. Ask for a new one."


class PairingIn(BaseModel):
    note: str = Field(default="", max_length=200)


class ClaimIn(BaseModel):
    code: str = Field(max_length=200)
    product: str = Field(default="ostraka", max_length=40)
    name: str = Field(default="Ostraka", max_length=100)
    version: str = Field(default="", max_length=40)
    webhook_url: str = Field(max_length=2000)


def code_hash(code: str) -> str:
    """What's kept of a code: its SHA-256 (256 random bits need no slow hash)."""
    return hashlib.sha256(code.encode()).hexdigest()


def new_code() -> str:
    return PREFIX + secrets.token_urlsafe(32)


def _ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


def _storage():
    if not settings.rowanholt_server_mode:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Pairing is for a team server: on your own machine the API needs no token")
    if access._storage is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Pairing storage isn't available")
    return access._storage


def _audit(action: str, actor: Optional[dict], ip: Optional[str], pairing_id: Optional[str], **details) -> None:
    storage = access._storage
    if storage is None:
        logger.warning("Pairing %s not audited (no storage configured): %s", action, details)
        return
    storage.audit(action, actor or {"username": "server"}, ip, resource_type="pairing", resource_id=pairing_id,
                  **details)


def _listed(code: Dict) -> Dict:
    return {key: code[key] for key in
            ("id", "note", "created_by", "created_at", "expires_at", "claimed_at", "claimed_by_name")}


def _active_admin(user_id: str) -> Optional[dict]:
    """The code's maker, if they're still an active admin."""
    record = load_users().get(user_id)
    if not record or not record.get("is_active", True) or record.get("role") != "admin":
        return None
    return public(record)


@router.post("", status_code=status.HTTP_201_CREATED)
async def make_code(body: PairingIn, request: Request, admin: dict = Depends(access.require_admin)) -> Dict:
    """A pairing link, shown this once: only the code's hash is kept."""
    storage = _storage()
    code = new_code()
    now = datetime.now()
    record = storage.add_pairing({
        "id": str(uuid.uuid4()), "code_hash": code_hash(code), "note": body.note.strip(),
        "created_by_id": admin["id"], "created_by": admin["username"], "created_at": now,
        "expires_at": now + timedelta(minutes=MINUTES)})
    origin = None if settings.rowanholt_public_url else reset_access.request_origin(request)
    _audit("pairing_code_created", admin, _ip(request), record["id"], note=record["note"],
           expires_at=record["expires_at"].isoformat())
    return {"id": record["id"], "link": reset_access.link(PATH, code, origin), "expires_at": record["expires_at"]}


@router.get("")
async def list_codes(admin: dict = Depends(access.require_admin)) -> List[Dict]:
    return [_listed(code) for code in _storage().list_pairings()]


@router.delete("/{pairing_id}", status_code=status.HTTP_204_NO_CONTENT)
async def withdraw_code(pairing_id: str, request: Request, admin: dict = Depends(access.require_admin)) -> Response:
    """Withdraw an unclaimed code. A claimed one stays: revoke its token or delete its webhook to undo it."""
    outcome = _storage().withdraw_pairing(pairing_id)
    if outcome is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such pairing code")
    if outcome == "claimed":
        raise HTTPException(status.HTTP_409_CONFLICT, "That code has been claimed: to undo the pairing, revoke "
                            "its token (Ostraka (paired)) or delete its webhook")
    _audit("pairing_code_withdrawn", admin, _ip(request), pairing_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _refused(request: Request, code: Optional[Dict], status_code: int, detail: str, reason: str) -> JSONResponse:
    _audit("pairing_claim_refused", None, _ip(request), code["id"] if code else None, reason=reason,
           created_by=code["created_by"] if code else None)
    return JSONResponse({"detail": detail}, status_code=status_code)


@router.post("/claim")
async def claim(body: ClaimIn, request: Request):
    """Ostraka's claim of a code (no sign-in: the code is the credential). Makes the token and the webhook,
    and answers with both secrets, once."""
    if access._storage is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Pairing storage isn't available")
    storage = access._storage
    # Before the code is claimed, so a mistyped URL doesn't use the code up
    problem = webhooks.shared.url_problem(body.webhook_url)
    if problem:
        return _refused(request, None, status.HTTP_422_UNPROCESSABLE_CONTENT, problem, "webhook_url")
    now = datetime.now()
    hashed = code_hash(body.code.strip())
    code = storage.pairing_by_hash(hashed) if body.code.strip().startswith(PREFIX) else None
    if code is None or code["claimed_at"] is not None:
        return _refused(request, code, status.HTTP_404_NOT_FOUND, INVALID, "claimed" if code else "unknown")
    if code["expires_at"] <= now:
        return _refused(request, code, status.HTTP_410_GONE, EXPIRED, "expired")
    owner = _active_admin(code["created_by_id"])
    if owner is None:
        return _refused(request, code, status.HTTP_404_NOT_FOUND, INVALID, "maker_not_an_active_admin")
    name = body.name.strip() or "Ostraka"
    claimed = storage.claim_pairing(hashed, now, name)
    if claimed is None:  # another claim won, or it expired in between
        again = storage.pairing_by_hash(hashed)
        if again and again["claimed_at"] is None:
            return _refused(request, again, status.HTTP_410_GONE, EXPIRED, "expired")
        return _refused(request, again, status.HTTP_404_NOT_FOUND, INVALID, "claimed")

    token, record = tokens.new_token(owner, TOKEN_NAME, tokens.OSTRAKA_SCOPE, TOKEN_DAYS)
    stored = storage.add_token(record)
    hook = webhooks.add(body.webhook_url, EVENTS, None, TOKEN_NAME)
    storage.set_pairing_result(claimed["id"], stored["id"], hook["id"])
    _audit("pairing_claimed", None, _ip(request), claimed["id"], created_by=claimed["created_by"],
           created_by_id=claimed["created_by_id"], token_prefix=stored["prefix"], token_id=stored["id"],
           webhook_id=hook["id"], product=body.product, name=name, version=body.version)
    logger.info(f"Paired with {name} ({body.product} {body.version}): token {stored['prefix']}… for "
                f"{owner['username']}, webhook {hook['id']}")
    return {"product": "rowanholt", "version": settings.app_version, "token": token,
            "token_expires_at": stored["expires_at"].isoformat(), "webhook_id": hook["id"],
            "webhook_secret": hook["secret"], "events": EVENTS}
