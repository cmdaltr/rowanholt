"""
Simple File-Based Authentication Routes

Lightweight authentication without database dependencies: users live in a JSON file
(auth/users.py). Password sign-in with an optional second factor (auth/mfa.py), single
sign-on (auth/oidc.py) when configured, and, in server mode, user administration for
admins in place of open sign-up.

Every route that reads the users (or the invitations), decides and writes them back does so inside
users.locked(), which `rowanholt server users` takes too: a link can't be completed twice at once,
and one write doesn't undo another's.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import quote, urlsplit

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

try:
    from ..config import settings
    from .security import verify_password, create_access_token
    from .users import (NO_ACCOUNTS, deactivate, find_user, init_default_admin, load_users,  # noqa: F401
                        locked, loopback_only, new_user, public, save_users, set_password)
    from . import access, invitations, mfa, oidc, reset_access, tokens
    from .throttle import throttle
    from .. import licence, mailer
except ImportError:
    from config import settings
    from auth.security import verify_password, create_access_token
    from auth.users import (NO_ACCOUNTS, deactivate, find_user, init_default_admin, load_users,  # noqa: F401
                            locked, loopback_only, new_user, public, save_users, set_password)
    from auth import access, invitations, mfa, oidc, reset_access, tokens
    from auth.throttle import throttle
    import licence
    import mailer

router = APIRouter(prefix="/api/auth", tags=["authentication"])
logger = logging.getLogger(__name__)

MIN_PASSWORD = 12
# Forgot password: requests per address and per client address, an hour
FORGOT_PER_ADDRESS = 3
FORGOT_PER_IP = 10
FORGOT_WINDOW = 3600


# Request/Response Models
class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    email: str  # Email validated manually
    username: str
    password: str
    full_name: Optional[str] = None
    role: str = "user"  # ignored: a sign-up is always a user (only a local stack signs up)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


class UserResponse(BaseModel):
    id: str
    email: str
    username: str
    full_name: Optional[str]
    role: str


class UserUpdate(BaseModel):
    role: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None  # refused: nobody sets another person's password
    full_name: Optional[str] = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


def _session(response: Response, user: dict) -> dict:
    """Issue a token for `user`, set it as the session cookie, and return the login body."""
    access_token = create_access_token(data={"sub": user["id"], "role": user["role"]})
    response.set_cookie(
        key="session_token",
        value=access_token,
        httponly=True,
        secure=settings.rowanholt_server_mode,
        samesite="lax",
        max_age=settings.access_token_expire_minutes * 60,
    )
    body = {"access_token": access_token, "token_type": "bearer", "user": public(user)}
    if access.enrolment_pending(body["user"]):
        # ROWANHOLT_REQUIRE_MFA: the web app goes to Account, and keeps the user there (the user's
        # copy, which it stores) until MFA is on
        body["mfa_enrolment_required"] = body["user"]["mfa_enrolment_required"] = True
    return body


def _address(request: Request) -> str:
    # Behind the server's proxy, uvicorn's --proxy-headers makes this the browser's address
    return request.client.host if request.client else "unknown"


def _failed(name: str, address: str, record: dict | None, stage: str) -> None:
    """Count a failed sign-in (or a wrong code that counts as one); the failure that locks the account
    is audited as account_locked, with where it happened."""
    if throttle.failed(name, address):
        target = record or {"id": None, "username": name}
        mfa.audit("account_locked", None, target, address, stage=stage,
                  minutes=settings.lockout_duration_minutes)


def _local_open() -> bool:
    """Whether this is a local stack published on this machine only (ROWANHOLT_BIND on loopback): the
    only place with open sign-up and guests, as the default admin is seeded only there."""
    return not settings.rowanholt_server_mode and loopback_only(settings.rowanholt_bind)


def _forgot_password_offered() -> bool:
    """Forgot password emails a link, so it needs email and ROWANHOLT_PUBLIC_URL: an emailed link is
    never built from the request (its Origin or Host is the asker's to choose, and the token would go
    to their address)."""
    return mailer.configured() and bool(settings.rowanholt_public_url)


def _link_origin(request: Request) -> str | None:
    """Where links point without ROWANHOLT_PUBLIC_URL: the request's own address."""
    return None if settings.rowanholt_public_url else reset_access.request_origin(request)


def _refuse_if_locked(name: str, address: str) -> None:
    wait = throttle.locked_for(name, address)
    if wait:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed sign-ins; try again in {wait // 60 + 1} minutes",
        )


def _check_password_strength(password: str) -> None:
    if settings.rowanholt_server_mode and len(password) < MIN_PASSWORD:
        raise HTTPException(status_code=400, detail=f"Passwords need at least {MIN_PASSWORD} characters")


def _room_for_one_more(users: dict) -> None:
    """Refuse adding an account past the licence's places (server mode only; never retroactive)."""
    refusal = licence.seat_refusal(users, settings.rowanholt_server_mode)
    if refusal:
        raise HTTPException(status_code=status.HTTP_402_PAYMENT_REQUIRED, detail=refusal)


def _users_or_503() -> dict:
    """The users, after seeding a local stack's default admin (auth/users.init_default_admin)."""
    return init_default_admin()


def _users_to_sign_in() -> dict:
    """The users for a sign-in: 503 on a server with none yet, saying how its first admin is made."""
    users = init_default_admin()
    if not users and settings.rowanholt_server_mode:
        raise HTTPException(status_code=503, detail=NO_ACCOUNTS)
    return users


# Routes
@router.get("/config")
async def auth_config():
    """How this Rowanholt signs people in, for the login page."""
    server = settings.rowanholt_server_mode
    return {
        "server_mode": server,
        "local_login": settings.rowanholt_local_login or not settings.oidc_enabled,
        "guest": _local_open(),
        "register": _local_open(),
        # Forgot password emails a reset link: only with email to send it by (mailer.py)
        "forgot_password": _forgot_password_offered(),
        "sso": {"enabled": settings.oidc_enabled, "name": settings.oidc_display_name},
    }


@router.post("/login")
async def login(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends()
):
    """Login with username/email and password (OAuth2 form data). With MFA on, the answer is a
    challenge for the second step (POST /login/mfa), not a session."""
    users = _users_to_sign_in()
    known = find_user(users, form_data.username)
    # One account, one count: its username and its email share a lockout
    name = known["username"] if known else form_data.username
    address = _address(request)
    _refuse_if_locked(name, address)

    user = known
    if not user or not user.get("hashed_password") or not verify_password(form_data.password, user["hashed_password"]):
        _failed(name, address, known, "sign-in")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )
    # With single sign-on as the only way in, a password still works for admins (break glass)
    if settings.oidc_enabled and not settings.rowanholt_local_login and user["role"] != "admin":
        raise HTTPException(status_code=403, detail=f"Sign in with {settings.oidc_display_name}")

    if mfa.is_enabled(user):
        # The failures so far stand until the second factor is right, so a known password doesn't
        # reset the count against guessing codes
        return {"mfa_required": True, "challenge": mfa.new_challenge(user),
                "expires_in": mfa.CHALLENGE_SECONDS, "methods": ["totp", "backup_code"]}
    throttle.succeeded(name, address)
    with locked():  # read again: the password check took a while, and another write may have landed
        users = load_users()
        user = users.get(user["id"]) or user
        user["last_login"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        save_users(users)
    return _session(response, user)


class SecondFactor(BaseModel):
    challenge: str
    code: str


@router.post("/login/mfa", response_model=LoginResponse)
async def login_second_factor(body: SecondFactor, request: Request, response: Response):
    """The sign-in's second step: the challenge from /login and a TOTP or backup code. Signs in as
    /login does without MFA. A wrong code counts towards the sign-in lockout; the challenge lasts
    five minutes and signs in once."""
    address = _address(request)
    with locked():  # a backup code is used up once
        users = _users_or_503()
        try:
            record, nonce = mfa.read_challenge(body.challenge, users)
        except mfa.MfaError as exc:
            raise HTTPException(status_code=401, detail=str(exc))
        name = record["username"]
        _refuse_if_locked(name, address)
        accepted, how = mfa.check_code(record, body.code)
        if not accepted:
            _failed(name, address, record, "sign-in")
            mfa.audit("mfa_failed", record, record, address, stage="sign-in")
            raise HTTPException(status_code=401, detail="Incorrect code")
        if not mfa.spend_challenge(nonce):
            raise HTTPException(status_code=401, detail="That sign-in has been used; start again")
        throttle.succeeded(name, address)
        record["last_login"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        save_users(users)
    if how == "backup_code":
        mfa.audit("mfa_backup_code_used", record, record, address, stage="sign-in",
                  left=len(record.get("mfa_backup_codes") or []))
    return _session(response, record)


@router.post("/guest", response_model=LoginResponse)
async def login_as_guest(response: Response):
    """Login as guest user (limited access): only on a local stack published on this machine alone."""
    if settings.rowanholt_server_mode:
        raise HTTPException(status_code=403, detail="Guest access is off on this server")
    if not _local_open():
        raise HTTPException(status_code=403, detail=CLOSED_BEYOND_LOOPBACK)
    access_token = create_access_token(
        data={"sub": "guest", "role": "guest"},
        expires_delta=timedelta(seconds=settings.guest_session_timeout)
    )

    response.set_cookie(
        key="session_token",
        value=access_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=settings.guest_session_timeout,
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": "guest",
            "email": "guest@rowanholt.app",
            "username": "guest",
            "full_name": "Guest User",
            "role": "guest",
        }
    }


CLOSED_BEYOND_LOOPBACK = ("Sign-up and guests are only for a Rowanholt on this machine alone: this one is published "
                          "beyond it (ROWANHOLT_BIND). For a team, run a server (rowanholt server init), whose "
                          "accounts come by invitation")


@router.post("/register", response_model=UserResponse)
async def register(request: RegisterRequest, http_request: Request):
    """Register a new user account: the sign-up of a local stack published on this machine alone
    (ROWANHOLT_BIND on loopback, as for the default admin). A server's accounts come by invitation."""
    role = "user"
    if settings.rowanholt_server_mode:
        access.require_admin(http_request)
        raise HTTPException(status_code=400, detail=invitations.INVITE_INSTEAD)
    if not _local_open():
        raise HTTPException(status_code=403, detail=CLOSED_BEYOND_LOOPBACK)
    _check_password_strength(request.password)
    with locked():
        return _register(request, role, _address(http_request))


def _register(request: RegisterRequest, role: str, address: str) -> dict:
    users = _users_or_503()

    # Check if email already exists
    for u in users.values():
        if u["email"] == request.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered",
            )
        if u["username"] == request.username:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already taken",
            )

    _room_for_one_more(users)
    try:
        user = new_user(request.username, request.email, role=role, password=request.password,
                        full_name=request.full_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    users[user["id"]] = user
    save_users(users)
    mfa.audit("account_created", user, user, address, role=user["role"], via="register")
    return public(user)


@router.post("/logout")
async def logout(response: Response):
    """Logout current user."""
    response.delete_cookie(key="session_token")
    return {"message": "Logged out successfully"}


NO_EMAIL = ("This Rowanholt doesn't send email, so it can't send you a link: ask an administrator for a "
            "reset link (rowanholt server users reset-access <username>)")
LINK_ON_ITS_WAY = "If that address has an account, a link is on its way"
TOO_MANY_REQUESTS = "Too many requests for a link: try again in an hour"


class ForgotPassword(BaseModel):
    email: str  # or the username: sign-in takes either


@router.post("/forgot-password")
async def forgot_password(body: ForgotPassword, request: Request, background: BackgroundTasks):
    """Forgot password: an active password account matching the email (or username) is emailed a
    reset-access link, the same link and page as an admin's reset. The answer is the same whether or
    not one matched, and the email goes after it (a background task), so its timing doesn't say either.
    Rate-limited per address and per client address. The account's sessions and tokens are left alone,
    since anyone can ask; completing the reset ends them. An admin's link that's still open isn't
    replaced. Without email (ROWANHOLT_SMTP_*) or ROWANHOLT_PUBLIC_URL, 503 saying to ask an
    administrator: the emailed link is always the public URL's, never the request's address."""
    if not _forgot_password_offered():
        raise HTTPException(status_code=503, detail=NO_EMAIL)
    name = (body.email or "").strip()
    address = _address(request)
    if not throttle.allow(f"forgot|ip|{address}", FORGOT_PER_IP, FORGOT_WINDOW) or \
            not throttle.allow(f"forgot|{name}", FORGOT_PER_ADDRESS, FORGOT_WINDOW):
        raise HTTPException(status_code=429, detail=TOO_MANY_REQUESTS)
    with locked():
        users = _users_or_503()
        record = find_user(users, name) if name else None
        if record is None and name:
            record = next((u for u in users.values() if (u.get("email") or "").lower() == name.lower()), None)
        link = None
        if record and record.get("email"):
            link = reset_access.issue_self_service(record, address, storage=access._storage)
            if link:
                save_users(users)
    if link:
        background.add_task(mailer.send_reset_link, record["email"], record["username"], link,
                            reset_access.RESET_HOURS)
    return {"message": LINK_ON_ITS_WAY}


@router.get("/me")
async def get_current_user(user: dict = Depends(access.current_user)):
    """The signed-in user (the local analyst on a local stack without a sign-in), and whether
    ROWANHOLT_REQUIRE_MFA holds them to setting MFA up first, which the web app keeps them to"""
    return {**user, "mfa_enrolment_required": True} if access.enrolment_pending(user) else user


@router.post("/session", response_model=LoginResponse)
async def session_from_cookie(request: Request, response: Response):
    """A bearer token for the session cookie, for the frontend after single sign-on."""
    user = access.user_from_request(request)
    if not user:
        raise HTTPException(status_code=401, detail="Sign in required")
    return _session(response, load_users()[user["id"]])


def _sign_in_url(request: Request) -> str:
    """The sign-in page at whichever of the server's addresses the browser is on (the proxy's
    X-Forwarded-Host), since its cookies belong to that address; the public URL otherwise."""
    host = (request.headers.get("X-Forwarded-Host") or "").rsplit(":", 1)[0].lower()
    for url in [settings.rowanholt_public_url, *settings.rowanholt_other_urls.split(",")]:
        url = url.strip().rstrip("/")
        if url and host and urlsplit(url).hostname == host:
            return f"{url}/login"
    return f"{settings.rowanholt_public_url.rstrip('/')}/login"


@router.get("/verify")
async def verify(request: Request, response: Response, login_redirect: bool = False,
                 service: Optional[str] = None):
    """200 for a signed-in user, 401 otherwise: the reverse proxy's check in front of
    Kibana, Splunk and the ATT&CK Navigator on a server. With login_redirect the refusal
    is a redirect to the sign-in page, which the proxy passes on to the browser. For the
    Navigator (service=navigator), a case's layer also needs access to the case: the
    proxy sends the URI it's asking about in X-Forwarded-Uri."""
    user = access.user_from_request(request)
    if not user and login_redirect and settings.rowanholt_public_url:
        return RedirectResponse(_sign_in_url(request), status_code=302)
    if not user:
        raise HTTPException(status_code=401, detail="Sign in required")
    if access.enrolment_pending(user):
        raise HTTPException(status_code=403, detail=access.ENROLMENT_REFUSAL)
    if service == "navigator" and not access.layer_allowed(user, request.headers.get("X-Forwarded-Uri", "/")):
        raise HTTPException(status_code=403, detail="Not your case")
    response.headers["X-Rowanholt-User"] = user["username"]
    return {"username": user["username"]}


@router.post("/change-password")
async def change_password(body: PasswordChange, response: Response, user: dict = Depends(access.current_user)):
    """Change the caller's own password. Every other session ends; this one carries on with a new
    token (a browser's cookie is replaced, a bearer caller takes it from the answer)."""
    _check_password_strength(body.new_password)
    with locked():
        users = load_users()
        record = users.get(user["id"])
        if not record or not record.get("hashed_password"):
            raise HTTPException(status_code=400, detail="This account signs in with single sign-on")
        if not verify_password(body.current_password, record["hashed_password"]):
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        set_password(record, body.new_password)
        save_users(users)
    return {"message": "Password changed", **_session(response, record)}


# ── Multi-factor authentication (auth/mfa.py) ────────────────────────────────

LOCAL_MFA = ("MFA applies to a team server's sign-in: on your own machine Rowanholt has no sign-in "
             "for it to protect")
SSO_MFA = "This account signs in with single sign-on: its MFA is your identity provider's"


class MfaCode(BaseModel):
    code: str = ""


class MfaDisable(BaseModel):
    password: str
    code: str


def _local_mfa(record: dict | None) -> bool:
    """On a local stack, MFA is managed only by an account that already has it on (a reset of its
    access turns it on): it can change its authenticator, make new backup codes or turn it off, as on a
    server. Others aren't offered it: a local stack has no sign-in for it to protect."""
    return bool(record and mfa.offered_to(record) and mfa.is_enabled(record))


def _mfa_account(user: dict) -> tuple:
    """(users, the caller's record) for managing their own MFA, or the reason they can't."""
    if not settings.rowanholt_server_mode and not _local_mfa(load_users().get(user["id"])):
        raise HTTPException(status_code=400, detail=LOCAL_MFA)
    if user.get("token"):
        # A token already skips the second factor; it mustn't also be able to replace it
        raise HTTPException(status_code=403, detail="Manage MFA from a sign-in, not an API token")
    users = load_users()
    record = users.get(user["id"])
    if not record:
        raise HTTPException(status_code=400, detail="This account has no MFA to manage")
    if not mfa.offered_to(record):
        raise HTTPException(status_code=400, detail=SSO_MFA)
    return users, record


def _second_factor(record: dict, code: str, request: Request, purpose: str, allow_backup: bool = True) -> str:
    """Check the caller's current code (and use it up); a wrong one counts as a failed sign-in."""
    address = _address(request)
    _refuse_if_locked(record["username"], address)
    accepted, how = mfa.check_code(record, code, allow_backup=allow_backup)
    if not accepted:
        _failed(record["username"], address, record, purpose)
        mfa.audit("mfa_failed", record, record, address, stage=purpose)
        raise HTTPException(status_code=400, detail="Incorrect code")
    if how == "backup_code":
        mfa.audit("mfa_backup_code_used", record, record, address, stage=purpose,
                  left=len(record.get("mfa_backup_codes") or []))
    return how


@router.get("/mfa")
async def mfa_status(user: dict = Depends(access.current_user)):
    """The caller's MFA: whether it's on, backup codes left, and whether this server requires it."""
    record = load_users().get(user["id"])
    if not settings.rowanholt_server_mode and not _local_mfa(record):
        return {"available": False, "reason": "local", "message": LOCAL_MFA}
    if not record:
        return {"available": False, "reason": "none", "message": "This account has no MFA to manage"}
    if not mfa.offered_to(record):
        return {"available": False, "reason": "sso", "message": SSO_MFA}
    return {"available": True, "required": settings.rowanholt_require_mfa,
            "setup_started": bool(record.get("mfa_pending_secret")), **mfa.status(record)}


@router.post("/mfa/setup")
async def mfa_setup(body: MfaCode, request: Request, user: dict = Depends(access.current_user)):
    """Start enrolment: a new secret, as an otpauth:// URI, a QR code and text to type in. Nothing
    changes until /mfa/enable confirms a code from it. With MFA already on (a new phone), it needs a
    current code first, so a session left open can't move the account to someone else's app."""
    with locked():
        users, record = _mfa_account(user)
        if mfa.is_enabled(record):
            if not body.code:
                raise HTTPException(status_code=400, detail="Enter a current code to set up a new authenticator")
            _second_factor(record, body.code, request, "re-enrolment")
        secret = mfa.new_secret()
        record["mfa_pending_secret"] = mfa.encrypt_secret(secret)
        record["mfa_pending_at"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        save_users(users)
        uri = mfa.provisioning_uri(secret, record["username"])
        return {"secret": secret, "otpauth_uri": uri, "qr_svg": mfa.qr_svg_data_uri(uri)}


@router.post("/mfa/enable")
async def mfa_enable(body: MfaCode, request: Request, user: dict = Depends(access.current_user)):
    """Confirm enrolment with a code from the new secret: MFA goes on (or the new secret replaces the
    old). The first time, ten backup codes come back, shown this once."""
    with locked():
        users, record = _mfa_account(user)
        secret = mfa.decrypt_secret(record.get("mfa_pending_secret") or "") if record.get("mfa_pending_secret") else None
        if not secret:
            raise HTTPException(status_code=400, detail="Start setting MFA up first")
        address = _address(request)
        _refuse_if_locked(record["username"], address)
        # The new secret's own codes: none has been used, whatever step the old secret last took
        step = mfa.matching_step(secret, body.code)
        if step is None:
            _failed(record["username"], address, record, "enrolment")
            mfa.audit("mfa_failed", record, record, address, stage="enrolment")
            raise HTTPException(status_code=400, detail="Incorrect code: check the app's clock and try the next one")
        again = mfa.is_enabled(record)
        codes = mfa.enable(record, secret, step)
        save_users(users)
        mfa.audit("mfa_reenrolled" if again else "mfa_enabled", record, record, address)
        return {**mfa.status(record), "backup_codes": codes}


@router.post("/mfa/disable")
async def mfa_disable(body: MfaDisable, request: Request, user: dict = Depends(access.current_user)):
    """Turn the caller's MFA off: their password and a current code (or a backup code)."""
    with locked():
        users, record = _mfa_account(user)
        if not mfa.is_enabled(record):
            raise HTTPException(status_code=400, detail="MFA isn't on")
        if settings.rowanholt_require_mfa:
            raise HTTPException(status_code=400, detail="This server requires MFA: set up a new authenticator instead")
        address = _address(request)
        _refuse_if_locked(record["username"], address)
        if not verify_password(body.password, record.get("hashed_password") or ""):
            _failed(record["username"], address, record, "disable")
            raise HTTPException(status_code=400, detail="Password is incorrect")
        _second_factor(record, body.code, request, "disable")
        mfa.disable(record)
        save_users(users)
        mfa.audit("mfa_disabled", record, record, address)
        return mfa.status(record)


@router.post("/mfa/backup-codes")
async def mfa_backup_codes(body: MfaCode, request: Request, user: dict = Depends(access.current_user)):
    """Ten new backup codes in place of the old ones, for a current authenticator code (not a backup
    code: losing the codes is why someone makes new ones). Shown this once."""
    with locked():
        users, record = _mfa_account(user)
        if not mfa.is_enabled(record):
            raise HTTPException(status_code=400, detail="Turn MFA on first")
        _second_factor(record, body.code, request, "backup codes", allow_backup=False)
        codes = mfa.replace_backup_codes(record)
        save_users(users)
        mfa.audit("mfa_backup_codes_regenerated", record, record, _address(request))
        return {**mfa.status(record), "backup_codes": codes}


@router.delete("/users/{user_id}/mfa")
async def mfa_admin_reset(user_id: str, request: Request, admin: dict = Depends(access.require_admin)):
    """Turn MFA off for someone who's lost their authenticator and backup codes (admins). They sign
    in with their password next, and set it up again (ROWANHOLT_REQUIRE_MFA holds them to it)."""
    with locked():
        users = load_users()
        record = users.get(user_id)
        if not record:
            raise HTTPException(status_code=404, detail="User not found")
        if not mfa.is_enabled(record) and not record.get("mfa_pending_secret"):
            raise HTTPException(status_code=400, detail=f"MFA isn't on for {record['username']}")
        mfa.disable(record)
        save_users(users)
        mfa.audit("mfa_admin_reset", admin, record, _address(request))
        return public(record)


# ── Reset access (auth/reset_access.py) ──────────────────────────────────────

@router.post("/users/{user_id}/reset-access")
async def reset_access_link(user_id: str, request: Request, admin: dict = Depends(access.require_admin)):
    """A one-time link for someone who's lost their password, authenticator or backup codes (admins):
    they choose a new password and set up a new authenticator. Their sessions end and their API
    tokens are revoked now, and any earlier link stops working. Pass the link on: it's shown once."""
    with locked():
        users = load_users()
        record = users.get(user_id)
        if not record:
            raise HTTPException(status_code=404, detail="User not found")
        try:
            link, expires = reset_access.issue(record, admin, _address(request), storage=access._storage,
                                               origin=_link_origin(request))
        except reset_access.ResetRefused as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        save_users(users)
    return {"link": link, "expires_at": datetime.fromtimestamp(expires, timezone.utc).replace(tzinfo=None).isoformat(),
            "user": public(record)}


class ResetStart(BaseModel):
    token: str


class ResetComplete(BaseModel):
    token: str
    new_password: str
    code: str


def _reset_record(token: str) -> tuple:
    """(users, the record a reset link is for); 400 for a link that's unknown or used, 410 expired.
    Never 401, which the web app reads as a session that's ended. The caller holds users.locked()."""
    users = _users_or_503()
    try:
        return users, reset_access.find(users, token)
    except reset_access.ResetRefused as exc:
        if exc.changed:  # an expired link's authenticator dropped
            save_users(users)
        raise HTTPException(status_code=exc.status, detail=str(exc))


@router.post("/reset-access/start")
async def reset_access_start(body: ResetStart, request: Request):
    """Opening a reset link: the account's username and a new authenticator to set up (a secret, as
    text and a QR code). Nothing changes until /reset-access/complete; opening it again shows the same
    one. 429 while the account is locked out."""
    with locked():
        users, record = _reset_record(body.token)
        _refuse_if_locked(record["username"], _address(request))
        enrolment = reset_access.start(record)
        save_users(users)
    return {**enrolment, "expires_in": int(float(record["access_reset_expires"]) - mfa._now())}


@router.post("/reset-access/complete")
async def reset_access_complete(body: ResetComplete, request: Request, response: Response):
    """Finishing a reset: the new password and a code from the new authenticator. Signs the person in,
    with MFA on and ten new backup codes, returned this once; the link is used up, every other session
    ends and the account's API tokens are revoked. A wrong code is audited and counts towards the
    account's sign-in lockout (429 once it's locked, here and at sign-in)."""
    if len(body.new_password) < MIN_PASSWORD:
        raise HTTPException(status_code=400, detail=f"Passwords need at least {MIN_PASSWORD} characters")
    with locked():  # the link is claimed once: a second completion finds it gone
        users, record = _reset_record(body.token)
        name, address = record["username"], _address(request)
        _refuse_if_locked(name, address)
        try:
            step = reset_access.pending_step(record, body.code)
        except reset_access.ResetRefused as exc:
            raise HTTPException(status_code=exc.status, detail=str(exc))
        if step is None:
            _failed(name, address, record, "reset access")
            mfa.audit("access_reset_failed", record, record, address, reason="wrong code")
            raise HTTPException(status_code=400, detail="Incorrect code: check the app's clock and try the next one")
        codes = reset_access.complete(record, body.new_password, step, address, storage=access._storage)
        throttle.succeeded(name, address)
        record["last_login"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        save_users(users)
    return {**_session(response, record), "backup_codes": codes}


# ── API tokens (auth/tokens.py) ──────────────────────────────────────────────

class TokenRequest(BaseModel):
    name: str
    scope: str = "full"
    days: int = tokens.DEFAULT_DAYS


def _token_storage():
    if not settings.rowanholt_server_mode:
        raise HTTPException(status_code=400, detail="Tokens are for a team server: on your own machine the API needs none")
    if access._storage is None:
        raise HTTPException(status_code=503, detail="Token storage isn't available")
    return access._storage


@router.get("/tokens")
async def list_tokens(all: bool = False, user: dict = Depends(access.current_user)):
    """The caller's tokens; with all=true, everyone's (admins)."""
    if all and not access.is_admin(user):
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return {"tokens": _token_storage().list_tokens(None if all else user["id"])}


@router.post("/tokens")
async def create_token(body: TokenRequest, user: dict = Depends(access.current_user)):
    """A new token for the caller, returned once: only its hash is kept."""
    storage = _token_storage()
    name = body.name.strip()
    if not name or len(name) > 100:
        raise HTTPException(status_code=400, detail="Give the token a name of up to 100 characters")
    body.scope = tokens.scope_of(body.scope)  # "eru-mcp" is still taken, as smith-mcp
    if body.scope not in tokens.SCOPES:
        raise HTTPException(status_code=400, detail=f"Scope is one of: {', '.join(tokens.SCOPES)}")
    if not 1 <= body.days <= tokens.MAX_DAYS:
        raise HTTPException(status_code=400, detail=f"A token lasts 1 to {tokens.MAX_DAYS} days")
    token, record = tokens.new_token(user, name, body.scope, body.days)
    stored = storage.add_token(record)
    logger.info(f"{user['username']} made {body.scope} token {stored['prefix']}… ({name}, {body.days} days)")
    return {"token": token, **stored}


@router.delete("/tokens/{token_id}")
async def revoke_token(token_id: str, user: dict = Depends(access.current_user)):
    """Revoke one of the caller's tokens (admins: anyone's)."""
    revoked = _token_storage().revoke_token(token_id, None if access.is_admin(user) else user["id"])
    if not revoked:
        raise HTTPException(status_code=404, detail="Token not found")
    logger.info(f"{user['username']} revoked {revoked['username']}'s token {revoked['prefix']}…")
    return revoked


# ── Users: the directory for sharing, and administration ─────────────────────

@router.get("/directory")
async def directory(user: dict = Depends(access.current_user)):
    """Usernames and names of active users, for sharing a job."""
    return [{"username": u["username"], "full_name": u.get("full_name")}
            for u in load_users().values() if u.get("is_active", True)]


# ── Invitations (auth/invitations.py): how a team server's accounts are made ──

class InvitationRequest(BaseModel):
    email: str
    role: str = "user"
    full_name: Optional[str] = None


@router.post("/users/invitations")
async def create_invitation(body: InvitationRequest, request: Request, admin: dict = Depends(access.require_admin)):
    """Invite someone (admins): a one-time link where they choose a username, a password and an
    authenticator. Returns the invitation and `link`, shown this once. A newer invitation for the
    same email replaces an older one. 409 for an email with an account, 402 with no free place."""
    try:
        with locked():
            invitation, link = invitations.create(_users_or_503(), body.email, body.role, body.full_name, admin,
                                                  _address(request), storage=access._storage,
                                                  origin=_link_origin(request))
    except invitations.InvitationRefused as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    return {**invitation, "link": link}


@router.get("/users/invitations")
async def list_invitations(admin: dict = Depends(access.require_admin)):
    """Pending invitations (admins), newest first; never their links."""
    if not settings.rowanholt_server_mode:
        raise HTTPException(status_code=400, detail=invitations.LOCAL)
    return invitations.pending()


@router.delete("/users/invitations/{invitation_id}")
async def revoke_invitation(invitation_id: str, request: Request, admin: dict = Depends(access.require_admin)):
    """Withdraw a pending invitation (admins): its link stops working."""
    revoked = invitations.revoke(invitation_id, admin, _address(request), storage=access._storage)
    if not revoked:
        raise HTTPException(status_code=404, detail="Invitation not found")
    return revoked


class InvitationToken(BaseModel):
    token: str


class InvitationStart(InvitationToken):
    username: str


class InvitationAccept(InvitationStart):
    full_name: Optional[str] = None
    new_password: str
    code: str


def _open_invitation(token: str) -> tuple:
    """(invitations, the one a link is for); 400 unknown or used, 410 expired (never 401: see
    _reset_record). The caller holds users.locked()."""
    try:
        return invitations.find(token)
    except invitations.InvitationRefused as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))


@router.post("/invitations/accept")
async def invitation_preview(body: InvitationToken):
    """Opening an invitation: the email, role and name it's for, and a username to suggest."""
    with locked():
        _, invitation = _open_invitation(body.token)
        return invitations.preview(_users_or_503(), invitation)


@router.post("/invitations/accept/start")
async def invitation_start(body: InvitationStart):
    """The username chosen (checked: well formed and free), the authenticator to set up. Nothing is
    made until /invitations/accept/complete; starting again shows the same authenticator."""
    with locked():
        pending, invitation = _open_invitation(body.token)
        try:
            enrolment = invitations.start(_users_or_503(), pending, invitation, body.username)
        except invitations.InvitationRefused as exc:
            raise HTTPException(status_code=exc.status, detail=str(exc))
        invitations.save(pending)
    return enrolment


@router.post("/invitations/accept/complete")
async def invitation_complete(body: InvitationAccept, request: Request, response: Response):
    """The account made, once a code from the new authenticator is confirmed: the invited role, MFA
    on, ten backup codes (returned this once), signed in. The invitation is used up. Each wrong code is
    audited, and the fifth closes the invitation: the admin issues a new one."""
    if len(body.new_password) < MIN_PASSWORD:
        raise HTTPException(status_code=400, detail=f"Passwords need at least {MIN_PASSWORD} characters")
    address = _address(request)
    with locked():  # the invitation is claimed once: a second completion finds it gone
        pending, invitation = _open_invitation(body.token)
        users = _users_or_503()
        try:
            step = invitations.pending_step(invitation, body.code)
            if step is None:
                closed = invitations.wrong_code(pending, invitation, address, storage=access._storage)
                invitations.save(pending)
                raise HTTPException(status_code=400, detail=invitations.CLOSED if closed else
                                    "Incorrect code: check the app's clock and try the next one")
            record, codes = invitations.complete(users, pending, invitation, body.username, body.full_name,
                                                 body.new_password, step, address, storage=access._storage)
        except invitations.InvitationRefused as exc:
            raise HTTPException(status_code=exc.status, detail=str(exc))
    return {**_session(response, record), "backup_codes": codes}


@router.get("/users")
async def list_users(admin: dict = Depends(access.require_admin)):
    """Every user (admins)."""
    return [public(u) for u in load_users().values()]


@router.post("/users")
async def create_user(http_request: Request):
    """Gone: nobody makes an account with a password for someone else. A team server's accounts come
    by invitation (POST /users/invitations); a local stack's by its own sign-up (/register)."""
    access.require_admin(http_request)
    raise HTTPException(status_code=400, detail=invitations.INVITE_INSTEAD if settings.rowanholt_server_mode
                        else "Nobody makes an account with a password for someone else: on a local stack, "
                             "people sign up for themselves (Register)")


@router.patch("/users/{user_id}")
async def update_user(user_id: str, update: UserUpdate, request: Request,
                      admin: dict = Depends(access.require_admin)):
    """Change a user's role, status or name (admins). The last active admin stays one. Disabling an
    account ends its sessions and revokes its API tokens. Nobody sets another person's password, on a
    server or locally: a reset link lets them choose it (POST /users/{id}/reset-access)."""
    if update.password:
        raise HTTPException(status_code=400, detail=reset_access.RESET_INSTEAD)
    with locked():
        users = load_users()
        user = users.get(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        demoting = (update.role is not None and update.role != "admin") or update.is_active is False
        if user["role"] == "admin" and demoting:
            admins = [u for u in users.values() if u["role"] == "admin" and u.get("is_active", True)]
            if len(admins) <= 1:
                raise HTTPException(status_code=400, detail="That's the last active admin")
        if update.role is not None:
            if update.role not in ("admin", "user"):
                raise HTTPException(status_code=400, detail="Role must be admin or user")
            user["role"] = update.role
        if update.is_active is not None:
            if update.is_active and not user.get("is_active", True):
                _room_for_one_more(users)
                user["is_active"] = True
            elif not update.is_active and user.get("is_active", True):
                deactivate(user, admin, _address(request), storage=access._storage)
        if update.full_name is not None:
            user["full_name"] = update.full_name
        save_users(users)
    return public(user)


# ── Single sign-on ────────────────────────────────────────────────────────────

@router.get("/oidc/login")
async def oidc_login():
    """Start single sign-on: off to the identity provider."""
    if not settings.oidc_enabled:
        raise HTTPException(status_code=404, detail="Single sign-on isn't configured")
    flow = oidc.new_flow()
    try:
        url = await oidc.authorize_url(flow)
    except Exception as exc:  # noqa: BLE001 - an unreachable IdP becomes a message on the login page
        return RedirectResponse(f"/login?sso_error={quote(f'Identity provider unreachable: {exc}')}", status_code=302)
    redirect = RedirectResponse(url, status_code=302)
    redirect.set_cookie("oidc_flow", oidc.seal(flow), max_age=oidc.STATE_SECONDS, httponly=True,
                        secure=settings.rowanholt_server_mode, samesite="lax", path="/api/auth/oidc")
    return redirect


@router.get("/oidc/callback")
async def oidc_callback(request: Request, code: Optional[str] = None, state: Optional[str] = None,
                        error: Optional[str] = None, error_description: Optional[str] = None):
    """The identity provider's answer: verify it, sign the user in, back to the app."""
    def fail(message: str) -> RedirectResponse:
        return RedirectResponse(f"/login?sso_error={quote(message)}", status_code=302)

    if error:
        return fail(error_description or error)
    flow = oidc.unseal(request.cookies.get("oidc_flow"))
    if not flow or not code or state != flow.get("state"):
        return fail("Sign-in expired or didn't match; try again")
    try:
        claims = await oidc.claims_for(code, flow)
        user = oidc.user_for(claims)
    except oidc.SignInRefused as exc:
        return fail(str(exc))
    except Exception as exc:  # noqa: BLE001
        return fail(f"Single sign-on failed: {exc}")
    redirect = RedirectResponse("/login/sso", status_code=302)
    _session(redirect, user)
    redirect.delete_cookie("oidc_flow", path="/api/auth/oidc")
    return redirect
