"""
Simple File-Based Authentication Routes

Lightweight authentication without database dependencies: users live in a JSON file
(auth/users.py). Password sign-in, single sign-on (auth/oidc.py) when configured, and,
in server mode, user administration for admins in place of open sign-up.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

try:
    from ..config import settings
    from .security import hash_password, verify_password, create_access_token
    from .users import (AdminPasswordMissing, find_user, init_default_admin, load_users,  # noqa: F401
                        new_user, public, save_users)
    from . import access, oidc, tokens
    from .throttle import throttle
except ImportError:
    from config import settings
    from auth.security import hash_password, verify_password, create_access_token
    from auth.users import (AdminPasswordMissing, find_user, init_default_admin, load_users,  # noqa: F401
                            new_user, public, save_users)
    from auth import access, oidc, tokens
    from auth.throttle import throttle

router = APIRouter(prefix="/api/auth", tags=["authentication"])
logger = logging.getLogger(__name__)

MIN_PASSWORD = 12


# Request/Response Models
class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    email: str  # Email validated manually
    username: str
    password: str
    full_name: Optional[str] = None
    role: str = "user"  # honoured for admins creating users in server mode


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
    password: Optional[str] = None
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
        secure=settings.rivendell_server_mode,
        samesite="lax",
        max_age=settings.access_token_expire_minutes * 60,
    )
    return {"access_token": access_token, "token_type": "bearer", "user": public(user)}


def _check_password_strength(password: str) -> None:
    if settings.rivendell_server_mode and len(password) < MIN_PASSWORD:
        raise HTTPException(status_code=400, detail=f"Passwords need at least {MIN_PASSWORD} characters")


def _users_or_503() -> dict:
    try:
        return init_default_admin()
    except AdminPasswordMissing as exc:
        raise HTTPException(status_code=503, detail=str(exc))


# Routes
@router.get("/config")
async def auth_config():
    """How this Rivendell signs people in, for the login page."""
    server = settings.rivendell_server_mode
    return {
        "server_mode": server,
        "local_login": settings.rivendell_local_login or not settings.oidc_enabled,
        "guest": not server,
        "register": not server,
        "sso": {"enabled": settings.oidc_enabled, "name": settings.oidc_display_name},
    }


@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends()
):
    """Login with username/email and password (OAuth2 form data)."""
    users = _users_or_503()
    name = form_data.username
    # Behind the server's proxy, uvicorn's --proxy-headers makes this the browser's address
    address = request.client.host if request.client else "unknown"
    wait = throttle.locked_for(name, address)
    if wait:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed sign-ins; try again in {wait // 60 + 1} minutes",
        )

    user = find_user(users, name)
    if not user or not user.get("hashed_password") or not verify_password(form_data.password, user["hashed_password"]):
        throttle.failed(name, address)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    throttle.succeeded(name, address)

    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )
    # With single sign-on as the only way in, a password still works for admins (break glass)
    if settings.oidc_enabled and not settings.rivendell_local_login and user["role"] != "admin":
        raise HTTPException(status_code=403, detail=f"Sign in with {settings.oidc_display_name}")

    user["last_login"] = datetime.utcnow().isoformat()
    save_users(users)
    return _session(response, user)


@router.post("/guest", response_model=LoginResponse)
async def login_as_guest(response: Response):
    """Login as guest user (limited access). Not on a server."""
    if settings.rivendell_server_mode:
        raise HTTPException(status_code=403, detail="Guest access is off on this server")
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
            "email": "guest@rivendell.app",
            "username": "guest",
            "full_name": "Guest User",
            "role": "guest",
        }
    }


@router.post("/register", response_model=UserResponse)
async def register(request: RegisterRequest, http_request: Request):
    """Register a new user account. On a server, only admins create accounts."""
    role = "user"
    if settings.rivendell_server_mode:
        access.require_admin(http_request)
        role = request.role
    _check_password_strength(request.password)
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

    try:
        user = new_user(request.username, request.email, role=role, password=request.password,
                        full_name=request.full_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    users[user["id"]] = user
    save_users(users)
    return public(user)


@router.post("/logout")
async def logout(response: Response):
    """Logout current user."""
    response.delete_cookie(key="session_token")
    return {"message": "Logged out successfully"}


@router.post("/forgot-password")
async def forgot_password(email: str):
    """Request password reset (stub)."""
    # Always return success to prevent email enumeration
    return {"message": "If the email exists, a password reset link has been sent"}


@router.get("/me")
async def get_current_user(user: dict = Depends(access.current_user)):
    """The signed-in user (the local analyst on a local stack without a sign-in)."""
    return user


@router.post("/session", response_model=LoginResponse)
async def session_from_cookie(request: Request, response: Response):
    """A bearer token for the session cookie, for the frontend after single sign-on."""
    user = access.user_from_request(request)
    if not user:
        raise HTTPException(status_code=401, detail="Sign in required")
    return _session(response, load_users()[user["id"]])


@router.get("/verify")
async def verify(request: Request, response: Response, login_redirect: bool = False,
                 service: Optional[str] = None):
    """200 for a signed-in user, 401 otherwise: the reverse proxy's check in front of
    Kibana, Splunk and the ATT&CK Navigator on a server. With login_redirect the refusal
    is a redirect to the sign-in page, which the proxy passes on to the browser. For the
    Navigator (service=navigator), a case's layer also needs access to the case: the
    proxy sends the URI it's asking about in X-Forwarded-Uri."""
    user = access.user_from_request(request)
    if not user and login_redirect and settings.rivendell_public_url:
        return RedirectResponse(f"{settings.rivendell_public_url.rstrip('/')}/login", status_code=302)
    if not user:
        raise HTTPException(status_code=401, detail="Sign in required")
    if service == "navigator" and not access.layer_allowed(user, request.headers.get("X-Forwarded-Uri", "/")):
        raise HTTPException(status_code=403, detail="Not your case")
    response.headers["X-Rivendell-User"] = user["username"]
    return {"username": user["username"]}


@router.post("/change-password")
async def change_password(body: PasswordChange, user: dict = Depends(access.current_user)):
    """Change the caller's own password."""
    users = load_users()
    record = users.get(user["id"])
    if not record or not record.get("hashed_password"):
        raise HTTPException(status_code=400, detail="This account signs in with single sign-on")
    if not verify_password(body.current_password, record["hashed_password"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    _check_password_strength(body.new_password)
    record["hashed_password"] = hash_password(body.new_password)
    save_users(users)
    return {"message": "Password changed"}


# ── API tokens (auth/tokens.py) ──────────────────────────────────────────────

class TokenRequest(BaseModel):
    name: str
    scope: str = "full"
    days: int = tokens.DEFAULT_DAYS


def _token_storage():
    if not settings.rivendell_server_mode:
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


@router.get("/users")
async def list_users(admin: dict = Depends(access.require_admin)):
    """Every user (admins)."""
    return [public(u) for u in load_users().values()]


@router.post("/users", response_model=UserResponse)
async def create_user(request: RegisterRequest, http_request: Request):
    """Create a user (admins)."""
    access.require_admin(http_request)
    _check_password_strength(request.password)
    users = _users_or_503()
    if find_user(users, request.username) or find_user(users, request.email):
        raise HTTPException(status_code=400, detail="Username or email already taken")
    try:
        user = new_user(request.username, request.email, role=request.role, password=request.password,
                        full_name=request.full_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    users[user["id"]] = user
    save_users(users)
    return public(user)


@router.patch("/users/{user_id}")
async def update_user(user_id: str, update: UserUpdate, admin: dict = Depends(access.require_admin)):
    """Change a user's role, status, password or name (admins). The last active admin stays one."""
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
        user["is_active"] = update.is_active
    if update.password:
        _check_password_strength(update.password)
        user["hashed_password"] = hash_password(update.password)
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
                        secure=settings.rivendell_server_mode, samesite="lax", path="/api/auth/oidc")
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
