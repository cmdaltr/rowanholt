"""
Single Sign-On (OpenID Connect)

The authorization code flow with PKCE against settings.oidc_issuer (Entra ID, Okta,
Keycloak, Google Workspace, ...). The ID token is checked against the issuer's
published keys, audience and nonce; the user is matched on the issuer and subject, or
created on first sign-in, and then gets the same session a password sign-in does.
"""

import base64
import hashlib
import re
import secrets
import time
from typing import Optional

import httpx
from jose import JWTError, jwt

try:
    from ..config import settings
    from .users import load_users, new_user, save_users
except ImportError:
    from config import settings
    from auth.users import load_users, new_user, save_users

CACHE_SECONDS = 3600
STATE_SECONDS = 600
ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"]

_cache: dict = {}


class SignInRefused(Exception):
    """The IdP vouched for the user, but Rivendell won't let them in (group, disabled)."""


async def _get_json(url: str) -> dict:
    cached = _cache.get(url)
    if cached and cached[0] > time.time():
        return cached[1]
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()
    _cache[url] = (time.time() + CACHE_SECONDS, data)
    return data


async def discovery() -> dict:
    return await _get_json(f"{settings.oidc_issuer.rstrip('/')}/.well-known/openid-configuration")


def redirect_uri() -> str:
    return f"{settings.rivendell_public_url.rstrip('/')}/api/auth/oidc/callback"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def new_flow() -> dict:
    """State, nonce and PKCE verifier for one sign-in."""
    return {"state": secrets.token_urlsafe(24), "nonce": secrets.token_urlsafe(24),
            "verifier": secrets.token_urlsafe(48)}


def challenge(verifier: str) -> str:
    return _b64url(hashlib.sha256(verifier.encode()).digest())


def seal(flow: dict) -> str:
    """The flow as a short-lived signed cookie value."""
    return jwt.encode({**flow, "exp": int(time.time()) + STATE_SECONDS}, settings.secret_key, algorithm="HS256")


def unseal(value: Optional[str]) -> Optional[dict]:
    if not value:
        return None
    try:
        return jwt.decode(value, settings.secret_key, algorithms=["HS256"])
    except JWTError:
        return None


async def authorize_url(flow: dict) -> str:
    doc = await discovery()
    params = {
        "response_type": "code",
        "client_id": settings.oidc_client_id,
        "redirect_uri": redirect_uri(),
        "scope": settings.oidc_scopes,
        "state": flow["state"],
        "nonce": flow["nonce"],
        "code_challenge": challenge(flow["verifier"]),
        "code_challenge_method": "S256",
    }
    return str(httpx.URL(doc["authorization_endpoint"], params=params))


async def claims_for(code: str, flow: dict) -> dict:
    """Exchange the code and return the verified ID token's claims."""
    doc = await discovery()
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(doc["token_endpoint"], data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri(),
            "client_id": settings.oidc_client_id,
            "client_secret": settings.oidc_client_secret,
            "code_verifier": flow["verifier"],
        }, headers={"Accept": "application/json"})
    if resp.status_code != 200:
        raise SignInRefused(f"The identity provider refused the code ({resp.status_code})")
    tokens = resp.json()
    id_token = tokens.get("id_token")
    if not id_token:
        raise SignInRefused("The identity provider returned no ID token")

    header = jwt.get_unverified_header(id_token)
    keys = (await _get_json(doc["jwks_uri"])).get("keys", [])
    key = next((k for k in keys if k.get("kid") == header.get("kid")), None)
    if key is None:
        # Keys rotated since we cached them
        _cache.pop(doc["jwks_uri"], None)
        keys = (await _get_json(doc["jwks_uri"])).get("keys", [])
        key = next((k for k in keys if k.get("kid") == header.get("kid")), None)
    if key is None or header.get("alg") not in ALGORITHMS:
        raise SignInRefused("The ID token isn't signed with one of the identity provider's keys")
    try:
        claims = jwt.decode(id_token, key, algorithms=[header["alg"]], audience=settings.oidc_client_id,
                            issuer=doc["issuer"], access_token=tokens.get("access_token"))
    except JWTError as exc:
        raise SignInRefused(f"The ID token didn't verify: {exc}")
    if claims.get("nonce") != flow["nonce"]:
        raise SignInRefused("The ID token's nonce doesn't match this sign-in")
    return claims


def _groups(claims: dict) -> list:
    value = claims.get(settings.oidc_groups_claim) or []
    return [value] if isinstance(value, str) else list(value)


def _username_for(claims: dict, users: dict) -> str:
    base = claims.get("preferred_username") or claims.get("email") or claims["sub"]
    base = re.sub(r"[^A-Za-z0-9._@-]", "_", base)[:56] or "user"
    taken = {u["username"] for u in users.values()}
    name, n = base, 2
    while name in taken:
        name, n = f"{base}-{n}", n + 1
    return name


def user_for(claims: dict) -> dict:
    """The Rivendell user for verified claims: matched on issuer and subject, created on
    first sign-in, with the admin role following the admin group when one is configured."""
    groups = _groups(claims)
    if settings.oidc_allowed_group and settings.oidc_allowed_group not in groups \
            and settings.oidc_admin_group not in groups:
        raise SignInRefused("Your account isn't in the group allowed to use Rivendell")
    subject = f"{claims['iss']}|{claims['sub']}"
    users = load_users()
    user = next((u for u in users.values() if u.get("oidc_subject") == subject), None)
    if user is None:
        user = new_user(_username_for(claims, users), claims.get("email", ""), role="user",
                        full_name=claims.get("name"), oidc_subject=subject)
        users[user["id"]] = user
    if not user.get("is_active", True):
        raise SignInRefused("Your Rivendell account is disabled")
    if settings.oidc_admin_group:
        user["role"] = "admin" if settings.oidc_admin_group in groups else "user"
    user["full_name"] = claims.get("name") or user.get("full_name")
    user["email"] = claims.get("email") or user.get("email", "")
    user["last_login"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    save_users(users)
    return user
