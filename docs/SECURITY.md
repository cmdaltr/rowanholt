# Security Features & Implementation

## Overview

Rowanholt implements comprehensive security measures to protect sensitive forensic data and user credentials. This document outlines all security features and best practices.

## Authentication & Authorization

### Signing In

There are three ways in, and no others:

- **Password**: accounts in the user store (`auth/users.py`, a JSON file), made by invitation on a team server, where there's no open sign-up; a local stack's sign-up is open only while it's published on loopback (`ROWANHOLT_BIND`).
- **Single sign-on (OIDC)**: any OpenID Connect identity provider (Entra ID, Okta, Keycloak), set up in [SERVER.md](SERVER.md#single-sign-on); roles can follow an IdP group.
- **API tokens**: for scripts and Smith's MCP server ([API Tokens](#api-tokens-team-server) below).

### Multi-Factor Authentication

A team server's password accounts can add a second factor: a code from an authenticator app (TOTP), set up under Account → Security ([USAGE.md](USAGE.md#multi-factor-authentication)). The code is `auth/mfa.py`, with its routes in `auth/routes_simple.py`.

- **TOTP**: RFC 6238, HMAC-SHA1, 30-second steps, 6 digits, one step either side of now accepted. A step that's been used can't be used again by that account (the last one is kept in the account, and claimed in Redis so two requests racing with one code can't both win).
- **Enrolment**: the server makes a 160-bit secret and returns it as an `otpauth://` URI, a QR code (an SVG drawn by the server, so the browser needs no QR library and the secret goes nowhere else) and text to type in. Nothing changes until a code from it is confirmed. Setting up a new authenticator while MFA is on needs a current code first, and the new secret replaces the old only when it's confirmed.
- **The secret at rest**: Fernet-encrypted in the user store, with a key derived by HKDF-SHA256 from the server's `SECRET_KEY` (label `rowanholt mfa totp secret v1`). The API never returns it after enrolment. Changing `SECRET_KEY` makes stored secrets unreadable: those accounts need an admin's reset.
- **Backup codes**: ten, made when MFA goes on and shown once, each `XXXXX-XXXXX` from an unambiguous alphabet (49 random bits). Stored as HMAC-SHA256 under another derived key rather than bcrypt: they're random, not chosen by a person, so a slow hash adds nothing a key doesn't, and a sign-in checks up to ten. Each signs in once; Account shows how many are left and makes ten new ones (replacing the rest) for a current authenticator code.
- **Sign-in**: with MFA on, a right password doesn't sign in. `POST /api/auth/login` answers with a challenge, valid for five minutes, which only `POST /api/auth/login/mfa` takes, with a code or a backup code; it's signed with its own derived key, isn't a JWT or an API token, signs in once, and goes stale if the password changes. Wrong codes count towards the same lockout as wrong passwords, and a right password doesn't reset the count while the second factor is outstanding.
- **Forgot password**: with email set up (`ROWANHOLT_SMTP_*`, `mailer.py`, the standard library's `smtplib` with STARTTLS or TLS), `POST /api/auth/forgot-password` emails an active password account the same one-time reset link an admin issues (`via: self-service`). The emailed link is always at `ROWANHOLT_PUBLIC_URL`, never built from the request's `Origin`, `Host` or `X-Forwarded-*` (host-header injection would otherwise email the victim a real token pointing at the asker), so without that setting Forgot password isn't offered. The answer is the same whether or not an account matched, and the email is sent after it, so neither the answer nor its timing says which addresses have accounts. Requests are limited per address and per client address. Asking ends no sessions and revokes no tokens, since anyone can ask (a request can't sign anyone out); completing the reset does both. It replaces an earlier self-service link, never an admin's that's still open. Without email, the page says to ask an administrator for a link (`rowanholt server users reset-access <username>`). A lost password is only ever recovered by a reset link, which also enrols a new authenticator: there's no reset by backup code (removed 20 November 2026, as Ostraka and Shikari have none). Backup codes still sign in in place of an app code.
- **Turning it off**: the account's password and a current code (or a backup code). An admin can turn it off for someone who has lost both (`DELETE /api/auth/users/{id}/mfa`, or `rowanholt server users mfa-reset <username>` on the server); they set it up again from Account.
- **First admins**: a local stack (an analyst's machine, the desktop app) seeds `admin` / `3000YearsAgo` into an empty store (audited, `default_admin_seeded`), a published password that's acceptable only because the stack is this machine's alone: when `ROWANHOLT_BIND` publishes it beyond loopback, nothing is seeded and the backend logs why (and a local stack's API answers anyone who reaches it without signing in anyway: run a server instead). A team server seeds nothing and ignores `ROWANHOLT_ADMIN_PASSWORD`; its first admin comes from `rowanholt server users first-admin <email>`, an admin's invitation (only the newest works, refused once an active admin exists unless `--force`, no licence place needed while no admin can sign in), printed by the CLI or `rowanholt start`, never logged. Open sign-up and guests follow the seeding's guard: only on a local stack published on loopback.
- **Invitations**: a server's accounts are made by invitation (`rowanholt server users invite <email>`, or `POST /api/auth/users/invitations`; `auth/invitations.py`), the same flow as a reset of access ending in a new account, and sharing its code: a 256-bit token in the link's fragment (`/accept-invite#<token>`), only its SHA-256 kept, 24 hours, single use, a newer invitation for the email replacing an older one. The person chooses their username and password, and the account is made only once a code from the new authenticator is confirmed, with MFA on and ten backup codes. Nobody sets another person's password, on a server or a local stack (`POST /api/auth/users` and a password in `PATCH /api/auth/users/{id}` are refused, and the CLI has no `add` or `password`), so nobody but its owner ever knows it. Opening the link again shows the same authenticator; each wrong code is audited, and the fifth closes the invitation. An invitation is refused at completion if the admin who made it has since been disabled or is no longer an admin. Pending invitations live in `invitations.json` beside the users (mode 600), not in `users.json`, so nothing that reads the accounts mistakes one for an account; each holds a licence place.
- **Resetting access**: for someone who has lost their password, authenticator or backup codes, an admin issues a one-time link (`rowanholt server users reset-access <username>`, or `POST /api/auth/users/{id}/reset-access`; `auth/reset_access.py`). Issuing ends the account's sessions and revokes its API tokens, which a password change doesn't reach, and replaces any earlier link. The token (256 random bits) is in the link's fragment, so it never reaches a server or proxy log, and only its SHA-256 is kept, on the account with its expiry, 24 hours on. The page gets a new TOTP secret from the server, which keeps it encrypted on the account rather than trusting one sent back, and nothing changes until a code from it is confirmed with the new password: then MFA is on with that secret (always, whatever `ROWANHOLT_REQUIRE_MFA` says), ten new backup codes replace the old ones, the link is used up, sessions end and API tokens are revoked again, and the person is signed in. Opening the link again shows the same authenticator. Wrong codes count towards the sign-in lockout, and a locked account gets 429 at the link as at sign-in. An expired link says so (410) for a day, then reads as never valid. It works on a local stack too. Until then the old password and authenticator stand, so a link nobody opens takes nothing away; to shut someone out, disable the account. Single sign-on accounts are refused: their identity provider handles recovery.
- **Requiring it**: `ROWANHOLT_REQUIRE_MFA=true` ([CONFIG.md](CONFIG.md)) signs a password user without MFA in only to set it up: every other route answers 403 until they have, and turning it off isn't offered (an admin's reset still is).
- **What it doesn't cover**: single sign-on accounts get MFA from the identity provider (Entra ID Conditional Access, Okta's sign-on policies, Keycloak's OTP), so Account says so rather than offering enrolment. API tokens are the non-interactive way in and need no second factor; they can't set up or change MFA. On an analyst's own machine (no server mode) there's no sign-in for it to protect, and Account says MFA applies to a team server's sign-in, except to an account that already has MFA on (a reset of access turns it on there too): that one manages it as on a server, new backup codes, a new authenticator and turning it off under the same rules.
- **Claimed once**: `users.json` and `invitations.json` are read, checked and written back under an exclusive file lock (`users.json.lock`, `fcntl.flock`) that the API and the CLI share, so two completions of one link can't both succeed and one write can't undo another.
- **Deactivation**: disabling an account ends its sessions and revokes its API tokens (`account_deactivated`, with the count), so enabling it again brings neither back.
- **The audit log**: every MFA event is a row in `audit_logs` (resource type `user`): `mfa_enabled`, `mfa_reenrolled`, `mfa_disabled`, `mfa_backup_code_used`, `mfa_backup_codes_regenerated`, `mfa_failed` (with the stage: sign-in, enrolment, disable, backup codes…) and `mfa_admin_reset`; an invitation is `invitation_created`, `invitation_revoked` (withdrawn, or `reason: replaced` by a newer one) and `account_created`, an invitation's wrong codes are `invitation_wrong_code` and the fifth closes it, `invitation_closed`; a reset of someone's access is `access_reset_issued` (by the admin, `server-cli` or the person, with `via` admin, cli or self-service, and how many API tokens were revoked), `access_reset_failed` (a wrong code) and `access_reset_completed`; and `account_locked` (the failure that locks a username, with its stage), `account_created` (an invitation or a local sign-up), `account_deactivated` and `default_admin_seeded`.

With single sign-on, `ROWANHOLT_LOCAL_LOGIN=false` leaves passwords to admins as a break-glass way in: give those admins MFA too, or keep their passwords long, few and out of daily use.

### Password Security

#### Hashing
- **Algorithm**: bcrypt with configurable cost factor
- **Salt**: Automatic per-password unique salt
- **Version**: bcrypt 4.x (no compatibility with legacy versions)
- **Max Length**: 72 bytes (bcrypt limitation)

#### Password Requirements
- At least 12 characters on a team server, and at a reset link anywhere (checked by the backend); a local stack's sign-up and Change Password set no minimum
- Chosen by the account's owner: on a server, a new account's password is set by the person accepting the invitation, never by an admin
- Reset by a one-time link, never by an admin choosing one: an admin issues it (`rowanholt server users reset-access <user>`), or, with email set up, the person asks for it from Forgot password; they choose the new password there
- Failed sign-ins lock the username ([SERVER.md](SERVER.md#how-sign-in-lockouts-work))

### Session Management

#### JWT Tokens
- **Algorithm**: HS256 (HMAC-SHA256)
- **Secret Key**: Configurable via environment variable
- **Expiration**: 24 hours (configurable)
- **Payload**: User ID, role, expiration, unique JTI
- **Refresh**: Not implemented (users must re-login)

#### API Tokens (team server)
- **Purpose**: scripts and Smith's MCP server (`ROWANHOLT_TOKEN`), made under Account in the web app
- **Format**: `rvt_` and 43 random characters; only the SHA-256 is stored (`api_tokens` table), the token is shown once
- **Lifetime**: 1 to 365 days (90 by default); revocable by its user or an admin; stops when the user is deactivated
- **Scopes**: `smith-mcp` (read, ask Smith, flag leads, add notes, recorded as Smith; no admin areas), `ostraka` (made by pairing with Ostraka: read jobs and their cases, the case-id check and the file browser, and start jobs; nothing else, no admin areas) or `full` (the user's rights)
- **Limits**: a token can't make or revoke tokens, be exchanged for a session (`/api/auth/session`), set a password or manage accounts (`/api/auth/users`, `/api/auth/change-password`): each would outlive the token, so revoking it ends the access

#### Session Cookies
- **httpOnly**: True (prevents XSS access)
- **secure**: Should be True in production (HTTPS only)
- **sameSite**: Lax (stops other sites, not the same site: every app on a tailnet is one site, since `ts.net` is a public suffix; see CSRF below)
- **Expiration**: Synchronized with token expiration

#### Session Storage
- Database-backed sessions in PostgreSQL
- Session invalidation on logout
- Automatic cleanup of expired sessions
- Last activity tracking

## Input Sanitization

### HTML Escaping
- User-provided text (full names, notes, findings) is stored as written and escaped where it's shown:
  React renders text, never HTML

### Path Sanitization
- **Directory Traversal Protection**: Absolute path resolution
- **Allowlist**: Only paths under configured `allowed_paths`
- **Validation**: Path existence and accessibility checks

### Email Validation
- **Format**: RFC-compliant regex pattern
- **Length**: Maximum 255 characters
- **Normalization**: Lowercased and trimmed

### Username Validation
- **Characters**: Alphanumeric and underscore only
- **Length**: 3-50 characters
- **Pattern**: `^[a-zA-Z0-9_]{3,50}$`

### Case Number Validation
- **Characters**: Alphanumeric, spaces, hyphens, underscores, slashes, dots
- **Length**: Maximum 100 characters
- **Sanitization**: Dangerous characters removed

## Encryption

### Sensitive Data Encryption
- **Algorithm**: Fernet (symmetric encryption using AES-128 in CBC mode with HMAC)
- **Key Derivation**: HKDF-SHA256 from the server's secret key, one label per purpose
- **Use Cases**: built-in MFA's TOTP secrets use HKDF and Fernet in `auth/mfa.py` ([Multi-Factor Authentication](#multi-factor-authentication))

### Key Management
- **Secret Key**: Loaded from `settings.secret_key`
- **Production**: Should use environment variable or secrets manager
- **Rotation**: Not implemented (requires migration script)

## Role-Based Access Control (RBAC)

### Roles
1. **ADMIN**: Full system access
   - User management (invitations, roles)
   - Reset-access links for other users (never choosing their password)
   - Account enable/disable
2. **USER**: Standard access
   - Job creation/management
   - Profile management
3. **GUEST**: Limited access
   - Only on a local stack published on loopback
   - Acts as the local analyst; no account, no data of its own

### Admin Restrictions
- Nobody sets another person's password, admins included, on a server or locally: they issue a reset link
- The last active admin can't be demoted or disabled
- Admin actions are logged (audit trail)

## Security Headers

### CORS (Cross-Origin Resource Sharing)
```python
allowed_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5687",
    "http://127.0.0.1:5687",
    "http://localhost:5688",
    "http://127.0.0.1:5688",
]
```
- **Credentials**: Allowed
- **Methods**: All
- **Headers**: All

**Production TODO**: Restrict to production domains only

### Content Security Policy
**Status**: Not implemented
**TODO**: Add CSP headers to prevent XSS

### HTTPS
**Status**: Not enforced
**TODO**:
- Enable secure cookies in production
- Enforce HTTPS redirects
- HSTS headers

## Database Security

### Connection
- **Driver**: asyncpg for async, psycopg2 for sync
- **Pool Size**: 10 connections
- **Max Overflow**: 20
- **SSL**: Not configured (should enable for production)

### Credentials
- **Storage**: Environment variables or .env file
- **Default**: `rowanholt:rowanholt@postgres:5432/rowanholt`
- **Production TODO**: Use strong unique credentials

### SQL Injection Prevention
- **ORM**: SQLAlchemy with parameterized queries
- **Raw SQL**: Avoided except where necessary
- **Validation**: All inputs validated before queries

## API Security

### Rate Limiting
**Status**: for accounts only: sign-in lockouts (failed passwords, codes and reset-link codes), and Forgot password's 3 requests an hour for one address and 10 from one client address
**TODO**: Add rate limiting middleware
- API calls: 100 per minute per user

### Request Size Limits
- **Upload Size**: 100GB max (configurable)
- **JSON Body**: Default FastAPI limits

### Authentication Bypass Protection
- Guest role cannot access protected endpoints
- Token verification on every request
- Session validation against database

## Logging & Auditing

### Security Events Logged
- Login attempts (success/failure)
- Password changes
- Admin actions
- Account lockouts

### Log Storage
- **Location**: Application logs (TODO: centralize)
- **Format**: ISO 8601 timestamps
- **Sensitive Data**: Passwords never logged

### Audit Trail
- Database table: `audit_logs`
- Tracks: user_id, action, timestamp, IP, metadata
- Retention: Indefinite (should configure retention policy)

## Threat Mitigation

### Cross-Site Scripting (XSS)
- ✅ Text escaped on display (React), never rendered as HTML
- ✅ httpOnly cookies
- ⚠️ TODO: Content Security Policy headers
- ✅ No innerHTML usage in frontend

### Cross-Site Request Forgery (CSRF)
- ✅ SameSite cookie attribute
- ✅ A state-changing `/api` request signed in by the session cookie must send `X-Rowanholt: 1` (`auth/access.py`); the web app's API client sends it, and a page on another origin can't without CORS allowing it. Bearer tokens don't need it ([API.md](API.md#cross-site-requests-the-x-rowanholt-header))
- ✅ Origin validation via CORS (and an origin check on the case browser's websocket)

### SQL Injection
- ✅ SQLAlchemy ORM parameterized queries
- ✅ Input validation
- ✅ No string concatenation in queries

### Directory Traversal
- ✅ Path sanitization and validation
- ✅ Allowlist-based path access
- ✅ Absolute path resolution

### Brute Force Attacks
- ⚠️ TODO: Rate limiting on login
- ✅ Account lockout after repeated failed sign-ins ([SERVER.md](SERVER.md#how-sign-in-lockouts-work))
- ✅ MFA (TOTP and backup codes) for password accounts, required with `ROWANHOLT_REQUIRE_MFA=true`; single sign-on accounts get it from the identity provider ([Multi-Factor Authentication](#multi-factor-authentication))

### Session Hijacking
- ✅ Secure token generation
- ✅ Token expiration
- ✅ Session invalidation on logout
- ⚠️ TODO: Secure cookies (HTTPS)
- ⚠️ TODO: Session binding to IP/User-Agent

### Timing Attacks
- ✅ Constant-time comparison for tokens
- ✅ bcrypt (inherently timing-attack resistant)

## Production Security Checklist

### Critical (Must Do)
- [ ] A team server seeds no account: make the first admin with `rowanholt server users first-admin <email>` ([SERVER.md](SERVER.md#the-first-admin)), and on a server set up before 19 November 2026, remove `ROWANHOLT_ADMIN_PASSWORD` (`server init` again does) and change `admin`'s password if it still has that one. The local default (`admin` / `3000YearsAgo`) is only made while the stack is published on loopback
- [ ] Require MFA: `ROWANHOLT_REQUIRE_MFA=true` for password accounts, and for single sign-on, MFA at the identity provider (with `ROWANHOLT_LOCAL_LOGIN=false` if passwords should be for admins only)
- [ ] Set strong `SECRET_KEY` environment variable
- [ ] Enable HTTPS and secure cookies
- [ ] Use strong database credentials
- [ ] Enable database SSL/TLS
- [ ] Implement rate limiting
- [x] Add account lockout mechanism
- [ ] Configure CSP headers
- [ ] Restrict CORS to production domains
- [ ] Set up centralized logging

### Important (Should Do)
- [x] Implement CSRF protection (the `X-Rowanholt` header, 12 November 2026)
- [ ] Add session IP/User-Agent validation
- [ ] Configure key rotation policy
- [ ] Set up automated security scanning
- [ ] Implement password complexity rules
- [ ] Add login attempt monitoring/alerting
- [ ] Configure log retention policy
- [ ] Set up secrets manager (AWS Secrets Manager, HashiCorp Vault)

### Recommended (Nice to Have)
- [ ] Implement WebAuthn/FIDO2 support
- [ ] Add security headers (HSTS, X-Frame-Options, etc.)
- [ ] Set up WAF (Web Application Firewall)
- [ ] Implement honeypot fields
- [ ] Add geo-blocking for suspicious countries
- [ ] Configure DDoS protection
- [ ] Implement anomaly detection

## Security Reporting

If you discover a security vulnerability, please:
1. Do not open a public issue
2. Email security contact (TODO: add email)
3. Provide detailed reproduction steps
4. Allow 90 days for fix before disclosure

## Dependencies Security

### Regular Updates
```bash
# Check for vulnerabilities
pip-audit

# Update dependencies
pip install --upgrade -r requirements/web.txt
```

### Known Vulnerabilities
- None currently identified

## Compliance

### Data Protection
- **GDPR**: Supports right to erasure (user deletion)
- **Password Storage**: Industry standard bcrypt
- **Encryption**: AES-128 for sensitive data

### Forensic Standards
- Evidence integrity preserved
- Chain of custody maintained in audit logs
- No modification of source evidence

## Version History

- **12 November 2026**: built-in MFA for password accounts (TOTP, backup codes, admins' reset, `ROWANHOLT_REQUIRE_MFA`)
- **v2.1.0**: Added input sanitization and admin controls (MFA routes were written too, but never mounted)
- **v2.0.0**: Initial authentication system
- **v1.0.0**: No authentication (development only)
