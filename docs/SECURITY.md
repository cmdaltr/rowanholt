# Security Features & Implementation

## Overview

Rowanholt implements comprehensive security measures to protect sensitive forensic data and user credentials. This document outlines all security features and best practices.

## Authentication & Authorization

### Signing In

There are three ways in, and no others:

- **Password**: accounts in the user store (`auth/users.py`, a JSON file), made by an admin on a team server; there's no open sign-up there.
- **Single sign-on (OIDC)**: any OpenID Connect identity provider (Entra ID, Okta, Keycloak), set up in [SERVER.md](SERVER.md#single-sign-on); roles can follow an IdP group.
- **API tokens**: for scripts and Smith's MCP server ([API Tokens](#api-tokens-team-server) below).

### Multi-Factor Authentication

A team server's password accounts can add a second factor: a code from an authenticator app (TOTP), set up under Account → Security ([USAGE.md](USAGE.md#multi-factor-authentication)). The code is `auth/mfa.py`, with its routes in `auth/routes_simple.py`.

- **TOTP**: RFC 6238, HMAC-SHA1, 30-second steps, 6 digits, one step either side of now accepted. A step that's been used can't be used again by that account (the last one is kept in the account, and claimed in Redis so two requests racing with one code can't both win).
- **Enrolment**: the server makes a 160-bit secret and returns it as an `otpauth://` URI, a QR code (an SVG drawn by the server, so the browser needs no QR library and the secret goes nowhere else) and text to type in. Nothing changes until a code from it is confirmed. Setting up a new authenticator while MFA is on needs a current code first, and the new secret replaces the old only when it's confirmed.
- **The secret at rest**: Fernet-encrypted in the user store, with a key derived by HKDF-SHA256 from the server's `SECRET_KEY` (label `rowanholt mfa totp secret v1`). The API never returns it after enrolment. Changing `SECRET_KEY` makes stored secrets unreadable: those accounts need an admin's reset.
- **Backup codes**: ten, made when MFA goes on and shown once, each `XXXXX-XXXXX` from an unambiguous alphabet (49 random bits). Stored as HMAC-SHA256 under another derived key rather than bcrypt: they're random, not chosen by a person, so a slow hash adds nothing a key doesn't, and a sign-in checks up to ten. Each signs in once; Account shows how many are left and makes ten new ones (replacing the rest) for a current authenticator code.
- **Sign-in**: with MFA on, a right password doesn't sign in. `POST /api/auth/login` answers with a challenge, valid for five minutes, which only `POST /api/auth/login/mfa` takes, with a code or a backup code; it's signed with its own derived key, isn't a JWT or an API token, signs in once, and goes stale if the password changes. Wrong codes count towards the same lockout as wrong passwords, and a right password doesn't reset the count while the second factor is outstanding.
- **Turning it off**: the account's password and a current code (or a backup code). An admin can turn it off for someone who has lost both (`DELETE /api/auth/users/{id}/mfa`, or `rowanholt server users mfa-reset <username>` on the server); they set it up again from Account.
- **Requiring it**: `ROWANHOLT_REQUIRE_MFA=true` ([CONFIG.md](CONFIG.md)) signs a password user without MFA in only to set it up: every other route answers 403 until they have, and turning it off isn't offered (an admin's reset still is).
- **What it doesn't cover**: single sign-on accounts get MFA from the identity provider (Entra ID Conditional Access, Okta's sign-on policies, Keycloak's OTP), so Account says so rather than offering enrolment. API tokens are the non-interactive way in and need no second factor; they can't set up or change MFA. On an analyst's own machine (no server mode) there's no sign-in for it to protect, and Account says MFA applies to a team server's sign-in.
- **The audit log**: every MFA event is a row in `audit_logs` (resource type `user`): `mfa_enabled`, `mfa_reenrolled`, `mfa_disabled`, `mfa_backup_code_used`, `mfa_backup_codes_regenerated`, `mfa_failed` (with the stage: sign-in, enrolment, disable…) and `mfa_admin_reset`.

With single sign-on, `ROWANHOLT_LOCAL_LOGIN=false` leaves passwords to admins as a break-glass way in: give those admins MFA too, or keep their passwords long, few and out of daily use.

(`auth/routes.py` holds MFA routes from an earlier design, for a database user model that doesn't exist; the backend doesn't mount it.)

### Password Security

#### Hashing
- **Algorithm**: bcrypt with configurable cost factor
- **Salt**: Automatic per-password unique salt
- **Version**: bcrypt 4.x (no compatibility with legacy versions)
- **Max Length**: 72 bytes (bcrypt limitation)

#### Password Requirements
- At least 12 characters on a team server (checked by the backend)
- No password reset by email: an admin sets a new one (`rowanholt server users password <user>`, or `/api/auth/users`)
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
- **Scopes**: `smith-mcp` (read, ask Smith, flag leads, add notes, recorded as Smith; no admin areas) or `full` (the user's rights)
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

### HTML Sanitization
- **Library**: bleach
- **Scope**: All user-provided text fields (full names, etc.)
- **Method**: Complete tag/attribute stripping

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
- **Key Derivation**: PBKDF2-HMAC-SHA256
  - **Iterations**: 100,000
  - **Salt**: Application-specific (should be unique per deployment)
- **Use Cases**: none in this build. The helpers (`auth/security_utils.py`) serve only the unmounted MFA code in `auth/routes.py`; built-in MFA's TOTP secrets use HKDF and Fernet in `auth/mfa.py` ([Multi-Factor Authentication](#multi-factor-authentication))

### Key Management
- **Secret Key**: Loaded from `settings.secret_key`
- **Production**: Should use environment variable or secrets manager
- **Rotation**: Not implemented (requires migration script)

## Role-Based Access Control (RBAC)

### Roles
1. **ADMIN**: Full system access
   - User management
   - Password resets for other users
   - Account enable/disable
2. **USER**: Standard access
   - Job creation/management
   - Profile management
3. **GUEST**: Limited access
   - Read-only browsing
   - No job creation
   - No data persistence

### Admin Restrictions
- Admins cannot reset other admins' passwords (except self)
- Admins cannot disable their own account
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
**Status**: Not implemented
**TODO**: Add rate limiting middleware
- Login attempts: 5 per minute
- Registration: 3 per hour
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
- ✅ HTML sanitization with bleach
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
- [ ] Change default admin password
- [ ] Require MFA: `ROWANHOLT_REQUIRE_MFA=true` for password accounts, and for single sign-on, MFA at the identity provider (with `ROWANHOLT_LOCAL_LOGIN=false` if passwords should be for admins only)
- [ ] Set strong `SECRET_KEY` environment variable
- [ ] Enable HTTPS and secure cookies
- [ ] Use strong database credentials
- [ ] Enable database SSL/TLS
- [ ] Implement rate limiting
- [ ] Add account lockout mechanism
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
