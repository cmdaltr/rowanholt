# Security Features & Implementation

## Overview

Rowanholt implements comprehensive security measures to protect sensitive forensic data and user credentials. This document outlines all security features and best practices.

## Authentication & Authorization

### Signing In

There are three ways in, and no others:

- **Password**: accounts in the user store (`auth/users.py`, a JSON file), made by an admin on a team server; there's no open sign-up there.
- **Single sign-on (OIDC)**: any OpenID Connect identity provider (Entra ID, Okta, Keycloak), set up in [SERVER.md](SERVER.md#single-sign-on); roles can follow an IdP group.
- **API tokens**: for scripts and Smith's MCP server ([API Tokens](#api-tokens-team-server) below).

**Rowanholt has no built-in MFA.** There's no TOTP, no backup codes and no second step at sign-in. (`auth/routes.py` holds MFA routes from an earlier design, but the backend doesn't mount it, and the user store has nowhere to keep a second factor.) A team server should get MFA from its identity provider: sign people in through SSO, require MFA there (Entra ID Conditional Access, Okta's sign-on policies, Keycloak's OTP), and set `ROWANHOLT_LOCAL_LOGIN=false` so that only admins keep a password, as a break-glass way in. Those admin passwords are a single factor: keep them long, few and out of daily use.

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
- **Use Cases**: none in this build. The helpers (`auth/security_utils.py`) serve only the unmounted MFA code in `auth/routes.py`

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
- ⚠️ No built-in MFA: require it at the identity provider and sign in through SSO ([Signing In](#signing-in))

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
- [ ] Sign people in through SSO, with MFA required at the identity provider, and `ROWANHOLT_LOCAL_LOGIN=false` (Rowanholt has no MFA of its own)
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

- **v2.1.0**: Added input sanitization and admin controls (MFA routes were written too, but never mounted)
- **v2.0.0**: Initial authentication system
- **v1.0.0**: No authentication (development only)
