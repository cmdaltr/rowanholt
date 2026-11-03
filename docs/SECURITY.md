# Security Features & Implementation

## Overview

Rivendell implements comprehensive security measures to protect sensitive forensic data and user credentials. This document outlines all security features and best practices.

## Authentication & Authorization

### Multi-Factor Authentication (MFA)

#### TOTP (Time-based One-Time Password)
- **Implementation**: PyOTP library for RFC 6238 compliance
- **Storage**: TOTP secrets are encrypted using Fernet (AES-128)
- **QR Code Setup**: Users can scan QR codes with authenticator apps (Google Authenticator, Authy, etc.)
- **Time Window**: 30-second validity window with 1-step tolerance for clock skew

#### Backup Codes
- **Generation**: 10 cryptographically secure backup codes per user
- **Format**: 8-character alphanumeric codes (XXXX-XXXX)
- **Storage**: Hashed using bcrypt before encryption
- **Single-Use**: Codes are removed after successful verification
- **Regeneration**: Users can regenerate backup codes with MFA verification

### Password Security

#### Hashing
- **Algorithm**: bcrypt with configurable cost factor
- **Salt**: Automatic per-password unique salt
- **Version**: bcrypt 4.x (no compatibility with legacy versions)
- **Max Length**: 72 bytes (bcrypt limitation)

#### Password Requirements
- Minimum 8 characters
- Validated on both frontend and backend
- Password reset requires email verification
- All user sessions invalidated on password change

### Session Management

#### JWT Tokens
- **Algorithm**: HS256 (HMAC-SHA256)
- **Secret Key**: Configurable via environment variable
- **Expiration**: 24 hours (configurable)
- **Payload**: User ID, role, expiration, unique JTI
- **Refresh**: Not implemented (users must re-login)

#### API Tokens (team server)
- **Purpose**: scripts and Eru's MCP server (`RIVENDELL_TOKEN`), made under Account in the web app
- **Format**: `rvt_` and 43 random characters; only the SHA-256 is stored (`api_tokens` table), the token is shown once
- **Lifetime**: 1 to 365 days (90 by default); revocable by its user or an admin; stops when the user is deactivated
- **Scopes**: `eru-mcp` (read, flag leads, add notes, recorded as Eru; no admin areas) or `full` (the user's rights)
- **Limits**: a token can't make or revoke tokens, or be exchanged for a session (`/api/auth/session`)

#### Session Cookies
- **httpOnly**: True (prevents XSS access)
- **secure**: Should be True in production (HTTPS only)
- **sameSite**: Lax (prevents CSRF)
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
- **Use Cases**:
  - MFA TOTP secrets
  - Hashed backup codes
  - Any PII in future features

### Key Management
- **Secret Key**: Loaded from `settings.secret_key`
- **Production**: Should use environment variable or secrets manager
- **Rotation**: Not implemented (requires migration script)

## Role-Based Access Control (RBAC)

### Roles
1. **ADMIN**: Full system access
   - User management
   - Password resets for other users
   - MFA disable for emergency access
   - Account enable/disable
2. **USER**: Standard access
   - Job creation/management
   - MFA setup
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
- **Default**: `rivendell:rivendell@postgres:5432/rivendell`
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
- MFA attempts: 10 per minute
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
- Password reset requests
- MFA enable/disable
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
- ⚠️ TODO: CSRF tokens for state-changing operations
- ✅ Origin validation via CORS

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
- ⚠️ TODO: Account lockout after N failed attempts
- ✅ MFA provides additional layer

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
- [ ] Implement CSRF protection
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

- **v2.1.0**: Added MFA, input sanitization, admin controls
- **v2.0.0**: Initial authentication system
- **v1.0.0**: No authentication (development only)
