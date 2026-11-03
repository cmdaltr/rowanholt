"""
Security Utilities

Encryption, sanitization, and security helper functions.
"""

import os
import secrets
import base64
import re
from typing import List, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import bleach
import pyotp

from ..config import settings


# Initialize encryption key from settings
def _get_encryption_key() -> bytes:
    """Get or generate encryption key for sensitive data."""
    # In production, this should come from environment variable or secure key management
    key_material = settings.secret_key.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'dernvale_mfa_salt',  # In production, use unique salt per deployment
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(key_material))
    return key


_cipher = Fernet(_get_encryption_key())


def encrypt_data(data: str) -> str:
    """Encrypt sensitive data."""
    if not data:
        return ""
    return _cipher.encrypt(data.encode()).decode()


def decrypt_data(encrypted_data: str) -> str:
    """Decrypt sensitive data."""
    if not encrypted_data:
        return ""
    return _cipher.decrypt(encrypted_data.encode()).decode()


# Input sanitization functions
def sanitize_html(text: str) -> str:
    """Sanitize HTML input to prevent XSS attacks."""
    if not text:
        return ""
    # Remove all HTML tags and attributes
    return bleach.clean(text, tags=[], attributes={}, strip=True)


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent directory traversal attacks."""
    if not filename:
        return ""
    # Remove any path components
    filename = os.path.basename(filename)
    # Remove or replace dangerous characters
    filename = re.sub(r'[^\w\s\-\.]', '_', filename)
    # Prevent hidden files
    if filename.startswith('.'):
        filename = '_' + filename[1:]
    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:255-len(ext)] + ext
    return filename


def sanitize_path(path: str, allowed_prefixes: List[str]) -> Optional[str]:
    """
    Sanitize and validate file path.

    Args:
        path: Path to validate
        allowed_prefixes: List of allowed path prefixes

    Returns:
        Sanitized path if valid, None otherwise
    """
    if not path:
        return None

    # Resolve to absolute path to prevent traversal
    try:
        abs_path = os.path.abspath(path)
    except (ValueError, OSError):
        return None

    # Check if path starts with any allowed prefix
    for prefix in allowed_prefixes:
        abs_prefix = os.path.abspath(prefix)
        if abs_path.startswith(abs_prefix):
            return abs_path

    return None


def sanitize_email(email: str) -> str:
    """Sanitize and validate email address."""
    if not email:
        return ""
    # Remove whitespace and convert to lowercase
    email = email.strip().lower()
    # Basic email validation regex
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        raise ValueError("Invalid email format")
    # Length limit
    if len(email) > 255:
        raise ValueError("Email too long")
    return email


def sanitize_username(username: str) -> str:
    """Sanitize and validate username."""
    if not username:
        return ""
    # Remove whitespace
    username = username.strip()
    # Only allow alphanumeric and underscore
    if not re.match(r'^[a-zA-Z0-9_]{3,50}$', username):
        raise ValueError("Username must be 3-50 characters, alphanumeric and underscore only")
    return username


def sanitize_case_number(case_number: str) -> str:
    """Sanitize case/incident number."""
    if not case_number:
        return ""
    # Remove dangerous characters but allow common separators
    case_number = re.sub(r'[^\w\s\-_/.]', '', case_number.strip())
    # Limit length
    if len(case_number) > 100:
        raise ValueError("Case number too long (max 100 characters)")
    return case_number


# MFA functions
def generate_totp_secret() -> str:
    """Generate a new TOTP secret for MFA."""
    return pyotp.random_base32()


def generate_totp_uri(secret: str, username: str, issuer: str = "Dernvale") -> str:
    """Generate TOTP provisioning URI for QR code."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def verify_totp_code(secret: str, code: str) -> bool:
    """Verify a TOTP code."""
    if not secret or not code:
        return False
    # Remove any whitespace from code
    code = code.strip().replace(' ', '')
    # Verify code is 6 digits
    if not re.match(r'^\d{6}$', code):
        return False
    totp = pyotp.TOTP(secret)
    # Allow for time skew (1 window before/after)
    return totp.verify(code, valid_window=1)


def generate_backup_codes(count: int = 10) -> List[str]:
    """Generate backup codes for MFA."""
    codes = []
    for _ in range(count):
        # Generate 8-character alphanumeric code
        code = secrets.token_hex(4).upper()
        # Format as XXXX-XXXX for readability
        formatted = f"{code[:4]}-{code[4:]}"
        codes.append(formatted)
    return codes


def hash_backup_code(code: str) -> str:
    """Hash a backup code for storage."""
    from .security import hash_password
    # Remove formatting
    code = code.replace('-', '').upper()
    # Hash like a password
    return hash_password(code)


def verify_backup_code(code: str, hashed_codes: List[str]) -> Optional[int]:
    """
    Verify a backup code against hashed codes.

    Returns:
        Index of matching code if found, None otherwise
    """
    from .security import verify_password
    if not code or not hashed_codes:
        return None

    # Remove formatting
    code = code.replace('-', '').replace(' ', '').upper()

    # Check against each hashed code
    for i, hashed_code in enumerate(hashed_codes):
        if verify_password(code, hashed_code):
            return i

    return None


# Rate limiting helpers
def generate_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token."""
    return secrets.token_urlsafe(length)


def constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return secrets.compare_digest(a.encode(), b.encode())
