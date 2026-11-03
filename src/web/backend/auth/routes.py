"""
Authentication Routes

Login, registration, password reset, and session management.
"""

import uuid
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Response, Cookie
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, validator
from sqlalchemy.orm import Session

from ..database import get_db_dependency
from ..models.database import User, UserSettings, Session as UserSession, UserRole
from ..config import settings
from .security import hash_password, verify_password, create_access_token
from .dependencies import get_current_user, require_auth, require_admin
from .security_utils import (
    sanitize_email, sanitize_username, sanitize_html,
    generate_totp_secret, generate_totp_uri, verify_totp_code,
    generate_backup_codes, hash_backup_code, verify_backup_code,
    encrypt_data, decrypt_data, generate_secure_token
)

router = APIRouter(prefix="/api/auth", tags=["authentication"])


# Request/Response Models
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str
    full_name: Optional[str] = None

    @validator('username')
    def username_valid(cls, v):
        if len(v) < 3:
            raise ValueError('Username must be at least 3 characters')
        if not v.replace('_', '').isalnum():
            raise ValueError('Username must be alphanumeric (underscores allowed)')
        return v

    @validator('password')
    def password_strong(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v


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
    created_at: datetime
    last_login: Optional[datetime]


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

    @validator('new_password')
    def password_strong(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v


# Routes
@router.post("/register", response_model=UserResponse)
async def register(
    request: RegisterRequest,
    db: Session = Depends(get_db_dependency),
):
    """
    Register a new user account.
    """
    try:
        # Sanitize inputs
        email = sanitize_email(request.email)
        username = sanitize_username(request.username)
        full_name = sanitize_html(request.full_name) if request.full_name else None

        # Check if email already exists
        if db.query(User).filter(User.email == email).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered",
            )

        # Check if username already exists
        if db.query(User).filter(User.username == username).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already taken",
            )

        # Create user
        user = User(
            id=str(uuid.uuid4()),
            email=email,
            username=username,
            hashed_password=hash_password(request.password),
            full_name=full_name,
            role=UserRole.USER,
            is_active=True,
            created_at=datetime.utcnow(),
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    db.add(user)
    db.flush()

    # Create default user settings
    user_settings = UserSettings(
        id=str(uuid.uuid4()),
        user_id=user.id,
    )
    db.add(user_settings)
    db.commit()

    return user


@router.post("/login", response_model=LoginResponse)
async def login(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db_dependency),
):
    """
    Login with username/email and password.
    """
    # Find user by username or email
    user = db.query(User).filter(
        (User.username == form_data.username) | (User.email == form_data.username)
    ).first()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    # Create access token
    access_token = create_access_token(data={"sub": user.id, "role": user.role})

    # Create session
    session = UserSession(
        id=str(uuid.uuid4()),
        user_id=user.id,
        token=access_token,
        is_active=True,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes),
        last_activity=datetime.utcnow(),
    )
    db.add(session)

    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()

    # Set session cookie
    response.set_cookie(
        key="session_token",
        value=access_token,
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax",
        max_age=settings.access_token_expire_minutes * 60,
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "full_name": user.full_name,
            "role": user.role,
        }
    }


@router.post("/guest")
async def login_as_guest(response: Response):
    """
    Login as guest user (limited access, no persistence).
    """
    # Create a temporary guest token
    guest_token = create_access_token(
        data={"sub": "guest", "role": UserRole.GUEST},
        expires_delta=timedelta(seconds=settings.guest_session_timeout)
    )

    response.set_cookie(
        key="session_token",
        value=guest_token,
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax",
        max_age=settings.guest_session_timeout,
    )

    return {
        "access_token": guest_token,
        "token_type": "bearer",
        "user": {
            "id": "guest",
            "email": "guest@dernvale.app",
            "username": "guest",
            "role": UserRole.GUEST,
        }
    }


@router.post("/logout")
async def logout(
    response: Response,
    session_token: Optional[str] = Cookie(None, alias="session_token"),
    current_user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db_dependency),
):
    """
    Logout current user.
    """
    if session_token and current_user:
        # Invalidate session
        session = db.query(UserSession).filter(
            UserSession.token == session_token,
            UserSession.user_id == current_user.id
        ).first()

        if session:
            session.is_active = False
            db.commit()

    # Clear cookie
    response.delete_cookie(key="session_token")

    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(require_auth),
):
    """
    Get current authenticated user information.
    """
    return current_user


@router.post("/forgot-password")
async def forgot_password(
    request: ForgotPasswordRequest,
    db: Session = Depends(get_db_dependency),
):
    """
    Request password reset. Sends email with reset token.
    """
    user = db.query(User).filter(User.email == request.email).first()

    # Always return success to prevent email enumeration
    if not user:
        return {"message": "If the email exists, a password reset link has been sent"}

    # Generate reset token
    reset_token = str(uuid.uuid4())
    user.password_reset_token = reset_token
    user.password_reset_expires = datetime.utcnow() + timedelta(hours=1)
    db.commit()

    # TODO: Send email with reset link
    # For now, just log it (in production, use email service)
    print(f"Password reset token for {user.email}: {reset_token}")

    return {"message": "If the email exists, a password reset link has been sent"}


@router.post("/reset-password")
async def reset_password(
    request: ResetPasswordRequest,
    db: Session = Depends(get_db_dependency),
):
    """
    Reset password using reset token.
    """
    user = db.query(User).filter(
        User.password_reset_token == request.token,
        User.password_reset_expires > datetime.utcnow()
    ).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    # Update password
    user.hashed_password = hash_password(request.new_password)
    user.password_reset_token = None
    user.password_reset_expires = None

    # Invalidate all sessions
    db.query(UserSession).filter(UserSession.user_id == user.id).update(
        {"is_active": False}
    )

    db.commit()

    return {"message": "Password reset successfully"}


# MFA Endpoints
class MFASetupResponse(BaseModel):
    secret: str
    qr_code_uri: str
    backup_codes: list[str]


class MFAVerifyRequest(BaseModel):
    code: str


class MFAEnableRequest(BaseModel):
    code: str


@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(
    current_user: User = Depends(require_auth),
    db: Session = Depends(get_db_dependency),
):
    """
    Initialize MFA setup for the current user.
    Generates TOTP secret and backup codes.
    """
    # Generate TOTP secret
    secret = generate_totp_secret()

    # Generate QR code URI
    qr_uri = generate_totp_uri(secret, current_user.username)

    # Generate backup codes
    backup_codes = generate_backup_codes(10)

    # Don't save yet - user must verify first
    # Store temporarily in session or return to frontend
    return {
        "secret": secret,
        "qr_code_uri": qr_uri,
        "backup_codes": backup_codes,
    }


@router.post("/mfa/enable")
async def enable_mfa(
    request: MFAEnableRequest,
    secret: str,
    backup_codes: list[str],
    current_user: User = Depends(require_auth),
    db: Session = Depends(get_db_dependency),
):
    """
    Enable MFA after verifying the TOTP code.
    """
    # Verify the TOTP code
    if not verify_totp_code(secret, request.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code",
        )

    # Hash backup codes
    hashed_backup_codes = [hash_backup_code(code) for code in backup_codes]

    # Update user with encrypted MFA data
    current_user.mfa_enabled = True
    current_user.mfa_secret = encrypt_data(secret)
    current_user.backup_codes = [encrypt_data(hc) for hc in hashed_backup_codes]

    db.commit()

    return {"message": "MFA enabled successfully"}


@router.post("/mfa/disable")
async def disable_mfa(
    request: MFAVerifyRequest,
    current_user: User = Depends(require_auth),
    db: Session = Depends(get_db_dependency),
):
    """
    Disable MFA after verifying identity.
    """
    if not current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled",
        )

    # Decrypt secret and verify code or backup code
    secret = decrypt_data(current_user.mfa_secret)
    code_valid = verify_totp_code(secret, request.code)

    if not code_valid:
        # Try backup codes
        hashed_codes = [decrypt_data(hc) for hc in current_user.backup_codes or []]
        backup_index = verify_backup_code(request.code, hashed_codes)
        if backup_index is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid verification code",
            )

    # Disable MFA
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    current_user.backup_codes = None

    db.commit()

    return {"message": "MFA disabled successfully"}


@router.post("/mfa/verify")
async def verify_mfa(
    request: MFAVerifyRequest,
    current_user: User = Depends(require_auth),
    db: Session = Depends(get_db_dependency),
):
    """
    Verify an MFA code during login (called after password verification).
    """
    if not current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled for this account",
        )

    # Decrypt secret and verify
    secret = decrypt_data(current_user.mfa_secret)
    code_valid = verify_totp_code(secret, request.code)

    if not code_valid:
        # Try backup codes
        hashed_codes = [decrypt_data(hc) for hc in current_user.backup_codes or []]
        backup_index = verify_backup_code(request.code, hashed_codes)

        if backup_index is not None:
            # Valid backup code - remove it from the list
            current_user.backup_codes.pop(backup_index)
            db.commit()
            code_valid = True

    if not code_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA code",
        )

    # Update last verification time
    current_user.last_mfa_verification = datetime.utcnow()
    db.commit()

    return {"message": "MFA verification successful"}


@router.post("/mfa/regenerate-backup-codes", response_model=dict)
async def regenerate_backup_codes(
    request: MFAVerifyRequest,
    current_user: User = Depends(require_auth),
    db: Session = Depends(get_db_dependency),
):
    """
    Regenerate backup codes after verifying identity.
    """
    if not current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled",
        )

    # Verify current MFA code
    secret = decrypt_data(current_user.mfa_secret)
    if not verify_totp_code(secret, request.code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid verification code",
        )

    # Generate new backup codes
    backup_codes = generate_backup_codes(10)
    hashed_backup_codes = [hash_backup_code(code) for code in backup_codes]

    # Update user
    current_user.backup_codes = [encrypt_data(hc) for hc in hashed_backup_codes]
    db.commit()

    return {"backup_codes": backup_codes}


# Admin Endpoints
class AdminPasswordResetRequest(BaseModel):
    user_id: str
    new_password: str

    @validator('new_password')
    def password_strong(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v


@router.post("/admin/reset-user-password")
async def admin_reset_user_password(
    request: AdminPasswordResetRequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db_dependency),
):
    """
    Admin endpoint to reset another user's password.
    """
    # Get target user
    target_user = db.query(User).filter(User.id == request.user_id).first()

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Prevent admins from resetting other admin passwords (unless super admin logic)
    if target_user.role == UserRole.ADMIN and current_user.id != target_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot reset another admin's password",
        )

    # Reset password
    target_user.hashed_password = hash_password(request.new_password)

    # Invalidate all sessions for this user
    db.query(UserSession).filter(UserSession.user_id == target_user.id).update(
        {"is_active": False}
    )

    db.commit()

    return {"message": f"Password reset successfully for user {target_user.username}"}


class AdminToggleMFARequest(BaseModel):
    user_id: str


@router.post("/admin/disable-user-mfa")
async def admin_disable_user_mfa(
    request: AdminToggleMFARequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db_dependency),
):
    """
    Admin endpoint to disable MFA for a user (emergency access).
    """
    # Get target user
    target_user = db.query(User).filter(User.id == request.user_id).first()

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if not target_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled for this user",
        )

    # Disable MFA
    target_user.mfa_enabled = False
    target_user.mfa_secret = None
    target_user.backup_codes = None

    db.commit()

    return {"message": f"MFA disabled for user {target_user.username}"}


class AdminToggleUserRequest(BaseModel):
    user_id: str


@router.post("/admin/toggle-user-status")
async def admin_toggle_user_status(
    request: AdminToggleUserRequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db_dependency),
):
    """
    Admin endpoint to enable/disable a user account.
    """
    # Get target user
    target_user = db.query(User).filter(User.id == request.user_id).first()

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Prevent admins from disabling themselves
    if target_user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot disable your own account",
        )

    # Toggle status
    target_user.is_active = not target_user.is_active

    # If disabling, invalidate all sessions
    if not target_user.is_active:
        db.query(UserSession).filter(UserSession.user_id == target_user.id).update(
            {"is_active": False}
        )

    db.commit()

    status_text = "enabled" if target_user.is_active else "disabled"
    return {"message": f"User {target_user.username} has been {status_text}"}


@router.get("/admin/users", response_model=list)
async def admin_list_users(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db_dependency),
):
    """
    Admin endpoint to list all users.
    """
    users = db.query(User).all()

    return [
        {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "full_name": user.full_name,
            "role": user.role,
            "is_active": user.is_active,
            "mfa_enabled": user.mfa_enabled,
            "created_at": user.created_at,
            "last_login": user.last_login,
        }
        for user in users
    ]
