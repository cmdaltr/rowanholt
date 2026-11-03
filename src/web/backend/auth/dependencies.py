"""
Authentication Dependencies

FastAPI dependencies for authentication and authorization.
"""

from typing import Optional
from fastapi import Depends, HTTPException, status, Cookie
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from ..database import get_db_dependency
from ..models.database import User, Session as UserSession, UserRole
from .security import verify_token
from datetime import datetime

security = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    session_token: Optional[str] = Cookie(None, alias="session_token"),
    db: Session = Depends(get_db_dependency),
) -> Optional[User]:
    """
    Get current authenticated user from JWT token or session cookie.

    Returns None for guest access.
    """
    token = None

    # Try Bearer token first
    if credentials:
        token = credentials.credentials
    # Then try session cookie
    elif session_token:
        token = session_token

    if not token:
        return None

    # Verify token
    payload = verify_token(token)
    if not payload:
        return None

    user_id = payload.get("sub")
    if not user_id:
        return None

    # Get user from database
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()

    # Update session last activity
    if user and session_token:
        session = db.query(UserSession).filter(
            UserSession.token == session_token,
            UserSession.is_active == True
        ).first()
        if session:
            session.last_activity = datetime.utcnow()
            db.commit()

    return user


async def require_auth(
    current_user: Optional[User] = Depends(get_current_user)
) -> User:
    """
    Require authentication. Raises 401 if not authenticated.
    """
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return current_user


async def require_admin(
    current_user: User = Depends(require_auth)
) -> User:
    """
    Require admin role. Raises 403 if not admin.
    """
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return current_user


async def get_user_or_guest(
    current_user: Optional[User] = Depends(get_current_user)
) -> User:
    """
    Get current user or create guest user.
    Guest users can browse but cannot save.
    """
    if current_user:
        return current_user

    # Return a guest user (not saved to database)
    return User(
        id="guest",
        email="guest@dernvale.app",
        username="guest",
        hashed_password="",
        role=UserRole.GUEST,
        is_active=True,
    )
