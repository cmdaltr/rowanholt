"""
Database Models

SQLAlchemy models for PostgreSQL database.
"""

from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import (
    Column, String, Integer, Float, DateTime, Boolean,
    JSON, Text, ForeignKey, Enum as SQLEnum, Index
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import enum


def utcnow() -> datetime:
    """Naive UTC, as the columns store it (datetime.utcnow is deprecated)"""
    return datetime.now(timezone.utc).replace(tzinfo=None)


Base = declarative_base()


class UserRole(str, enum.Enum):
    """User role enumeration."""
    ADMIN = "admin"
    USER = "user"
    GUEST = "guest"


class JobStatus(str, enum.Enum):
    """Job status enumeration."""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ARCHIVED = "archived"


class User(Base):
    """User model."""
    __tablename__ = "users"

    id = Column(String(36), primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    role = Column(SQLEnum(UserRole), default=UserRole.USER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    last_login = Column(DateTime)
    password_reset_token = Column(String(255))
    password_reset_expires = Column(DateTime)

    # MFA fields
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(String(255))  # Encrypted TOTP secret
    backup_codes = Column(JSON)  # Encrypted list of backup codes
    last_mfa_verification = Column(DateTime)

    # Relationships
    jobs = relationship("Job", back_populates="owner")
    settings = relationship("UserSettings", back_populates="user", uselist=False)
    accounts = relationship("Account", back_populates="user")

    # Indexes
    __table_args__ = (
        Index('idx_user_email', 'email'),
        Index('idx_user_username', 'username'),
        Index('idx_user_role', 'role'),
    )


class UserSettings(Base):
    """User settings model."""
    __tablename__ = "user_settings"

    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id"), unique=True, nullable=False)
    theme = Column(String(50), default="dark")
    notifications_enabled = Column(Boolean, default=True)
    auto_refresh_interval = Column(Integer, default=5000)  # milliseconds
    default_analysis_options = Column(JSON)
    custom_settings = Column(JSON)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    # Relationships
    user = relationship("User", back_populates="settings")


class Account(Base):
    """External account/integration model (e.g., Splunk, Elastic)."""
    __tablename__ = "accounts"

    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    account_type = Column(String(50), nullable=False)  # splunk, elastic, etc.
    name = Column(String(255), nullable=False)
    credentials = Column(JSON, nullable=False)  # Encrypted credentials
    endpoint_url = Column(String(512))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    # Relationships
    user = relationship("User", back_populates="accounts")

    # Indexes
    __table_args__ = (
        Index('idx_account_user', 'user_id'),
        Index('idx_account_type', 'account_type'),
    )


class Job(Base):
    """Analysis job model."""
    __tablename__ = "jobs"

    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    case_number = Column(String(255), nullable=False, index=True)
    source_paths = Column(JSON, nullable=False)
    destination_path = Column(String(1024))
    options = Column(JSON, nullable=False)
    status = Column(SQLEnum(JobStatus), default=JobStatus.PENDING, nullable=False, index=True)
    progress = Column(Integer, default=0)
    log = Column(JSON, default=list)
    result = Column(JSON)
    error = Column(Text)
    celery_task_id = Column(String(255), index=True)  # For job control
    created_at = Column(DateTime, default=utcnow, nullable=False)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    archived_at = Column(DateTime)

    # Relationships
    owner = relationship("User", back_populates="jobs")

    # Indexes
    __table_args__ = (
        Index('idx_job_user', 'user_id'),
        Index('idx_job_status', 'status'),
        Index('idx_job_case', 'case_number'),
        Index('idx_job_created', 'created_at'),
    )


class Session(Base):
    """User session model."""
    __tablename__ = "sessions"

    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    token = Column(String(512), unique=True, nullable=False, index=True)
    ip_address = Column(String(45))
    user_agent = Column(String(512))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    expires_at = Column(DateTime, nullable=False)
    last_activity = Column(DateTime, default=utcnow)

    # Indexes
    __table_args__ = (
        Index('idx_session_token', 'token'),
        Index('idx_session_user', 'user_id'),
        Index('idx_session_expires', 'expires_at'),
    )


class AuditLog(Base):
    """Audit log for tracking user actions."""
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id"))
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50))
    resource_id = Column(String(36))
    details = Column(JSON)
    ip_address = Column(String(45))
    timestamp = Column(DateTime, default=utcnow, nullable=False, index=True)

    # Indexes
    __table_args__ = (
        Index('idx_audit_user', 'user_id'),
        Index('idx_audit_timestamp', 'timestamp'),
        Index('idx_audit_action', 'action'),
    )
