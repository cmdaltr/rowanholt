"""
Web Backend Configuration

Configuration settings for the elrond web interface backend.
"""

import platform
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings."""

    # Application
    app_name: str = "elrond Web Interface"
    app_version: str = "2.1.0"
    debug: bool = False

    # Server
    host: str = "0.0.0.0"
    port: int = 8000

    # CORS
    cors_origins: list = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5687",
        "http://127.0.0.1:5687",
        "http://localhost:5688",
        "http://127.0.0.1:5688",
    ]

    # Redis
    redis_host: str = "redis"
    redis_port: int = 6379
    redis_db: int = 0

    @property
    def redis_url(self) -> str:
        """Get Redis connection URL."""
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"

    # Celery
    celery_broker_url: str = "redis://redis:6379/0"
    celery_result_backend: str = "redis://redis:6379/0"

    # Database
    database_url: str = "postgresql://rivendell:rivendell@postgres:5432/rivendell"

    # Storage
    upload_dir: Path = Path("/tmp/elrond/uploads")
    output_dir: Path = Path("/tmp/elrond/output")
    max_upload_size: int = 100 * 1024 * 1024 * 1024  # 100GB

    # JWT Authentication
    # CRITICAL: Change this in production! Use a cryptographically secure random string
    # Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
    secret_key: str = "your-secret-key-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 24  # 24 hours
    refresh_token_expire_days: int = 30

    # Security settings
    # Enable these in production
    enable_https_only: bool = False  # Set to True in production
    enable_rate_limiting: bool = False  # TODO: Implement rate limiting
    max_login_attempts: int = 5  # Account lockout threshold
    lockout_duration_minutes: int = 15  # How long accounts are locked after max attempts

    # Session
    session_timeout: int = 3600  # 1 hour

    # Default Admin
    default_admin_email: str = "admin@rivendell.app"
    default_admin_password: str = "IWasThere3000YearsAgo!"

    # Guest Mode
    guest_session_timeout: int = 3600  # 1 hour

    # Analysis
    max_concurrent_analyses: int = 3
    analysis_timeout: int = 86400  # 24 hours

    # Server mode (RIVENDELL_SERVER_MODE, set by deploy/server): one Rivendell shared by a
    # team. Every API route outside sign-in needs a user, each job is visible to its owner,
    # the people it's shared with and admins, sign-up and guest access are off, and the
    # first admin's password comes from RIVENDELL_ADMIN_PASSWORD. Off (the default), the
    # API stays open to whoever reaches it, as on an analyst's own machine.
    rivendell_server_mode: bool = False
    rivendell_admin_password: str = ""
    # The URL people open, e.g. https://rivendell.example.org (CORS, cookies, OIDC redirects)
    rivendell_public_url: str = ""
    # More places evidence may be read from and written to, separated by commas, as the
    # containers see them (a server's evidence share mounted at /srv/evidence, say)
    rivendell_evidence_paths: str = ""

    # Password sign-in alongside single sign-on; turn off to make the IdP the only way in
    rivendell_local_login: bool = True

    # Single sign-on (OpenID Connect): on when issuer, client ID and secret are all set
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_display_name: str = "single sign-on"
    oidc_scopes: str = "openid profile email"
    oidc_groups_claim: str = "groups"
    oidc_admin_group: str = ""  # members become Rivendell admins
    oidc_allowed_group: str = ""  # when set, only its members may sign in

    @property
    def oidc_enabled(self) -> bool:
        """Whether single sign-on is configured."""
        return bool(self.oidc_issuer and self.oidc_client_id and self.oidc_client_secret)

    @property
    def allowed_paths(self) -> list:
        """Directories evidence may come from and output go to: this OS's defaults, plus
        RIVENDELL_EVIDENCE_PATHS."""
        extra = [path.strip() for path in self.rivendell_evidence_paths.split(",") if path.strip()]
        return self._default_paths() + [path for path in extra if path.startswith("/") or ":" in path]

    def _default_paths(self) -> list:
        """This OS's default places for evidence."""
        system = platform.system()

        if system == "Windows":
            # Windows paths only
            return [
                "C:\\Temp\\rivendell",
                "D:\\Temp\\rivendell",
                "E:\\Temp\\rivendell",
                "F:\\Temp\\rivendell",
            ]
        elif system == "Darwin":
            # macOS paths
            return [
                "/Volumes",
                "/tmp/rivendell",
            ]
        else:
            # Linux/Unix paths (includes Docker containers)
            return [
                "/Volumes",  # Docker on macOS - external drives
                "/mnt",
                "/media",
                "/tmp/rivendell",
                "/host/tmp/rivendell",  # Docker on macOS - host /tmp access
            ]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()

DEFAULT_SECRET_KEY = "your-secret-key-change-in-production"


def _persistent_secret_key() -> str:
    """A random JWT secret kept beside the user store, created on first start.

    The built-in default is public, so anyone could sign an admin token with it.
    Setting SECRET_KEY in the environment still takes precedence.
    """
    import os
    import secrets

    path = Path(os.environ.get("SECRET_KEY_FILE", "/app/data/.jwt_secret"))
    try:
        if path.exists():
            key = path.read_text().strip()
            if key:
                return key
        path.parent.mkdir(parents=True, exist_ok=True)
        key = secrets.token_urlsafe(48)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key)
        return key
    except FileExistsError:
        return path.read_text().strip()  # another worker created it first
    except OSError:
        # Unwritable data directory: a per-process key still beats the public default.
        return secrets.token_urlsafe(48)


if settings.secret_key in ("", DEFAULT_SECRET_KEY):
    settings.secret_key = _persistent_secret_key()

# A server answers only its own origin; a local stack keeps the localhost list
if settings.rivendell_server_mode and settings.rivendell_public_url:
    settings.cors_origins = [settings.rivendell_public_url.rstrip("/")]

# Create necessary directories
settings.upload_dir.mkdir(parents=True, exist_ok=True)
settings.output_dir.mkdir(parents=True, exist_ok=True)
