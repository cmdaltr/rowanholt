# Rowanholt Configuration Guide

**Version:** 2.1.0
**Last Updated:** 2025-01-15

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Backend Configuration](#backend-configuration)
3. [Frontend Configuration](#frontend-configuration)
4. [Database Configuration](#database-configuration)
5. [Security Configuration](#security-configuration)
6. [Tool Requirements](#tool-requirements)
7. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Default Configuration

Rowanholt works out-of-the-box with sensible defaults:

- **Backend**: http://localhost:5688
- **Frontend**: http://localhost:5687
- **Database**: PostgreSQL (localhost:5432)
- **Redis**: localhost:6379
- **Default Admin**: admin@rowanholt.app / IWasThere3000YearsAgo!

### Environment Variables

Create `.env` file in `/src/web/backend/`:

```bash
# Application
APP_NAME="Rowanholt Web Interface"
DEBUG=false

# Database
DATABASE_URL=postgresql://rowanholt:rowanholt@postgres:5432/rowanholt

# Redis
REDIS_HOST=redis
REDIS_PORT=6379

# Security
SECRET_KEY=your-secret-key-change-in-production
ENABLE_HTTPS_ONLY=false  # Set true in production

# File Paths
UPLOAD_DIR=/tmp/elrond/uploads
OUTPUT_DIR=/tmp/elrond/output
```

---

## Backend Configuration

### Configuration File

Location: `/src/web/backend/config.py`

```python
class Settings(BaseSettings):
    # Application
    app_name: str = "elrond Web Interface"
    app_version: str = "2.1.0"
    debug: bool = False

    # Server
    host: str = "0.0.0.0"
    port: int = 8000

    # JWT Authentication
    secret_key: str = "your-secret-key-change-in-production"
    access_token_expire_minutes: int = 1440  # 24 hours

    # Security
    enable_https_only: bool = False
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 15

    # Storage
    upload_dir: Path = Path("/tmp/elrond/uploads")
    output_dir: Path = Path("/tmp/elrond/output")
    max_upload_size: int = 100 * 1024 * 1024 * 1024  # 100GB

    # Analysis
    max_concurrent_analyses: int = 3
    analysis_timeout: int = 86400  # 24 hours
```

### Allowed Paths

Configure which directories can be browsed for evidence files:

**Linux/Docker:**
```python
allowed_paths = [
    "/Volumes",
    "/mnt",
    "/media",
    "/tmp/rowanholt",
    "/host/tmp",  # Host /tmp mounted in Docker
]
```

**macOS:**
```python
allowed_paths = [
    "/Volumes",
    "/tmp/rowanholt",
]
```

**Windows:**
```python
allowed_paths = [
    "C:\\Temp\\rowanholt",
    "D:\\Temp\\rowanholt",
]
```

---

## Frontend Configuration

### Environment Variables

Create `.env` file in `/src/web/frontend/`:

```bash
REACT_APP_API_URL=http://localhost:5688/api
REACT_APP_VERSION=2.1.0
```

### package.json Configuration

```json
{
  "name": "elrond-web",
  "version": "2.1.0",
  "proxy": "http://localhost:5688",
  "homepage": "/"
}
```

### Build Configuration

```bash
# Development
npm start

# Production build
npm run build

# Build output
ls -la build/
```

---

## Database Configuration

### PostgreSQL Setup

**Docker Compose (Recommended):**
```yaml
postgres:
  image: postgres:15-alpine
  environment:
    POSTGRES_USER: rowanholt
    POSTGRES_PASSWORD: rowanholt
    POSTGRES_DB: rowanholt
  ports:
    - "5432:5432"
  volumes:
    - rowanholt-postgres:/var/lib/postgresql/data
```

**Connection String:**
```
postgresql://rowanholt:rowanholt@localhost:5432/rowanholt
```

### Database Migrations

```bash
# Run migrations
cd /src/web/backend
python -m alembic upgrade head

# Create new migration
python -m alembic revision --autogenerate -m "description"

# Rollback
python -m alembic downgrade -1
```

### Redis Configuration

**Docker Compose:**
```yaml
redis:
  image: redis:7-alpine
  ports:
    - "6379:6379"
  volumes:
    - rowanholt-redis:/data
```

---

## Security Configuration

### Production Checklist

#### Critical (Must Do)

- [ ] **Change SECRET_KEY**: Generate with `python -c "import secrets; print(secrets.token_urlsafe(32))"`
- [ ] **Enable HTTPS**: Set `ENABLE_HTTPS_ONLY=true`
- [ ] **Change default admin password**: First thing after deployment
- [ ] **Secure database password**: Use strong, random passwords
- [ ] **Restrict CORS origins**: Update `cors_origins` list

#### Important (Should Do)

- [ ] **Enable MFA**: Require MFA for admin accounts
- [ ] **Configure allowed_paths**: Limit file system access
- [ ] **Set up backups**: Regular database backups
- [ ] **Configure logging**: Centralized log collection
- [ ] **Update dependencies**: Keep packages up-to-date

#### Recommended (Nice to Have)

- [ ] **Rate limiting**: Prevent brute force attacks
- [ ] **Session timeout**: Configure appropriate timeouts
- [ ] **Audit logging**: Track user actions
- [ ] **SSL certificates**: Use valid certificates (not self-signed)

### Generating Secure Keys

```bash
# SECRET_KEY for JWT
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Database password
openssl rand -base64 32

# API keys
python -c "import uuid; print(str(uuid.uuid4()))"
```

### Security Headers

Add to nginx/reverse proxy:

```nginx
add_header X-Frame-Options "SAMEORIGIN";
add_header X-Content-Type-Options "nosniff";
add_header X-XSS-Protection "1; mode=block";
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
```

---

## Tool Requirements

### Required Tools (Core Functionality)

| Tool | Purpose | Installation |
|------|---------|--------------|
| **Python 3.8+** | Backend runtime | `apt install python3` |
| **Node.js 16+** | Frontend build | `apt install nodejs npm` |
| **PostgreSQL 12+** | Database | `apt install postgresql` |
| **Redis 6+** | Task queue | `apt install redis-server` |

### Forensic Tools (Analysis Features)

| Tool | Purpose | Installation |
|------|---------|--------------|
| **Volatility 3** | Memory analysis | `pip install volatility3` |
| **The Sleuth Kit** | File system analysis | `apt install sleuthkit` |
| **libewf** | E01 image support | `apt install ewf-tools` |
| **YARA** | Pattern matching | `apt install yara` |
| **ClamAV** | Malware scanning | `apt install clamav` |

### Optional Tools (Enhanced Features)

| Tool | Purpose | Installation |
|------|---------|--------------|
| **Artemis** | Windows artifact parsing (MFT, EVTX, Prefetch, etc.) | [GitHub Releases](https://github.com/puffyCid/artemis/releases) |
| **Plaso** | Timeline generation | `apt install plaso-tools` |
| **QEMU** | VM disk mounting | `apt install qemu-utils` |
| **RegRipper** | Registry analysis | Download from GitHub |

### Installation Commands

**Ubuntu/Debian:**
```bash
# Core tools
sudo apt update
sudo apt install -y python3 python3-pip nodejs npm postgresql redis-server

# Forensic tools
sudo apt install -y sleuthkit ewf-tools yara clamav plaso-tools qemu-utils

# Python packages
pip3 install volatility3

# Install Artemis (comprehensive Rust-based forensic parser)
# Download from https://github.com/puffyCid/artemis/releases
```

**macOS:**
```bash
# Install Homebrew first: https://brew.sh

# Core tools
brew install python node postgresql redis

# Forensic tools
brew install sleuthkit libewf yara clamav

# Python packages
pip3 install volatility3

# Install Artemis (comprehensive Rust-based forensic parser)
# Download from https://github.com/puffyCid/artemis/releases
```

**Windows (WSL2 Recommended):**
```bash
# Install WSL2 first
wsl --install -d Ubuntu-22.04

# Then run Ubuntu commands above
```

### Verifying Installation

```bash
# Check versions
python3 --version
node --version
psql --version
redis-cli --version

# Check tools
vol --version
tsk_recover -V
ewfinfo -V
yara --version
```

---

## Troubleshooting

### Common Issues

#### Backend Won't Start

**Symptom**: `Application startup failed`

**Solutions:**
```bash
# Check database connection
psql -h localhost -U rowanholt -d rowanholt

# Check Redis connection
redis-cli ping

# Check logs
docker logs rowanholt-backend

# Verify dependencies
pip install -r requirements/web.txt
```

#### Frontend Build Fails

**Symptom**: `npm run build` errors

**Solutions:**
```bash
# Clear cache
rm -rf node_modules package-lock.json
npm install

# Check Node version
node --version  # Should be 16+

# Rebuild
npm run build
```

#### Database Migration Fails

**Symptom**: `column does not exist`

**Solutions:**
```bash
# Check current version
cd /src/web/backend
python -m alembic current

# Run migrations
python -m alembic upgrade head

# If stuck, check migration history
python -m alembic history
```

#### File Browser Not Loading

**Symptom**: `Failed to load directory`

**Solutions:**
```bash
# Check allowed_paths in config.py
# Verify directory exists
ls -la /tmp/rowanholt

# Check permissions
chmod 755 /tmp/rowanholt

# Check Docker volume mounts
docker inspect rowanholt-backend | grep Mounts
```

#### Celery Tasks Not Running

**Symptom**: Jobs stuck in "pending"

**Solutions:**
```bash
# Check Celery worker
docker logs rowanholt-celery-worker

# Check Redis
redis-cli ping

# Restart Celery
docker restart rowanholt-celery-worker
```

### Debug Mode

Enable verbose logging:

```bash
# In .env
DEBUG=true
LOG_LEVEL=DEBUG

# Or environment variable
export ROWANHOLT_DEBUG=1
```

### Getting Help

1. Check logs: `docker logs rowanholt-backend`
2. Review [API.md](API.md) for endpoint docs
3. See [SECURITY.md](SECURITY.md) for security setup
4. Check GitHub issues: https://github.com/cmdaltr/rowanholt/issues

---

## Performance Tuning

### Database Optimization

```sql
-- Increase shared_buffers (PostgreSQL)
-- In postgresql.conf:
shared_buffers = 256MB
effective_cache_size = 1GB
work_mem = 16MB
```

### Redis Optimization

```bash
# In redis.conf:
maxmemory 512mb
maxmemory-policy allkeys-lru
```

### Celery Workers

```yaml
# In docker-compose.yml:
celery:
  command: celery -A tasks worker --concurrency=4 --loglevel=info
```

### User Profile Collection

Control how user profiles are collected during forensic analysis:

| Environment Variable | Values | Default | Description |
|---------------------|--------|---------|-------------|
| `ROWANHOLT_EXCLUDE_PROFILE_CACHE` | `true`/`false` | `true` | Skip cache directories when copying full user profiles |
| `ROWANHOLT_DEBUG_PROFILE_COPY` | `true`/`false` | `false` | Show progress updates during profile copies (every 60s) |

When enabled, the following directories are excluded from user profile collection:
- `AppData/Local/Temp` - Temporary files
- `AppData/Local/Packages` - UWP/Windows Store app data
- `AppData/Local/Microsoft/Windows/INetCache` - Browser cache
- `AppData/Local/Google/Chrome/User Data/*/Cache` - Chrome cache
- `AppData/Local/Mozilla/Firefox/Profiles` - Firefox cache
- `AppData/Local/Microsoft/Edge/User Data/*/Cache` - Edge cache
- `AppData/Local/CrashDumps` - Windows crash dumps
- `AppData/Local/Spotify/Storage` - Spotify cache
- `AppData/Local/Discord/Cache` - Discord cache
- `AppData/Local/Microsoft/Teams/Cache` - Teams cache

**To disable exclusions** (copy everything including caches):
```yaml
# In docker-compose.yml under celery-worker environment:
- ROWANHOLT_EXCLUDE_PROFILE_CACHE=false
```

Then restart: `docker compose up -d --force-recreate celery-worker`

### File System

```bash
# Use SSD/NVMe for:
- Database volume
- Evidence storage
- Output directory

# Use HDD for:
- Archive storage
- Backup storage
```

---

## Backup and Recovery

### Database Backup

```bash
# Backup
docker exec rowanholt-postgres pg_dump -U rowanholt rowanholt > backup_$(date +%Y%m%d).sql

# Restore
docker exec -i rowanholt-postgres psql -U rowanholt rowanholt < backup_20250115.sql
```

### Configuration Backup

```bash
# Backup all configs
tar czf rowanholt-config_$(date +%Y%m%d).tar.gz \
  /src/web/backend/.env \
  /src/web/backend/config.py \
  /src/web/frontend/.env
```

### Automated Backups

```bash
# Add to crontab
0 2 * * * /opt/rowanholt/scripts/backup.sh
```

---

**Version:** 2.1.0
**For additional help, see:**
- [API.md](API.md) - REST API reference
- [CLI.md](CLI.md) - Command-line tools
- [SECURITY.md](SECURITY.md) - Security guide
