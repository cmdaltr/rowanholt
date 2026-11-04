# Elrond Docker Quick Start

> **Legacy.** This describes the standalone Elrond stack in `src/analysis/web` and `src/analysis/docker` (ports 3000 and 8000), which Rowanholt no longer uses. Rowanholt runs from the repository's `docker-compose.yml` (web UI on :5687, API on :5688): start with [docs/QUICKSTART.md](../../../docs/QUICKSTART.md) and the `rowanholt` command.

Get Elrond up and running in Docker in 5 minutes!

## Prerequisites

- Docker installed ([Get Docker](https://docs.docker.com/get-docker/))
- Docker Compose installed
- 8GB RAM available
- 20GB free disk space

## Quick Start - Development

### 1. Clone and Setup

```bash
# Clone repository
git clone https://github.com/cmdaltr/elrond.git
cd elrond

# Copy environment file
cp .env.example .env
```

### 2. Start Elrond

**Option A: Using the startup script (recommended)**

```bash
# Make script executable
chmod +x docker-start.sh

# Start all services
./docker-start.sh

# Or start in background
./docker-start.sh --detached
```

**Option B: Using Docker Compose directly**

```bash
# Start all services
docker-compose up

# Or in background
docker-compose up -d
```

### 3. Access Elrond

Open your browser:

- **Web Interface**: http://localhost:3000
- **API Documentation**: http://localhost:8000/docs
- **API Health Check**: http://localhost:8000/api/health

### 4. Run Your First Analysis

**Via Web Interface:**

1. Go to http://localhost:3000
2. Click "New Analysis"
3. Browse for a disk image
4. Select analysis options
5. Click "Start Analysis"
6. Monitor progress in "Job List"

**Via CLI:**

```bash
# Copy evidence into container
docker cp /path/to/disk.E01 elrond-engine:/evidence/

# Enter container
docker-compose exec elrond-engine bash

# Run analysis
python3 elrond.py CASE-001 /evidence/disk.E01 /output --Collect --Process --quick

# View results
ls -la /output/CASE-001/
```

## Quick Start - Production

### 1. Setup Environment

```bash
# Copy and edit production config
cp .env.example .env
nano .env

# Update these critical settings:
# - SECRET_KEY (generate secure key)
# - REDIS_PASSWORD (strong password)
# - DEBUG=false
```

### 2. Deploy

```bash
# Build and start production stack
./docker-start.sh --prod --build --detached

# Or manually
docker-compose -f docker-compose.prod.yml up --build -d
```

### 3. Verify Deployment

```bash
# Check all services are running
docker-compose -f docker-compose.prod.yml ps

# Check logs
docker-compose -f docker-compose.prod.yml logs -f
```

### 4. Configure Domain (Optional)

Edit `nginx.conf` to add your domain and SSL certificates.

## Essential Commands

### Start/Stop

```bash
# Start services
./docker-start.sh

# Start in background
./docker-start.sh --detached

# Stop services
./docker-start.sh --stop

# Restart services
./docker-start.sh --restart
```

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend

# Show logs from startup script
./docker-start.sh --logs
```

### Manage Services

```bash
# Rebuild images
./docker-start.sh --build

# Scale workers
docker-compose up --scale celery-worker=3 -d

# Check status
docker-compose ps
```

### Access Containers

```bash
# Backend shell
docker-compose exec backend bash

# Frontend shell
docker-compose exec frontend sh

# Forensics engine shell
docker-compose exec elrond-engine bash

# Redis CLI
docker-compose exec redis redis-cli
```

## Common Tasks

### Add Evidence

```bash
# Copy to evidence volume
docker cp /local/disk.E01 elrond-engine:/evidence/

# Or mount host directory (edit docker-compose.yml):
volumes:
  - /host/evidence:/evidence:ro
```

### Retrieve Results

```bash
# Copy from container
docker cp elrond-engine:/output/CASE-001 ./results/

# Or check mounted volume
docker volume inspect elrond-output
```

### Update Elrond

```bash
# Pull latest code
git pull

# Rebuild and restart
./docker-start.sh --stop
./docker-start.sh --build --detached
```

### Backup Data

```bash
# Backup output volume
docker run --rm \
  -v elrond-output:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/elrond-backup-$(date +%Y%m%d).tar.gz /data
```

## Troubleshooting

### Services Won't Start

```bash
# Check Docker is running
docker info

# View detailed logs
docker-compose logs

# Restart Docker daemon
sudo systemctl restart docker  # Linux
# Or restart Docker Desktop  # Mac/Windows
```

### Port Already in Use

```bash
# Find process using port 3000
lsof -i :3000  # Mac/Linux
netstat -ano | findstr :3000  # Windows

# Kill process or change port in docker-compose.yml
```

### Permission Denied

```bash
# On Linux, add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Or run with sudo
sudo ./docker-start.sh
```

### Out of Disk Space

```bash
# Check Docker disk usage
docker system df

# Clean up unused resources
docker system prune -a

# Or use script
./docker-start.sh --clean
```

### Container Keeps Restarting

```bash
# Check logs for errors
docker-compose logs backend

# Check container health
docker inspect elrond-backend | grep Health -A 10

# Restart specific service
docker-compose restart backend
```

### Can't Access Web Interface

```bash
# Check frontend is running
docker-compose ps frontend

# Test from command line
curl http://localhost:3000

# Check firewall
sudo ufw status  # Linux
```

## Environment Variables

Key settings in `.env`:

```bash
# Security
SECRET_KEY=your-secret-key-here
REDIS_PASSWORD=your-redis-password

# Debug mode (disable in production!)
DEBUG=false

# Analysis settings
MAX_CONCURRENT_ANALYSES=3
ANALYSIS_TIMEOUT=86400

# Storage paths
ALLOWED_PATHS=/evidence,/mnt,/media

# API settings
CORS_ORIGINS=http://localhost:3000

# Non-Interactive Mode (DEFAULT: Enabled)
# Elrond runs in non-interactive mode by default for web/automation
# This provides clean output without prompts, colors, or ASCII art
ELROND_NONINTERACTIVE=1  # 1=enabled (default), 0=interactive CLI mode
```

### Non-Interactive Mode

**Elrond automatically runs in non-interactive mode by default** for web and automation environments. This ensures:

- ✅ **No user prompts** - All decisions use safe defaults
- ✅ **Clean log output** - No ANSI color codes, banners, or separators
- ✅ **No visual noise** - No ASCII art or formatting characters
- ✅ **Web-ready** - Perfect for job logs and monitoring

**This is automatically configured in Docker** - no setup needed!

To enable interactive mode (CLI use only):
```bash
export ELROND_NONINTERACTIVE=0
```

**Note**: Interactive mode is only recommended for manual CLI usage, not for web applications.

## Architecture Overview

```
┌─────────────┐     ┌─────────────┐     ┌──────────────┐
│  Frontend   │────▶│   Backend   │────▶│    Redis     │
│   :3000     │     │    :8000    │     │    :6379     │
└─────────────┘     └─────────────┘     └──────────────┘
                           │
                           ▼
                    ┌──────────────┐
                    │    Celery    │
                    │   Workers    │
                    └──────────────┘
                           │
                           ▼
                    ┌──────────────┐
                    │   Elrond     │
                    │   Engine     │
                    └──────────────┘
```

## Next Steps

1. **Configure Analysis Options**
   - Review available forensic tools
   - Customize analysis workflows
   - Set up YARA rules and IOCs

2. **Set Up Monitoring**
   - Configure log aggregation
   - Set up performance monitoring
   - Enable alerting

3. **Production Hardening**
   - Enable SSL/TLS
   - Configure firewall rules
   - Set up automatic backups
   - Review security settings

4. **Scale Resources**
   - Add more Celery workers
   - Increase memory limits
   - Configure distributed storage

## Getting Help

- **Documentation**: See [DOCKER.md](DOCKER.md) for detailed guide
- **Logs**: `docker-compose logs -f`
- **Health Check**: http://localhost:8000/api/health
- **API Docs**: http://localhost:8000/docs

## Resources

- [Full Docker Documentation](DOCKER.md)
- [Testing Guide](TESTING.md)
- [Main README](README.md)
- [Configuration Guide](CONFIG.md)

---

**Quick Commands Reference**

```bash
# Start
./docker-start.sh

# Stop
./docker-start.sh --stop

# Logs
./docker-start.sh --logs

# Production
./docker-start.sh --prod --build -D

# Clean all
./docker-start.sh --clean
```

Happy forensicating! 🔍
