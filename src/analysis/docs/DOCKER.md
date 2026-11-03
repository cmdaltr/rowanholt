# Elrond Docker Deployment Guide

> **Legacy.** This describes the standalone Elrond stack in `src/analysis/web` and `src/analysis/docker` (ports 3000 and 8000), which Dernvale no longer uses. Dernvale runs from the repository's `docker-compose.yml` (web UI on :5687, API on :5688): start with [docs/QUICKSTART.md](../../../docs/QUICKSTART.md) and the `dernvale` command.

Complete guide for running Elrond in Docker containers for development and production environments.

## Overview

Elrond's Docker setup includes:
- **Forensics Engine**: Core analysis tools in isolated container
- **Web Backend**: FastAPI REST API
- **Web Frontend**: React single-page application
- **Celery Workers**: Background task processing
- **Redis**: Message broker and cache
- **Nginx**: Reverse proxy (production only)

## Prerequisites

### Required
- Docker 20.10 or later
- Docker Compose 2.0 or later (or docker-compose 1.29+)
- 8GB RAM minimum (16GB recommended)
- 50GB free disk space minimum

### Optional
- SSL certificates for HTTPS (production)
- Domain name (production)

## Quick Start

### Development Mode

```bash
# 1. Clone the repository
git clone https://github.com/cmdaltr/elrond.git
cd elrond

# 2. Copy environment file
cp .env.example .env

# 3. Start all services
./docker-start.sh

# Or manually:
docker-compose up
```

The application will be available at:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Documentation: http://localhost:8000/docs

### Production Mode

```bash
# 1. Configure environment
cp .env.example .env
# Edit .env with production settings

# 2. Build and start
./docker-start.sh --prod --build --detached

# Or manually:
docker-compose -f docker-compose.prod.yml up --build -d
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Nginx (Port 80/443)                  │
│                      Reverse Proxy & SSL                     │
└────────────────┬────────────────────────┬────────────────────┘
                 │                        │
    ┌────────────▼──────────┐   ┌────────▼─────────────┐
    │   Frontend (Port 3000) │   │  Backend (Port 8000) │
    │   React SPA            │   │  FastAPI API         │
    └────────────────────────┘   └──────┬───────────────┘
                                        │
                    ┌───────────────────┼───────────────────┐
                    │                   │                   │
         ┌──────────▼────────┐  ┌──────▼───────┐  ┌───────▼────────┐
         │ Celery Workers    │  │    Redis     │  │ Elrond Engine  │
         │ Background Tasks  │  │  Message     │  │  Forensics     │
         │                   │  │  Broker      │  │  Analysis      │
         └───────────────────┘  └──────────────┘  └────────────────┘
                    │                                      │
                    └──────────────────┬───────────────────┘
                                      │
                            ┌─────────▼──────────┐
                            │   Shared Volumes   │
                            │ evidence/, output/ │
                            └────────────────────┘
```

## Docker Services

### 1. Frontend Service

**Container**: `elrond-frontend`
**Port**: 3000
**Purpose**: React web interface

Development:
```bash
docker-compose up frontend
```

Production (optimized build):
```bash
docker-compose -f docker-compose.prod.yml up frontend
```

### 2. Backend API Service

**Container**: `elrond-backend`
**Port**: 8000
**Purpose**: REST API and job management

```bash
# View logs
docker-compose logs -f backend

# Execute commands in container
docker-compose exec backend bash
```

### 3. Celery Worker Service

**Container**: `elrond-celery-worker`
**Purpose**: Process forensic analysis jobs

```bash
# Scale workers
docker-compose up --scale celery-worker=3

# Monitor worker status
docker-compose exec celery-worker celery -A tasks.celery_app inspect active
```

### 4. Redis Service

**Container**: `elrond-redis`
**Port**: 6379
**Purpose**: Message broker and caching

```bash
# Access Redis CLI
docker-compose exec redis redis-cli

# Monitor Redis
docker-compose exec redis redis-cli MONITOR
```

### 5. Elrond Engine Service

**Container**: `elrond-engine`
**Purpose**: Core forensics engine

```bash
# Run forensic analysis
docker-compose exec elrond-engine python3 elrond.py CASE-001 /evidence

# Interactive shell
docker-compose exec elrond-engine bash
```

## Volumes

### Persistent Volumes

```yaml
elrond-evidence:    # Forensic disk images
elrond-output:      # Analysis results
elrond-cases:       # Case files
elrond-uploads:     # Web uploads
elrond-jobs:        # Job metadata
redis-data:         # Redis persistence
```

### Mounting Evidence

```bash
# Option 1: Copy to evidence volume
docker cp /path/to/image.E01 elrond-engine:/evidence/

# Option 2: Mount host directory (add to docker-compose.yml)
volumes:
  - /host/path/to/evidence:/evidence:ro

# Option 3: Use bind mount with docker run
docker run -v /host/evidence:/evidence elrond-engine
```

## Configuration

### Environment Variables

Create `.env` from `.env.example`:

```bash
# Required settings
SECRET_KEY=your_secret_key_here
REDIS_PASSWORD=secure_password

# Optional settings
DEBUG=false
MAX_CONCURRENT_ANALYSES=3
ALLOWED_PATHS=/evidence,/mnt,/media
```

### Backend Configuration

Edit `web/backend/config.py` or use environment variables:

```bash
HOST=0.0.0.0
PORT=8000
CORS_ORIGINS=http://localhost:3000
MAX_UPLOAD_SIZE=107374182400  # 100GB
```

### Nginx Configuration

Production deployment with SSL:

```bash
# Edit nginx.conf
vim nginx.conf

# Add SSL certificates
mkdir -p ssl
cp your-cert.pem ssl/cert.pem
cp your-key.pem ssl/key.pem

# Update docker-compose.prod.yml to mount SSL
volumes:
  - ./ssl:/etc/nginx/ssl:ro
```

## Common Operations

### Build Images

```bash
# Build all images
docker-compose build

# Build specific service
docker-compose build backend

# Build with no cache
docker-compose build --no-cache
```

### Start Services

```bash
# Start all services
docker-compose up

# Start specific service
docker-compose up frontend

# Start in background (detached)
docker-compose up -d

# Start with rebuild
docker-compose up --build
```

### Stop Services

```bash
# Stop all services
docker-compose down

# Stop and remove volumes
docker-compose down -v

# Stop but keep containers
docker-compose stop
```

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend

# Last 100 lines
docker-compose logs --tail=100 backend

# Since specific time
docker-compose logs --since 2h backend
```

### Scale Services

```bash
# Scale Celery workers
docker-compose up --scale celery-worker=5 -d

# Check running containers
docker-compose ps
```

### Execute Commands

```bash
# Backend shell
docker-compose exec backend bash

# Run Python script
docker-compose exec backend python3 -c "print('Hello')"

# Database migrations (if using PostgreSQL)
docker-compose exec backend alembic upgrade head

# Create admin user
docker-compose exec backend python3 create_admin.py
```

### Health Checks

```bash
# Check service health
docker-compose ps

# Test backend health endpoint
curl http://localhost:8000/api/health

# View health check logs
docker inspect elrond-backend | jq '.[0].State.Health'
```

## Running Forensic Analysis

### Via Web Interface

1. Access http://localhost:3000
2. Navigate to "New Analysis"
3. Select disk image from file browser
4. Configure analysis options
5. Start analysis and monitor progress

### Via CLI in Container

```bash
# Enter container
docker-compose exec elrond-engine bash

# Run analysis
python3 elrond.py CASE-001 /evidence/disk.E01 /output \
  --Collect --Process --quick

# Check results
ls -la /output/CASE-001/
```

### Via Docker Run

```bash
docker run --rm \
  -v /path/to/evidence:/evidence \
  -v /path/to/output:/output \
  --privileged \
  elrond-engine \
  python3 elrond.py CASE-001 /evidence/disk.E01 /output
```

## Production Deployment

### 1. Prepare Environment

```bash
# Create production .env
cp .env.example .env

# Update critical settings
SECRET_KEY=<generate-secure-key>
REDIS_PASSWORD=<secure-password>
DEBUG=false
```

### 2. SSL/TLS Setup

```bash
# Option 1: Use Let's Encrypt (recommended)
# Add certbot service to docker-compose.prod.yml

# Option 2: Use existing certificates
mkdir -p ssl
cp /path/to/cert.pem ssl/
cp /path/to/key.pem ssl/
```

### 3. Deploy

```bash
# Build and start
docker-compose -f docker-compose.prod.yml up --build -d

# Verify services
docker-compose -f docker-compose.prod.yml ps

# Check logs
docker-compose -f docker-compose.prod.yml logs
```

### 4. Configure Firewall

```bash
# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Block direct access to services
sudo ufw deny 8000/tcp
sudo ufw deny 6379/tcp
```

### 5. Setup Monitoring

```bash
# Add monitoring stack (Prometheus + Grafana)
# See docker-compose.monitoring.yml
```

## Monitoring and Maintenance

### View Resource Usage

```bash
# Container stats
docker stats

# Specific container
docker stats elrond-backend

# Disk usage
docker system df

# Detailed info
docker system df -v
```

### Cleanup

```bash
# Remove stopped containers
docker container prune

# Remove unused images
docker image prune -a

# Remove unused volumes
docker volume prune

# Full cleanup (CAUTION: removes everything)
./docker-start.sh --clean
```

### Backups

```bash
# Backup volumes
docker run --rm \
  -v elrond-output:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/elrond-output-$(date +%Y%m%d).tar.gz /data

# Backup Redis
docker-compose exec redis redis-cli BGSAVE
docker cp elrond-redis:/data/dump.rdb ./backup/
```

### Updates

```bash
# Pull latest code
git pull

# Rebuild images
docker-compose build --no-cache

# Restart services
docker-compose down && docker-compose up -d
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose logs backend

# Check container status
docker-compose ps

# Inspect container
docker inspect elrond-backend
```

### Permission Errors

```bash
# Fix volume permissions
docker-compose exec elrond-engine chown -R elrond:elrond /evidence /output

# Run with privileged mode (for mounting)
docker-compose up --privileged
```

### Network Issues

```bash
# Inspect network
docker network inspect elrond_elrond-network

# Recreate network
docker-compose down
docker network prune
docker-compose up
```

### Out of Disk Space

```bash
# Check usage
docker system df

# Clean up
docker system prune -a --volumes

# Resize volumes (if needed)
docker volume rm elrond-output
docker volume create --opt size=500G elrond-output
```

### Backend Not Accessible

```bash
# Check if service is running
docker-compose ps backend

# Test from inside network
docker-compose exec frontend curl http://backend:8000/api/health

# Check firewall
sudo ufw status
```

## Performance Tuning

### Memory Limits

Add to services in docker-compose.yml:

```yaml
services:
  backend:
    mem_limit: 4g
    mem_reservation: 2g
```

### CPU Limits

```yaml
services:
  celery-worker:
    cpus: 2
    cpu_percent: 50
```

### Celery Workers

```bash
# Increase worker concurrency
command: celery -A tasks.celery_app worker --concurrency=8

# Use multiple worker containers
docker-compose up --scale celery-worker=4
```

## Security Best Practices

1. **Change default passwords** in `.env`
2. **Use secrets** instead of environment variables in production
3. **Enable SSL/TLS** with valid certificates
4. **Restrict CORS origins** to known domains
5. **Use non-root users** in containers (already configured)
6. **Keep images updated** regularly
7. **Scan images** for vulnerabilities:
   ```bash
   docker scan elrond-backend
   ```
8. **Limit container capabilities**
9. **Use read-only volumes** for evidence
10. **Enable firewall rules**

## Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [FastAPI Docker Guide](https://fastapi.tiangolo.com/deployment/docker/)
- [React Docker Guide](https://create-react-app.dev/docs/deployment/)

## Support

For issues or questions:
- Check logs: `docker-compose logs`
- Review this documentation
- Check GitHub issues
- Contact support team

---

**Last Updated**: 2025-01-15
**Docker Version**: 20.10+
**Docker Compose Version**: 2.0+
