# Docker Troubleshooting Guide for Rowanholt

> **Legacy.** This describes the standalone Elrond stack in `src/analysis/web` and `src/analysis/docker` (ports 3000 and 8000), which Rowanholt no longer uses. Rowanholt runs from the repository's `docker-compose.yml` (web UI on :5687, API on :5688): start with [docs/QUICKSTART.md](../../../docs/QUICKSTART.md) and the `rowanholt` command.

This guide covers common Docker issues with Rowanholt and their solutions.

## Table of Contents
- [Build Failures](#build-failures)
- [Container Issues](#container-issues)
- [Network & Port Issues](#network--port-issues)
- [Volume & Storage Issues](#volume--storage-issues)
- [Performance Issues](#performance-issues)
- [Clean-Up & Reset](#clean-up--reset)

---

## Build Failures

### Issue: Package Installation Failed (Exit Code 100)

**Symptoms:**
```
failed to solve: process "/bin/sh -c apt-get install ..." did not complete successfully: exit code: 100
```

**Common Causes & Solutions:**

#### 1. Obsolete Package Names
Some packages have been renamed in newer Ubuntu versions:

```bash
# OLD (Ubuntu 18.04/20.04)
exfat-utils          # ❌ No longer available

# NEW (Ubuntu 22.04)
exfatprogs           # ✅ Use this instead
```

**Solution:** Update Dockerfile to use current package names.

#### 2. Missing Package Repository
Some packages require additional repositories (e.g., deadsnakes PPA for Python 3.11).

**Solution:**
```dockerfile
# Add repository before installing
RUN apt-get update && apt-get install -y software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa -y && \
    apt-get update
```

#### 3. Architecture Incompatibility
Some packages may not be available for ARM64 (Apple Silicon).

**Check your architecture:**
```bash
uname -m
# Output: arm64 (Apple Silicon) or x86_64 (Intel)
```

**Solution:** Use architecture-agnostic alternatives or skip platform-specific tools.

---

### Issue: Docker Cache Using Old Layers

**Symptoms:**
- Build fails on lines that don't exist in current Dockerfile
- Error mentions old package names or configurations
- Build target shows unexpected names (e.g., "flower")

**Example:**
```
target flower: failed to solve...
Dockerfile:50
>>> RUN git clone https://github.com/sgan81/apfs-fuse.git
```

But line 50 in your Dockerfile is completely different!

**Solution:**

```bash
# Option 1: Rebuild without cache
docker-compose -f docker/docker-compose.yml build --no-cache

# Option 2: Clean all Docker cache
docker system prune -a
docker builder prune -a

# Option 3: Complete Docker reset
docker system prune -a --volumes
```

**Pro Tip:** Always use `--no-cache` when troubleshooting build issues:
```bash
docker-compose build --no-cache elrond-engine
```

---

### Issue: Context Path Not Found

**Symptoms:**
```
unable to prepare context: path "/path/to/web/frontend" not found
```

**Cause:** Docker Compose file is using incorrect relative paths.

**Solution:**

Check where your `docker-compose.yml` is located and adjust paths accordingly:

```yaml
# If docker-compose.yml is in /analysis/docker/
services:
  backend:
    build:
      context: ../web/backend  # Go up one level, then into web/backend
      dockerfile: Dockerfile

# If docker-compose.yml is in /analysis/
services:
  backend:
    build:
      context: ./web/backend   # Direct path from current directory
      dockerfile: Dockerfile
```

**Quick Fix:**
```bash
# From the analysis directory
cd /path/to/rowanholt/analysis

# Check docker-compose.yml location
ls -la docker/docker-compose.yml

# Update all context paths to use ../
# context: ./web/backend  →  context: ../web/backend
```

---

### Issue: Python Version Not Available

**Symptoms:**
```
E: Package 'python3.11' has no installation candidate
```

**Solution:**

**Option 1:** Use system Python (recommended for compatibility)
```dockerfile
# Use Ubuntu 22.04's default Python 3.10
RUN apt-get install -y python3 python3-dev python3-pip
```

**Option 2:** Add deadsnakes PPA
```dockerfile
RUN apt-get install -y software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa -y && \
    apt-get update && \
    apt-get install -y python3.11 python3.11-dev
```

---

## Container Issues

### Issue: Container Exits Immediately

**Check container status:**
```bash
docker-compose -f docker/docker-compose.yml ps
docker logs elrond-engine
```

**Common causes:**

#### 1. Missing FUSE device
```bash
# Add to docker-compose.yml
services:
  elrond-engine:
    privileged: true
    devices:
      - /dev/fuse
```

#### 2. Command fails immediately
Check the container logs:
```bash
docker logs elrond-engine 2>&1 | tail -50
```

#### 3. Health check failing
```bash
# Check health status
docker inspect elrond-engine | grep -A 10 Health

# Disable health check temporarily
# Comment out healthcheck in docker-compose.yml
```

---

### Issue: Cannot Access Container Shell

**Symptoms:**
```bash
docker-compose exec elrond-engine bash
# Error: container not running
```

**Solution:**

```bash
# Check if container is running
docker-compose ps

# If stopped, check why
docker logs elrond-engine

# Start in foreground to see errors
docker-compose up elrond-engine

# Or override command to keep container alive
docker-compose run --rm elrond-engine bash
```

---

### Issue: Permission Denied Inside Container

**Symptoms:**
```
Permission denied: '/evidence'
mkdir: cannot create directory '/mnt/elrond_mount01'
```

**Solution:**

```bash
# Fix permissions for mounted volumes
docker-compose exec --user root elrond-engine bash
chown -R elrond:elrond /evidence /output /mnt/elrond_mount*

# Or in docker-compose.yml
services:
  elrond-engine:
    user: "0:0"  # Run as root temporarily
```

---

## Network & Port Issues

### Issue: Port Already in Use

**Symptoms:**
```
Error starting userland proxy: listen tcp 0.0.0.0:3000: bind: address already in use
```

**Find what's using the port:**
```bash
# macOS/Linux
lsof -i :3000
sudo lsof -ti:3000 | xargs kill -9

# Windows
netstat -ano | findstr :3000
```

**Solution 1: Change port in docker-compose.yml**
```yaml
ports:
  - "3001:3000"  # Host:Container
```

**Solution 2: Stop conflicting service**
```bash
# Example: Stop Node.js dev server
ps aux | grep node
kill <PID>
```

---

### Issue: Cannot Access Web Interface

**Check if containers are running:**
```bash
docker-compose ps
```

**Test connectivity:**
```bash
# Test backend
curl http://localhost:8000/api/health

# Test frontend
curl http://localhost:3000

# Check container logs
docker-compose logs frontend
docker-compose logs backend
```

**Common fixes:**
```bash
# 1. Restart services
docker-compose restart

# 2. Check firewall (macOS)
sudo pfctl -d  # Disable temporarily

# 3. Check firewall (Linux)
sudo ufw status
sudo ufw allow 3000/tcp
sudo ufw allow 8000/tcp

# 4. Rebuild with clean state
docker-compose down
docker-compose up --build
```

---

## Volume & Storage Issues

### Issue: Out of Disk Space

**Check Docker disk usage:**
```bash
docker system df

# Example output:
# TYPE            TOTAL     ACTIVE    SIZE      RECLAIMABLE
# Images          15        5         10.5GB    8.2GB (78%)
# Containers      20        3         1.2GB     900MB (75%)
# Local Volumes   10        2         5GB       4GB (80%)
# Build Cache     50        0         15GB      15GB (100%)
```

**Clean up:**
```bash
# Remove unused images
docker image prune -a

# Remove stopped containers
docker container prune

# Remove unused volumes (BE CAREFUL!)
docker volume prune

# Remove build cache
docker builder prune -a

# Nuclear option - remove everything
docker system prune -a --volumes
```

**Before major cleanup, backup important volumes:**
```bash
# List volumes
docker volume ls

# Backup a volume
docker run --rm \
  -v elrond-output:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/elrond-backup-$(date +%Y%m%d).tar.gz /data
```

---

### Issue: Volume Mount Not Working

**Symptoms:**
```
# Files on host don't appear in container
# Or changes in container don't persist
```

**Debug:**
```bash
# Check volume is mounted
docker inspect elrond-engine | grep -A 10 Mounts

# Check volume contents
docker run --rm -v elrond-evidence:/data alpine ls -la /data

# Check permissions
docker exec elrond-engine ls -la /evidence
```

**Solution:**
```yaml
# Fix volume paths in docker-compose.yml
volumes:
  # Named volume (managed by Docker)
  - elrond-evidence:/evidence

  # Host mount (direct mapping)
  - /host/path/to/evidence:/evidence

  # Relative path (from docker-compose.yml location)
  - ../evidence:/evidence
```

---

## Performance Issues

### Issue: Slow Build Times

**Solutions:**

```bash
# 1. Use build cache (don't use --no-cache unless necessary)
docker-compose build

# 2. Increase Docker resources
# Docker Desktop → Settings → Resources
# - CPUs: 4+
# - Memory: 8GB+
# - Disk: 60GB+

# 3. Use BuildKit (faster builds)
export DOCKER_BUILDKIT=1
docker-compose build

# 4. Multi-stage builds (already in Dockerfile)
# Reduces final image size

# 5. Clean build cache periodically
docker builder prune
```

---

### Issue: Container Uses Too Much Memory

**Monitor resource usage:**
```bash
docker stats elrond-engine

# Example output:
# CONTAINER       CPU %    MEM USAGE / LIMIT    MEM %
# elrond-engine   15%      2GB / 8GB           25%
```

**Set memory limits:**
```yaml
services:
  elrond-engine:
    mem_limit: 4g
    mem_reservation: 2g
```

**Check for memory leaks:**
```bash
# Monitor over time
watch -n 5 'docker stats --no-stream elrond-engine'

# Check container logs for OOM
docker logs elrond-engine 2>&1 | grep -i "out of memory\|oom"
```

---

## Clean-Up & Reset

### Complete Docker Reset

**When to use:** Last resort when nothing else works.

**⚠️ WARNING: This will delete ALL Docker data!**

```bash
# 1. Stop all containers
docker-compose down
docker stop $(docker ps -aq)

# 2. Remove all containers
docker rm $(docker ps -aq)

# 3. Remove all images
docker rmi $(docker images -q)

# 4. Remove all volumes (CAREFUL - this deletes data!)
docker volume rm $(docker volume ls -q)

# 5. Remove all networks
docker network prune

# 6. Remove all build cache
docker builder prune -a

# 7. System-wide prune
docker system prune -a --volumes

# 8. Verify everything is clean
docker system df
```

**Rebuild from scratch:**
```bash
cd /path/to/rowanholt/analysis
docker-compose -f docker/docker-compose.yml build --no-cache
docker-compose -f docker/docker-compose.yml up
```

---

### Selective Clean-Up

**Remove only Rowanholt containers:**
```bash
# Stop Rowanholt services
docker-compose -f docker/docker-compose.yml down

# Remove Rowanholt containers
docker ps -a | grep elrond | awk '{print $1}' | xargs docker rm

# Remove Rowanholt images
docker images | grep elrond | awk '{print $3}' | xargs docker rmi
```

**Preserve volumes but rebuild:**
```bash
# Keep data, rebuild containers
docker-compose -f docker/docker-compose.yml down
docker-compose -f docker/docker-compose.yml build --no-cache
docker-compose -f docker/docker-compose.yml up
```

---

## Monitoring & Debugging

### View Real-Time Logs

```bash
# All services
docker-compose -f docker/docker-compose.yml logs -f

# Specific service
docker-compose -f docker/docker-compose.yml logs -f backend

# Last 100 lines
docker-compose -f docker/docker-compose.yml logs --tail=100

# With timestamps
docker-compose -f docker/docker-compose.yml logs -f -t
```

### Inspect Container Details

```bash
# Full container configuration
docker inspect elrond-engine

# Just the status
docker inspect elrond-engine | jq '.[0].State'

# Environment variables
docker inspect elrond-engine | jq '.[0].Config.Env'

# Mounts
docker inspect elrond-engine | jq '.[0].Mounts'

# Health check
docker inspect elrond-engine | jq '.[0].State.Health'
```

### Execute Commands in Running Container

```bash
# Interactive shell
docker exec -it elrond-engine bash

# Run command as root
docker exec -it --user root elrond-engine bash

# Run single command
docker exec elrond-engine python3 --version

# Check Python environment
docker exec elrond-engine python3 -c "import sys; print(sys.path)"
```

---

## Build Progress Monitoring

### Monitor Live Build

```bash
# Method 1: Direct output
docker-compose -f docker/docker-compose.yml build

# Method 2: Save to log file
docker-compose -f docker/docker-compose.yml build 2>&1 | tee build.log

# Method 3: Watch log file (if backgrounded)
tail -f build.log

# Method 4: Check only for errors
docker-compose build 2>&1 | grep -i error
```

### Check Build Status

```bash
# Check if build completed successfully
docker images | grep elrond

# If you see the image with recent timestamp = SUCCESS
# elrond-engine   latest   abc123  2 minutes ago   2.5GB

# Check build history
docker history elrond-engine:latest

# Verify image works
docker run --rm elrond-engine:latest python3 --version
```

---

## Common Error Messages & Solutions

| Error | Cause | Solution |
|-------|-------|----------|
| `Package has no installation candidate` | Package name changed/doesn't exist | Update package name in Dockerfile |
| `failed to solve: process ... exit code: 100` | Package installation failed | Check package availability, update names |
| `unable to prepare context: path not found` | Wrong build context path | Fix paths in docker-compose.yml |
| `bind: address already in use` | Port conflict | Change port or kill process using it |
| `permission denied` | Volume permission issue | Fix with `chown` or run as root |
| `container not running` | Container crashed | Check `docker logs` for errors |
| `no space left on device` | Disk full | Run `docker system prune -a` |
| `Cannot connect to Docker daemon` | Docker not running | Start Docker Desktop/daemon |

---

## Quick Reference Commands

```bash
# === Build ===
docker-compose build                          # Build with cache
docker-compose build --no-cache               # Clean build
docker-compose build --pull                   # Pull latest base images

# === Start/Stop ===
docker-compose up                            # Start in foreground
docker-compose up -d                         # Start in background
docker-compose down                          # Stop and remove containers
docker-compose restart                       # Restart all services

# === Logs ===
docker-compose logs -f                       # Follow all logs
docker-compose logs -f backend               # Follow specific service
docker-compose logs --tail=50                # Last 50 lines

# === Status ===
docker-compose ps                            # List containers
docker-compose top                           # Show running processes
docker stats                                 # Resource usage

# === Debug ===
docker exec -it elrond-engine bash           # Interactive shell
docker logs elrond-engine                    # View logs
docker inspect elrond-engine                 # Full config

# === Clean-up ===
docker-compose down -v                       # Stop and remove volumes
docker system prune                          # Clean unused resources
docker system prune -a --volumes             # Nuclear clean
```

---

## Getting Help

If you're still stuck after trying these solutions:

1. **Check the build log:**
   ```bash
   cat build.log | tail -100
   ```

2. **Gather debug information:**
   ```bash
   docker version
   docker-compose version
   uname -a
   docker info
   docker system df
   ```

3. **Create a minimal reproduction:**
   ```bash
   # Try building just the base stage
   docker build --target base -t test-base .
   ```

4. **Check GitHub Issues:**
   - Search for similar errors
   - Include your OS, architecture, and error messages

5. **Enable debug mode:**
   ```bash
   export DOCKER_BUILDKIT=0
   export COMPOSE_DOCKER_CLI_BUILD=0
   docker-compose build --progress=plain
   ```

---

## Best Practices

✅ **Do:**
- Always use `--no-cache` when troubleshooting builds
- Regularly clean up unused Docker resources
- Monitor disk space with `docker system df`
- Keep Docker Desktop/Engine updated
- Use specific image tags (not `latest`)
- Test builds in stages

❌ **Don't:**
- Use `docker system prune -a --volumes` without backing up
- Ignore build warnings
- Run containers as root unnecessarily
- Mount sensitive host directories
- Use `:latest` tag in production

---

**Last Updated:** November 2025
**Rowanholt Version:** 2.1.0
