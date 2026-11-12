# Rowanholt Installation Guide

Complete installation and setup guide for the Rowanholt Digital Forensics Suite.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [First-Time Setup](#first-time-setup)
4. [Starting Rowanholt](#starting-rowanholt)
5. [Running Your First Test](#running-your-first-test)
6. [Verification](#verification)
7. [Troubleshooting](#troubleshooting)
8. [Next Steps](#next-steps)

---

## Prerequisites

Before installing Rowanholt, ensure you have:

### Required

- **Git** - For cloning the repository
- **Python 3.10+** - For running the installer and test scripts
- **Docker** or **OrbStack** - For running Rowanholt containers
- **At least 10GB free disk space** - For Docker images and containers
- **At least 12GB RAM** - Recommended 16GB for full stack, 10GB minimum for testing mode

### Recommended System Specs

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 10GB | 16GB+ |
| CPU | 4 cores | 8+ cores |
| Disk | 10GB | 50GB+ |
| OS | macOS 12+, Ubuntu 20.04+, Windows 10+ | Latest versions |

### Platform Notes

**macOS:**
- Apple Silicon (M1/M2/M3) or Intel processors supported
- macOS 12.0 (Monterey) or later

**Linux:**
- Ubuntu 20.04+, Debian 11+, Fedora 36+, RHEL 8+
- Kernel 4.15+ recommended

**Windows:**
- Windows 10 or 11
- WSL2 recommended for better performance
- Virtualization enabled in BIOS/UEFI

---

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/cmdaltr/rowanholt.git
cd rowanholt
```

### Step 2: Install Docker Container Runtime

**Recommended: OrbStack (macOS Only)**

OrbStack is the **preferred solution** for macOS users:

```bash
# Install via Homebrew
brew install --cask orbstack

# Or download from: https://orbstack.dev/download
```

**Why OrbStack?**
- ✅ **No gVisor networking bugs** - Docker Desktop 4.52.0+ has critical bugs that cause crashes when processing large forensic images (11GB+ E01 files)
- ✅ **2-3x faster** than Docker Desktop for forensic workloads
- ✅ **Uses ~4GB RAM** instead of 8-12GB
- ✅ **Native file sharing** - Much faster than Docker Desktop's VirtioFS
- ✅ **Instant startup** - Containers start immediately
- ✅ **Free for personal use** ($10/month for commercial)
- ✅ **Docker Engine v28.5.2** - Stable version without bugs

**Alternative: Docker Desktop (Linux/Windows, or macOS if needed)**

For non-macOS platforms, use the installer:

```bash
python3 scripts/install-rowanholt.py
```

The installer will:
1. Detect your operating system and architecture
2. Present installation options:
   - **OrbStack** (macOS only) - **RECOMMENDED**
   - **Docker Desktop 4.51.0** (Engine v28.5.2) - Stable, no gVisor bugs
3. Download and install your selected option
4. Verify the installation
5. **Prompt for forensic image paths** (primary, secondary, tertiary)
6. Automatically update `docker-compose.yml` with your paths

**Installation Options Comparison:**

| Feature | OrbStack (macOS) | Docker Desktop 4.51.0 |
|---------|------------------|----------------------|
| **Platforms** | macOS only | macOS, Linux, Windows |
| **RAM Usage** | ~4GB | ~8-12GB |
| **Performance** | **2-3x faster** | Standard |
| **File Sharing** | **Native (fast)** | VirtioFS (slower) |
| **gVisor Bugs** | ✅ **None** | ✅ None (4.51.0 only) |
| **Startup Time** | **Instant** | 30-60 seconds |
| **Cost** | Free (personal), $10/mo (commercial) | Free |

**⚠️ AVOID Docker Desktop 4.52.0+** - These versions include Docker Engine v29.x with gVisor networking bugs that cause crashes when processing large forensic images.

**Recommendation:**
- **macOS users**: **Use OrbStack** (best performance, no bugs)
- **Linux/Windows users**: Use Docker Desktop 4.51.0
- **16GB RAM or less**: Use OrbStack or Testing Mode

#### What Happens During Image Path Configuration

After Docker installation, the installer will prompt:

```
Configure forensic image paths now? (Y/n):
```

**If you choose Yes (recommended):**

1. **Primary path (required):**
   ```
   Enter path to forensic images: /path/to/your/images
   ```
   - The installer validates the path exists
   - Offers to create the directory if it doesn't exist
   - Loops until a valid path is provided

2. **Secondary path (optional):**
   ```
   Enter secondary path or press Enter to skip:
   ```
   - Press Enter to skip
   - If provided, validates like primary path

3. **Tertiary path (optional):**
   ```
   Enter tertiary path or press Enter to skip:
   ```
   - Press Enter to skip
   - If provided, validates like primary path

**The installer then automatically:**
- Updates `docker-compose.yml` with your paths
- Mounts paths as `/data`, `/data1`, `/data2` in containers
- Shows you the configured mappings

**If you choose No:**
- You'll need to manually edit `docker-compose.yml` (see Step 5 below)

---

## First-Time Setup

### Step 3: Verify Docker is Running

```bash
# Check Docker is running
docker --version
docker ps

# Should see Docker version and empty container list
```

### Step 4: Configure Environment (Optional)

**Note:** The installer automatically creates `.env` from `.env.example` during installation.

Rowanholt uses environment variables for configuration. Default settings work for most users.

**To customize configuration**, edit the `.env` file:

```bash
# Edit with your settings
nano .env
# Or use: vi .env, vim .env, code .env, etc.
```

**If you skipped the installer or need to recreate `.env`:**

```bash
# Copy example environment file
cp .env.example .env

# Edit with your settings
nano .env
```

**Common settings to customize:**

```bash
# API Port (default: 5688)
API_PORT=5688

# Frontend Port (default: 5687)
FRONTEND_PORT=5687

# Database settings (defaults work for most users)
DATABASE_URL=postgresql://rowanholt:rowanholt@postgres:5432/rowanholt

# Security (IMPORTANT: Change these for production!)
SECRET_KEY=change-this-to-a-random-secret-key
API_KEY=your-api-key-here
```

### Step 5: Configure Forensic Image Paths (If Not Done During Installation)

**Note:** If you configured image paths during installation (Step 2), you can skip this step.

**⚠️ IMPORTANT:** If you skipped path configuration during installation, you need to configure where your forensic images are located before running tests.

#### Quick Method: Use the Path Manager Script

The easiest way to configure or update paths:

```bash
python3 scripts/image-paths.py
```

**This interactive script lets you:**
- View currently configured paths
- Add new paths
- Remove specific paths
- Replace all paths
- Validates paths and updates docker-compose.yml automatically

#### Manual Method: Edit Configuration Files

#### Option 1: Use Default Paths (Recommended for Testing)

The default configuration expects images at:
- **macOS**: `/Volumes/Media5TB/rowanholt_imgs/`
- **Linux**: `/data/rowanholt_imgs/`
- **Windows**: `C:\data\rowanholt_imgs\`

**Create the directory and add your E01 images:**

```bash
# macOS
mkdir -p /Volumes/Media5TB/rowanholt_imgs
# Copy your E01 files here

# Linux
sudo mkdir -p /data/rowanholt_imgs
sudo chown $USER:$USER /data/rowanholt_imgs
# Copy your E01 files here

# Windows (PowerShell as Administrator)
New-Item -ItemType Directory -Path "C:\data\rowanholt_imgs"
# Copy your E01 files here
```

#### Option 2: Configure Custom Paths

If your images are in a different location, update the configuration:

**1. Edit `docker-compose.yml`:**

```yaml
# Find the volumes section for backend and celery-worker
volumes:
  - /your/custom/path:/data:ro    # Change this to your image location
```

**Example for different systems:**

```yaml
# macOS with external drive
- /Volumes/MyDrive/forensics:/data:ro

# Linux
- /home/user/forensic_images:/data:ro

# Windows (use forward slashes)
- C:/Users/YourName/ForensicImages:/data:ro
```

**2. Update test job configurations:**

Edit files in `tests/jobs/*.json` to match your paths:

```json
{
  "source_paths": [
    "/data/your-image.E01"    // This path is inside the container
  ],
  "destination_path": "/data/output/test_case"
}
```

#### Where to Get Sample Images

If you don't have forensic images, you can:

**1. Use Public Datasets:**
- [Digital Corpora](https://digitalcorpora.org/) - Free forensic images
- [NIST Computer Forensics Reference Datasets](https://www.nist.gov/itl/ssd/software-quality-group/computer-forensics-tool-testing-program-cftt/cftt-technical/forensic-0)
- [DFIR Training Images](https://dfir.training/)

**2. Create Your Own Test Images:**
```bash
# Create a test E01 image from a directory (requires FTK Imager or similar)
# This is just an example - you'll need forensic imaging tools
```

**3. Skip Tests Initially:**
You can start Rowanholt without images to:
- Access the web interface
- Configure settings
- Add images later via the UI

#### Verify Image Access

After configuration, verify Docker can access your images:

```bash
# macOS/Linux
docker run --rm -v /your/image/path:/data:ro alpine ls -lh /data

# Windows
docker run --rm -v C:/your/image/path:/data:ro alpine ls -lh /data
```

**Expected output:** List of your E01 files

---

## Starting Rowanholt

### Step 6: Start Rowanholt in Testing Mode

For first-time users or systems with 16GB RAM or less, use **Testing Mode**:

```bash
./scripts/start-testing-mode.sh
```

**Testing Mode disables:**
- Splunk (saves 4GB RAM)
- Elasticsearch (saves 2GB RAM)
- Kibana
- Navigator

**Testing Mode runs:**
- ✅ PostgreSQL (job storage)
- ✅ Redis (task queue)
- ✅ Backend API
- ✅ Celery Worker (forensic processing)
- ✅ Frontend

**Total memory usage: ~9GB** (fits in Docker with 10GB allocation)

### Alternative: Full Stack Mode

If you have 32GB+ RAM and want all features:

```bash
# Start full stack with SIEM integration (Splunk, Elastic, Kibana, Navigator)
docker compose --profile siem up -d
```

### Step 7: Wait for Services to Start

The startup script waits ~15 seconds for services to initialize.

**Check service status:**

```bash
docker compose ps
```

**Expected output:**

```
NAME                STATUS          PORTS
rowanholt-backend   Up 30 seconds   127.0.0.1:5688->5688/tcp
rowanholt-celery    Up 30 seconds
rowanholt-frontend  Up 30 seconds   127.0.0.1:5687->3000/tcp
rowanholt-postgres  Up 45 seconds   127.0.0.1:5432->5432/tcp
rowanholt-redis     Up 45 seconds   127.0.0.1:6379->6379/tcp
```

---

## Running Your First Test

### Step 8: Navigate to Test Directory

```bash
cd tests
```

### Step 9: Run a Quick Test

Run the fastest test case to verify everything works:

```bash
./scripts/run_single_test.sh win_brisk
```

**What this does:**
1. Submits a forensic job to the backend API
2. Celery worker processes the E01 image
3. Generates output with forensic artifacts
4. Returns job status and results

**Expected output:**

```
======================================================================
  Starting Test: win_brisk
======================================================================
Job ID: 61f1a31e-67c5-4763-bb34-cc809cbb8f51
Status: running
Progress: 25%
...
Status: completed
Progress: 100%

✓ Test completed successfully!
```

### Step 10: Check Job Status

Monitor running jobs:

```bash
# Basic status
./scripts/status.sh

# Watch mode (auto-refresh every 5s)
./scripts/status.sh --watch

# Show full job IDs
./scripts/status.sh --full
```

**Example output:**

```
======================================================================
  JOB STATUS SUMMARY
======================================================================
  Running: 1  |  Pending: 0  |  Completed: 3  |  Failed: 0
======================================================================

  RUNNING:
    🔄 TEST_win_brisk (45%)
       ID: 61f1a31e-67c5-4763-bb34-cc809cbb8f51
```

---

## Verification

### Step 11: Access Web Interface

Open your browser and navigate to:

**Frontend:** http://localhost:5687
**Backend API:** http://localhost:5688

### Step 12: Verify Output Files

Check that test output was generated:

```bash
# Navigate to test output directory
ls -lh /Volumes/Media5TB/rowanholt_imgs/tests/win_brisk/

# Should see output files like:
# - artifacts/
# - timeline.csv
# - results.json
# - etc.
```

---

## Troubleshooting

### Docker Not Starting

**Problem:** `Docker is not running`

**Solution:**
```bash
# macOS: Open Docker Desktop from Applications
open -a Docker

# Linux: Start Docker service
sudo systemctl start docker

# Windows: Start Docker Desktop from Start menu
```

### Services Not Ready

**Problem:** `Connection refused` or `API not responding`

**Solution:**
```bash
# Check container logs
docker compose logs backend
docker compose logs celery-worker

# Restart services
docker compose restart

# Or full restart
docker compose down
./scripts/start-testing-mode.sh
```

### Out of Memory

**Problem:** Docker crashes or `Killed` processes

**Solution:**
```bash
# Use Testing Mode (saves 6GB RAM)
./scripts/start-testing-mode.sh

# Increase Docker memory allocation:
# Docker Desktop → Settings → Resources → Memory → 10GB or more
```

### Job Stuck

**Problem:** Job shows `running` but no progress for >1 hour

**Solution:**
```bash
# Get full job ID
./scripts/status.sh --full

# Stop the stuck job
./scripts/stop-jobs.sh <job-id>

# Or stop all jobs
./scripts/stop-jobs.sh
```

### Port Already in Use

**Problem:** `Port 5688 already allocated`

**Solution:**
```bash
# Check what's using the port
lsof -i :5688

# Kill the process or change Rowanholt's port in .env
# Then restart
docker compose down
docker compose up -d
```

### Permission Denied

**Problem:** `Permission denied` when accessing files

**Solution:**
```bash
# macOS/Linux: Fix ownership
sudo chown -R $USER:$USER .

# Docker: Run with current user
docker compose down
docker compose up -d
```

### Docker Desktop gVisor Crash

**Problem:** `com.docker.virtualization: process terminated unexpectedly`

**Solution:**
This is a known bug in Docker Desktop 4.52.0+. Use the installer to downgrade:
```bash
python3 scripts/install-rowanholt.py
# Select option 1 (Docker Desktop 4.51.0)
```

Or switch to OrbStack on macOS.

---

## Next Steps

### Run More Tests

```bash
# Run individual tests
./scripts/run_single_test.sh win_keywords
./scripts/run_single_test.sh linux_brisk

# Run batch tests
./scripts/batch/batch1a-archive-lnk.sh
./scripts/batch/batch1b-web-usb.sh

# Run all tests (takes several hours)
./scripts/batch/RUN_ALL_TESTS.sh
```

### Explore the Documentation

- **Quick Start Guide:** `tests/QUICK_START.md`
- **Test Runner Guide:** `tests/docs/TEST_RUNNER_GUIDE.md`
- **Docker Installation:** `scripts/DOCKER_INSTALL.md`
- **Test Configuration:** `tests/tests.conf`

### Job Management

```bash
# Check status
./scripts/status.sh

# Stop a specific job
./scripts/stop-jobs.sh <job-id>

# Stop all jobs
./scripts/stop-jobs.sh

# Clear old completed jobs
./scripts/clear-old-jobs.sh
```

### View Logs

```bash
# View all logs
docker compose logs

# View specific service
docker compose logs backend
docker compose logs celery-worker

# Follow logs in real-time
docker compose logs -f backend
```

### Manage Image Paths

Update forensic image paths anytime:
```bash
# Interactive path manager
python3 scripts/image-paths.py

# Options:
# 1. Show current paths
# 2. Add new paths
# 3. Remove paths
# 4. Replace all paths
```

### Customize Configuration

Edit test configurations:
```bash
# Main test config
nano tests/tests.conf

# Job configurations
nano tests/jobs/win_brisk.json
```

### Access SIEM (Full Stack Only)

If running full stack:

**Splunk:**
- URL: http://localhost:7755
- User: admin
- Password: the `SPLUNK_PASSWORD` value in `docker-compose.yml`

**Elasticsearch:**
- URL: http://localhost:9200

**Kibana:**
- URL: http://localhost:5601

---

## Stopping Rowanholt

```bash
# Stop all containers
docker compose down

# Stop and remove volumes (WARNING: deletes all data)
docker compose down -v

# Stop specific service
docker compose stop backend
```

---

## Updating Rowanholt

```bash
# Pull latest changes
git pull origin main

# Rebuild containers
docker compose build

# Restart services
docker compose down
./scripts/start-testing-mode.sh
```

---

## Uninstalling

### Remove Containers and Images

```bash
# Stop all containers
docker compose down

# Remove all Rowanholt images
docker rmi $(docker images | grep rowanholt | awk '{print $3}')

# Remove all unused volumes
docker volume prune
```

### Remove Docker Desktop

**macOS:**
```bash
# Docker Desktop → Troubleshoot → Uninstall
# Or drag Docker.app to Trash
```

**Linux:**
```bash
sudo apt remove docker-desktop  # Ubuntu/Debian
sudo dnf remove docker-desktop  # Fedora/RHEL
```

**Windows:**
```
Settings → Apps → Docker Desktop → Uninstall
```

### Remove OrbStack (macOS)

```bash
brew uninstall --cask orbstack
```

---

## Getting Help

- **Documentation:** Check `docs/` directory
- **Issues:** https://github.com/cmdaltr/rowanholt/issues
- **Discussions:** https://github.com/cmdaltr/rowanholt/discussions

---

## Quick Reference

### Essential Commands

```bash
# Start Rowanholt (testing mode)
./scripts/start-testing-mode.sh

# Check status
./scripts/status.sh

# Run a test
cd tests && ./scripts/run_single_test.sh win_brisk

# Stop Rowanholt
docker compose down

# View logs
docker compose logs -f
```

### Common File Locations

| Path | Description |
|------|-------------|
| `tests/` | Test configurations and scripts |
| `tests/jobs/` | Job configuration files |
| `tests/logs/` | Test execution logs |
| `tests/output/` | Test results |
| `scripts/` | Utility scripts |
| `docker-compose.yml` | Main Docker configuration |
| `tests/docker-compose.testing.yml` | Testing mode overrides |

---

**Ready to start investigating? Run your first test!**

```bash
cd tests
./scripts/run_single_test.sh win_brisk
```
