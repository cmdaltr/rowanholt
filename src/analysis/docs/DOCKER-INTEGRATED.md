# Elrond Fully Integrated Docker Deployment

> **Legacy.** This describes the standalone Elrond stack in `src/analysis/web` and `src/analysis/docker` (ports 3000 and 8000), which Rowanholt no longer uses. Rowanholt runs from the repository's `docker-compose.yml` (web UI on :5687, API on :5688): start with [docs/QUICKSTART.md](../../../docs/QUICKSTART.md) and the `rowanholt` command.

Complete dockerization of the entire Elrond application - forensics engine + web interface running from a single unified container image.

## Overview

This deployment method runs **everything** in Docker containers, including:
- ✅ Full forensics engine with all tools (Volatility, Plaso, Sleuthkit, etc.)
- ✅ Web backend API (FastAPI)
- ✅ Celery workers executing actual forensic analyses
- ✅ React frontend
- ✅ Redis message broker

**Key Difference**: Unlike the basic Docker setup where only the web interface runs in containers, this configuration runs the complete Elrond forensics engine inside Docker, allowing for:
- Complete isolation and reproducibility
- No need to install forensic tools on the host
- Consistent environment across all deployments
- Easy scaling and distribution

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Host System                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              Elrond Docker Environment                      │ │
│  │                                                              │ │
│  │   ┌──────────────┐    ┌──────────────┐    ┌─────────────┐│ │
│  │   │   Frontend   │───▶│   Backend    │───▶│    Redis    ││ │
│  │   │  (React)     │    │  (FastAPI)   │    │   Broker    ││ │
│  │   │  Port 3000   │    │  Port 8000   │    │  Port 6379  ││ │
│  │   └──────────────┘    └──────────────┘    └─────────────┘│ │
│  │                              │                              │ │
│  │                              ▼                              │ │
│  │   ┌────────────────────────────────────────────────┐      │ │
│  │   │        Celery Workers                          │      │ │
│  │   │  ┌────────────────────────────────────────┐   │      │ │
│  │   │  │  Elrond Forensics Engine               │   │      │ │
│  │   │  │  • Volatility 3                        │   │      │ │
│  │   │  │  • Plaso                               │   │      │ │
│  │   │  │  • Sleuthkit                           │   │      │ │
│  │   │  │  • Registry Tools                      │   │      │ │
│  │   │  │  • All Python Forensic Libraries       │   │      │ │
│  │   │  └────────────────────────────────────────┘   │      │ │
│  │   │                                                │      │ │
│  │   │  Privileged Container with:                   │      │ │
│  │   │  • FUSE support                                │      │ │
│  │   │  • Disk mounting capabilities                  │      │ │
│  │   │  • Full filesystem access                      │      │ │
│  │   └────────────────────────────────────────────────┘      │ │
│  │                              │                              │ │
│  │   ┌──────────────────────────▼────────────────────────┐  │ │
│  │   │             Shared Volumes                        │  │ │
│  │   │  /evidence  /output  /cases  /logs               │  │ │
│  │   └───────────────────────────────────────────────────┘  │ │
│  └──────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Build the Image

```bash
# From elrond root directory
docker build -t elrond-forensics:latest .
```

This creates a ~5GB image with all forensic tools pre-installed.

### 2. Start the Full Stack

```bash
# Using the integrated compose file
docker-compose -f docker/docker-compose-integrated.yml up
```

Or use the startup script:

```bash
# The script will detect and use the integrated config
./scripts/docker-start.sh --integrated
```

### 3. Access the Application

- **Web Interface**: http://localhost:3000
- **API Documentation**: http://localhost:8000/docs
- **API Health**: http://localhost:8000/api/health

## What's Included in the Forensics Container

### System Tools
- `ewf-tools` - E01 image mounting
- `sleuthkit` - File system analysis
- `ntfs-3g`, `exfat-fuse`, `hfsutils` - File system drivers
- `fuse` - For mounting disk images
- `p7zip`, `unzip` - Archive handling

### Python Forensic Libraries
- **Volatility 3** - Memory forensics
- **Plaso** - Timeline analysis
- **pytsk3** - Sleuthkit Python bindings
- **python-registry** - Windows registry parsing
- **regipy** - Modern registry parser
- **Artemis** - Comprehensive Rust-based forensic parser (fast)
- **dissect** - Cross-platform forensics framework
- **pefile** - PE file analysis
- **yara-python** - YARA rule engine
- **oletools** - Office document analysis
- And 30+ more forensic libraries

### Analysis Tools
- Hash calculators (md5deep, ssdeep)
- Hex viewers (xxd, hexdump)
- Text processors (jq, xmlstarlet)
- Network tools (curl, wget, netcat)

## Usage Examples

### Via Web Interface

1. Open http://localhost:3000
2. Click "New Analysis"
3. Browse for disk image (will be in `/evidence` mount)
4. Configure options
5. Start analysis
6. Watch real-time progress
7. View results in `/output`

The forensics engine runs **inside the container** with full access to all tools.

### Via CLI (Direct Container Access)

```bash
# Enter the forensics container
docker-compose -f docker/docker-compose-integrated.yml exec elrond-cli bash

# Run analysis directly
python3 elrond.py CASE-001 /evidence/disk.E01 /output --Collect --Process --quick

# Check available tools
volatility --help
log2timeline.py --help
fls --help

# Exit container
exit
```

### Via Docker Exec (One-liner)

```bash
# Run a quick analysis
docker-compose -f docker/docker-compose-integrated.yml exec elrond-cli \
  python3 elrond.py INC-2025-001 /evidence/disk.E01 /output \
  --Collect --Process --Userprofiles --quick

# Memory analysis
docker-compose -f docker/docker-compose-integrated.yml exec elrond-cli \
  python3 elrond.py MEM-001 /evidence/memory.mem /output \
  --Memory --memorytimeline

# With SIEM export
docker-compose -f docker/docker-compose-integrated.yml exec elrond-cli \
  python3 elrond.py CASE-001 /evidence/disk.E01 /output \
  --Collect --Process --Splunk --Navigator
```

## Volume Management

### Adding Evidence Files

```bash
# Option 1: Copy into Docker volume
docker cp /host/path/disk.E01 elrond-cli:/evidence/

# Option 2: Use bind mount (edit docker-compose-integrated.yml)
volumes:
  - /host/evidence:/evidence:ro  # Read-only for safety

# Option 3: Mount during run
docker run -v /host/evidence:/evidence elrond-forensics:latest
```

### Accessing Results

```bash
# Copy results out
docker cp elrond-cli:/output/CASE-001 ./results/

# Or inspect volume
docker volume inspect elrond_elrond-output

# Direct access to volume location
sudo ls $(docker volume inspect elrond_elrond-output --format '{{.Mountpoint}}')
```

## Configuration

### Environment Variables

Set in `.env` or `docker-compose-integrated.yml`:

```bash
# Forensics Engine
ELROND_HOME=/opt/elrond
ELROND_OUTPUT=/output
ELROND_EVIDENCE=/evidence
ELROND_CASES=/cases

# Backend API
DEBUG=true
CELERY_BROKER_URL=redis://redis:6379/0
ALLOWED_PATHS=/evidence,/mnt,/output

# Analysis Settings
MAX_CONCURRENT_ANALYSES=2
ANALYSIS_TIMEOUT=86400
```

### Resource Limits

Add to services in `docker-compose-integrated.yml`:

```yaml
celery-worker:
  mem_limit: 8g
  mem_reservation: 4g
  cpus: 4
```

### Scaling Workers

```bash
# Scale Celery workers for parallel processing
docker-compose -f docker/docker-compose-integrated.yml up --scale celery-worker=4 -d
```

## Differences from Standard Docker Setup

| Feature | Standard Setup | Integrated Setup |
|---------|---------------|------------------|
| **Forensics Engine** | On host system | In Docker container |
| **Tool Installation** | Manual on host | Pre-installed in image |
| **Analysis Execution** | Celery calls host tools | Celery runs containerized tools |
| **Disk Mounting** | On host | In privileged container |
| **Reproducibility** | Varies by host | 100% consistent |
| **Isolation** | Partial | Complete |
| **Portability** | Medium | High |
| **Setup Complexity** | Lower | Higher (initial) |

## Advantages

### ✅ Complete Isolation
- No forensic tools needed on host
- Clean separation from host system
- No conflicts with system packages

### ✅ Reproducibility
- Exact same environment every time
- Consistent results across machines
- Easy to share and deploy

### ✅ Security
- Forensics runs in isolated container
- Privileged operations contained
- Evidence protection with read-only mounts

### ✅ Portability
- Run on any Docker host
- Same setup for dev/staging/prod
- Easy distribution to team

### ✅ Maintenance
- Update once, deploy everywhere
- Version control the entire stack
- Easy rollback to previous versions

## Performance Considerations

### Disk I/O
- Docker volumes may have slight overhead
- Use bind mounts for large evidence files
- Consider host-based storage for best performance

### CPU/Memory
- No overhead - native performance
- Can limit resources per container
- Scale workers for parallel processing

### Networking
- Minimal overhead for API calls
- Local container network is fast
- No external network needed

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose -f docker/docker-compose-integrated.yml logs celery-worker

# Check if FUSE device is available
docker-compose -f docker/docker-compose-integrated.yml exec elrond-cli ls -l /dev/fuse
```

### Disk Mounting Fails

```bash
# Ensure privileged mode is enabled
docker-compose -f docker/docker-compose-integrated.yml config | grep privileged

# Check capabilities
docker inspect elrond-celery-worker | grep -A 10 CapAdd

# Try mounting manually
docker-compose -f docker/docker-compose-integrated.yml exec elrond-cli \
  sudo ewfmount /evidence/disk.E01 /mnt/elrond_mount00
```

### Analysis Hangs

```bash
# Check worker status
docker-compose -f docker/docker-compose-integrated.yml exec celery-worker \
  celery -A web.backend.tasks.celery_app inspect active

# View real-time logs
docker-compose -f docker/docker-compose-integrated.yml logs -f celery-worker

# Restart worker
docker-compose -f docker/docker-compose-integrated.yml restart celery-worker
```

### Out of Memory

```bash
# Check container memory usage
docker stats elrond-celery-worker

# Increase memory limit in docker-compose-integrated.yml
mem_limit: 16g

# Scale down concurrent analyses
MAX_CONCURRENT_ANALYSES=1
```

## Production Deployment

For production, combine with the production compose:

```bash
# Use integrated forensics with production web stack
docker-compose \
  -f docker/docker-compose-integrated.yml \
  -f docker/docker-compose.prod.yml \
  up -d
```

Add nginx reverse proxy, SSL, monitoring, etc. as shown in [DOCKER.md](DOCKER.md).

## Comparison with Native Installation

| Aspect | Native | Dockerized |
|--------|--------|-----------|
| Setup Time | Hours | Minutes |
| Tool Updates | Manual each | Rebuild image |
| Consistency | Varies | Identical |
| Isolation | None | Complete |
| Resource Usage | Direct | ~5% overhead |
| Portability | Low | High |
| Maintenance | Complex | Simple |

## Next Steps

1. **Customize the Image**: Add your own tools to Dockerfile
2. **Configure Volumes**: Set up persistent storage strategy
3. **Scale Workers**: Add more Celery workers for throughput
4. **Add Monitoring**: Integrate Prometheus/Grafana
5. **Automate**: Create CI/CD pipeline for image builds

## Resources

- [Main Docker Guide](DOCKER.md) - Complete Docker documentation
- [Docker Quick Start](DOCKER-QUICKSTART.md) - 5-minute setup
- [Testing Guide](TESTING.md) - Testing the Docker setup

---

**Note**: This integrated setup requires Docker with privileged container support and FUSE device access. Not all cloud providers support this configuration.

**Last Updated**: 2025-01-15
**Docker Version**: 20.10+
**Image Size**: ~5GB
