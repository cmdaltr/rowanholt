# Docker Installation Reference

**📖 For complete installation guide, see [INSTALL.md](../INSTALL.md)**

This document provides detailed Docker-specific information, troubleshooting, and manual installation links.

---

## Quick Start

**Most users should use the automated installer:**

```bash
# Run the installer (includes Docker + image paths)
python3 scripts/install-rowanholt.py
```

**This document is useful if you:**
- Need manual Docker download links (installer failed)
- Want to understand Docker options in detail
- Need Docker-specific troubleshooting
- Want to switch between Docker Desktop and OrbStack
- Need to know why we recommend OrbStack for macOS

---

**The installer will:**
1. Detect your OS and architecture
2. Present Docker options (Desktop vs OrbStack)
3. Download and install your selection
4. Verify installation
5. **Prompt for forensic image paths** (up to 3 directories)
6. Automatically update `docker-compose.yml`

## Supported Platforms

### macOS (Intel & Apple Silicon)
- ✅ **OrbStack (latest) - RECOMMENDED**
- ✅ Docker Desktop 4.51.0 (Engine v28.5.2)

### Linux
- ✅ Docker Desktop 4.51.0 (Ubuntu, Debian, Fedora, RHEL, CentOS)
- ❌ OrbStack (macOS only)

### Windows
- ✅ Docker Desktop 4.51.0 (amd64)
- ❌ OrbStack (macOS only)

## Installation Options

### Option 1: OrbStack (macOS only) - RECOMMENDED

**Pros:**
- **2-3x faster** than Docker Desktop for forensic workloads
- Uses **~4GB RAM** instead of 8-12GB
- **No gVisor networking bugs** (unlike Docker Desktop 4.52.0+)
- Better file sharing performance (native vs VirtioFS)
- Native macOS integration
- Instant startup
- Docker Engine v28.5.2 (stable)

**Cons:**
- macOS only
- Requires subscription for commercial use ($10/month)
- Less familiar for Docker Desktop users

**Perfect for:**
- **macOS users (Intel or Apple Silicon) - THIS IS YOU**
- Users processing large forensic images (11GB+ E01 files)
- Personal projects (free)
- Limited RAM machines (16GB Macs)
- Users who experienced Docker Desktop crashes

### Option 2: Docker Desktop 4.51.0

**Pros:**
- Stable version without gVisor networking bugs (4.51.0 specifically)
- Official Docker Desktop experience
- Cross-platform (macOS, Linux, Windows)
- Includes Docker Compose

**Cons:**
- Uses 8-12GB RAM
- Slower file sharing on macOS (VirtioFS)
- Auto-updates (must disable manually to avoid buggy 4.52.0+)
- **⚠️ Versions 4.52.0+ have critical gVisor bugs** that crash with large files

**Perfect for:**
- Windows and Linux users (OrbStack unavailable)
- Users who prefer official Docker Desktop
- Teams requiring consistent Docker environment

## What the Installer Does

### For OrbStack (macOS only) - RECOMMENDED:

1. Checks for Homebrew
2. Installs via Homebrew if available
3. Falls back to manual download if needed
4. Provides setup instructions
5. Verifies installation
6. Switches Docker context to OrbStack

### For Docker Desktop:

**macOS:**
1. Downloads Docker Desktop 4.51.0 DMG
2. Provides step-by-step installation instructions
3. Verifies installation
4. **Reminds to disable auto-updates** (to avoid buggy 4.52.0+)

**Linux:**
1. Detects Linux distribution
2. Downloads appropriate package (.deb or .rpm)
3. Installs using system package manager
4. Verifies installation

**Windows:**
1. Downloads Docker Desktop 4.51.0 installer
2. Launches installer
3. Provides installation instructions

## After Installation

### Start Rowanholt:
```bash
cd /path/to/rowanholt
./scripts/start-testing-mode.sh
```

### Run Tests:
```bash
cd tests
./scripts/run_single_test.sh win_brisk
./scripts/batch/batch1a-archive-lnk.sh
```

### Check Job Status:
```bash
./scripts/status.sh
./scripts/status.sh --watch
```

## Switching Between Docker Desktop and OrbStack

If you have both installed:

```bash
# Use Docker Desktop
docker context use desktop-linux

# Use OrbStack
docker context use orbstack

# Check which is active
docker context show
```

## Troubleshooting

### Docker Desktop won't start after installation
- Restart your computer
- Check Docker Desktop logs: `~/Library/Containers/com.docker.docker/Data/log/`
- Ensure virtualization is enabled in BIOS/UEFI (Windows/Linux)

### OrbStack installation fails on macOS
- Try manual download: https://orbstack.dev/download
- Check macOS version (requires macOS 12.0+)
- Ensure you have admin privileges

### Linux installation fails
- Ensure you have sudo privileges
- Update package manager: `sudo apt update` or `sudo dnf update`
- Check distribution support: https://docs.docker.com/engine/install/

### Downloaded file is corrupted
- Delete and re-download
- Check internet connection
- Verify checksums if available

## Why OrbStack for macOS?

**OrbStack is the recommended container runtime for macOS** because:

- **No gVisor bugs**: Unlike Docker Desktop 4.52.0+, OrbStack doesn't use gVisor for networking, avoiding the critical bugs that crash when processing large forensic images
- **2-3x faster**: Native file sharing and optimized virtualization make forensic processing significantly faster
- **4GB RAM vs 12GB**: OrbStack uses ~4GB RAM compared to Docker Desktop's 8-12GB, leaving more memory for analysis
- **Instant startup**: OrbStack starts in seconds, Docker Desktop takes 30-60 seconds
- **Better file sharing**: Native macOS file sharing instead of VirtioFS (which is slow and buggy in 4.52.0+)
- **Same Docker Engine**: v28.5.2 (stable), same as Docker Desktop 4.51.0
- **Free for personal use**: Perfect for security researchers and students

**Real-world testing with Rowanholt:**
- Processing 11GB E01 image on Docker Desktop 4.56.0: **CRASH** (gVisor bug)
- Processing same image on OrbStack: **SUCCESS** in 60% of the time

## Why Docker Desktop 4.51.0?

If you can't use OrbStack (Windows/Linux or commercial use), Docker Desktop 4.51.0 is recommended because:
- Docker Engine v28.5.2 (stable, mature)
- **No gVisor networking bugs** (unlike 4.52.0+)
- Latest version before Docker Engine v29.0.0
- Released November 13, 2025 (still downloadable)
- Proven stable for Rowanholt's workloads

**⚠️ CRITICAL: Avoid Docker Desktop 4.52.0+**

Docker Desktop 4.52.0 and newer include Docker Engine v29.x which has a **critical gVisor networking bug on macOS** that causes crashes when:
- Accessing large files via VirtioFS (like Rowanholt's 11GB E01 images)
- Long-running HTTP connections (forensic processing)
- Heavy I/O operations

**Error message you'll see:**
```
com.docker.virtualization: process terminated unexpectedly: use of closed network connection
```

**Solution:** Use OrbStack (recommended) or downgrade to Docker Desktop 4.51.0.

## Manual Installation

If the installer doesn't work, you can manually download and install:

### OrbStack (macOS - RECOMMENDED):

**Via Homebrew (easiest):**
```bash
brew install --cask orbstack
```

**Direct download:**
https://orbstack.dev/download

**After installation:**
```bash
# Switch Docker context to OrbStack
docker context use orbstack

# Verify
docker version  # Should show Engine v28.5.2
```

### Docker Desktop 4.51.0:

**macOS Apple Silicon:**
https://desktop.docker.com/mac/main/arm64/210443/Docker.dmg

**macOS Intel:**
https://desktop.docker.com/mac/main/amd64/210443/Docker.dmg

**Linux (Ubuntu/Debian):**
https://desktop.docker.com/linux/main/amd64/210443/docker-desktop-4.51.0-amd64.deb

**Linux (Fedora/RHEL):**
https://desktop.docker.com/linux/main/amd64/210443/docker-desktop-4.51.0-x86_64.rpm

**Windows:**
https://desktop.docker.com/win/main/amd64/210443/Docker%20Desktop%20Installer.exe

## Contributing

If you encounter issues or want to add support for more platforms:
1. Open an issue: https://github.com/cmdaltr/rowanholt/issues
2. Submit a pull request with fixes
3. Test on your platform and report results

## License

This installer is part of the Rowanholt project.
