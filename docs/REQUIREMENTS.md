# Installation Requirements

## 🛠️ System Requirements

These figures are the same everywhere they're quoted (README.md, INSTALL.md, desktop/README.md) and are the ones the launchers check.

| | Minimum | Recommended |
|---|---|---|
| **Memory** | 16 GB | 32 GB, and for the SIEM profile |
| **Processor** | 4 cores, with hardware virtualisation on (Windows and macOS run Docker in a VM) | 8 cores or more |
| **Free disk space** | 60 GB on the drive that holds Docker's data, on an SSD | 200 GB or more on an SSD, plus room for evidence and cases |
| **OS** | Windows 10 or 11 (64-bit) with WSL 2, macOS 12+, Ubuntu 20.04+ | Latest versions |

**Memory.** The core stack's containers are capped at about 10 GB between them, most of it the worker's 8 GB for Volatility and Plaso. Docker Desktop on Windows gives its Linux VM half the PC's memory by default, and the OS, the browser and Ollama with Smith's model (about 3 GB) need the rest. On 8 GB, a Windows PC hung while Docker unpacked the images. The SIEM profile (Splunk, Elastic, Kibana, the Navigator) adds 8 GB or more: give Docker 16 GB with it up, so 32 GB on the machine. Large memory images want 32 GB whatever the profile.

**Disk.** A first start builds three images (about 3.5 GB) and BuildKit's cache beside them, which together took Docker's data disk to 20 GB on Windows. Docker Desktop and WSL take a few GB more, and Smith's model 2 GB. Each case's output, timelines and CSVs included, comes on top, on the drive its output folder is on.

**What the launchers check.** `rowanholt start`, the desktop apps' starts and the Windows app's What Rowanholt needs page check the machine (`src/common/resources.py`; the Windows launcher holds the same numbers). They stop under 8 GB of memory, or under 30 GB free where Docker keeps its data when there are images to build (a first start, or the rebuild after an update), and warn under the minimums above. `ROWANHOLT_SKIP_CHECKS=1` turns the stops into warnings.

A team server needs the same as a desktop for a handful of analysts; give it 32 GB and 8 cores when several jobs run at once ([SERVER.md](SERVER.md)).

---

## 📦 Dependencies

### Core Tools

**Required:**
- Python 3.10+
- pip (Python package manager)
- Git
- SQLite 3
- libffi-dev / libffi-devel
- python3-dev / python3-devel

**Forensic Tools:**
- Volatility 3 (memory forensics)
- Plaso/log2timeline (timeline generation)
- Artemis (artefact parsing)
- YARA (signature scanning)
- TSK (The Sleuth Kit) - file system analysis
- libewf (E01 image support)

### Platform-Specific Dependencies

<div align="left">
  <table>
    <tr>
      <td><img src="./docs/images/readme/linux.png" alt="Linux" width="42"/></td>
      <td><strong>Linux (Ubuntu/Debian)</strong></td>
    </tr>
    <tr>
      <td colspan="2">
        <pre>
sudo apt-get update
sudo apt-get install -y \
  python3 python3-pip python3-dev \
  build-essential git sqlite3 \
  libffi-dev libssl-dev \
  libbz2-dev libreadline-dev \
  libsqlite3-dev wget curl \
  llvm libncurses5-dev \
  xz-utils tk-dev libxml2-dev \
  libxmlsec1-dev liblzma-dev
        </pre>
      </td>
    </tr>
    <tr>
      <td><img src="./docs/images/readme/apple.png" alt="macOS" width="42"/></td>
      <td><strong>macOS</strong></td>
    </tr>
    <tr>
      <td colspan="2">
        <pre>
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python@3.11 git sqlite3
brew install libffi openssl readline
        </pre>
      </td>
    </tr>
    <tr>
      <td><img src="./docs/images/readme/microsoft.png" alt="Windows" width="42"/></td>
      <td><strong>Windows (WSL2)</strong></td>
    </tr>
    <tr>
      <td colspan="2">
        <pre>
# Install WSL2 (PowerShell as Administrator)
wsl --install -d Ubuntu-22.04

# Inside WSL2, run Linux installation commands above
        </pre>
      </td>
    </tr>
  </table>
</div>

---

## 🔧 Integrated Forensic Tools

### Memory Forensics
- **Volatility 3** - Advanced memory forensics framework
- **Rekall** - Memory analysis framework (optional)

### Timeline Generation
- **Plaso/log2timeline** - Super timeline generation
- **log2timeline** - Event log parsing

### Registry Analysis (Windows)
- **RegRipper** - Registry parsing and analysis
- **Registry Explorer** - Registry viewer

### Event Log Analysis (Windows)
- **Artemis** - Comprehensive Rust-based forensic parser (fast)

### Phones (`--Mobile`)
- **iLEAPP** v2026.4.6 - iOS backups (encrypted too) and file system extractions
- **ALEAPP** v2026.4.5 - Android file system extractions, bug reports, and ADB backups (laid out by Elrond)

Both are in the worker image (`src/web/backend/Dockerfile.forensics`, step 4h), each cloned at its release tag into `/opt/<tool>/src` with its own Python 3.12 virtualenv (`/opt/<tool>/venv`, from the deadsnakes PPA: they need 3.11+), so their pinned dependencies stay out of Elrond's Python. Elrond runs them as `/usr/local/bin/ileapp` and `aleapp` (`src/analysis/tools/definitions.py`). Outside the image, install them the same way and put launchers of those names on the `PATH`.

### File System Analysis
- **The Sleuth Kit (TSK)** - File system analysis tools
- **libewf** - Expert Witness Format support (E01 images)
- **libvmdk** - VMware VMDK support
- **libvhdi** - VHD/VHDX support

### IOC Extraction
IOCs (IPs, domains, URLs, emails, hashes) are extracted by Elrond itself from the cooked artefacts; no external tool is needed.

### Artifact Parsers
- **python-registry** - Windows Registry parser
- **pytsk3** - Python bindings for TSK
- **dfvfs** - Virtual file system library (used by Plaso)

Browser history (Chromium-based browsers, Firefox and Safari) is collected by Elrond and parsed by Artemis.

### Malware Analysis
- **YARA** - Signature scanning
- **ClamAV** - Antivirus engine (optional)

---

## 🐳 Optional Dependencies

### Docker Deployment
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo apt-get install docker-compose-plugin
```

### Smith (AI analyst)
```bash
# Install Ollama for local LLM
curl -fsSL https://ollama.com/install.sh | sh

# Pull the default model (ROWANHOLT_MODEL_NAME); see SMITH.md for the smith-* models
ollama pull llama3.2:3b
```

### SIEM Integration

**Splunk:**
- Splunk Enterprise or Cloud instance
- HTTP Event Collector (HEC) token

**Elasticsearch:**
- Elasticsearch 7.x or 8.x
- Logstash (optional)
- Kibana (optional)

---

## 📚 Python Package Requirements

### Core Packages
```
volatility3>=2.5.0
plaso>=20230623
python-registry>=1.3.1
pytsk3>=20230125
dfvfs>=20230418
dfwinreg>=20230318
yara-python>=4.3.1
pefile>=2023.2.7
oletools>=0.60.1
```

### Analysis Packages
```
pandas>=2.0.0
numpy>=1.24.0
matplotlib>=3.7.0
networkx>=3.1
```

### AI/LLM Packages
```
langchain>=0.1.0
chromadb>=0.4.0
sentence-transformers>=2.2.0
```

### Cloud Forensics
```
boto3>=1.26.0  # AWS
azure-mgmt-compute>=30.0.0  # Azure
google-cloud-compute>=1.14.0  # GCP
```

### Web Interface
```
fastapi>=0.104.0
uvicorn>=0.24.0
celery>=5.3.0
redis>=5.0.0
```

### Utility Packages
```
requests>=2.31.0
rich>=13.5.0
typer>=0.9.0
tqdm>=4.66.0
pyyaml>=6.0
python-magic>=0.4.27
```

---

## 🚀 Installation Methods

### Method 1: Automated Installation (Recommended)

<div align="left">
  <table>
    <tr>
      <td><img src="./docs/images/readme/linux.png" alt="Linux" width="42"/></td>
      <td><code>sudo ./scripts/install_linux.sh</code></td>
    </tr>
    <tr>
      <td><img src="./docs/images/readme/apple.png" alt="macOS" width="42"/></td>
      <td><code>sudo ./scripts/install_macos.sh</code></td>
    </tr>
    <tr>
      <td><img src="./docs/images/readme/microsoft.png" alt="Windows" width="42"/></td>
      <td><code>.\scripts\install_windows_wsl.ps1</code></td>
    </tr>
  </table>
</div>

### Method 2: Docker Deployment

```bash
# Clone repository
git clone https://github.com/cmdaltr/rowanholt.git
cd rowanholt

# Build and start containers
docker compose up -d

# Access web interface
# http://localhost:5688
```

### Method 3: Manual Installation

```bash
# Clone repository
git clone https://github.com/cmdaltr/rowanholt.git
cd rowanholt

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install forensic tools
./scripts/install_tools.sh

# Verify installation
elrond --check-dependencies
```

---

## ✅ Verification

After installation, verify all components:

```bash
# Check Python version
python3 --version

# Check dependencies
elrond --check-dependencies

# Run test case
./scripts/test_installation.sh
```

Expected output:
```
✓ Python 3.11.x
✓ Volatility 3 installed
✓ Plaso installed
✓ TSK installed
✓ All required tools available
✓ Installation successful
```

---

## 🔧 Troubleshooting

### Common Issues

**Missing Python Headers:**
```bash
# Ubuntu/Debian
sudo apt-get install python3-dev

# macOS
xcode-select --install
```

**Permission Errors:**
```bash
# Add user to required groups
sudo usermod -a -G disk $USER
sudo usermod -a -G sudo $USER

# Re-login for changes to take effect
```

**Volatility Symbol Tables:**
```bash
# Download Windows symbol tables
python3 -m volatility3.plugins.windows.info --download-symbols
```

**Plaso Installation Issues:**
```bash
# Use pip instead of system package
pip install plaso --upgrade
```

---

## 📖 Additional Resources

- **[Installation Guide](../INSTALL.md)** - Detailed installation instructions
- **[Configuration](CONFIG.md)** - Configuration options and tool installation
- **[CLI Reference](CLI.md)** - Every command
- **[Troubleshooting](CLI.md#troubleshooting)** - Common issues and solutions

---

**See:** [README.md](README.md) for quick start guide
