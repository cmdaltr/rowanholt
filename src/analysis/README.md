# Ledger - Digital Forensics Automation Tool

[![Version](https://img.shields.io/badge/version-2.1.0-blue.svg)](https://github.com/cmdaltr/elrond)
[![Python](https://img.shields.io/badge/python-3.10+-green.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/license-Elastic--2.0-orange.svg)](LICENSE)

**Ledger** is a comprehensive digital forensics automation tool designed to streamline the analysis of disk images, memory dumps, and digital evidence.

Ledger is the analysis module's display name; its code name, Elrond, stays in paths, identifiers and flags (`elrond.py`). The other modules:

| Display name | Code name | Where the code lives |
|---|---|---|
| Custodian (acquisition) | Gandalf | `src/acquisition/`: `bash/gandalf.sh`, `python/gandalf.py`, `windows/Invoke-Gandalf.ps1`; web page `/gandalf` |
| Ledger (analysis) | Elrond | `src/analysis/elrond.py`, `src/analysis/rowanholt/`; web page `/elrond` |
| Smith (AI analyst) | Smith | `src/analysis/rowanholt/ai/`, `src/web/backend/ai_routes.py`, `src/smith_mcp/` |
| Lookout (threat intelligence) | Pippin | `src/analysis/rowanholt/threat_intel/`, `src/web/backend/threat_intel_routes.py`; web page `/pippin` (`ThreatIntel.js`) |
| Steward (administration) | Aragorn | web page `/aragorn` (`Aragorn.js`), `src/web/backend/lab_routes.py` |
| Quartermaster (Docker manager) | Andúril | `src/common/anduril/`, `src/cli/anduril_cli.py`, `src/web/backend/anduril_routes.py`; `rowanholt quartermaster` (or `anduril`) |
| Crucible (lab and recorded attack telemetry) | Mordor | `src/mordor/`, `src/web/backend/mordor_routes.py`, `lab/`; web page `/mordor` |

## 🎯 Features

### Core Capabilities
- ✅ **Automated Forensic Analysis**: Full-stack automation for disk and memory forensics
- ✅ **Multi-Platform Support**: Linux, macOS, and Windows analysis capabilities
- ✅ **Web Interface**: Modern React-based UI for job management and monitoring
- ✅ **CLI Interface**: Powerful command-line interface for advanced users
- ✅ **Docker Support**: Fully containerized deployment option
- ✅ **Distributed Processing**: Celery-based background task execution

### Forensic Tools Integration
- **Disk Imaging**: E01, RAW, DD, VMDK, VHD/VHDX support
- **Memory Analysis**: Volatility 3 integration
- **Timeline Analysis**: Plaso (log2timeline) integration
- **Registry Analysis**: Windows registry parsing and analysis
- **Event Log Analysis**: EVTX parsing and correlation
- **File System Analysis**: MFT, USN Journal, $I30 index analysis
- **Artifact Extraction**: Browser history, prefetch, shimcache, SRUM, and more

### Analysis Features
- 📊 **Timeline Generation**: Comprehensive timeline analysis with Plaso
- 🧠 **Memory Forensics**: Full Volatility 3 plugin suite
- 🔍 **IOC Detection**: YARA rules and keyword searching
- 🗂️ **Artifact Collection**: Automated collection of key forensic artifacts
- 📈 **MITRE ATT&CK Mapping**: Comprehensive content-based technique detection (about 320 techniques, Enterprise and Mobile, at ATT&CK v20.1), multi-tactic support, and ATT&CK Navigator layers per domain
- 🔐 **Malware Detection**: ClamAV integration for malware scanning
- 📤 **SIEM Export**: Direct export to Splunk and Elastic

## 📁 Project Structure

```
elrond/
├── cli.py                   # Command-line interface
├── elrond.py               # Main forensics engine entry point
├── Dockerfile              # Docker image for forensics engine
├── .env.example            # Environment variable template
├── .dockerignore           # Docker build exclusions
├── nginx.conf              # Nginx configuration for production
│
├── docs/                   # 📚 Documentation
│   ├── CONFIG.md          # Configuration guide
│   ├── DOCKER.md          # Docker deployment guide (detailed)
│   ├── DOCKER-QUICKSTART.md # Docker quick start
│   ├── SUPPORT.md         # Support and troubleshooting
│   ├── TESTING.md         # Testing guide
│   └── VIRTUALMACHINE.md  # VM setup guide
│
├── docker/                 # 🐳 Docker Configuration
│   ├── docker-compose.yml      # Development stack
│   └── docker-compose.prod.yml # Production stack
│
├── scripts/                # 🔧 Shell Scripts
│   ├── config.sh          # Configuration script
│   ├── elrond.sh          # Ledger wrapper script
│   └── docker-start.sh    # Docker startup manager
│
├── core/                   # 🎯 Core Engine
│   ├── engine.py          # Main forensics engine
│   ├── executor.py        # Task executor
│   └── __init__.py
│
├── platform/               # 💻 Platform Adapters
│   ├── base.py            # Base platform interface
│   ├── factory.py         # Platform factory
│   ├── linux.py           # Linux adapter
│   ├── macos.py           # macOS adapter
│   └── windows.py         # Windows adapter
│
├── tools/                  # 🛠️ Tool Management
│   ├── definitions.py     # Forensic tool definitions
│   ├── manager.py         # Tool manager
│   ├── installer.py       # Tool installer
│   └── siem_installer.py  # SIEM setup
│
├── utils/                  # 🔨 Utilities
│   ├── helpers.py         # Helper functions
│   ├── logging.py         # Logging configuration
│   ├── validators.py      # Input validators
│   └── constants.py       # Constants and enums
│
├── config/                 # ⚙️ Configuration
│   ├── settings.py        # Application settings
│   └── __init__.py
│
├── rowanholt/             # 🏰 Forensic Modules (Legacy)
│   ├── main.py            # Main orchestrator
│   ├── collect/           # Artifact collection
│   ├── process/           # Artifact processing
│   ├── analysis/          # Analysis modules
│   ├── memory/            # Memory forensics
│   └── post/              # Post-processing
│
├── web/                    # 🌐 Web Application
│   ├── backend/           # FastAPI backend
│   │   ├── main.py        # API server
│   │   ├── models/        # Data models
│   │   ├── storage.py     # Job storage
│   │   ├── tasks.py       # Celery tasks
│   │   ├── config.py      # Backend config
│   │   ├── Dockerfile     # Backend container
│   │   └── requirements.txt
│   │
│   └── frontend/          # React frontend
│       ├── src/           # Source code
│       ├── public/        # Static files
│       ├── Dockerfile     # Frontend container
│       └── package.json
│
└── tests/                  # 🧪 Test Suite
    ├── conftest.py        # Test fixtures
    ├── pytest.ini         # Pytest config
    ├── requirements.txt   # Test dependencies
    ├── unit/              # Unit tests
    └── integration/       # Integration tests
```

## 🚀 Quick Start

### Option 1: Docker (Recommended)

Ledger runs inside Rowanholt's stack, as the Celery worker behind the web UI. From the repository root:

```bash
rowanholt start --testing      # or ./rowanholt start --testing
```

- **Web Interface**: http://localhost:5687
- **API Documentation**: http://localhost:5688/docs
- **API Health**: http://localhost:5688/api/health

See [docs/QUICKSTART.md](../../docs/QUICKSTART.md).

### Option 2: Native Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Check dependencies
python cli.py --check-dependencies

# Install forensic tools
python cli.py --install

# Run analysis
python elrond.py CASE-001 /path/to/image.E01 /output --Collect --Process --quick
```

## 📖 Usage

### Web Interface

1. Navigate to http://localhost:5687
2. Click **"New Analysis"**
3. Select disk image from file browser
4. Configure analysis options
5. Start analysis and monitor progress

### Command Line Interface

```bash
# Basic usage
python elrond.py <CASE_ID> <SOURCE_PATH> [DESTINATION] [OPTIONS]

# Examples:

# Quick analysis
python elrond.py INC-2025-001 /evidence/disk.E01 /output \
  --Collect --Process --quick --Userprofiles

# Comprehensive analysis
python elrond.py INC-2025-001 /evidence/disk.E01 /output \
  --eXhaustive --Collect

# Memory analysis
python elrond.py MEM-2025-001 /evidence/memory.mem /output \
  --Memory --memorytimeline

# With SIEM export
python elrond.py INC-2025-001 /evidence/disk.E01 /output \
  --Collect --Process --Splunk --Navigator
```

### Common Options

**Evidence Sources:**
- `-C, --Collect`: Local disk/memory images
- `-G, --Custodian` (or `--Gandalf`): Custodian acquisition archives
- `--Crucible` (or `--Mordor`): OTRF Mordor datasets

**Processing Modes:**
- `-B, --Brisk`: Balanced speed/thoroughness (recommended)
- `-X, --eXhaustive`: Comprehensive analysis (all flags)
- `-q, --quick`: Quick mode (skip hashing/entropy)

**Other Options:**
- `-P, --Process`: Processing phase (always enabled, flag optional)
- `-A, --Analysis`: Conduct automated forensic analysis
- `-M, --Memory`: Analyze memory dumps with Volatility
- `-T, --Timeline`: Create timeline with Plaso
- `-U, --Userprofiles`: Collect user profile artifacts
- `-S, --Splunk`: Export to Splunk
- `-E, --Elastic`: Export to Elasticsearch

### Non-Interactive Mode (Web/Automation)

**Ledger runs in non-interactive mode by default** when used in Docker or web environments. This provides:

- ✅ Clean output without ANSI colors or ASCII art
- ✅ No interactive prompts (uses safe defaults)
- ✅ Perfect for web job logs and automation

The `ELROND_NONINTERACTIVE=1` environment variable is automatically set in Docker. To use interactive CLI mode:

```bash
export ELROND_NONINTERACTIVE=0
python elrond.py CASE-001 /evidence/disk.E01 /output --Collect
```

## 🐳 Docker Usage

Rowanholt's `docker-compose.yml` at the repository root runs Ledger; use `rowanholt start | stop | restart | status` ([docs/CLI.md](../../docs/CLI.md#the-rowanholt-command)). The compose files and `docs/DOCKER*.md` here describe the earlier standalone Ledger stack (ports 3000 and 8000) and are kept for reference only.

## 🧪 Testing

Ledger includes comprehensive test suites for both Python and web components.

### Python Tests

```bash
cd tests

# Install test dependencies
pip install -r requirements.txt

# Run all tests
pytest

# Run with coverage
pytest --cov=elrond --cov-report=html

# Or use the test runner
./run_tests.sh --all --coverage
```

### Web Tests

```bash
cd web/tests

# Install dependencies
npm install
npx playwright install --with-deps

# Run all tests
npm test

# Run with UI
npm run test:ui
```

See [docs/TESTING.md](docs/TESTING.md) for detailed testing documentation.

## 📚 Documentation

Comprehensive documentation is available in the `docs/` directory:

- **[CONFIG.md](docs/CONFIG.md)** - Configuration and setup guide
- **[DOCKER.md](docs/DOCKER.md)** - Complete Docker deployment guide
- **[DOCKER-QUICKSTART.md](docs/DOCKER-QUICKSTART.md)** - Quick Docker setup
- **[TESTING.md](docs/TESTING.md)** - Testing guide and best practices
- **[SUPPORT.md](docs/SUPPORT.md)** - Support and troubleshooting
- **[VIRTUALMACHINE.md](docs/VIRTUALMACHINE.md)** - VM setup instructions

## 🔧 Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
# Security
SECRET_KEY=your-secret-key-here
REDIS_PASSWORD=your-redis-password

# Debug mode
DEBUG=false

# Analysis settings
MAX_CONCURRENT_ANALYSES=3
ANALYSIS_TIMEOUT=86400

# Storage
ALLOWED_PATHS=/evidence,/mnt,/media
```

### Tool Installation

```bash
# Check tool availability
python cli.py --check-dependencies

# Interactive installation
python cli.py --install --interactive

# Install required tools only
python cli.py --install --required-only
```

## 🛠️ Development

### Setting Up Development Environment

```bash
# Clone repository
git clone https://github.com/cmdaltr/elrond.git
cd elrond

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
pip install -r tests/requirements.txt

# Install pre-commit hooks (optional)
pre-commit install
```

### Running Tests

```bash
# Python tests
cd tests && pytest

# Web backend tests
cd web/backend && pytest

# Web frontend tests
cd web/frontend && npm test

# Integration tests
cd tests && pytest -m integration
```

### Code Style

```bash
# Format code
black .
isort .

# Lint code
flake8 .
pylint elrond/

# Type checking
mypy elrond/
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure:
- All tests pass
- Code follows style guidelines
- Documentation is updated
- Commit messages are descriptive

## 🔒 Security

Ledger is designed for defensive security and forensic analysis only. Please:
- Do not use for malicious purposes
- Report security vulnerabilities responsibly
- Follow ethical forensic practices
- Respect privacy and legal requirements

## 📄 License

This project is licensed under the Elastic License 2.0 - see the [LICENSE](../../LICENSE) file for details. Releases published before it keep the MIT License.

## 🙏 Acknowledgments

- **Volatility Foundation** - Memory forensics framework
- **Plaso Project** - Timeline analysis tool
- **The Sleuth Kit** - File system analysis
- **FastAPI** - Modern web framework
- **React** - Frontend framework

## 📞 Support

For issues, questions, or contributions:

- **GitHub Issues**: [Report a bug](https://github.com/cmdaltr/elrond/issues)
- **Documentation**: See [docs/SUPPORT.md](docs/SUPPORT.md)
- **Discussions**: [GitHub Discussions](https://github.com/cmdaltr/elrond/discussions)

## 🗺️ Roadmap

### v2.2.0 (Planned)
- [ ] Cloud storage support (AWS S3, Azure Blob)
- [ ] Distributed analysis across multiple nodes
- [ ] Advanced machine learning for anomaly detection
- [ ] Mobile device forensics support
- [ ] Encrypted disk image support

### v2.3.0 (Planned)
- [ ] Real-time analysis streaming
- [ ] Collaborative investigation features
- [ ] Advanced reporting engine
- [ ] Plugin system for custom analyzers

## 📊 Project Stats

- **Lines of Code**: ~50,000+
- **Tests**: 290+ test cases
- **Test Coverage**: ~85%
- **Supported Platforms**: Linux, macOS, Windows
- **Docker Images**: 3 (engine, backend, frontend)
- **Documentation Pages**: 6

---

**Made with ⚔️ by forensic investigators, for forensic investigators**
