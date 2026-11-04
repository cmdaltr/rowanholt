# Rowanholt Quick Start Guide

Get up and running with Rowanholt DF Acceleration Suite in minutes!

## 🚀 Quick Start (Docker - Recommended)

```bash
# Clone the repository
git clone https://github.com/cmdaltr/rowanholt.git
cd rowanholt

# Start core services (postgres, redis, backend, celery-worker, frontend)
docker compose up -d

# Access web interface
open http://localhost:5687

# Access API documentation
open http://localhost:5688/docs

# Check status
docker compose ps

# View logs
docker compose logs -f backend
```

**That's it!** The web interface is available at http://localhost:5687 and the API at http://localhost:5688 (or http://rowanholt.lab if using FlightDeck with the local proxy).

SIEM services (Splunk, Elasticsearch, Kibana, ATT&CK Navigator) are optional and gated behind the `siem` profile. Start them separately once the core stack is healthy:

```bash
docker compose --profile siem up -d
```

Analysis jobs that request Splunk or Elastic export (`-S`/`-E`, `"splunk": true`, Threat Hunt or Exhaustive mode) fail immediately if the SIEM stack isn't running, rather than completing with nothing exported.

Stop only the SIEM stack without touching the core services:

```bash
docker compose stop splunk elastic elastic-setup kibana kibana-setup navigator
```

If you use [FlightDeck](https://github.com/cmdaltr/FlightDeck) to manage your homelab, the equivalent commands are `fd start rowanholt` and `fd start rowanholt-siem`.

## 🔧 Quick Start (Local Installation)

Docker is the supported way to run the web stack: the worker image carries every forensic tool. A local install suits CLI use of Elrond and Gandalf.

### 1. Install Dependencies

```bash
git clone https://github.com/cmdaltr/rowanholt.git
cd rowanholt

python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

pip install -e .                 # base
pip install -e ".[web]"          # web backend
pip install -r requirements/siem.txt
```

The forensic tools themselves (Sleuth Kit, libewf, Volatility 3, Plaso, YARA and others) are listed in [CONFIG.md](CONFIG.md).

### 2. Start the Web Backend

The backend needs Postgres and Redis. Point it at them with `DATABASE_URL` and the Redis settings in `src/web/backend/config.py`, then:

```bash
cd src/web/backend
uvicorn main:app --host 0.0.0.0 --port 5688 --reload
```

Jobs also need a Celery worker running `celery -A tasks_docker.celery_app worker --concurrency=1` with the forensic tools installed.

## 📥 Acquire Evidence

Run Gandalf from `src/acquisition/`; it opens `lists/` and `tools/` relative to the current directory.

### Local Acquisition (Linux/macOS)

```bash
cd src/acquisition

# Key-encrypted (recommended)
sudo python3 python/gandalf.py Key Local -O /evidence

# With a memory dump
sudo python3 python/gandalf.py Password Local -M -O /evidence

# Bash version
sudo bash bash/gandalf.sh Password Local -m -o /evidence
```

### Remote Acquisition

The Python version reads hosts from `lists/hosts.list` and prompts for each host's address and credentials:

```bash
cd src/acquisition
printf '192.168.1.100\n192.168.1.101\n' > lists/hosts.list
sudo python3 python/gandalf.py Password Remote -M -O /evidence
```

The Bash version takes the host on the command line:

```bash
sudo bash src/acquisition/bash/gandalf.sh Key Remote -h 192.168.1.100 -u analyst -m
```

### Windows Acquisition

```powershell
# PowerShell as Administrator
cd src\acquisition\windows
.\Invoke-Gandalf.ps1 -EncryptionObject Key -Acquisition Local -OutputDirectory D:\evidence -Memory
```

Each acquisition produces `<host>.zip` (or `<host>.zip.enc` when encrypted).

## 📁 Analysis Files (Keywords, YARA & IOC Watchlists)

Keyword search, YARA scanning and IOC watchlist matching read their input from `fixtures/`, which Docker mounts read-only into the worker at `/tmp/rowanholt/fixtures/`:

```
fixtures/
├── keywords.txt     # one keyword per line
├── iocs.txt         # IOC watchlist (IPs, domains, hashes)
└── yara_rules/      # .yar / .yara files
```

Keep blank and `#` lines out of `keywords.txt`: Elrond treats them as keywords and matches every line. Lines starting `#` in `iocs.txt` are comments.

When creating jobs, use these paths:

- Keywords: `/tmp/rowanholt/fixtures/keywords.txt`
- YARA: `/tmp/rowanholt/fixtures/yara_rules/`
- IOCs: `/tmp/rowanholt/fixtures/iocs.txt`

## 🔍 Analyze Evidence

Elrond takes long options only (`--Brisk`, not `-B`) and reads every image in the source directory. See [CLI.md](CLI.md#elrond---analysis) for all options and [PERFORMANCE.md](PERFORMANCE.md) for what each one costs.

### Quick Analysis

```bash
# Collect, process and analyse a disk image directory
python3 src/analysis/elrond.py CASE-001 /evidence /output/CASE-001 --Collect --Process --Analysis

# Brisk mode (adds IOC extraction, Navigator and user profiles, so not faster)
python3 src/analysis/elrond.py CASE-001 /evidence /output/CASE-001 --Collect --Brisk

# A Gandalf acquisition
python3 src/analysis/elrond.py CASE-001 /evidence /output/CASE-001 --Gandalf --Process --Analysis
```

### With SIEM Export

```bash
docker compose --profile siem up -d

python3 src/analysis/elrond.py CASE-001 /evidence /output/CASE-001 --Collect --Process --Analysis --Splunk
python3 src/analysis/elrond.py CASE-001 /evidence /output/CASE-001 --Collect --Process --Analysis --Elastic
python3 src/analysis/elrond.py CASE-001 /evidence /output/CASE-001 --Collect --Process --Analysis --Splunk --Elastic --Navigator
```

### Memory Analysis

```bash
# Memory image in /evidence/memory
python3 src/analysis/elrond.py MEM-001 /evidence/memory /output/MEM-001 --Collect --Process --Memory
```

## 🌐 Using the Web Interface

### Starting Jobs via API

```bash
# Create an analysis job
curl -X POST http://localhost:5688/api/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "case_number": "CASE-001",
    "source_paths": ["/Volumes/Evidence/disk.E01"],
    "destination_path": "/Volumes/Evidence/output/CASE-001",
    "options": {"analysis": true, "splunk": true, "elastic": true}
  }'

# Check job status
curl http://localhost:5688/api/jobs/JOB-ID

# List all jobs
curl http://localhost:5688/api/jobs
```

Every option is listed under Create Job in [API.md](API.md#create-job). Acquisition is CLI-only; the API runs analysis jobs.

### Using the Web UI

1. Open `http://localhost:5687`
2. Click **"New Analysis"**
3. Enter the case number, choose the image(s) and an output directory
4. Select options (Analysis, Splunk, Elastic, Navigator…)
5. Click **"Start Analysis"**
6. Follow progress in **"Job List"** and results in **"Job Details"**

## 🔐 SIEM Setup

The `siem` Compose profile runs Splunk, Elasticsearch, Kibana and ATT&CK Navigator already wired to the worker:

```bash
docker compose --profile siem up -d
```

| Service | URL |
|---|---|
| Splunk web | http://localhost:7755 |
| Kibana | http://localhost:5601 |
| Navigator | http://localhost:5602 |

Splunk runs under Rosetta on Apple silicon and needs several minutes to start. Give Docker at least 16 GB of memory with the profile up.

To use an existing Splunk or Elasticsearch instead, set these on the worker:

| Variable | Default in Compose |
|---|---|
| `SPLUNK_HOST`, `SPLUNK_PORT`, `SPLUNK_USERNAME`, `SPLUNK_PASSWORD` | `splunk`, 8089 (management API) |
| `ELASTICSEARCH_HOST`, `ELASTICSEARCH_PORT`, `ELASTIC_USERNAME`, `ELASTIC_PASSWORD` | `elastic`, 9200 |

## 📊 Common Workflows

### Workflow 1: Quick Triage

```bash
cd src/acquisition && sudo python3 python/gandalf.py None Local -O /evidence/TRIAGE-001 && cd -
python3 src/analysis/elrond.py TRIAGE-001 /evidence/TRIAGE-001 /output/TRIAGE-001 --Gandalf --Process --Analysis
cat /output/TRIAGE-001/*/analysis/analysis.csv
```

### Workflow 2: Full Investigation with SIEM

```bash
cd src/acquisition && sudo python3 python/gandalf.py Password Remote -M -O /evidence/CASE-001 && cd -
python3 src/analysis/elrond.py CASE-001 /evidence/CASE-001 /output/CASE-001 \
  --Gandalf --Process --Analysis --extractIocs --Memory --Splunk --Navigator
# Splunk: http://localhost:7755/en-US/app/elrond/
```

### Workflow 3: Memory Analysis

```bash
cd src/acquisition && sudo python3 python/gandalf.py None Local -M -O /evidence/MEM-001 && cd -
python3 src/analysis/elrond.py MEM-001 /evidence/MEM-001 /output/MEM-001 --Gandalf --Process --Memory
ls /output/MEM-001/*/   # one JSON file per Volatility 3 plugin
```

### Workflow 4: Several Hosts

Acquire them all with one `Remote` run (Workflow 2), then analyse each archive as its own case, one at a time. Parallel runs share mount points and unmount each other's images.

```bash
for dir in /evidence/hosts/*/; do
  host=$(basename "$dir")
  python3 src/analysis/elrond.py "CASE-${host}" "$dir" "/output/CASE-${host}" --Gandalf --Process --Analysis
done
```

## 🐛 Troubleshooting

### Docker Issues

```bash
docker compose ps
docker compose logs -f backend celery-worker
docker compose restart backend celery-worker
docker compose build --no-cache celery-worker
```

`docker compose down -v` also deletes the Postgres volume and with it every job record.

### Permission Issues (Acquisition)

Gandalf needs root (`sudo`) to read system artefacts and memory. Make the scripts executable with `chmod +x src/acquisition/bash/gandalf.sh src/acquisition/python/gandalf.py`.

### Import Errors (Analysis)

Run Python modules from the repository root, never from inside `src/analysis` (see [CLI.md](CLI.md)). `src/analysis/cli.py --check-dependencies` is currently broken (it imports a package that no longer exists); use the Docker worker or check tools against [CONFIG.md](CONFIG.md).

### Web Interface Not Loading

```bash
curl http://localhost:5688/api/health
docker compose logs backend
lsof -iTCP:5687 -iTCP:5688 -sTCP:LISTEN
```

## 📚 Next Steps

- **Full documentation**: [README.md](../README.md)
- **CLI reference**: [CLI.md](CLI.md)
- **API reference**: [API.md](API.md)
- **Configuration**: [CONFIG.md](CONFIG.md)
- **Processing times**: [PERFORMANCE.md](PERFORMANCE.md)

## 🎯 Example Outputs

### Acquisition Output
```
/evidence/
└── <host>.zip            # <host>.zip.enc when encrypted
    ├── artefacts/
    │   ├── host.info
    │   └── <host>.mem    # with -M
    ├── log.audit         # SHA-256 per file
    └── log.meta
```

### Analysis Output
```
/output/CASE-001/
├── rowanholt_audit.log
├── mitre_techniques.txt
└── <image>/
    ├── artefacts/
    │   ├── raw/          # collected files
    │   └── cooked/       # parsed artefacts (JSON/CSV)
    └── analysis/         # analysis.csv, iocs.csv, keyword_matches.csv, yara.csv
```

## 💡 Pro Tips

1. **Use Docker** - the worker image has every tool installed
2. **Enable memory acquisition** for a fuller picture
3. **Size the job first** - [PERFORMANCE.md](PERFORMANCE.md) has per-option times; `--Timeline`, `--vss`, `--extractIocs` and carving take hours
4. **Run one job at a time** on the web stack (worker concurrency 1)
5. **Use key-based encryption** for sensitive cases
6. **Monitor disk space** - carving alone can produce tens of thousands of files
7. **Review `log.audit`** after each acquisition

---

**Need Help?** Check the [full documentation](../README.md) or open an [issue](https://github.com/cmdaltr/rowanholt/issues).

Happy Investigating! 🔍🧙‍♂️
