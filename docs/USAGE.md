# Rowanholt Usage Guide

**Version:** 2.1.0
**Quick Reference for Common Tasks**

---

## Quick Links

- **[API.md](API.md)** - Complete REST API reference
- **[CLI.md](CLI.md)** - Command-line interface guide
- **[CONFIG.md](CONFIG.md)** - Configuration and setup
- **[SECURITY.md](SECURITY.md)** - Security features and best practices

---

## Getting Started

### 1. Access the Web Interface

Open your browser to: **http://localhost:5687**

**Default Login:**
- **Email**: admin@rowanholt.app
- **Password**: IWasThere3000YearsAgo!

⚠️ **Change this password immediately in production!**

### 2. Create a Forensic Analysis Job

**Via Web Interface:**
1. Click "New Analysis"
2. Enter case number (e.g., "CASE-2025-001")
3. Browse and select disk/memory images
4. Configure analysis options
5. Click "Start Analysis"

**Via API:**
```bash
curl -X POST http://localhost:5688/api/jobs \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "case_number": "CASE-2025-001",
    "source_paths": ["/evidence/disk.E01"],
    "destination_path": "/output/CASE-2025-001",
    "options": {
      "analysis": true,
      "memory": false
    }
  }'
```

**Via CLI:**
```bash
python3 src/analysis/elrond.py CASE-2025-001 /evidence /output/CASE-2025-001 --Collect --Process --Analysis
```

---

## Common Workflows

### Complete Investigation

**Step 1: Acquire Evidence** (if needed)
```bash
# Remote acquisition (hosts from src/acquisition/lists/hosts.list)
cd src/acquisition
sudo python3 python/gandalf.py Password Remote -M -O /evidence/CASE-001
```

**Step 2: Start Analysis**
- Use web interface or API to create job
- Select disk image and memory dump
- Enable desired analysis options

**Step 3: Monitor Progress**
- View real-time progress in web interface
- Check logs tab for detailed output
- Wait for completion. A basic Windows E01 takes about 15 minutes; `vss`, `timeline`, `extract_iocs` and carving add hours (see [PERFORMANCE.md](PERFORMANCE.md))

**Step 4: Review Results**
- View completed job details
- Download analysis reports
- Export to SIEM if needed

### Quick Triage

For rapid initial analysis:

**CLI:**
```bash
python3 src/analysis/elrond.py TRIAGE-001 /evidence /output/TRIAGE-001 --Collect --Process --Analysis
```

**Web Interface:**
- Enable Analysis only
- Leave Timeline, VSS, IOC extraction and file collection off: they are the slow options
- Brisk mode is not a quick mode; it adds IOC extraction

### Memory-Only Analysis

For memory dump analysis only:

**CLI:**
```bash
# memory image in /evidence/memory
python3 src/analysis/elrond.py MEMORY-001 /evidence/memory /output/MEMORY-001 --Collect --Process --Memory
```

**Web Interface:**
- Create new analysis job
- Select only memory dump file
- Enable memory analysis option

---

## User Management

### Create New User

**Via Web Interface** (Admin only):
1. Navigate to Admin → Users
2. Click "Create User"
3. Fill in details
4. Assign role (Admin/User/Guest)
5. Click "Create"

**Via API:**
```bash
curl -X POST http://localhost:5688/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "analyst@company.com",
    "username": "analyst1",
    "password": "<your-password>",
    "full_name": "Security Analyst"
  }'
```

> MFA, password reset and the admin user screens below depend on `auth/routes.py`, which the backend does not mount in the current build (it uses the simple file-based router). See [API.md](API.md#authentication-status).

### Enable Multi-Factor Authentication (MFA)

**For Your Account:**
1. Click your profile → Security
2. Click "Enable MFA"
3. Scan QR code with authenticator app
4. Enter verification code
5. Save backup codes securely!

**For Other Users (Admin):**
1. Navigate to Admin → Users
2. Select user
3. Click "Reset MFA" to disable (emergency)

### Reset User Password (Admin)

**Via Web Interface:**
1. Navigate to Admin → Users
2. Select user
3. Click "Reset Password"
4. Enter new password
5. Click "Confirm"

**Via API:**
```bash
curl -X POST http://localhost:5688/api/auth/admin/reset-user-password \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user-uuid-here",
    "new_password": "NewSecurePass123!"
  }'
```

---

## Job Management

### List Jobs

**Web Interface:** Dashboard shows all your jobs

**API:**
```bash
# All jobs
curl http://localhost:5688/api/jobs \
  -H "Authorization: Bearer YOUR_TOKEN"

# Filter by status
curl "http://localhost:5688/api/jobs?status=running" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Cancel Running Job

**Web Interface:** Click "Cancel" button on job card

**API:**
```bash
curl -X POST http://localhost:5688/api/jobs/{job_id}/cancel \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**CLI:**
```bash
python3 tests/scripts/run_test.py --cancel {job_id}
```

Cancelling leaves the tool Elrond was running (foremost, yara, Plaso) alive in the worker, still holding the image mount. See [TEST_RUNNER_GUIDE.md](../tests/docs/TEST_RUNNER_GUIDE.md#cleaning-up-after-a-cancel) for clean-up.

A job in `awaiting_confirmation` can only be cancelled with `POST /api/jobs/{job_id}/cancel-sudo`.

### Restart Failed Job

**Web Interface:** Click "Restart" button on failed job

**API:**
```bash
curl -X POST http://localhost:5688/api/jobs/{job_id}/restart \
  -H "Authorization: Bearer YOUR_TOKEN"
```

A job with findings answers 409 with their count: the re-run rewrites the rows they point at, and any that change show "row changed". Add `?confirm=true` to restart anyway.

### Archive Completed Jobs

**Web Interface:** Select jobs → Bulk Actions → Archive

**API:**
```bash
curl -X POST http://localhost:5688/api/jobs/bulk/archive \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '["uuid1", "uuid2"]'
```

### Delete Jobs

**Web Interface:** Select jobs → Bulk Actions → Delete

**API:**
```bash
curl -X DELETE http://localhost:5688/api/jobs/{job_id} \
  -H "Authorization: Bearer YOUR_TOKEN"
```

⚠️ **Cannot delete running jobs** - cancel first, then delete

---

## File System Browsing

### Browse Evidence Directory

**Web Interface:**
- File browser automatically shows allowed directories
- Navigate by clicking folders
- Select files by clicking checkboxes

**Allowed Directories** (`allowed_paths` in `src/web/backend/config.py`, chosen by the OS the backend runs on):
- Docker / Linux: `/Volumes`, `/mnt`, `/media`, `/tmp/rowanholt`, `/host/tmp/rowanholt`
- macOS native: `/Volumes`, `/tmp/rowanholt`
- Windows: `C:\Temp\rowanholt` (and `D:`–`F:`)

### Supported Image Formats

**Disk Images:**
- E01, Ex01 (EnCase)
- DD, RAW, IMG, BIN (Raw)
- VMDK (VMware)
- VHD, VHDX (Hyper-V)

**Memory Dumps:**
- MEM, DMP (Raw memory)
- LIME (LiME format)
- VMEM (VMware snapshot)

---

## Viewing Results

### Access Output Files

Output goes to the job's `destination_path`. Under Docker on macOS, use a path on `/Volumes` (both containers mount it) and the files appear directly on the host. Output under `/host/tmp/rowanholt` in the backend maps to `/tmp/elrond/output` in the worker.

### Output Structure

```
<destination>/
├── rowanholt_audit.log        # CSV, one row per finished piece of work (UTC)
├── mitre_techniques.txt
├── <case>_navigator.json      # if Navigator enabled
└── <image>/
    ├── artefacts/
    │   ├── raw/               # collected files
    │   ├── cooked/            # parsed artefacts: registry/, evt/, browsers/, journal_mft.jsonl …
    │   └── plaso_timeline.jsonl # if Timeline enabled
    ├── analysis/              # analysis.jsonl, iocs.jsonl, keyword_matches.jsonl, yara.jsonl
    └── carved/                # if carving enabled
```

Memory images get one table per Volatility 3 plugin, `memory_<plugin>.jsonl`, under `<destination>/<memory image>/`. Every table is JSON Lines with the same five leading fields (`host`, `artefact`, `source_path`, `timestamp` in UTC, `techniques`); the case browser's **Download as CSV** gives one as a spreadsheet. See `docs/CLI.md` (Output Structure) and `docs/OUTPUT_FORMAT.md`.

### Common Result Files

```bash
cat /output/CASE-001/*/analysis/analysis.jsonl
cat /output/CASE-001/*/analysis/iocs.jsonl
ls  /output/CASE-001/*/artefacts/cooked/registry/
cat /output/CASE-001/*/artefacts/plaso_timeline.jsonl | head
```

---

## Integration Examples

### Export to Splunk and Elasticsearch

SIEM export runs inside Elrond, not as a separate tool. Enable Splunk, Elastic and Navigator on the job, or re-run the export for a completed job:

```bash
curl -X POST http://localhost:5688/api/jobs/{job_id}/export-siem
```

From the CLI, add `--Splunk --Elastic --Navigator` to the Elrond command. Start the services first with `docker compose --profile siem up -d`.

### Generate MITRE ATT&CK Mapping

```bash
python3 -m src.analysis.mitre.cli map powershell_history -c "<command line>"
python3 -m src.analysis.mitre.coverage_cli dashboard CASE-001 /output/CASE-001 -o coverage.html
```

The Navigator layer is written by Elrond (`<case>_navigator.json`) or downloaded with `GET /api/jobs/{job_id}/navigator`.

---

## API Authentication

### Login and Get Token

```bash
# Login
TOKEN=$(curl -s -X POST http://localhost:5688/api/auth/login \
  -d "username=admin@rowanholt.app" --data-urlencode "password=IWasThere3000YearsAgo!" \
  | jq -r '.access_token')

# Use token in requests
curl http://localhost:5688/api/jobs \
  -H "Authorization: Bearer $TOKEN"
```

### Login with MFA

> Not available in the current build: the mounted auth router has no MFA step.

```bash
# Step 1: Login (returns temp_token if MFA enabled)
TEMP_TOKEN=$(curl -s -X POST http://localhost:5688/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user@example.com", "password": "password"}' \
  | jq -r '.temp_token')

# Step 2: Verify MFA code
TOKEN=$(curl -s -X POST http://localhost:5688/api/auth/mfa/verify \
  -H "Content-Type: application/json" \
  -d '{"temp_token": "'$TEMP_TOKEN'", "code": "123456"}' \
  | jq -r '.access_token')
```

---

## Keyboard Shortcuts

**Web Interface (when available):**
- `n` - New Analysis
- `r` - Refresh job list
- `Escape` - Close modal/dialog
- `/` - Focus search

---

## Tips and Best Practices

### Performance

1. **Use SSD/NVMe** for evidence and output directories
2. **Run one job at a time** (worker `--concurrency=1`): concurrent jobs share mount points and unmount each other's images
3. **Close browser tabs** monitoring jobs to reduce load
4. **Archive old jobs** to keep database performant

### Security

1. **Change default password** immediately
2. **Enable MFA** for all admin accounts
3. **Use HTTPS** in production (configure reverse proxy)
4. **Limit allowed_paths** to necessary directories only
5. **Regular backups** of database and configuration

### Workflow

1. **Use meaningful case numbers** (e.g., CASE-2025-001)
2. **Document analysis options** used for each case
3. **Save backup codes** when enabling MFA
4. **Check logs** if job fails
5. **Export results** to SIEM for long-term storage

---

## Troubleshooting

### Job Stuck in "Pending"

**Check Celery worker:**
```bash
docker logs rowanholt-celery-worker --tail 100
```

**Restart worker:**
```bash
docker restart rowanholt-celery-worker
```

Restarting the worker kills any running job. The backend notices within about three minutes and marks it failed, with *Interrupted: …* as its error and the last line of its log; restart it from the job list. A pending job whose task was lost from the queue is failed the same way ([API: jobs left by a crash](API.md#jobs-left-by-a-crash)).

### "Failed to load directory"

**Check permissions:**
```bash
chmod 755 /tmp/rowanholt
ls -la /tmp/rowanholt
```

**Verify allowed_paths** in `/src/web/backend/config.py`

### Can't Login

Users are stored in the JSON file named by `USERS_FILE` (default `/app/data/users.json` in the backend container). When the file has no users, the next login creates the default admin from `default_admin_email` and `default_admin_password` in `config.py`. Moving the file aside resets it (`/app/data` is `src/web/backend/data` on the host); other accounts are kept in the `.bak` copy:

```bash
docker exec rowanholt-backend mv /app/data/users.json /app/data/users.json.bak
```

---

## Further Reading

- **[API.md](API.md)** - Complete REST API documentation with examples
- **[CLI.md](CLI.md)** - Command-line tools (gandalf, elrond, MITRE, cloud, AI)
- **[CONFIG.md](CONFIG.md)** - Configuration options and tuning
- **[SECURITY.md](SECURITY.md)** - Security implementation details
- **[QUICKSTART.md](QUICKSTART.md)** - 5-minute getting started guide

---

**Version:** 2.1.0
**Last Updated:** 2026-10-22
