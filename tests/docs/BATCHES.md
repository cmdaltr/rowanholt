# Test Batch Scripts

Automated test batch scripts for running Dernvale tests in smaller, Docker-friendly groups.

**Organization**: Batches split into 2-3 tests each (~60-90 min) to prevent Docker crashes from resource exhaustion.

---

## Quick Reference Table

| Batch | Tests | Duration | Difficulty | Notes |
|-------|-------|----------|------------|-------|
| **1a** | Archive + LNK | ~65 min | ✅ Easy | Best starting point |
| **1b** | Archive Files + Docs | ~60 min | ✅ Easy | Safe |
| **1c** | Binaries + Hidden | ~75 min | ✅ Easy | Safe |
| **2a** | Mail + Scripts | ~60 min | ✅ Easy | Safe |
| **2b** | Virtual + Web | ~60 min | ✅ Easy | Safe |
| **2c** | IOCs + Timeline | ~60 min | ⚠️ Medium | IOCs may stall at 91% |
| **3a** | Profiles + VSS | ~60 min | ⚠️ Medium | Monitor closely |
| **3b** | YARA + Memory | ~90 min | ⚠️ Medium | Memory-intensive |
| **4a** | Brisk | ~10 min | ✅ Easy | Quick test |
| **4b** | Keywords | ~90 min | 🔴 Hard | Long-running |
| **4c** | Collect All | ~90 min | 🔴 Hard | Resource-intensive |
| **5a** | Full Analysis | 2-4+ hrs | 🔴 Extreme | ONE PER DAY |
| **5b** | Disk + Memory | 2-4+ hrs | 🔴 Extreme | ONE PER DAY |
| **5c** | SIEM Exports | 2-4+ hrs | 🔴 Extreme | ONE PER DAY |
| **5d** | Memory + SIEM | 2-4+ hrs | 🔴 Extreme | ONE PER DAY |

---

## 🎯 Recommended Approach

### Option 1: Full Sequential Run (Automated)

Run all batches sequentially with Docker restarts between each. Best for overnight/unattended execution.

```bash
cd tests

# Phase 1: Quick Tests (3-4 hours)
./scripts/batch/batch1a-archive-lnk.sh
docker restart dernvale-backend dernvale-celery-worker && sleep 15

./scripts/batch/batch1b-archive-docs.sh
docker restart dernvale-backend dernvale-celery-worker && sleep 15

./scripts/batch/batch1c-bin-hidden.sh
docker restart dernvale-backend dernvale-celery-worker && sleep 15

# Phase 2: Collection Tests (3 hours)
./scripts/batch/batch2a-mail-scripts.sh
docker restart dernvale-backend dernvale-celery-worker && sleep 15

./scripts/batch/batch2b-virtual-web.sh
docker restart dernvale-backend dernvale-celery-worker && sleep 15

./scripts/batch/batch2c-extraction.sh
docker restart dernvale-backend dernvale-celery-worker && sleep 15

# Phase 3: Advanced Tests (2.5 hours)
./scripts/batch/batch3a-profiles-vss.sh
docker restart dernvale-backend dernvale-celery-worker && sleep 15

./scripts/batch/batch3b-yara-memory.sh
docker restart dernvale-backend dernvale-celery-worker && sleep 15

# Phase 4: Long Tests (2-3 hours)
./scripts/batch/batch4a-brisk.sh
docker restart dernvale-backend dernvale-celery-worker && sleep 15

./scripts/batch/batch4b-keywords.sh
docker restart dernvale-backend dernvale-celery-worker && sleep 15

./scripts/batch/batch4c-collect-all.sh

# Phase 5: Run extreme tests separately (ONE PER DAY)
```

**Total Time**: ~11-13 hours (Phases 1-4)

---

### Option 2: Batch Groups (Semi-Automated)

Run batches in groups with manual Docker restarts between groups. Best for monitored execution during work hours.

**Group A - Morning Session (3 hours)**
```bash
cd tests
./scripts/batch/batch1a-archive-lnk.sh
./scripts/batch/batch1b-archive-docs.sh
./scripts/batch/batch1c-bin-hidden.sh
```
**→ Restart Docker Desktop manually**

**Group B - Afternoon Session (3 hours)**
```bash
./scripts/batch/batch2a-mail-scripts.sh
./scripts/batch/batch2b-virtual-web.sh
./scripts/batch/batch2c-extraction.sh
```
**→ Restart Docker Desktop manually**

**Group C - Evening Session (2.5 hours)**
```bash
./scripts/batch/batch3a-profiles-vss.sh
./scripts/batch/batch3b-yara-memory.sh
```

**Group D - Long Tests (run individually over 2-3 days)**
```bash
# Day 1
./scripts/batch/batch4a-brisk.sh
# Day 2
./scripts/batch/batch4b-keywords.sh
# Day 3
./scripts/batch/batch4c-collect-all.sh
```

---

### Option 3: Cherry-Pick (Manual)

Run only specific tests you need. Best for targeted testing or re-running failed tests.

```bash
cd tests

# Example: Just verify system is working
./scripts/batch/batch1a-archive-lnk.sh

# Example: Test artifact collection only
./scripts/batch/batch1c-bin-hidden.sh
./scripts/batch/batch2a-mail-scripts.sh
```

---

### Option 4: Extreme Tests (One Per Day)

**🔴 EXTREME CAUTION**: Only run ONE extreme test per day with full Docker restart between each.

```bash
# Day 1 - Full Analysis
docker restart dernvale-backend dernvale-celery-worker
cd tests && ./scripts/batch/batch5a-full-analysis.sh

# Day 2 - Disk + Memory (after full Docker Desktop restart)
docker restart dernvale-backend dernvale-celery-worker
./scripts/batch/batch5b-disk-memory.sh

# Day 3 - SIEM Exports (after full Docker Desktop restart)
docker restart dernvale-backend dernvale-celery-worker
./scripts/batch/batch5c-siem-exports.sh

# Day 4 - Memory + SIEM (after full Docker Desktop restart)
docker restart dernvale-backend dernvale-celery-worker
./scripts/batch/batch5d-memory-siem.sh
```

**Important**: Monitor Docker resources during extreme tests. Increase memory to 12GB if possible.

---

## 📋 Pre-Flight Checklist

Before running **ANY** batch:

```bash
# 1. Check Docker is running
docker ps

# 2. Check API is responsive
python3 run_test.py --status

# 3. Check disk space (need ~50GB+ free)
# macOS:   df -h /Volumes/*/dernvale_imgs
# Linux:   df -h /mnt/*/dernvale_imgs
# Windows: dir [DriveLetter]:\dernvale_imgs

# 4. Optional: Clean old test outputs (adjust path to your drive/mount)
# macOS:   rm -rf /Volumes/YourDrive/dernvale_imgs/tests/win_*
# Linux:   rm -rf /mnt/YourMount/dernvale_imgs/tests/win_*
# Windows: del /S [Drive]:\dernvale_imgs\tests\win_*

# 5. Restart Docker for clean state (recommended)
docker restart dernvale-backend dernvale-celery-worker
sleep 10
python3 run_test.py --status  # Verify still working
```

---

## 📊 Monitoring During Execution

### Check Test Progress
```bash
# View current job status
python3 run_test.py --status

# Watch for running jobs
watch -n 10 'python3 run_test.py --status | grep -A 5 RUNNING'
```

### Check Docker Health
```bash
# Container status
docker ps --filter "name=dernvale"

# Resource usage
docker stats --no-stream dernvale-backend dernvale-celery-worker

# Recent logs
docker logs dernvale-celery-worker --tail 20
docker logs dernvale-backend --tail 20
```

### Monitor for Problems
- **Progress stuck >30 min**: Check logs, may need to restart
- **Docker high memory usage**: May crash soon, monitor closely
- **API errors**: Backend may be unresponsive, restart it

---

## 🔧 Between-Batch Maintenance

**After each batch completes** (recommended for stability):

```bash
# Option 1: Restart just the worker containers (fast, 10 seconds)
docker restart dernvale-backend dernvale-celery-worker
sleep 10

# Option 2: Restart Docker Desktop (slower, ~60 seconds)
# Use if you notice memory creeping up or instability
# - Quit Docker Desktop from menu bar
# - Reopen Docker Desktop
# - Wait for containers to start
```

**Why restart?**
- Prevents memory leaks from accumulating
- Clears file handles and connections
- Reduces chance of Docker crash mid-test

---

## 🚨 Troubleshooting

### Docker Crashes Mid-Test

**Symptoms**:
```
failed to connect to docker API
Error: Could not connect to API
docker ps: no such file or directory
```

**Solution**:
1. Open Docker Desktop application
2. Wait 60 seconds for full startup
3. Verify: `docker ps`
4. Check if test is still running: `python3 run_test.py --status`
5. If test failed, re-run that specific batch

---

### API Not Responding

**Symptoms**:
```
ERROR: Could not connect to API at http://localhost:5688
Connection aborted, RemoteDisconnected
```

**Solution**:
```bash
# Restart backend
docker restart dernvale-backend
sleep 5

# Test connection
curl http://localhost:5688/api/jobs

# If still not working, restart all containers
docker compose restart
```

---

### Test Hangs/Stalls

**Symptoms**: Progress stuck at same percentage for >30 minutes

**Diagnosis**:
```bash
# Check if job is still active
python3 run_test.py --status

# Check worker logs for errors
docker logs dernvale-celery-worker --tail 50

# Check for stuck processes
docker exec dernvale-celery-worker ps aux | grep elrond
```

**Solution**:
- If making progress slowly: Let it continue
- If truly stuck: Cancel test (Ctrl+C) and restart Docker

---

### Out of Disk Space

**Symptoms**: Tests fail with disk errors, Docker becomes unstable

**Solution**:
```bash
# Check space (platform-specific commands)
# macOS:   df -h /Volumes/*/dernvale_imgs
# Linux:   df -h /mnt/*/dernvale_imgs
# Windows: dir [Drive]:\dernvale_imgs

# Clean old outputs (CAUTION: deletes test results)
# macOS/Linux:  rm -rf [path]/dernvale_imgs/tests/win_*
# Windows:      del /S [Drive]:\dernvale_imgs\tests\win_*

# Clean Docker volumes (if needed)
docker system prune -a --volumes
```

---

## 📁 Batch Details

### Batch 1a: Archive + LNK
**Tests**: win_archive, win_collect_files_lnk
**Duration**: ~65 minutes
**Purpose**: Basic archive creation and LNK file collection. Best starting point to verify system works.

```bash
cd tests && ./scripts/batch/batch1a-archive-lnk.sh
```

---

### Batch 1b: Archive Files + Documents
**Tests**: win_collect_files_archive, win_collect_files_docs
**Duration**: ~60 minutes
**Purpose**: Collect compressed archives (.zip, .rar) and documents (.doc, .pdf, .txt)

```bash
cd tests && ./scripts/batch/batch1b-archive-docs.sh
```

---

### Batch 1c: Binaries + Hidden Files
**Tests**: win_collect_files_bin, win_collect_files_hidden
**Duration**: ~75 minutes
**Purpose**: Collect executables and hidden/system files. Most thorough of Phase 1 tests.

```bash
cd tests && ./scripts/batch/batch1c-bin-hidden.sh
```

---

### Batch 2a: Mail + Scripts
**Tests**: win_collect_files_mail, win_collect_files_scripts
**Duration**: ~60 minutes
**Purpose**: Collect email files (.pst, .eml) and script files (.ps1, .bat, .sh)

```bash
cd tests && ./scripts/batch/batch2a-mail-scripts.sh
```

---

### Batch 2b: Virtual + Web
**Tests**: win_collect_files_virtual, win_collect_files_web
**Duration**: ~60 minutes
**Purpose**: Collect VM files (.vmdk, .vdi) and web artifacts

```bash
cd tests && ./scripts/batch/batch2b-virtual-web.sh
```

---

### Batch 2c: IOC Extraction + Timeline
**Tests**: win_extract_iocs, win_timeline
**Duration**: ~60 minutes
**Purpose**: Extract indicators of compromise and generate timeline
**⚠️ Note**: IOC extraction may stall at 91% - this is a known issue

```bash
cd tests && ./scripts/batch/batch2c-extraction.sh
```

---

### Batch 3a: User Profiles + VSS
**Tests**: win_userprofiles, win_vss
**Duration**: ~60 minutes
**Purpose**: Analyze user profiles and Volume Shadow Copies

```bash
cd tests && ./scripts/batch/batch3a-profiles-vss.sh
```

---

### Batch 3b: YARA + Memory
**Tests**: win_yara, win_memory_basic, win_memory_timeline
**Duration**: ~90 minutes
**Purpose**: YARA malware scanning and memory analysis
**⚠️ Note**: Memory-intensive, ensure Docker has 10GB+ RAM

```bash
cd tests && ./scripts/batch/batch3b-yara-memory.sh
```

---

### Batch 4a: Brisk Analysis
**Tests**: win_brisk
**Duration**: ~10 minutes
**Purpose**: Quick forensic triage analysis

```bash
cd tests && ./scripts/batch/batch4a-brisk.sh
```

---

### Batch 4b: Keyword Search
**Tests**: win_keywords
**Duration**: ~90 minutes
**Purpose**: Search entire disk for keywords
**🔴 Caution**: Long-running, resource-intensive

```bash
cd tests && ./scripts/batch/batch4b-keywords.sh
```

---

### Batch 4c: Collect All Files
**Tests**: win_collect_files_all
**Duration**: ~90 minutes
**Purpose**: Collect all file types (combination of all collect tests)
**🔴 Caution**: Long-running, high disk usage

```bash
cd tests && ./scripts/batch/batch4c-collect-all.sh
```

---

### Batch 5a: Full Analysis
**Tests**: win_full
**Duration**: 2-4+ hours
**Purpose**: Comprehensive forensic analysis of entire disk
**🔴 EXTREME**: ONE PER DAY, restart Docker before running

```bash
docker restart dernvale-backend dernvale-celery-worker
cd tests && ./scripts/batch/batch5a-full-analysis.sh
```

---

### Batch 5b: Disk + Memory
**Tests**: win_disk_and_memory
**Duration**: 2-4+ hours
**Purpose**: Combined disk and memory analysis
**🔴 EXTREME**: ONE PER DAY, restart Docker before running

```bash
docker restart dernvale-backend dernvale-celery-worker
cd tests && ./scripts/batch/batch5b-disk-memory.sh
```

---

### Batch 5c: SIEM Exports
**Tests**: win_splunk_elastic_nav
**Duration**: 2-4+ hours
**Purpose**: Export results to Splunk, Elasticsearch, and ATT&CK Navigator
**🔴 EXTREME**: ONE PER DAY, restart Docker before running

```bash
docker restart dernvale-backend dernvale-celery-worker
cd tests && ./scripts/batch/batch5c-siem-exports.sh
```

---

### Batch 5d: Memory + SIEM
**Tests**: win_mem_splunk_elastic_nav
**Duration**: 2-4+ hours
**Purpose**: Memory analysis with SIEM exports
**🔴 EXTREME**: ONE PER DAY, restart Docker before running

```bash
docker restart dernvale-backend dernvale-celery-worker
cd tests && ./scripts/batch/batch5d-memory-siem.sh
```

---

## 📝 Log Files

Each batch creates a timestamped log file:
```
tests/scripts/batch/batch1a-archive-lnk-YYYYMMDD-HHMMSS.log
tests/scripts/batch/batch1b-archive-docs-YYYYMMDD-HHMMSS.log
...
```

These logs contain:
- Test execution output with timestamps
- Success/failure status for each test
- Job IDs for tracking
- Duration information
- Error messages if tests fail

---

## 🔗 Related Documentation

- **`run_test.py`** - Individual test runner, use for single tests
- **`BUG3_DEEP_INVESTIGATION.md`** - Artifact directory creation fix (RESOLVED)
- **Test outputs**: Auto-detected location + `/tests/` subdirectory
- **Job API**: `http://localhost:5688/api/jobs` (view in browser or curl)

---

## 💡 Tips & Best Practices

1. **Start small**: Run batch1a first to verify everything works
2. **Restart often**: Docker restart between batches prevents crashes
3. **Monitor resources**: Use `docker stats` during long tests
4. **Don't stack batches**: Run one at a time, don't queue multiple
5. **Increase Docker memory**: Set to 10-12GB in Docker Desktop settings
6. **Keep terminal open**: Don't let Mac sleep during long tests
7. **Check disk space**: Tests generate 10-50GB per batch
8. **Read the logs**: Check batch log files if tests fail
9. **Use `--status`**: Monitor progress with `python3 run_test.py --status`
10. **Be patient**: Extreme tests (5a-5d) genuinely take 2-4+ hours

---

## 🎓 Example: First-Time Full Test Run

```bash
# Day 1: Quick verification (~4 hours)
cd tests
./scripts/batch/batch1a-archive-lnk.sh     # 65 min - verify system works
docker restart dernvale-backend dernvale-celery-worker && sleep 10
./scripts/batch/batch1b-archive-docs.sh    # 60 min
docker restart dernvale-backend dernvale-celery-worker && sleep 10
./scripts/batch/batch1c-bin-hidden.sh      # 75 min
docker restart dernvale-backend dernvale-celery-worker && sleep 10

# Day 2: Collection tests (~3 hours)
./scripts/batch/batch2a-mail-scripts.sh    # 60 min
docker restart dernvale-backend dernvale-celery-worker && sleep 10
./scripts/batch/batch2b-virtual-web.sh     # 60 min
docker restart dernvale-backend dernvale-celery-worker && sleep 10
./scripts/batch/batch2c-extraction.sh      # 60 min

# Day 3: Advanced tests (~2.5 hours)
docker restart dernvale-backend dernvale-celery-worker && sleep 10
./scripts/batch/batch3a-profiles-vss.sh    # 60 min
docker restart dernvale-backend dernvale-celery-worker && sleep 10
./scripts/batch/batch3b-yara-memory.sh     # 90 min

# Day 4: Long tests individually
docker restart dernvale-backend dernvale-celery-worker && sleep 10
./scripts/batch/batch4a-brisk.sh           # 10 min
# (Later that day)
docker restart dernvale-backend dernvale-celery-worker && sleep 10
./scripts/batch/batch4b-keywords.sh        # 90 min

# Day 5: Last long test
docker restart dernvale-backend dernvale-celery-worker && sleep 10
./scripts/batch/batch4c-collect-all.sh     # 90 min

# Days 6-9: Extreme tests (one per day)
# Only if needed - these are optional comprehensive tests
```

**Total**: 4-5 days for all standard tests, 8-9 days if including extreme tests
