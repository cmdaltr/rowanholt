# Batch Test Scripts

## Quick Start

**All batch scripts now automatically clean up file handles!** Just run them directly:

```bash
# From project root
./tests/scripts/batch/1a_archive.sh
./tests/scripts/batch/1b_collect--lnk-docs.sh
./tests/scripts/batch/1c_collect--bin-hidden-scripts.sh
./tests/scripts/batch/1d_collect--mail-virtual-web.sh
```

Or run sequentially:
```bash
./tests/scripts/batch/1a_archive.sh && \
./tests/scripts/batch/1b_collect--lnk-docs.sh && \
./tests/scripts/batch/1c_collect--bin-hidden-scripts.sh && \
./tests/scripts/batch/1d_collect--mail-virtual-web.sh
```

### Optional Manual Cleanup

While not required, you can still manually clean up if desired:

```bash
# From project root
./scripts/cleanup-orbstack-handles.sh

# Then run batch tests
./tests/scripts/batch/1a_archive.sh
```

## Automatic File Handle Management

OrbStack accumulates ~8,000 file handles per file collection test that **are not released** even after tests complete. This would normally hit macOS system limits (~122K files) after 1-2 tests.

**Solution implemented:**
1. **Pre-batch cleanup:** ALL batch scripts automatically check and clean up file handles from previous runs (threshold: >100 handles)
2. **Between-test cleanup:** File collection scripts (1b, 1c, 1d) also clean up between tests (threshold: >1,000 handles, lowered from 5,000)

## Batch Scripts Overview

### Phase 1: File Collection
- **1a_archive.sh** - Archive test (~30 min)
- **1b_collect--lnk-docs.sh** - LNK + Docs (~60 min)
  - win_collect_files_lnk
  - win_collect_files_docs
- **1c_collect--bin-hidden-scripts.sh** - Binary + Hidden + Scripts (~60 min)
  - win_collect_files_bin
  - win_collect_files_hidden
  - win_collect_files_scripts
- **1d_collect--mail-virtual-web.sh** - Mail + Virtual + Web (~60 min)
  - win_collect_files_mail
  - win_collect_files_virtual
  - win_collect_files_web

### Phase 2: Processing
- **2a-profiles-vss.sh** - Profile + VSS tests (~45 min)
- **2b-memory.sh** - Memory analysis (~30 min)
- **2c-brisk.sh** - Quick analysis (~15 min)
- **2d-collect-all.sh** - Full collection (~90 min)

### Phase 3: Analysis
- **3a-ioc-extraction.sh** - IOC extraction (~30 min)
- **3b-keywords.sh** - Keyword search (~20 min)
- **3c-yara.sh** - YARA scanning (~45 min)
- **3d-yara-memory.sh** - YARA memory scan (~30 min)

### Phase 4: Export
- **4a-splunk-export.sh** - Splunk export (~20 min)
- **4b-elastic-export.sh** - Elasticsearch export (~20 min)
- **4c-navigator-export.sh** - ATT&CK Navigator (~15 min)
- **4d-siem-nav-export.sh** - Combined SIEM + Navigator (~30 min)

### Phase 5: Full Suite
- **5a-full_analysis.sh** - Complete analysis (~120 min)
- **5b-exhaustive-disk.sh** - All disk tests (~180 min)
- **5c-exhaustive-memory.sh** - All memory tests (~90 min)
- **5d-exhaustive-disk-memory.sh** - Everything (~240 min)

## Automatic Cleanup Details

### Pre-Batch Cleanup (ALL Scripts)
Every batch script checks for file handles BEFORE starting any tests:

```bash
Checking for file handles from previous runs...
✓ File handle count acceptable (0)
```

If handles exceed 100, automatic cleanup runs:
```bash
⚠️  Found 245 file handles - cleaning up before starting batch...
✓ Pre-batch cleanup complete
```

### Between-Test Cleanup (File Collection Only)
File collection scripts (1b, 1c, 1d) also check between tests. If handles exceed 1,000 (lowered from 5,000):

```bash
⚠️  High file handle count (1234) - cleaning up OrbStack...
✓ Cleanup complete - continuing tests...
```

**Cleanup adds ~20s overhead but prevents test failures**

## Manual Cleanup (Rarely Needed)

With automatic cleanup in all scripts, manual cleanup is rarely necessary. However, you can still run it if desired:

```bash
# Optional - scripts handle this automatically now
./scripts/cleanup-orbstack-handles.sh

# Or force cleanup even below threshold
./scripts/cleanup-orbstack-handles.sh --force
```

## Configuration

### Test Delay
Control delay between tests in a batch (default: 30s):
```bash
DELAY_BETWEEN_TESTS=60 ./tests/scripts/batch/1b_collect--lnk-docs.sh
```

### Output Logs
Logs are stored in `tests/logs/` with timestamp:
```
tests/logs/1b_collect--lnk-docs-20260115-204927.log
```

## Monitoring

Check file handle usage:
```bash
# Current handle count
lsof | grep "/Volumes/Media5TB/rowanholt_imgs" | wc -l

# Detailed view
lsof -p $(pgrep OrbStack | head -1) | grep "/Volumes/Media5TB/rowanholt_imgs" | head -30
```

Check job status:
```bash
cd /Users/ben/Library/CloudStorage/OneDrive-Personal/Projects/GitHub/rowanholt
./scripts/status.sh

# Or via Docker
docker logs -f rowanholt-celery-worker
```

## Troubleshooting

### "Too many open files" errors
**This should no longer occur** with automatic pre-batch cleanup. If it does happen:

1. Check if the automatic cleanup ran (look for "Checking for file handles" message at batch start)
2. Manually force cleanup:
```bash
./scripts/cleanup-orbstack-handles.sh --force
```

### Tests showing PASSED but actually failed
**Fixed:** `run_test.py` now returns correct exit codes

### Batch script reports wrong PASS/FAIL count
**Fixed:** Scripts now check `${PIPESTATUS[0]}` instead of `tee` exit code

### High memory usage
**Solution:** Use testing mode (already active):
- Disables Splunk (saves 4GB)
- Disables Elasticsearch (saves 2GB)
- Total: ~9GB vs 15GB full mode

## Related Documentation

- `docs/ORBSTACK_FILE_HANDLE_ISSUE.md` - Detailed analysis of file handle issue
- `docs/FILE_DESCRIPTOR_MANAGEMENT.md` - Retry logic implementation
- `docs/INTEGRATION_SUMMARY.md` - Technical integration details
- `scripts/cleanup-orbstack-handles.sh` - Cleanup helper script
