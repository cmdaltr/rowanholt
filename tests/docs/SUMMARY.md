# Rowanholt Test Runner - Summary

## Overview

Comprehensive test automation system for Rowanholt forensic analysis with automatic Docker management and resource optimization.

## Key Features

### 1. Automatic Docker Management
- **Auto-start:** Offers to start Docker if not running
- **Auto-restart:** Restarts Docker between tests to prevent crashes
- **Wait logic:** Automatically waits for Docker to be ready
- **Cross-platform:** Works on macOS, Linux, Windows

### 2. Test Organization

**Single Tests:**
- Run individual tests with `./run_single_test.sh <test_name>`
- Automatic Docker restart after completion
- ~10-90 minutes per test

**Test Batches:**
- 15 batch scripts organized by test type
- 2-3 tests per batch (except batch 5 extreme tests)
- Docker restart between each test
- ~60-90 minutes per batch

**Master Script:**
- `RUN_ALL_TESTS.sh` runs batches 1a-4c
- ~9-10 hours total runtime
- Automatic Docker restarts between batches

### 3. Resource Management

**Problem Solved:** Long-running forensic analysis causes Docker to crash due to memory/resource exhaustion

**Solution:**
- Restart Docker containers between tests
- Wait 30s for services to stabilize
- Verify backend responsiveness before continuing
- Results preserved on external drive

### 4. User Experience

**Interactive:**
- Docker auto-start prompt
- Clear progress indicators
- Timestamped logs
- Pass/fail summaries

**Safe:**
- Graceful error handling
- Proper exit codes
- Cross-platform instructions
- Timeout protection (60s Docker start)

## File Structure

```
tests/
├── run_single_test.sh          # Run one test with auto-restart
├── run_test.py                 # Core test runner (unchanged)
├── TEST_RUNNER_GUIDE.md        # Complete documentation
├── QUICK_START.md              # Getting started guide
├── CHANGES.md                  # Change log
├── SUMMARY.md                  # This file
├── logs/                       # Timestamped batch logs
└── batches/
    ├── batch1a-archive-lnk.sh  # Quick tests
    ├── batch1b-archive-docs.sh
    ├── batch1c-bin-hidden.sh
    ├── batch2a-mail-scripts.sh
    ├── batch2b-virtual-web.sh
    ├── batch2c-extraction.sh
    ├── batch3a-profiles-vss.sh
    ├── batch3b-yara-memory.sh
    ├── batch4a-brisk.sh
    ├── batch4b-keywords.sh
    ├── batch4c-collect-all.sh
    ├── batch5a-full-analysis.sh    # Extreme tests
    ├── batch5b-disk-memory.sh      # (2-4+ hours each)
    ├── batch5c-siem-exports.sh
    ├── batch5d-memory-siem.sh
    └── RUN_ALL_TESTS.sh            # Master script
```

## Usage Examples

### Quick Test (10 minutes)
```bash
cd tests
./run_single_test.sh win_brisk
```

### Quick Batch (65 minutes)
```bash
cd tests/scripts/batch
./batch1a-archive-lnk.sh
```

### All Tests (9-10 hours)
```bash
cd tests/scripts/batch
./RUN_ALL_TESTS.sh
```

## Docker Auto-Start Flow

```
┌─────────────────────────┐
│  Run batch/test script  │
└───────────┬─────────────┘
            │
            ▼
     ┌──────────────┐
     │ Docker       │
     │ running?     │
     └──┬────────┬──┘
        │        │
      Yes       No
        │        │
        │        ▼
        │   ┌─────────────────────┐
        │   │ Prompt: Start       │
        │   │ Docker? [Y/n]       │
        │   └──┬───────────┬──────┘
        │      │           │
        │     Yes         No
        │      │           │
        │      ▼           ▼
        │   ┌──────┐   ┌──────┐
        │   │Start │   │ Exit │
        │   │Docker│   │ (1)  │
        │   └──┬───┘   └──────┘
        │      │
        │      ▼
        │   ┌───────────────┐
        │   │ Wait 60s max  │
        │   │ for ready     │
        │   └──┬────────┬───┘
        │      │        │
        │    Ready   Timeout
        │      │        │
        ▼      ▼        ▼
    ┌──────────┐   ┌──────┐
    │   Run    │   │ Exit │
    │  tests   │   │ (1)  │
    └──────────┘   └──────┘
```

## Test Output Locations

### Platform-Specific
- **macOS:** `/Volumes/[Drive]/rowanholt_imgs/tests/`
- **Linux:** `/mnt/[mount]/rowanholt_imgs/tests/` or `/media/[user]/[drive]/rowanholt_imgs/tests/`
- **Windows:** `[Drive]:/rowanholt_imgs/tests/`

### Structure
```
tests/
├── win_archive/
│   └── win7-64-nfury-c-drive.E01/
│       ├── artefacts/
│       │   ├── raw/        # Collected files
│       │   └── cooked/     # Parsed JSON/CSV
│       └── audit_log.csv
└── [test_name]/
    └── ...
```

## Benefits Summary

✅ **Automatic Docker management** - No manual restarts needed  
✅ **Crash prevention** - Docker restarts between tests  
✅ **User-friendly** - Interactive prompts and clear messages  
✅ **Cross-platform** - Works on macOS, Linux, Windows  
✅ **Resource efficient** - Automatic cleanup between tests  
✅ **Logged** - Timestamped logs for all operations  
✅ **Safe** - Graceful error handling and proper exit codes  
✅ **Flexible** - Single tests, batches, or everything at once  

## Quick Reference

| Task | Command | Duration |
|------|---------|----------|
| Test one | `./run_single_test.sh win_brisk` | ~10 min |
| Quick batch | `./batch1a-archive-lnk.sh` | ~65 min |
| All tests | `./RUN_ALL_TESTS.sh` | ~9-10 hrs |
| Check results | `ls -lh /Volumes/*/rowanholt_imgs/tests/` | - |
| View logs | `ls -lt tests/logs/*.log \| head -5` | - |

## Documentation Files

1. **QUICK_START.md** - Get started in 5 minutes
2. **TEST_RUNNER_GUIDE.md** - Complete reference guide
3. **CHANGES.md** - Detailed change log
4. **SUMMARY.md** - This overview document

## Version History

- **v1.0** (Jan 2026) - Initial batch scripts
- **v1.1** (Jan 2026) - Added Docker auto-restart between tests
- **v1.2** (Jan 2026) - Added Docker running check with graceful exit
- **v1.3** (Jan 2026) - Added Docker auto-start with interactive prompt

---

**For detailed usage instructions, see:** `TEST_RUNNER_GUIDE.md`  
**To get started quickly, see:** `QUICK_START.md`
