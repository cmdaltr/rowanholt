# Test Runner Changes - October 2026

Changes made during the October 2026 E2E matrix run (uncommitted at 22 Oct).

## Test Tooling

- **`run_test.py --cancel JOB_ID [...]`** cancels specific jobs. A job in `awaiting_confirmation` returns 400 on `/cancel`, so it falls back to `/cancel-sudo`. Exits 1 if any cancel fails.
- **`run_test.py` image discovery** also searches `/Volumes/*/rowanholt` and `/Volumes/*/*/rowanholt`.
- **`tests/scripts/test_timings.py`** (new) extracts per-test and per-stage timings from every `rowanholt_audit.log` into JSON, CSV or Markdown. It splits records on timestamps rather than newlines because `iocs.py` writes entries without a trailing newline.
- **`docs/PERFORMANCE.md`** (new) records what each option costs, measured from this run.

## Worker and Elrond Fixes

- **Celery redelivery** (`tasks_docker.py`): `visibility_timeout` raised to 24 h and `worker_prefetch_multiplier` set to 1. With the 1 h default, a job queued behind one that ran over an hour was delivered again and ran up to three times.
- **`$I30` walk** (`collect/files/i30.py`): stops once the image is handled. It used to `os.walk` the whole evidence directory, including any test output stored there, adding 11–73 minutes to each Windows run.
- **Carving** (`collect/files/carve.py`): the per-file logging sleep dropped from 0.5 s to 0.1 s, and foremost's `audit.txt` is kept as the record of what was scanned.
- **YARA** (`post/yara.py`): `-N` stops `yara -r` following symlinks. On Linux images `/dev/fd -> /proc/self/fd` led back into the mount and the scan never finished.
- **Splunk healthcheck** (`docker-compose.yml`): a curl check on :8089 replaces the image's own check, which ran as `ansible` and always reported unhealthy.

## Documentation

- `TEST_RUNNER_GUIDE.md` rewritten: current script paths, job control, clean-up after a cancel, silent steps, output layout and timings.
- `TEST_RESULTS.md` regenerated from the Notion Test Plan.
- `tests/docs/README.md`: corrected the `run_test.py` path and test count.
- `docs/CLI.md`, `QUICKSTART.md`, `USAGE.md`, `docs/README.md`, root `README.md`, `src/web/README.md`: replaced commands that don't exist (Elrond short flags, `rowanholt-ai`, `rowanholt.mitre.*`, `rowanholt.siem.*` and similar) with the real entry points, which must run from the repository root. Fixed the Gandalf syntax and output format (zip, not tar.gz), fixture paths, ports and dead links.
- `docs/API.md`: added an authentication status section (simple file-based router mounted; job endpoints don't check tokens; MFA and admin routes not mounted), form-encoded login, the real job `options`, and endpoints that were missing.
- `docs/ARCHITECTURE.md`, `ACCESSING-DATA.md`, `CONFIG.md`, `REQUIREMENTS.md`, `INSTALL.md`: current container names, Compose v2 syntax, the `siem` profile and live links.

---

# Test Runner Changes - January 2026

## Summary

Added automatic Docker restart functionality to all test scripts to prevent Docker crashes during long-running test batches.

## Changes Made

### New Scripts

1. **`run_single_test.sh`** - Single test runner with auto-restart
   - Runs one test with Docker restart afterward
   - Checks Docker/backend status before starting
   - Verifies services after restart
   - Usage: `./run_single_test.sh <test_name>`

2. **`batches/RUN_ALL_TESTS.sh`** - Master script
   - Runs batches 1a-4c sequentially
   - Restarts Docker between batches
   - ~9-10 hours total runtime

3. **`TEST_RUNNER_GUIDE.md`** - Complete documentation
   - Usage instructions for all scripts
   - Troubleshooting guide
   - Best practices

### Modified Scripts

**All batch scripts updated:**
- `batch1a-archive-lnk.sh` through `batch4c-collect-all.sh`
- `batch5a-full-analysis.sh` through `batch5d-memory-siem.sh`

**Changes:**
- Multi-test batches (1a-3b): Restart Docker **between each test**
- Single-test batches (4a-5d): Restart Docker **after test completes**
- Wait 30s for services to stabilize after restart
- Verify backend responsiveness before continuing

## Problem Solved

**Before:** Docker crashed after ~30-60 minutes of continuous testing due to resource exhaustion, even though individual tests completed successfully.

**After:** Docker restarts between tests free accumulated resources (memory, file handles, cache), preventing crashes and allowing test batches to complete reliably.

## Migration Guide

### Old Way
```bash
# Manual restart required between tests
./batch1a-archive-lnk.sh
docker restart rowanholt-backend rowanholt-celery-worker
./batch1b-archive-docs.sh
```

### New Way
```bash
# Automatic restarts built-in
./batch1a-archive-lnk.sh
./batch1b-archive-docs.sh

# Or run single tests
./run_single_test.sh win_archive
./run_single_test.sh win_collect_files_lnk
```

## Backward Compatibility

All existing functionality preserved:
- `run_test.py` unchanged
- Test definitions unchanged
- Output paths unchanged
- Log format unchanged

## Testing

Verified with:
- ✅ batch1a completed successfully (2 tests, 1.7GB + 1.8GB output)
- ✅ Artifacts collected: raw/, cooked/, $MFT, registry, event logs
- ✅ Docker crashes handled gracefully (tests complete before crash)
- ✅ Output preserved on external drive

## Related Files

- `tests/run_single_test.sh` (new)
- `tests/scripts/batch/RUN_ALL_TESTS.sh` (new)
- `tests/TEST_RUNNER_GUIDE.md` (new)
- `tests/scripts/batch/batch*.sh` (all modified)
- `tests/scripts/batch/README.md` (may need update - see TEST_RUNNER_GUIDE.md)

## Update 2: Docker Running Check (January 2026)

### Changes

Added Docker running check to all batch scripts and master script.

**Modified Files:**
- All 15 batch scripts (`batch1a-archive-lnk.sh` through `batch5d-memory-siem.sh`)
- Master script (`RUN_ALL_TESTS.sh`)

### Behavior

**Before:** Scripts would attempt to run tests even if Docker wasn't running, resulting in connection errors.

**After:** Scripts gracefully exit immediately if Docker is not detected running.

### Example Output (Docker Not Running)

```bash
$ ./batch1a-archive-lnk.sh

ERROR: Docker is not running
Please start Docker Desktop and try again

To start Docker:
  macOS:   Open Docker Desktop application
  Linux:   sudo systemctl start docker
  Windows: Start Docker Desktop

$ echo $?
1  # Exit code 1 indicates error
```

### Example Output (Docker Running)

```bash
$ ./batch1a-archive-lnk.sh
======================================
BATCH 1a: Archive + LNK Tests
======================================
Start: Mon Jan 12 16:30:00 GMT 2026
...
```

### Implementation Details

Check performed:
- **Location:** After LOG_FILE initialization, before test execution
- **Method:** `docker ps &> /dev/null`
- **On failure:** Display helpful message and exit with code 1
- **Logged:** Error message written to batch log file

### Benefits

1. ✅ Prevents wasted time running tests that will fail
2. ✅ Clear error message with platform-specific instructions
3. ✅ Proper exit code for automation/CI integration
4. ✅ Error logged to batch log file for debugging
5. ✅ Graceful exit preserves user's terminal state

## Update 3: Docker Auto-Start (January 2026)

### Changes

Enhanced Docker check to offer automatic Docker startup instead of just exiting.

**Modified Files:**
- All 15 batch scripts (`batch1a-archive-lnk.sh` through `batch5d-memory-siem.sh`)
- Master script (`RUN_ALL_TESTS.sh`)
- Single test runner (`run_single_test.sh`)

### New Behavior

**Interactive Prompt:**
```bash
$ ./batch1a-archive-lnk.sh

WARNING: Docker is not running

Would you like to start Docker now? [Y/n] 
```

**If user chooses 'Y' (default):**
```bash
Starting Docker...
Waiting for Docker to start (max 60 seconds)...
✓ Docker is now running

======================================
BATCH 1a: Archive + LNK Tests
======================================
```

**If user chooses 'N':**
```bash
Please start Docker manually and try again:
  macOS:   Open Docker Desktop application
  Linux:   sudo systemctl start docker
  Windows: Start Docker Desktop

$ echo $?
1  # Exits with error code
```

### Platform Support

**macOS:**
- Uses `open -a Docker` to launch Docker Desktop
- Waits up to 60 seconds for Docker to be ready

**Linux:**
- Uses `sudo systemctl start docker` to start Docker service
- May prompt for sudo password
- Waits up to 60 seconds for Docker to be ready

**Windows:**
- Prompts user to start Docker Desktop manually
- Cannot auto-start on Windows (requires manual launch)

### Benefits

1. ✅ **One less step** - No need to manually start Docker before running tests
2. ✅ **Automatic wait** - Script waits for Docker to be fully ready
3. ✅ **Still graceful** - User can decline and start Docker manually
4. ✅ **Cross-platform** - Works on macOS, Linux, Windows (with manual start)
5. ✅ **Timeout protection** - Exits with error if Docker doesn't start in 60s

### Example Workflow

**Before (manual):**
```bash
$ ./batch1a-archive-lnk.sh
ERROR: Docker is not running
$ open -a Docker
$ # Wait... check status... retry...
$ ./batch1a-archive-lnk.sh
```

**After (automatic):**
```bash
$ ./batch1a-archive-lnk.sh
WARNING: Docker is not running
Would you like to start Docker now? [Y/n] y

Starting Docker...
Waiting for Docker to start (max 60 seconds)...
✓ Docker is now running

[Tests begin automatically]
```

### Implementation Details

- **Timeout:** 60 seconds max wait for Docker to start
- **Check interval:** 1 second
- **Default choice:** Yes (pressing Enter starts Docker)
- **Logged:** All output is logged to batch log file
- **Exit codes:** Returns 1 if Docker fails to start or user declines
