# Rowanholt Test Runner - Quick Start

## Prerequisites
## Prerequisites

### Option 1: Automatic (Recommended)

Just run any test script - it will offer to start Docker for you!

```bash
cd tests
./scripts/run_single_test.sh win_brisk

# If Docker isn't running, you'll see:
# WARNING: Docker is not running
# Would you like to start Docker now? [Y/n]
# Press Enter to start automatically
```

### Option 2: Manual

1. **Start Docker Desktop**
   ```bash
   # macOS
   open -a Docker

   # Linux
   sudo systemctl start docker

   # Windows
   # Start Docker Desktop from Start Menu
   ```

2. **Wait for Docker to be ready** (~30 seconds)

3. **Start Rowanholt services**
## Run Your First Test

```bash
cd tests
./scripts/run_single_test.sh win_brisk
```

Expected output:
```
======================================
Single Test Runner with Auto-Restart
======================================
Test: win_brisk
Started: Mon Jan 12 16:30:00 GMT 2026
...

✓ win_brisk PASSED

Restarting Docker to free resources...
```

## Run a Quick Batch

```bash
cd tests/scripts/batch
./batch1a-archive-lnk.sh
```

This runs 2 tests (~65 minutes total):
- `win_archive`
- `win_collect_files_lnk`

## Check Results

```bash
# Check job status
./scripts/status.sh

# Show full job IDs
./scripts/status.sh --full

# List test outputs
ls -lh /Volumes/Media5TB/rowanholt_imgs/tests/

# View a test's artifacts
ls -la /Volumes/Media5TB/rowanholt_imgs/tests/win_brisk/
```

## Common Issues

### "WARNING: Docker is not running"
The script will ask if you want to start Docker automatically:
- Press `Y` or Enter to start automatically (macOS/Linux)
- Press `N` to exit and start Docker manually

### "Could not connect to API"
Restart the backend:
```bash
docker restart rowanholt-backend rowanholt-celery-worker
sleep 30
```

### Job is Stuck or Taking Too Long
Stop the stuck job:
```bash
# Check status and get job ID
./scripts/status.sh --full

# Stop specific job
./scripts/stop-jobs.sh <job-id>

# Or stop all jobs
./scripts/stop-jobs.sh
```

### "No space left on device"
Clean old test outputs:
```bash
rm -rf /Volumes/*/rowanholt_imgs/tests/win_*
```

## Next Steps

- Read the full guide: `docs/TEST_RUNNER_GUIDE.md`
- Run more batches: `cd scripts/batch && ls batch*.sh`
- Run all tests: `cd scripts/batch && ./RUN_ALL_TESTS.sh` (~9-10 hours)

## Quick Reference

### Running Tests

| Command | Purpose | Duration |
|---------|---------|----------|
| `./scripts/run_single_test.sh win_brisk` | Quick test | ~10 min |
| `./scripts/batch/batch1a-archive-lnk.sh` | Quick batch | ~65 min |
| `./scripts/batch/batch4a-brisk.sh` | Single fast test | ~10 min |
| `./scripts/batch/RUN_ALL_TESTS.sh` | All tests (1-4) | ~9-10 hrs |

### Job Management

| Command | Purpose |
|---------|---------|
| `./scripts/status.sh` | Check job status |
| `./scripts/status.sh --full` | Show full job IDs |
| `./scripts/status.sh --watch` | Auto-refresh status |
| `./scripts/stop-jobs.sh` | Stop all jobs |
| `./scripts/stop-jobs.sh <job-id>` | Stop specific job |

