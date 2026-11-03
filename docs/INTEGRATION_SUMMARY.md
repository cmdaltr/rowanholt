# File Descriptor Retry Logic - Integration Summary

## ✅ Changes Applied

The retry-on-file-descriptor-limit logic has been integrated into the critical file processing paths of Dernvale.

### Files Modified

#### 1. **File Collection** (`dernvale/collect/files/compare.py`)

**Changes:**
- Added imports: `from analysis.utils import retry_on_fd_limit, safe_open`
- Wrapped `compare_include_exclude()` with `@retry_on_fd_limit(max_retries=10, initial_wait=1.0, max_wait=30.0)`
- Replaced `open()` with `safe_open()` for include/exclude filter files (2 instances)

**Impact:**
- All file collection operations now automatically retry on FD exhaustion
- 10 retries with 1-30 second waits (exponential backoff)
- Critical for tests like `win_collect_files_*` that process thousands of files

#### 2. **IOC Extraction** (`dernvale/analysis/iocs.py`)

**Changes:**
- Added imports: `from analysis.utils import retry_on_fd_limit, safe_open`
- Wrapped `load_ioc_watchlist()` with `@retry_on_fd_limit(max_retries=5)`
- Wrapped `compare_iocs()` with `@retry_on_fd_limit(max_retries=10, initial_wait=1.0, max_wait=30.0)`
- Replaced `open()` with `safe_open()` for:
  - Watchlist file loading
  - IOC file reading during extraction

**Impact:**
- IOC extraction from collected files now resilient to FD limits
- Critical for tests like `win_extract_iocs` that scan many files

### How It Works

#### Before Integration:
```python
def collect_files(...):
    with open(file_path, 'r') as f:  # ❌ Fails immediately at limit
        data = f.read()
```

**Result:** `OSError: [Errno 24] Too many open files` → Test FAILS

#### After Integration:
```python
@retry_on_fd_limit(max_retries=10, initial_wait=1.0, max_wait=30.0)
def collect_files(...):
    with safe_open(file_path, 'r') as f:  # ✅ Retries with backoff
        data = f.read()
```

**Result:**
1. Hit FD limit → Trigger garbage collection
2. Wait 1.0s → Retry
3. If still failing → Wait 2.0s → Retry
4. Continue up to 10 times
5. If all retries exhausted → Raise `FileDescriptorLimitError` with helpful message

### Retry Configuration

| Function | Max Retries | Initial Wait | Max Wait | Use Case |
|----------|-------------|--------------|----------|----------|
| `compare_include_exclude()` | 10 | 1.0s | 30.0s | File collection - many files |
| `compare_iocs()` | 10 | 1.0s | 30.0s | IOC extraction - scan many files |
| `load_ioc_watchlist()` | 5 | 0.5s | 10.0s | Load single watchlist file |

### Benefits

1. **Graceful Degradation**: Tests don't fail immediately - they retry intelligently
2. **Automatic Cleanup**: Garbage collection frees unreferenced file handles
3. **Exponential Backoff**: Gives system time to recover
4. **Logging**: Clear warnings when retries happen (visible in logs)
5. **Ultimate Failure**: Still fails after all retries with helpful error message

### Example Log Output

#### Successful Retry:
```
WARNING:analysis.utils.file_limits:File descriptor limit reached in compare_include_exclude (attempt 1/10): [Errno 24] Too many open files: '/path/to/file'. Waiting 1.0s and retrying...
DEBUG:analysis.utils.file_limits:Garbage collection freed 127 objects, attempting to close file handles
✓ Test PASSED
```

#### Exhausted Retries (rare):
```
ERROR:analysis.utils.file_limits:File descriptor limit reached after 10 retries in compare_include_exclude: [Errno 24] Too many open files
FileDescriptorLimitError: Too many open files after 10 retries. Consider increasing ulimit or reducing concurrent file operations.
✗ Test FAILED
```

## Testing

### Before Rebuild

The current running containers (built before these changes) will **not** have the retry logic. Tests may still fail with "Too many open files".

### After Rebuild

Once containers are rebuilt, the retry logic will be active:

```bash
# Rebuild containers with new code
cd /Users/ben/Library/CloudStorage/OneDrive-Personal/Projects/GitHub/dernvale
./scripts/start-testing-mode.sh

# Test file collection (previously failing)
cd tests/scripts/batch
./1d_collect--mail-virtual-web.sh

# Should now see retry warnings instead of immediate failures
```

### Verification

Check logs for retry messages:
```bash
# Look for retry warnings
docker logs dernvale-celery-worker 2>&1 | grep "File descriptor limit reached"

# Look for successful completions after retries
docker logs dernvale-celery-worker 2>&1 | grep "Garbage collection freed"
```

## Additional Improvements

These files now also have:

1. **Docker ulimits**: Set to 65,536 (from 256) in `docker-compose.yml`
2. **Batch test delays**: 30s between tests in batch scripts (configurable)
3. **Safe open utility**: Drop-in replacement for `open()` with retry logic

## Three-Layer Defense

1. **Prevention** (Docker limits: 65,536)
   - Prevents most FD exhaustion issues

2. **Recovery** (Retry logic with GC) ← **NEW**
   - Automatically recovers from FD exhaustion
   - Triggers garbage collection to free handles
   - Waits for system cleanup

3. **Isolation** (30s delays between tests)
   - Allows full cleanup between batch tests

## Next Steps

1. **Rebuild containers** to apply changes:
   ```bash
   ./scripts/start-testing-mode.sh
   ```

2. **Run previously failing tests**:
   ```bash
   cd tests/scripts/batch
   ./1b_collect--lnk-docs.sh
   ./1c_collect--bin-hidden-scripts.sh
   ./1d_collect--mail-virtual-web.sh
   ```

3. **Monitor logs** for retry behavior:
   ```bash
   ./scripts/status.sh --watch
   ```

4. **Optional: Extend to other modules** if needed:
   - YARA scanning
   - Timeline generation
   - Memory analysis
   - Profile extraction

## Architecture

```
┌─────────────────────────────────────────┐
│  Test: win_collect_files_mail          │
│  Opening 10,000+ mail files             │
└────────────┬────────────────────────────┘
             │
             ↓
┌─────────────────────────────────────────┐
│  compare_include_exclude()              │
│  @retry_on_fd_limit(max_retries=10)     │
└────────────┬────────────────────────────┘
             │
             ↓ Hit FD limit (24 files open)
┌─────────────────────────────────────────┐
│  Retry Logic                            │
│  1. Catch OSError(errno.EMFILE)         │
│  2. Trigger gc.collect()                │
│  3. Wait with exponential backoff       │
│  4. Retry operation                     │
└────────────┬────────────────────────────┘
             │
             ↓ Retry successful
┌─────────────────────────────────────────┐
│  File collection continues              │
│  ✓ Test PASSES                          │
└─────────────────────────────────────────┘
```

## Summary

- ✅ **File collection** now resilient to FD limits
- ✅ **IOC extraction** now resilient to FD limits
- ✅ **Automatic retry** with garbage collection
- ✅ **Exponential backoff** prevents thrashing
- ✅ **Clear logging** shows retry behavior
- ✅ **Graceful failure** after exhausting retries

The integration is complete. Rebuild containers to activate!
