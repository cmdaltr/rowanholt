# Rowanholt Forensic Platform - Key Functionality

This document describes the critical architectural features and operational characteristics of the Rowanholt forensic analysis platform.

**Contents:**
- [Integration Summary](#integration-summary)
- [Progress Tracking](#progress-tracking)
- [Deferred Memory Processing](#deferred-memory-processing)
- [File Descriptor Management](#file-descriptor-management)
- [OrbStack File Handle Accumulation](#orbstack-file-handle-accumulation)

---

# Integration Summary

## ✅ File Descriptor Retry Logic Integration

The retry-on-file-descriptor-limit logic has been integrated into the critical file processing paths of Rowanholt.

### Files Modified

#### 1. **File Collection** (`rowanholt/collect/files/compare.py`)

**Changes:**
- Added imports: `from analysis.utils import retry_on_fd_limit, safe_open`
- Wrapped `compare_include_exclude()` with `@retry_on_fd_limit(max_retries=10, initial_wait=1.0, max_wait=30.0)`
- Replaced `open()` with `safe_open()` for include/exclude filter files (2 instances)

**Impact:**
- All file collection operations now automatically retry on FD exhaustion
- 10 retries with 1-30 second waits (exponential backoff)
- Critical for tests like `win_collect_files_*` that process thousands of files

#### 2. **IOC Extraction** (`rowanholt/analysis/iocs.py`)

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

## Three-Layer Defense

1. **Prevention** (Docker limits: 65,536)
   - Prevents most FD exhaustion issues

2. **Recovery** (Retry logic with GC)
   - Automatically recovers from FD exhaustion
   - Triggers garbage collection to free handles
   - Waits for system cleanup

3. **Isolation** (30s delays between tests)
   - Allows full cleanup between batch tests

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

---

# Progress Tracking

This section describes how progress percentage is calculated during forensic analysis jobs.

## Overview

Progress is tracked per-image and scaled to overall job progress:
- Each image gets a proportional share of 0-95% progress
- Final 5% (95-100%) is reserved for job completion
- Progress never goes backwards

## Phase Transitions

| Trigger Message | Internal Progress |
|-----------------|-------------------|
| Identification phase | 5% |
| Scanning for forensic images | 7% |
| Found forensic image | 8% |
| **Commencing Collection Phase** | **10%** |
| Identifying operating system | 12% |
| Identified platform | 15% |
| **Completed Collection Phase** | **35%** |
| Scanning for artefacts | 40% |
| **Commencing Processing Phase** | **45%** |
| **Completed Processing Phase** | **70%** |
| **Commencing Analysis Phase** | **75%** |
| **Completed Analysis Phase** | **95%** |
| Splunk/Elastic/Navigator phases | 97% |
| Rowanholt completed | 95% (overall) |

## Collection Sub-Steps (Windows)

| Trigger Message | Progress Range |
|-----------------|----------------|
| Collecting artefacts for... | 12% → 25% |
| Copying full user profile | 25% → 33% |
| Completed copying profile | 26% → 34% |
| Collecting registry/WMI/WBEM | 30% → 34% |
| Collected event logs | 34% |
| Recovered ($I30 records) | 35% |

## Collection Sub-Steps (Linux)

| Trigger Message | Progress Range |
|-----------------|----------------|
| /etc/passwd, shadow, group, hosts | 18% → 24% |
| Configuration files | 20% → 28% |
| Crontab | 22% → 28% |
| Bash history/files | 24% → 30% |
| Service files (systemd) | 26% → 32% |
| Systemd journal | 28% → 34% |
| Keyrings | 30% → 34% |

## Collection Sub-Steps (macOS)

| Trigger Message | Progress Range |
|-----------------|----------------|
| /etc/passwd, shadow, group, hosts | 18% → 24% |
| Crontab | 22% → 28% |
| Plist files | 24% → 33% |
| LaunchAgents/LaunchDaemons | 26% → 32% |
| StartupItems | 28% → 33% |
| Trash files | 30% → 34% |

## Shared (Linux/macOS)

| Trigger Message | Progress Range |
|-----------------|----------------|
| Log files (/var/log, /Library/Logs) | 22% → 30% |
| Temp files (/tmp) | 32% → 34% |
| Memory files (sleepimage, swapfile) | 33% → 35% |

## Processing & Analysis

| Phase | Progress Range |
|-------|----------------|
| Processing/parsing | 45% → 65% |
| Analyzing | 75% → 93% |

## Generic Fallback

| Trigger Message | Progress Range |
|-----------------|----------------|
| General "collecting/mounting" | 15% → 32% |

## Multi-Image Scaling

Progress is dynamically scaled based on the total number of images being analyzed.

### How it works

1. **Initial estimate**: Progress starts with an estimate from `source_paths` count
2. **Dynamic adjustment**: When elrond reports "Processing image X of Y", the system uses Y as the actual image count
3. **Progress range**: 95% is divided equally among all images (5% reserved for completion)

### Example: 3 images

| Image | Progress Range |
|-------|----------------|
| Image 1 of 3 | 0% - 31.6% |
| Image 2 of 3 | 31.6% - 63.3% |
| Image 3 of 3 | 63.3% - 95% |

### Example: 2 images

| Image | Progress Range |
|-------|----------------|
| Image 1 of 2 | 0% - 47.5% |
| Image 2 of 2 | 47.5% - 95% |

### Example: 1 image

| Image | Progress Range |
|-------|----------------|
| Image 1 of 1 | 0% - 95% |

Each image's internal progress (0-100% scale) is mapped to its allocated range. For example, if Image 2 of 3 is at 50% internal progress, the overall job progress would be: `31.6% + (31.6% × 0.5) = 47.4%`

## Implementation

Progress tracking is implemented in `src/web/backend/tasks_docker.py` in the `start_analysis` task.

Key variables:
- `total_images`: Total number of images being analyzed (dynamically updated from elrond output)
- `image_progress_range`: Progress range allocated to each image (95 / total_images)
- `image_base_progress`: Starting progress for current image
- `image_internal_progress`: Progress within current image (0-100 scale)
- `actual_image_count_detected`: Flag indicating if elrond has reported the actual image count
- `progress_count`: Number of log lines processed

Progress is saved to the job storage every 10 log lines.

## DEBUG Messages

Debug messages (MITRE enrichment, verbose command output) are filtered out by default.
They only appear in the job log if the "Debug" option is enabled in the Web UI.

---

# Deferred Memory Processing

## Overview

Rowanholt/Elrond implements a **deferred memory processing** architecture that separates disk image collection from memory image processing. This ensures proper phase separation and prevents processing conflicts when both disk and memory images are provided together.

## Key Concept

**Memory images are "parked" during the Collection Phase and processed after disk image collection completes.**

This is critical because:
- Disk and memory images require different processing pipelines
- Memory images should not interfere with disk artifact collection
- Volatility processing for memory images can be resource-intensive
- Phase separation provides clearer progress tracking and error handling

## Image Format

Images are identified using a three-part format:

```
filename::mount_point::type
```

**Examples:**
- `win7-64-disk.E01::/mnt/elrond_mount00::disk`
- Linux: `win7-64-nfury-memory-raw.001::/mnt/external/rowanholt_imgs/::memory`
- macOS: `win7-64-nfury-memory-raw.001::/Volumes/ExternalDrive/rowanholt_imgs/::memory`
- Windows: `win7-64-nfury-memory-raw.001::D:/rowanholt_imgs/::memory`

**Field Breakdown:**
- **[0] filename**: The base image filename
- **[1] mount_point**: Where the image is mounted (for disk) or source directory (for memory)
- **[2] type**: Either `disk` or `memory`

## Processing Phases

### Phase 1: Identification (in elrond.py)

When images are first identified:

1. **Disk images**: Added to `imgs` dict for immediate processing
2. **Memory images**:
   - Profile identified via `identify_memory_image()`
   - Profile saved to `.memory_profiles.json` via `save_memory_profile()`
   - **NOT added to `imgs` dict** - they are "parked"

**Location**: `src/analysis/rowanholt/core/identify.py:186`

```python
# The actual memory processing (artefact extraction) is deferred to the
# processing phase via process_deferred_memory().
```

### Phase 2: Collection (collect.py)

**Only disk images are processed during collection.**

Memory images should be filtered out using image type detection:

```python
# CORRECT way to check image type:
img_type = img.split("::")[2] if len(img.split("::")) > 2 else ""
if img_type != "memory":
    # Process disk artifacts
```

**Location**: `src/analysis/rowanholt/collect/collect.py:161-405`

### Phase 3: Processing (select.py)

**Only disk artifacts are processed during the main processing phase.**

Memory images must be excluded from artifact processing:

```python
# CORRECT way to filter out memory images:
img_type = img.split("::")[2] if len(img.split("::")) > 2 else ""
if img_basename not in str(processed_imgs) and img_type != "memory":
    # Process disk artifacts
```

**Location**: `src/analysis/rowanholt/process/select.py:113-117`

### Phase 3b: Deferred Memory Processing (elrond.py)

**After all disk images are processed**, memory images are loaded from the saved profiles:

```python
# Load saved memory profiles
has_deferred_memory = bool(load_memory_profiles(output_directory))
if volatility or has_deferred_memory:
    process_deferred_memory(
        verbosity,
        output_directory,
        flags,
        mount_point,
    )
```

**Location**: `src/analysis/elrond.py:730-737`

**Implementation**: `src/analysis/rowanholt/core/identify.py:275-359`

The `process_deferred_memory()` function:
1. Loads profiles from `.memory_profiles.json`
2. For each saved memory image:
   - Reconstructs the image info
   - Calls `process_memory()` with Volatility 3
   - Extracts memory artifacts to output directory

### Phase 4: Analysis

All images (disk and memory) are analyzed for IOCs, keywords, YARA rules, etc.

## Memory Profile Storage

Profiles are saved to: `{output_directory}/.memory_profiles.json`

**Example profile (macOS):**
```json
{
  "win7-64-nfury-memory-raw.001": {
    "profile": "Windows",
    "platform": "Windows memory",
    "volchoice": "3",
    "path": "/Volumes/ExternalDrive/rowanholt_imgs/win7-64-nfury-memory-raw.001",
    "mount_point": "/Volumes/ExternalDrive/rowanholt_imgs/",
    "vss": false,
    "vssmem": "",
    "memtimeline": ""
  }
}
```

## Critical Bug: Image Type Detection (FIXED)

### The Bug

**Three locations were checking the WRONG index** when determining image type:

```python
# WRONG - checks mount_point (index 1):
if img.split("::")[1].endswith("memory"):
    # ...

# CORRECT - checks type (index 2):
img_type = img.split("::")[2] if len(img.split("::")) > 2 else ""
if img_type == "memory":
    # ...
```

### Affected Files (FIXED)

1. **select.py:113-117** - Processing phase artifact filtering
2. **collect.py:183-184** - Collection phase memory detection
3. **core.py:232-234** - Timeline phase memory filtering

## RecursionError Fix: `hiberfil.sys` Processing

### The Problem

Tests were failing with `RecursionError: maximum recursion depth exceeded` at 38% of Processing Phase when processing `hiberfil.sys`.

### Root Cause

`hiberfil.sys` (hibernation file) found on disk images was being processed **synchronously during the disk Processing Phase** using the full memory processing pipeline. Volatility 3's plugin system has deep internal call stacks that exceeded Python's default recursion limit (1000).

### The Fix

**Increased Python recursion limit during the Processing Phase** to handle Volatility's deep call stacks.

**Implementation**: `src/analysis/rowanholt/process/select.py`

```python
def select_pre_process_artefacts(...):
    # Increase recursion limit for Volatility processing
    original_recursion_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(5000)

    try:
        # ... all processing logic ...
    finally:
        # Restore original recursion limit
        sys.setrecursionlimit(original_recursion_limit)
```

### Why This is Correct

- **Standalone memory images** (`.raw`, `.mem`): Should be deferred to Phase 3b
- **`hiberfil.sys`** (disk artifact): Should be collected and processed during disk phases

The recursion issue is not architectural - it's simply that Volatility's deep processing exceeds Python's default recursion limit.

## Workflow Diagram

```
┌─────────────────────────────────────────────────┐
│ Phase 1: Identification                         │
├─────────────────────────────────────────────────┤
│ ┌─────────────┐          ┌──────────────┐      │
│ │ Disk Image  │──────────>│ Add to imgs  │      │
│ └─────────────┘          └──────────────┘      │
│                                                  │
│ ┌──────────────┐         ┌────────────────────┐│
│ │ Memory Image │────────>│ Save to            ││
│ └──────────────┘         │ .memory_profiles   ││
│                          │ (PARKED)           ││
│                          └────────────────────┘│
└─────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────┐
│ Phase 2: Collection                             │
├─────────────────────────────────────────────────┤
│ Process ONLY disk images from imgs dict         │
│ - Filter: img_type != "memory"                  │
│ - Collect system artifacts                      │
│ - Extract files                                 │
└─────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────┐
│ Phase 3: Processing                             │
├─────────────────────────────────────────────────┤
│ Process ONLY disk artifacts                     │
│ - Filter: img_type != "memory"                  │
│ - Parse registry, logs, browsers, etc.          │
└─────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────┐
│ Phase 3b: Deferred Memory Processing            │
├─────────────────────────────────────────────────┤
│ Load .memory_profiles.json                      │
│ For each memory image:                          │
│   - Reconstruct image info                      │
│   - Run Volatility 3 plugins                    │
│   - Extract memory artifacts                    │
└─────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────┐
│ Phase 4: Analysis                               │
├─────────────────────────────────────────────────┤
│ Analyze ALL artifacts (disk + memory)           │
│ - IOC extraction                                │
│ - Keyword searching                             │
│ - YARA scanning                                 │
│ - Timeline generation                           │
└─────────────────────────────────────────────────┘
```

## File Locations

| File | Purpose | Key Functions/Lines |
|------|---------|-------------------|
| `src/analysis/elrond.py` | Main orchestration | Lines 730-737: Deferred memory processing |
| `src/analysis/rowanholt/core/identify.py` | Memory identification & deferred processing | Lines 17-42: save/load profiles<br>Lines 186: Deferral comment<br>Lines 275-359: process_deferred_memory() |
| `src/analysis/rowanholt/core/core.py` | Phase orchestration | Lines 54-121: Phase control logic |
| `src/analysis/rowanholt/collect/collect.py` | Artifact collection | Lines 161-405: Collection loop<br>Lines 183-184: Memory filtering |
| `src/analysis/rowanholt/process/select.py` | Artifact processing | Lines 113-117: Memory filtering |
| `src/analysis/rowanholt/memory/memory.py` | Memory processing | Lines 131-322: process_memory() |

---

# File Descriptor Management

## Problem

When processing large forensic images, Rowanholt can hit the operating system's file descriptor limit, causing this error:

```
OSError: [Errno 24] Too many open files: '/path/to/file'
```

This happens when:
- Processing many small files simultaneously
- Collecting files from large disk images
- Running multiple tests back-to-back without cleanup

## Solution: Automatic Retry Logic

We've implemented **automatic retry logic** that gracefully handles file descriptor exhaustion:

1. **Catches the error** instead of failing immediately
2. **Triggers garbage collection** to close unreferenced file handles
3. **Waits with exponential backoff** to allow system cleanup
4. **Retries the operation** up to 5 times
5. **Only fails** if all retries are exhausted

## Usage

### Option 1: Decorator (Recommended for Functions)

Wrap any function that opens many files:

```python
from analysis.utils import retry_on_fd_limit

@retry_on_fd_limit(max_retries=5, initial_wait=0.5)
def process_collected_files(file_paths):
    """Process a large collection of files."""
    results = []
    for path in file_paths:
        with open(path, 'rb') as f:
            data = f.read()
            results.append(analyze(data))
    return results

# Function will automatically retry if it hits file descriptor limits
results = process_collected_files(many_files)
```

### Option 2: Safe Open (Drop-in Replacement)

Replace `open()` with `safe_open()`:

```python
from analysis.utils import safe_open

# Before:
with open('/path/to/file', 'r') as f:
    data = f.read()

# After:
with safe_open('/path/to/file', 'r') as f:
    data = f.read()
```

### Option 3: Monitor File Descriptor Usage

Check usage and get warnings:

```python
from analysis.utils import check_fd_usage, get_fd_limit

# Check current usage
stats = check_fd_usage(warn_threshold=0.8)
print(f"FD usage: {stats['used']}/{stats['soft_limit']} ({stats['percent']}%)")

# Get limits
soft, hard = get_fd_limit()
print(f"Limits: {soft} (soft), {hard} (hard)")
```

## Configuration

### Decorator Options

```python
@retry_on_fd_limit(
    max_retries=5,          # Number of retry attempts
    initial_wait=0.5,       # Initial wait time (seconds)
    backoff_multiplier=2.0, # Exponential backoff multiplier
    max_wait=10.0,          # Maximum wait between retries
    trigger_gc=True         # Trigger garbage collection on retry
)
def my_function():
    pass
```

## Benefits

### Before (Hard Failure)

```
Processing files...
OSError: [Errno 24] Too many open files
❌ Test FAILED
```

### After (Automatic Recovery)

```
Processing files...
⚠️  File descriptor limit reached (attempt 1/5): Too many open files.
    Waiting 0.5s and retrying...
✓ Garbage collection freed 127 objects
✓ Retry successful
✓ Test PASSED
```

## Docker Configuration

We've already increased Docker container limits:

```yaml
services:
  celery-worker:
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
```

Combined with the retry logic, this provides:
1. **High limits** (65,536) to prevent most errors
2. **Automatic retry** if limits are still hit
3. **Graceful degradation** instead of hard failures

## Testing

Test the retry logic:

```bash
# Run the utility test
python3 src/analysis/utils/file_limits.py
```

Expected output:
```
File Descriptor Limit Management Utility
==================================================
Current FD limits: 65536 (soft), 65536 (hard)
Currently open FDs: 42
Function executed successfully
Test result: success
```

---

# OrbStack File Handle Accumulation

## Problem

OrbStack on macOS accumulates **~8,000 file handles per file collection test** from Docker volume mounts (`/Volumes/Media5TB/rowanholt_imgs`). These handles are **not released** even after:
- Tests complete
- Containers stop
- Containers restart

### Impact
- **macOS system limit**: ~122,880 total open files
- **After 1-2 tests**: Approaching system limit
- **Subsequent tests fail**: `[Errno 23] Too many open files in system`

## Root Cause

This is a **known limitation** with Docker on macOS (both Docker Desktop and OrbStack):
- File handles from volume mounts persist at the host level
- macOS doesn't aggressively release handles from container filesystem operations
- Large forensic file collection operations (processing thousands of files) accumulate handles rapidly

## Evidence

```bash
# Before any tests
$ lsof | grep "/Volumes/Media5TB/rowanholt_imgs" | wc -l
0

# After win_collect_files_lnk (13m, collected 97 LNK files + 1.7GB artifacts)
$ lsof | grep "/Volumes/Media5TB/rowanholt_imgs" | wc -l
4243

# After win_collect_files_docs (also successful)
$ lsof | grep "/Volumes/Media5TB/rowanholt_imgs" | wc -l
8008

# After win_collect_files_mail (12m, successful)
$ lsof | grep "/Volumes/Media5TB/rowanholt_imgs" | wc -l
7998
```

### Which Tests Are Affected

**High accumulation** (require cleanup):
- `win_collect_files_lnk` - LNK shortcut files
- `win_collect_files_docs` - Document files
- `win_collect_files_bin` - Binary files
- `win_collect_files_mail` - Email files (PST/OST)
- `win_collect_files_scripts` - Script files
- `win_collect_files_hidden` - Hidden files
- `win_collect_files_virtual` - Virtual machine files
- `win_collect_files_web` - Web browser artifacts

**Lower accumulation** (usually OK):
- Processing-only tests (no large file collection)
- Memory analysis tests
- Timeline generation
- IOC extraction

## Solution Implemented

### 1. Automatic Cleanup in Batch Scripts

**ALL batch scripts** now automatically clean up file handles in two ways:

#### A. Pre-Batch Cleanup (ALL scripts)
Every batch script now checks for and cleans up file handles from previous runs BEFORE starting any tests:

```bash
# Pre-batch cleanup: Clear any existing file handles from previous runs
HANDLE_COUNT=$(lsof 2>/dev/null | grep "/Volumes/Media5TB/rowanholt_imgs" | wc -l | tr -d " \n" || echo "0")
if [ "$HANDLE_COUNT" -gt 100 ]; then
    echo "⚠️  Found $HANDLE_COUNT file handles - cleaning up before starting batch..."
    # Stop containers, restart OrbStack, restart Rowanholt
    ...
    echo "✓ Pre-batch cleanup complete"
fi
```

**Updated scripts:** All 20 batch scripts (1a through 5d)

#### B. Between-Test Cleanup (File collection scripts only)
File collection batch scripts also clean up between tests when handle count exceeds 1,000:

**Scripts with between-test cleanup:**
- `tests/scripts/batch/1b_collect--lnk-docs.sh`
- `tests/scripts/batch/1c_collect--bin-hidden-scripts.sh`
- `tests/scripts/batch/1d_collect--mail-virtual-web.sh`

**Cleanup logic:**
```bash
# Check file handle count and cleanup if needed
HANDLE_COUNT=$(lsof 2>/dev/null | grep "/Volumes/Media5TB/rowanholt_imgs" | wc -l | tr -d " \n" || echo "0")
if [ "$HANDLE_COUNT" -gt 1000 ]; then
    echo "⚠️  High file handle count ($HANDLE_COUNT) - cleaning up OrbStack..."
    # Stop containers, restart OrbStack, restart Rowanholt
    ...
    echo "✓ Cleanup complete - continuing tests..."
fi
```

**Threshold lowered:** From 5,000 to 1,000 handles for more proactive cleanup

### 2. Manual Cleanup Script

Created helper script for manual cleanup between test batches:

**Script:** `scripts/cleanup-orbstack-handles.sh`

**Usage:**
```bash
cd /Users/ben/Library/CloudStorage/OneDrive-Personal/Projects/GitHub/rowanholt
./scripts/cleanup-orbstack-handles.sh

# Or force cleanup even below threshold
./scripts/cleanup-orbstack-handles.sh --force
```

### 3. Fixed Batch Script Exit Code Bug

**Problem:** Batch scripts were reporting "PASSED" for failed tests because they checked the exit code of `tee` (which always succeeds) instead of the python script.

**Fix:** Changed from:
```bash
if python3 scripts/run_test.py --run "$test" -y --wait 2>&1 | tee -a "$LOG_FILE"; then
    echo "✓ $test PASSED"
```

To:
```bash
python3 scripts/run_test.py --run "$test" -y --wait 2>&1 | tee -a "$LOG_FILE"

# Check the exit code of the python script (PIPESTATUS[0]), not tee
if [ "${PIPESTATUS[0]}" -eq 0 ]; then
    echo "✓ $test PASSED"
```

Applied to all 20 batch scripts.

## Monitoring File Handles

Check current file handle usage:
```bash
# Total rowanholt-related handles
lsof | grep "rowanholt" | wc -l

# Handles on test volume
lsof | grep "/Volumes/Media5TB/rowanholt_imgs" | wc -l

# Detailed view
lsof -p $(pgrep OrbStack | head -1) | grep "/Volumes/Media5TB/rowanholt_imgs" | head -30
```

## When to Run Cleanup

### Automatic Cleanup (Built-in)

**All batch scripts** now automatically handle cleanup:

1. **Pre-batch cleanup:** Every batch script checks and cleans up file handles BEFORE starting tests (threshold: >100 handles)
2. **Between-test cleanup:** File collection scripts (1b, 1c, 1d) also clean up between tests (threshold: >1,000 handles)

**This means you usually don't need to manually run cleanup before batch tests anymore!** The scripts will handle it automatically.

### Manual Cleanup (Optional)

You may still want to manually run cleanup in these scenarios:

```bash
# From project root
./scripts/cleanup-orbstack-handles.sh
```

**When to use:**
- Before running individual tests (non-batch) if you've accumulated handles
- To force cleanup even if below threshold (use `--force` flag)
- When debugging file handle issues
- Between very large test batches if you want to ensure a clean slate

## Alternative Solutions Considered

### ❌ Increase macOS system limits
- Requires SIP disabling (security risk)
- Temporary - doesn't address root cause
- May hit other system constraints

### ❌ Use Docker volumes instead of host mounts
- Would avoid this issue entirely
- **BUT:** Forensic images (10-30GB each) must stay on external drive
- No practical way to move images into Docker volumes

### ❌ Restart containers only (not OrbStack)
- **Doesn't work** - handles are held by OrbStack itself
- Tested: restarting containers leaves handles open

### ✅ Restart OrbStack between tests
- **Most reliable solution**
- Guarantees handle release
- ~20 second overhead per cleanup
- Acceptable tradeoff for batch testing

## Integration: Retry Logic + OrbStack Cleanup

The retry logic implemented in `utils/file_limits.py` is still valuable:
- Handles transient FD exhaustion during test execution
- Provides exponential backoff and garbage collection
- Adds resilience to individual tests
- **However:** Does NOT solve the OrbStack handle accumulation issue

Both solutions work together:
- **Retry logic**: Handles in-test FD issues (container-level)
- **OrbStack restart**: Cleans up between-test accumulation (host-level)

---

# Summary

## Three-Layer File Descriptor Strategy

1. **Prevention** (Docker limits)
   - Increased Docker container limits to 65,536
   - Prevents most FD exhaustion errors

2. **Recovery** (Retry logic)
   - Automatic retry with exponential backoff
   - Garbage collection on retry
   - Graceful handling of transient FD issues

3. **Cleanup** (OrbStack management)
   - Automatic pre-batch cleanup (threshold: 100 handles)
   - Automatic between-test cleanup for file collection (threshold: 1,000 handles)
   - Manual cleanup script for edge cases

## Best Practices

1. **Always close files explicitly** - Don't rely on garbage collection
2. **Use context managers** - `with open()` ensures cleanup
3. **Process in batches** - Don't open 10,000 files at once
4. **Monitor usage** - Log FD usage at operation boundaries
5. **Use `safe_open`** - For code that must be bulletproof
6. **Trust automatic cleanup** - Batch scripts handle cleanup automatically

## Key Takeaways

- **Memory processing is deferred** - Never processed during disk Collection/Processing phases
- **Image type detection is critical** - Always check index [2] for image type
- **File descriptors have three solutions** - Prevention, recovery, and cleanup
- **Batch tests are automatic** - No manual cleanup required before running
- **OrbStack needs special handling** - Host-level handles require OrbStack restart
- **Progress tracking is multi-image aware** - Dynamic scaling based on actual image count
- **Integration is complete** - Retry logic applied to file collection and IOC extraction

---

**Last Updated**: 2026-01-16
**Contributors**: Investigation and implementation by Claude Code (Sonnet 4.5)
