# Dernvale Image Combination Tests

This directory contains test definitions and tooling for validating Dernvale's forensic image processing capabilities across different combinations of images and options.

## Quick Start

```bash
# List all available tests
python3 tests/scripts/run_test.py --list

# Run a specific test
python3 tests/scripts/run_test.py --run win_brisk

# Generate JSON files for Web UI
python3 tests/scripts/run_test.py --generate-jobs
```

## Prerequisites

```bash
# Install required Python package
pip install requests
```

## Test Script Usage

### List Tests

```bash
# List all 120 test cases
python3 tests/scripts/run_test.py --list

# Filter by tags
python3 tests/scripts/run_test.py --list --tags windows
python3 tests/scripts/run_test.py --list --tags memory quick
```

### Show Test Details

```bash
python3 tests/scripts/run_test.py --show win_vss
```

### Run Tests via API

```bash
# Run a single test (submits job and returns immediately)
python3 tests/scripts/run_test.py --run win_brisk

# Run and wait for completion
python3 tests/scripts/run_test.py --run win_brisk --wait

# Run all tests matching tags
python3 tests/scripts/run_test.py --run-tags windows quick

# Use custom API URL
python3 tests/scripts/run_test.py --run win_brisk --api-url http://192.168.1.100:5688
```

### Generate Job JSON Files

```bash
# Generate to default directory (tests/jobs/)
python3 tests/scripts/run_test.py --generate-jobs

# Generate to custom directory
python3 tests/scripts/run_test.py --generate-jobs --output-dir /path/to/jobs
```

### Validate Test Images

```bash
# Check if test images exist on disk
python3 tests/scripts/run_test.py --validate
```

## Using JSON Files in Web UI

The Web UI supports loading test configurations from JSON files:

1. **Generate JSON files:**
   ```bash
   python3 tests/scripts/run_test.py --generate-jobs
   ```

2. **Open Web UI:** Navigate to http://localhost:5687

3. **Create New Analysis:** Click "New Analysis"

4. **Select JSON Mode:** Under "Analysis Mode", select **JSON**

5. **Load Configuration:** A file picker will open - select a JSON file from `tests/jobs/`

6. **Review & Submit:** The form will be auto-populated with:
   - Case number
   - Source image paths
   - All processing options

   Review the settings and click "Start Analysis"

## JSON File Format

Test configuration JSON files follow this structure:

```json
{
  "case_number": "TEST_win_vss",
  "source_paths": [
    "/Volumes/Media5TB/dernvale_imgs/win7-64-nfury-c-drive.E01"
  ],
  "destination_path": "/tmp/dernvale_tests/win_vss",
  "options": {
    "local": true,
    "gandalf": false,
    "analysis": false,
    "extract_iocs": false,
    "timeline": false,
    "memory": false,
    "memory_timeline": false,
    "keywords": false,
    "yara": false,
    "collectFiles": false,
    "brisk": false,
    "vss": true,
    "symlinks": false,
    "userprofiles": false,
    "nsrl": false,
    "hash_collected": false,
    "hash_all": false,
    "splunk": false,
    "elastic": false,
    "navigator": false
  }
}
```

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `case_number` | string | Unique case identifier (min 6 chars) |
| `source_paths` | array | List of full paths to disk/memory images |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `destination_path` | string | Output directory (defaults to `/tmp/dernvale/<case_number>`) |
| `options` | object | Processing options (see below) |

### Processing Options

| Option | Type | Description |
|--------|------|-------------|
| `local` | bool | Local disk/memory image analysis (default: true) |
| `gandalf` | bool | Process pre-collected Gandalf artifacts |
| `analysis` | bool | Run automated analysis |
| `extract_iocs` | bool | Extract IOCs from artifacts |
| `vss` | bool | Process Volume Shadow Copies (Windows) |
| `timeline` | bool | Generate Plaso timeline |
| `memory` | bool | Process memory images with Volatility |
| `memory_timeline` | bool | Generate memory timeline |
| `userprofiles` | bool | Collect user profiles |
| `collectFiles` | bool | Collect all files from image |
| `collectFiles_filter` | string | File extensions filter (e.g., "exe,dll,sys") |
| `keywords` | bool | Enable keyword searching |
| `keywords_file` | string | Path to keywords file |
| `yara` | bool | Enable YARA scanning |
| `yara_dir` | string | Path to YARA rules directory |
| `nsrl` | bool | Compare hashes against NSRL |
| `hash_collected` | bool | Hash collected files |
| `brisk` | bool | Fast processing mode |
| `symlinks` | bool | Follow symbolic links |
| `splunk` | bool | Export to Splunk |
| `elastic` | bool | Export to Elasticsearch |
| `navigator` | bool | Generate MITRE ATT&CK Navigator layer |

## Test Categories

### Windows Tests (22 tests)
- Basic processing, VSS, user profiles, file collection
- Analysis, IOC extraction, timeline, hashing
- SIEM exports (Splunk, Elastic), ATT&CK Navigator
- Keywords, YARA, archive, debug modes

### Linux Tests (20 tests)
- Full coverage matching Windows options
- Symlinks support

### macOS Tests (19 tests)
- Full coverage matching Windows options

### Memory Tests (6 tests)
- Windows, Linux, macOS memory processing
- Combined disk + memory analysis

### Multi-Image Tests (5 tests)
- Cross-platform combinations
- Stress tests with all images

### Gandalf Tests (1 test)
- Pre-collected artifact processing

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TEST_IMAGES_PATH` | `/Volumes/Media5TB/dernvale_imgs` | Directory containing test images |
| `TEST_OUTPUT_PATH` | `/Volumes/Media5TB/dernvale_imgs/tests` | Output directory for test results |
| `DERNVALE_API_URL` | `http://localhost:5688` | Backend API URL |

## Tags Reference

Tests are tagged for easy filtering:

- **Platform:** `windows`, `linux`, `macos`
- **Type:** `disk`, `memory`, `combined`, `multi`
- **Speed:** `quick`, `slow`, `very_slow`
- **Feature:** `analysis`, `vss`, `timeline`, `keywords`, `yara`, `iocs`, `hashing`, `nsrl`
- **Output:** `splunk`, `elastic`, `navigator`, `archive`
- **Mode:** `gandalf`, `brisk`, `debug`, `comprehensive`, `stress`

Example: Find all quick Windows tests:
```bash
python3 tests/scripts/run_test.py --list --tags windows quick
```

## Adding New Tests

Edit `tests/scripts/run_test.py` and add a new `TestCase` to the appropriate list:

```python
TestCase(
    name="win_custom_test",
    description="Windows disk image with custom options",
    images=[WIN_DISK_IMAGE],
    options={
        "analysis": True,
        "vss": True,
        "custom_option": True,
    },
    expected_outputs=["artefacts/cooked/", "analysis/"],
    tags=["windows", "custom"],
    estimated_duration_minutes=60,
),
```
