#!/usr/bin/env python3
"""
Automated Test Runner for Rowanholt

Runs all test cases sequentially (except Mordor tests) and updates TEST_RESULTS.md
with actual results including status, date, duration, and notes.

Usage:
    python3 run_all_tests.py           # Interactive mode with confirmation
    python3 run_all_tests.py --yes     # Auto-confirm and run all tests
"""

import sys
import time
import json
import subprocess
from datetime import datetime
from pathlib import Path
import requests
from typing import Dict, Optional, Tuple
import argparse

# Configuration
API_URL = "http://localhost:5688"
RESULTS_FILE = Path(__file__).parent / "TEST_RESULTS.md"
CONFIG_FILE = Path(__file__).parent.parent / "tests.conf"
API_TIMEOUT = 15
POLL_INTERVAL = 30  # seconds between status checks
MAX_JOB_DURATION = 7200  # 2 hours max per job


def get_available_tests() -> list:
    """Read tests from tests.conf (uncommented lines only)."""
    if not CONFIG_FILE.exists():
        print(f"Error: Config file not found: {CONFIG_FILE}")
        return []

    tests = []
    with open(CONFIG_FILE, "r") as f:
        for line in f:
            # Remove leading/trailing whitespace
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            # Add test name
            tests.append(line)

    return tests


def run_test(test_name: str) -> Tuple[bool, Optional[str], int, str]:
    """
    Run a single test and monitor it to completion.

    Returns:
        (success, job_id, duration_seconds, notes)
    """
    print(f"\n{'='*80}")
    print(f"Running test: {test_name}")
    print(f"{'='*80}")

    start_time = time.time()

    # Run the test
    result = subprocess.run(
        ["python3", "run_test.py", "--run", test_name, "-y"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent,
        timeout=60,  # Just for submission
    )

    # Extract job ID from output
    job_id = None
    for line in result.stdout.split("\n"):
        if "Job ID:" in line:
            job_id = line.split("Job ID:")[1].strip()
            break

    if not job_id:
        duration = int(time.time() - start_time)
        return False, None, duration, "Failed to submit job"

    print(f"  Job ID: {job_id}")
    print(f"  Monitoring progress...")

    # Monitor the job
    last_progress = -1
    stall_count = 0

    while True:
        elapsed = int(time.time() - start_time)

        # Check for timeout
        if elapsed > MAX_JOB_DURATION:
            return False, job_id, elapsed, f"Job timeout after {elapsed//60} minutes"

        # Get job status
        try:
            response = requests.get(
                f"{API_URL}/api/jobs/{job_id}",
                timeout=API_TIMEOUT,
            )

            if response.status_code != 200:
                time.sleep(POLL_INTERVAL)
                continue

            job = response.json()
            status = job.get("status")
            progress = job.get("progress", 0)

            # Print progress update
            if progress != last_progress:
                print(f"    Progress: {progress}% - Status: {status} - Elapsed: {elapsed//60}m")
                last_progress = progress
                stall_count = 0
            else:
                stall_count += 1

            # Check if job is done
            if status == "completed":
                duration = int(time.time() - start_time)
                print(f"  ✓ Test completed in {duration//60}m {duration%60}s")
                return True, job_id, duration, ""

            elif status == "failed":
                duration = int(time.time() - start_time)
                error = job.get("error", "Unknown error")
                print(f"  ✗ Test failed: {error}")
                return False, job_id, duration, error

            # Check for stalled job (only if running, not pending)
            # Allow up to 20 polls (10 minutes) with no progress before declaring stall
            if status == "running" and stall_count > 20:
                return False, job_id, elapsed, f"Job stalled at {progress}%"

        except requests.exceptions.RequestException as e:
            print(f"    API error: {e} - retrying...")

        time.sleep(POLL_INTERVAL)


def update_results_file(test_name: str, success: bool, duration: int, notes: str):
    """Update TEST_RESULTS.md with test results."""

    # Read current results
    with open(RESULTS_FILE, "r") as f:
        lines = f.readlines()

    # Determine status emoji and text
    if success:
        status = "🟢 SUCCESS"
    else:
        status = "🔴 FAILED"

    # Format date and duration
    date = datetime.now().strftime("%Y-%m-%d")
    duration_str = f"{duration//60}m" if duration >= 60 else f"{duration}s"

    # Sanitize notes for markdown
    notes = notes.replace("|", "\\|").replace("\n", " ")[:100]
    if not notes:
        notes = "-"

    # Find and update the test line
    updated = False
    for i, line in enumerate(lines):
        if f"| {test_name} |" in line:
            # Replace the line with updated results
            lines[i] = f"| {test_name} | {status} | {date} | {duration_str} | {notes} |\n"
            updated = True
            break

    if updated:
        # Write back
        with open(RESULTS_FILE, "w") as f:
            f.writelines(lines)
        print(f"  Updated TEST_RESULTS.md: {status}")
    else:
        print(f"  Warning: Could not find {test_name} in TEST_RESULTS.md")


def main():
    """Main test runner."""
    # Parse command line args
    parser = argparse.ArgumentParser(description="Run Rowanholt test suite")
    parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt")
    args = parser.parse_args()

    print("=" * 50)
    print("ROWANHOLT AUTOMATED TEST RUNNER")
    print("=" * 50)
    print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Config file: {CONFIG_FILE}")
    print(f"Results file: {RESULTS_FILE}")
    print(f"API URL: {API_URL}")
    print()

    # Get all tests from config
    print("Loading test configuration...")
    tests = get_available_tests()

    if not tests:
        print("Error: No tests found in config file!")
        print(f"Please check {CONFIG_FILE}")
        return 1

    print(f"Found {len(tests)} tests to run\n")

    # Show first 10 tests
    print("Tests to run:")
    for i, test in enumerate(tests[:10], 1):
        print(f"  {i}. {test}")
    if len(tests) > 10:
        print(f"  ... and {len(tests) - 10} more")
    print()

    # Confirmation prompt (unless --yes flag)
    if not args.yes:
        response = input("Continue with test run? [y/N]: ")
        if response.lower() != "y":
            print("Test run cancelled.")
            return 0
        print()
    else:
        print("Auto-confirmed (--yes flag), starting tests...\n")

    # Track results
    total_start = time.time()
    results = {
        "passed": 0,
        "failed": 0,
        "total": len(tests),
    }

    # Run each test
    for i, test_name in enumerate(tests, 1):
        print(f"\n[{i}/{len(tests)}] Running: {test_name}")

        try:
            success, job_id, duration, notes = run_test(test_name)

            # Update results
            if success:
                results["passed"] += 1
            else:
                results["failed"] += 1

            # Update TEST_RESULTS.md
            update_results_file(test_name, success, duration, notes)

            # Brief pause between tests
            if i < len(tests):
                print(f"\n  Waiting 10s before next test...")
                time.sleep(10)

        except KeyboardInterrupt:
            print("\n\nTest run interrupted by user!")
            break
        except Exception as e:
            print(f"\n  ✗ Exception running {test_name}: {e}")
            results["failed"] += 1
            update_results_file(test_name, False, 0, str(e))
            continue

    # Print summary
    total_duration = int(time.time() - total_start)
    print("\n" + "=" * 80)
    print("TEST RUN COMPLETE")
    print("=" * 50)
    print(f"Total tests: {results['total']}")
    print(f"Passed: {results['passed']} ✓")
    print(f"Failed: {results['failed']} ✗")
    print(f"Total time: {total_duration//3600}h {(total_duration%3600)//60}m")
    print(f"Results saved to: {RESULTS_FILE}")
    print("=" * 50)

    return 0 if results["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
