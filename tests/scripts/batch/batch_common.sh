#!/bin/bash
# Common functions for batch test scripts
# Source this file at the start of each batch script

# Set strict mode
set -e
set -o pipefail

# Setup directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[1]}")" && pwd)"
TEST_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
cd "$TEST_DIR"

# Default delay between tests (can be overridden)
DELAY_BETWEEN_TESTS=${DELAY_BETWEEN_TESTS:-30}

# ============================================================================
# Print header banner
# Usage: print_header "BATCH_ID" "BATCH_TITLE" "ESTIMATED_DURATION"
# ============================================================================
print_header() {
    local batch_id="$1"
    local batch_title="$2"
    local estimated_duration="$3"
    local log_file="$4"

    echo "=================================================="
    echo "  BATCH ${batch_id}: ${batch_title}"
    echo "=================================================="
    echo "Start: $(date +"%a %d-%b-%Y %H:%M:%S%Z")"
    echo "Log: ${log_file}"
    echo "Estimated duration: ${estimated_duration}"
    echo ""
}

# ============================================================================
# Print footer banner
# Usage: print_footer "BATCH_ID" "passed_count" "failed_count" "log_file"
# ============================================================================
print_footer() {
    local batch_id="$1"
    local passed="$2"
    local failed="$3"
    local log_file="$4"

    echo ""
    echo "=================================================="
    echo "  BATCH ${batch_id}: Completed"
    echo "  ----------------------------------------------"
    echo "Passed: ${passed}"
    echo "Failed: ${failed}"
    echo "End: $(date)"
    echo "Log: ${log_file}"
    echo "=================================================="
}

# ============================================================================
# Check and cleanup file handles from previous runs
# Usage: check_file_handles [threshold]
# ============================================================================
check_file_handles() {
    local threshold="${1:-100}"

    echo "Checking for file handles from previous runs..."
    HANDLE_COUNT=$(lsof 2>/dev/null | grep -c "/Volumes/Media5TB/rowanholt_imgs" 2>/dev/null) || HANDLE_COUNT=0

    if [ "$HANDLE_COUNT" -gt "$threshold" ]; then
        echo "⚠️  Found $HANDLE_COUNT file handles - cleaning up before starting batch..."
        cleanup_docker
        echo "✓ Pre-batch cleanup complete"
    else
        echo "✓ File handle count acceptable"
    fi
    echo ""
}

# ============================================================================
# Cleanup Docker and OrbStack
# ============================================================================
cleanup_docker() {
    local project_dir
    project_dir="$(dirname "$(dirname "$TEST_DIR")")"

    cd "$project_dir"
    docker-compose -f docker-compose.yml -f tests/docker-compose.testing.yml down >/dev/null 2>&1 || true
    orbctl stop && sleep 3 && orbctl start && sleep 5
    ./scripts/start-testing-mode.sh >/dev/null 2>&1 || true
    cd "$TEST_DIR"
}

# ============================================================================
# Run a batch of tests
# Usage: run_batch "BATCH_ID" "BATCH_TITLE" "ESTIMATED_DURATION" test1 test2 ...
# ============================================================================
run_batch() {
    local batch_id="$1"
    local batch_title="$2"
    local estimated_duration="$3"
    shift 3
    local tests=("$@")

    local log_file="$TEST_DIR/logs/${batch_id}-$(date +%Y%m%d-%H%M%S).log"
    local passed=0
    local failed=0
    local total_tests=${#tests[@]}
    local current_test=0

    # Print header
    print_header "$batch_id" "$batch_title" "$estimated_duration" "$log_file"

    # Check file handles
    check_file_handles

    # Run each test
    for test in "${tests[@]}"; do
        ((current_test++))

        echo ""
        if [ "$total_tests" -gt 1 ]; then
            echo "Running: $test [$current_test/$total_tests] ($(date +%H:%M:%S))"
        else
            echo "Running: $test ($(date +%H:%M:%S))"
        fi

        python3 scripts/run_test.py --run "$test" -y --wait 2>&1 | tee -a "$log_file"

        # Check the exit code of the python script (PIPESTATUS[0]), not tee
        if [ "${PIPESTATUS[0]}" -eq 0 ]; then
            echo "✓ $test PASSED"
            ((passed++))
        else
            echo "✗ $test FAILED"
            ((failed++))
        fi

        # Delay between tests (except after the last one)
        if [ "$current_test" -lt "$total_tests" ]; then
            echo ""
            echo "Cleaning resources before next test..."
            sleep "$DELAY_BETWEEN_TESTS"

            # Check file handle count and cleanup if needed
            HANDLE_COUNT=$(lsof 2>/dev/null | grep -c "/Volumes/Media5TB/rowanholt_imgs" 2>/dev/null) || HANDLE_COUNT=0
            if [ "$HANDLE_COUNT" -gt 1000 ]; then
                echo "⚠️  High file handle count ($HANDLE_COUNT) - cleaning up OrbStack..."
                cleanup_docker
                echo "✓ Cleanup complete - continuing tests..."
            fi
        fi
    done

    # Print footer
    print_footer "$batch_id" "$passed" "$failed" "$log_file"

    # Return non-zero if any tests failed
    [ "$failed" -eq 0 ]
}
