#!/bin/bash
# Dernvale Test Runner
# Runs all tests sequentially with proper error handling
# Failed tests are logged to error.log for review

# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Configuration
DELAY_BETWEEN_TESTS=60  # seconds to wait between tests (reduced from 300)
LOG_FILE="test_results_$(date +%Y%m%d_%H%M%S).log"
ERROR_LOG="error.log"
FAILED_TESTS=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

log_error() {
    local test_name="$1"
    local error_output="$2"
    local exit_code="${3:-unknown}"
    echo "=========================================="  >> "$ERROR_LOG"
    echo "TEST FAILED: ${test_name}"                  >> "$ERROR_LOG"
    echo "TIME: $(date)"                              >> "$ERROR_LOG"
    echo "EXIT CODE: ${exit_code}"                    >> "$ERROR_LOG"
    echo "------------------------------------------" >> "$ERROR_LOG"
    echo "OUTPUT:"                                    >> "$ERROR_LOG"
    echo "$error_output"                              >> "$ERROR_LOG"
    echo ""                                           >> "$ERROR_LOG"
    echo "SUGGESTION: Check job logs in Web UI at http://localhost:5687" >> "$ERROR_LOG"
    echo ""                                           >> "$ERROR_LOG"
}

run_test() {
    local test_name="$1"
    log "${YELLOW}Starting ${test_name}...${NC}"

    # Capture both stdout and stderr
    local output
    local exit_code
    output=$(python3 test_image_combinations.py --run "$test_name" 2>&1)
    exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        # Check if output contains job ID (successful submission)
        if echo "$output" | grep -q "Job ID:"; then
            local job_id=$(echo "$output" | grep "Job ID:" | awk '{print $3}')
            log "${GREEN}Submitted ${test_name} successfully (Job: ${job_id})${NC}"
            log "  Note: Check job status in Web UI or API for actual results"
        else
            log "${GREEN}${test_name} completed${NC}"
        fi
    else
        log "${RED}Failed to submit ${test_name} (exit code: ${exit_code})${NC}"
        log_error "$test_name" "$output" "$exit_code"
        log "${RED}  -> Error details written to ${ERROR_LOG}${NC}"
        # Also show a preview of the error
        log "${RED}  -> Error preview: $(echo "$output" | head -3 | tr '\n' ' ')${NC}"
        ((FAILED_TESTS++))
    fi

    log "Waiting ${DELAY_BETWEEN_TESTS}s before next test..."
    sleep "$DELAY_BETWEEN_TESTS"
}

# Parse arguments
TESTS_TO_RUN=""
TAGS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --tags)
            TAGS="$2"
            shift 2
            ;;
        --delay)
            DELAY_BETWEEN_TESTS="$2"
            shift 2
            ;;
        --test)
            TESTS_TO_RUN="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --tags TAGS    Run only tests matching these tags (e.g., 'windows quick')"
            echo "  --delay SECS   Delay between tests (default: 60)"
            echo "  --test NAME    Run a single specific test"
            echo "  --help         Show this help"
            echo ""
            echo "Examples:"
            echo "  $0                          # Run all tests"
            echo "  $0 --tags 'windows basic'   # Run Windows basic tests"
            echo "  $0 --test win_basic         # Run single test"
            echo "  $0 --delay 30               # 30 second delay between tests"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

log "=========================================="
log "Dernvale Test Runner"
log "Started: $(date)"
log "Log file: $LOG_FILE"
log "Delay between tests: ${DELAY_BETWEEN_TESTS}s"
log "=========================================="

# Check if API is available
log "Checking API availability..."
if ! curl -s --connect-timeout 5 http://localhost:5688/api/health > /dev/null 2>&1; then
    log "${RED}ERROR: Cannot connect to API at http://localhost:5688${NC}"
    log "Make sure Dernvale is running: docker-compose up -d"
    exit 1
fi
log "${GREEN}API is available${NC}"

# Analysis files (keywords, YARA rules, IOC watchlists) are mounted via docker-compose volume
# from ./files to /tmp/dernvale/files
REPO_DIR="$(dirname "$SCRIPT_DIR")"
FILES_DIR="$REPO_DIR/files"

if [ -d "$FILES_DIR" ]; then
    log "${GREEN}Analysis files directory found at ${FILES_DIR}${NC}"
    log "  (Mounted in container at /tmp/dernvale/files via docker-compose)"
else
    log "${YELLOW}WARNING: Analysis files directory not found at ${FILES_DIR}${NC}"
    log "${YELLOW}Keywords, YARA, and IOC tests may fail${NC}"
    log "${YELLOW}Create the directory with keywords.txt, iocs.txt, and yara_rules/ subdirectory${NC}"
fi

# Run tests
if [[ -n "$TESTS_TO_RUN" ]]; then
    # Run single test
    run_test "$TESTS_TO_RUN"
elif [[ -n "$TAGS" ]]; then
    # Run tests by tags
    log "Running tests with tags: $TAGS"
    TAG_OUTPUT=""
    if TAG_OUTPUT=$(python3 test_image_combinations.py --run-tags $TAGS 2>&1); then
        log "${GREEN}Tag-based tests completed${NC}"
        echo "$TAG_OUTPUT"
    else
        log "${RED}Some tag-based tests failed${NC}"
        log_error "tags: $TAGS" "$TAG_OUTPUT"
        log "${RED}  -> Error details written to ${ERROR_LOG}${NC}"
        ((FAILED_TESTS++))
    fi
else
    # Run all tests
    log "Running all tests..."

    # Get list of all tests (lines starting with exactly 2 spaces then a letter)
    TESTS=$(python3 test_image_combinations.py --list 2>/dev/null | grep "^  [a-z]" | awk '{print $1}')

    for test in $TESTS; do
        run_test "$test"
    done
fi

log "=========================================="
log "Test run completed: $(date)"
log "Results saved to: $LOG_FILE"
if [[ $FAILED_TESTS -gt 0 ]]; then
    log "${RED}FAILED TESTS: ${FAILED_TESTS}${NC}"
    log "${RED}Error details: ${ERROR_LOG}${NC}"
else
    log "${GREEN}All tests submitted successfully${NC}"
fi
log "=========================================="
