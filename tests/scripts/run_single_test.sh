#!/bin/bash
# Run a single test with automatic Docker restart
# Usage: ./run_single_test.sh <test_name> [--no-restart]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$(dirname "$SCRIPT_DIR")"
cd "$TEST_DIR"

# Check arguments
if [ $# -eq 0 ]; then
    echo "Usage: $0 <test_name> [--no-restart]"
    echo ""
    echo "Examples:"
    echo "  $0 win_archive"
    echo "  $0 win_collect_files_lnk --no-restart"
    echo ""
    echo "Available tests:"
    python3 scripts/run_test.py --list | grep "  -" | head -20
    exit 1
fi

TEST_NAME="$1"
NO_RESTART=false

if [ "$2" = "--no-restart" ]; then
    NO_RESTART=true
fi

LOG_DIR="$TEST_DIR/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/single-${TEST_NAME}-$(date +%Y%m%d-%H%M%S).log"

echo "======================================" | tee "$LOG_FILE"
echo "Single Test Runner with Auto-Restart" | tee -a "$LOG_FILE"
echo "======================================" | tee -a "$LOG_FILE"
echo "Test: $TEST_NAME" | tee -a "$LOG_FILE"
echo "Started: $(date)" | tee -a "$LOG_FILE"
echo "Log: $LOG_FILE" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Check if Docker is running
if ! docker ps &> /dev/null; then
    echo "" | tee -a "$LOG_FILE"
    echo "WARNING: Docker is not running" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    # Offer to start Docker
    read -p "Would you like to start Docker now? [Y/n] " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo "" | tee -a "$LOG_FILE"
        echo "Please start Docker manually and try again:" | tee -a "$LOG_FILE"
        echo "  macOS:   Open Docker Desktop application" | tee -a "$LOG_FILE"
        echo "  Linux:   sudo systemctl start docker" | tee -a "$LOG_FILE"
        echo "  Windows: Start Docker Desktop" | tee -a "$LOG_FILE"
        echo "" | tee -a "$LOG_FILE"
        exit 1
    fi

    # Start Docker based on platform
    echo "" | tee -a "$LOG_FILE"
    echo "Starting Docker..." | tee -a "$LOG_FILE"

    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        open -a Docker
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        echo "Attempting to start Docker service..." | tee -a "$LOG_FILE"
        sudo systemctl start docker 2>&1 | tee -a "$LOG_FILE"
    else
        # Windows or unknown
        echo "Please start Docker Desktop manually" | tee -a "$LOG_FILE"
        exit 1
    fi

    # Wait for Docker to be ready
    echo "Waiting for Docker to start (max 60 seconds)..." | tee -a "$LOG_FILE"
    for i in {1..60}; do
        if docker ps &> /dev/null; then
            echo "✓ Docker is now running" | tee -a "$LOG_FILE"
            echo "" | tee -a "$LOG_FILE"
            break
        fi
        sleep 1
        if [ $i -eq 60 ]; then
            echo "" | tee -a "$LOG_FILE"
            echo "ERROR: Docker failed to start within 60 seconds" | tee -a "$LOG_FILE"
            echo "Please start Docker manually and try again" | tee -a "$LOG_FILE"
            echo "" | tee -a "$LOG_FILE"
            exit 1
        fi
    done
fi

# Check if backend is responsive
echo "Checking backend status..." | tee -a "$LOG_FILE"
if ! python3 scripts/run_test.py --status &> /dev/null; then
    echo "Backend not responsive, restarting containers..." | tee -a "$LOG_FILE"
    docker restart dernvale-backend dernvale-celery-worker 2>&1 | tee -a "$LOG_FILE"
    echo "Waiting 30s for services to start..." | tee -a "$LOG_FILE"
    sleep 30
fi

# Run the test
echo "" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"
echo "Running test: $TEST_NAME" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

if python3 scripts/run_test.py --run "$TEST_NAME" -y --wait 2>&1 | tee -a "$LOG_FILE"; then
    echo "" | tee -a "$LOG_FILE"
    echo "✓ $TEST_NAME PASSED" | tee -a "$LOG_FILE"
    TEST_RESULT=0
else
    echo "" | tee -a "$LOG_FILE"
    echo "✗ $TEST_NAME FAILED" | tee -a "$LOG_FILE"
    TEST_RESULT=1
fi

# Restart Docker if not disabled
if [ "$NO_RESTART" = false ]; then
    echo "" | tee -a "$LOG_FILE"
    echo "Restarting Docker containers to free resources..." | tee -a "$LOG_FILE"
    docker restart dernvale-backend dernvale-celery-worker 2>&1 | tee -a "$LOG_FILE"

    echo "Waiting 30s for services to stabilize..." | tee -a "$LOG_FILE"
    sleep 30

    echo "Verifying backend is back online..." | tee -a "$LOG_FILE"
    if python3 scripts/run_test.py --status &> /dev/null; then
        echo "✓ Backend is responsive" | tee -a "$LOG_FILE"
    else
        echo "⚠ Backend may need more time to start" | tee -a "$LOG_FILE"
    fi
fi

echo "" | tee -a "$LOG_FILE"
echo "======================================" | tee -a "$LOG_FILE"
echo "Test Complete" | tee -a "$LOG_FILE"
echo "======================================" | tee -a "$LOG_FILE"
echo "Test: $TEST_NAME" | tee -a "$LOG_FILE"
echo "Ended: $(date)" | tee -a "$LOG_FILE"
echo "Log: $LOG_FILE" | tee -a "$LOG_FILE"

exit $TEST_RESULT
