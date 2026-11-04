#!/bin/bash
# Run all test batches sequentially with Docker restarts
# This master script runs all batches 1-5 in order

set -e
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ============================================================================
# Check if Docker is running
# ============================================================================
check_docker() {
    if docker ps &> /dev/null; then
        return 0
    fi

    echo ""
    echo "WARNING: Docker is not running"
    echo ""

    read -p "Would you like to start Docker now? [Y/n] " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo ""
        echo "Please start Docker manually and try again:"
        echo "  macOS:   Open Docker Desktop application"
        echo "  Linux:   sudo systemctl start docker"
        echo "  Windows: Start Docker Desktop"
        echo ""
        exit 1
    fi

    echo ""
    echo "Starting Docker..."

    if [[ "$OSTYPE" == "darwin"* ]]; then
        open -a Docker
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "Attempting to start Docker service..."
        sudo systemctl start docker
    else
        echo "Please start Docker Desktop manually"
        exit 1
    fi

    echo "Waiting for Docker to start (max 60 seconds)..."
    for i in {1..60}; do
        if docker ps &> /dev/null; then
            echo "✓ Docker is now running"
            echo ""
            return 0
        fi
        sleep 1
    done

    echo ""
    echo "ERROR: Docker failed to start within 60 seconds"
    echo "Please start Docker manually and try again"
    echo ""
    exit 1
}

# ============================================================================
# Main
# ============================================================================
check_docker

echo "=================================================="
echo "  RUNNING ALL TEST BATCHES"
echo "=================================================="
echo "Start: $(date +"%a %d-%b-%Y %H:%M:%S%Z")"
echo ""
echo "Group 1 - File Collection"
echo "Group 2 - Analysis"
echo "Group 3 - Detection"
echo "Group 4 - SIEM Exports"
echo "Group 5 - Comprehensive (LONG!)"
echo ""
echo "Estimated total duration: ~30+ hours"
echo ""
echo "Press Ctrl+C within 10s to abort..."
sleep 10

BATCHES=(
    "1a_archive.sh"
    "1b_collect--lnk-docs.sh"
    "1c_collect--bin-hidden-scripts.sh"
    "1d_collect--mail-virtual-web.sh"
    "2a-profiles-vss.sh"
    "2b-memory.sh"
    "2c-brisk.sh"
    "2d-collect-all.sh"
    "3a-ioc-extraction.sh"
    "3b-keywords.sh"
    "3c-yara.sh"
    "3d-yara-memory.sh"
    "4a-splunk-export.sh"
    "4b-elastic-export.sh"
    "4c-navigator-export.sh"
    "4d-siem-nav-export.sh"
    "5a-full_analysis.sh"
    "5b-exhaustive-disk.sh"
    "5c-exhaustive-memory.sh"
    "5d-exhaustive-disk-memory.sh"
)

total_batches=${#BATCHES[@]}
current_batch=0
passed_batches=0
failed_batches=0

for batch in "${BATCHES[@]}"; do
    ((current_batch++))
    echo ""
    echo "Running: BATCH $current_batch/$total_batches - $batch ($(date +%H:%M:%S))"

    if bash "$batch"; then
        echo "✓ Batch $batch PASSED"
        ((passed_batches++))
    else
        echo "✗ Batch $batch FAILED"
        ((failed_batches++))
    fi

    # Restart Docker between batches for extra safety
    if [ $current_batch -lt $total_batches ]; then
        echo ""
        echo "Cleaning resources before next batch..."
        docker restart rowanholt-backend rowanholt-celery-worker 2>/dev/null || true
        sleep 30
    fi
done

echo ""
echo "=================================================="
echo "  ALL BATCHES: Completed"
echo "  ----------------------------------------------"
echo "Passed batches: $passed_batches"
echo "Failed batches: $failed_batches"
echo "End: $(date)"
echo ""
echo "Test outputs are in:"
echo "  /Volumes/Media5TB/rowanholt_imgs/tests/"
echo "  (or your configured TEST_OUTPUT_PATH)"
echo "=================================================="
