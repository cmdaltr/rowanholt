#!/bin/bash
# Quick status checker for Rowanholt jobs
# Usage:
#   ./status.sh              # Show job status summary
#   ./status.sh --full       # Show full job IDs
#   ./status.sh --watch      # Watch mode (auto-refresh)
#   ./status.sh --full -w    # Watch mode with full IDs

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
TEST_DIR="$REPO_DIR/tests"
cd "$TEST_DIR"

# Parse arguments
SHOW_FULL_IDS=false
WATCH_MODE=false

for arg in "$@"; do
    case $arg in
        --full|--ids|-f)
            SHOW_FULL_IDS=true
            ;;
        --watch|-w)
            WATCH_MODE=true
            ;;
    esac
done

# Function to display status
show_status() {
    if [ "$SHOW_FULL_IDS" = true ]; then
        # Query API directly to get full job IDs
        API_URL="http://localhost:5688/api/jobs"

        if command -v jq &> /dev/null; then
            RESPONSE=$(curl -s "$API_URL" 2>/dev/null)

            if [ $? -eq 0 ] && [ -n "$RESPONSE" ]; then
                # Parse job counts
                RUNNING=$(echo "$RESPONSE" | jq '[.jobs[] | select(.status == "running")] | length')
                PENDING=$(echo "$RESPONSE" | jq '[.jobs[] | select(.status == "pending")] | length')
                COMPLETED=$(echo "$RESPONSE" | jq '[.jobs[] | select(.status == "completed")] | length')
                FAILED=$(echo "$RESPONSE" | jq '[.jobs[] | select(.status == "failed")] | length')

                echo "======================================================================"
                echo "  JOB STATUS SUMMARY"
                echo "======================================================================"
                echo "  Running: $RUNNING  |  Pending: $PENDING  |  Completed: $COMPLETED  |  Failed: $FAILED"
                echo "======================================================================"
                echo ""

                # Show running jobs with full IDs
                if [ "$RUNNING" -gt 0 ]; then
                    echo "  RUNNING:"
                    echo "$RESPONSE" | jq -r '.jobs[] | select(.status == "running") |
                        "    🔄 " + .case_number + " (" + (.progress // 0 | tostring) + "%)\n       ID: " + .id'
                    echo ""
                fi

                # Show pending jobs with full IDs
                if [ "$PENDING" -gt 0 ]; then
                    echo "  PENDING:"
                    echo "$RESPONSE" | jq -r '.jobs[] | select(.status == "pending") |
                        "    ⏳ " + .case_number + "\n       ID: " + .id'
                    echo ""
                fi

                # Show completed jobs with full IDs
                if [ "$COMPLETED" -gt 0 ]; then
                    echo "  COMPLETED:"
                    echo "$RESPONSE" | jq -r '.jobs[] | select(.status == "completed") |
                        "    ✅ " + .case_number + "\n       ID: " + .id' | head -20
                    if [ "$COMPLETED" -gt 10 ]; then
                        echo "    ... (showing first 10 of $COMPLETED completed jobs)"
                    fi
                    echo ""
                fi

                # Show failed jobs with full IDs
                if [ "$FAILED" -gt 0 ]; then
                    echo "  FAILED:"
                    echo "$RESPONSE" | jq -r '.jobs[] | select(.status == "failed") |
                        "    ❌ " + .case_number + "\n       ID: " + .id'
                    echo ""
                fi
            else
                echo "Error: Could not connect to API"
                exit 1
            fi
        else
            echo "Error: jq is required for --full mode"
            echo "Install with: brew install jq (macOS) or apt-get install jq (Linux)"
            exit 1
        fi
    else
        # Use default run_test.py status
        python3 scripts/run_test.py --status
    fi
}

# Execute based on mode
if [ "$WATCH_MODE" = true ]; then
    echo "Watching job status (Ctrl+C to exit)..."
    echo ""
    while true; do
        clear
        echo "=== Job Status - $(date +%H:%M:%S) ==="
        echo ""
        show_status
        echo ""
        echo "Refreshing in 5 seconds... (Ctrl+C to exit)"
        sleep 5
    done
else
    show_status
fi
