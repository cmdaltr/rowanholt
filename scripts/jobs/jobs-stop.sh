#!/bin/bash
# Rowanholt - Stop/Cancel Running Jobs
# Usage:
#   ./stop-jobs.sh              # Cancel all running/pending jobs (with confirmation)
#   ./stop-jobs.sh -y           # Cancel all jobs (no confirmation)
#   ./stop-jobs.sh <job-id>     # Cancel specific job by ID
#   ./stop-jobs.sh <job-id> -y  # Cancel specific job (no confirmation)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
API_HOST="${ROWANHOLT_API_HOST:-localhost}"
API_PORT="${ROWANHOLT_API_PORT:-5688}"
API_BASE="http://${API_HOST}:${API_PORT}/api"

# Parse arguments
SPECIFIC_JOB_ID=""
SKIP_CONFIRM=false

for arg in "$@"; do
    case $arg in
        -y|--yes)
            SKIP_CONFIRM=true
            ;;
        *)
            # Check if it looks like a job ID (UUID format)
            if [[ $arg =~ ^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$ ]]; then
                SPECIFIC_JOB_ID="$arg"
            fi
            ;;
    esac
done

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
if [ -n "$SPECIFIC_JOB_ID" ]; then
    echo -e "${BLUE}║         Rowanholt - Stop Specific Job                       ║${NC}"
else
    echo -e "${BLUE}║         Rowanholt - Stop Running Jobs                       ║${NC}"
fi
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if curl is available
if ! command -v curl &> /dev/null; then
    echo -e "${RED}Error: curl is not installed${NC}"
    exit 1
fi

# Check if jq is available
if ! command -v jq &> /dev/null; then
    echo -e "${RED}Error: jq is not installed${NC}"
    echo -e "${YELLOW}Install with: brew install jq (macOS) or apt-get install jq (Linux)${NC}"
    exit 1
fi

# Test API connectivity
echo -e "${BLUE}Checking API connectivity...${NC}"
if ! curl -s -f "${API_BASE}/health" > /dev/null 2>&1; then
    echo -e "${RED}Error: Cannot connect to Rowanholt API at ${API_BASE}${NC}"
    echo -e "${YELLOW}Make sure Rowanholt backend is running on ${API_HOST}:${API_PORT}${NC}"
    exit 1
fi
echo -e "${GREEN}✓ API is reachable${NC}"
echo ""

# Handle specific job cancellation
if [ -n "$SPECIFIC_JOB_ID" ]; then
    echo -e "${BLUE}Fetching job details...${NC}"
    JOB_RESPONSE=$(curl -s -X GET "${API_BASE}/jobs/${SPECIFIC_JOB_ID}" 2>/dev/null || echo '{}')
    JOB_STATUS=$(echo "$JOB_RESPONSE" | jq -r '.status // "not_found"')
    JOB_CASE=$(echo "$JOB_RESPONSE" | jq -r '.case_number // "unknown"')

    if [ "$JOB_STATUS" == "not_found" ] || [ "$JOB_STATUS" == "null" ]; then
        echo -e "${RED}Error: Job ${SPECIFIC_JOB_ID} not found${NC}"
        exit 1
    fi

    echo -e "${YELLOW}Job to cancel:${NC}"
    echo "  • ${JOB_CASE} (${SPECIFIC_JOB_ID:0:8}...) - ${JOB_STATUS}"
    echo ""

    # Confirm cancellation
    if [ "$SKIP_CONFIRM" = false ]; then
        echo -e "${RED}⚠️  WARNING: This will cancel the job!${NC}"
        read -p "Are you sure? (yes/no): " -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            echo -e "${BLUE}Cancelled${NC}"
            exit 0
        fi
    fi

    # Build JSON array with single job ID
    JOB_IDS_ARRAY="[\"${SPECIFIC_JOB_ID}\"]"
else
    # Get list of all jobs
    echo -e "${BLUE}Fetching job list...${NC}"
    JOBS_RESPONSE=$(curl -s -X GET "${API_BASE}/jobs" || echo '{"jobs":[]}')
    ALL_JOBS=$(echo "$JOBS_RESPONSE" | jq -r '.jobs // []')

    if [ "$ALL_JOBS" == "[]" ]; then
        echo -e "${YELLOW}No jobs found${NC}"
        exit 0
    fi

    # Filter running and pending jobs
    RUNNING_JOBS=$(echo "$ALL_JOBS" | jq -r '.[] | select(.status == "running" or .status == "pending") | .id')
    RUNNING_COUNT=$(echo "$RUNNING_JOBS" | grep -v '^$' | wc -l | tr -d ' ')

    if [ "$RUNNING_COUNT" -eq 0 ]; then
        echo -e "${GREEN}No running or pending jobs to stop${NC}"
        exit 0
    fi

    echo -e "${YELLOW}Found ${RUNNING_COUNT} running/pending job(s):${NC}"
    echo ""

    # Display running jobs
    echo "$ALL_JOBS" | jq -r '.[] | select(.status == "running" or .status == "pending") |
        "  • " + .case_number + " (" + .id[0:8] + "...) - " + .status' 2>/dev/null || \
        echo "$RUNNING_JOBS" | while read -r job_id; do
            if [ -n "$job_id" ]; then
                echo "  • Job ID: ${job_id:0:8}..."
            fi
        done

    echo ""

    # Confirm cancellation
    if [ "$SKIP_CONFIRM" = false ]; then
        echo -e "${RED}⚠️  WARNING: This will cancel all running and pending jobs!${NC}"
        read -p "Are you sure? (yes/no): " -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            echo -e "${BLUE}Cancelled${NC}"
            exit 0
        fi
    fi

    # Build JSON array of job IDs
    JOB_IDS_ARRAY=$(echo "$RUNNING_JOBS" | grep -v '^$' | jq -R -s -c 'split("\n") | map(select(length > 0))')

    if [ "$JOB_IDS_ARRAY" == "[]" ] || [ -z "$JOB_IDS_ARRAY" ]; then
        echo -e "${YELLOW}No jobs to cancel${NC}"
        exit 0
    fi
fi

# Cancel jobs via bulk API
echo -e "${BLUE}Cancelling jobs...${NC}"
CANCEL_RESPONSE=$(curl -s -X POST "${API_BASE}/jobs/bulk/cancel" \
    -H "Content-Type: application/json" \
    -d "$JOB_IDS_ARRAY" || echo '{"results":[]}')

# Parse results
SUCCESS_COUNT=$(echo "$CANCEL_RESPONSE" | jq -r '[.results[] | select(.success == true)] | length' 2>/dev/null || echo "0")
FAILED_COUNT=$(echo "$CANCEL_RESPONSE" | jq -r '[.results[] | select(.success == false)] | length' 2>/dev/null || echo "0")

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║             Cancellation Complete                         ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${GREEN}✓ Successfully cancelled: ${SUCCESS_COUNT} job(s)${NC}"

if [ "$FAILED_COUNT" -gt 0 ]; then
    echo -e "  ${RED}✗ Failed to cancel: ${FAILED_COUNT} job(s)${NC}"
    echo ""
    echo -e "${YELLOW}Failed jobs:${NC}"
    echo "$CANCEL_RESPONSE" | jq -r '.results[] | select(.success == false) |
        "  • " + .job_id[0:8] + "... - " + .error' 2>/dev/null
fi

echo ""
echo -e "${BLUE}Done!${NC}"
