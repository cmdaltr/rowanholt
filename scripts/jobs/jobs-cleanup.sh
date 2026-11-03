#!/bin/bash
# Dernvale - Cleanup Old Jobs
# This script deletes old completed, failed, cancelled, or archived jobs

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
API_HOST="${DERNVALE_API_HOST:-localhost}"
API_PORT="${DERNVALE_API_PORT:-5688}"
API_BASE="http://${API_HOST}:${API_PORT}/api"

# Default settings
DAYS_OLD=30
STATUS_FILTER="completed,failed,cancelled,archived"
DRY_RUN=false
AUTO_YES=false

# Usage function
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -d, --days DAYS          Delete jobs older than DAYS days (default: 30)"
    echo "  -s, --status STATUS      Delete jobs with specific status"
    echo "                           (completed|failed|cancelled|archived|all)"
    echo "                           Default: completed,failed,cancelled,archived"
    echo "  -a, --all                Delete ALL non-running jobs (ignores --days)"
    echo "  -n, --dry-run            Show what would be deleted without deleting"
    echo "  -y, --yes                Skip confirmation prompt"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                              # Delete jobs older than 30 days"
    echo "  $0 --days 7                     # Delete jobs older than 7 days"
    echo "  $0 --status failed              # Delete only failed jobs"
    echo "  $0 --all --dry-run              # Preview all deletable jobs"
    echo "  $0 --days 14 --yes              # Delete jobs older than 14 days without confirmation"
    echo ""
    exit 0
}

# Parse arguments
DELETE_ALL=false
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--days)
            DAYS_OLD="$2"
            shift 2
            ;;
        -s|--status)
            STATUS_FILTER="$2"
            shift 2
            ;;
        -a|--all)
            DELETE_ALL=true
            shift
            ;;
        -n|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -y|--yes)
            AUTO_YES=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            ;;
    esac
done

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         Dernvale - Cleanup Old Jobs                        ║${NC}"
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

# Check if date command supports required options
if date --version >/dev/null 2>&1; then
    # GNU date
    DATE_CMD="date"
else
    # BSD date (macOS)
    DATE_CMD="date"
fi

# Test API connectivity
echo -e "${BLUE}Checking API connectivity...${NC}"
if ! curl -s -f "${API_BASE}/health" > /dev/null 2>&1; then
    echo -e "${RED}Error: Cannot connect to Dernvale API at ${API_BASE}${NC}"
    echo -e "${YELLOW}Make sure Dernvale backend is running on ${API_HOST}:${API_PORT}${NC}"
    exit 1
fi
echo -e "${GREEN}✓ API is reachable${NC}"
echo ""

# Get list of all jobs
echo -e "${BLUE}Fetching job list...${NC}"
JOBS_RESPONSE=$(curl -s -X GET "${API_BASE}/jobs" || echo '{"jobs":[]}')
ALL_JOBS=$(echo "$JOBS_RESPONSE" | jq -r '.jobs // []')

if [ "$ALL_JOBS" == "[]" ]; then
    echo -e "${YELLOW}No jobs found${NC}"
    exit 0
fi

TOTAL_JOBS=$(echo "$ALL_JOBS" | jq -r 'length')
echo -e "${GREEN}✓ Found ${TOTAL_JOBS} total job(s)${NC}"
echo ""

# Calculate cutoff date (for filtering by age)
CUTOFF_DATE=""
if [ "$DELETE_ALL" == false ]; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        CUTOFF_DATE=$(date -u -v-${DAYS_OLD}d +%Y-%m-%dT%H:%M:%S)
    else
        # Linux
        CUTOFF_DATE=$(date -u -d "${DAYS_OLD} days ago" +%Y-%m-%dT%H:%M:%S)
    fi
fi

# Build status filter for jq
if [ "$STATUS_FILTER" == "all" ]; then
    STATUS_JQ_FILTER='select(.status != "running" and .status != "pending")'
else
    IFS=',' read -ra STATUSES <<< "$STATUS_FILTER"
    STATUS_CONDITIONS=""
    for status in "${STATUSES[@]}"; do
        status=$(echo "$status" | xargs) # trim whitespace
        if [ -n "$STATUS_CONDITIONS" ]; then
            STATUS_CONDITIONS="${STATUS_CONDITIONS} or "
        fi
        STATUS_CONDITIONS="${STATUS_CONDITIONS}.status == \"${status}\""
    done
    STATUS_JQ_FILTER="select(${STATUS_CONDITIONS})"
fi

# Filter jobs
if [ "$DELETE_ALL" == true ]; then
    echo -e "${YELLOW}Filter: All non-running jobs${NC}"
    JOBS_TO_DELETE=$(echo "$ALL_JOBS" | jq -c "[.[] | ${STATUS_JQ_FILTER}]")
else
    echo -e "${YELLOW}Filter: Jobs older than ${DAYS_OLD} days (before ${CUTOFF_DATE})${NC}"
    echo -e "${YELLOW}Status: ${STATUS_FILTER}${NC}"
    JOBS_TO_DELETE=$(echo "$ALL_JOBS" | jq -c "[.[] | ${STATUS_JQ_FILTER} | select(.completed_at != null and .completed_at < \"${CUTOFF_DATE}\")]")
fi

DELETE_COUNT=$(echo "$JOBS_TO_DELETE" | jq -r 'length')

if [ "$DELETE_COUNT" -eq 0 ]; then
    echo -e "${GREEN}No jobs match the deletion criteria${NC}"
    exit 0
fi

echo -e "${YELLOW}Found ${DELETE_COUNT} job(s) to delete:${NC}"
echo ""

# Display jobs to be deleted
echo "$JOBS_TO_DELETE" | jq -r '.[] |
    "  • " + .case_number + " (" + .id[0:8] + "...) - " + .status +
    (if .completed_at then " - completed: " + .completed_at[0:10] else "" end)' 2>/dev/null || \
    echo "$JOBS_TO_DELETE" | jq -r '.[].id' | while read -r job_id; do
        if [ -n "$job_id" ]; then
            echo "  • Job ID: ${job_id:0:8}..."
        fi
    done

echo ""

# Dry run check
if [ "$DRY_RUN" == true ]; then
    echo -e "${BLUE}Dry run complete. No jobs were deleted.${NC}"
    exit 0
fi

# Confirm deletion
if [ "$AUTO_YES" == false ]; then
    echo -e "${RED}⚠️  WARNING: This will permanently delete ${DELETE_COUNT} job(s)!${NC}"
    echo -e "${RED}⚠️  This action cannot be undone!${NC}"
    read -p "Are you sure? (yes/no): " -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        echo -e "${BLUE}Cancelled${NC}"
        exit 0
    fi
fi

# Build JSON array of job IDs
JOB_IDS_ARRAY=$(echo "$JOBS_TO_DELETE" | jq -c '[.[].id]')

if [ "$JOB_IDS_ARRAY" == "[]" ] || [ -z "$JOB_IDS_ARRAY" ]; then
    echo -e "${YELLOW}No jobs to delete${NC}"
    exit 0
fi

# Delete jobs via bulk API
echo -e "${BLUE}Deleting jobs...${NC}"
DELETE_RESPONSE=$(curl -s -X POST "${API_BASE}/jobs/bulk-delete" \
    -H "Content-Type: application/json" \
    -d "$JOB_IDS_ARRAY" || echo '{"results":[]}')

# Parse results
SUCCESS_COUNT=$(echo "$DELETE_RESPONSE" | jq -r '[.results[] | select(.success == true)] | length' 2>/dev/null || echo "0")
FAILED_COUNT=$(echo "$DELETE_RESPONSE" | jq -r '[.results[] | select(.success == false)] | length' 2>/dev/null || echo "0")

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║             Cleanup Complete                               ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${GREEN}✓ Successfully deleted: ${SUCCESS_COUNT} job(s)${NC}"

if [ "$FAILED_COUNT" -gt 0 ]; then
    echo -e "  ${RED}✗ Failed to delete: ${FAILED_COUNT} job(s)${NC}"
    echo ""
    echo -e "${YELLOW}Failed jobs:${NC}"
    echo "$DELETE_RESPONSE" | jq -r '.results[] | select(.success == false) |
        "  • " + .job_id[0:8] + "... - " + .error' 2>/dev/null
fi

echo ""
echo -e "${BLUE}Done!${NC}"
