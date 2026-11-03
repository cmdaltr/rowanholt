#!/bin/bash
#
# Reset Splunk Trial License
#
# This script resets the Splunk trial license by removing license files
# and restarting Splunk. Use this when the trial license expires.
#
# WARNING: This will reset Splunk to a fresh trial. Your indexed data
# will remain, but you may need to reconfigure some settings.
#

set -e

CONTAINER_NAME="dernvale-splunk"
SPLUNK_USER="admin"
SPLUNK_PASS="dernvale"

echo "=========================================="
echo "Splunk Trial License Reset Script"
echo "=========================================="
echo ""

# Check if container exists
if ! docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Error: Container '${CONTAINER_NAME}' not found"
    exit 1
fi

# Check if container is running
RUNNING=$(docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$" && echo "yes" || echo "no")

echo "Step 1: Stopping Splunk service inside container..."
if [ "$RUNNING" = "yes" ]; then
    docker exec -u splunk ${CONTAINER_NAME} /opt/splunk/bin/splunk stop -f 2>/dev/null || true
    sleep 5
fi

echo "Step 2: Removing license files..."
docker exec -u root ${CONTAINER_NAME} bash -c '
    rm -rf /opt/splunk/etc/licenses/enterprise/*.lic 2>/dev/null || true
    rm -rf /opt/splunk/etc/licenses/download-trial/*.lic 2>/dev/null || true
    rm -rf /opt/splunk/etc/licenses/forwarder/*.lic 2>/dev/null || true
    rm -f /opt/splunk/var/lib/splunk/kvstore/mongo/splunk.key 2>/dev/null || true
    rm -rf /opt/splunk/var/lib/splunk/license* 2>/dev/null || true
' 2>/dev/null || true

echo "Step 3: Restarting Splunk container..."
docker restart ${CONTAINER_NAME}

echo "Step 4: Waiting for Splunk to initialize (this may take 1-2 minutes)..."
sleep 30

# Wait for Splunk to be healthy
MAX_ATTEMPTS=24
ATTEMPT=0
while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    HEALTH=$(docker inspect --format='{{.State.Health.Status}}' ${CONTAINER_NAME} 2>/dev/null || echo "unknown")
    if [ "$HEALTH" = "healthy" ]; then
        echo "Splunk is healthy!"
        break
    fi
    ATTEMPT=$((ATTEMPT + 1))
    echo "  Waiting... (attempt $ATTEMPT/$MAX_ATTEMPTS, status: $HEALTH)"
    sleep 10
done

if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
    echo "Warning: Splunk did not become healthy in time, but may still be starting..."
fi

echo ""
echo "Step 5: Checking license status..."
sleep 5

# Try to get license info
docker exec -u splunk ${CONTAINER_NAME} /opt/splunk/bin/splunk list licenser-localslave -auth ${SPLUNK_USER}:${SPLUNK_PASS} 2>/dev/null || echo "  (License check requires Splunk to be fully started)"

echo ""
echo "=========================================="
echo "Done! Splunk should now have a fresh trial license."
echo ""
echo "Access Splunk at: http://localhost:7755"
echo "Login: ${SPLUNK_USER} / ${SPLUNK_PASS}"
echo ""
echo "If you still see license issues, try:"
echo "  1. Wait a few more minutes for full initialization"
echo "  2. Go to Settings > Licensing in Splunk web UI"
echo "  3. Click 'Change license group' and select 'Free license'"
echo "=========================================="
