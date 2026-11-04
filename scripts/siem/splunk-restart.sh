#!/bin/bash
# Clear Splunk cache aggressively
# Run this when CSS/JS changes aren't showing up

CONTAINER="rowanholt-splunk"

echo "=== Clearing Splunk Cache ==="

# Clear the static asset cache
echo "[1/4] Clearing static asset cache..."
docker exec -u root $CONTAINER rm -rf /opt/splunk/var/run/splunk/dispatch/* 2>/dev/null
docker exec -u root $CONTAINER rm -rf /opt/splunk/var/run/splunk/srtemp/* 2>/dev/null

# Clear the KV store cache
echo "[2/4] Clearing KV store cache..."
docker exec -u root $CONTAINER rm -rf /opt/splunk/var/lib/splunk/kvstore/mongo/journal/* 2>/dev/null

# Bump the static asset version by touching files
echo "[3/4] Bumping static asset timestamps..."
docker exec -u root $CONTAINER find /opt/splunk/etc/apps/elrond/appserver/static -type f \( -name "*.css" -o -name "*.js" \) -exec touch {} \;

# Restart Splunk web only (faster than full restart)
echo "[4/4] Restarting Splunk Web..."
docker exec $CONTAINER /opt/splunk/bin/splunk restart splunkweb 2>/dev/null

if [ $? -ne 0 ]; then
    echo "Could not restart splunkweb, doing full container restart..."
    docker restart $CONTAINER
    echo "Waiting for Splunk to come back up..."
    sleep 30
fi

echo ""
echo "=== Done! ==="
echo "Now hard refresh your browser (Cmd+Shift+R or Ctrl+Shift+R)"
echo "Or open in incognito/private window"
