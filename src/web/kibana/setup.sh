#!/bin/bash
# Kibana Dashboard Setup Script
# Imports Rowanholt dashboards into Kibana on startup

KIBANA_URL="${KIBANA_URL:-http://kibana:5601}"
ELASTIC_USER="${ELASTIC_USER:-elastic}"
ELASTIC_PASSWORD="${ELASTIC_PASSWORD:-rowanholt}"
MAX_RETRIES=60
RETRY_INTERVAL=5

echo "Rowanholt Kibana Dashboard Setup"
echo "================================="

# Wait for Kibana to be ready
echo "Waiting for Kibana to be available..."
retries=0
while [ $retries -lt $MAX_RETRIES ]; do
    if curl -s -u "${ELASTIC_USER}:${ELASTIC_PASSWORD}" "${KIBANA_URL}/api/status" | grep -q '"overall":{"level":"available"'; then
        echo "Kibana is ready!"
        break
    fi
    retries=$((retries + 1))
    echo "  Attempt $retries/$MAX_RETRIES - Kibana not ready yet, waiting ${RETRY_INTERVAL}s..."
    sleep $RETRY_INTERVAL
done

if [ $retries -eq $MAX_RETRIES ]; then
    echo "ERROR: Kibana did not become available within the timeout period"
    exit 1
fi

# Import dashboards
echo "Importing Rowanholt dashboards..."
DASHBOARD_FILE="/dashboards/dashboards.ndjson"

if [ -f "$DASHBOARD_FILE" ]; then
    response=$(curl -s -X POST \
        -u "${ELASTIC_USER}:${ELASTIC_PASSWORD}" \
        "${KIBANA_URL}/api/saved_objects/_import?overwrite=true" \
        -H "kbn-xsrf: true" \
        --form file=@"$DASHBOARD_FILE")

    if echo "$response" | grep -q '"success":true'; then
        echo "Dashboards imported successfully!"
        # Parse and display what was imported
        success_count=$(echo "$response" | grep -o '"successCount":[0-9]*' | cut -d: -f2)
        echo "  Imported $success_count saved objects"
    else
        echo "WARNING: Dashboard import may have encountered issues"
        echo "  Response: $response"
    fi
else
    echo "ERROR: Dashboard file not found: $DASHBOARD_FILE"
    exit 1
fi

# Set default index pattern
echo "Setting default index pattern..."
curl -s -X POST \
    -u "${ELASTIC_USER}:${ELASTIC_PASSWORD}" \
    "${KIBANA_URL}/api/kibana/settings" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -d '{"changes":{"defaultIndex":"rowanholt-index-pattern"}}' > /dev/null

echo ""
echo "Kibana setup complete!"
echo "  - Overview dashboard: ${KIBANA_URL}/app/dashboards#/view/rowanholt-overview"
echo "  - MITRE ATT&CK dashboard: ${KIBANA_URL}/app/dashboards#/view/rowanholt-mitre"
echo "  - Analysis dashboard: ${KIBANA_URL}/app/dashboards#/view/rowanholt-analysis"
echo "  - IoCs dashboard: ${KIBANA_URL}/app/dashboards#/view/rowanholt-iocs"
echo "  - Keywords dashboard: ${KIBANA_URL}/app/dashboards#/view/rowanholt-keywords"
echo "  - YARA dashboard: ${KIBANA_URL}/app/dashboards#/view/rowanholt-yara"
echo "  - Actors/Software dashboard: ${KIBANA_URL}/app/dashboards#/view/rowanholt-actors"
