#!/bin/bash
# Restart Elasticsearch instance inside Docker container
# Usage: ./restart-elastic.sh

CONTAINER_NAME="dernvale-elastic"

echo "Restarting Elasticsearch in container: $CONTAINER_NAME"

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Error: Container '$CONTAINER_NAME' is not running"
    exit 1
fi

# Restart the container
echo "Restarting container..."
docker restart "$CONTAINER_NAME"

# Wait for Elasticsearch to be healthy
echo "Waiting for Elasticsearch to be ready..."
for i in {1..90}; do
    STATUS=$(docker inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null)
    if [ "$STATUS" = "healthy" ]; then
        echo "Elasticsearch is ready!"

        # Also restart Kibana since it depends on Elastic
        if docker ps --format '{{.Names}}' | grep -q "^dernvale-kibana$"; then
            echo "Restarting Kibana..."
            docker restart dernvale-kibana
            echo "Waiting for Kibana to be ready..."
            for j in {1..60}; do
                KIBANA_STATUS=$(docker inspect --format='{{.State.Health.Status}}' "dernvale-kibana" 2>/dev/null)
                if [ "$KIBANA_STATUS" = "healthy" ]; then
                    echo "Kibana is ready!"
                    exit 0
                fi
                echo -n "."
                sleep 2
            done
        fi
        exit 0
    fi
    echo -n "."
    sleep 2
done

echo ""
echo "Warning: Elasticsearch may still be starting up. Check with: docker logs $CONTAINER_NAME"
