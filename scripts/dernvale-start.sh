#!/bin/bash
# Start Dernvale - removes old containers and starts fresh

set -e

echo "Stopping and removing old Dernvale containers..."
docker-compose down --remove-orphans 2>/dev/null || true

# Force remove any lingering containers
docker rm -f dernvale-splunk dernvale-elasticsearch dernvale-redis dernvale-navigator \
    dernvale-backend dernvale-celery-worker dernvale-frontend dernvale-kibana 2>/dev/null || true

echo "Starting Dernvale..."
docker-compose up -d

echo ""
echo "Dernvale is starting up!"
echo ""
echo "Services:"
echo "  Frontend:      http://localhost:5687"
echo "  Backend API:   http://localhost:5688"
echo "  Splunk:        http://localhost:7755"
echo "  Kibana:        http://localhost:5601"
echo "  Elasticsearch: http://localhost:9200"
echo "  Navigator:     http://localhost:5602"
echo ""
echo "Credentials:     admin / dernvale"
echo ""
echo "View logs: docker-compose logs -f"
