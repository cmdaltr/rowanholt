#!/bin/bash
# Start Rowanholt - removes old containers and starts fresh

set -e

echo "Stopping and removing old Rowanholt containers..."
docker-compose down --remove-orphans 2>/dev/null || true

# Force remove any lingering containers
docker rm -f rowanholt-splunk rowanholt-elasticsearch rowanholt-redis rowanholt-navigator \
    rowanholt-backend rowanholt-celery-worker rowanholt-frontend rowanholt-kibana 2>/dev/null || true

echo "Starting Rowanholt..."
docker-compose up -d

echo ""
echo "Rowanholt is starting up!"
echo ""
echo "Services:"
echo "  Frontend:      http://localhost:5687"
echo "  Backend API:   http://localhost:5688"
echo "  Splunk:        http://localhost:7755"
echo "  Kibana:        http://localhost:5601"
echo "  Elasticsearch: http://localhost:9200"
echo "  Navigator:     http://localhost:5602"
echo ""
echo "Credentials:     admin / rowanholt"
echo ""
echo "View logs: docker-compose logs -f"
