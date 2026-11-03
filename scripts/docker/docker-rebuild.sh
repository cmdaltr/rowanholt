#!/bin/bash
# Rebuild and start Dernvale - removes old containers, rebuilds images, and starts fresh

set -e

echo "Stopping and removing old Dernvale containers..."
docker-compose down --remove-orphans 2>/dev/null || true

# Force remove any lingering containers
docker rm -f dernvale-splunk dernvale-elasticsearch dernvale-redis dernvale-navigator \
    dernvale-backend dernvale-celery-worker dernvale-frontend dernvale-kibana \
    dernvale-elasticsearch-setup 2>/dev/null || true

# Clean up Docker to prevent disk bloat
echo ""
echo "Cleaning up Docker (removing unused images, build cache, and orphan volumes)..."
docker image prune -f 2>/dev/null || true
docker builder prune -f 2>/dev/null || true
docker volume prune -f 2>/dev/null || true

echo ""
echo "Rebuilding Dernvale images..."
docker-compose build --no-cache

echo ""
echo "Starting Dernvale..."
docker-compose up -d

echo ""
echo "Dernvale is starting up!"
echo ""
echo "Services:"
echo "  Frontend:      http://localhost:5687"
echo "  Backend API:   http://localhost:5688"
echo "  Splunk:        http://localhost:7755  (admin/dernvale)"
echo "  Kibana:        http://localhost:5601  (admin/dernvale)"
echo "  Elasticsearch: http://localhost:9200  (admin/dernvale)"
echo "  Navigator:     http://localhost:5602"
echo ""
echo "View logs: docker-compose logs -f"
echo ""
echo "To clean up Docker disk space: scripts/docker-clean.sh"
