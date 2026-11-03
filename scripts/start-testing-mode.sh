#!/bin/bash
# Start Rivendell in Testing Mode (optimized for 16GB Macs)
# This disables Splunk and Elastic to save 6GB+ RAM

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║   Rivendell - Testing Mode (16GB RAM Optimized)           ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "This mode disables:"
echo "  • Splunk (saves 4GB)"
echo "  • Elasticsearch (saves 2GB)"
echo "  • Kibana"
echo "  • Navigator"
echo ""
echo "Services that WILL run:"
echo "  ✓ PostgreSQL (job storage)"
echo "  ✓ Redis (task queue)"
echo "  ✓ Backend API"
echo "  ✓ Celery Worker (forensic processing)"
echo "  ✓ Frontend"
echo ""
echo "Total memory usage: ~9GB (fits in Docker with 10GB allocation)"
echo ""

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "⚠️  Docker is not running!"
    echo ""
    echo "Starting Docker Desktop..."
    open -g -j -a Docker  # in the background: no window, nothing new in the Dock

    echo "Waiting for Docker to start..."
    for i in {1..60}; do
        if docker info &> /dev/null 2>&1; then
            echo "✓ Docker started"
            break
        fi
        sleep 1
        if [ $i -eq 60 ]; then
            echo "❌ Docker failed to start. Please start it manually."
            exit 1
        fi
    done
    echo ""
fi

# Stop any running containers
echo "Stopping existing containers..."
docker-compose down 2>/dev/null || true
echo ""

# Start in testing mode
echo "Starting containers in testing mode..."
docker-compose -f docker-compose.yml -f tests/docker-compose.testing.yml up -d

echo ""
echo "Waiting for services to be ready..."
sleep 15

# Check service status
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║   Service Status                                           ║"
echo "╚════════════════════════════════════════════════════════════╝"
docker-compose ps --format "table {{.Name}}\t{{.Status}}"

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║   Ready!                                                   ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Frontend:  http://localhost:5687"
echo "Backend:   http://localhost:5688"
echo ""
echo "To check job status:"
echo "  ./scripts/status.sh"
echo ""
echo "To run tests:"
echo "  cd tests"
echo "  ./scripts/run_single_test.sh win_brisk"
echo "  ./scripts/batch/batch1a-archive-lnk.sh"
echo ""
