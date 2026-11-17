#!/bin/bash
# Elrond Docker Startup Script
# Simplifies starting the Elrond Docker environment

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
MODE="dev"
DETACHED=false
BUILD=false
PULL=false

# Help message
show_help() {
    cat << EOF
Ledger Docker Startup Script

Usage: ./docker-start.sh [OPTIONS]

Options:
    -h, --help          Show this help message
    -d, --dev           Start in development mode (default)
    -p, --prod          Start in production mode
    -b, --build         Build images before starting
    -D, --detached      Run in detached mode (background)
    -P, --pull          Pull latest images before starting
    -s, --stop          Stop all services
    -r, --restart       Restart all services
    -l, --logs          Show logs (follow mode)
    --clean             Stop and remove all containers, volumes, and images

Examples:
    # Start in development mode
    ./docker-start.sh

    # Start in production mode with build
    ./docker-start.sh --prod --build

    # Start detached
    ./docker-start.sh --detached

    # Show logs
    ./docker-start.sh --logs

    # Stop services
    ./docker-start.sh --stop
EOF
}

# Print header
print_header() {
    echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║   Ledger Docker Environment Manager   ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"

    # Check Docker
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}✗ Docker not found. Please install Docker first.${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Docker installed${NC}"

    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        echo -e "${RED}✗ Docker Compose not found. Please install Docker Compose first.${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Docker Compose installed${NC}"

    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        echo -e "${RED}✗ Docker daemon is not running. Please start Docker.${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Docker daemon running${NC}"

    echo ""
}

# Setup environment
setup_environment() {
    echo -e "${YELLOW}Setting up environment...${NC}"

    # Check for .env file
    if [ ! -f .env ]; then
        if [ -f .env.example ]; then
            echo -e "${YELLOW}⚠ .env file not found. Creating from .env.example${NC}"
            cp .env.example .env
            echo -e "${YELLOW}⚠ Please update .env with your settings!${NC}"
        else
            echo -e "${RED}✗ .env.example not found${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}✓ .env file found${NC}"
    fi

    # Create necessary directories
    mkdir -p evidence output cases
    echo -e "${GREEN}✓ Created necessary directories${NC}"

    echo ""
}

# Start services
start_services() {
    local compose_file="docker/docker-compose.yml"
    local compose_cmd="docker-compose"

    # Use docker compose (v2) if available
    if docker compose version &> /dev/null; then
        compose_cmd="docker compose"
    fi

    # Select compose file
    if [ "$MODE" == "prod" ]; then
        compose_file="docker/docker-compose.prod.yml"
        echo -e "${BLUE}Starting in PRODUCTION mode${NC}"
    else
        echo -e "${BLUE}Starting in DEVELOPMENT mode${NC}"
    fi

    # Build option
    local build_flag=""
    if [ "$BUILD" = true ]; then
        build_flag="--build"
        echo -e "${YELLOW}Building images...${NC}"
    fi

    # Pull option
    if [ "$PULL" = true ]; then
        echo -e "${YELLOW}Pulling latest images...${NC}"
        $compose_cmd -f $compose_file pull
    fi

    # Detached option
    local detach_flag=""
    if [ "$DETACHED" = true ]; then
        detach_flag="-d"
        echo -e "${YELLOW}Starting in detached mode...${NC}"
    fi

    echo ""
    echo -e "${GREEN}Starting Ledger services...${NC}"
    $compose_cmd -f $compose_file up $build_flag $detach_flag

    if [ "$DETACHED" = true ]; then
        echo ""
        echo -e "${GREEN}✓ Services started successfully!${NC}"
        echo ""
        echo -e "${BLUE}Access the application:${NC}"
        echo -e "  Frontend: ${GREEN}http://localhost:3000${NC}"
        echo -e "  Backend API: ${GREEN}http://localhost:8000${NC}"
        echo -e "  API Docs: ${GREEN}http://localhost:8000/docs${NC}"
        echo ""
        echo -e "${YELLOW}View logs:${NC} docker-compose -f $compose_file logs -f"
        echo -e "${YELLOW}Stop services:${NC} ./docker-start.sh --stop"
    fi
}

# Stop services
stop_services() {
    local compose_file="docker/docker-compose.yml"
    local compose_cmd="docker-compose"

    if docker compose version &> /dev/null; then
        compose_cmd="docker compose"
    fi

    if [ "$MODE" == "prod" ]; then
        compose_file="docker/docker-compose.prod.yml"
    fi

    echo -e "${YELLOW}Stopping Ledger services...${NC}"
    $compose_cmd -f $compose_file down

    echo -e "${GREEN}✓ Services stopped${NC}"
}

# Restart services
restart_services() {
    stop_services
    echo ""
    start_services
}

# Show logs
show_logs() {
    local compose_file="docker/docker-compose.yml"
    local compose_cmd="docker-compose"

    if docker compose version &> /dev/null; then
        compose_cmd="docker compose"
    fi

    if [ "$MODE" == "prod" ]; then
        compose_file="docker/docker-compose.prod.yml"
    fi

    echo -e "${BLUE}Showing logs (Ctrl+C to exit)...${NC}"
    $compose_cmd -f $compose_file logs -f
}

# Clean everything
clean_all() {
    local compose_file="docker/docker-compose.yml"
    local compose_cmd="docker-compose"

    if docker compose version &> /dev/null; then
        compose_cmd="docker compose"
    fi

    echo -e "${RED}WARNING: This will remove all Ledger containers, volumes, and images!${NC}"
    read -p "Are you sure? (yes/no): " confirm

    if [ "$confirm" != "yes" ]; then
        echo "Cancelled."
        exit 0
    fi

    echo -e "${YELLOW}Cleaning up...${NC}"

    # Stop and remove containers
    $compose_cmd -f docker/docker-compose.yml down -v --remove-orphans || true
    $compose_cmd -f docker/docker-compose.prod.yml down -v --remove-orphans || true

    # Remove images
    docker images | grep elrond | awk '{print $3}' | xargs -r docker rmi -f || true

    echo -e "${GREEN}✓ Cleanup complete${NC}"
}

# Parse arguments
ACTION="start"

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -d|--dev)
            MODE="dev"
            shift
            ;;
        -p|--prod)
            MODE="prod"
            shift
            ;;
        -b|--build)
            BUILD=true
            shift
            ;;
        -D|--detached)
            DETACHED=true
            shift
            ;;
        -P|--pull)
            PULL=true
            shift
            ;;
        -s|--stop)
            ACTION="stop"
            shift
            ;;
        -r|--restart)
            ACTION="restart"
            shift
            ;;
        -l|--logs)
            ACTION="logs"
            shift
            ;;
        --clean)
            ACTION="clean"
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

# Main execution
print_header

case $ACTION in
    start)
        check_prerequisites
        setup_environment
        start_services
        ;;
    stop)
        stop_services
        ;;
    restart)
        restart_services
        ;;
    logs)
        show_logs
        ;;
    clean)
        clean_all
        ;;
esac

exit 0
