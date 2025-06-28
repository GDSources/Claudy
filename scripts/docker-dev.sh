#!/bin/bash

# Claudy Docker Development Helper Script
# Provides convenient commands for Docker-based development

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        log_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
}

# Check if docker-compose is available
check_compose() {
    if ! command -v docker-compose > /dev/null 2>&1; then
        log_error "docker-compose is not installed. Please install docker-compose and try again."
        exit 1
    fi
}

# Wait for service to be healthy
wait_for_service() {
    local service=$1
    local max_attempts=30
    local attempt=1
    
    log_info "Waiting for $service to be healthy..."
    
    while [ $attempt -le $max_attempts ]; do
        if docker-compose ps | grep "$service" | grep "healthy" > /dev/null; then
            log_success "$service is healthy!"
            return 0
        fi
        
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    log_error "$service failed to become healthy within $((max_attempts * 2)) seconds"
    return 1
}

# Start development environment
dev_start() {
    log_info "Starting Claudy development environment..."
    
    check_docker
    check_compose
    
    # Create .env file if it doesn't exist
    if [ ! -f .env ]; then
        log_info "Creating .env file from template..."
        cp .env.docker .env
        log_warning "Please review and customize .env file as needed"
    fi
    
    # Pull latest images
    log_info "Pulling latest Docker images..."
    docker-compose pull
    
    # Build application image
    log_info "Building application image..."
    docker-compose build app
    
    # Start services in background
    log_info "Starting services..."
    docker-compose up -d
    
    # Wait for services to be healthy
    wait_for_service "claudy-mongo-dev"
    wait_for_service "claudy-redis-dev"
    wait_for_service "claudy-backend-dev"
    
    log_success "Development environment is ready!"
    log_info "Services:"
    log_info "  • Application: http://localhost:8080"
    log_info "  • MongoDB Express: http://localhost:8081 (admin/admin)"
    log_info "  • Redis Commander: http://localhost:8082 (admin/admin)"
    log_info "  • Documentation: http://localhost:8083"
    log_info "  • MailHog: http://localhost:8025"
    log_info ""
    log_info "Use './scripts/docker-dev.sh logs' to view application logs"
    log_info "Use './scripts/docker-dev.sh stop' to stop services"
}

# Stop development environment
dev_stop() {
    log_info "Stopping Claudy development environment..."
    docker-compose down
    log_success "Development environment stopped"
}

# Restart development environment
dev_restart() {
    log_info "Restarting Claudy development environment..."
    docker-compose restart
    log_success "Development environment restarted"
}

# View logs
dev_logs() {
    local service=${1:-app}
    log_info "Showing logs for $service..."
    docker-compose logs -f "$service"
}

# Execute command in app container
dev_exec() {
    if [ $# -eq 0 ]; then
        log_info "Opening shell in app container..."
        docker-compose exec app sh
    else
        log_info "Executing command in app container: $*"
        docker-compose exec app "$@"
    fi
}

# Run tests
dev_test() {
    log_info "Running tests in Docker environment..."
    
    # Start test services
    log_info "Starting test services..."
    docker-compose --profile testing up -d mongo-test redis-test
    
    # Wait for test services
    wait_for_service "claudy-mongo-test"
    wait_for_service "claudy-redis-test"
    
    # Run tests
    docker-compose exec app go test ./... -v
    
    # Stop test services
    log_info "Stopping test services..."
    docker-compose --profile testing down
    
    log_success "Tests completed"
}

# Run integration tests
dev_test_integration() {
    log_info "Running integration tests in Docker environment..."
    
    # Start test services
    docker-compose --profile testing up -d mongo-test redis-test
    
    # Wait for test services
    wait_for_service "claudy-mongo-test"
    wait_for_service "claudy-redis-test"
    
    # Set test environment variables
    docker-compose exec app sh -c "
        export TEST_MONGO_URI=mongodb://root:testpassword@mongo-test:27017/claudy_test?authSource=admin
        export TEST_REDIS_ADDR=redis-test:6379
        go test ./tests/integration/... -v -timeout=300s
    "
    
    # Stop test services
    docker-compose --profile testing down
    
    log_success "Integration tests completed"
}

# Clean up Docker resources
dev_clean() {
    log_info "Cleaning up Docker resources..."
    
    docker-compose down -v
    docker system prune -f
    docker volume prune -f
    
    log_success "Docker cleanup completed"
}

# Show service status
dev_status() {
    log_info "Service status:"
    docker-compose ps
    
    echo ""
    log_info "Resource usage:"
    docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"
}

# Debug application
dev_debug() {
    log_info "Starting debug session..."
    log_info "Connect your debugger to localhost:2345"
    docker-compose exec app dlv attach --headless --listen=:2345 --api-version=2 1
}

# Build production image
dev_build_prod() {
    log_info "Building production image..."
    docker build --target production -t claudy-backend:latest .
    log_success "Production image built: claudy-backend:latest"
}

# Show help
show_help() {
    echo "Claudy Docker Development Helper"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  start             Start development environment"
    echo "  stop              Stop development environment"
    echo "  restart           Restart development environment"
    echo "  logs [service]    Show logs (default: app)"
    echo "  exec [command]    Execute command in app container (default: shell)"
    echo "  test              Run unit tests"
    echo "  test-integration  Run integration tests"
    echo "  clean             Clean up Docker resources"
    echo "  status            Show service status and resource usage"
    echo "  debug             Start debug session"
    echo "  build-prod        Build production image"
    echo "  help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 start                    # Start development environment"
    echo "  $0 logs app                 # Show app logs"
    echo "  $0 exec go test ./...       # Run tests in container"
    echo "  $0 exec go mod tidy         # Update dependencies"
}

# Main command dispatcher
case "${1:-help}" in
    start)
        dev_start
        ;;
    stop)
        dev_stop
        ;;
    restart)
        dev_restart
        ;;
    logs)
        dev_logs "${2:-app}"
        ;;
    exec)
        shift
        dev_exec "$@"
        ;;
    test)
        dev_test
        ;;
    test-integration)
        dev_test_integration
        ;;
    clean)
        dev_clean
        ;;
    status)
        dev_status
        ;;
    debug)
        dev_debug
        ;;
    build-prod)
        dev_build_prod
        ;;
    help)
        show_help
        ;;
    *)
        log_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac