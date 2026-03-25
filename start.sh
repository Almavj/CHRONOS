#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_help() {
    cat << EOF
CHRONOS - APT Detection Platform

Usage: $0 [COMMAND] [OPTIONS]

Commands:
    start           Start all CHRONOS services (full stack)
    start-core      Start only core services (API, Engine, Redis)
    start-full      Start full stack with all optional services
    stop            Stop all CHRONOS services
    restart         Restart all services
    status          Show status of all services
    logs [SERVICE]  Show logs for a specific service (or all)
    clean           Stop and remove all containers and volumes
    test            Run system verification tests

Options:
    -h, --help      Show this help message
    -v, --verbose   Enable verbose output

Examples:
    $0 start              Start full stack
    $0 start-core         Start core services only
    $0 logs chronos-api   View API logs
    $0 status             Check service status
    $0 test               Run verification tests

EOF
}

start_core() {
    log_info "Starting CHRONOS core services..."
    docker compose --profile default up -d
    log_success "Core services started!"
}

start_full() {
    log_info "Starting CHRONOS full stack (including Wazuh, Elasticsearch, Kafka, etc.)..."
    
    log_info "Building Docker images if needed..."
    docker compose build chronos-api chronos-engine chronos-frontend 2>/dev/null || true
    
    log_info "Starting all services with 'full' profile..."
    docker compose --profile full up -d
    
    log_success "Full stack started!"
    log_info "Services available at:"
    echo "  - CHRONOS Frontend:  http://localhost:80"
    echo "  - CHRONOS API:       http://localhost:8000"
    echo "  - Elasticsearch:      http://localhost:19200"
    echo "  - Kibana:            http://localhost:5601"
    echo "  - Grafana:           http://localhost:3000"
    echo "  - Kafka UI:          http://localhost:8080"
    echo "  - Neo4j Browser:     http://localhost:7474"
    echo "  - MISP:              https://localhost:8443"
}

stop_services() {
    log_info "Stopping CHRONOS services..."
    docker compose down
    log_success "Services stopped!"
}

restart_services() {
    stop_services
    sleep 2
    start_full
}

show_status() {
    echo ""
    echo "========================================="
    echo "🔍 CHRONOS SERVICE STATUS"
    echo "========================================="
    echo ""
    
    docker compose ps
}

show_logs() {
    local service="${1:-}"
    if [ -n "$service" ]; then
        docker compose logs -f "$service"
    else
        docker compose logs -f
    fi
}

clean_all() {
    log_warn "This will remove ALL CHRONOS containers and volumes!"
    read -p "Are you sure? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Stopping and removing containers..."
        docker compose down -v
        log_info "Removing build artifacts..."
        docker compose build --rmi local 2>/dev/null || true
        log_success "Clean complete!"
    else
        log_info "Clean cancelled."
    fi
}

run_tests() {
    chmod +x "$SCRIPT_DIR/test.sh"
    "$SCRIPT_DIR/test.sh"
}

case "${1:-start}" in
    start|start-core)
        start_core
        ;;
    start-full|full)
        start_full
        ;;
    stop)
        stop_services
        ;;
    restart)
        restart_services
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs "$2"
        ;;
    clean)
        clean_all
        ;;
    test)
        run_tests
        ;;
    -h|--help|help)
        show_help
        ;;
    *)
        log_error "Unknown command: $1"
        echo ""
        show_help
        exit 1
        ;;
esac
