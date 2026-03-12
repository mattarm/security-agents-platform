#!/bin/bash

# Identity Threat Response System Run Script
# Starts the application with proper environment and logging

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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

# Change to project directory
cd "$PROJECT_DIR"

# Default configuration
CONFIG_FILE="config/config.yaml"
HOST="0.0.0.0"
PORT=8000
WORKERS=1
LOG_LEVEL="info"
ENVIRONMENT="development"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --host)
            HOST="$2"
            shift 2
            ;;
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        -w|--workers)
            WORKERS="$2"
            shift 2
            ;;
        --log-level)
            LOG_LEVEL="$2"
            shift 2
            ;;
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --production)
            ENVIRONMENT="production"
            WORKERS=4
            LOG_LEVEL="warning"
            shift
            ;;
        --development|--dev)
            ENVIRONMENT="development"
            WORKERS=1
            LOG_LEVEL="debug"
            shift
            ;;
        -h|--help)
            echo "Identity Threat Response System Runner"
            echo ""
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  -c, --config FILE      Configuration file (default: config/config.yaml)"
            echo "  --host HOST           Host to bind to (default: 0.0.0.0)"
            echo "  -p, --port PORT       Port to bind to (default: 8000)"
            echo "  -w, --workers NUM     Number of worker processes (default: 1)"
            echo "  --log-level LEVEL     Log level (default: info)"
            echo "  -e, --environment ENV Environment (development/production)"
            echo "  --production          Production mode (4 workers, warning log level)"
            echo "  --development         Development mode (1 worker, debug log level)"
            echo "  -h, --help           Show this help message"
            echo ""
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validation
if [ ! -f "$CONFIG_FILE" ]; then
    log_error "Configuration file not found: $CONFIG_FILE"
    log_info "Please run ./scripts/setup.sh first or specify a valid config file"
    exit 1
fi

if [ ! -f ".env" ]; then
    log_warning "Environment file (.env) not found. Some features may not work properly."
fi

# Check for virtual environment
if [ ! -d "venv" ]; then
    log_error "Virtual environment not found. Please run ./scripts/setup.sh first"
    exit 1
fi

# Pre-flight checks
log_info "Performing pre-flight checks..."

# Check Python dependencies
source venv/bin/activate
if ! python3 -c "import fastapi, aiohttp, yaml, cryptography" 2>/dev/null; then
    log_error "Missing required Python dependencies. Please run ./scripts/setup.sh"
    exit 1
fi

# Check configuration validity
if ! python3 -c "
import yaml
try:
    with open('$CONFIG_FILE', 'r') as f:
        config = yaml.safe_load(f)
    if not config.get('okta', {}).get('domain'):
        raise ValueError('Okta domain not configured')
except Exception as e:
    print(f'Configuration error: {e}')
    exit(1)
" 2>/dev/null; then
    log_error "Configuration validation failed"
    exit 1
fi

# Create necessary directories
mkdir -p logs data

# Set environment variables
export PYTHONPATH="$PROJECT_DIR"
export ENVIRONMENT="$ENVIRONMENT"

# Load environment file if it exists
if [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Display startup information
echo "=========================================="
echo "Identity Threat Response System"
echo "=========================================="
echo "Configuration: $CONFIG_FILE"
echo "Environment: $ENVIRONMENT"
echo "Host: $HOST"
echo "Port: $PORT"
echo "Workers: $WORKERS"
echo "Log Level: $LOG_LEVEL"
echo "=========================================="
echo

log_success "Starting application..."

# Start the application
if [ "$ENVIRONMENT" = "development" ]; then
    # Development mode with auto-reload
    python3 main.py \
        --config "$CONFIG_FILE" \
        --host "$HOST" \
        --port "$PORT" \
        --workers "$WORKERS"
else
    # Production mode
    exec uvicorn main:app \
        --host "$HOST" \
        --port "$PORT" \
        --workers "$WORKERS" \
        --log-level "$LOG_LEVEL" \
        --access-log \
        --no-use-colors \
        --loop uvloop \
        --http httptools
fi