#!/bin/bash
set -e

# SecurityAgents Platform - Docker Entrypoint Script
# Handles initialization, health checks, and service startup

echo "🚀 SecurityAgents Platform - Starting..."

# Environment variables with defaults
ENVIRONMENT=${ENVIRONMENT:-development}
API_HOST=${API_HOST:-0.0.0.0}
API_PORT=${API_PORT:-8080}
API_WORKERS=${API_WORKERS:-4}
LOG_LEVEL=${LOG_LEVEL:-INFO}

# Database configuration
DB_HOST=${DB_HOST:-postgres}
DB_PORT=${DB_PORT:-5432}
DB_NAME=${DB_NAME:-security_agents}
DB_USER=${DB_USER:-postgres}

# Redis configuration
REDIS_HOST=${REDIS_HOST:-redis}
REDIS_PORT=${REDIS_PORT:-6379}

echo "📊 Environment: $ENVIRONMENT"
echo "🔗 API: $API_HOST:$API_PORT (workers: $API_WORKERS)"
echo "🗄️ Database: $DB_HOST:$DB_PORT/$DB_NAME"
echo "🔴 Redis: $REDIS_HOST:$REDIS_PORT"

# Function to wait for service
wait_for_service() {
    local host=$1
    local port=$2
    local service_name=$3
    local timeout=${4:-30}
    
    echo "⏳ Waiting for $service_name at $host:$port..."
    
    for i in $(seq 1 $timeout); do
        if nc -z "$host" "$port"; then
            echo "✅ $service_name is ready"
            return 0
        fi
        echo "   Attempt $i/$timeout - $service_name not ready, waiting..."
        sleep 1
    done
    
    echo "❌ $service_name failed to start within $timeout seconds"
    return 1
}

# Function to check database connection
check_database() {
    echo "🔍 Checking database connection..."
    
    export PGPASSWORD=$DB_PASSWORD
    
    if pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME"; then
        echo "✅ Database connection successful"
        return 0
    else
        echo "❌ Database connection failed"
        return 1
    fi
}

# Function to check Redis connection
check_redis() {
    echo "🔍 Checking Redis connection..."
    
    if redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping | grep -q PONG; then
        echo "✅ Redis connection successful"
        return 0
    else
        echo "❌ Redis connection failed"
        return 1
    fi
}

# Function to run database migrations
run_migrations() {
    echo "🔄 Running database migrations..."
    # Add your migration commands here
    # python manage.py migrate
    echo "✅ Migrations complete"
}

# Function to initialize data
initialize_data() {
    echo "📊 Initializing application data..."
    # Add your data initialization here
    echo "✅ Data initialization complete"
}

# Function to validate configuration
validate_config() {
    echo "🔧 Validating configuration..."
    
    python -c "
from config_manager import ConfigManager
import sys

try:
    config = ConfigManager()
    print('✅ Configuration validation passed')
except Exception as e:
    print(f'❌ Configuration validation failed: {e}')
    sys.exit(1)
"
}

# Function to start API server
start_api() {
    echo "🌐 Starting API server..."
    
    exec python production_api_server.py \
        --host "$API_HOST" \
        --port "$API_PORT" \
        --workers "$API_WORKERS"
}

# Function to start orchestrator
start_orchestrator() {
    echo "🎯 Starting orchestrator..."
    
    exec python agent_orchestration_system.py
}

# Function to start worker
start_worker() {
    echo "⚡ Starting worker..."
    
    # Add worker startup logic here
    exec python -c "
import asyncio
from agent_orchestration_system import SecurityAgentOrchestrator

async def main():
    orchestrator = SecurityAgentOrchestrator()
    await orchestrator.start()

if __name__ == '__main__':
    asyncio.run(main())
"
}

# Function to run health check
health_check() {
    echo "🏥 Running health check..."
    
    curl -f "http://localhost:$API_PORT/health" || {
        echo "❌ Health check failed"
        exit 1
    }
    
    echo "✅ Health check passed"
}

# Main execution logic
main() {
    local command=${1:-api}
    
    # Always validate configuration first
    validate_config
    
    case "$command" in
        "api")
            # Wait for dependencies
            if [ "$ENVIRONMENT" != "development" ]; then
                wait_for_service "$DB_HOST" "$DB_PORT" "Database" 60
                wait_for_service "$REDIS_HOST" "$REDIS_PORT" "Redis" 30
                
                # Additional checks in production
                if [ "$ENVIRONMENT" = "production" ]; then
                    check_database
                    check_redis
                fi
            fi
            
            start_api
            ;;
            
        "orchestrator")
            if [ "$ENVIRONMENT" != "development" ]; then
                wait_for_service "$DB_HOST" "$DB_PORT" "Database" 60
                wait_for_service "$REDIS_HOST" "$REDIS_PORT" "Redis" 30
            fi
            
            start_orchestrator
            ;;
            
        "worker")
            if [ "$ENVIRONMENT" != "development" ]; then
                wait_for_service "$DB_HOST" "$DB_PORT" "Database" 60
                wait_for_service "$REDIS_HOST" "$REDIS_PORT" "Redis" 30
            fi
            
            start_worker
            ;;
            
        "migrate")
            wait_for_service "$DB_HOST" "$DB_PORT" "Database" 60
            run_migrations
            ;;
            
        "init")
            wait_for_service "$DB_HOST" "$DB_PORT" "Database" 60
            run_migrations
            initialize_data
            ;;
            
        "health")
            health_check
            ;;
            
        "bash")
            echo "🐚 Starting bash shell..."
            exec bash
            ;;
            
        *)
            echo "❌ Unknown command: $command"
            echo "Available commands: api, orchestrator, worker, migrate, init, health, bash"
            exit 1
            ;;
    esac
}

# Handle signals for graceful shutdown
cleanup() {
    echo "🛑 Received shutdown signal, cleaning up..."
    # Add cleanup logic here
    exit 0
}

trap cleanup SIGTERM SIGINT

# Run main function
main "$@"