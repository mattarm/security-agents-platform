#!/bin/bash
# Okta Security Integration - Deployment Script

set -e

echo "🔐 Okta Security Integration - Production Deployment"
echo "=================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DEPLOY_ENV=${1:-production}
CONFIG_FILE="config/config.yml"
SERVICE_NAME="okta-security"
VENV_PATH="venv"

echo -e "${BLUE}Deployment Environment: ${DEPLOY_ENV}${NC}"
echo

# Function to print status
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Check prerequisites
echo "📋 Checking Prerequisites..."

# Check Python version
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    if python3 -c 'import sys; exit(0 if sys.version_info >= (3, 8) else 1)'; then
        print_status "Python ${PYTHON_VERSION} (compatible)"
    else
        print_error "Python 3.8+ required (found ${PYTHON_VERSION})"
        exit 1
    fi
else
    print_error "Python 3 not found"
    exit 1
fi

# Check required environment variables
required_vars=(
    "OKTA_API_TOKEN"
    "PANTHER_HTTP_ENDPOINT"
    "PANTHER_API_TOKEN"
)

missing_vars=()
for var in "${required_vars[@]}"; do
    if [[ -z "${!var}" ]]; then
        missing_vars+=("$var")
    else
        print_status "Environment variable: $var"
    fi
done

if [[ ${#missing_vars[@]} -gt 0 ]]; then
    print_error "Missing required environment variables:"
    for var in "${missing_vars[@]}"; do
        echo "  - $var"
    done
    echo
    echo "Set them with: export VAR_NAME=value"
    exit 1
fi

# Check configuration file
if [[ -f "$CONFIG_FILE" ]]; then
    print_status "Configuration file: $CONFIG_FILE"
else
    if [[ -f "config/config.example.yml" ]]; then
        print_warning "Config file not found, copying from example"
        cp config/config.example.yml "$CONFIG_FILE"
        print_status "Created config file from example"
    else
        print_error "Configuration file not found: $CONFIG_FILE"
        exit 1
    fi
fi

echo

# Setup virtual environment
echo "🐍 Setting up Python Environment..."

if [[ ! -d "$VENV_PATH" ]]; then
    print_status "Creating virtual environment"
    python3 -m venv "$VENV_PATH"
fi

# Activate virtual environment
source "$VENV_PATH/bin/activate"
print_status "Activated virtual environment"

# Upgrade pip
pip install --upgrade pip > /dev/null 2>&1
print_status "Updated pip"

# Install dependencies
if [[ -f "requirements.txt" ]]; then
    print_status "Installing Python dependencies"
    pip install -r requirements.txt > /dev/null 2>&1
    print_status "Dependencies installed"
else
    print_error "requirements.txt not found"
    exit 1
fi

echo

# Run tests (optional)
if [[ "$DEPLOY_ENV" != "production" ]]; then
    echo "🧪 Running Tests..."
    
    if command -v pytest &> /dev/null && [[ -d "tests" ]]; then
        if pytest tests/ --tb=short -q; then
            print_status "All tests passed"
        else
            print_warning "Some tests failed (continuing deployment)"
        fi
    else
        print_warning "Tests not available (pytest or tests/ directory not found)"
    fi
    echo
fi

# Connectivity test
echo "🔗 Testing Connectivity..."

if python3 main.py test-connectivity; then
    print_status "Connectivity test passed"
else
    print_error "Connectivity test failed"
    echo "Please check your configuration and network connectivity"
    exit 1
fi

echo

# Create directories
echo "📁 Creating Directories..."

directories=(
    "logs"
    "models"
    "data"
)

for dir in "${directories[@]}"; do
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir"
        print_status "Created directory: $dir"
    else
        print_status "Directory exists: $dir"
    fi
done

echo

# Set up systemd service (Linux only)
if [[ "$OSTYPE" == "linux-gnu"* ]] && command -v systemctl &> /dev/null; then
    echo "⚙️ Setting up Systemd Service..."
    
    SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
    CURRENT_USER=$(whoami)
    CURRENT_DIR=$(pwd)
    
    if [[ ! -f "$SERVICE_FILE" ]] || [[ "$1" == "--force-service" ]]; then
        print_status "Creating systemd service file"
        
        sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=Okta Security Integration Platform
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=$CURRENT_USER
Group=$CURRENT_USER
WorkingDirectory=$CURRENT_DIR
Environment=PATH=$CURRENT_DIR/$VENV_PATH/bin
ExecStart=$CURRENT_DIR/$VENV_PATH/bin/python main.py run --config $CONFIG_FILE
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$CURRENT_DIR

# Environment variables
Environment=OKTA_API_TOKEN=$OKTA_API_TOKEN
Environment=PANTHER_HTTP_ENDPOINT=$PANTHER_HTTP_ENDPOINT
Environment=PANTHER_API_TOKEN=$PANTHER_API_TOKEN

[Install]
WantedBy=multi-user.target
EOF
        
        sudo systemctl daemon-reload
        sudo systemctl enable "$SERVICE_NAME"
        print_status "Systemd service configured and enabled"
    else
        print_status "Systemd service already exists"
    fi
    
    echo
fi

# Create startup script
echo "🚀 Creating Startup Script..."

cat > start.sh <<EOF
#!/bin/bash
# Okta Security Integration - Startup Script

cd "\$(dirname "\$0")"
source venv/bin/activate

echo "Starting Okta Security Integration..."
python main.py run --config config/config.yml
EOF

chmod +x start.sh
print_status "Created start.sh script"

# Create stop script for systemd
if [[ "$OSTYPE" == "linux-gnu"* ]] && command -v systemctl &> /dev/null; then
    cat > stop.sh <<EOF
#!/bin/bash
# Okta Security Integration - Stop Script

echo "Stopping Okta Security Integration service..."
sudo systemctl stop $SERVICE_NAME
echo "Service stopped"
EOF

    cat > restart.sh <<EOF
#!/bin/bash
# Okta Security Integration - Restart Script

echo "Restarting Okta Security Integration service..."
sudo systemctl restart $SERVICE_NAME
echo "Service restarted"

# Show status
sudo systemctl status $SERVICE_NAME --no-pager
EOF

    chmod +x stop.sh restart.sh
    print_status "Created stop.sh and restart.sh scripts"
fi

echo

# Final deployment steps
echo "🎯 Final Deployment Steps..."

if [[ "$DEPLOY_ENV" == "production" ]]; then
    # Start service in production
    if [[ "$OSTYPE" == "linux-gnu"* ]] && command -v systemctl &> /dev/null; then
        print_status "Starting systemd service"
        sudo systemctl start "$SERVICE_NAME"
        
        # Check service status
        if sudo systemctl is-active --quiet "$SERVICE_NAME"; then
            print_status "Service is running"
        else
            print_error "Service failed to start"
            echo "Check logs with: sudo journalctl -u $SERVICE_NAME -f"
            exit 1
        fi
    else
        print_status "Manual start required (systemd not available)"
        echo "Run: ./start.sh"
    fi
else
    # Development/staging
    print_status "Development deployment complete"
    echo "Start manually with: ./start.sh"
fi

echo

# Health check
echo "🏥 Health Check..."

# Wait a moment for service to start
sleep 3

if curl -s http://localhost:8080/health > /dev/null 2>&1; then
    print_status "Health check endpoint responding"
    
    # Show health status
    echo
    echo "Health Status:"
    curl -s http://localhost:8080/health | python3 -m json.tool
else
    print_warning "Health check endpoint not responding yet"
    echo "This may be normal during startup. Check again in a few moments."
fi

echo

# Deployment summary
echo "📊 Deployment Summary"
echo "===================="
echo "Environment: $DEPLOY_ENV"
echo "Python Version: $PYTHON_VERSION"
echo "Configuration: $CONFIG_FILE"
echo "Virtual Environment: $VENV_PATH"

if [[ "$OSTYPE" == "linux-gnu"* ]] && command -v systemctl &> /dev/null; then
    echo "Systemd Service: $SERVICE_NAME"
    echo "Service Status: $(sudo systemctl is-active $SERVICE_NAME)"
fi

echo
echo "🎉 Deployment Complete!"
echo

# Show next steps
echo "Next Steps:"
echo "==========="

if [[ "$DEPLOY_ENV" == "production" ]]; then
    if [[ "$OSTYPE" == "linux-gnu"* ]] && command -v systemctl &> /dev/null; then
        echo "• Monitor service: sudo systemctl status $SERVICE_NAME"
        echo "• View logs: sudo journalctl -u $SERVICE_NAME -f"
        echo "• Restart service: sudo systemctl restart $SERVICE_NAME"
    fi
    echo "• Health check: curl http://localhost:8080/health"
    echo "• Metrics: curl http://localhost:8080/metrics"
    echo "• Statistics: curl http://localhost:8080/statistics"
else
    echo "• Start application: ./start.sh"
    echo "• Test connectivity: python main.py test-connectivity"
    echo "• Collect test events: python main.py collect-events --hours 1"
fi

echo "• Review configuration: $CONFIG_FILE"
echo "• Monitor logs in: logs/"
echo

echo -e "${GREEN}🔐 Okta Security Integration is ready!${NC}"