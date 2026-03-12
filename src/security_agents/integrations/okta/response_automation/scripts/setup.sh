#!/bin/bash

# Identity Threat Response System Setup Script
# This script sets up the environment and installs dependencies

set -euo pipefail

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

# Check if Python 3.11+ is installed
check_python() {
    log_info "Checking Python version..."
    
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed. Please install Python 3.11 or higher."
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    REQUIRED_VERSION="3.11"
    
    if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 11) else 1)" 2>/dev/null; then
        log_error "Python ${PYTHON_VERSION} is installed, but Python ${REQUIRED_VERSION}+ is required."
        exit 1
    fi
    
    log_success "Python ${PYTHON_VERSION} is installed"
}

# Create virtual environment
create_venv() {
    log_info "Creating Python virtual environment..."
    
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        log_success "Virtual environment created"
    else
        log_warning "Virtual environment already exists"
    fi
}

# Activate virtual environment and install dependencies
install_dependencies() {
    log_info "Installing Python dependencies..."
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install dependencies
    pip install -r requirements.txt
    
    log_success "Dependencies installed"
}

# Create necessary directories
create_directories() {
    log_info "Creating necessary directories..."
    
    mkdir -p logs
    mkdir -p data
    mkdir -p config
    
    log_success "Directories created"
}

# Setup configuration
setup_config() {
    log_info "Setting up configuration..."
    
    if [ ! -f "config/config.yaml" ]; then
        if [ -f "config/config.example.yaml" ]; then
            cp config/config.example.yaml config/config.yaml
            log_warning "Configuration copied from example. Please edit config/config.yaml with your settings."
        else
            log_error "Example configuration file not found!"
            exit 1
        fi
    else
        log_warning "Configuration file already exists"
    fi
}

# Setup environment file
setup_env() {
    log_info "Setting up environment file..."
    
    if [ ! -f ".env" ]; then
        cat > .env << EOF
# Identity Threat Response System Environment Variables
# Copy this file and update with your actual values

# Okta Configuration
OKTA_API_TOKEN=your_okta_api_token_here

# Panther SIEM
PANTHER_API_KEY=your_panther_api_key_here

# CrowdStrike
CROWDSTRIKE_CLIENT_ID=your_crowdstrike_client_id
CROWDSTRIKE_CLIENT_SECRET=your_crowdstrike_client_secret

# TheHive
THEHIVE_API_KEY=your_thehive_api_key_here

# Notification Settings
SOC_SLACK_WEBHOOK=your_soc_slack_webhook_url
SECURITY_AGENTS_API=your_security_agents_api_endpoint
SECURITY_AGENTS_KEY=your_security_agents_api_key

# Email Configuration (for user notifications)
SMTP_PASSWORD=your_smtp_password

# Optional: Database (if using persistent storage)
# DATABASE_URL=postgresql://user:password@localhost/identity_response
EOF
        log_warning "Environment file created. Please edit .env with your actual values."
    else
        log_warning "Environment file already exists"
    fi
}

# Set file permissions
set_permissions() {
    log_info "Setting file permissions..."
    
    # Make scripts executable
    chmod +x scripts/*.sh
    
    # Secure config and data directories
    chmod 750 config
    chmod 750 data
    chmod 750 logs
    
    # Secure environment file
    chmod 600 .env 2>/dev/null || true
    
    log_success "Permissions set"
}

# Install system dependencies (Ubuntu/Debian)
install_system_deps() {
    if command -v apt-get &> /dev/null; then
        log_info "Installing system dependencies (Ubuntu/Debian)..."
        
        sudo apt-get update
        sudo apt-get install -y \
            curl \
            wget \
            git \
            build-essential \
            libffi-dev \
            libssl-dev \
            python3-dev
        
        log_success "System dependencies installed"
    elif command -v yum &> /dev/null; then
        log_info "Installing system dependencies (RHEL/CentOS)..."
        
        sudo yum update -y
        sudo yum install -y \
            curl \
            wget \
            git \
            gcc \
            openssl-devel \
            libffi-devel \
            python3-devel
        
        log_success "System dependencies installed"
    else
        log_warning "Could not detect package manager. Please install build tools manually."
    fi
}

# Test installation
test_installation() {
    log_info "Testing installation..."
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Test imports
    if python3 -c "import fastapi, aiohttp, cryptography" 2>/dev/null; then
        log_success "Core dependencies import successfully"
    else
        log_error "Dependency import test failed"
        exit 1
    fi
    
    # Test configuration loading
    if python3 -c "
import yaml
try:
    with open('config/config.yaml', 'r') as f:
        yaml.safe_load(f)
    print('Configuration file is valid')
except Exception as e:
    print(f'Configuration validation failed: {e}')
    exit(1)
    " 2>/dev/null; then
        log_success "Configuration file is valid"
    else
        log_error "Configuration validation failed"
        exit 1
    fi
}

# Main setup function
main() {
    echo "=========================================="
    echo "Identity Threat Response System Setup"
    echo "=========================================="
    echo
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        log_warning "Running as root. Consider running as a regular user."
    fi
    
    # System-specific setup
    if [ "${1:-}" = "--with-system-deps" ]; then
        install_system_deps
    fi
    
    # Core setup steps
    check_python
    create_directories
    create_venv
    install_dependencies
    setup_config
    setup_env
    set_permissions
    test_installation
    
    echo
    log_success "Setup completed successfully!"
    echo
    echo "Next steps:"
    echo "1. Edit config/config.yaml with your specific settings"
    echo "2. Edit .env with your API keys and credentials"
    echo "3. Run the system with: ./scripts/run.sh"
    echo
    echo "For production deployment:"
    echo "- Use Docker: docker-compose up -d"
    echo "- Or systemd service: ./scripts/install-service.sh"
    echo
}

# Run main function
main "$@"