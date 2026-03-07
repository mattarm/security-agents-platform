#!/bin/bash

# SecOps AI Platform - Deployment Script
# Tiger Team Beta-2: AI Orchestration with Graduated Autonomy

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ENVIRONMENT=${ENVIRONMENT:-dev}
AWS_REGION=${AWS_REGION:-us-east-1}
PROJECT_NAME="secops-ai"

echo -e "${BLUE}🚀 SecOps AI Platform Deployment${NC}"
echo -e "${BLUE}Environment: ${ENVIRONMENT}${NC}"
echo -e "${BLUE}AWS Region: ${AWS_REGION}${NC}"
echo ""

# Function to print status messages
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Function to check prerequisites
check_prerequisites() {
    echo -e "${BLUE}🔍 Checking prerequisites...${NC}"
    
    # Check if AWS CLI is installed
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI is not installed. Please install it first."
        exit 1
    fi
    print_status "AWS CLI found"
    
    # Check if Terraform is installed
    if ! command -v terraform &> /dev/null; then
        print_error "Terraform is not installed. Please install it first."
        exit 1
    fi
    print_status "Terraform found"
    
    # Check if Python 3.9+ is installed
    if ! python3 -c "import sys; assert sys.version_info >= (3, 9)" 2>/dev/null; then
        print_error "Python 3.9+ is required. Please upgrade your Python version."
        exit 1
    fi
    print_status "Python 3.9+ found"
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        print_error "AWS credentials not configured. Please run 'aws configure'."
        exit 1
    fi
    print_status "AWS credentials configured"
    
    echo ""
}

# Function to set up Python environment
setup_python_env() {
    echo -e "${BLUE}🐍 Setting up Python environment...${NC}"
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        print_status "Created Python virtual environment"
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    print_status "Activated virtual environment"
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install requirements
    pip install -r requirements.txt
    print_status "Installed Python dependencies"
    
    echo ""
}

# Function to deploy infrastructure
deploy_infrastructure() {
    echo -e "${BLUE}🏗️ Deploying AWS infrastructure...${NC}"
    
    cd infrastructure
    
    # Initialize Terraform
    terraform init
    print_status "Terraform initialized"
    
    # Create Terraform workspace for environment
    terraform workspace select ${ENVIRONMENT} 2>/dev/null || terraform workspace new ${ENVIRONMENT}
    print_status "Terraform workspace: ${ENVIRONMENT}"
    
    # Plan deployment
    terraform plan \
        -var="environment=${ENVIRONMENT}" \
        -var="project_name=${PROJECT_NAME}" \
        -out=tfplan
    print_status "Terraform plan created"
    
    # Apply deployment
    if [ "${ENVIRONMENT}" = "prod" ]; then
        echo -e "${YELLOW}Production deployment detected. Please review the plan above.${NC}"
        read -p "Continue with deployment? (y/N): " confirm
        if [[ $confirm != [yY] ]]; then
            print_warning "Deployment cancelled"
            exit 0
        fi
    fi
    
    terraform apply tfplan
    print_status "AWS infrastructure deployed"
    
    # Extract outputs
    VPC_ID=$(terraform output -raw vpc_id)
    KMS_KEY_ID=$(terraform output -raw kms_key_id)
    BEDROCK_ENDPOINT=$(terraform output -raw bedrock_endpoint_id)
    IAM_ROLE_ARN=$(terraform output -raw iam_role_arn)
    
    print_status "Infrastructure outputs extracted"
    
    cd ..
    echo ""
}

# Function to configure application
configure_application() {
    echo -e "${BLUE}⚙️ Configuring application...${NC}"
    
    # Create .env file if it doesn't exist
    if [ ! -f ".env" ]; then
        cp .env.example .env 2>/dev/null || echo "# SecOps AI Platform Configuration" > .env
        print_status "Created .env file"
    fi
    
    # Update .env with infrastructure outputs
    cat >> .env << EOF

# Infrastructure Configuration (Auto-generated)
SECOPS_AI_AWS_REGION=${AWS_REGION}
SECOPS_AI_VPC_ID=${VPC_ID}
SECOPS_AI_KMS_KEY_ID=${KMS_KEY_ID}
SECOPS_AI_BEDROCK_ENDPOINT=${BEDROCK_ENDPOINT}
SECOPS_AI_IAM_ROLE_ARN=${IAM_ROLE_ARN}

# Environment
SECOPS_AI_ENVIRONMENT=${ENVIRONMENT}
EOF
    
    print_status "Updated configuration with infrastructure details"
    
    echo ""
}

# Function to run database migrations
setup_database() {
    echo -e "${BLUE}🗄️ Setting up audit database...${NC}"
    
    # Create audit database directory
    mkdir -p data
    
    # Initialize audit database (SQLite)
    python3 -c "
from ai_engine.audit_logger import AuditLogger
import asyncio

async def init_db():
    config = {'audit_db_path': 'data/audit_log.db'}
    logger = AuditLogger(config)
    print('Audit database initialized')

asyncio.run(init_db())
"
    
    print_status "Audit database initialized"
    
    echo ""
}

# Function to run tests
run_tests() {
    echo -e "${BLUE}🧪 Running tests...${NC}"
    
    # Run unit tests
    pytest tests/ -v --cov=. --cov-report=html --cov-report=term
    
    if [ $? -eq 0 ]; then
        print_status "All tests passed"
    else
        print_error "Tests failed"
        exit 1
    fi
    
    echo ""
}

# Function to start services
start_services() {
    echo -e "${BLUE}🚀 Starting services...${NC}"
    
    if [ "${ENVIRONMENT}" = "dev" ]; then
        # Development mode - start with auto-reload
        echo -e "${YELLOW}Starting in development mode with auto-reload${NC}"
        python3 main.py &
        SERVER_PID=$!
        print_status "Development server started (PID: ${SERVER_PID})"
    else
        # Production mode - use Gunicorn
        echo -e "${BLUE}Starting in production mode${NC}"
        gunicorn main:app \
            --workers 4 \
            --worker-class uvicorn.workers.UvicornWorker \
            --bind 0.0.0.0:8080 \
            --timeout 30 \
            --keep-alive 2 \
            --max-requests 1000 \
            --max-requests-jitter 50 \
            --preload \
            --daemon
        print_status "Production server started"
    fi
    
    # Wait for service to be ready
    echo "Waiting for service to be ready..."
    for i in {1..30}; do
        if curl -s http://localhost:8080/health > /dev/null; then
            print_status "Service is ready"
            break
        fi
        sleep 2
    done
    
    echo ""
}

# Function to validate deployment
validate_deployment() {
    echo -e "${BLUE}✅ Validating deployment...${NC}"
    
    # Test health endpoint
    HEALTH_RESPONSE=$(curl -s http://localhost:8080/health)
    if echo "${HEALTH_RESPONSE}" | grep -q '"status":"healthy"'; then
        print_status "Health check passed"
    else
        print_error "Health check failed"
        echo "${HEALTH_RESPONSE}"
        exit 1
    fi
    
    # Test metrics endpoint
    METRICS_RESPONSE=$(curl -s http://localhost:8080/metrics)
    if echo "${METRICS_RESPONSE}" | grep -q '"total_actions"'; then
        print_status "Metrics endpoint working"
    else
        print_warning "Metrics endpoint may have issues"
    fi
    
    # Test a sample alert processing (if not in production)
    if [ "${ENVIRONMENT}" != "prod" ]; then
        SAMPLE_ALERT='{
            "title": "Test Alert",
            "description": "Deployment validation test",
            "severity": "low",
            "source": "deployment_test",
            "evidence": {"test": true},
            "metadata": {"deployment": true}
        }'
        
        ALERT_RESPONSE=$(curl -s -X POST \
            -H "Content-Type: application/json" \
            -d "${SAMPLE_ALERT}" \
            http://localhost:8080/analyze)
        
        if echo "${ALERT_RESPONSE}" | grep -q '"status"'; then
            print_status "Alert processing test passed"
        else
            print_warning "Alert processing test failed"
        fi
    fi
    
    echo ""
}

# Function to display deployment summary
deployment_summary() {
    echo -e "${GREEN}🎉 Deployment completed successfully!${NC}"
    echo ""
    echo -e "${BLUE}📋 Deployment Summary${NC}"
    echo -e "Environment: ${ENVIRONMENT}"
    echo -e "AWS Region: ${AWS_REGION}"
    echo -e "Application URL: http://localhost:8080"
    echo -e "API Documentation: http://localhost:8080/docs"
    echo -e "Health Check: http://localhost:8080/health"
    echo ""
    
    echo -e "${BLUE}🔍 Next Steps${NC}"
    echo "1. Configure Slack webhook URL in .env for approval workflows"
    echo "2. Set up monitoring and alerting"
    echo "3. Configure firewall rules for production access"
    echo "4. Review and customize autonomy tier thresholds"
    echo "5. Set up backup and disaster recovery"
    echo ""
    
    echo -e "${BLUE}📚 Documentation${NC}"
    echo "- README.md: Getting started guide"
    echo "- API docs: http://localhost:8080/docs"
    echo "- Architecture: infrastructure/bedrock-vpc.tf"
    echo ""
    
    if [ "${ENVIRONMENT}" = "dev" ]; then
        echo -e "${YELLOW}💡 Development Tips${NC}"
        echo "- Use 'source venv/bin/activate' to activate Python environment"
        echo "- Run 'pytest tests/' to execute test suite"
        echo "- Check logs in secops-ai.log"
        echo "- Use Ctrl+C to stop development server"
    fi
}

# Main deployment flow
main() {
    echo -e "${BLUE}Starting SecOps AI Platform deployment...${NC}"
    echo ""
    
    check_prerequisites
    setup_python_env
    
    # Only deploy infrastructure in non-local environments
    if [ "${ENVIRONMENT}" != "local" ]; then
        deploy_infrastructure
        configure_application
    else
        print_warning "Skipping infrastructure deployment for local environment"
    fi
    
    setup_database
    
    # Run tests unless explicitly skipped
    if [ "${SKIP_TESTS}" != "true" ]; then
        run_tests
    else
        print_warning "Skipping tests (SKIP_TESTS=true)"
    fi
    
    start_services
    validate_deployment
    deployment_summary
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --environment|-e)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --region|-r)
            AWS_REGION="$2"
            shift 2
            ;;
        --skip-tests)
            SKIP_TESTS="true"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -e, --environment    Deployment environment (dev/staging/prod)"
            echo "  -r, --region        AWS region (default: us-east-1)"
            echo "  --skip-tests        Skip running tests"
            echo "  -h, --help          Show this help message"
            echo ""
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Run main deployment
main