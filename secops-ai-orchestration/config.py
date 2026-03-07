"""
Configuration Management for SecOps AI Platform
Handles environment variables, settings, and configuration validation
"""

import os
from typing import Optional, List
from pydantic import BaseSettings, validator
from pathlib import Path

class Settings(BaseSettings):
    """
    Application settings with environment variable support
    
    Configuration can be provided via:
    1. Environment variables (prefixed with SECOPS_AI_)
    2. .env file
    3. Default values
    """
    
    # Application settings
    app_name: str = "SecOps AI Platform"
    version: str = "1.0.0"
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False
    
    # AWS configuration
    aws_region: str = "us-east-1"
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    bedrock_vpc_endpoint: Optional[str] = None
    
    # Database configuration
    audit_db_path: str = "audit_log.db"
    audit_encryption_key: Optional[str] = None
    
    # Slack integration
    slack_webhook_url: Optional[str] = None
    slack_bot_token: Optional[str] = None
    
    # Security settings
    secret_key: str = "your-secret-key-change-in-production"
    encryption_key: Optional[str] = None
    
    # AI model configuration
    default_model: str = "haiku"
    cost_optimization_enabled: bool = True
    max_monthly_cost_usd: float = 250.0
    
    # Compliance settings
    compliance_frameworks: List[str] = ["SOC2", "ISO27001"]
    audit_retention_days: int = 2555  # 7 years
    
    # Performance settings
    max_processing_time_seconds: int = 30
    max_concurrent_requests: int = 100
    
    # Monitoring settings
    enable_metrics: bool = True
    metrics_port: int = 9090
    
    class Config:
        env_prefix = "SECOPS_AI_"
        env_file = ".env"
        case_sensitive = False
    
    @validator('aws_region')
    def validate_aws_region(cls, v):
        """Validate AWS region format"""
        valid_regions = [
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            'eu-west-1', 'eu-west-2', 'eu-central-1',
            'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1'
        ]
        if v not in valid_regions:
            raise ValueError(f'Invalid AWS region. Must be one of: {valid_regions}')
        return v
    
    @validator('port')
    def validate_port(cls, v):
        """Validate port number"""
        if not 1 <= v <= 65535:
            raise ValueError('Port must be between 1 and 65535')
        return v
    
    @validator('max_monthly_cost_usd')
    def validate_cost_limit(cls, v):
        """Validate cost limit"""
        if v <= 0:
            raise ValueError('Monthly cost limit must be positive')
        return v
    
    @validator('audit_retention_days')
    def validate_retention_days(cls, v):
        """Validate audit retention period"""
        if v < 90:  # Minimum 90 days for compliance
            raise ValueError('Audit retention must be at least 90 days')
        return v

def load_config() -> Settings:
    """
    Load and validate application configuration
    
    Returns:
        Settings: Validated configuration object
    """
    
    # Create .env file if it doesn't exist
    env_file = Path(".env")
    if not env_file.exists():
        create_default_env_file(env_file)
    
    try:
        settings = Settings()
        
        # Validate critical configuration
        validate_critical_config(settings)
        
        return settings
        
    except Exception as e:
        print(f"Configuration error: {str(e)}")
        print("Please check your environment variables or .env file")
        raise

def create_default_env_file(env_file: Path):
    """Create a default .env file with example values"""
    
    default_content = """
# SecOps AI Platform Configuration
# Copy this file to .env and customize for your environment

# Application Settings
SECOPS_AI_APP_NAME=SecOps AI Platform
SECOPS_AI_HOST=0.0.0.0
SECOPS_AI_PORT=8080
SECOPS_AI_DEBUG=false

# AWS Configuration (Required)
SECOPS_AI_AWS_REGION=us-east-1
# SECOPS_AI_AWS_ACCESS_KEY_ID=your_access_key_here
# SECOPS_AI_AWS_SECRET_ACCESS_KEY=your_secret_key_here
# SECOPS_AI_BEDROCK_VPC_ENDPOINT=https://bedrock-runtime.us-east-1.amazonaws.com

# Database Configuration
SECOPS_AI_AUDIT_DB_PATH=audit_log.db
# SECOPS_AI_AUDIT_ENCRYPTION_KEY=your_encryption_key_here

# Slack Integration (Optional)
# SECOPS_AI_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
# SECOPS_AI_SLACK_BOT_TOKEN=xoxb-your-bot-token

# Security Settings (Change in Production!)
SECOPS_AI_SECRET_KEY=your-secret-key-change-in-production
# SECOPS_AI_ENCRYPTION_KEY=your_encryption_key_here

# AI Model Configuration
SECOPS_AI_DEFAULT_MODEL=haiku
SECOPS_AI_COST_OPTIMIZATION_ENABLED=true
SECOPS_AI_MAX_MONTHLY_COST_USD=250.0

# Compliance Settings
SECOPS_AI_COMPLIANCE_FRAMEWORKS=["SOC2", "ISO27001"]
SECOPS_AI_AUDIT_RETENTION_DAYS=2555

# Performance Settings
SECOPS_AI_MAX_PROCESSING_TIME_SECONDS=30
SECOPS_AI_MAX_CONCURRENT_REQUESTS=100

# Monitoring Settings
SECOPS_AI_ENABLE_METRICS=true
SECOPS_AI_METRICS_PORT=9090
    """.strip()
    
    with open(env_file, 'w') as f:
        f.write(default_content)
    
    print(f"Created default configuration file: {env_file}")
    print("Please edit this file with your actual configuration values")

def validate_critical_config(settings: Settings):
    """
    Validate critical configuration that's required for operation
    
    Args:
        settings: Settings object to validate
        
    Raises:
        ValueError: If critical configuration is missing
    """
    
    critical_checks = []
    
    # Check AWS configuration
    if not settings.aws_access_key_id:
        critical_checks.append("AWS_ACCESS_KEY_ID is required for Bedrock integration")
    
    if not settings.aws_secret_access_key:
        critical_checks.append("AWS_SECRET_ACCESS_KEY is required for Bedrock integration")
    
    # Check security configuration in production
    if not settings.debug:
        if settings.secret_key == "your-secret-key-change-in-production":
            critical_checks.append("SECRET_KEY must be changed in production")
        
        if not settings.audit_encryption_key:
            critical_checks.append("AUDIT_ENCRYPTION_KEY is required in production")
    
    # Check database path is writable
    db_dir = Path(settings.audit_db_path).parent
    if not db_dir.exists():
        try:
            db_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            critical_checks.append(f"Cannot create database directory: {db_dir}")
    
    if critical_checks:
        error_message = "Critical configuration issues:\n" + "\n".join(f"- {check}" for check in critical_checks)
        raise ValueError(error_message)

def get_model_config() -> dict:
    """Get model-specific configuration"""
    
    return {
        'haiku': {
            'model_id': 'anthropic.claude-3-haiku-20240307-v1:0',
            'max_tokens': 2048,
            'cost_per_1k_tokens': 0.00025,  # $0.25 per 1K tokens
            'latency_target_ms': 2000
        },
        'sonnet': {
            'model_id': 'anthropic.claude-3-sonnet-20240229-v1:0', 
            'max_tokens': 4096,
            'cost_per_1k_tokens': 0.003,    # $3 per 1K tokens
            'latency_target_ms': 5000
        },
        'opus': {
            'model_id': 'anthropic.claude-3-opus-20240229-v1:0',
            'max_tokens': 8192,
            'cost_per_1k_tokens': 0.015,    # $15 per 1K tokens
            'latency_target_ms': 30000
        }
    }

def get_autonomy_config() -> dict:
    """Get autonomy tier configuration"""
    
    return {
        'tier_0_autonomous': {
            'confidence_threshold': 0.95,
            'description': 'Auto-close false positives',
            'requires_approval': False,
            'post_audit': True
        },
        'tier_1_assisted': {
            'confidence_threshold': 0.80,
            'description': 'Enrich and create tickets',
            'requires_approval': False,
            'human_review_queue': True
        },
        'tier_2_supervised': {
            'confidence_threshold': 0.60,
            'description': 'Recommend containment actions', 
            'requires_approval': True,
            'approval_timeout_minutes': 30
        },
        'tier_3_collaborative': {
            'confidence_threshold': 0.00,
            'description': 'Human-led assistance',
            'requires_approval': False,
            'collaboration_mode': True
        }
    }

def get_compliance_config() -> dict:
    """Get compliance framework configuration"""
    
    return {
        'soc2': {
            'enabled': True,
            'controls': ['CC1', 'CC2', 'CC3', 'CC4', 'CC5'],
            'audit_requirements': {
                'complete_reasoning_chains': True,
                'decision_transparency': True,
                'risk_assessment': True,
                'monitoring_evidence': True,
                'control_validation': True
            }
        },
        'iso27001': {
            'enabled': True,
            'controls': ['A.12', 'A.13', 'A.14'],
            'security_requirements': {
                'operations_security': True,
                'communications_security': True,
                'system_acquisition': True,
                'vpc_isolation': True,
                'encryption_in_transit': True,
                'encryption_at_rest': True
            }
        },
        'gdpr': {
            'enabled': True,
            'requirements': {
                'pii_detection': True,
                'data_minimization': True,
                'consent_management': True,
                'right_to_explanation': True,
                'data_retention_limits': True
            }
        }
    }

# Export main configuration loader
__all__ = ['Settings', 'load_config', 'get_model_config', 'get_autonomy_config', 'get_compliance_config']