# SecurityAgents Development Environment
# Complete infrastructure deployment for Phase 2A development and testing

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
  required_version = ">= 1.0"
  
  # TODO: P0 @alpha-1 2026-03-08 Configure remote backend for team collaboration
  # backend "s3" {
  #   bucket         = "security-agents-terraform-state-dev"
  #   key            = "dev/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "security-agents-terraform-locks"
  # }
}

# Configure AWS Provider
provider "aws" {
  region = var.aws_region
  
  # Enterprise-grade provider configuration
  default_tags {
    tags = {
      Project     = "SecurityAgents"
      Environment = "dev"
      Team        = "Alpha-1"
      Purpose     = "AI-Security-Platform"
      Compliance  = "SOC2-ISO27001"
      ManagedBy   = "Terraform"
      Owner       = "security-team@company.com"
      CostCenter  = "Security-Operations"
    }
  }
}

# Get current AWS account and region information
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  # Environment-specific configuration
  name_prefix = "secagents-dev"
  environment = "dev"
  
  common_tags = {
    Project            = "SecurityAgents"
    Environment        = "dev"
    Team               = "Alpha-1"
    Infrastructure     = "Phase-2A"
    DeploymentDate     = timestamp()
    DataClassification = "Internal"
  }
  
  # Development-specific settings (less restrictive than prod)
  dev_config = {
    vpc_cidr                    = "10.100.0.0/16"  # Dev-specific CIDR
    log_retention_days          = 30               # Shorter retention for dev
    enable_detailed_monitoring  = true
    enable_debug_logging       = true
    monthly_bedrock_budget     = 200              # Lower budget for dev
    monthly_platform_budget    = 500
  }
}

# Security Module - KMS and IAM
module "security" {
  source = "../../modules/security"
  
  name_prefix  = local.name_prefix
  environment  = local.environment
  tags         = local.common_tags
  
  # KMS Configuration
  kms_deletion_window_days = 7  # Shorter for dev environment
  enable_multi_region_key  = false
  
  # IAM Configuration  
  admin_principal_arns = var.admin_principal_arns
  mfa_required_for_admin = true
  
  # Bedrock Access
  allowed_bedrock_models = [
    "anthropic.claude-3-sonnet-20240229-v1:0",
    "anthropic.claude-3-haiku-20240307-v1:0"  # Limit models in dev
  ]
  bedrock_regions = ["us-east-1"]  # Single region for dev
  
  # Audit Configuration
  enable_multi_region_trail = false  # Single region for dev
  audit_log_retention_years = 1      # Shorter retention
  
  # Development-specific settings
  allow_dev_access     = true
  dev_principal_arns   = var.dev_principal_arns
  
  # Compliance (relaxed for dev)
  compliance_requirements = {
    soc2_type2        = false  # Not required for dev
    iso_27001        = false  # Not required for dev
    pci_dss          = false
    gdpr_compliance  = true   # Still important for data handling
    encrypt_at_rest  = true   # Always required
    encrypt_in_transit = true # Always required
    audit_all_actions = true  # Always required
  }
}

# VPC Module - Zero-trust networking
module "vpc" {
  source = "../../modules/vpc"
  
  name_prefix  = local.name_prefix
  environment  = local.environment
  tags         = local.common_tags
  
  # Network Configuration
  vpc_cidr                = local.dev_config.vpc_cidr
  kms_key_arn            = module.security.kms_key_arn
  log_retention_days     = local.dev_config.log_retention_days
  availability_zone_count = 2  # 2 AZs sufficient for dev
  
  # Security Configuration
  enable_vpc_flow_logs = true
  
  # Development-specific network ACLs (slightly more permissive)
  network_acl_rules = {
    private_subnets = {
      allow_internal_https = true
      allow_vpc_endpoints  = true
      block_all_internet   = true
    }
    database_subnets = {
      allow_internal_only = true
      allow_monitoring    = true
    }
  }
  
  # CloudWatch Configuration
  cloudwatch_config = {
    enable_detailed_monitoring = true
    metric_filters = {
      failed_bedrock_calls = true
      unusual_traffic      = local.dev_config.enable_detailed_monitoring
      security_events      = true
    }
    alarms = {
      high_error_rate     = true
      unusual_activity    = local.dev_config.enable_detailed_monitoring
      vpc_flow_anomalies = true
    }
  }
  
  # Cost optimization for dev
  subnet_configuration = {
    private_subnet_size  = 27  # /27 = 27 IPs (smaller for dev)
    database_subnet_size = 28  # /28 = 11 IPs
    reserved_ip_count    = 3   # Fewer reserved IPs
  }
}

# Bedrock Module - Secure AI deployment
module "bedrock" {
  source = "../../modules/bedrock"
  
  name_prefix  = local.name_prefix
  environment  = local.environment
  tags         = local.common_tags
  
  # Security
  kms_key_arn = module.security.kms_key_arn
  
  # Logging Configuration
  log_retention_days      = local.dev_config.log_retention_days
  enable_bedrock_logging  = true
  enable_embedding_logging = true
  enable_image_logging    = true
  enable_text_logging     = true
  
  # Model Configuration
  allowed_bedrock_models = module.security.allowed_bedrock_models
  default_model_id      = "anthropic.claude-3-sonnet-20240229-v1:0"
  
  # Monitoring (more detailed for dev/testing)
  enable_detailed_monitoring = local.dev_config.enable_detailed_monitoring
  error_threshold           = 3   # Lower threshold for dev testing
  throttle_threshold        = 2   # Lower threshold for dev testing
  latency_threshold_ms      = 20000  # 20 seconds for dev
  
  # Cost Management
  monthly_cost_threshold = local.dev_config.monthly_bedrock_budget
  enable_cost_alerts    = true
  
  # Development Features
  enable_debug_logging    = local.dev_config.enable_debug_logging
  sample_request_logging  = 100  # Log all requests in dev
  
  # Business Metrics
  enable_business_metrics = true
  business_metrics_config = {
    track_security_analysis_requests = true
    track_response_times            = true
    track_model_usage_patterns      = true
    track_cost_per_analysis         = true
  }
  
  # Compliance (relaxed for dev)
  compliance_requirements = {
    data_residency_required     = false  # More flexible for dev
    audit_all_invocations      = true   # Still audit everything
    encrypt_logs_at_rest       = true   # Always required
    retain_logs_for_compliance = true   # Always required
    enable_model_monitoring    = true   # Always required
  }
  
  data_classification = "Internal"  # Less restrictive for dev
}

# Monitoring Module - Comprehensive observability
module "monitoring" {
  source = "../../modules/monitoring"
  
  name_prefix  = local.name_prefix
  environment  = local.environment
  tags         = local.common_tags
  
  # Security
  kms_key_arn = module.security.kms_key_arn
  
  # Log Groups
  vpc_flow_log_group_name    = module.vpc.vpc_flow_log_group_name
  bedrock_log_group_name     = module.bedrock.bedrock_model_invocation_log_group_name
  application_log_group_name = module.bedrock.application_log_group_name
  
  # Network Monitoring
  vpc_id           = module.vpc.vpc_id
  vpc_endpoint_ids = [
    module.vpc.bedrock_runtime_endpoint_id,
    module.vpc.bedrock_management_endpoint_id,
    module.vpc.cloudwatch_logs_endpoint_id
  ]
  
  # Configuration
  log_retention_days = local.dev_config.log_retention_days
  
  # Alert Configuration (development team)
  security_alert_emails    = var.security_alert_emails
  operational_alert_emails = var.operational_alert_emails
  cost_alert_emails       = var.cost_alert_emails
  
  # Development-specific thresholds (more sensitive)
  security_events_threshold  = 5   # Lower for dev testing
  failed_auth_threshold     = 3   # Lower for dev testing
  unusual_activity_threshold = 2   # Lower for dev testing
  
  # Cost Monitoring
  monthly_bedrock_budget  = local.dev_config.monthly_bedrock_budget
  monthly_platform_budget = local.dev_config.monthly_platform_budget
  enable_cost_anomaly_detection = true
  
  # Dashboards
  enable_executive_dashboard   = true
  enable_operational_dashboard = true
  dashboard_refresh_interval  = "PT1M"  # 1 minute for dev
  
  # Development Features
  enable_advanced_security_processing = true   # Test advanced features
  enable_debug_logging               = local.dev_config.enable_debug_logging
  security_event_processing_timeout  = 60
  
  # Integrations (optional for dev)
  slack_webhook_url         = var.slack_webhook_url
  pagerduty_integration_key = null  # Disable PagerDuty in dev
  
  # CloudWatch Features
  enable_cloudwatch_insights = true
  enable_application_insights = true
  enable_custom_metrics      = true
  metric_collection_interval = 60
  
  # Compliance (relaxed for dev)
  compliance_requirements = {
    soc2_monitoring     = false  # Not required for dev
    iso27001_monitoring = false  # Not required for dev
    real_time_alerting  = true   # Still important for testing
    audit_trail_monitoring = true   # Always required
    performance_monitoring = true   # Always required
  }
  
  # Data retention (shorter for dev)
  data_retention_policy = {
    metrics_retention_days = 90   # 3 months
    logs_retention_days    = 30   # 1 month
    alerts_retention_days  = 90   # 3 months
  }
  
  # Alert severity (immediate for dev testing)
  alert_severity_config = {
    critical_immediate_notification = true
    high_notification_delay_minutes = 1    # Immediate in dev
    medium_notification_delay_minutes = 5  # Quick in dev
    low_notification_suppression = false   # Show all alerts in dev
  }
}

# TODO: P0 @alpha-1 2026-03-08 Add outputs for easy access to key resources
# Development environment testing resources
resource "aws_iam_role" "bedrock_test_role" {
  name_prefix = "${local.name_prefix}-bedrock-test-"
  description = "Test role for Bedrock development and validation"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        AWS = data.aws_caller_identity.current.arn
      }
    }]
  })
  
  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-bedrock-test-role"
    Purpose = "Development-Testing"
  })
}

# Attach Bedrock access policy to test role
resource "aws_iam_role_policy_attachment" "bedrock_test_access" {
  role       = aws_iam_role.bedrock_test_role.name
  policy_arn = module.security.bedrock_access_policy_arn
}

# TODO: P0 @alpha-1 2026-03-08 Add test scripts and validation resources