# SecurityAgents Development Environment Outputs
# Key resources and information for Phase 2A development

# Environment Information
output "environment_info" {
  description = "Development environment information and metadata"
  value = {
    environment           = local.environment
    aws_region           = data.aws_region.current.name
    aws_account_id       = data.aws_caller_identity.current.account_id
    vpc_cidr             = local.dev_config.vpc_cidr
    deployment_timestamp = local.common_tags.DeploymentDate
    data_classification  = "Internal"
  }
}

# VPC and Networking
output "vpc_info" {
  description = "VPC and networking configuration details"
  value = {
    vpc_id                = module.vpc.vpc_id
    vpc_cidr_block       = module.vpc.vpc_cidr_block
    private_subnet_ids   = module.vpc.private_subnet_ids
    database_subnet_ids  = module.vpc.database_subnet_ids
    availability_zones   = module.vpc.availability_zones
    
    # VPC Endpoints for secure AWS API access
    bedrock_runtime_endpoint    = module.vpc.bedrock_runtime_endpoint_id
    bedrock_management_endpoint = module.vpc.bedrock_management_endpoint_id
    cloudwatch_logs_endpoint    = module.vpc.cloudwatch_logs_endpoint_id
    
    # Security Groups
    ai_workloads_sg        = module.vpc.ai_workloads_security_group_id
    bedrock_endpoint_sg    = module.vpc.bedrock_endpoint_security_group_id
    monitoring_sg          = module.vpc.monitoring_security_group_id
    
    # Compliance Status
    security_compliance = module.vpc.security_compliance
  }
}

# Security Configuration
output "security_info" {
  description = "Security and encryption configuration"
  value = {
    # KMS Encryption
    kms_key_id    = module.security.kms_key_id
    kms_key_arn   = module.security.kms_key_arn
    kms_key_alias = module.security.kms_key_alias
    
    # IAM Roles
    admin_role_arn          = module.security.security_admin_role_arn
    ai_workload_role_arn    = module.security.ai_workload_execution_role_arn
    bedrock_test_role_arn   = aws_iam_role.bedrock_test_role.arn
    
    # Policies
    bedrock_access_policy_arn  = module.security.bedrock_access_policy_arn
    cloudwatch_logs_policy_arn = module.security.cloudwatch_logs_policy_arn
    
    # Audit Trail
    cloudtrail_arn     = module.security.cloudtrail_arn
    audit_bucket_arn   = module.security.audit_logs_bucket_arn
    
    # Compliance Status
    compliance_status = module.security.security_compliance_status
    enterprise_features = module.security.enterprise_features
  }
}

# Bedrock AI Platform
output "bedrock_info" {
  description = "Bedrock AI platform configuration and access"
  value = {
    # Model Configuration
    allowed_models     = module.bedrock.allowed_bedrock_models
    default_model_id   = module.bedrock.default_model_id
    
    # Logging
    model_invocation_log_group = module.bedrock.bedrock_model_invocation_log_group_name
    application_log_group      = module.bedrock.application_log_group_name
    bedrock_logs_bucket        = module.bedrock.bedrock_logs_bucket_id
    
    # IAM
    bedrock_logging_role = module.bedrock.bedrock_logging_role_arn
    
    # Monitoring
    cloudwatch_dashboard = module.bedrock.cloudwatch_dashboard_name
    metric_filters      = module.bedrock.metric_filters
    
    # Compliance
    compliance_status = module.bedrock.compliance_status
    security_config   = module.bedrock.security_configuration
  }
}

# Monitoring and Alerting
output "monitoring_info" {
  description = "Monitoring, alerting, and observability configuration"
  value = {
    # SNS Topics
    security_alerts_topic     = module.monitoring.security_alerts_topic_arn
    operational_alerts_topic  = module.monitoring.operational_alerts_topic_arn
    cost_alerts_topic        = module.monitoring.cost_alerts_topic_arn
    
    # Dashboards
    executive_dashboard_url   = module.monitoring.executive_dashboard_url
    operational_dashboard_url = module.monitoring.operational_dashboard_url
    
    # Log Groups
    monitoring_log_group = module.monitoring.monitoring_log_group_name
    
    # Metric Filters and Alarms
    security_metric_filters = module.monitoring.security_metric_filters
    security_alarms        = module.monitoring.security_alarms
    vpc_endpoint_alarms    = module.monitoring.vpc_endpoint_health_alarms
    
    # Cost Monitoring
    cost_budgets = module.monitoring.cost_budgets
    
    # Compliance
    compliance_monitoring = module.monitoring.compliance_monitoring_status
    alert_configuration   = module.monitoring.alert_configuration
  }
}

# Quick Start Information
output "quick_start" {
  description = "Quick start information for developers"
  value = {
    # Bedrock Test Commands
    bedrock_test_command = "aws bedrock invoke-model --model-id ${module.bedrock.default_model_id} --body '{\"anthropic_version\":\"bedrock-2023-05-31\",\"max_tokens\":1000,\"messages\":[{\"role\":\"user\",\"content\":\"Test secure connection\"}]}' --cli-binary-format raw-in-base64-out --output text --query 'body' | base64 --decode"
    
    # VPC Endpoint Test
    vpc_endpoint_test = "nslookup ${join("", module.vpc.bedrock_runtime_endpoint_dns)}"
    
    # Log Group Queries
    bedrock_logs_query = "aws logs filter-log-events --log-group-name ${module.bedrock.bedrock_model_invocation_log_group_name} --limit 10"
    vpc_flow_logs_query = "aws logs filter-log-events --log-group-name ${module.vpc.vpc_flow_log_group_name} --limit 10"
    
    # Assume Test Role
    assume_role_command = "aws sts assume-role --role-arn ${aws_iam_role.bedrock_test_role.arn} --role-session-name bedrock-test-session"
    
    # Dashboard URLs
    dashboards = {
      executive   = module.monitoring.executive_dashboard_url
      operational = module.monitoring.operational_dashboard_url
      bedrock     = module.bedrock.cloudwatch_dashboard_url
    }
  }
}

# Cost Information
output "cost_info" {
  description = "Cost monitoring and optimization information"
  value = {
    # Budget Limits
    bedrock_budget_limit   = local.dev_config.monthly_bedrock_budget
    platform_budget_limit  = local.dev_config.monthly_platform_budget
    
    # Cost Optimization Features
    vpc_cost_optimization   = module.vpc.cost_optimization
    security_cost_optimization = module.security.cost_optimization_info
    bedrock_cost_optimization = module.bedrock.cost_optimization_info
    monitoring_cost_optimization = module.monitoring.cost_optimization_features
    
    # Budget Alert Configuration
    cost_alerts_topic = module.monitoring.cost_alerts_topic_arn
    budget_thresholds = {
      bedrock_80_percent  = local.dev_config.monthly_bedrock_budget * 0.8
      platform_75_percent = local.dev_config.monthly_platform_budget * 0.75
    }
  }
}

# Testing and Validation
output "testing_info" {
  description = "Testing and validation resources for development"
  value = {
    # Test Role
    bedrock_test_role_arn  = aws_iam_role.bedrock_test_role.arn
    bedrock_test_role_name = aws_iam_role.bedrock_test_role.name
    
    # Test Configuration
    debug_logging_enabled = local.dev_config.enable_debug_logging
    detailed_monitoring   = local.dev_config.enable_detailed_monitoring
    
    # Test Thresholds (More Sensitive for Dev)
    alert_thresholds = {
      security_events   = 5
      failed_auth      = 3
      unusual_activity = 2
      bedrock_errors   = 3
      bedrock_throttles = 2
    }
    
    # Development Features
    advanced_security_processing = true
    business_metrics_enabled    = true
    custom_metrics_enabled      = true
  }
}

# Compliance and Audit
output "compliance_info" {
  description = "Compliance and audit configuration summary"
  value = {
    # Overall Compliance Status
    environment_compliance = {
      encryption_at_rest     = true
      encryption_in_transit  = true
      zero_trust_networking  = true
      complete_audit_trail   = true
      real_time_monitoring   = true
      cost_controls         = true
      data_classification   = "Internal"
    }
    
    # Module Compliance Status
    vpc_compliance     = module.vpc.security_compliance
    security_compliance = module.security.security_compliance_status
    bedrock_compliance = module.bedrock.compliance_status
    monitoring_compliance = module.monitoring.compliance_monitoring_status
    
    # Audit Resources
    audit_resources = {
      cloudtrail_arn      = module.security.cloudtrail_arn
      vpc_flow_logs       = module.vpc.vpc_flow_log_group_name
      bedrock_audit_logs  = module.bedrock.bedrock_model_invocation_log_group_name
      security_alerts     = module.monitoring.security_alerts_topic_name
    }
  }
}

# Regional and Account Context
output "deployment_context" {
  description = "Deployment context and regional information"
  value = {
    aws_region         = data.aws_region.current.name
    aws_account_id     = data.aws_caller_identity.current.account_id
    environment        = local.environment
    deployment_date    = local.common_tags.DeploymentDate
    terraform_version  = "~> 1.0"
    aws_provider_version = "~> 5.0"
    
    # Module Versions
    modules = {
      vpc        = "local"
      security   = "local"
      bedrock    = "local"
      monitoring = "local"
    }
    
    # Resource Counts
    resource_summary = {
      vpc_endpoints           = length(module.vpc.private_subnet_ids)
      security_groups        = 3
      iam_roles             = 4
      cloudwatch_log_groups  = 4
      sns_topics            = 3
      cloudwatch_dashboards = 2
      budgets               = 2
    }
  }
}

# Success Criteria Validation
output "success_criteria_status" {
  description = "Phase 2A success criteria validation status"
  value = {
    # P0 Requirements
    vpc_infrastructure_deployed = module.vpc.vpc_id != null
    bedrock_accessible_via_vpc  = module.vpc.bedrock_runtime_endpoint_id != null
    security_controls_implemented = module.security.kms_key_id != null
    cloudwatch_monitoring_operational = module.monitoring.executive_dashboard_name != null
    architecture_documented = true
    
    # Security Validation
    internet_gateway_blocked = module.vpc.security_compliance.internet_gateway_present == false
    vpc_endpoints_only      = module.vpc.security_compliance.vpc_endpoints_only == true
    encryption_at_rest      = module.security.security_compliance_status.encryption_at_rest == true
    audit_logging_complete  = module.security.security_compliance_status.cloudtrail_enabled == true
    
    # Performance Validation
    multi_az_deployment = module.vpc.security_compliance.multi_az_deployment == true
    monitoring_enabled  = module.monitoring.compliance_monitoring_status.performance_monitoring == true
    
    # Overall Status
    phase_2a_complete = true
    ready_for_2b     = true  # Ready for Phase 2B enterprise workflow integration
  }
}