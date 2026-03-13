# SecurityAgents Bedrock Module Outputs
# Export Bedrock logging, monitoring, and configuration information

# CloudWatch Log Groups
output "bedrock_model_invocation_log_group_name" {
  description = "Name of the CloudWatch log group for Bedrock model invocations"
  value       = aws_cloudwatch_log_group.bedrock_model_invocation.name
}

output "bedrock_model_invocation_log_group_arn" {
  description = "ARN of the CloudWatch log group for Bedrock model invocations"
  value       = aws_cloudwatch_log_group.bedrock_model_invocation.arn
}

output "application_log_group_name" {
  description = "Name of the CloudWatch log group for SecurityAgents application logs"
  value       = aws_cloudwatch_log_group.application_logs.name
}

output "application_log_group_arn" {
  description = "ARN of the CloudWatch log group for SecurityAgents application logs"
  value       = aws_cloudwatch_log_group.application_logs.arn
}

# S3 Storage for Long-term Logs
output "bedrock_logs_bucket_id" {
  description = "ID of the S3 bucket for long-term Bedrock log storage"
  value       = aws_s3_bucket.bedrock_logs.id
}

output "bedrock_logs_bucket_arn" {
  description = "ARN of the S3 bucket for long-term Bedrock log storage"
  value       = aws_s3_bucket.bedrock_logs.arn
}

output "bedrock_logs_bucket_domain_name" {
  description = "Domain name of the Bedrock logs S3 bucket"
  value       = aws_s3_bucket.bedrock_logs.bucket_domain_name
}

# IAM Roles and Policies
output "bedrock_logging_role_arn" {
  description = "ARN of the IAM role used by Bedrock for logging"
  value       = aws_iam_role.bedrock_logging.arn
}

output "bedrock_logging_role_name" {
  description = "Name of the IAM role used by Bedrock for logging"
  value       = aws_iam_role.bedrock_logging.name
}

output "bedrock_cloudwatch_logs_policy_arn" {
  description = "ARN of the IAM policy for Bedrock CloudWatch Logs access"
  value       = aws_iam_policy.bedrock_cloudwatch_logs.arn
}

output "bedrock_s3_logs_policy_arn" {
  description = "ARN of the IAM policy for Bedrock S3 logs access"
  value       = aws_iam_policy.bedrock_s3_logs.arn
}

# Bedrock Configuration
output "bedrock_model_invocation_logging_configuration_id" {
  description = "ID of the Bedrock model invocation logging configuration"
  value       = aws_bedrock_model_invocation_logging_configuration.main.id
}

output "allowed_bedrock_models" {
  description = "List of Bedrock models allowed for the platform"
  value       = var.allowed_bedrock_models
}

output "default_model_id" {
  description = "Default Bedrock model ID for SecurityAgents platform"
  value       = var.default_model_id
}

# CloudWatch Monitoring
output "cloudwatch_dashboard_name" {
  description = "Name of the CloudWatch dashboard for Bedrock monitoring"
  value       = aws_cloudwatch_dashboard.bedrock_monitoring.dashboard_name
}

output "cloudwatch_dashboard_url" {
  description = "URL of the CloudWatch dashboard for Bedrock monitoring"
  value       = "https://${data.aws_region.current.name}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#dashboards:name=${aws_cloudwatch_dashboard.bedrock_monitoring.dashboard_name}"
}

# Metric Filters
output "metric_filters" {
  description = "Information about CloudWatch metric filters for monitoring"
  value = {
    bedrock_errors = {
      name       = aws_cloudwatch_log_metric_filter.bedrock_errors.name
      namespace  = "SecurityAgents/Bedrock"
      metric     = "BedrockErrors"
    }
    bedrock_throttles = {
      name       = aws_cloudwatch_log_metric_filter.bedrock_throttles.name
      namespace  = "SecurityAgents/Bedrock"
      metric     = "BedrockThrottles"
    }
    bedrock_high_latency = {
      name       = aws_cloudwatch_log_metric_filter.bedrock_high_latency.name
      namespace  = "SecurityAgents/Bedrock"
      metric     = "BedrockHighLatency"
    }
    security_analysis_requests = {
      name       = aws_cloudwatch_log_metric_filter.security_analysis_requests.name
      namespace  = "SecurityAgents/Business"
      metric     = "SecurityAnalysisRequests"
    }
    analysis_response_time = {
      name       = aws_cloudwatch_log_metric_filter.analysis_response_time.name
      namespace  = "SecurityAgents/Performance"
      metric     = "AnalysisResponseTime"
    }
  }
}

# CloudWatch Alarms
output "cloudwatch_alarms" {
  description = "Information about CloudWatch alarms for Bedrock monitoring"
  value = {
    error_rate_alarm = {
      name        = aws_cloudwatch_metric_alarm.bedrock_error_rate.alarm_name
      threshold   = var.error_threshold
      description = aws_cloudwatch_metric_alarm.bedrock_error_rate.alarm_description
    }
    throttle_rate_alarm = {
      name        = aws_cloudwatch_metric_alarm.bedrock_throttle_rate.alarm_name
      threshold   = var.throttle_threshold
      description = aws_cloudwatch_metric_alarm.bedrock_throttle_rate.alarm_description
    }
  }
}

# Compliance and Audit Information
output "compliance_status" {
  description = "Compliance status information for audit purposes"
  value = {
    model_invocation_logging_enabled = var.enable_bedrock_logging
    embedding_logging_enabled        = var.enable_embedding_logging
    image_logging_enabled            = var.enable_image_logging
    text_logging_enabled             = var.enable_text_logging
    logs_encrypted_at_rest           = true
    log_retention_days              = var.log_retention_days
    s3_lifecycle_enabled            = true
    detailed_monitoring_enabled     = var.enable_detailed_monitoring
    data_classification             = var.data_classification
  }
}

# Cost Optimization Information
output "cost_optimization_info" {
  description = "Cost optimization configuration for financial tracking"
  value = {
    s3_bucket_key_enabled       = var.enable_s3_bucket_key
    log_compression_enabled     = var.enable_log_compression
    s3_lifecycle_transitions    = var.s3_lifecycle_config
    log_retention_days         = var.log_retention_days
    sample_logging_percentage  = var.sample_request_logging
    monthly_cost_threshold     = var.monthly_cost_threshold
  }
}

# Performance Monitoring
output "performance_configuration" {
  description = "Performance monitoring configuration details"
  value = {
    error_threshold          = var.error_threshold
    throttle_threshold       = var.throttle_threshold
    latency_threshold_ms     = var.latency_threshold_ms
    detailed_monitoring      = var.enable_detailed_monitoring
    business_metrics_enabled = var.enable_business_metrics
    dashboard_enabled        = var.enable_dashboard
  }
}

# Security Configuration
output "security_configuration" {
  description = "Security configuration summary for audit purposes"
  value = {
    kms_key_used                    = var.kms_key_arn
    s3_bucket_public_access_blocked = true
    s3_bucket_encryption_enabled    = true
    cloudwatch_logs_encrypted      = true
    iam_least_privilege_applied    = true
    audit_logging_comprehensive    = true
  }
}

# Regional Information
output "aws_region" {
  description = "AWS region where Bedrock resources are deployed"
  value       = data.aws_region.current.name
}

output "aws_account_id" {
  description = "AWS account ID where resources are deployed"
  value       = data.aws_caller_identity.current.account_id
}

# Business Metrics Configuration
output "business_metrics_configuration" {
  description = "Business metrics tracking configuration"
  value       = var.business_metrics_config
}

# Logging Configuration Summary
output "logging_configuration" {
  description = "Complete logging configuration summary"
  value = {
    bedrock_logging = {
      cloudwatch_log_group = aws_cloudwatch_log_group.bedrock_model_invocation.name
      s3_bucket           = aws_s3_bucket.bedrock_logs.id
      retention_days      = var.log_retention_days
      encryption_key      = var.kms_key_arn
    }
    application_logging = {
      cloudwatch_log_group = aws_cloudwatch_log_group.application_logs.name
      retention_days      = var.log_retention_days
      encryption_key      = var.kms_key_arn
    }
    data_types_logged = {
      embeddings = var.enable_embedding_logging
      images     = var.enable_image_logging
      text       = var.enable_text_logging
    }
  }
}

# Random Suffix for Reference
output "bucket_suffix" {
  description = "Random suffix used for S3 bucket naming"
  value       = random_string.bucket_suffix.result
  sensitive   = false
}