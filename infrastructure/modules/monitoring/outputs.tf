# SecurityAgents Monitoring Module Outputs
# Export SNS topics, dashboards, and monitoring configuration

# SNS Topics
output "security_alerts_topic_arn" {
  description = "ARN of the SNS topic for critical security alerts"
  value       = aws_sns_topic.security_alerts.arn
}

output "operational_alerts_topic_arn" {
  description = "ARN of the SNS topic for operational alerts"
  value       = aws_sns_topic.operational_alerts.arn
}

output "cost_alerts_topic_arn" {
  description = "ARN of the SNS topic for cost alerts"
  value       = aws_sns_topic.cost_alerts.arn
}

output "security_alerts_topic_name" {
  description = "Name of the SNS topic for critical security alerts"
  value       = aws_sns_topic.security_alerts.name
}

output "operational_alerts_topic_name" {
  description = "Name of the SNS topic for operational alerts"
  value       = aws_sns_topic.operational_alerts.name
}

output "cost_alerts_topic_name" {
  description = "Name of the SNS topic for cost alerts"
  value       = aws_sns_topic.cost_alerts.name
}

# CloudWatch Log Groups
output "monitoring_log_group_name" {
  description = "Name of the CloudWatch log group for monitoring system logs"
  value       = aws_cloudwatch_log_group.monitoring_logs.name
}

output "monitoring_log_group_arn" {
  description = "ARN of the CloudWatch log group for monitoring system logs"
  value       = aws_cloudwatch_log_group.monitoring_logs.arn
}

# Dashboards
output "executive_dashboard_url" {
  description = "URL of the executive CloudWatch dashboard"
  value = var.enable_executive_dashboard ? "https://${data.aws_region.current.name}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#dashboards:name=${aws_cloudwatch_dashboard.executive.dashboard_name}" : null
}

output "operational_dashboard_url" {
  description = "URL of the operational CloudWatch dashboard"
  value = var.enable_operational_dashboard ? "https://${data.aws_region.current.name}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#dashboards:name=${aws_cloudwatch_dashboard.operational.dashboard_name}" : null
}

output "executive_dashboard_name" {
  description = "Name of the executive CloudWatch dashboard"
  value       = var.enable_executive_dashboard ? aws_cloudwatch_dashboard.executive.dashboard_name : null
}

output "operational_dashboard_name" {
  description = "Name of the operational CloudWatch dashboard"
  value       = var.enable_operational_dashboard ? aws_cloudwatch_dashboard.operational.dashboard_name : null
}

# Metric Filters
output "security_metric_filters" {
  description = "Information about security-related CloudWatch metric filters"
  value = {
    security_events = {
      name      = aws_cloudwatch_log_metric_filter.security_events.name
      namespace = "SecurityAgents/Security"
      metric    = "SecurityEvents"
    }
    failed_auth_attempts = {
      name      = aws_cloudwatch_log_metric_filter.failed_auth_attempts.name
      namespace = "SecurityAgents/Security"
      metric    = "FailedAuthAttempts"
    }
    unusual_activity = {
      name      = aws_cloudwatch_log_metric_filter.unusual_activity.name
      namespace = "SecurityAgents/Security"
      metric    = "UnusualActivity"
    }
  }
}

# CloudWatch Alarms
output "security_alarms" {
  description = "Information about security CloudWatch alarms"
  value = {
    security_events_alarm = {
      name        = aws_cloudwatch_metric_alarm.security_events_high.alarm_name
      threshold   = var.security_events_threshold
      description = aws_cloudwatch_metric_alarm.security_events_high.alarm_description
    }
    failed_auth_alarm = {
      name        = aws_cloudwatch_metric_alarm.failed_auth_alarm.alarm_name
      threshold   = var.failed_auth_threshold
      description = aws_cloudwatch_metric_alarm.failed_auth_alarm.alarm_description
    }
    unusual_activity_alarm = {
      name        = aws_cloudwatch_metric_alarm.unusual_activity_alarm.alarm_name
      threshold   = var.unusual_activity_threshold
      description = aws_cloudwatch_metric_alarm.unusual_activity_alarm.alarm_description
    }
  }
}

output "vpc_endpoint_health_alarms" {
  description = "Information about VPC endpoint health alarms"
  value = [
    for i, alarm in aws_cloudwatch_metric_alarm.vpc_endpoint_health : {
      name         = alarm.alarm_name
      endpoint_id  = var.vpc_endpoint_ids[i]
      description  = alarm.alarm_description
    }
  ]
}

# Budget Information
output "cost_budgets" {
  description = "Information about cost budgets and monitoring"
  value = {
    bedrock_budget = {
      name           = aws_budgets_budget.bedrock_monthly.name
      limit_amount   = var.monthly_bedrock_budget
      limit_unit     = "USD"
      time_unit      = "MONTHLY"
    }
    platform_budget = {
      name           = aws_budgets_budget.platform_monthly.name
      limit_amount   = var.monthly_platform_budget
      limit_unit     = "USD"
      time_unit      = "MONTHLY"
    }
  }
}

# Advanced Security Processing
output "security_processor_function_arn" {
  description = "ARN of the Lambda function for advanced security processing"
  value       = var.enable_advanced_security_processing ? aws_lambda_function.security_event_processor[0].arn : null
}

output "security_processor_function_name" {
  description = "Name of the Lambda function for advanced security processing"
  value       = var.enable_advanced_security_processing ? aws_lambda_function.security_event_processor[0].function_name : null
}

# Compliance Status
output "compliance_monitoring_status" {
  description = "Compliance monitoring configuration status"
  value = {
    soc2_monitoring_enabled     = var.compliance_requirements.soc2_monitoring
    iso27001_monitoring_enabled = var.compliance_requirements.iso27001_monitoring
    real_time_alerting_enabled  = var.compliance_requirements.real_time_alerting
    audit_trail_monitoring      = var.compliance_requirements.audit_trail_monitoring
    performance_monitoring      = var.compliance_requirements.performance_monitoring
    
    # Data retention compliance
    metrics_retention_days = var.data_retention_policy.metrics_retention_days
    logs_retention_days   = var.data_retention_policy.logs_retention_days
    alerts_retention_days = var.data_retention_policy.alerts_retention_days
    
    # Encryption and security
    sns_topics_encrypted = true
    log_groups_encrypted = true
    
    # Alert configuration
    critical_alerts_immediate = var.alert_severity_config.critical_immediate_notification
    security_email_count     = length(var.security_alert_emails)
    cost_monitoring_enabled  = true
  }
}

# Alert Configuration Summary
output "alert_configuration" {
  description = "Complete alert configuration summary"
  value = {
    email_notifications = {
      security_emails    = length(var.security_alert_emails)
      operational_emails = length(var.operational_alert_emails)
      cost_emails       = length(var.cost_alert_emails)
    }
    sms_notifications = {
      enabled     = var.enable_sms_alerts
      numbers     = length(var.sms_alert_numbers)
    }
    thresholds = {
      security_events      = var.security_events_threshold
      failed_auth_attempts = var.failed_auth_threshold
      unusual_activity     = var.unusual_activity_threshold
    }
    integrations = {
      slack_enabled      = var.slack_webhook_url != null
      pagerduty_enabled  = var.pagerduty_integration_key != null
    }
  }
}

# Monitoring Features Summary
output "monitoring_features" {
  description = "Summary of enabled monitoring features"
  value = {
    dashboards = {
      executive_enabled    = var.enable_executive_dashboard
      operational_enabled  = var.enable_operational_dashboard
      refresh_interval    = var.dashboard_refresh_interval
    }
    advanced_processing = {
      enabled               = var.enable_advanced_security_processing
      lambda_timeout       = var.security_event_processing_timeout
      debug_logging        = var.enable_debug_logging
    }
    insights = {
      cloudwatch_insights  = var.enable_cloudwatch_insights
      application_insights = var.enable_application_insights
      custom_metrics      = var.enable_custom_metrics
    }
    cost_monitoring = {
      budgets_enabled           = true
      anomaly_detection_enabled = var.enable_cost_anomaly_detection
      bedrock_budget_limit     = var.monthly_bedrock_budget
      platform_budget_limit    = var.monthly_platform_budget
    }
  }
}

# Performance Monitoring
output "performance_monitoring" {
  description = "Performance monitoring configuration details"
  value = {
    metric_collection_interval = var.metric_collection_interval
    application_insights      = var.enable_application_insights
    custom_metrics           = var.enable_custom_metrics
    log_retention_days       = var.log_retention_days
  }
}

# Regional Information
output "aws_region" {
  description = "AWS region where monitoring resources are deployed"
  value       = data.aws_region.current.name
}

output "aws_account_id" {
  description = "AWS account ID where resources are deployed"
  value       = data.aws_caller_identity.current.account_id
}

# Security Event Processing
output "security_event_processing" {
  description = "Security event processing configuration"
  value = {
    advanced_processing_enabled = var.enable_advanced_security_processing
    lambda_function_arn        = var.enable_advanced_security_processing ? aws_lambda_function.security_event_processor[0].arn : null
    subscription_filters_count = var.enable_advanced_security_processing ? 1 : 0
    processing_timeout_seconds = var.security_event_processing_timeout
  }
}

# Cost Optimization Information
output "cost_optimization_features" {
  description = "Cost optimization features for monitoring infrastructure"
  value = {
    sns_topics_encrypted           = true  # Reduces data transfer costs
    cloudwatch_logs_lifecycle      = true  # Automatic log retention
    lambda_timeout_optimized      = var.security_event_processing_timeout
    budget_alerts_configured      = true
    cost_anomaly_detection        = var.enable_cost_anomaly_detection
    metric_collection_optimized   = var.metric_collection_interval >= 60
  }
}