# SecurityAgents Monitoring Module Variables
# Comprehensive monitoring, alerting, and dashboard configuration

variable "name_prefix" {
  type        = string
  description = "Prefix for all resource names to ensure uniqueness"
  
  validation {
    condition     = length(var.name_prefix) <= 20 && can(regex("^[a-zA-Z][a-zA-Z0-9-]*$", var.name_prefix))
    error_message = "Name prefix must be 20 characters or less and start with a letter."
  }
}

variable "environment" {
  type        = string
  description = "Environment name (dev, staging, prod)"
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "tags" {
  type        = map(string)
  description = "Additional tags to apply to all resources"
  default = {
    Project    = "SecurityAgents"
    Purpose    = "AI-Security-Platform"
    Compliance = "SOC2-ISO27001"
  }
}

# Security and Encryption
variable "kms_key_arn" {
  type        = string
  description = "ARN of customer-managed KMS key for encryption"
  
  validation {
    condition     = can(regex("^arn:aws:kms:", var.kms_key_arn))
    error_message = "KMS key ARN must be a valid AWS KMS key ARN."
  }
}

# Log Groups for Monitoring
variable "vpc_flow_log_group_name" {
  type        = string
  description = "Name of the VPC flow log CloudWatch log group"
}

variable "bedrock_log_group_name" {
  type        = string
  description = "Name of the Bedrock invocation CloudWatch log group"
}

variable "application_log_group_name" {
  type        = string
  description = "Name of the application CloudWatch log group"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID for network monitoring"
}

variable "vpc_endpoint_ids" {
  type        = list(string)
  description = "List of VPC endpoint IDs to monitor"
  default     = []
}

# Logging Configuration
variable "log_retention_days" {
  type        = number
  description = "CloudWatch log retention period in days"
  default     = 365
  
  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653
    ], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch retention period."
  }
}

# Alert Configuration
variable "security_alert_emails" {
  type        = list(string)
  description = "Email addresses for critical security alerts"
  
  validation {
    condition = length(var.security_alert_emails) > 0 && alltrue([
      for email in var.security_alert_emails : can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", email))
    ])
    error_message = "At least one valid email address is required for security alerts."
  }
}

variable "operational_alert_emails" {
  type        = list(string)
  description = "Email addresses for operational alerts"
  default     = []
}

variable "cost_alert_emails" {
  type        = list(string)
  description = "Email addresses for cost alerts"
  default     = []
}

variable "enable_sms_alerts" {
  type        = bool
  description = "Enable SMS alerts for critical security events"
  default     = false
}

variable "sms_alert_numbers" {
  type        = list(string)
  description = "Phone numbers for SMS alerts (E.164 format)"
  default     = []
  
  validation {
    condition = !var.enable_sms_alerts || (length(var.sms_alert_numbers) > 0 && alltrue([
      for number in var.sms_alert_numbers : can(regex("^\\+[1-9]\\d{1,14}$", number))
    ]))
    error_message = "If SMS alerts are enabled, at least one valid phone number in E.164 format is required."
  }
}

# Threshold Configuration
variable "security_events_threshold" {
  type        = number
  description = "Threshold for security events alarm (events per 5 minutes)"
  default     = 10
  
  validation {
    condition     = var.security_events_threshold >= 1 && var.security_events_threshold <= 1000
    error_message = "Security events threshold must be between 1 and 1000."
  }
}

variable "failed_auth_threshold" {
  type        = number
  description = "Threshold for failed authentication attempts alarm"
  default     = 5
  
  validation {
    condition     = var.failed_auth_threshold >= 1 && var.failed_auth_threshold <= 100
    error_message = "Failed auth threshold must be between 1 and 100."
  }
}

variable "unusual_activity_threshold" {
  type        = number
  description = "Threshold for unusual activity detection alarm"
  default     = 3
  
  validation {
    condition     = var.unusual_activity_threshold >= 1 && var.unusual_activity_threshold <= 50
    error_message = "Unusual activity threshold must be between 1 and 50."
  }
}

# Cost Monitoring
variable "monthly_bedrock_budget" {
  type        = number
  description = "Monthly budget limit for Bedrock costs in USD"
  default     = 500
  
  validation {
    condition     = var.monthly_bedrock_budget >= 10 && var.monthly_bedrock_budget <= 50000
    error_message = "Monthly Bedrock budget must be between $10 and $50,000."
  }
}

variable "monthly_platform_budget" {
  type        = number
  description = "Monthly budget limit for entire platform costs in USD"
  default     = 1000
  
  validation {
    condition     = var.monthly_platform_budget >= 50 && var.monthly_platform_budget <= 100000
    error_message = "Monthly platform budget must be between $50 and $100,000."
  }
}

variable "enable_cost_anomaly_detection" {
  type        = bool
  description = "Enable AWS Cost Anomaly Detection"
  default     = true
}

# Dashboard Configuration
variable "enable_executive_dashboard" {
  type        = bool
  description = "Enable executive-level dashboard for business metrics"
  default     = true
}

variable "enable_operational_dashboard" {
  type        = bool
  description = "Enable operational dashboard for detailed monitoring"
  default     = true
}

variable "dashboard_refresh_interval" {
  type        = string
  description = "Dashboard refresh interval (ISO 8601 duration)"
  default     = "PT5M"
  
  validation {
    condition = contains([
      "PT1M", "PT5M", "PT15M", "PT30M", "PT1H", "PT3H", "PT6H", "PT12H", "P1D"
    ], var.dashboard_refresh_interval)
    error_message = "Dashboard refresh interval must be a valid ISO 8601 duration."
  }
}

# Advanced Security Processing
variable "enable_advanced_security_processing" {
  type        = bool
  description = "Enable advanced Lambda-based security event processing"
  default     = false  # Start disabled, enable in production
}

variable "enable_debug_logging" {
  type        = bool
  description = "Enable debug-level logging for troubleshooting"
  default     = false
}

variable "security_event_processing_timeout" {
  type        = number
  description = "Timeout in seconds for security event processing Lambda"
  default     = 60
  
  validation {
    condition     = var.security_event_processing_timeout >= 30 && var.security_event_processing_timeout <= 900
    error_message = "Security event processing timeout must be between 30 and 900 seconds."
  }
}

# Integration Configuration
variable "slack_webhook_url" {
  type        = string
  description = "Slack webhook URL for alert notifications (optional)"
  default     = null
  sensitive   = true
}

variable "pagerduty_integration_key" {
  type        = string
  description = "PagerDuty integration key for critical alerts (optional)"
  default     = null
  sensitive   = true
}

variable "enable_cloudwatch_insights" {
  type        = bool
  description = "Enable CloudWatch Insights for advanced log analysis"
  default     = true
}

# Compliance and Audit
variable "compliance_requirements" {
  type = object({
    soc2_monitoring     = bool
    iso27001_monitoring = bool
    real_time_alerting  = bool
    audit_trail_monitoring = bool
    performance_monitoring = bool
  })
  description = "Compliance requirements for monitoring configuration"
  default = {
    soc2_monitoring     = true
    iso27001_monitoring = true
    real_time_alerting  = true
    audit_trail_monitoring = true
    performance_monitoring = true
  }
  
  validation {
    condition = (
      var.compliance_requirements.real_time_alerting &&
      var.compliance_requirements.audit_trail_monitoring
    )
    error_message = "Real-time alerting and audit trail monitoring are required for enterprise compliance."
  }
}

variable "data_retention_policy" {
  type = object({
    metrics_retention_days = number
    logs_retention_days    = number
    alerts_retention_days  = number
  })
  description = "Data retention policy for compliance"
  default = {
    metrics_retention_days = 2555  # ~7 years
    logs_retention_days    = 365   # 1 year
    alerts_retention_days  = 1095  # 3 years
  }
}

# Performance Monitoring
variable "enable_application_insights" {
  type        = bool
  description = "Enable application performance insights"
  default     = true
}

variable "enable_custom_metrics" {
  type        = bool
  description = "Enable custom business and security metrics"
  default     = true
}

variable "metric_collection_interval" {
  type        = number
  description = "Metric collection interval in seconds"
  default     = 60
  
  validation {
    condition     = var.metric_collection_interval >= 60 && var.metric_collection_interval <= 3600
    error_message = "Metric collection interval must be between 60 seconds and 1 hour."
  }
}

# Alert Severity Configuration
variable "alert_severity_config" {
  type = object({
    critical_immediate_notification = bool
    high_notification_delay_minutes = number
    medium_notification_delay_minutes = number
    low_notification_suppression = bool
  })
  description = "Alert severity and notification configuration"
  default = {
    critical_immediate_notification = true
    high_notification_delay_minutes = 5
    medium_notification_delay_minutes = 15
    low_notification_suppression = true
  }
}