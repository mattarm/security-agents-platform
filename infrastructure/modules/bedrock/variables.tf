# SecurityAgents Bedrock Module Variables
# Secure Bedrock deployment configuration with enterprise monitoring

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

# Logging Configuration
variable "log_retention_days" {
  type        = number
  description = "CloudWatch log retention period in days"
  default     = 365  # 1 year for enterprise compliance
  
  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653
    ], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch retention period."
  }
}

variable "enable_bedrock_logging" {
  type        = bool
  description = "Enable Bedrock model invocation logging (required for compliance)"
  default     = true
}

variable "enable_embedding_logging" {
  type        = bool
  description = "Enable logging of embedding data in model invocations"
  default     = true
}

variable "enable_image_logging" {
  type        = bool
  description = "Enable logging of image data in model invocations"
  default     = true
}

variable "enable_text_logging" {
  type        = bool
  description = "Enable logging of text data in model invocations"
  default     = true
}

# Model Configuration
variable "allowed_bedrock_models" {
  type        = list(string)
  description = "List of allowed Bedrock model IDs for the platform"
  default = [
    "anthropic.claude-3-sonnet-20240229-v1:0",
    "anthropic.claude-3-haiku-20240307-v1:0",
    "anthropic.claude-3-opus-20240229-v1:0"
  ]
  
  validation {
    condition = length(var.allowed_bedrock_models) > 0 && alltrue([
      for model in var.allowed_bedrock_models : can(regex("^anthropic\\.", model))
    ])
    error_message = "At least one valid Anthropic Bedrock model ID is required."
  }
}

variable "default_model_id" {
  type        = string
  description = "Default Bedrock model ID for SecurityAgents platform"
  default     = "anthropic.claude-3-sonnet-20240229-v1:0"
}

# Performance and Monitoring
variable "enable_detailed_monitoring" {
  type        = bool
  description = "Enable detailed CloudWatch monitoring for Bedrock"
  default     = true
}

variable "error_threshold" {
  type        = number
  description = "Error count threshold for CloudWatch alarms"
  default     = 5
  
  validation {
    condition     = var.error_threshold >= 1 && var.error_threshold <= 100
    error_message = "Error threshold must be between 1 and 100."
  }
}

variable "throttle_threshold" {
  type        = number
  description = "Throttle count threshold for CloudWatch alarms"
  default     = 3
  
  validation {
    condition     = var.throttle_threshold >= 1 && var.throttle_threshold <= 50
    error_message = "Throttle threshold must be between 1 and 50."
  }
}

variable "latency_threshold_ms" {
  type        = number
  description = "Latency threshold in milliseconds for high-latency alerts"
  default     = 30000  # 30 seconds
  
  validation {
    condition     = var.latency_threshold_ms >= 1000 && var.latency_threshold_ms <= 300000
    error_message = "Latency threshold must be between 1 second and 5 minutes."
  }
}

# Alerting
variable "alarm_topic_arn" {
  type        = string
  description = "SNS topic ARN for CloudWatch alarms (optional)"
  default     = null
}

variable "enable_cost_alerts" {
  type        = bool
  description = "Enable cost-related alerts for Bedrock usage"
  default     = true
}

variable "monthly_cost_threshold" {
  type        = number
  description = "Monthly cost threshold in USD for budget alerts"
  default     = 1000
  
  validation {
    condition     = var.monthly_cost_threshold >= 10 && var.monthly_cost_threshold <= 50000
    error_message = "Monthly cost threshold must be between $10 and $50,000."
  }
}

# S3 Configuration for Long-term Log Storage
variable "s3_lifecycle_config" {
  type = object({
    transition_to_ia_days         = number
    transition_to_glacier_days    = number
    transition_to_deep_archive_days = number
  })
  description = "S3 lifecycle configuration for Bedrock logs"
  default = {
    transition_to_ia_days         = 30
    transition_to_glacier_days    = 90
    transition_to_deep_archive_days = 365
  }
  
  validation {
    condition = (
      var.s3_lifecycle_config.transition_to_ia_days < var.s3_lifecycle_config.transition_to_glacier_days &&
      var.s3_lifecycle_config.transition_to_glacier_days < var.s3_lifecycle_config.transition_to_deep_archive_days
    )
    error_message = "S3 lifecycle transitions must be in increasing order: IA < Glacier < Deep Archive."
  }
}

# Dashboard and Reporting
variable "enable_dashboard" {
  type        = bool
  description = "Enable CloudWatch dashboard for Bedrock monitoring"
  default     = true
}

variable "dashboard_refresh_interval" {
  type        = string
  description = "CloudWatch dashboard refresh interval"
  default     = "PT5M"  # 5 minutes
  
  validation {
    condition = contains([
      "PT1M", "PT5M", "PT15M", "PT30M", "PT1H", "PT3H", "PT6H", "PT12H", "P1D"
    ], var.dashboard_refresh_interval)
    error_message = "Dashboard refresh interval must be a valid ISO 8601 duration."
  }
}

# Enterprise Features
variable "compliance_requirements" {
  type = object({
    data_residency_required     = bool
    audit_all_invocations      = bool
    encrypt_logs_at_rest       = bool
    retain_logs_for_compliance = bool
    enable_model_monitoring    = bool
  })
  description = "Enterprise compliance requirements for Bedrock deployment"
  default = {
    data_residency_required     = true
    audit_all_invocations      = true
    encrypt_logs_at_rest       = true
    retain_logs_for_compliance = true
    enable_model_monitoring    = true
  }
  
  validation {
    condition = (
      var.compliance_requirements.audit_all_invocations &&
      var.compliance_requirements.encrypt_logs_at_rest
    )
    error_message = "Audit logging and encryption are required for enterprise compliance."
  }
}

variable "data_classification" {
  type        = string
  description = "Data classification level for the Bedrock deployment"
  default     = "Confidential"
  
  validation {
    condition     = contains(["Public", "Internal", "Confidential", "Restricted"], var.data_classification)
    error_message = "Data classification must be one of: Public, Internal, Confidential, Restricted."
  }
}

# Cost Optimization
variable "enable_s3_bucket_key" {
  type        = bool
  description = "Enable S3 bucket key to reduce KMS costs for log storage"
  default     = true
}

variable "enable_log_compression" {
  type        = bool
  description = "Enable log compression for cost optimization"
  default     = true
}

# Development and Testing
variable "enable_debug_logging" {
  type        = bool
  description = "Enable debug-level logging (dev environments only)"
  default     = false
}

variable "sample_request_logging" {
  type        = number
  description = "Percentage of requests to log in detail (0-100)"
  default     = 100  # Log all requests for security
  
  validation {
    condition     = var.sample_request_logging >= 0 && var.sample_request_logging <= 100
    error_message = "Sample request logging must be between 0 and 100 percent."
  }
}

# Business Metrics
variable "enable_business_metrics" {
  type        = bool
  description = "Enable business KPI tracking and metrics"
  default     = true
}

variable "business_metrics_config" {
  type = object({
    track_security_analysis_requests = bool
    track_response_times            = bool
    track_model_usage_patterns      = bool
    track_cost_per_analysis         = bool
  })
  description = "Configuration for business metrics tracking"
  default = {
    track_security_analysis_requests = true
    track_response_times            = true
    track_model_usage_patterns      = true
    track_cost_per_analysis         = true
  }
}