# SecurityAgents Development Environment Variables
# Configuration for Phase 2A development deployment

variable "aws_region" {
  type        = string
  description = "AWS region for development environment"
  default     = "us-east-1"
  
  validation {
    condition = contains([
      "us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"
    ], var.aws_region)
    error_message = "AWS region must be a supported Bedrock region."
  }
}

# IAM Configuration
variable "admin_principal_arns" {
  type        = list(string)
  description = "List of IAM principal ARNs that can assume admin roles"
  
  validation {
    condition = length(var.admin_principal_arns) > 0 && alltrue([
      for arn in var.admin_principal_arns : can(regex("^arn:aws:iam::", arn))
    ])
    error_message = "At least one valid IAM principal ARN is required for admin access."
  }
}

variable "dev_principal_arns" {
  type        = list(string)
  description = "List of development team IAM principal ARNs"
  default     = []
  
  validation {
    condition = alltrue([
      for arn in var.dev_principal_arns : can(regex("^arn:aws:iam::", arn))
    ])
    error_message = "All development principal ARNs must be valid IAM principal ARNs."
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
  
  validation {
    condition = alltrue([
      for email in var.operational_alert_emails : can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", email))
    ])
    error_message = "All operational alert emails must be valid email addresses."
  }
}

variable "cost_alert_emails" {
  type        = list(string)
  description = "Email addresses for cost alerts"
  default     = []
  
  validation {
    condition = alltrue([
      for email in var.cost_alert_emails : can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", email))
    ])
    error_message = "All cost alert emails must be valid email addresses."
  }
}

# Integration Configuration
variable "slack_webhook_url" {
  type        = string
  description = "Slack webhook URL for alert notifications (optional)"
  default     = null
  sensitive   = true
}

variable "enable_slack_integration" {
  type        = bool
  description = "Enable Slack integration for alerts and notifications"
  default     = false
}

# Development Configuration
variable "enable_development_features" {
  type        = bool
  description = "Enable development-specific features and relaxed security"
  default     = true
}

variable "enable_debug_mode" {
  type        = bool
  description = "Enable debug mode with verbose logging"
  default     = true
}

variable "development_ip_whitelist" {
  type        = list(string)
  description = "IP addresses allowed for development access (CIDR blocks)"
  default     = []
  
  validation {
    condition = alltrue([
      for cidr in var.development_ip_whitelist : can(cidrhost(cidr, 0))
    ])
    error_message = "All development IP whitelist entries must be valid CIDR blocks."
  }
}

# Cost Configuration
variable "development_budget_limit" {
  type        = number
  description = "Total monthly budget limit for development environment in USD"
  default     = 500
  
  validation {
    condition     = var.development_budget_limit >= 50 && var.development_budget_limit <= 5000
    error_message = "Development budget limit must be between $50 and $5,000."
  }
}

variable "bedrock_budget_limit" {
  type        = number
  description = "Monthly budget limit for Bedrock costs in development"
  default     = 200
  
  validation {
    condition     = var.bedrock_budget_limit >= 10 && var.bedrock_budget_limit <= 2000
    error_message = "Bedrock budget limit must be between $10 and $2,000 for development."
  }
}

# Testing Configuration
variable "enable_testing_features" {
  type        = bool
  description = "Enable additional testing and validation features"
  default     = true
}

variable "testing_data_retention_days" {
  type        = number
  description = "Data retention period for testing data in days"
  default     = 7
  
  validation {
    condition     = var.testing_data_retention_days >= 1 && var.testing_data_retention_days <= 90
    error_message = "Testing data retention must be between 1 and 90 days."
  }
}

variable "enable_performance_testing" {
  type        = bool
  description = "Enable performance testing features and metrics"
  default     = true
}

# Network Configuration
variable "vpc_cidr_override" {
  type        = string
  description = "Override VPC CIDR block for development (optional)"
  default     = null
  
  validation {
    condition     = var.vpc_cidr_override == null || can(cidrhost(var.vpc_cidr_override, 0))
    error_message = "VPC CIDR override must be a valid IPv4 CIDR block."
  }
}

variable "enable_vpc_flow_logs" {
  type        = bool
  description = "Enable VPC Flow Logs for network monitoring"
  default     = true
}

# Compliance Configuration (Relaxed for Development)
variable "compliance_level" {
  type        = string
  description = "Compliance level for development environment"
  default     = "development"
  
  validation {
    condition     = contains(["development", "staging", "production"], var.compliance_level)
    error_message = "Compliance level must be development, staging, or production."
  }
}

variable "enable_audit_logging" {
  type        = bool
  description = "Enable comprehensive audit logging"
  default     = true
}

variable "data_classification" {
  type        = string
  description = "Data classification level for development environment"
  default     = "Internal"
  
  validation {
    condition     = contains(["Public", "Internal", "Confidential", "Restricted"], var.data_classification)
    error_message = "Data classification must be one of: Public, Internal, Confidential, Restricted."
  }
}

# Monitoring Configuration
variable "monitoring_level" {
  type        = string
  description = "Level of monitoring detail for development"
  default     = "detailed"
  
  validation {
    condition     = contains(["basic", "detailed", "comprehensive"], var.monitoring_level)
    error_message = "Monitoring level must be basic, detailed, or comprehensive."
  }
}

variable "alert_frequency" {
  type        = string
  description = "Frequency of alerts for development environment"
  default     = "immediate"
  
  validation {
    condition     = contains(["immediate", "hourly", "daily"], var.alert_frequency)
    error_message = "Alert frequency must be immediate, hourly, or daily."
  }
}

# Feature Flags
variable "feature_flags" {
  type = object({
    advanced_security_processing = bool
    custom_metrics_collection   = bool
    ai_model_monitoring        = bool
    cost_optimization_alerts   = bool
    performance_analytics      = bool
  })
  description = "Feature flags for development environment capabilities"
  default = {
    advanced_security_processing = true
    custom_metrics_collection   = true
    ai_model_monitoring        = true
    cost_optimization_alerts   = true
    performance_analytics      = true
  }
}

# Deployment Configuration
variable "deployment_mode" {
  type        = string
  description = "Deployment mode for development environment"
  default     = "development"
  
  validation {
    condition     = contains(["development", "testing", "integration"], var.deployment_mode)
    error_message = "Deployment mode must be development, testing, or integration."
  }
}

variable "auto_scaling_enabled" {
  type        = bool
  description = "Enable auto-scaling for development resources"
  default     = false
}

variable "high_availability_enabled" {
  type        = bool
  description = "Enable high availability features (not required for dev)"
  default     = false
}

# Resource Sizing
variable "resource_sizing" {
  type = object({
    vpc_endpoints_count    = number
    availability_zones     = number
    log_retention_days     = number
    metric_retention_days  = number
  })
  description = "Resource sizing configuration for cost optimization"
  default = {
    vpc_endpoints_count    = 3   # Minimal set for dev
    availability_zones     = 2   # Two AZs sufficient for dev
    log_retention_days     = 30  # One month for development
    metric_retention_days  = 90  # Three months for analysis
  }
  
  validation {
    condition = (
      var.resource_sizing.vpc_endpoints_count >= 1 &&
      var.resource_sizing.availability_zones >= 1 &&
      var.resource_sizing.log_retention_days >= 1 &&
      var.resource_sizing.metric_retention_days >= 1
    )
    error_message = "All resource sizing values must be positive numbers."
  }
}

# Environment-Specific Overrides
variable "environment_overrides" {
  type = map(any)
  description = "Environment-specific configuration overrides"
  default = {}
}

# Tags
variable "additional_tags" {
  type        = map(string)
  description = "Additional tags to apply to all resources"
  default = {
    Purpose     = "SecurityAgents-Development"
    Team        = "Alpha-1-Infrastructure"
    Phase       = "2A-Implementation"
    CostCenter  = "Security-Development"
  }
}