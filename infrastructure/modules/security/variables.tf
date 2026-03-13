# SecurityAgents Security Module Variables
# Customer-managed KMS and enterprise IAM configuration

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

# KMS Configuration
variable "kms_deletion_window_days" {
  type        = number
  description = "KMS key deletion window in days (7-30)"
  default     = 30
  
  validation {
    condition     = var.kms_deletion_window_days >= 7 && var.kms_deletion_window_days <= 30
    error_message = "KMS deletion window must be between 7 and 30 days."
  }
}

variable "enable_multi_region_key" {
  type        = bool
  description = "Enable multi-region KMS key for cross-region deployment"
  default     = false  # Start with single region, enable for prod
}

variable "enable_key_rotation" {
  type        = bool
  description = "Enable automatic KMS key rotation"
  default     = true
}

# IAM Configuration
variable "admin_principal_arns" {
  type        = list(string)
  description = "List of IAM principal ARNs that can assume the admin role"
  
  validation {
    condition = length(var.admin_principal_arns) > 0 && alltrue([
      for arn in var.admin_principal_arns : can(regex("^arn:aws:iam::", arn))
    ])
    error_message = "At least one valid IAM principal ARN is required for admin access."
  }
}

variable "mfa_required_for_admin" {
  type        = bool
  description = "Require MFA for admin role assumption"
  default     = true
}

variable "max_session_duration" {
  type        = number
  description = "Maximum session duration in seconds for IAM roles"
  default     = 3600  # 1 hour
  
  validation {
    condition     = var.max_session_duration >= 3600 && var.max_session_duration <= 43200
    error_message = "Session duration must be between 1 hour and 12 hours."
  }
}

# Bedrock Access Configuration
variable "allowed_bedrock_models" {
  type        = list(string)
  description = "List of allowed Bedrock model IDs for security policies"
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

variable "bedrock_regions" {
  type        = list(string)
  description = "AWS regions where Bedrock access is allowed"
  default     = ["us-east-1", "us-west-2"]  # Primary Bedrock regions
  
  validation {
    condition = length(var.bedrock_regions) > 0 && alltrue([
      for region in var.bedrock_regions : can(regex("^[a-z]{2}-[a-z]+-[0-9]$", region))
    ])
    error_message = "At least one valid AWS region is required for Bedrock access."
  }
}

# CloudTrail Configuration
variable "enable_multi_region_trail" {
  type        = bool
  description = "Enable multi-region CloudTrail for comprehensive audit coverage"
  default     = true
}

variable "cloudtrail_log_file_validation" {
  type        = bool
  description = "Enable CloudTrail log file validation for integrity"
  default     = true
}

variable "include_global_service_events" {
  type        = bool
  description = "Include global service events in CloudTrail"
  default     = true
}

variable "audit_log_retention_years" {
  type        = number
  description = "Audit log retention period in years (for compliance)"
  default     = 7  # 7 years for enterprise compliance
  
  validation {
    condition     = var.audit_log_retention_years >= 1 && var.audit_log_retention_years <= 10
    error_message = "Audit log retention must be between 1 and 10 years."
  }
}

# S3 Configuration for Audit Logs
variable "s3_lifecycle_config" {
  type = object({
    transition_to_ia_days         = number
    transition_to_glacier_days    = number
    transition_to_deep_archive_days = number
  })
  description = "S3 lifecycle configuration for cost optimization"
  default = {
    transition_to_ia_days         = 30   # Standard-IA after 30 days
    transition_to_glacier_days    = 90   # Glacier after 90 days  
    transition_to_deep_archive_days = 365 # Deep Archive after 1 year
  }
  
  validation {
    condition = (
      var.s3_lifecycle_config.transition_to_ia_days < var.s3_lifecycle_config.transition_to_glacier_days &&
      var.s3_lifecycle_config.transition_to_glacier_days < var.s3_lifecycle_config.transition_to_deep_archive_days
    )
    error_message = "S3 lifecycle transitions must be in increasing order: IA < Glacier < Deep Archive."
  }
}

variable "s3_bucket_force_destroy" {
  type        = bool
  description = "Allow S3 bucket force destroy (should be false for audit logs)"
  default     = false
}

# Security Monitoring Configuration
variable "enable_guardduty" {
  type        = bool
  description = "Enable AWS GuardDuty for threat detection"
  default     = true
}

variable "enable_security_hub" {
  type        = bool
  description = "Enable AWS Security Hub for compliance monitoring"
  default     = true
}

variable "enable_config" {
  type        = bool
  description = "Enable AWS Config for configuration compliance"
  default     = true
}

variable "security_standards" {
  type        = list(string)
  description = "Security standards to enable in Security Hub"
  default = [
    "aws-foundational-security-standard",
    "cis-aws-foundations-benchmark",
    "pci-dss"
  ]
}

# Compliance and Governance
variable "compliance_requirements" {
  type = object({
    soc2_type2        = bool
    iso_27001        = bool
    pci_dss          = bool
    gdpr_compliance  = bool
    encrypt_at_rest  = bool
    encrypt_in_transit = bool
    audit_all_actions = bool
  })
  description = "Compliance requirements for the security configuration"
  default = {
    soc2_type2        = true
    iso_27001        = true
    pci_dss          = false  # Enable if processing payments
    gdpr_compliance  = true
    encrypt_at_rest  = true
    encrypt_in_transit = true
    audit_all_actions = true
  }
  
  validation {
    condition = (
      var.compliance_requirements.encrypt_at_rest &&
      var.compliance_requirements.encrypt_in_transit &&
      var.compliance_requirements.audit_all_actions
    )
    error_message = "Encryption at rest, in transit, and audit logging are required for enterprise deployment."
  }
}

# Cost Optimization
variable "enable_s3_bucket_key" {
  type        = bool
  description = "Enable S3 bucket key to reduce KMS costs"
  default     = true
}

variable "kms_key_usage_tracking" {
  type        = bool
  description = "Enable KMS key usage tracking for cost analysis"
  default     = true
}

# Development and Testing
variable "allow_dev_access" {
  type        = bool
  description = "Allow additional development access (dev environment only)"
  default     = false
}

variable "dev_principal_arns" {
  type        = list(string)
  description = "Development team IAM principal ARNs (dev environment only)"
  default     = []
  
  validation {
    condition = !var.allow_dev_access || length(var.dev_principal_arns) > 0
    error_message = "If dev access is allowed, dev principal ARNs must be provided."
  }
}