# SecurityAgents VPC Module Variables
# Enterprise-grade networking configuration for zero-trust AI workloads

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

variable "vpc_cidr" {
  type        = string
  description = "CIDR block for the VPC - should be large enough for multi-AZ private subnets"
  default     = "10.0.0.0/16"
  
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid IPv4 CIDR block."
  }
}

variable "kms_key_arn" {
  type        = string
  description = "ARN of customer-managed KMS key for encryption at rest"
  
  validation {
    condition     = can(regex("^arn:aws:kms:", var.kms_key_arn))
    error_message = "KMS key ARN must be a valid AWS KMS key ARN."
  }
}

variable "log_retention_days" {
  type        = number
  description = "CloudWatch log retention period in days for audit compliance"
  default     = 365  # 1 year retention for enterprise compliance
  
  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653
    ], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch retention period."
  }
}

variable "enable_vpc_flow_logs" {
  type        = bool
  description = "Enable VPC Flow Logs for security monitoring and compliance"
  default     = true
}

variable "enable_dns_hostnames" {
  type        = bool
  description = "Enable DNS hostnames in the VPC (required for VPC endpoints)"
  default     = true
}

variable "enable_dns_support" {
  type        = bool
  description = "Enable DNS support in the VPC (required for VPC endpoints)"
  default     = true
}

variable "availability_zone_count" {
  type        = number
  description = "Number of availability zones to use (2-3 for HA, cost optimization)"
  default     = 3
  
  validation {
    condition     = var.availability_zone_count >= 2 && var.availability_zone_count <= 3
    error_message = "Availability zone count must be between 2 and 3 for cost-effective high availability."
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

# Security-specific variables
variable "allowed_bedrock_models" {
  type        = list(string)
  description = "List of allowed Bedrock model IDs for VPC endpoint policy"
  default = [
    "anthropic.claude-3-sonnet-20240229-v1:0",
    "anthropic.claude-3-haiku-20240307-v1:0",
    "anthropic.claude-3-opus-20240229-v1:0"
  ]
}

variable "enable_bedrock_logging" {
  type        = bool
  description = "Enable detailed logging for Bedrock API calls (compliance requirement)"
  default     = true
}

variable "network_acl_rules" {
  type = object({
    private_subnets = object({
      allow_internal_https = bool
      allow_vpc_endpoints  = bool
      block_all_internet   = bool
    })
    database_subnets = object({
      allow_internal_only = bool
      allow_monitoring    = bool
    })
  })
  description = "Network ACL rules configuration for defense in depth"
  default = {
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
}

# Monitoring and alerting configuration
variable "cloudwatch_config" {
  type = object({
    enable_detailed_monitoring = bool
    metric_filters = object({
      failed_bedrock_calls = bool
      unusual_traffic      = bool
      security_events      = bool
    })
    alarms = object({
      high_error_rate     = bool
      unusual_activity    = bool
      vpc_flow_anomalies = bool
    })
  })
  description = "CloudWatch monitoring and alerting configuration"
  default = {
    enable_detailed_monitoring = true
    metric_filters = {
      failed_bedrock_calls = true
      unusual_traffic      = true
      security_events      = true
    }
    alarms = {
      high_error_rate     = true
      unusual_activity    = true
      vpc_flow_anomalies = true
    }
  }
}

# Performance and cost optimization
variable "subnet_configuration" {
  type = object({
    private_subnet_size  = number  # /24 = 251 IPs, /25 = 123 IPs, /26 = 59 IPs
    database_subnet_size = number
    reserved_ip_count    = number  # IPs to reserve for future growth
  })
  description = "Subnet sizing configuration for cost and performance optimization"
  default = {
    private_subnet_size  = 26  # /26 = 59 usable IPs per AZ (sufficient for containers)
    database_subnet_size = 28  # /28 = 11 usable IPs per AZ (databases don't need many)
    reserved_ip_count    = 5   # Reserve 5 IPs per subnet for AWS services
  }
}

# Enterprise security validation
variable "security_requirements" {
  type = object({
    require_encryption_in_transit = bool
    require_encryption_at_rest    = bool
    require_mfa_for_access       = bool
    require_audit_logging        = bool
    block_internet_egress        = bool
  })
  description = "Enterprise security requirements validation"
  default = {
    require_encryption_in_transit = true
    require_encryption_at_rest    = true
    require_mfa_for_access       = true
    require_audit_logging        = true
    block_internet_egress        = true
  }
  
  validation {
    condition = (
      var.security_requirements.require_encryption_in_transit &&
      var.security_requirements.require_encryption_at_rest &&
      var.security_requirements.require_audit_logging &&
      var.security_requirements.block_internet_egress
    )
    error_message = "All core security requirements must be enabled for enterprise deployment."
  }
}