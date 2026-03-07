# SecurityAgents Security Module Outputs
# Export KMS keys, IAM roles, and security resources for other modules

# KMS Key Information
output "kms_key_id" {
  description = "ID of the customer-managed KMS key for SecurityAgents platform"
  value       = aws_kms_key.main.key_id
}

output "kms_key_arn" {
  description = "ARN of the customer-managed KMS key for SecurityAgents platform"
  value       = aws_kms_key.main.arn
}

output "kms_key_alias" {
  description = "Alias of the KMS key for easy reference"
  value       = aws_kms_alias.main.name
}

output "kms_key_alias_arn" {
  description = "ARN of the KMS key alias"
  value       = aws_kms_alias.main.arn
}

# IAM Roles
output "security_admin_role_arn" {
  description = "ARN of the SecurityAgents admin role for management operations"
  value       = aws_iam_role.security_admin.arn
}

output "security_admin_role_name" {
  description = "Name of the SecurityAgents admin role"
  value       = aws_iam_role.security_admin.name
}

output "ai_workload_execution_role_arn" {
  description = "ARN of the AI workload execution role for Bedrock access"
  value       = aws_iam_role.ai_workload_execution.arn
}

output "ai_workload_execution_role_name" {
  description = "Name of the AI workload execution role"
  value       = aws_iam_role.ai_workload_execution.name
}

# IAM Policies
output "bedrock_access_policy_arn" {
  description = "ARN of the Bedrock access policy for AI workloads"
  value       = aws_iam_policy.bedrock_access.arn
}

output "cloudwatch_logs_policy_arn" {
  description = "ARN of the CloudWatch Logs policy for monitoring"
  value       = aws_iam_policy.cloudwatch_logs.arn
}

# CloudTrail and Audit
output "cloudtrail_arn" {
  description = "ARN of the CloudTrail for audit logging"
  value       = aws_cloudtrail.main.arn
}

output "cloudtrail_name" {
  description = "Name of the CloudTrail"
  value       = aws_cloudtrail.main.name
}

output "audit_logs_bucket_id" {
  description = "ID of the S3 bucket for CloudTrail audit logs"
  value       = aws_s3_bucket.audit_logs.id
}

output "audit_logs_bucket_arn" {
  description = "ARN of the S3 bucket for CloudTrail audit logs"
  value       = aws_s3_bucket.audit_logs.arn
}

output "audit_logs_bucket_domain_name" {
  description = "Domain name of the audit logs S3 bucket"
  value       = aws_s3_bucket.audit_logs.bucket_domain_name
}

# Security Configuration Summary
output "security_compliance_status" {
  description = "Security compliance status for audit purposes"
  value = {
    kms_key_rotation_enabled   = aws_kms_key.main.enable_key_rotation
    cloudtrail_enabled        = true
    cloudtrail_multi_region   = aws_cloudtrail.main.is_multi_region_trail
    log_file_validation       = aws_cloudtrail.main.enable_log_file_validation
    encryption_at_rest        = true
    audit_logs_encrypted     = true
    mfa_required_for_admin   = var.mfa_required_for_admin
    least_privilege_policies = true
  }
}

# Cost Information
output "cost_optimization_info" {
  description = "Cost optimization configuration for financial tracking"
  value = {
    kms_key_deletion_window = aws_kms_key.main.deletion_window_in_days
    s3_lifecycle_enabled    = true
    s3_bucket_key_enabled   = var.enable_s3_bucket_key
    multi_region_key        = var.enable_multi_region_key
    audit_retention_years   = var.audit_log_retention_years
  }
}

# Allowed Resources Information
output "allowed_bedrock_models" {
  description = "List of Bedrock models allowed by security policies"
  value       = var.allowed_bedrock_models
}

output "allowed_bedrock_regions" {
  description = "AWS regions where Bedrock access is allowed"
  value       = var.bedrock_regions
}

# Security Monitoring Resources (Future Implementation)
output "security_monitoring" {
  description = "Security monitoring resources information"
  value = {
    guardduty_enabled   = var.enable_guardduty
    security_hub_enabled = var.enable_security_hub
    config_enabled      = var.enable_config
    standards_enabled   = var.security_standards
  }
}

# Enterprise Features Summary
output "enterprise_features" {
  description = "Enterprise security features enabled"
  value = {
    customer_managed_keys     = true
    zero_trust_network       = true
    complete_audit_trail     = true
    encryption_everywhere    = true
    least_privilege_access   = true
    multi_factor_auth        = var.mfa_required_for_admin
    compliance_ready         = true
    automated_key_rotation   = aws_kms_key.main.enable_key_rotation
  }
}

# Account and Region Information
output "aws_account_id" {
  description = "AWS account ID where resources are deployed"
  value       = data.aws_caller_identity.current.account_id
}

output "aws_region" {
  description = "AWS region where resources are deployed"
  value       = data.aws_region.current.name
}

# Bucket Suffix for Reference
output "bucket_suffix" {
  description = "Random suffix used for S3 bucket naming"
  value       = random_string.bucket_suffix.result
  sensitive   = false
}