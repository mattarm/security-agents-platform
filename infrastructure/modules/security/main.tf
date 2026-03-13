# SecurityAgents Security Module
# Customer-managed KMS encryption and enterprise IAM controls

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
}

locals {
  common_tags = merge(var.tags, {
    Module      = "SecurityAgents-Security"
    Environment = var.environment
    Security    = "Enterprise"
    Project     = "SecurityAgents"
  })
}

# Get current AWS account and region information
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Customer-Managed KMS Key for SecurityAgents Platform
# Provides enterprise-grade encryption for all data at rest
resource "aws_kms_key" "main" {
  description              = "SecurityAgents platform encryption key - customer-managed for enterprise compliance"
  key_usage               = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  
  # Enterprise security requirements
  deletion_window_in_days = var.kms_deletion_window_days
  enable_key_rotation    = true
  multi_region          = var.enable_multi_region_key
  
  # Key policy - least privilege with audit trail
  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "SecurityAgents-KMS-Policy"
    Statement = [
      {
        # Root account access for key administration
        Sid    = "Enable-Root-Account-Access"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        # SecurityAgents platform services access
        Sid    = "Enable-SecurityAgents-Platform-Access"
        Effect = "Allow"
        Principal = {
          Service = [
            "bedrock.amazonaws.com",
            "logs.amazonaws.com",
            "dynamodb.amazonaws.com",
            "s3.amazonaws.com",
            "monitoring.amazonaws.com"
          ]
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = [
              "bedrock.${data.aws_region.current.name}.amazonaws.com",
              "logs.${data.aws_region.current.name}.amazonaws.com",
              "dynamodb.${data.aws_region.current.name}.amazonaws.com",
              "s3.${data.aws_region.current.name}.amazonaws.com",
              "monitoring.${data.aws_region.current.name}.amazonaws.com"
            ]
          }
        }
      },
      {
        # CloudTrail access for audit logging
        Sid    = "Enable-CloudTrail-Access"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        # Admin role access (to be created)
        Sid    = "Enable-Admin-Role-Access"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.security_admin.arn
        }
        Action = [
          "kms:Create*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:List*",
          "kms:Put*",
          "kms:Update*",
          "kms:Revoke*",
          "kms:Disable*",
          "kms:Get*",
          "kms:Delete*",
          "kms:TagResource",
          "kms:UntagResource",
          "kms:ScheduleKeyDeletion",
          "kms:CancelKeyDeletion"
        ]
        Resource = "*"
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name        = "${var.name_prefix}-main-key"
    Purpose     = "SecurityAgents-Platform-Encryption"
    Compliance  = "SOC2-ISO27001"
    KeyRotation = "Enabled"
  })
}

# KMS Key Alias for easier reference
resource "aws_kms_alias" "main" {
  name          = "alias/${var.name_prefix}-security-platform"
  target_key_id = aws_kms_key.main.key_id
}

# SecurityAgents Platform Admin Role
# Used for administrative operations and key management
resource "aws_iam_role" "security_admin" {
  name_prefix        = "${var.name_prefix}-security-admin-"
  description        = "Administrative role for SecurityAgents platform operations"
  max_session_duration = 3600  # 1 hour sessions for security
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        AWS = var.admin_principal_arns
      }
      Condition = {
        Bool = {
          "aws:MultiFactorAuthPresent" = "true"
        }
        NumericLessThan = {
          "aws:MultiFactorAuthAge" = "3600"  # MFA within 1 hour
        }
      }
    }]
  })
  
  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-security-admin-role"
    Type = "Administrative"
  })
}

# SecurityAgents AI Workload Execution Role  
# Used by ECS/Lambda/etc for AI processing workloads
resource "aws_iam_role" "ai_workload_execution" {
  name_prefix        = "${var.name_prefix}-ai-execution-"
  description        = "Execution role for SecurityAgents AI workloads"
  max_session_duration = 3600
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = [
          "ecs-tasks.amazonaws.com",
          "lambda.amazonaws.com",
          "ec2.amazonaws.com"
        ]
      }
    }]
  })
  
  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-ai-execution-role"
    Type = "WorkloadExecution"
  })
}

# IAM Policy for AI Workload Bedrock Access
resource "aws_iam_policy" "bedrock_access" {
  name_prefix = "${var.name_prefix}-bedrock-access-"
  description = "Least privilege Bedrock access for SecurityAgents AI workloads"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Bedrock model invocation - restricted to allowed models
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ]
        Resource = [
          for model in var.allowed_bedrock_models :
          "arn:aws:bedrock:${data.aws_region.current.name}::foundation-model/${model}"
        ]
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = data.aws_region.current.name
          }
        }
      },
      {
        # Bedrock model listing and information
        Effect = "Allow"
        Action = [
          "bedrock:GetFoundationModel",
          "bedrock:ListFoundationModels"
        ]
        Resource = "*"
      },
      {
        # KMS access for Bedrock encryption
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.main.arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = "bedrock.${data.aws_region.current.name}.amazonaws.com"
          }
        }
      }
    ]
  })
  
  tags = local.common_tags
}

# Attach Bedrock policy to AI workload role
resource "aws_iam_role_policy_attachment" "ai_workload_bedrock" {
  role       = aws_iam_role.ai_workload_execution.name
  policy_arn = aws_iam_policy.bedrock_access.arn
}

# IAM Policy for CloudWatch Logs Access
resource "aws_iam_policy" "cloudwatch_logs" {
  name_prefix = "${var.name_prefix}-cloudwatch-logs-"
  description = "CloudWatch Logs access for SecurityAgents monitoring"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/security-agents/*"
    }]
  })
  
  tags = local.common_tags
}

# Attach CloudWatch Logs policy to AI workload role
resource "aws_iam_role_policy_attachment" "ai_workload_logs" {
  role       = aws_iam_role.ai_workload_execution.name
  policy_arn = aws_iam_policy.cloudwatch_logs.arn
}

# CloudTrail for Complete Audit Trail
resource "aws_cloudtrail" "main" {
  name           = "${var.name_prefix}-audit-trail"
  s3_bucket_name = aws_s3_bucket.audit_logs.id
  
  # Enable logging for all management events
  include_global_service_events = true
  is_multi_region_trail        = var.enable_multi_region_trail
  enable_log_file_validation   = true
  
  # Enterprise security requirements
  kms_key_id = aws_kms_key.main.arn
  
  # TODO: P0 @alpha-1 2026-03-08 Configure data events for S3 and DynamoDB
  event_selector {
    read_write_type                 = "All"
    include_management_events       = true
    exclude_management_event_sources = []
  }
  
  depends_on = [aws_s3_bucket_policy.audit_logs]
  
  tags = merge(local.common_tags, {
    Name        = "${var.name_prefix}-audit-trail"
    Purpose     = "Compliance-Audit-Trail"
    Compliance  = "SOC2-ISO27001-Required"
  })
}

# S3 Bucket for CloudTrail Logs
resource "aws_s3_bucket" "audit_logs" {
  bucket        = "${var.name_prefix}-audit-logs-${random_string.bucket_suffix.result}"
  force_destroy = false  # Prevent accidental deletion of audit logs
  
  tags = merge(local.common_tags, {
    Name        = "${var.name_prefix}-audit-logs"
    Purpose     = "CloudTrail-Audit-Storage"
    Compliance  = "SOC2-ISO27001"
    Retention   = "${var.audit_log_retention_years}-years"
  })
}

# Random string for S3 bucket uniqueness
resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# S3 Bucket Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.main.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true  # Reduce KMS costs
  }
}

# S3 Bucket Versioning for Audit Trail Integrity
resource "aws_s3_bucket_versioning" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 Bucket Lifecycle for Cost Optimization
resource "aws_s3_bucket_lifecycle_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  
  rule {
    id     = "audit_log_lifecycle"
    status = "Enabled"
    
    # Move to IA after 30 days
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    
    # Move to Glacier after 90 days
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    
    # Move to Deep Archive after 1 year
    transition {
      days          = 365
      storage_class = "DEEP_ARCHIVE"
    }
    
    # Retain for compliance period
    expiration {
      days = var.audit_log_retention_years * 365
    }
  }
}

# S3 Bucket Policy for CloudTrail
resource "aws_s3_bucket_policy" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.audit_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.audit_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# TODO: P0 @alpha-1 2026-03-08 Add GuardDuty and Security Hub integrations
# TODO: P0 @alpha-1 2026-03-08 Configure AWS Config for compliance monitoring