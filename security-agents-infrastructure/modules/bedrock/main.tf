# SecurityAgents Bedrock Module
# Secure AWS Bedrock deployment with enterprise logging and monitoring

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
    Module      = "SecurityAgents-Bedrock"
    Environment = var.environment
    Security    = "Enterprise"
    Project     = "SecurityAgents"
  })
}

# Get current region and account information
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# CloudWatch Log Group for Bedrock Model Invocation Logging
# Required for enterprise compliance and monitoring
resource "aws_cloudwatch_log_group" "bedrock_model_invocation" {
  name              = "/aws/bedrock/security-agents/${var.name_prefix}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  
  tags = merge(local.common_tags, {
    Name        = "${var.name_prefix}-bedrock-model-logs"
    Purpose     = "AI-Model-Invocation-Audit"
    Compliance  = "SOC2-ISO27001-Required"
  })
}

# CloudWatch Log Group for Application Logs
resource "aws_cloudwatch_log_group" "application_logs" {
  name              = "/aws/security-agents/${var.name_prefix}/application"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  
  tags = merge(local.common_tags, {
    Name    = "${var.name_prefix}-application-logs"
    Purpose = "Application-Logging"
  })
}

# Bedrock Model Invocation Logging Configuration
# This configures logging for all model invocations in the account
resource "aws_bedrock_model_invocation_logging_configuration" "main" {
  logging_config {
    embedding_data_delivery_enabled = var.enable_embedding_logging
    image_data_delivery_enabled     = var.enable_image_logging
    text_data_delivery_enabled      = var.enable_text_logging
    
    # CloudWatch Logs configuration
    cloudwatch_config {
      log_group_name = aws_cloudwatch_log_group.bedrock_model_invocation.name
      role_arn      = aws_iam_role.bedrock_logging.arn
    }
    
    # S3 configuration for long-term storage
    s3_config {
      bucket_name  = aws_s3_bucket.bedrock_logs.id
      key_prefix   = "bedrock-invocations/"
    }
  }
}

# S3 Bucket for Bedrock Logs Long-term Storage
resource "aws_s3_bucket" "bedrock_logs" {
  bucket        = "${var.name_prefix}-bedrock-logs-${random_string.bucket_suffix.result}"
  force_destroy = false  # Prevent accidental deletion
  
  tags = merge(local.common_tags, {
    Name        = "${var.name_prefix}-bedrock-logs"
    Purpose     = "Bedrock-Model-Invocation-Storage"
    Compliance  = "SOC2-ISO27001"
  })
}

# Random string for bucket uniqueness
resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# S3 Bucket Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "bedrock_logs" {
  bucket = aws_s3_bucket.bedrock_logs.id
  
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# S3 Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "bedrock_logs" {
  bucket = aws_s3_bucket.bedrock_logs.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 Bucket Lifecycle for Cost Optimization
resource "aws_s3_bucket_lifecycle_configuration" "bedrock_logs" {
  bucket = aws_s3_bucket.bedrock_logs.id
  
  rule {
    id     = "bedrock_logs_lifecycle"
    status = "Enabled"
    
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    
    transition {
      days          = 365
      storage_class = "DEEP_ARCHIVE"
    }
    
    expiration {
      days = var.log_retention_days
    }
  }
}

# IAM Role for Bedrock Logging
resource "aws_iam_role" "bedrock_logging" {
  name_prefix        = "${var.name_prefix}-bedrock-logging-"
  description        = "IAM role for Bedrock model invocation logging"
  max_session_duration = 3600
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "bedrock.amazonaws.com"
      }
    }]
  })
  
  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-bedrock-logging-role"
    Type = "ServiceRole"
  })
}

# IAM Policy for Bedrock CloudWatch Logs Access
resource "aws_iam_policy" "bedrock_cloudwatch_logs" {
  name_prefix = "${var.name_prefix}-bedrock-logs-"
  description = "Policy for Bedrock to write to CloudWatch Logs"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.bedrock_model_invocation.arn}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = var.kms_key_arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = "logs.${data.aws_region.current.name}.amazonaws.com"
          }
        }
      }
    ]
  })
  
  tags = local.common_tags
}

# IAM Policy for Bedrock S3 Access
resource "aws_iam_policy" "bedrock_s3_logs" {
  name_prefix = "${var.name_prefix}-bedrock-s3-"
  description = "Policy for Bedrock to write logs to S3"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl"
        ]
        Resource = "${aws_s3_bucket.bedrock_logs.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketLocation",
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.bedrock_logs.arn
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = var.kms_key_arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${data.aws_region.current.name}.amazonaws.com"
          }
        }
      }
    ]
  })
  
  tags = local.common_tags
}

# Attach CloudWatch Logs policy to Bedrock logging role
resource "aws_iam_role_policy_attachment" "bedrock_cloudwatch_logs" {
  role       = aws_iam_role.bedrock_logging.name
  policy_arn = aws_iam_policy.bedrock_cloudwatch_logs.arn
}

# Attach S3 policy to Bedrock logging role
resource "aws_iam_role_policy_attachment" "bedrock_s3_logs" {
  role       = aws_iam_role.bedrock_logging.name
  policy_arn = aws_iam_policy.bedrock_s3_logs.arn
}

# CloudWatch Metric Filters for Monitoring
resource "aws_cloudwatch_log_metric_filter" "bedrock_errors" {
  name           = "${var.name_prefix}-bedrock-errors"
  log_group_name = aws_cloudwatch_log_group.bedrock_model_invocation.name
  pattern        = "[timestamp, request_id, \"ERROR\", ...]"
  
  metric_transformation {
    name      = "BedrockErrors"
    namespace = "SecurityAgents/Bedrock"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "bedrock_throttles" {
  name           = "${var.name_prefix}-bedrock-throttles"
  log_group_name = aws_cloudwatch_log_group.bedrock_model_invocation.name
  pattern        = "[timestamp, request_id, *, \"ThrottlingException\", ...]"
  
  metric_transformation {
    name      = "BedrockThrottles"
    namespace = "SecurityAgents/Bedrock"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "bedrock_high_latency" {
  name           = "${var.name_prefix}-bedrock-latency"
  log_group_name = aws_cloudwatch_log_group.bedrock_model_invocation.name
  # Look for invocations taking longer than 30 seconds
  pattern        = "[timestamp, request_id, *, duration > 30000, ...]"
  
  metric_transformation {
    name      = "BedrockHighLatency"
    namespace = "SecurityAgents/Bedrock"
    value     = "1"
  }
}

# CloudWatch Alarms for Monitoring
resource "aws_cloudwatch_metric_alarm" "bedrock_error_rate" {
  alarm_name          = "${var.name_prefix}-bedrock-error-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "BedrockErrors"
  namespace           = "SecurityAgents/Bedrock"
  period              = 300  # 5 minutes
  statistic           = "Sum"
  threshold           = var.error_threshold
  alarm_description   = "Bedrock error rate is too high"
  alarm_actions       = var.alarm_topic_arn != null ? [var.alarm_topic_arn] : []
  
  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-bedrock-error-alarm"
  })
}

resource "aws_cloudwatch_metric_alarm" "bedrock_throttle_rate" {
  alarm_name          = "${var.name_prefix}-bedrock-throttle-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "BedrockThrottles"
  namespace           = "SecurityAgents/Bedrock"
  period              = 300
  statistic           = "Sum"
  threshold           = var.throttle_threshold
  alarm_description   = "Bedrock throttle rate is too high - may need to increase limits"
  alarm_actions       = var.alarm_topic_arn != null ? [var.alarm_topic_arn] : []
  
  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-bedrock-throttle-alarm"
  })
}

# TODO: P0 @alpha-1 2026-03-08 Add custom CloudWatch dashboard for Bedrock metrics
resource "aws_cloudwatch_dashboard" "bedrock_monitoring" {
  dashboard_name = "${var.name_prefix}-bedrock-dashboard"
  
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            ["SecurityAgents/Bedrock", "BedrockErrors"],
            [".", "BedrockThrottles"],
            [".", "BedrockHighLatency"]
          ]
          period = 300
          stat   = "Sum"
          region = data.aws_region.current.name
          title  = "Bedrock Error and Performance Metrics"
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 6
        width  = 24
        height = 6
        
        properties = {
          query = "SOURCE '${aws_cloudwatch_log_group.bedrock_model_invocation.name}'\n| fields @timestamp, @message\n| filter @message like /ERROR/\n| sort @timestamp desc\n| limit 100"
          region = data.aws_region.current.name
          title  = "Recent Bedrock Errors"
        }
      }
    ]
  })
  
  tags = local.common_tags
}

# TODO: P0 @alpha-1 2026-03-08 Add performance monitoring and cost tracking
# Custom metrics for business KPIs
resource "aws_cloudwatch_log_metric_filter" "security_analysis_requests" {
  name           = "${var.name_prefix}-security-analysis-requests"
  log_group_name = aws_cloudwatch_log_group.application_logs.name
  pattern        = "[timestamp, level, \"SECURITY_ANALYSIS\", request_type, ...]"
  
  metric_transformation {
    name      = "SecurityAnalysisRequests"
    namespace = "SecurityAgents/Business"
    value     = "1"
  }
}

# Performance metric for response times
resource "aws_cloudwatch_log_metric_filter" "analysis_response_time" {
  name           = "${var.name_prefix}-analysis-response-time"
  log_group_name = aws_cloudwatch_log_group.application_logs.name
  pattern        = "[timestamp, level, \"ANALYSIS_COMPLETE\", duration=?, ...]"
  
  metric_transformation {
    name      = "AnalysisResponseTime"
    namespace = "SecurityAgents/Performance"
    value     = "$duration"
  }
}