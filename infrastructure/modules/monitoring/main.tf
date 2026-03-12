# SecurityAgents Monitoring Module
# Comprehensive CloudWatch monitoring, alerting, and security dashboards

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.0"
}

locals {
  common_tags = merge(var.tags, {
    Module      = "SecurityAgents-Monitoring"
    Environment = var.environment
    Security    = "Enterprise"
    Project     = "SecurityAgents"
  })
}

# Get current region and account information
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# SNS Topic for Critical Security Alerts
resource "aws_sns_topic" "security_alerts" {
  name              = "${var.name_prefix}-security-alerts"
  kms_master_key_id = var.kms_key_arn
  
  tags = merge(local.common_tags, {
    Name        = "${var.name_prefix}-security-alerts"
    Purpose     = "Critical-Security-Alerting"
    Compliance  = "SOC2-Required"
  })
}

# SNS Topic for Operational Alerts
resource "aws_sns_topic" "operational_alerts" {
  name              = "${var.name_prefix}-operational-alerts"
  kms_master_key_id = var.kms_key_arn
  
  tags = merge(local.common_tags, {
    Name        = "${var.name_prefix}-operational-alerts"
    Purpose     = "Operational-Monitoring"
  })
}

# SNS Topic for Cost Alerts
resource "aws_sns_topic" "cost_alerts" {
  name              = "${var.name_prefix}-cost-alerts"
  kms_master_key_id = var.kms_key_arn
  
  tags = merge(local.common_tags, {
    Name        = "${var.name_prefix}-cost-alerts"
    Purpose     = "Cost-Management"
  })
}

# SNS Topic Subscriptions (email endpoints)
resource "aws_sns_topic_subscription" "security_alerts_email" {
  count     = length(var.security_alert_emails)
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.security_alert_emails[count.index]
  
  # TODO: P0 @alpha-1 2026-03-08 Configure SMS for critical alerts
}

resource "aws_sns_topic_subscription" "operational_alerts_email" {
  count     = length(var.operational_alert_emails)
  topic_arn = aws_sns_topic.operational_alerts.arn
  protocol  = "email"
  endpoint  = var.operational_alert_emails[count.index]
}

# CloudWatch Log Group for Monitoring Logs
resource "aws_cloudwatch_log_group" "monitoring_logs" {
  name              = "/aws/security-agents/${var.name_prefix}/monitoring"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  
  tags = merge(local.common_tags, {
    Name    = "${var.name_prefix}-monitoring-logs"
    Purpose = "Monitoring-System-Logs"
  })
}

# Security Events Metric Filter
resource "aws_cloudwatch_log_metric_filter" "security_events" {
  name           = "${var.name_prefix}-security-events"
  log_group_name = var.vpc_flow_log_group_name
  pattern        = "[timestamp, account, eni, source, destination, srcport, destport, protocol, packets, bytes, windowstart, windowend, action=\"REJECT\", flowlogstatus]"
  
  metric_transformation {
    name      = "SecurityEvents"
    namespace = "SecurityAgents/Security"
    value     = "1"
  }
}

# Failed Authentication Attempts
resource "aws_cloudwatch_log_metric_filter" "failed_auth_attempts" {
  name           = "${var.name_prefix}-failed-auth"
  log_group_name = var.application_log_group_name
  pattern        = "[timestamp, level=\"ERROR\", \"AUTH_FAILED\", ...]"
  
  metric_transformation {
    name      = "FailedAuthAttempts"
    namespace = "SecurityAgents/Security"
    value     = "1"
  }
}

# Unusual Activity Detection
resource "aws_cloudwatch_log_metric_filter" "unusual_activity" {
  name           = "${var.name_prefix}-unusual-activity"
  log_group_name = var.bedrock_log_group_name
  pattern        = "[timestamp, request_id, \"UNUSUAL_PATTERN\", ...]"
  
  metric_transformation {
    name      = "UnusualActivity"
    namespace = "SecurityAgents/Security"
    value     = "1"
  }
}

# High-Severity Security Alert
resource "aws_cloudwatch_metric_alarm" "security_events_high" {
  alarm_name          = "${var.name_prefix}-security-events-critical"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "SecurityEvents"
  namespace           = "SecurityAgents/Security"
  period              = 300  # 5 minutes
  statistic           = "Sum"
  threshold           = var.security_events_threshold
  alarm_description   = "High number of security events detected in VPC flow logs"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  ok_actions         = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"
  
  tags = merge(local.common_tags, {
    Name     = "${var.name_prefix}-security-events-alarm"
    Severity = "Critical"
  })
}

# Failed Authentication Alarm
resource "aws_cloudwatch_metric_alarm" "failed_auth_alarm" {
  alarm_name          = "${var.name_prefix}-failed-auth-attempts"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FailedAuthAttempts"
  namespace           = "SecurityAgents/Security"
  period              = 300
  statistic           = "Sum"
  threshold           = var.failed_auth_threshold
  alarm_description   = "High number of failed authentication attempts"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"
  
  tags = merge(local.common_tags, {
    Name     = "${var.name_prefix}-failed-auth-alarm"
    Severity = "High"
  })
}

# Unusual Activity Alarm
resource "aws_cloudwatch_metric_alarm" "unusual_activity_alarm" {
  alarm_name          = "${var.name_prefix}-unusual-activity"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "UnusualActivity"
  namespace           = "SecurityAgents/Security"
  period              = 300
  statistic           = "Sum"
  threshold           = var.unusual_activity_threshold
  alarm_description   = "Unusual activity patterns detected in Bedrock usage"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"
  
  tags = merge(local.common_tags, {
    Name     = "${var.name_prefix}-unusual-activity-alarm"
    Severity = "Medium"
  })
}

# Cost Monitoring - Bedrock Usage
resource "aws_budgets_budget" "bedrock_monthly" {
  name         = "${var.name_prefix}-bedrock-monthly-budget"
  budget_type  = "COST"
  limit_amount = var.monthly_bedrock_budget
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  time_period_start = "2024-01-01_00:00"
  
  cost_filters = {
    Service = ["Amazon Bedrock"]
  }
  
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                 = 80  # 80% of budget
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_email_addresses = var.cost_alert_emails
  }
  
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                 = 100  # 100% of budget
    threshold_type            = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = var.cost_alert_emails
  }
  
  depends_on = [aws_sns_topic.cost_alerts]
}

# Cost Monitoring - Overall Platform
resource "aws_budgets_budget" "platform_monthly" {
  name         = "${var.name_prefix}-platform-monthly-budget"
  budget_type  = "COST"
  limit_amount = var.monthly_platform_budget
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  time_period_start = "2024-01-01_00:00"
  
  cost_filters = {
    TagKey = ["Project"]
    TagValue = ["SecurityAgents"]
  }
  
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                 = 75  # 75% of budget
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_email_addresses = var.cost_alert_emails
  }
  
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                 = 90  # 90% of budget
    threshold_type            = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = var.cost_alert_emails
  }
}

# SecurityAgents Executive Dashboard
resource "aws_cloudwatch_dashboard" "executive" {
  dashboard_name = "${var.name_prefix}-executive-dashboard"
  
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
            ["SecurityAgents/Business", "SecurityAnalysisRequests", { "stat": "Sum" }],
            ["SecurityAgents/Performance", "AnalysisResponseTime", { "stat": "Average" }]
          ]
          period = 3600  # 1 hour
          stat   = "Average"
          region = data.aws_region.current.name
          title  = "Business Metrics - Security Analysis Volume & Performance"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            ["SecurityAgents/Security", "SecurityEvents", { "stat": "Sum" }],
            [".", "FailedAuthAttempts", { "stat": "Sum" }],
            [".", "UnusualActivity", { "stat": "Sum" }]
          ]
          period = 3600
          stat   = "Sum"
          region = data.aws_region.current.name
          title  = "Security Events & Threat Detection"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 24
        height = 6
        
        properties = {
          metrics = [
            ["SecurityAgents/Bedrock", "BedrockErrors", { "stat": "Sum" }],
            [".", "BedrockThrottles", { "stat": "Sum" }],
            [".", "BedrockHighLatency", { "stat": "Sum" }]
          ]
          period = 3600
          stat   = "Sum"
          region = data.aws_region.current.name
          title  = "AI Platform Health & Performance"
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name    = "${var.name_prefix}-executive-dashboard"
    Purpose = "Executive-Overview"
  })
}

# SecurityAgents Operational Dashboard
resource "aws_cloudwatch_dashboard" "operational" {
  dashboard_name = "${var.name_prefix}-operational-dashboard"
  
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "log"
        x      = 0
        y      = 0
        width  = 12
        height = 8
        
        properties = {
          query = "SOURCE '${var.bedrock_log_group_name}'\n| fields @timestamp, @message\n| filter @message like /ERROR/\n| sort @timestamp desc\n| limit 50"
          region = data.aws_region.current.name
          title  = "Recent Bedrock Errors"
        }
      },
      {
        type   = "log"
        x      = 12
        y      = 0
        width  = 12
        height = 8
        
        properties = {
          query = "SOURCE '${var.vpc_flow_log_group_name}'\n| fields @timestamp, srcaddr, dstaddr, srcport, dstport, action\n| filter action = \"REJECT\"\n| sort @timestamp desc\n| limit 50"
          region = data.aws_region.current.name
          title  = "Recent Network Security Events"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 8
        width  = 24
        height = 6
        
        properties = {
          metrics = [
            ["AWS/Logs", "IncomingLogEvents", "LogGroupName", var.bedrock_log_group_name],
            [".", ".", "LogGroupName", var.application_log_group_name],
            [".", ".", "LogGroupName", var.vpc_flow_log_group_name]
          ]
          period = 300
          stat   = "Sum"
          region = data.aws_region.current.name
          title  = "Log Volume by Source"
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name    = "${var.name_prefix}-operational-dashboard"
    Purpose = "Operational-Monitoring"
  })
}

# Health Check for VPC Endpoints
resource "aws_cloudwatch_metric_alarm" "vpc_endpoint_health" {
  count               = length(var.vpc_endpoint_ids)
  alarm_name          = "${var.name_prefix}-vpc-endpoint-${count.index}-health"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 3
  metric_name         = "PacketDropCount"
  namespace           = "AWS/VPC"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "VPC endpoint health check for SecurityAgents platform"
  alarm_actions       = [aws_sns_topic.operational_alerts.arn]
  treat_missing_data  = "breaching"  # Treat missing data as unhealthy
  
  dimensions = {
    VpcId     = var.vpc_id
    VpcEndpointId = var.vpc_endpoint_ids[count.index]
  }
  
  tags = merge(local.common_tags, {
    Name     = "${var.name_prefix}-vpc-endpoint-${count.index}-health"
    Purpose  = "VPC-Endpoint-Health"
  })
}

# TODO: P0 @alpha-1 2026-03-08 Add custom Lambda for advanced threat detection
# Lambda function for custom security event processing
resource "aws_lambda_function" "security_event_processor" {
  count         = var.enable_advanced_security_processing ? 1 : 0
  filename      = "security_processor.zip"
  function_name = "${var.name_prefix}-security-processor"
  role          = aws_iam_role.lambda_security_processor[0].arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 60
  
  # Placeholder code - TODO: Implement actual security processing
  source_code_hash = data.archive_file.security_processor_code[0].output_base64sha256
  
  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.security_alerts.arn
      LOG_LEVEL    = var.enable_debug_logging ? "DEBUG" : "INFO"
    }
  }
  
  tags = merge(local.common_tags, {
    Name    = "${var.name_prefix}-security-processor"
    Purpose = "Advanced-Security-Processing"
  })
}

# Archive file for Lambda function
data "archive_file" "security_processor_code" {
  count       = var.enable_advanced_security_processing ? 1 : 0
  type        = "zip"
  output_path = "security_processor.zip"
  
  source {
    content = <<EOF
import json
import boto3
import os

def handler(event, context):
    """
    Advanced security event processing for SecurityAgents platform
    TODO: Implement actual threat detection and response logic
    """
    print(f"Processing security event: {json.dumps(event)}")
    
    # Placeholder - implement actual security processing
    sns = boto3.client('sns')
    
    return {
        'statusCode': 200,
        'body': json.dumps('Security event processed successfully')
    }
EOF
    filename = "index.py"
  }
}

# IAM Role for Lambda Security Processor
resource "aws_iam_role" "lambda_security_processor" {
  count       = var.enable_advanced_security_processing ? 1 : 0
  name_prefix = "${var.name_prefix}-lambda-security-"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
  
  tags = local.common_tags
}

# Lambda basic execution policy attachment
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  count      = var.enable_advanced_security_processing ? 1 : 0
  role       = aws_iam_role.lambda_security_processor[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Lambda CloudWatch Logs subscription filter
resource "aws_cloudwatch_log_subscription_filter" "security_events_lambda" {
  count           = var.enable_advanced_security_processing ? 1 : 0
  name            = "${var.name_prefix}-security-events-filter"
  log_group_name  = var.vpc_flow_log_group_name
  filter_pattern  = "[timestamp, account, eni, source, destination, srcport, destport, protocol, packets, bytes, windowstart, windowend, action=\"REJECT\", flowlogstatus]"
  destination_arn = aws_lambda_function.security_event_processor[0].arn
}

# TODO: P0 @alpha-1 2026-03-08 Add GuardDuty and Security Hub integration