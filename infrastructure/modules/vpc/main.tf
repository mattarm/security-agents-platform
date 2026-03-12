# SecurityAgents VPC Module
# Zero-trust networking for AI workloads with complete internet isolation

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
  # Calculate subnet CIDRs automatically for clean IP space management
  availability_zones = data.aws_availability_zones.available.names
  
  # Private subnets for AI workloads (no internet access)
  private_subnet_cidrs = [
    for i, az in local.availability_zones : cidrsubnet(var.vpc_cidr, 8, i + 10)
  ]
  
  # Database subnets for monitoring and audit storage
  database_subnet_cidrs = [
    for i, az in local.availability_zones : cidrsubnet(var.vpc_cidr, 8, i + 20)  
  ]
  
  common_tags = merge(var.tags, {
    Module      = "SecurityAgents-VPC"
    Environment = var.environment
    Security    = "Enterprise"
    Project     = "SecurityAgents"
  })
}

# Get available AZs for the region
data "aws_availability_zones" "available" {
  state = "available"
  # Use first 3 AZs for multi-AZ deployment
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

# Main VPC - no internet gateway by design (zero-trust)
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  # Enable VPC Flow Logs for security monitoring
  tags = merge(local.common_tags, {
    Name        = "${var.name_prefix}-vpc"
    Purpose     = "AI-Security-Workloads"
    Compliance  = "SOC2-ISO27001"
  })
}

# TODO: P0 @alpha-1 2026-03-08 Enable VPC Flow Logs to CloudWatch for security monitoring
resource "aws_flow_log" "vpc_flow_log" {
  iam_role_arn    = aws_iam_role.flow_log_role.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_log.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id
  
  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-flow-logs"
  })
}

# CloudWatch Log Group for VPC Flow Logs
resource "aws_cloudwatch_log_group" "vpc_flow_log" {
  name              = "/aws/vpc/flowlogs/${var.name_prefix}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  
  tags = local.common_tags
}

# IAM role for VPC Flow Logs
resource "aws_iam_role" "flow_log_role" {
  name_prefix        = "${var.name_prefix}-flow-log-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
    }]
  })
  
  tags = local.common_tags
}

# IAM policy for VPC Flow Logs
resource "aws_iam_role_policy" "flow_log_policy" {
  name_prefix = "${var.name_prefix}-flow-log-"
  role        = aws_iam_role.flow_log_role.id
  
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
      Resource = "*"
    }]
  })
}

# Private subnets for AI workloads - NO internet access by design
resource "aws_subnet" "private" {
  count = min(length(local.availability_zones), 3) # Limit to 3 AZs for cost optimization
  
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.private_subnet_cidrs[count.index]
  availability_zone = local.availability_zones[count.index]
  
  # Explicitly disable public IP assignment (zero-trust)
  map_public_ip_on_launch = false
  
  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-private-${substr(local.availability_zones[count.index], -1, 1)}"
    Type = "Private"
    Tier = "Application"
    "kubernetes.io/role/internal-elb" = "1" # For future EKS if needed
  })
}

# Database subnets for monitoring and audit data
resource "aws_subnet" "database" {
  count = min(length(local.availability_zones), 3)
  
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.database_subnet_cidrs[count.index]
  availability_zone = local.availability_zones[count.index]
  
  map_public_ip_on_launch = false
  
  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-database-${substr(local.availability_zones[count.index], -1, 1)}"
    Type = "Database"
    Tier = "Data"
  })
}

# Route table for private subnets (no internet gateway route)
resource "aws_route_table" "private" {
  count  = length(aws_subnet.private)
  vpc_id = aws_vpc.main.id
  
  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-private-rt-${count.index + 1}"
    Type = "Private"
  })
}

# Associate private subnets with private route table
resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# Route table for database subnets
resource "aws_route_table" "database" {
  count  = length(aws_subnet.database)
  vpc_id = aws_vpc.main.id
  
  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-database-rt-${count.index + 1}"
    Type = "Database"
  })
}

# Associate database subnets with database route table
resource "aws_route_table_association" "database" {
  count          = length(aws_subnet.database)
  subnet_id      = aws_subnet.database[count.index].id
  route_table_id = aws_route_table.database[count.index].id
}

# Security Group for Bedrock VPC Endpoints
resource "aws_security_group" "bedrock_endpoint" {
  name_prefix = "${var.name_prefix}-bedrock-endpoint-"
  description = "Security group for AWS Bedrock VPC endpoints - enterprise zero-trust"
  vpc_id      = aws_vpc.main.id
  
  # Allow HTTPS traffic from AI workload security group
  ingress {
    description     = "HTTPS from AI workloads to Bedrock"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.ai_workloads.id]
  }
  
  # Allow HTTPS traffic from monitoring systems  
  ingress {
    description     = "HTTPS from monitoring systems"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.monitoring.id]
  }
  
  # No outbound rules needed - VPC endpoints handle return traffic
  
  tags = merge(local.common_tags, {
    Name    = "${var.name_prefix}-bedrock-endpoint-sg"
    Purpose = "Bedrock-VPC-Endpoint-Access"
  })
}

# Security Group for AI Workloads
resource "aws_security_group" "ai_workloads" {
  name_prefix = "${var.name_prefix}-ai-workloads-"
  description = "Security group for AI processing workloads - least privilege"
  vpc_id      = aws_vpc.main.id
  
  # Allow outbound HTTPS to Bedrock endpoints only
  egress {
    description     = "HTTPS to Bedrock VPC endpoints"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.bedrock_endpoint.id]
  }
  
  # Allow outbound to monitoring endpoints
  egress {
    description     = "HTTPS to monitoring endpoints"  
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.monitoring.id]
  }
  
  # TODO: P0 @alpha-1 2026-03-08 Add ingress rules for MCP server communications
  
  tags = merge(local.common_tags, {
    Name    = "${var.name_prefix}-ai-workloads-sg"
    Purpose = "AI-Processing-Security"
  })
}

# Security Group for Monitoring Systems
resource "aws_security_group" "monitoring" {
  name_prefix = "${var.name_prefix}-monitoring-"
  description = "Security group for CloudWatch and audit monitoring"
  vpc_id      = aws_vpc.main.id
  
  # Allow inbound HTTPS from AI workloads
  ingress {
    description     = "HTTPS from AI workloads"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.ai_workloads.id]
  }
  
  # Allow outbound HTTPS for CloudWatch API calls
  egress {
    description = "HTTPS to CloudWatch endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Required for CloudWatch API - TODO: Replace with VPC endpoint
  }
  
  tags = merge(local.common_tags, {
    Name    = "${var.name_prefix}-monitoring-sg"
    Purpose = "Security-Monitoring"
  })
}

# VPC Endpoint for AWS Bedrock (primary AI service)
resource "aws_vpc_endpoint" "bedrock_runtime" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.bedrock-runtime"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.bedrock_endpoint.id]
  
  # Enable private DNS for clean endpoint access
  private_dns_enabled = true
  
  # Required for enterprise compliance
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = "*"
      Action = [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ]
      Resource = "*"
      Condition = {
        StringEquals = {
          "aws:PrincipalVpc" = aws_vpc.main.id
        }
      }
    }]
  })
  
  tags = merge(local.common_tags, {
    Name    = "${var.name_prefix}-bedrock-runtime-endpoint"
    Service = "AWS-Bedrock"
  })
}

# VPC Endpoint for Bedrock Model Management
resource "aws_vpc_endpoint" "bedrock" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.bedrock"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.bedrock_endpoint.id]
  private_dns_enabled = true
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = "*"
      Action = [
        "bedrock:GetFoundationModel",
        "bedrock:ListFoundationModels",
        "bedrock:GetModelInvocationLoggingConfiguration"
      ]
      Resource = "*"
      Condition = {
        StringEquals = {
          "aws:PrincipalVpc" = aws_vpc.main.id
        }
      }
    }]
  })
  
  tags = merge(local.common_tags, {
    Name    = "${var.name_prefix}-bedrock-endpoint"
    Service = "AWS-Bedrock-Management"
  })
}

# TODO: P0 @alpha-1 2026-03-08 Add VPC endpoints for CloudWatch, DynamoDB, S3
# VPC Endpoint for CloudWatch Logs
resource "aws_vpc_endpoint" "cloudwatch_logs" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.monitoring.id]
  private_dns_enabled = true
  
  tags = merge(local.common_tags, {
    Name    = "${var.name_prefix}-cloudwatch-logs-endpoint"
    Service = "CloudWatch-Logs"
  })
}

# Get current AWS region
data "aws_region" "current" {}

# Database subnet group for RDS/ElastiCache deployment
resource "aws_db_subnet_group" "main" {
  name       = "${var.name_prefix}-database-subnet-group"
  subnet_ids = aws_subnet.database[*].id
  
  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-database-subnet-group"
    Type = "Database"
  })
}

# Network ACLs for defense in depth
resource "aws_network_acl" "private" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.private[*].id
  
  # Allow inbound HTTPS from within VPC
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 443
    to_port    = 443
  }
  
  # Allow ephemeral ports for return traffic
  ingress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 1024
    to_port    = 65535
  }
  
  # Allow outbound HTTPS
  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 443
    to_port    = 443
  }
  
  # Allow outbound ephemeral ports
  egress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 1024
    to_port    = 65535
  }
  
  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-private-nacl"
    Type = "Private-Network-ACL"
  })
}