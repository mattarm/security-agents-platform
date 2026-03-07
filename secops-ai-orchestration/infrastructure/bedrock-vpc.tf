# AWS Bedrock VPC Deployment for SecOps AI Platform
# Implements VPC-isolated Claude deployment with customer-managed KMS encryption

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Variables
variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "secops-ai"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.100.0.0/16"
}

variable "allowed_ip_ranges" {
  description = "IP ranges allowed to access the AI platform"
  type        = list(string)
  default     = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
}

variable "kms_key_deletion_window" {
  description = "KMS key deletion window in days"
  type        = number
  default     = 7
}

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# KMS Key for encryption
resource "aws_kms_key" "secops_ai_key" {
  description             = "${var.project_name}-${var.environment} Customer-managed encryption key"
  deletion_window_in_days = var.kms_key_deletion_window
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Bedrock Service"
        Effect = "Allow"
        Principal = {
          Service = "bedrock.amazonaws.com"
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
            "kms:ViaService" = "bedrock.${data.aws_region.current.name}.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-${var.environment}-kms"
    Environment = var.environment
    Project     = var.project_name
    Purpose     = "AI_Encryption"
  }
}

resource "aws_kms_alias" "secops_ai_key_alias" {
  name          = "alias/${var.project_name}-${var.environment}-ai-key"
  target_key_id = aws_kms_key.secops_ai_key.key_id
}

# VPC Configuration
resource "aws_vpc" "secops_ai_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.project_name}-${var.environment}-vpc"
    Environment = var.environment
    Project     = var.project_name
    Purpose     = "AI_Isolation"
  }
}

# Internet Gateway (for egress control)
resource "aws_internet_gateway" "secops_ai_igw" {
  vpc_id = aws_vpc.secops_ai_vpc.id

  tags = {
    Name        = "${var.project_name}-${var.environment}-igw"
    Environment = var.environment
    Project     = var.project_name
  }
}

# Private Subnets for AI Processing
resource "aws_subnet" "private_ai" {
  count             = 2
  vpc_id            = aws_vpc.secops_ai_vpc.id
  cidr_block        = "10.100.${10 + count.index}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name        = "${var.project_name}-${var.environment}-private-ai-${count.index + 1}"
    Environment = var.environment
    Project     = var.project_name
    Tier        = "Private"
    Purpose     = "AI_Processing"
  }
}

# Public Subnets for NAT Gateways
resource "aws_subnet" "public_nat" {
  count                   = 2
  vpc_id                  = aws_vpc.secops_ai_vpc.id
  cidr_block              = "10.100.${20 + count.index}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name        = "${var.project_name}-${var.environment}-public-nat-${count.index + 1}"
    Environment = var.environment
    Project     = var.project_name
    Tier        = "Public"
    Purpose     = "NAT_Gateway"
  }
}

# Elastic IPs for NAT Gateways
resource "aws_eip" "nat_eip" {
  count  = 2
  domain = "vpc"

  tags = {
    Name        = "${var.project_name}-${var.environment}-nat-eip-${count.index + 1}"
    Environment = var.environment
    Project     = var.project_name
  }

  depends_on = [aws_internet_gateway.secops_ai_igw]
}

# NAT Gateways
resource "aws_nat_gateway" "secops_ai_nat" {
  count         = 2
  allocation_id = aws_eip.nat_eip[count.index].id
  subnet_id     = aws_subnet.public_nat[count.index].id

  tags = {
    Name        = "${var.project_name}-${var.environment}-nat-${count.index + 1}"
    Environment = var.environment
    Project     = var.project_name
  }

  depends_on = [aws_internet_gateway.secops_ai_igw]
}

# Route Tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.secops_ai_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.secops_ai_igw.id
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-public-rt"
    Environment = var.environment
    Project     = var.project_name
  }
}

resource "aws_route_table" "private_ai" {
  count  = 2
  vpc_id = aws_vpc.secops_ai_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.secops_ai_nat[count.index].id
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-private-ai-rt-${count.index + 1}"
    Environment = var.environment
    Project     = var.project_name
  }
}

# Route Table Associations
resource "aws_route_table_association" "public_nat" {
  count          = 2
  subnet_id      = aws_subnet.public_nat[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private_ai" {
  count          = 2
  subnet_id      = aws_subnet.private_ai[count.index].id
  route_table_id = aws_route_table.private_ai[count.index].id
}

# VPC Endpoints for AWS Services
resource "aws_vpc_endpoint" "bedrock" {
  vpc_id              = aws_vpc.secops_ai_vpc.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.bedrock-runtime"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private_ai[*].id
  security_group_ids  = [aws_security_group.bedrock_endpoint.id]
  private_dns_enabled = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:PrincipalVpc" = aws_vpc.secops_ai_vpc.id
          }
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-${var.environment}-bedrock-endpoint"
    Environment = var.environment
    Project     = var.project_name
  }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.secops_ai_vpc.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.private_ai[*].id

  tags = {
    Name        = "${var.project_name}-${var.environment}-s3-endpoint"
    Environment = var.environment
    Project     = var.project_name
  }
}

resource "aws_vpc_endpoint" "kms" {
  vpc_id              = aws_vpc.secops_ai_vpc.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.kms"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private_ai[*].id
  security_group_ids  = [aws_security_group.kms_endpoint.id]
  private_dns_enabled = true

  tags = {
    Name        = "${var.project_name}-${var.environment}-kms-endpoint"
    Environment = var.environment
    Project     = var.project_name
  }
}

# Security Groups
resource "aws_security_group" "ai_processing" {
  name        = "${var.project_name}-${var.environment}-ai-processing"
  description = "Security group for AI processing instances"
  vpc_id      = aws_vpc.secops_ai_vpc.id

  # Inbound rules - restrict to allowed IP ranges
  dynamic "ingress" {
    for_each = var.allowed_ip_ranges
    content {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
      description = "HTTPS from allowed networks"
    }
  }

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "AI API from VPC"
  }

  # Outbound rules - VPC endpoints only (no internet)
  egress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.bedrock_endpoint.id]
    description     = "HTTPS to Bedrock endpoint"
  }

  egress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.kms_endpoint.id]
    description     = "HTTPS to KMS endpoint"
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "HTTPS within VPC"
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-ai-processing-sg"
    Environment = var.environment
    Project     = var.project_name
  }
}

resource "aws_security_group" "bedrock_endpoint" {
  name        = "${var.project_name}-${var.environment}-bedrock-endpoint"
  description = "Security group for Bedrock VPC endpoint"
  vpc_id      = aws_vpc.secops_ai_vpc.id

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.ai_processing.id]
    description     = "HTTPS from AI processing instances"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound to AWS services"
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-bedrock-endpoint-sg"
    Environment = var.environment
    Project     = var.project_name
  }
}

resource "aws_security_group" "kms_endpoint" {
  name        = "${var.project_name}-${var.environment}-kms-endpoint"
  description = "Security group for KMS VPC endpoint"
  vpc_id      = aws_vpc.secops_ai_vpc.id

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.ai_processing.id]
    description     = "HTTPS from AI processing instances"
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-kms-endpoint-sg"
    Environment = var.environment
    Project     = var.project_name
  }
}

# IAM Role for AI Processing
resource "aws_iam_role" "ai_processing_role" {
  name = "${var.project_name}-${var.environment}-ai-processing-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-${var.environment}-ai-processing-role"
    Environment = var.environment
    Project     = var.project_name
  }
}

# IAM Policy for Bedrock Access
resource "aws_iam_policy" "bedrock_access" {
  name        = "${var.project_name}-${var.environment}-bedrock-access"
  description = "Policy for Bedrock access with encryption requirements"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ]
        Resource = [
          "arn:aws:bedrock:${data.aws_region.current.name}::foundation-model/anthropic.claude-3-haiku-20240307-v1:0",
          "arn:aws:bedrock:${data.aws_region.current.name}::foundation-model/anthropic.claude-3-sonnet-20240229-v1:0",
          "arn:aws:bedrock:${data.aws_region.current.name}::foundation-model/anthropic.claude-3-opus-20240229-v1:0"
        ]
        Condition = {
          StringEquals = {
            "aws:SourceVpc" = aws_vpc.secops_ai_vpc.id
          }
        }
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
        Resource = aws_kms_key.secops_ai_key.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams",
          "logs:DescribeLogGroups"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/secops-ai/*"
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-${var.environment}-bedrock-access-policy"
    Environment = var.environment
    Project     = var.project_name
  }
}

resource "aws_iam_role_policy_attachment" "bedrock_access" {
  role       = aws_iam_role.ai_processing_role.name
  policy_arn = aws_iam_policy.bedrock_access.arn
}

# Instance Profile
resource "aws_iam_instance_profile" "ai_processing_profile" {
  name = "${var.project_name}-${var.environment}-ai-processing-profile"
  role = aws_iam_role.ai_processing_role.name

  tags = {
    Name        = "${var.project_name}-${var.environment}-ai-processing-profile"
    Environment = var.environment
    Project     = var.project_name
  }
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "ai_processing" {
  name              = "/aws/secops-ai/${var.environment}/ai-processing"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.secops_ai_key.arn

  tags = {
    Name        = "${var.project_name}-${var.environment}-ai-processing-logs"
    Environment = var.environment
    Project     = var.project_name
  }
}

resource "aws_cloudwatch_log_group" "audit_trail" {
  name              = "/aws/secops-ai/${var.environment}/audit-trail"
  retention_in_days = 2555  # 7 years for compliance
  kms_key_id        = aws_kms_key.secops_ai_key.arn

  tags = {
    Name        = "${var.project_name}-${var.environment}-audit-trail-logs"
    Environment = var.environment
    Project     = var.project_name
  }
}

# Network ACLs for additional security
resource "aws_network_acl" "private_ai" {
  vpc_id     = aws_vpc.secops_ai_vpc.id
  subnet_ids = aws_subnet.private_ai[*].id

  # Allow inbound HTTPS from VPC
  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 443
    to_port    = 443
  }

  # Allow inbound API traffic from VPC
  ingress {
    rule_no    = 200
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 8080
    to_port    = 8080
  }

  # Allow inbound ephemeral ports
  ingress {
    rule_no    = 300
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  # Allow outbound HTTPS
  egress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  # Allow outbound ephemeral ports
  egress {
    rule_no    = 200
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-private-ai-nacl"
    Environment = var.environment
    Project     = var.project_name
  }
}

# Outputs
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.secops_ai_vpc.id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private_ai[*].id
}

output "security_group_id" {
  description = "ID of the AI processing security group"
  value       = aws_security_group.ai_processing.id
}

output "kms_key_id" {
  description = "ID of the KMS key for encryption"
  value       = aws_kms_key.secops_ai_key.key_id
  sensitive   = true
}

output "kms_key_arn" {
  description = "ARN of the KMS key for encryption"
  value       = aws_kms_key.secops_ai_key.arn
  sensitive   = true
}

output "bedrock_endpoint_id" {
  description = "ID of the Bedrock VPC endpoint"
  value       = aws_vpc_endpoint.bedrock.id
}

output "iam_role_arn" {
  description = "ARN of the IAM role for AI processing"
  value       = aws_iam_role.ai_processing_role.arn
}

output "instance_profile_name" {
  description = "Name of the instance profile"
  value       = aws_iam_instance_profile.ai_processing_profile.name
}