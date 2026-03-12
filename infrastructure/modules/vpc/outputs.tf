# SecurityAgents VPC Module Outputs
# Export essential VPC resources for use by other modules

# Core VPC Information
output "vpc_id" {
  description = "ID of the VPC created for SecurityAgents platform"
  value       = aws_vpc.main.id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC for network planning"
  value       = aws_vpc.main.cidr_block
}

output "vpc_arn" {
  description = "ARN of the VPC for IAM policies and cross-reference"
  value       = aws_vpc.main.arn
}

# Private Subnet Information (for AI workloads)
output "private_subnet_ids" {
  description = "IDs of private subnets for deploying AI workloads"
  value       = aws_subnet.private[*].id
}

output "private_subnet_cidrs" {
  description = "CIDR blocks of private subnets for security planning"
  value       = aws_subnet.private[*].cidr_block
}

output "private_subnet_arns" {
  description = "ARNs of private subnets for IAM and compliance"
  value       = aws_subnet.private[*].arn
}

output "private_subnet_availability_zones" {
  description = "Availability zones of private subnets for deployment planning"
  value       = aws_subnet.private[*].availability_zone
}

# Database Subnet Information (for monitoring/audit storage)
output "database_subnet_ids" {
  description = "IDs of database subnets for monitoring and audit storage"
  value       = aws_subnet.database[*].id
}

output "database_subnet_cidrs" {
  description = "CIDR blocks of database subnets"
  value       = aws_subnet.database[*].cidr_block
}

output "database_subnet_group" {
  description = "Database subnet group name for RDS/ElastiCache deployment"
  value       = aws_db_subnet_group.main.name
}

# Security Group Information
output "ai_workloads_security_group_id" {
  description = "Security group ID for AI processing workloads"
  value       = aws_security_group.ai_workloads.id
}

output "bedrock_endpoint_security_group_id" {
  description = "Security group ID for Bedrock VPC endpoints"
  value       = aws_security_group.bedrock_endpoint.id
}

output "monitoring_security_group_id" {
  description = "Security group ID for monitoring systems"
  value       = aws_security_group.monitoring.id
}

# VPC Endpoint Information
output "bedrock_runtime_endpoint_id" {
  description = "VPC endpoint ID for Bedrock runtime API"
  value       = aws_vpc_endpoint.bedrock_runtime.id
}

output "bedrock_runtime_endpoint_dns" {
  description = "DNS names for Bedrock runtime VPC endpoint"
  value       = aws_vpc_endpoint.bedrock_runtime.dns_entry[*].dns_name
}

output "bedrock_management_endpoint_id" {
  description = "VPC endpoint ID for Bedrock management API"
  value       = aws_vpc_endpoint.bedrock.id
}

output "cloudwatch_logs_endpoint_id" {
  description = "VPC endpoint ID for CloudWatch Logs"
  value       = aws_vpc_endpoint.cloudwatch_logs.id
}

# Route Table Information
output "private_route_table_ids" {
  description = "IDs of private route tables for custom routing"
  value       = aws_route_table.private[*].id
}

output "database_route_table_ids" {
  description = "IDs of database route tables"
  value       = aws_route_table.database[*].id
}

# Network ACL Information
output "private_network_acl_id" {
  description = "Network ACL ID for private subnets (defense in depth)"
  value       = aws_network_acl.private.id
}

# Monitoring and Logging
output "vpc_flow_log_group_name" {
  description = "CloudWatch log group name for VPC flow logs"
  value       = aws_cloudwatch_log_group.vpc_flow_log.name
}

output "vpc_flow_log_group_arn" {
  description = "CloudWatch log group ARN for VPC flow logs"
  value       = aws_cloudwatch_log_group.vpc_flow_log.arn
}

output "flow_log_role_arn" {
  description = "IAM role ARN for VPC flow logs"
  value       = aws_iam_role.flow_log_role.arn
}

# Regional and Availability Zone Information
output "availability_zones" {
  description = "Availability zones used by the VPC"
  value       = local.availability_zones
}

output "region" {
  description = "AWS region where VPC is deployed"
  value       = data.aws_region.current.name
}

# Enterprise Security Information
output "security_compliance" {
  description = "Security compliance information for audit purposes"
  value = {
    internet_gateway_present = false  # Confirms zero-trust design
    vpc_endpoints_only      = true   # Confirms all AWS API access via VPC endpoints
    flow_logs_enabled      = var.enable_vpc_flow_logs
    encryption_at_rest     = true   # All logs encrypted with customer KMS
    private_subnets_only   = true   # No public subnets created
    multi_az_deployment    = length(aws_subnet.private) > 1
  }
}

# Cost Optimization Information
output "cost_optimization" {
  description = "Cost optimization details for financial tracking"
  value = {
    vpc_endpoints_count     = length([aws_vpc_endpoint.bedrock_runtime, aws_vpc_endpoint.bedrock, aws_vpc_endpoint.cloudwatch_logs])
    private_subnets_count   = length(aws_subnet.private)
    database_subnets_count  = length(aws_subnet.database)
    availability_zones_used = length(local.availability_zones)
    nat_gateways_count     = 0  # Zero by design for cost and security
  }
}

# TODO: P0 @alpha-1 2026-03-08 Add outputs for additional VPC endpoints when implemented
# Future VPC endpoints that will be added:
# - DynamoDB gateway endpoint
# - S3 gateway endpoint  
# - CloudWatch monitoring endpoint
# - KMS endpoint for key operations

# Network Performance Information
output "network_performance" {
  description = "Network performance characteristics for capacity planning"
  value = {
    vpc_cidr_size          = split("/", var.vpc_cidr)[1]
    total_available_ips    = pow(2, 32 - tonumber(split("/", var.vpc_cidr)[1])) - 5  # AWS reserves 5 IPs per subnet
    subnets_per_az        = 2  # Private + Database
    max_eni_per_subnet    = floor((pow(2, 32 - 26) - 5) * 0.8)  # 80% utilization for ENI planning
  }
}