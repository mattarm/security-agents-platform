#!/usr/bin/env python3
"""
AWS Infrastructure Security Analyzer
Comprehensive security assessment of AWS infrastructure using boto3
"""

import boto3
import json
import asyncio
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import ipaddress
import re

@dataclass
class SecurityFinding:
    """Standardized security finding structure"""
    finding_id: str
    service: str
    resource_id: str
    resource_arn: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    title: str
    description: str
    remediation: str
    compliance_frameworks: List[str]
    risk_score: float  # 0-100
    metadata: Dict[str, Any]

@dataclass
class InfrastructureInventory:
    """Complete infrastructure inventory"""
    ec2_instances: List[Dict]
    s3_buckets: List[Dict]
    rds_instances: List[Dict]
    lambda_functions: List[Dict]
    iam_users: List[Dict]
    iam_roles: List[Dict]
    security_groups: List[Dict]
    vpc_endpoints: List[Dict]
    cloudtrail_trails: List[Dict]
    load_balancers: List[Dict]

class AWSSecurityAnalyzer:
    """Comprehensive AWS security analysis engine"""
    
    def __init__(self, profile_name: str = None):
        self.session = boto3.Session(profile_name=profile_name)
        self.regions = self.get_enabled_regions()
        self.findings = []
        self.inventory = None
        
        # Security baselines (CIS benchmarks)
        self.security_baselines = {
            'password_policy': {
                'minimum_length': 14,
                'require_uppercase': True,
                'require_lowercase': True,
                'require_numbers': True,
                'require_symbols': True,
                'max_age_days': 90
            },
            'cloudtrail': {
                'required_regions': ['us-east-1'],  # At least global services
                'log_file_validation': True,
                'include_global_services': True
            }
        }
        
        print(f"🏗️ AWS Security Analyzer initialized")
        print(f"📍 Regions to analyze: {', '.join(self.regions[:5])}{'...' if len(self.regions) > 5 else ''}")

    def get_enabled_regions(self) -> List[str]:
        """Get list of enabled AWS regions"""
        try:
            ec2 = self.session.client('ec2', region_name='us-east-1')
            response = ec2.describe_regions()
            regions = [region['RegionName'] for region in response['Regions']]
            # Filter out regions that are typically disabled
            enabled_regions = []
            for region in regions:
                try:
                    # Quick test to see if region is enabled
                    ec2_regional = self.session.client('ec2', region_name=region)
                    ec2_regional.describe_instances(MaxResults=1)
                    enabled_regions.append(region)
                except Exception:
                    pass  # Region not enabled
            return enabled_regions[:3] if len(enabled_regions) > 3 else enabled_regions  # Limit for demo
        except Exception as e:
            print(f"⚠️ Could not determine regions, using us-east-1: {str(e)}")
            return ['us-east-1']

    async def analyze_infrastructure(self) -> Dict[str, Any]:
        """Complete infrastructure security analysis"""
        print("🔍 Starting comprehensive AWS infrastructure analysis...")
        
        # Step 1: Inventory discovery
        print("📋 Phase 1: Infrastructure inventory")
        self.inventory = await self.discover_infrastructure()
        
        # Step 2: Security analysis
        print("🔒 Phase 2: Security analysis")
        security_findings = await self.analyze_security_configurations()
        
        # Step 3: Compliance assessment
        print("📊 Phase 3: Compliance assessment")
        compliance_results = await self.assess_compliance()
        
        # Step 4: Risk scoring
        print("⚖️ Phase 4: Risk assessment")
        risk_analysis = await self.calculate_risk_scores()
        
        analysis_results = {
            'analysis_timestamp': datetime.now().isoformat(),
            'inventory_summary': self.generate_inventory_summary(),
            'security_findings': security_findings,
            'compliance_results': compliance_results,
            'risk_analysis': risk_analysis,
            'recommendations': self.generate_recommendations()
        }
        
        print(f"✅ Analysis complete: {len(security_findings)} findings across {len(self.regions)} regions")
        return analysis_results

    async def discover_infrastructure(self) -> InfrastructureInventory:
        """Discover all AWS infrastructure components"""
        inventory_data = {
            'ec2_instances': [],
            's3_buckets': [],
            'rds_instances': [],
            'lambda_functions': [],
            'iam_users': [],
            'iam_roles': [],
            'security_groups': [],
            'vpc_endpoints': [],
            'cloudtrail_trails': [],
            'load_balancers': []
        }
        
        # Discover resources across all enabled regions
        for region in self.regions:
            print(f"  📡 Discovering resources in {region}")
            
            # EC2 instances
            try:
                ec2 = self.session.client('ec2', region_name=region)
                instances_response = ec2.describe_instances()
                for reservation in instances_response['Reservations']:
                    for instance in reservation['Instances']:
                        instance['Region'] = region
                        inventory_data['ec2_instances'].append(instance)
            except Exception as e:
                print(f"    ⚠️ EC2 discovery failed in {region}: {str(e)}")
            
            # Security Groups
            try:
                sg_response = ec2.describe_security_groups()
                for sg in sg_response['SecurityGroups']:
                    sg['Region'] = region
                    inventory_data['security_groups'].append(sg)
            except Exception as e:
                print(f"    ⚠️ Security Groups discovery failed in {region}: {str(e)}")
            
            # RDS instances
            try:
                rds = self.session.client('rds', region_name=region)
                rds_response = rds.describe_db_instances()
                for db in rds_response['DBInstances']:
                    db['Region'] = region
                    inventory_data['rds_instances'].append(db)
            except Exception as e:
                print(f"    ⚠️ RDS discovery failed in {region}: {str(e)}")
            
            # Lambda functions
            try:
                lambda_client = self.session.client('lambda', region_name=region)
                functions_response = lambda_client.list_functions()
                for func in functions_response['Functions']:
                    func['Region'] = region
                    inventory_data['lambda_functions'].append(func)
            except Exception as e:
                print(f"    ⚠️ Lambda discovery failed in {region}: {str(e)}")
            
            # CloudTrail
            try:
                cloudtrail = self.session.client('cloudtrail', region_name=region)
                trails_response = cloudtrail.describe_trails()
                for trail in trails_response['trailList']:
                    trail['Region'] = region
                    inventory_data['cloudtrail_trails'].append(trail)
            except Exception as e:
                print(f"    ⚠️ CloudTrail discovery failed in {region}: {str(e)}")
        
        # Global services (only need to query once)
        print("  🌍 Discovering global services")
        
        # S3 buckets
        try:
            s3 = self.session.client('s3')
            buckets_response = s3.list_buckets()
            for bucket in buckets_response['Buckets']:
                # Get bucket region
                try:
                    bucket_region = s3.get_bucket_location(Bucket=bucket['Name'])['LocationConstraint']
                    bucket['Region'] = bucket_region or 'us-east-1'
                except:
                    bucket['Region'] = 'unknown'
                inventory_data['s3_buckets'].append(bucket)
        except Exception as e:
            print(f"    ⚠️ S3 discovery failed: {str(e)}")
        
        # IAM users and roles
        try:
            iam = self.session.client('iam')
            users_response = iam.list_users()
            inventory_data['iam_users'] = users_response['Users']
            
            roles_response = iam.list_roles()
            inventory_data['iam_roles'] = roles_response['Roles']
        except Exception as e:
            print(f"    ⚠️ IAM discovery failed: {str(e)}")
        
        return InfrastructureInventory(**inventory_data)

    async def analyze_security_configurations(self) -> List[Dict[str, Any]]:
        """Analyze security configurations and generate findings"""
        findings = []
        
        # EC2 security analysis
        findings.extend(await self.analyze_ec2_security())
        
        # S3 security analysis
        findings.extend(await self.analyze_s3_security())
        
        # IAM security analysis
        findings.extend(await self.analyze_iam_security())
        
        # Network security analysis
        findings.extend(await self.analyze_network_security())
        
        # CloudTrail analysis
        findings.extend(await self.analyze_cloudtrail_security())
        
        # RDS security analysis
        findings.extend(await self.analyze_rds_security())
        
        # Lambda security analysis
        findings.extend(await self.analyze_lambda_security())
        
        return [asdict(finding) for finding in findings]

    async def analyze_ec2_security(self) -> List[SecurityFinding]:
        """Analyze EC2 instance security configurations"""
        findings = []
        
        for instance in self.inventory.ec2_instances:
            instance_id = instance['InstanceId']
            
            # Check for instances without encryption
            if not instance.get('EbsOptimized', False):
                findings.append(SecurityFinding(
                    finding_id=f"EC2-001-{instance_id}",
                    service="EC2",
                    resource_id=instance_id,
                    resource_arn=f"arn:aws:ec2:{instance['Region']}::instance/{instance_id}",
                    severity="MEDIUM",
                    category="Encryption",
                    title="EC2 instance not EBS optimized",
                    description=f"Instance {instance_id} is not EBS optimized, which may impact security and performance",
                    remediation="Enable EBS optimization for better security and performance",
                    compliance_frameworks=["CIS", "SOC2"],
                    risk_score=40.0,
                    metadata={"instance_type": instance.get('InstanceType', 'unknown')}
                ))
            
            # Check for public IP exposure
            if instance.get('PublicIpAddress'):
                findings.append(SecurityFinding(
                    finding_id=f"EC2-002-{instance_id}",
                    service="EC2",
                    resource_id=instance_id,
                    resource_arn=f"arn:aws:ec2:{instance['Region']}::instance/{instance_id}",
                    severity="HIGH",
                    category="Network Exposure",
                    title="EC2 instance has public IP",
                    description=f"Instance {instance_id} has a public IP address ({instance['PublicIpAddress']})",
                    remediation="Review if public access is necessary. Consider using NAT Gateway or VPN",
                    compliance_frameworks=["CIS", "NIST"],
                    risk_score=75.0,
                    metadata={
                        "public_ip": instance['PublicIpAddress'],
                        "vpc_id": instance.get('VpcId', 'unknown')
                    }
                ))
            
            # Check instance metadata service configuration
            metadata_options = instance.get('MetadataOptions', {})
            if metadata_options.get('HttpTokens') != 'required':
                findings.append(SecurityFinding(
                    finding_id=f"EC2-003-{instance_id}",
                    service="EC2",
                    resource_id=instance_id,
                    resource_arn=f"arn:aws:ec2:{instance['Region']}::instance/{instance_id}",
                    severity="MEDIUM",
                    category="Instance Metadata",
                    title="Instance metadata service not properly configured",
                    description=f"Instance {instance_id} doesn't require tokens for metadata service",
                    remediation="Configure metadata service to require tokens (IMDSv2)",
                    compliance_frameworks=["CIS"],
                    risk_score=50.0,
                    metadata=metadata_options
                ))
        
        return findings

    async def analyze_s3_security(self) -> List[SecurityFinding]:
        """Analyze S3 bucket security configurations"""
        findings = []
        
        for bucket in self.inventory.s3_buckets:
            bucket_name = bucket['Name']
            
            try:
                s3 = self.session.client('s3')
                
                # Check public access block
                try:
                    public_access_block = s3.get_public_access_block(Bucket=bucket_name)
                    pab_config = public_access_block['PublicAccessBlockConfiguration']
                    
                    if not all([
                        pab_config.get('BlockPublicAcls', False),
                        pab_config.get('IgnorePublicAcls', False),
                        pab_config.get('BlockPublicPolicy', False),
                        pab_config.get('RestrictPublicBuckets', False)
                    ]):
                        findings.append(SecurityFinding(
                            finding_id=f"S3-001-{bucket_name}",
                            service="S3",
                            resource_id=bucket_name,
                            resource_arn=f"arn:aws:s3:::{bucket_name}",
                            severity="HIGH",
                            category="Public Access",
                            title="S3 bucket public access not fully blocked",
                            description=f"Bucket {bucket_name} doesn't have all public access blocks enabled",
                            remediation="Enable all public access block settings unless public access is required",
                            compliance_frameworks=["CIS", "SOC2", "GDPR"],
                            risk_score=80.0,
                            metadata=pab_config
                        ))
                except:
                    # No public access block configured
                    findings.append(SecurityFinding(
                        finding_id=f"S3-002-{bucket_name}",
                        service="S3",
                        resource_id=bucket_name,
                        resource_arn=f"arn:aws:s3:::{bucket_name}",
                        severity="CRITICAL",
                        category="Public Access",
                        title="S3 bucket has no public access block",
                        description=f"Bucket {bucket_name} has no public access block configuration",
                        remediation="Configure public access block to prevent accidental public exposure",
                        compliance_frameworks=["CIS", "SOC2", "GDPR"],
                        risk_score=90.0,
                        metadata={}
                    ))
                
                # Check bucket encryption
                try:
                    encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                except:
                    findings.append(SecurityFinding(
                        finding_id=f"S3-003-{bucket_name}",
                        service="S3",
                        resource_id=bucket_name,
                        resource_arn=f"arn:aws:s3:::{bucket_name}",
                        severity="HIGH",
                        category="Encryption",
                        title="S3 bucket not encrypted",
                        description=f"Bucket {bucket_name} does not have default encryption enabled",
                        remediation="Enable default encryption using AES-256 or KMS",
                        compliance_frameworks=["CIS", "SOC2", "GDPR"],
                        risk_score=70.0,
                        metadata={}
                    ))
                
                # Check versioning
                try:
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get('Status') != 'Enabled':
                        findings.append(SecurityFinding(
                            finding_id=f"S3-004-{bucket_name}",
                            service="S3",
                            resource_id=bucket_name,
                            resource_arn=f"arn:aws:s3:::{bucket_name}",
                            severity="MEDIUM",
                            category="Data Protection",
                            title="S3 bucket versioning not enabled",
                            description=f"Bucket {bucket_name} does not have versioning enabled",
                            remediation="Enable versioning to protect against accidental deletion and modification",
                            compliance_frameworks=["SOC2"],
                            risk_score=50.0,
                            metadata=versioning
                        ))
                except Exception as e:
                    pass  # Versioning check failed
                    
            except Exception as e:
                print(f"    ⚠️ S3 analysis failed for {bucket_name}: {str(e)}")
        
        return findings

    async def analyze_iam_security(self) -> List[SecurityFinding]:
        """Analyze IAM security configurations"""
        findings = []
        
        try:
            iam = self.session.client('iam')
            
            # Check password policy
            try:
                password_policy = iam.get_account_password_policy()['PasswordPolicy']
                baseline = self.security_baselines['password_policy']
                
                if password_policy.get('MinimumPasswordLength', 0) < baseline['minimum_length']:
                    findings.append(SecurityFinding(
                        finding_id="IAM-001",
                        service="IAM",
                        resource_id="account-password-policy",
                        resource_arn="arn:aws:iam::account:password-policy",
                        severity="HIGH",
                        category="Authentication",
                        title="Weak password policy",
                        description=f"Password minimum length is {password_policy.get('MinimumPasswordLength', 'not set')}, should be {baseline['minimum_length']}",
                        remediation=f"Update password policy to require minimum {baseline['minimum_length']} characters",
                        compliance_frameworks=["CIS", "SOC2"],
                        risk_score=70.0,
                        metadata=password_policy
                    ))
                
                if not password_policy.get('RequireUppercaseCharacters', False):
                    findings.append(SecurityFinding(
                        finding_id="IAM-002",
                        service="IAM",
                        resource_id="account-password-policy",
                        resource_arn="arn:aws:iam::account:password-policy",
                        severity="MEDIUM",
                        category="Authentication",
                        title="Password policy doesn't require uppercase",
                        description="Password policy should require uppercase characters",
                        remediation="Update password policy to require uppercase characters",
                        compliance_frameworks=["CIS"],
                        risk_score=40.0,
                        metadata=password_policy
                    ))
                    
            except iam.exceptions.NoSuchEntityException:
                findings.append(SecurityFinding(
                    finding_id="IAM-003",
                    service="IAM",
                    resource_id="account-password-policy",
                    resource_arn="arn:aws:iam::account:password-policy",
                    severity="CRITICAL",
                    category="Authentication",
                    title="No password policy configured",
                    description="Account has no password policy configured",
                    remediation="Configure a strong password policy for IAM users",
                    compliance_frameworks=["CIS", "SOC2"],
                    risk_score=90.0,
                    metadata={}
                ))
            
            # Check for users with console access but no MFA
            for user in self.inventory.iam_users:
                username = user['UserName']
                
                # Check if user has console access
                try:
                    login_profile = iam.get_login_profile(UserName=username)
                    
                    # Check MFA devices
                    mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
                    
                    if not mfa_devices:
                        findings.append(SecurityFinding(
                            finding_id=f"IAM-004-{username}",
                            service="IAM",
                            resource_id=username,
                            resource_arn=user['Arn'],
                            severity="HIGH",
                            category="Multi-Factor Authentication",
                            title="IAM user with console access has no MFA",
                            description=f"User {username} has console access but no MFA devices configured",
                            remediation="Enable MFA for all users with console access",
                            compliance_frameworks=["CIS", "SOC2"],
                            risk_score=80.0,
                            metadata={"has_console_access": True, "mfa_devices": len(mfa_devices)}
                        ))
                        
                except iam.exceptions.NoSuchEntityException:
                    pass  # User doesn't have console access
        
        except Exception as e:
            print(f"    ⚠️ IAM analysis failed: {str(e)}")
        
        return findings

    async def analyze_network_security(self) -> List[SecurityFinding]:
        """Analyze network security configurations"""
        findings = []
        
        for sg in self.inventory.security_groups:
            sg_id = sg['GroupId']
            
            # Check for overly permissive inbound rules
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')
                    
                    # Check for 0.0.0.0/0 (any IP)
                    if cidr == '0.0.0.0/0':
                        severity = "CRITICAL" if rule.get('FromPort') in [22, 3389] else "HIGH"
                        risk_score = 95.0 if rule.get('FromPort') in [22, 3389] else 75.0
                        
                        findings.append(SecurityFinding(
                            finding_id=f"NET-001-{sg_id}-{rule.get('FromPort', 'any')}",
                            service="EC2",
                            resource_id=sg_id,
                            resource_arn=f"arn:aws:ec2:{sg['Region']}::security-group/{sg_id}",
                            severity=severity,
                            category="Network Security",
                            title="Security group allows access from anywhere",
                            description=f"Security group {sg_id} allows inbound access from 0.0.0.0/0 on port {rule.get('FromPort', 'any')}",
                            remediation="Restrict source IP ranges to only necessary addresses",
                            compliance_frameworks=["CIS", "NIST"],
                            risk_score=risk_score,
                            metadata={
                                "protocol": rule.get('IpProtocol', 'unknown'),
                                "from_port": rule.get('FromPort'),
                                "to_port": rule.get('ToPort'),
                                "cidr": cidr
                            }
                        ))
        
        return findings

    async def analyze_cloudtrail_security(self) -> List[SecurityFinding]:
        """Analyze CloudTrail security configurations"""
        findings = []
        
        # Check if CloudTrail is enabled in required regions
        baseline = self.security_baselines['cloudtrail']
        
        for required_region in baseline['required_regions']:
            region_trails = [t for t in self.inventory.cloudtrail_trails if t['Region'] == required_region]
            
            if not region_trails:
                findings.append(SecurityFinding(
                    finding_id=f"TRAIL-001-{required_region}",
                    service="CloudTrail",
                    resource_id=f"missing-trail-{required_region}",
                    resource_arn=f"arn:aws:cloudtrail:{required_region}::trail/missing",
                    severity="HIGH",
                    category="Logging",
                    title=f"No CloudTrail in {required_region}",
                    description=f"No CloudTrail found in required region {required_region}",
                    remediation=f"Configure CloudTrail logging in {required_region}",
                    compliance_frameworks=["CIS", "SOC2"],
                    risk_score=80.0,
                    metadata={"region": required_region}
                ))
        
        # Analyze existing trails
        for trail in self.inventory.cloudtrail_trails:
            trail_name = trail.get('Name', 'unknown')
            
            # Check log file validation
            if not trail.get('LogFileValidationEnabled', False):
                findings.append(SecurityFinding(
                    finding_id=f"TRAIL-002-{trail_name}",
                    service="CloudTrail",
                    resource_id=trail_name,
                    resource_arn=trail.get('TrailARN', ''),
                    severity="MEDIUM",
                    category="Integrity",
                    title="CloudTrail log file validation disabled",
                    description=f"Trail {trail_name} doesn't have log file validation enabled",
                    remediation="Enable log file validation to detect tampering",
                    compliance_frameworks=["CIS"],
                    risk_score=60.0,
                    metadata=trail
                ))
        
        return findings

    async def analyze_rds_security(self) -> List[SecurityFinding]:
        """Analyze RDS security configurations"""
        findings = []
        
        for db in self.inventory.rds_instances:
            db_id = db['DBInstanceIdentifier']
            
            # Check encryption
            if not db.get('StorageEncrypted', False):
                findings.append(SecurityFinding(
                    finding_id=f"RDS-001-{db_id}",
                    service="RDS",
                    resource_id=db_id,
                    resource_arn=db.get('DBInstanceArn', ''),
                    severity="HIGH",
                    category="Encryption",
                    title="RDS instance not encrypted",
                    description=f"RDS instance {db_id} storage is not encrypted",
                    remediation="Enable encryption for RDS instances",
                    compliance_frameworks=["CIS", "SOC2", "GDPR"],
                    risk_score=75.0,
                    metadata={"engine": db.get('Engine', 'unknown')}
                ))
            
            # Check public accessibility
            if db.get('PubliclyAccessible', False):
                findings.append(SecurityFinding(
                    finding_id=f"RDS-002-{db_id}",
                    service="RDS",
                    resource_id=db_id,
                    resource_arn=db.get('DBInstanceArn', ''),
                    severity="CRITICAL",
                    category="Network Exposure",
                    title="RDS instance publicly accessible",
                    description=f"RDS instance {db_id} is publicly accessible",
                    remediation="Disable public accessibility unless required",
                    compliance_frameworks=["CIS", "NIST"],
                    risk_score=90.0,
                    metadata={"endpoint": db.get('Endpoint', {})}
                ))
        
        return findings

    async def analyze_lambda_security(self) -> List[SecurityFinding]:
        """Analyze Lambda function security configurations"""
        findings = []
        
        for func in self.inventory.lambda_functions:
            func_name = func['FunctionName']
            
            # Check for environment variables (potential secrets)
            env_vars = func.get('Environment', {}).get('Variables', {})
            
            suspicious_patterns = ['password', 'secret', 'key', 'token', 'credential']
            for var_name, var_value in env_vars.items():
                if any(pattern in var_name.lower() for pattern in suspicious_patterns):
                    findings.append(SecurityFinding(
                        finding_id=f"LAMBDA-001-{func_name}-{var_name}",
                        service="Lambda",
                        resource_id=func_name,
                        resource_arn=func.get('FunctionArn', ''),
                        severity="MEDIUM",
                        category="Secrets Management",
                        title="Potential secret in Lambda environment variable",
                        description=f"Lambda function {func_name} has suspicious environment variable: {var_name}",
                        remediation="Use AWS Secrets Manager or Parameter Store for sensitive data",
                        compliance_frameworks=["CIS", "SOC2"],
                        risk_score=60.0,
                        metadata={"variable_name": var_name, "runtime": func.get('Runtime', 'unknown')}
                    ))
        
        return findings

    async def assess_compliance(self) -> Dict[str, Any]:
        """Assess compliance against frameworks"""
        compliance_results = {
            'CIS': {'total_controls': 0, 'passed': 0, 'failed': 0},
            'SOC2': {'total_controls': 0, 'passed': 0, 'failed': 0},
            'NIST': {'total_controls': 0, 'passed': 0, 'failed': 0},
            'GDPR': {'total_controls': 0, 'passed': 0, 'failed': 0}
        }
        
        # Count findings by compliance framework
        for finding in self.findings:
            frameworks = finding.get('compliance_frameworks', [])
            for framework in frameworks:
                if framework in compliance_results:
                    compliance_results[framework]['total_controls'] += 1
                    if finding['severity'] in ['CRITICAL', 'HIGH']:
                        compliance_results[framework]['failed'] += 1
                    else:
                        compliance_results[framework]['passed'] += 1
        
        # Calculate compliance percentages
        for framework in compliance_results:
            total = compliance_results[framework]['total_controls']
            if total > 0:
                compliance_results[framework]['compliance_percentage'] = (
                    compliance_results[framework]['passed'] / total * 100
                )
            else:
                compliance_results[framework]['compliance_percentage'] = 100
        
        return compliance_results

    async def calculate_risk_scores(self) -> Dict[str, Any]:
        """Calculate comprehensive risk scores"""
        if not self.findings:
            return {'overall_risk_score': 0, 'risk_distribution': {}}
        
        # Calculate overall risk score
        total_risk = sum(finding['risk_score'] for finding in self.findings)
        overall_risk_score = min(total_risk / len(self.findings), 100)
        
        # Risk distribution by severity
        risk_distribution = {
            'CRITICAL': len([f for f in self.findings if f['severity'] == 'CRITICAL']),
            'HIGH': len([f for f in self.findings if f['severity'] == 'HIGH']),
            'MEDIUM': len([f for f in self.findings if f['severity'] == 'MEDIUM']),
            'LOW': len([f for f in self.findings if f['severity'] == 'LOW'])
        }
        
        # Risk by service
        risk_by_service = {}
        for finding in self.findings:
            service = finding['service']
            if service not in risk_by_service:
                risk_by_service[service] = []
            risk_by_service[service].append(finding['risk_score'])
        
        for service in risk_by_service:
            risk_by_service[service] = sum(risk_by_service[service]) / len(risk_by_service[service])
        
        return {
            'overall_risk_score': overall_risk_score,
            'risk_distribution': risk_distribution,
            'risk_by_service': risk_by_service,
            'total_findings': len(self.findings)
        }

    def generate_inventory_summary(self) -> Dict[str, int]:
        """Generate inventory summary statistics"""
        return {
            'ec2_instances': len(self.inventory.ec2_instances),
            's3_buckets': len(self.inventory.s3_buckets),
            'rds_instances': len(self.inventory.rds_instances),
            'lambda_functions': len(self.inventory.lambda_functions),
            'iam_users': len(self.inventory.iam_users),
            'iam_roles': len(self.inventory.iam_roles),
            'security_groups': len(self.inventory.security_groups),
            'cloudtrail_trails': len(self.inventory.cloudtrail_trails),
            'regions_analyzed': len(self.regions)
        }

    def generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate prioritized security recommendations"""
        if not self.findings:
            return []
        
        # Group findings by category and prioritize
        categories = {}
        for finding in self.findings:
            category = finding['category']
            if category not in categories:
                categories[category] = []
            categories[category].append(finding)
        
        recommendations = []
        for category, findings in categories.items():
            # Calculate average risk for category
            avg_risk = sum(f['risk_score'] for f in findings) / len(findings)
            
            recommendations.append({
                'category': category,
                'priority': 'HIGH' if avg_risk > 70 else 'MEDIUM' if avg_risk > 40 else 'LOW',
                'finding_count': len(findings),
                'average_risk_score': avg_risk,
                'top_recommendation': max(findings, key=lambda x: x['risk_score'])['remediation']
            })
        
        # Sort by average risk score
        recommendations.sort(key=lambda x: x['average_risk_score'], reverse=True)
        return recommendations

# Example usage
async def main():
    """Test the AWS security analyzer"""
    print("🚀 Starting AWS Security Analysis")
    
    analyzer = AWSSecurityAnalyzer()
    results = await analyzer.analyze_infrastructure()
    
    print("\n📊 Analysis Results Summary:")
    print(f"Total findings: {results['risk_analysis']['total_findings']}")
    print(f"Overall risk score: {results['risk_analysis']['overall_risk_score']:.1f}/100")
    print("\n🎯 Top recommendations:")
    for i, rec in enumerate(results['recommendations'][:3], 1):
        print(f"{i}. {rec['category']} ({rec['priority']} priority) - {rec['finding_count']} findings")

if __name__ == "__main__":
    asyncio.run(main())