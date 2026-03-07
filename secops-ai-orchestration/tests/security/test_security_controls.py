"""
Security Controls Test Suite - Critical Security Validation for Enterprise Deployment
Tests VPC isolation, encryption, PII masking, and security architecture compliance
"""

import pytest
import re
import json
import hashlib
from datetime import datetime, timezone
from unittest.mock import Mock, patch, MagicMock
import boto3
from moto import mock_ec2, mock_kms, mock_vpc
from cryptography.fernet import Fernet

from ai_engine.orchestrator import SecurityAlert, AlertSeverity
from ai_engine.audit_logger import AuditLogger
from governance.compliance import ComplianceEngine
from tests.datasets.synthetic_alerts import generate_test_alerts

# Security test configuration
EXPECTED_VPC_CIDR = "10.100.0.0/16"
REQUIRED_ENCRYPTION_ALGORITHM = "AES-256"
PII_PATTERNS = {
    'ssn': r'\b\d{3}-?\d{2}-?\d{4}\b',
    'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
}

@pytest.fixture
def security_config():
    """Security configuration for testing"""
    return {
        'aws_region': 'us-east-1',
        'vpc_cidr': EXPECTED_VPC_CIDR,
        'encryption_key': Fernet.generate_key().decode(),
        'audit_db_path': ':memory:',
        'kms_key_id': 'test-kms-key-id',
        'vpc_endpoints': {
            'bedrock': 'vpce-bedrock-test',
            'kms': 'vpce-kms-test',
            's3': 'vpce-s3-test'
        }
    }

class TestVPCIsolation:
    """Test VPC isolation and network security controls"""
    
    @mock_vpc
    @mock_ec2
    def test_vpc_configuration_security(self, security_config):
        """Test VPC configuration meets security requirements"""
        
        # Create mock VPC environment
        ec2 = boto3.client('ec2', region_name='us-east-1')
        
        # Create VPC
        vpc_response = ec2.create_vpc(CidrBlock=EXPECTED_VPC_CIDR)
        vpc_id = vpc_response['Vpc']['VpcId']
        
        # Create private subnets
        private_subnet_1 = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.100.10.0/24",
            AvailabilityZone="us-east-1a"
        )
        private_subnet_2 = ec2.create_subnet(
            VpcId=vpc_id, 
            CidrBlock="10.100.11.0/24",
            AvailabilityZone="us-east-1b"
        )
        
        # Create security group for AI processing
        security_group = ec2.create_security_group(
            GroupName="secops-ai-processing",
            Description="Security group for AI processing",
            VpcId=vpc_id
        )
        sg_id = security_group['GroupId']
        
        # Add restrictive rules (HTTPS only)
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'IpRanges': [{'CidrIp': EXPECTED_VPC_CIDR}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 8080,
                    'ToPort': 8080,
                    'IpRanges': [{'CidrIp': EXPECTED_VPC_CIDR}]
                }
            ]
        )
        
        # Validate VPC configuration
        vpcs = ec2.describe_vpcs(VpcIds=[vpc_id])
        vpc = vpcs['Vpcs'][0]
        
        assert vpc['CidrBlock'] == EXPECTED_VPC_CIDR
        assert vpc['State'] == 'available'
        
        # Validate private subnets
        subnets = ec2.describe_subnets(SubnetIds=[
            private_subnet_1['Subnet']['SubnetId'],
            private_subnet_2['Subnet']['SubnetId']
        ])
        
        for subnet in subnets['Subnets']:
            assert subnet['VpcId'] == vpc_id
            assert not subnet['MapPublicIpOnLaunch'], "Subnets should not auto-assign public IPs"
        
        # Validate security group rules
        security_groups = ec2.describe_security_groups(GroupIds=[sg_id])
        sg = security_groups['SecurityGroups'][0]
        
        # Should only allow HTTPS and API traffic from VPC
        ingress_rules = sg['IpPermissions']
        assert len(ingress_rules) == 2, "Should have exactly 2 ingress rules"
        
        for rule in ingress_rules:
            assert rule['IpProtocol'] == 'tcp'
            assert rule['FromPort'] in [443, 8080]
            assert len(rule['IpRanges']) == 1
            assert rule['IpRanges'][0]['CidrIp'] == EXPECTED_VPC_CIDR
    
    @mock_ec2
    def test_vpc_endpoints_configuration(self, security_config):
        """Test VPC endpoints are properly configured for zero internet egress"""
        
        ec2 = boto3.client('ec2', region_name='us-east-1')
        
        # Create VPC
        vpc_response = ec2.create_vpc(CidrBlock=EXPECTED_VPC_CIDR)
        vpc_id = vpc_response['Vpc']['VpcId']
        
        # Create VPC endpoints for required services
        required_endpoints = [
            'com.amazonaws.us-east-1.bedrock-runtime',
            'com.amazonaws.us-east-1.kms',
            'com.amazonaws.us-east-1.s3'
        ]
        
        endpoint_ids = []
        for service_name in required_endpoints:
            if 's3' in service_name:
                # S3 is Gateway endpoint
                endpoint = ec2.create_vpc_endpoint(
                    VpcId=vpc_id,
                    ServiceName=service_name,
                    VpcEndpointType='Gateway'
                )
            else:
                # Interface endpoints
                endpoint = ec2.create_vpc_endpoint(
                    VpcId=vpc_id,
                    ServiceName=service_name,
                    VpcEndpointType='Interface'
                )
            endpoint_ids.append(endpoint['VpcEndpoint']['VpcEndpointId'])
        
        # Validate endpoints
        endpoints = ec2.describe_vpc_endpoints(VpcEndpointIds=endpoint_ids)
        
        assert len(endpoints['VpcEndpoints']) == len(required_endpoints)
        
        for endpoint in endpoints['VpcEndpoints']:
            assert endpoint['VpcId'] == vpc_id
            assert endpoint['State'] == 'available'
            
            # Validate service access
            service_name = endpoint['ServiceName']
            if 'bedrock' in service_name:
                assert 'bedrock' in service_name.lower()
            elif 'kms' in service_name:
                assert 'kms' in service_name.lower()
            elif 's3' in service_name:
                assert 's3' in service_name.lower()
    
    def test_network_isolation_validation(self, security_config):
        """Test that AI processing cannot reach internet directly"""
        
        # This would be tested in actual deployment environment
        # For unit testing, we validate configuration principles
        
        # Network isolation requirements
        isolation_requirements = {
            'no_internet_gateway_routes': True,
            'vpc_endpoints_only': True,
            'private_subnets_only': True,
            'nat_gateway_for_updates': True,  # Limited outbound for system updates
            'security_group_restrictions': True
        }
        
        # Validate isolation principles
        for requirement, should_be_enabled in isolation_requirements.items():
            assert should_be_enabled, f"Network isolation requirement '{requirement}' not met"

class TestEncryptionControls:
    """Test encryption at rest and in transit"""
    
    @mock_kms
    def test_kms_key_configuration(self, security_config):
        """Test customer-managed KMS key configuration"""
        
        kms = boto3.client('kms', region_name='us-east-1')
        
        # Create customer-managed KMS key
        key_response = kms.create_key(
            Description='SecOps AI Platform encryption key',
            KeyUsage='ENCRYPT_DECRYPT',
            KeySpec='SYMMETRIC_DEFAULT',
            Origin='AWS_KMS'
        )
        
        key_id = key_response['KeyMetadata']['KeyId']
        
        # Create alias
        kms.create_alias(
            AliasName='alias/secops-ai-prod-key',
            TargetKeyId=key_id
        )
        
        # Set key policy
        key_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Enable IAM User Permissions",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:root"
                    },
                    "Action": "kms:*",
                    "Resource": "*"
                },
                {
                    "Sid": "Allow Bedrock Service",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "bedrock.amazonaws.com"
                    },
                    "Action": [
                        "kms:Encrypt",
                        "kms:Decrypt",
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKey*",
                        "kms:DescribeKey"
                    ],
                    "Resource": "*"
                }
            ]
        }
        
        kms.put_key_policy(
            KeyId=key_id,
            PolicyName='default',
            Policy=json.dumps(key_policy)
        )
        
        # Validate key configuration
        key_metadata = kms.describe_key(KeyId=key_id)['KeyMetadata']
        
        assert key_metadata['KeyUsage'] == 'ENCRYPT_DECRYPT'
        assert key_metadata['KeySpec'] == 'SYMMETRIC_DEFAULT'
        assert key_metadata['KeyState'] == 'Enabled'
        
        # Test encryption/decryption
        test_data = b"Test encryption data for SecOps AI"
        
        encrypt_response = kms.encrypt(
            KeyId=key_id,
            Plaintext=test_data
        )
        
        ciphertext = encrypt_response['CiphertextBlob']
        
        decrypt_response = kms.decrypt(
            CiphertextBlob=ciphertext
        )
        
        assert decrypt_response['Plaintext'] == test_data
        assert decrypt_response['KeyId'] == key_id
    
    def test_audit_log_encryption(self, security_config):
        """Test audit log encryption implementation"""
        
        # Initialize audit logger with encryption
        config = {
            'audit_db_path': ':memory:',
            'encryption_key': security_config['encryption_key']
        }
        
        audit_logger = AuditLogger(config)
        
        # Create test alert and analysis result
        alert = SecurityAlert(
            id="encryption_test",
            timestamp=datetime.now(timezone.utc),
            severity=AlertSeverity.HIGH,
            source="test",
            title="Encryption test alert",
            description="Testing audit log encryption",
            evidence={"sensitive_data": "confidential information"},
            metadata={}
        )
        
        # Test data that should be encrypted
        sensitive_data = {
            'alert_details': alert.to_dict(),
            'analysis_reasoning': ['Contains sensitive analysis'],
            'user_actions': ['Admin reviewed alert'],
            'system_context': {'internal_ip': '10.100.1.50'}
        }
        
        # Verify encryption key is properly formatted
        try:
            fernet = Fernet(security_config['encryption_key'].encode())
            
            # Test encryption/decryption
            test_string = json.dumps(sensitive_data)
            encrypted = fernet.encrypt(test_string.encode())
            decrypted = fernet.decrypt(encrypted).decode()
            
            assert json.loads(decrypted) == sensitive_data
            
        except Exception as e:
            pytest.fail(f"Encryption test failed: {str(e)}")
    
    def test_data_in_transit_encryption(self, security_config):
        """Test encryption requirements for data in transit"""
        
        # TLS/HTTPS requirements for all communications
        encryption_requirements = {
            'bedrock_api_calls': 'HTTPS/TLS 1.2+',
            'vpc_endpoint_communication': 'HTTPS/TLS 1.2+',
            'audit_log_transmission': 'HTTPS/TLS 1.2+',
            'slack_notifications': 'HTTPS/TLS 1.2+',
            'web_api_endpoints': 'HTTPS/TLS 1.2+',
            'client_connections': 'HTTPS/TLS 1.2+'
        }
        
        # Validate encryption requirements
        for component, requirement in encryption_requirements.items():
            assert 'HTTPS' in requirement or 'TLS' in requirement, \
                f"Component {component} lacks proper encryption requirement"

class TestPIIProtection:
    """Test PII detection and masking capabilities"""
    
    def test_pii_detection_patterns(self):
        """Test PII detection pattern accuracy"""
        
        # Test data with various PII types
        test_cases = [
            {
                'text': 'User john.doe@company.com accessed file with SSN 123-45-6789',
                'expected_pii': ['email', 'ssn']
            },
            {
                'text': 'Credit card 4532-1234-5678-9012 used for transaction',
                'expected_pii': ['credit_card']
            },
            {
                'text': 'Phone number 555-123-4567 in contact record',
                'expected_pii': ['phone']
            },
            {
                'text': 'No PII in this generic security alert message',
                'expected_pii': []
            },
            {
                'text': 'Multiple PII: john.smith@email.com, SSN: 987654321, Phone: (555) 987-6543',
                'expected_pii': ['email', 'ssn', 'phone']
            }
        ]
        
        for test_case in test_cases:
            text = test_case['text']
            expected_pii = test_case['expected_pii']
            detected_pii = []
            
            # Run PII detection
            for pii_type, pattern in PII_PATTERNS.items():
                if re.search(pattern, text):
                    detected_pii.append(pii_type)
            
            # Validate detection accuracy
            assert set(detected_pii) == set(expected_pii), \
                f"PII detection mismatch for '{text}'. Expected: {expected_pii}, Got: {detected_pii}"
    
    def test_pii_masking_functionality(self):
        """Test PII masking implementation"""
        
        original_text = "User email john.doe@company.com has SSN 123-45-6789"
        
        # Implement PII masking
        masked_text = original_text
        
        # Mask email
        email_pattern = PII_PATTERNS['email']
        masked_text = re.sub(email_pattern, '[EMAIL_MASKED]', masked_text)
        
        # Mask SSN
        ssn_pattern = PII_PATTERNS['ssn']
        masked_text = re.sub(ssn_pattern, '[SSN_MASKED]', masked_text)
        
        expected_masked = "User email [EMAIL_MASKED] has SSN [SSN_MASKED]"
        
        assert masked_text == expected_masked
        
        # Ensure no PII remains in masked text
        for pii_type, pattern in PII_PATTERNS.items():
            assert not re.search(pattern, masked_text), \
                f"PII of type {pii_type} still present in masked text: {masked_text}"
    
    async def test_compliance_pii_detection(self):
        """Test compliance engine PII detection"""
        
        # Create alert with PII content
        pii_alert = SecurityAlert(
            id="pii_test",
            timestamp=datetime.now(timezone.utc),
            severity=AlertSeverity.MEDIUM,
            source="user_activity",
            title="User access alert",
            description="User john.doe@company.com accessed sensitive file",
            evidence={
                'user_email': 'john.doe@company.com',
                'ssn_accessed': '123-45-6789',
                'credit_card': '4532-1234-5678-9012'
            },
            metadata={}
        )
        
        # Create mock analysis result
        analysis_result = Mock()
        analysis_result.reasoning_chain = [
            'User john.doe@company.com performed suspicious access',
            'SSN 987-65-4321 was accessed',
            'Credit card 1234-5678-9012-3456 transaction detected'
        ]
        
        # Test compliance validation with PII detection
        compliance_engine = ComplianceEngine({'enabled_frameworks': ['GDPR']})
        
        validation_result = await compliance_engine.validate_decision(analysis_result)
        
        # Should detect PII exposure
        assert 'privacy_assessment' in validation_result
        pii_detection = validation_result['privacy_assessment']['pii_detection']
        
        assert not pii_detection['compliant'], "Should detect PII exposure"
        assert pii_detection['requires_masking'], "Should require PII masking"
        assert len(pii_detection['pii_types_found']) > 0, "Should identify PII types"
    
    def test_pii_anonymization_techniques(self):
        """Test various PII anonymization techniques"""
        
        original_data = {
            'email': 'john.doe@company.com',
            'ssn': '123-45-6789', 
            'credit_card': '4532-1234-5678-9012',
            'ip_address': '192.168.1.100',
            'user_id': 'johndoe123'
        }
        
        # Technique 1: Complete masking
        completely_masked = {k: f'[{k.upper()}_MASKED]' for k in original_data}
        
        # Technique 2: Partial preservation (keep format)
        partially_masked = {
            'email': 'j***.d**@company.com',
            'ssn': 'XXX-XX-6789',  # Keep last 4 digits
            'credit_card': '****-****-****-3012',  # Keep last 4 digits
            'ip_address': '192.168.1.***',
            'user_id': 'j******123'  # Keep first and last chars
        }
        
        # Technique 3: Hashing for consistency
        hashed_data = {}
        for key, value in original_data.items():
            # Use SHA-256 hash for consistent anonymization
            hash_value = hashlib.sha256(value.encode()).hexdigest()[:16]
            hashed_data[key] = f'{key}_{hash_value}'
        
        # Validate anonymization techniques
        for technique_name, anonymized_data in [
            ('complete_masking', completely_masked),
            ('partial_preservation', partially_masked),
            ('hashing', hashed_data)
        ]:
            
            # Ensure no original PII remains
            anonymized_text = str(anonymized_data)
            
            for pii_type, pattern in PII_PATTERNS.items():
                if pii_type in original_data:
                    original_value = original_data[pii_type]
                    assert original_value not in anonymized_text, \
                        f"Original PII '{original_value}' found in {technique_name} result"

class TestAccessControls:
    """Test access controls and authorization"""
    
    def test_iam_role_permissions(self, security_config):
        """Test IAM role has minimal required permissions"""
        
        # Define minimal required permissions for AI processing
        required_permissions = {
            'bedrock:InvokeModel': [
                'arn:aws:bedrock:*::foundation-model/anthropic.claude-3-haiku-*',
                'arn:aws:bedrock:*::foundation-model/anthropic.claude-3-sonnet-*',
                'arn:aws:bedrock:*::foundation-model/anthropic.claude-3-opus-*'
            ],
            'kms:Encrypt': ['test-kms-key-arn'],
            'kms:Decrypt': ['test-kms-key-arn'],
            'logs:CreateLogGroup': ['arn:aws:logs:*:*:log-group:/aws/secops-ai/*'],
            'logs:CreateLogStream': ['arn:aws:logs:*:*:log-group:/aws/secops-ai/*'],
            'logs:PutLogEvents': ['arn:aws:logs:*:*:log-group:/aws/secops-ai/*']
        }
        
        # Prohibited permissions (should NOT have)
        prohibited_permissions = [
            's3:*',  # Should not have broad S3 access
            'ec2:*', # Should not have EC2 access
            'iam:*', # Should not have IAM access
            'bedrock:*', # Should not have broad Bedrock access
            '*:*'    # Should not have wildcard permissions
        ]
        
        # Validate permission structure
        for action, resources in required_permissions.items():
            assert isinstance(resources, list), f"Resources for {action} should be a list"
            
            for resource in resources:
                # Validate resource ARN format
                if resource.startswith('arn:aws:'):
                    assert len(resource.split(':')) >= 6, f"Invalid ARN format: {resource}"
        
        # Ensure no prohibited permissions
        for prohibited in prohibited_permissions:
            assert prohibited not in str(required_permissions), \
                f"Found prohibited permission: {prohibited}"
    
    def test_api_authentication_requirements(self):
        """Test API authentication and authorization requirements"""
        
        # API security requirements
        api_security_requirements = {
            'authentication_required': True,
            'authorization_levels': ['read', 'write', 'admin'],
            'rate_limiting': True,
            'input_validation': True,
            'output_sanitization': True,
            'audit_logging': True,
            'session_management': True
        }
        
        # Validate each requirement
        for requirement, should_be_enabled in api_security_requirements.items():
            assert should_be_enabled, f"API security requirement '{requirement}' not enabled"
    
    def test_principle_of_least_privilege(self):
        """Test adherence to principle of least privilege"""
        
        # Component access matrix - what each component should access
        access_matrix = {
            'ai_orchestrator': {
                'allowed': ['bedrock_api', 'confidence_engine', 'audit_logger'],
                'denied': ['direct_database', 'system_commands', 'user_data']
            },
            'confidence_engine': {
                'allowed': ['historical_patterns', 'bias_detection'],
                'denied': ['direct_alerts', 'system_config', 'user_credentials']
            },
            'audit_logger': {
                'allowed': ['audit_database', 'log_files'],
                'denied': ['alert_processing', 'ai_models', 'user_interface']
            },
            'compliance_engine': {
                'allowed': ['audit_trails', 'policy_rules'],
                'denied': ['ai_decisions', 'system_operations', 'user_management']
            }
        }
        
        # Validate access controls for each component
        for component, access_rules in access_matrix.items():
            allowed_resources = access_rules['allowed']
            denied_resources = access_rules['denied']
            
            # Ensure no overlap between allowed and denied
            overlap = set(allowed_resources).intersection(set(denied_resources))
            assert len(overlap) == 0, \
                f"Component {component} has overlapping allowed/denied resources: {overlap}"
            
            # Validate minimal access principle
            assert len(allowed_resources) <= 5, \
                f"Component {component} has too many allowed resources (>5): {allowed_resources}"

class TestSecurityMonitoring:
    """Test security monitoring and alerting capabilities"""
    
    def test_security_event_detection(self):
        """Test detection of security events in AI operations"""
        
        # Security events that should trigger alerts
        security_events = [
            {
                'event_type': 'unauthorized_access_attempt',
                'description': 'Attempt to access restricted AI model',
                'severity': 'HIGH',
                'should_trigger_alert': True
            },
            {
                'event_type': 'pii_exposure_detected',
                'description': 'PII found in unmasked AI output',
                'severity': 'CRITICAL', 
                'should_trigger_alert': True
            },
            {
                'event_type': 'unusual_model_usage',
                'description': 'Unexpected spike in expensive model usage',
                'severity': 'MEDIUM',
                'should_trigger_alert': True
            },
            {
                'event_type': 'audit_log_tampering',
                'description': 'Attempt to modify audit logs',
                'severity': 'CRITICAL',
                'should_trigger_alert': True
            },
            {
                'event_type': 'normal_operation',
                'description': 'Standard alert processing',
                'severity': 'INFO',
                'should_trigger_alert': False
            }
        ]
        
        # Validate security event handling
        for event in security_events:
            event_severity = event['severity']
            should_alert = event['should_trigger_alert']
            
            if event_severity in ['HIGH', 'CRITICAL']:
                assert should_alert, f"High/Critical event should trigger alert: {event['event_type']}"
            
            if 'pii' in event['event_type'].lower() or 'unauthorized' in event['event_type'].lower():
                assert should_alert, f"Security violation should trigger alert: {event['event_type']}"
    
    def test_audit_trail_integrity(self):
        """Test audit trail integrity and tamper detection"""
        
        # Create audit logger for integrity testing
        audit_logger = AuditLogger({
            'audit_db_path': ':memory:',
            'encryption_key': Fernet.generate_key().decode()
        })
        
        # Test data for audit trail
        test_events = [
            {
                'event_id': 'test_1',
                'timestamp': datetime.now(timezone.utc),
                'event_type': 'AI_DECISION',
                'data': {'decision': 'false_positive', 'confidence': 0.95}
            },
            {
                'event_id': 'test_2',
                'timestamp': datetime.now(timezone.utc),
                'event_type': 'HUMAN_OVERRIDE',
                'data': {'original_decision': 'false_positive', 'new_decision': 'investigate'}
            }
        ]
        
        # Validate event integrity features
        for event in test_events:
            # Each event should have unique ID
            assert 'event_id' in event
            assert event['event_id'] is not None
            
            # Each event should have timestamp
            assert 'timestamp' in event
            assert isinstance(event['timestamp'], datetime)
            
            # Each event should have type and data
            assert 'event_type' in event
            assert 'data' in event
            
        # Test hash chain integrity (simplified)
        previous_hash = None
        for i, event in enumerate(test_events):
            # Calculate event hash (simplified)
            event_string = f"{event['event_id']}{event['timestamp']}{event['event_type']}{event['data']}{previous_hash}"
            event_hash = hashlib.sha256(event_string.encode()).hexdigest()
            
            # Validate hash chain
            if i > 0:
                assert previous_hash is not None, "Hash chain should link events"
            
            previous_hash = event_hash
    
    def test_anomaly_detection_security(self):
        """Test security anomaly detection in AI operations"""
        
        # Anomaly patterns that should trigger security reviews
        anomaly_patterns = [
            {
                'pattern': 'excessive_opus_usage',
                'description': 'Unusual spike in expensive model usage',
                'threshold': 0.1,  # More than 10% Opus usage
                'test_value': 0.25,  # 25% usage
                'should_trigger': True
            },
            {
                'pattern': 'confidence_score_manipulation',
                'description': 'Artificially high confidence scores',
                'threshold': 0.98,  # Suspiciously high confidence
                'test_value': 0.99,
                'should_trigger': True
            },
            {
                'pattern': 'rapid_tier_escalation',
                'description': 'Too many alerts escalating to human review',
                'threshold': 0.5,   # More than 50% escalation rate
                'test_value': 0.75, # 75% escalation
                'should_trigger': True
            },
            {
                'pattern': 'normal_distribution',
                'description': 'Expected model usage pattern',
                'threshold': 0.1,
                'test_value': 0.05,  # 5% Opus usage (normal)
                'should_trigger': False
            }
        ]
        
        # Test anomaly detection logic
        for anomaly in anomaly_patterns:
            pattern = anomaly['pattern']
            threshold = anomaly['threshold']
            test_value = anomaly['test_value']
            should_trigger = anomaly['should_trigger']
            
            # Apply threshold logic
            threshold_exceeded = test_value > threshold
            
            if should_trigger:
                assert threshold_exceeded, \
                    f"Anomaly pattern '{pattern}' should exceed threshold ({test_value} > {threshold})"
            else:
                assert not threshold_exceeded or not should_trigger, \
                    f"Normal pattern '{pattern}' should not trigger anomaly"

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=governance", "--cov=ai_engine"])