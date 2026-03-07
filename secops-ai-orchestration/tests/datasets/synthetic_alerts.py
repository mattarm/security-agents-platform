"""
Synthetic Alert Datasets for AI Testing
Generates realistic security alert data for comprehensive testing of AI models, 
bias detection, and performance validation.
"""

import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

from ai_engine.orchestrator import SecurityAlert, AlertSeverity

class AlertPattern(Enum):
    """Common security alert patterns for realistic testing"""
    FALSE_POSITIVE_NOISE = "false_positive_noise"
    LEGITIMATE_THREAT = "legitimate_threat"
    BRUTE_FORCE_ATTACK = "brute_force_attack"
    MALWARE_DETECTION = "malware_detection"
    DATA_EXFILTRATION = "data_exfiltration"
    NETWORK_ANOMALY = "network_anomaly"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INSIDER_THREAT = "insider_threat"
    NOVEL_THREAT = "novel_threat"

@dataclass
class AlertTemplate:
    """Template for generating synthetic alerts"""
    pattern: AlertPattern
    severity: AlertSeverity
    source: str
    title_templates: List[str]
    description_templates: List[str]
    evidence_generators: List[callable]
    expected_category: str
    expected_confidence_range: tuple
    bias_test_category: Optional[str] = None

class SyntheticAlertGenerator:
    """
    Generates synthetic security alerts for comprehensive AI testing
    
    Features:
    - Realistic alert patterns based on real SOC data
    - Bias testing across different sources and severities
    - Performance testing with high-volume datasets
    - Edge case generation for robustness testing
    """
    
    def __init__(self):
        self.alert_templates = self._initialize_templates()
        self.ip_ranges = {
            'internal': ['10.{}.{}.{}', '192.168.{}.{}', '172.16.{}.{}'],
            'external': ['203.{}.{}.{}', '185.{}.{}.{}', '91.{}.{}.{}'],
            'suspicious': ['1.2.3.{}', '5.6.7.{}', '8.9.10.{}']
        }
        self.asset_types = [
            'domain_controller', 'database_server', 'web_server', 
            'file_server', 'email_server', 'workstation', 'laptop', 
            'mobile_device', 'network_device', 'cloud_resource'
        ]
    
    def generate_test_dataset(self, size: int = 1000, bias_testing: bool = True) -> List[SecurityAlert]:
        """
        Generate comprehensive test dataset for AI validation
        
        Args:
            size: Number of alerts to generate
            bias_testing: Include bias detection test cases
            
        Returns:
            List of synthetic security alerts
        """
        
        alerts = []
        
        # Distribute across different patterns realistically
        pattern_distribution = {
            AlertPattern.FALSE_POSITIVE_NOISE: 0.45,      # 45% false positives
            AlertPattern.NETWORK_ANOMALY: 0.20,           # 20% network anomalies
            AlertPattern.BRUTE_FORCE_ATTACK: 0.15,        # 15% brute force
            AlertPattern.MALWARE_DETECTION: 0.10,         # 10% malware
            AlertPattern.LEGITIMATE_THREAT: 0.05,         # 5% real threats
            AlertPattern.DATA_EXFILTRATION: 0.02,         # 2% data exfiltration
            AlertPattern.PRIVILEGE_ESCALATION: 0.02,      # 2% privilege escalation
            AlertPattern.NOVEL_THREAT: 0.01               # 1% novel threats
        }
        
        for pattern, percentage in pattern_distribution.items():
            count = int(size * percentage)
            for _ in range(count):
                alert = self._generate_alert_by_pattern(pattern)
                
                # Add bias testing variants
                if bias_testing and random.random() < 0.1:
                    alert = self._add_bias_testing_attributes(alert)
                
                alerts.append(alert)
        
        # Shuffle to remove generation order bias
        random.shuffle(alerts)
        return alerts
    
    def generate_performance_test_dataset(self, alerts_per_day: int = 122, days: int = 30) -> List[SecurityAlert]:
        """
        Generate dataset for performance testing (default: 122 alerts/day for 30 days)
        
        This simulates real SOC volume for cost and performance validation
        """
        
        total_alerts = alerts_per_day * days
        alerts = []
        
        start_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        for day in range(days):
            day_start = start_date + timedelta(days=day)
            
            # Realistic daily distribution (higher during business hours)
            hourly_distribution = self._get_realistic_hourly_distribution()
            
            for hour, percentage in enumerate(hourly_distribution):
                hour_count = max(1, int(alerts_per_day * percentage))
                hour_start = day_start + timedelta(hours=hour)
                
                for alert_num in range(hour_count):
                    # Randomly distributed within the hour
                    alert_time = hour_start + timedelta(
                        minutes=random.randint(0, 59),
                        seconds=random.randint(0, 59)
                    )
                    
                    # Generate alert with realistic timestamp
                    pattern = self._select_weighted_pattern()
                    alert = self._generate_alert_by_pattern(pattern, timestamp=alert_time)
                    alerts.append(alert)
        
        return alerts
    
    def generate_bias_test_dataset(self, size: int = 500) -> List[SecurityAlert]:
        """
        Generate dataset specifically for bias detection testing
        
        Tests for bias across:
        - Source systems (legacy vs modern)
        - Severity levels
        - Asset types
        - Time of day/week
        - Geographic indicators
        """
        
        alerts = []
        
        # Create balanced dataset for bias testing
        bias_categories = [
            'legacy_system_bias',      # Test for bias against legacy systems
            'severity_bias',           # Test for over/under-confidence by severity
            'asset_type_bias',         # Test for bias by asset criticality
            'temporal_bias',           # Test for time-based bias
            'geographic_bias'          # Test for location-based bias
        ]
        
        alerts_per_category = size // len(bias_categories)
        
        for category in bias_categories:
            for _ in range(alerts_per_category):
                alert = self._generate_bias_test_alert(category)
                alerts.append(alert)
        
        return alerts
    
    def generate_edge_case_dataset(self) -> List[SecurityAlert]:
        """Generate edge cases for robustness testing"""
        
        edge_cases = [
            self._generate_minimal_evidence_alert(),
            self._generate_maximal_evidence_alert(),
            self._generate_contradictory_evidence_alert(),
            self._generate_missing_fields_alert(),
            self._generate_unicode_content_alert(),
            self._generate_extremely_long_content_alert(),
            self._generate_pii_containing_alert(),
            self._generate_zero_confidence_indicators_alert(),
            self._generate_high_confidence_false_positive_alert(),
            self._generate_low_confidence_true_positive_alert()
        ]
        
        return edge_cases
    
    def _initialize_templates(self) -> Dict[AlertPattern, AlertTemplate]:
        """Initialize alert templates for each pattern"""
        
        return {
            AlertPattern.FALSE_POSITIVE_NOISE: AlertTemplate(
                pattern=AlertPattern.FALSE_POSITIVE_NOISE,
                severity=AlertSeverity.LOW,
                source="automated_scan",
                title_templates=[
                    "Port scan detected from {source_ip}",
                    "Failed login attempt from {source_ip}",
                    "Network timeout to {destination_ip}",
                    "SSL certificate warning for {hostname}"
                ],
                description_templates=[
                    "Automated scan detected {port_count} ports on {target_ip}. Likely legitimate network discovery.",
                    "Single failed authentication attempt from {source_ip}. User may have mistyped password.",
                    "Network timeout occurred during routine connectivity check.",
                    "SSL certificate expiring soon, generating expected warning."
                ],
                evidence_generators=[self._generate_benign_network_evidence],
                expected_category="false_positive",
                expected_confidence_range=(0.85, 0.98)
            ),
            
            AlertPattern.BRUTE_FORCE_ATTACK: AlertTemplate(
                pattern=AlertPattern.BRUTE_FORCE_ATTACK,
                severity=AlertSeverity.HIGH,
                source="auth_logs",
                title_templates=[
                    "Brute force attack detected against {target_user}",
                    "Multiple failed logins from {source_ip}",
                    "Password spray attack against {service}",
                    "Credential stuffing attempt detected"
                ],
                description_templates=[
                    "Detected {attempt_count} failed login attempts against user {target_user} from {source_ip} in {time_window}.",
                    "Multiple failed authentication attempts from {source_ip} against various accounts. Pattern consistent with brute force attack.",
                    "Password spray attack detected. {unique_users} unique usernames targeted with common passwords.",
                    "Credential stuffing attack using stolen credentials from {source_ip}."
                ],
                evidence_generators=[self._generate_brute_force_evidence],
                expected_category="containment_required",
                expected_confidence_range=(0.75, 0.95)
            ),
            
            AlertPattern.MALWARE_DETECTION: AlertTemplate(
                pattern=AlertPattern.MALWARE_DETECTION,
                severity=AlertSeverity.CRITICAL,
                source="endpoint_protection",
                title_templates=[
                    "Malware detected on {hostname}",
                    "Suspicious file execution on {hostname}",
                    "Trojan behavior detected",
                    "Ransomware indicators found"
                ],
                description_templates=[
                    "Malware signature {signature_name} detected on {hostname}. File {file_path} quarantined.",
                    "Suspicious executable {file_name} with unknown signature executed on {hostname}.",
                    "Trojan behavior detected: unauthorized network communication and file encryption activities.",
                    "Ransomware indicators found: mass file encryption and ransom note creation."
                ],
                evidence_generators=[self._generate_malware_evidence],
                expected_category="containment_required",
                expected_confidence_range=(0.80, 0.98)
            ),
            
            AlertPattern.NOVEL_THREAT: AlertTemplate(
                pattern=AlertPattern.NOVEL_THREAT,
                severity=AlertSeverity.MEDIUM,
                source="behavior_analytics",
                title_templates=[
                    "Anomalous behavior detected on {hostname}",
                    "Unknown attack pattern identified",
                    "Zero-day exploit indicators",
                    "Novel malware variant detected"
                ],
                description_templates=[
                    "Behavioral analytics detected anomalous activity pattern not matching known attack signatures.",
                    "Unknown attack methodology identified. Manual analysis required.",
                    "Potential zero-day exploit detected based on unusual system calls and network patterns.",
                    "Novel malware variant with previously unseen characteristics."
                ],
                evidence_generators=[self._generate_novel_threat_evidence],
                expected_category="investigation_required",
                expected_confidence_range=(0.30, 0.70)
            )
        }
    
    def _generate_alert_by_pattern(self, pattern: AlertPattern, timestamp: Optional[datetime] = None) -> SecurityAlert:
        """Generate a security alert matching the specified pattern"""
        
        template = self.alert_templates[pattern]
        
        # Generate dynamic values
        values = {
            'source_ip': self._generate_ip_address('external'),
            'destination_ip': self._generate_ip_address('internal'),
            'target_ip': self._generate_ip_address('internal'),
            'hostname': self._generate_hostname(),
            'target_user': self._generate_username(),
            'service': random.choice(['ssh', 'rdp', 'http', 'ftp', 'smb']),
            'attempt_count': random.randint(5, 50),
            'time_window': random.choice(['5 minutes', '10 minutes', '1 hour']),
            'port_count': random.randint(10, 1000),
            'unique_users': random.randint(5, 100),
            'signature_name': self._generate_signature_name(),
            'file_path': self._generate_file_path(),
            'file_name': self._generate_file_name()
        }
        
        # Select random templates
        title = random.choice(template.title_templates).format(**values)
        description = random.choice(template.description_templates).format(**values)
        
        # Generate evidence
        evidence = {}
        for evidence_generator in template.evidence_generators:
            evidence.update(evidence_generator(values))
        
        # Generate metadata
        metadata = {
            'pattern': pattern.value,
            'expected_category': template.expected_category,
            'expected_confidence_range': template.expected_confidence_range,
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'test_id': str(uuid.uuid4()),
            'asset_type': random.choice(self.asset_types)
        }
        
        return SecurityAlert(
            id=f"synthetic_{int(datetime.now(timezone.utc).timestamp())}_{random.randint(1000, 9999)}",
            timestamp=timestamp or datetime.now(timezone.utc),
            severity=template.severity,
            source=template.source,
            title=title,
            description=description,
            evidence=evidence,
            metadata=metadata
        )
    
    def _generate_benign_network_evidence(self, values: Dict) -> Dict[str, Any]:
        """Generate evidence for benign network activity"""
        return {
            'source_ip': values['source_ip'],
            'destination_ip': values['destination_ip'],
            'port': random.choice([80, 443, 22, 21, 25]),
            'protocol': 'tcp',
            'packet_count': random.randint(1, 10),
            'duration': random.randint(1, 30),
            'response_codes': ['200', '404', '301'],
            'user_agent': 'Mozilla/5.0 (legitimate browser)',
            'geolocation': random.choice(['US', 'CA', 'EU']),
            'reputation_score': random.uniform(0.8, 1.0)  # Good reputation
        }
    
    def _generate_brute_force_evidence(self, values: Dict) -> Dict[str, Any]:
        """Generate evidence for brute force attacks"""
        return {
            'source_ip': values['source_ip'],
            'target_user': values['target_user'],
            'failed_attempts': values['attempt_count'],
            'time_window_minutes': random.randint(5, 60),
            'unique_passwords_tried': random.randint(10, 100),
            'service': values['service'],
            'geolocation': random.choice(['CN', 'RU', 'TOR']),  # Suspicious origins
            'reputation_score': random.uniform(0.0, 0.3),  # Poor reputation
            'previous_attacks': random.choice([True, False]),
            'password_patterns': ['common_passwords', 'dictionary_attack', 'sequential']
        }
    
    def _generate_malware_evidence(self, values: Dict) -> Dict[str, Any]:
        """Generate evidence for malware detection"""
        return {
            'hostname': values['hostname'],
            'file_path': values['file_path'],
            'file_hash': self._generate_hash(),
            'file_size': random.randint(1024, 10485760),  # 1KB to 10MB
            'signature_match': values['signature_name'],
            'behavior_indicators': [
                'network_communication',
                'file_encryption',
                'registry_modification',
                'process_injection'
            ],
            'c2_communication': random.choice([True, False]),
            'encryption_activity': random.choice([True, False]),
            'privilege_escalation': random.choice([True, False])
        }
    
    def _generate_novel_threat_evidence(self, values: Dict) -> Dict[str, Any]:
        """Generate evidence for novel/unknown threats"""
        return {
            'hostname': values['hostname'],
            'anomaly_score': random.uniform(0.6, 0.9),
            'unknown_patterns': [
                'unusual_network_protocol',
                'undocumented_api_calls',
                'novel_encryption_method'
            ],
            'behavioral_deviation': random.uniform(0.5, 0.8),
            'signature_match': None,  # No known signature
            'ml_confidence': random.uniform(0.3, 0.7),  # Uncertain ML prediction
            'requires_analysis': True
        }
    
    def _generate_bias_test_alert(self, bias_category: str) -> SecurityAlert:
        """Generate alert specifically for bias testing"""
        
        if bias_category == 'legacy_system_bias':
            # Test bias against legacy systems
            return self._generate_alert_by_pattern(
                AlertPattern.FALSE_POSITIVE_NOISE
            )._replace(
                source='legacy_mainframe',
                metadata={'bias_test': 'legacy_system', 'expected_fair_treatment': True}
            )
        
        elif bias_category == 'severity_bias':
            # Test confidence consistency across severities
            pattern = random.choice(list(AlertPattern))
            alert = self._generate_alert_by_pattern(pattern)
            # Artificially vary severity to test bias
            alert.severity = random.choice(list(AlertSeverity))
            alert.metadata['bias_test'] = 'severity_consistency'
            return alert
        
        # Additional bias test implementations...
        return self._generate_alert_by_pattern(AlertPattern.FALSE_POSITIVE_NOISE)
    
    def _generate_minimal_evidence_alert(self) -> SecurityAlert:
        """Generate alert with minimal evidence for robustness testing"""
        return SecurityAlert(
            id="edge_case_minimal",
            timestamp=datetime.now(timezone.utc),
            severity=AlertSeverity.LOW,
            source="minimal_source",
            title="Minimal evidence alert",
            description="Alert with very little evidence",
            evidence={},  # Empty evidence
            metadata={'edge_case': 'minimal_evidence'}
        )
    
    def _generate_maximal_evidence_alert(self) -> SecurityAlert:
        """Generate alert with extensive evidence"""
        extensive_evidence = {}
        
        # Generate 50+ evidence fields
        for i in range(50):
            extensive_evidence[f'field_{i}'] = f'value_{i}'
            extensive_evidence[f'nested_{i}'] = {
                'subfield_1': f'subvalue_{i}_1',
                'subfield_2': f'subvalue_{i}_2'
            }
        
        return SecurityAlert(
            id="edge_case_maximal",
            timestamp=datetime.now(timezone.utc),
            severity=AlertSeverity.HIGH,
            source="extensive_monitoring",
            title="Maximal evidence alert with extensive data",
            description="Alert with comprehensive evidence for testing processing limits",
            evidence=extensive_evidence,
            metadata={'edge_case': 'maximal_evidence'}
        )
    
    def _generate_pii_containing_alert(self) -> SecurityAlert:
        """Generate alert containing PII for privacy testing"""
        return SecurityAlert(
            id="edge_case_pii",
            timestamp=datetime.now(timezone.utc),
            severity=AlertSeverity.MEDIUM,
            source="user_activity",
            title="Alert containing PII data",
            description="User john.doe@company.com accessed file with SSN 123-45-6789",
            evidence={
                'user_email': 'john.doe@company.com',
                'ssn': '123-45-6789',
                'credit_card': '4532-1234-5678-9012',
                'ip_address': '192.168.1.100'
            },
            metadata={'edge_case': 'pii_content', 'requires_masking': True}
        )
    
    # Utility methods for data generation
    def _generate_ip_address(self, ip_type: str) -> str:
        """Generate IP address of specified type"""
        templates = self.ip_ranges.get(ip_type, self.ip_ranges['external'])
        template = random.choice(templates)
        
        if ip_type == 'internal':
            return template.format(
                random.randint(0, 255),
                random.randint(1, 254)
            )
        else:
            return template.format(
                random.randint(1, 255),
                random.randint(1, 255),
                random.randint(1, 255),
                random.randint(1, 254)
            )
    
    def _generate_hostname(self) -> str:
        """Generate realistic hostname"""
        prefixes = ['web', 'db', 'app', 'mail', 'file', 'dc', 'ws', 'srv']
        numbers = random.randint(1, 99)
        domains = ['corp.local', 'company.com', 'internal.net']
        
        return f"{random.choice(prefixes)}{numbers:02d}.{random.choice(domains)}"
    
    def _generate_username(self) -> str:
        """Generate realistic username"""
        first_names = ['john', 'jane', 'mike', 'sarah', 'alex', 'admin', 'service']
        last_names = ['doe', 'smith', 'johnson', 'williams', 'brown', 'account', 'user']
        
        return f"{random.choice(first_names)}.{random.choice(last_names)}"
    
    def _generate_signature_name(self) -> str:
        """Generate malware signature name"""
        families = ['Trojan', 'Adware', 'Spyware', 'Rootkit', 'Worm', 'Virus']
        variants = ['Generic', 'Variant', 'Family', 'Packed']
        numbers = random.randint(1, 999)
        
        return f"{random.choice(families)}.{random.choice(variants)}.{numbers}"
    
    def _generate_file_path(self) -> str:
        """Generate realistic file path"""
        paths = [
            'C:\\Users\\{user}\\AppData\\Temp\\{file}',
            'C:\\Windows\\System32\\{file}',
            'C:\\Program Files\\{app}\\{file}',
            '/tmp/{file}',
            '/home/{user}/{file}',
            '/var/log/{file}'
        ]
        
        return random.choice(paths).format(
            user=self._generate_username(),
            file=self._generate_file_name(),
            app=random.choice(['Chrome', 'Firefox', 'Office', 'Adobe'])
        )
    
    def _generate_file_name(self) -> str:
        """Generate realistic file name"""
        names = ['setup', 'install', 'update', 'patch', 'config', 'data', 'temp', 'backup']
        extensions = ['.exe', '.dll', '.bat', '.ps1', '.tmp', '.log', '.zip', '.pdf']
        
        return f"{random.choice(names)}{random.randint(1, 999)}{random.choice(extensions)}"
    
    def _generate_hash(self) -> str:
        """Generate realistic file hash"""
        import hashlib
        random_string = f"{random.random()}{datetime.now(timezone.utc)}"
        return hashlib.md5(random_string.encode()).hexdigest()
    
    def _get_realistic_hourly_distribution(self) -> List[float]:
        """Get realistic hourly alert distribution (24 hours)"""
        # Simulates higher activity during business hours
        base_distribution = [
            0.02, 0.01, 0.01, 0.01, 0.01, 0.02,  # 0-5 AM (low activity)
            0.03, 0.04, 0.06, 0.08, 0.09, 0.10,  # 6-11 AM (increasing)
            0.09, 0.08, 0.09, 0.10, 0.08, 0.07,  # 12-5 PM (business hours)
            0.05, 0.04, 0.03, 0.03, 0.03, 0.02   # 6-11 PM (decreasing)
        ]
        
        # Normalize to sum to 1.0
        total = sum(base_distribution)
        return [x / total for x in base_distribution]
    
    def _select_weighted_pattern(self) -> AlertPattern:
        """Select alert pattern based on realistic weights"""
        patterns_weights = [
            (AlertPattern.FALSE_POSITIVE_NOISE, 0.45),
            (AlertPattern.NETWORK_ANOMALY, 0.20),
            (AlertPattern.BRUTE_FORCE_ATTACK, 0.15),
            (AlertPattern.MALWARE_DETECTION, 0.10),
            (AlertPattern.LEGITIMATE_THREAT, 0.05),
            (AlertPattern.DATA_EXFILTRATION, 0.02),
            (AlertPattern.PRIVILEGE_ESCALATION, 0.02),
            (AlertPattern.NOVEL_THREAT, 0.01)
        ]
        
        return random.choices(
            [p[0] for p in patterns_weights],
            weights=[p[1] for p in patterns_weights]
        )[0]

# Convenience functions for test usage
def generate_test_alerts(count: int = 100) -> List[SecurityAlert]:
    """Quick function to generate test alerts"""
    generator = SyntheticAlertGenerator()
    return generator.generate_test_dataset(count)

def generate_performance_alerts(alerts_per_day: int = 122, days: int = 30) -> List[SecurityAlert]:
    """Quick function to generate performance test alerts"""
    generator = SyntheticAlertGenerator()
    return generator.generate_performance_test_dataset(alerts_per_day, days)

def generate_bias_test_alerts(count: int = 500) -> List[SecurityAlert]:
    """Quick function to generate bias test alerts"""
    generator = SyntheticAlertGenerator()
    return generator.generate_bias_test_dataset(count)

def generate_edge_case_alerts() -> List[SecurityAlert]:
    """Quick function to generate edge case alerts"""
    generator = SyntheticAlertGenerator()
    return generator.generate_edge_case_dataset()