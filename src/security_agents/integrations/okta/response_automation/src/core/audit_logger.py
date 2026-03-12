"""
Audit Logger

Provides comprehensive audit logging for all identity threat response actions.
Ensures compliance with security and regulatory requirements.
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from typing import Dict, Any, Optional
from cryptography.fernet import Fernet
import hashlib
import uuid
from pathlib import Path


class AuditLogger:
    """
    Comprehensive audit logging system for identity response actions
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize audit logger"""
        self.config = config
        self.log_level = config.get('log_level', 'INFO')
        self.log_file = config.get('log_file', 'logs/identity_response.log')
        self.log_format = config.get('log_format', 'json')
        self.retention_days = config.get('retention_days', 2555)  # 7 years default
        self.encrypt_logs = config.get('encrypt_logs', True)
        
        # Compliance frameworks
        self.frameworks = config.get('frameworks', {})
        
        # Encryption setup
        self.encryption_key = self._get_or_create_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key) if self.encrypt_logs else None
        
        # Ensure log directory exists
        log_dir = Path(self.log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup file logger
        self.logger = self._setup_logger()
        
        # Audit sequence counter for integrity
        self.sequence_counter = 0
        
        self.logger.info("Audit logger initialized with encryption" + 
                        (" enabled" if self.encrypt_logs else " disabled"))

    def _setup_logger(self) -> logging.Logger:
        """Setup file-based audit logger"""
        logger = logging.getLogger('audit_logger')
        logger.setLevel(getattr(logging, self.log_level.upper()))
        
        # Remove existing handlers to avoid duplicates
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        # File handler for audit logs
        file_handler = logging.FileHandler(self.log_file)
        
        if self.log_format == 'json':
            formatter = logging.Formatter('%(message)s')
        else:
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
        
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # Don't propagate to root logger
        logger.propagate = False
        
        return logger

    def _get_or_create_encryption_key(self) -> bytes:
        """Get or create encryption key for audit logs"""
        key_file = Path('config/audit_encryption.key')
        
        if key_file.exists():
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # Create new key
            key = Fernet.generate_key()
            
            # Ensure config directory exists
            key_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Save key securely
            with open(key_file, 'wb') as f:
                f.write(key)
            
            # Set secure permissions (Linux/Mac only)
            if os.name != 'nt':
                os.chmod(key_file, 0o600)
            
            return key

    async def log_event(self, event_type: str, data: Dict[str, Any], user_id: str = "system") -> str:
        """
        Log an audit event
        
        Args:
            event_type: Type of event (THREAT_RECEIVED, ACTION_EXECUTED, etc.)
            data: Event data dictionary
            user_id: User who triggered the event
            
        Returns:
            Audit record ID for tracking
        """
        
        # Generate unique audit record ID
        audit_id = str(uuid.uuid4())
        self.sequence_counter += 1
        
        # Build comprehensive audit record
        audit_record = {
            'audit_id': audit_id,
            'sequence': self.sequence_counter,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': event_type,
            'user_id': user_id,
            'session_id': data.get('session_id', 'unknown'),
            'source_ip': data.get('source_ip'),
            'user_agent': data.get('user_agent'),
            'data': data,
            'compliance': self._build_compliance_metadata(event_type, data),
            'integrity_hash': None  # Will be calculated below
        }
        
        # Calculate integrity hash
        audit_record['integrity_hash'] = self._calculate_integrity_hash(audit_record)
        
        # Encrypt if enabled
        if self.encrypt_logs:
            encrypted_record = self._encrypt_record(audit_record)
            log_entry = {
                'encrypted': True,
                'audit_id': audit_id,
                'timestamp': audit_record['timestamp'],
                'event_type': event_type,
                'data': encrypted_record.decode('utf-8')
            }
        else:
            log_entry = audit_record
        
        # Write to log file
        if self.log_format == 'json':
            self.logger.info(json.dumps(log_entry))
        else:
            self.logger.info(f"[{event_type}] {audit_id}: {json.dumps(data)}")
        
        return audit_id

    def _calculate_integrity_hash(self, record: Dict[str, Any]) -> str:
        """Calculate integrity hash for audit record"""
        # Create a copy without the hash field
        record_copy = record.copy()
        record_copy.pop('integrity_hash', None)
        
        # Serialize and hash
        record_json = json.dumps(record_copy, sort_keys=True)
        return hashlib.sha256(record_json.encode()).hexdigest()

    def _encrypt_record(self, record: Dict[str, Any]) -> bytes:
        """Encrypt audit record"""
        record_json = json.dumps(record)
        return self.cipher_suite.encrypt(record_json.encode())

    def _decrypt_record(self, encrypted_data: bytes) -> Dict[str, Any]:
        """Decrypt audit record"""
        decrypted_json = self.cipher_suite.decrypt(encrypted_data)
        return json.loads(decrypted_json.decode())

    def _build_compliance_metadata(self, event_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Build compliance metadata based on configured frameworks"""
        metadata = {}
        
        # SOX compliance
        if self.frameworks.get('sox', False):
            metadata['sox'] = {
                'financial_impact': self._assess_financial_impact(event_type, data),
                'control_activity': self._map_to_sox_control(event_type),
                'risk_level': data.get('threat_level', 'unknown')
            }
        
        # PCI DSS compliance
        if self.frameworks.get('pci_dss', False):
            metadata['pci_dss'] = {
                'requirement': self._map_to_pci_requirement(event_type),
                'cardholder_data_involved': self._check_cardholder_data(data),
                'network_access': event_type in ['LOGIN_ATTEMPT', 'ACCESS_GRANTED', 'ACCESS_DENIED']
            }
        
        # GDPR compliance
        if self.frameworks.get('gdpr', False):
            metadata['gdpr'] = {
                'personal_data_processed': self._check_personal_data(data),
                'legal_basis': 'legitimate_interest_security',
                'data_subject': data.get('user_email', 'unknown'),
                'processing_purpose': 'identity_threat_response'
            }
        
        # ISO 27001 compliance
        if self.frameworks.get('iso27001', False):
            metadata['iso27001'] = {
                'security_event': True,
                'incident_classification': self._classify_iso_incident(event_type),
                'control_domain': 'access_control',
                'effectiveness': data.get('action_result', 'pending')
            }
        
        return metadata

    def _assess_financial_impact(self, event_type: str, data: Dict[str, Any]) -> str:
        """Assess financial impact for SOX compliance"""
        if event_type in ['ACCOUNT_COMPROMISE', 'PRIVILEGE_ESCALATION']:
            threat_level = data.get('threat_level', '').upper()
            if threat_level in ['HIGH', 'CRITICAL']:
                return 'medium'
            else:
                return 'low'
        return 'none'

    def _map_to_sox_control(self, event_type: str) -> str:
        """Map event to SOX control activity"""
        sox_mapping = {
            'THREAT_RECEIVED': 'monitoring_control',
            'ACTION_EXECUTED': 'preventive_control',
            'ACCESS_GRANTED': 'access_control',
            'ACCESS_DENIED': 'access_control',
            'PRIVILEGES_REVOKED': 'access_control'
        }
        return sox_mapping.get(event_type, 'general_control')

    def _map_to_pci_requirement(self, event_type: str) -> str:
        """Map event to PCI DSS requirement"""
        pci_mapping = {
            'LOGIN_ATTEMPT': 'req_8_access_management',
            'MFA_ENFORCED': 'req_8_two_factor_auth',
            'ACCESS_DENIED': 'req_7_access_restriction',
            'ACCOUNT_LOCKED': 'req_8_account_lockout',
            'SUSPICIOUS_LOGIN': 'req_10_logging_monitoring'
        }
        return pci_mapping.get(event_type, 'req_10_logging_monitoring')

    def _check_cardholder_data(self, data: Dict[str, Any]) -> bool:
        """Check if cardholder data might be involved"""
        # This is a simplified check - in practice you'd check against
        # systems and data classifications
        sensitive_systems = ['payment_system', 'billing_system', 'pos_system']
        system = data.get('system', '').lower()
        return any(sys in system for sys in sensitive_systems)

    def _check_personal_data(self, data: Dict[str, Any]) -> bool:
        """Check if personal data is processed"""
        personal_data_fields = ['user_email', 'user_name', 'ip_address', 'device_id']
        return any(field in data for field in personal_data_fields)

    def _classify_iso_incident(self, event_type: str) -> str:
        """Classify incident according to ISO 27001"""
        if event_type in ['ACCOUNT_COMPROMISE', 'UNAUTHORIZED_ACCESS']:
            return 'security_breach'
        elif event_type in ['SUSPICIOUS_LOGIN', 'FAILED_LOGIN']:
            return 'security_event'
        elif event_type in ['SYSTEM_ERROR', 'ACTION_FAILED']:
            return 'availability_incident'
        else:
            return 'security_event'

    async def log_threat_received(self, threat_event) -> str:
        """Log threat event reception"""
        data = {
            'threat_event_id': threat_event.id,
            'threat_type': threat_event.threat_type,
            'threat_level': threat_event.level.value,
            'user_id': threat_event.user_id,
            'user_email': threat_event.user_email,
            'source_system': threat_event.source,
            'source_ip': threat_event.ip_address,
            'user_agent': threat_event.user_agent,
            'device_id': threat_event.device_id,
            'indicators': threat_event.indicators,
            'context': threat_event.context
        }
        
        return await self.log_event('THREAT_RECEIVED', data)

    async def log_action_executed(self, response_action) -> str:
        """Log response action execution"""
        data = {
            'action_id': response_action.id,
            'action_type': response_action.action_type,
            'threat_event_id': response_action.threat_event_id,
            'parameters': response_action.parameters,
            'status': response_action.status.value,
            'executed_at': response_action.executed_at.isoformat() if response_action.executed_at else None,
            'completed_at': response_action.completed_at.isoformat() if response_action.completed_at else None,
            'result': response_action.result,
            'error': response_action.error,
            'requires_approval': response_action.requires_approval,
            'approved_by': response_action.approved_by,
            'approved_at': response_action.approved_at.isoformat() if response_action.approved_at else None
        }
        
        return await self.log_event('ACTION_EXECUTED', data)

    async def log_user_access(self, user_id: str, action: str, resource: str, result: str, details: Dict[str, Any] = None) -> str:
        """Log user access attempts"""
        data = {
            'user_id': user_id,
            'action': action,
            'resource': resource,
            'result': result,
            'details': details or {}
        }
        
        return await self.log_event('USER_ACCESS', data, user_id)

    async def log_privilege_change(self, user_id: str, change_type: str, privileges: Dict[str, Any], changed_by: str) -> str:
        """Log privilege changes"""
        data = {
            'user_id': user_id,
            'change_type': change_type,
            'privileges_before': privileges.get('before', {}),
            'privileges_after': privileges.get('after', {}),
            'changed_by': changed_by,
            'justification': privileges.get('justification', '')
        }
        
        return await self.log_event('PRIVILEGE_CHANGE', data, changed_by)

    async def log_configuration_change(self, component: str, change_details: Dict[str, Any], changed_by: str) -> str:
        """Log system configuration changes"""
        data = {
            'component': component,
            'change_details': change_details,
            'changed_by': changed_by
        }
        
        return await self.log_event('CONFIGURATION_CHANGE', data, changed_by)

    async def log_system_event(self, event_subtype: str, details: Dict[str, Any]) -> str:
        """Log general system events"""
        data = {
            'event_subtype': event_subtype,
            'details': details
        }
        
        return await self.log_event('SYSTEM_EVENT', data)

    async def search_logs(
        self,
        start_time: datetime,
        end_time: datetime,
        event_types: Optional[list] = None,
        user_id: Optional[str] = None
    ) -> list:
        """Search audit logs within time range"""
        
        # This is a simplified implementation
        # In production, you'd use a proper log search engine like ELK stack
        
        logs = []
        
        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    try:
                        if self.log_format == 'json':
                            log_entry = json.loads(line.strip())
                        else:
                            continue  # Skip non-JSON for now
                        
                        # Parse timestamp
                        log_time = datetime.fromisoformat(
                            log_entry['timestamp'].replace('Z', '+00:00')
                        )
                        
                        # Check time range
                        if not (start_time <= log_time <= end_time):
                            continue
                        
                        # Check event type filter
                        if event_types and log_entry.get('event_type') not in event_types:
                            continue
                        
                        # Check user filter
                        if user_id and log_entry.get('user_id') != user_id:
                            continue
                        
                        # Decrypt if needed
                        if log_entry.get('encrypted', False) and self.cipher_suite:
                            decrypted_data = self._decrypt_record(log_entry['data'].encode())
                            log_entry['decrypted_data'] = decrypted_data
                        
                        logs.append(log_entry)
                        
                    except (json.JSONDecodeError, KeyError, ValueError):
                        continue  # Skip malformed entries
                        
        except FileNotFoundError:
            pass  # Log file doesn't exist yet
        
        return logs

    async def verify_log_integrity(self, audit_id: str) -> bool:
        """Verify integrity of a specific audit log entry"""
        
        logs = await self.search_logs(
            datetime.min,
            datetime.max
        )
        
        for log_entry in logs:
            if log_entry.get('audit_id') == audit_id:
                # Decrypt if needed
                if log_entry.get('encrypted', False):
                    if not self.cipher_suite:
                        return False  # Can't verify without key
                    
                    try:
                        record = self._decrypt_record(log_entry['data'].encode())
                    except Exception:
                        return False  # Decryption failed
                else:
                    record = log_entry
                
                # Verify hash
                stored_hash = record.get('integrity_hash')
                calculated_hash = self._calculate_integrity_hash(record)
                
                return stored_hash == calculated_hash
        
        return False  # Log not found

    async def generate_compliance_report(
        self,
        framework: str,
        start_time: datetime,
        end_time: datetime
    ) -> Dict[str, Any]:
        """Generate compliance report for specified framework"""
        
        logs = await self.search_logs(start_time, end_time)
        
        report = {
            'framework': framework,
            'report_period': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat()
            },
            'generated_at': datetime.utcnow().isoformat(),
            'total_events': len(logs),
            'event_summary': {},
            'compliance_violations': [],
            'recommendations': []
        }
        
        # Analyze logs for compliance
        for log_entry in logs:
            event_type = log_entry.get('event_type', 'unknown')
            report['event_summary'][event_type] = report['event_summary'].get(event_type, 0) + 1
            
            # Check for compliance violations
            if self._check_compliance_violation(log_entry, framework):
                report['compliance_violations'].append({
                    'audit_id': log_entry.get('audit_id'),
                    'event_type': event_type,
                    'timestamp': log_entry.get('timestamp'),
                    'violation_type': self._get_violation_type(log_entry, framework)
                })
        
        # Add recommendations based on findings
        report['recommendations'] = self._generate_compliance_recommendations(
            report['event_summary'],
            report['compliance_violations'],
            framework
        )
        
        return report

    def _check_compliance_violation(self, log_entry: Dict[str, Any], framework: str) -> bool:
        """Check if log entry indicates a compliance violation"""
        
        # Simplified compliance checking
        event_type = log_entry.get('event_type', '')
        
        if framework == 'sox':
            # Check for unauthorized access to financial systems
            if event_type == 'ACCESS_GRANTED' and log_entry.get('resource', '').startswith('financial_'):
                return True
        
        elif framework == 'pci_dss':
            # Check for unauthorized access to payment systems
            if event_type == 'ACCOUNT_COMPROMISE' and 'payment' in str(log_entry.get('data', {})):
                return True
        
        elif framework == 'gdpr':
            # Check for unauthorized personal data processing
            if event_type == 'DATA_ACCESS' and not log_entry.get('consent_verified', False):
                return True
        
        return False

    def _get_violation_type(self, log_entry: Dict[str, Any], framework: str) -> str:
        """Get violation type for compliance framework"""
        # Simplified violation type mapping
        event_type = log_entry.get('event_type', '')
        
        violation_map = {
            'sox': {
                'ACCESS_GRANTED': 'unauthorized_financial_access',
                'PRIVILEGE_ESCALATION': 'inadequate_access_control'
            },
            'pci_dss': {
                'ACCOUNT_COMPROMISE': 'cardholder_data_breach',
                'WEAK_AUTHENTICATION': 'insufficient_authentication'
            },
            'gdpr': {
                'DATA_ACCESS': 'unlawful_processing',
                'DATA_RETENTION': 'excessive_retention'
            }
        }
        
        return violation_map.get(framework, {}).get(event_type, 'general_violation')

    def _generate_compliance_recommendations(
        self,
        event_summary: Dict[str, int],
        violations: list,
        framework: str
    ) -> list:
        """Generate compliance recommendations based on audit findings"""
        
        recommendations = []
        
        # General recommendations based on event patterns
        if event_summary.get('ACTION_FAILED', 0) > event_summary.get('ACTION_EXECUTED', 0) * 0.1:
            recommendations.append(
                "High action failure rate detected. Review system reliability and error handling."
            )
        
        if event_summary.get('SUSPICIOUS_LOGIN', 0) > 10:
            recommendations.append(
                "High number of suspicious login attempts. Consider strengthening authentication requirements."
            )
        
        # Framework-specific recommendations
        if framework == 'sox' and len(violations) > 0:
            recommendations.append(
                "SOX compliance violations detected. Review financial system access controls and approval workflows."
            )
        
        elif framework == 'pci_dss' and event_summary.get('ACCOUNT_COMPROMISE', 0) > 0:
            recommendations.append(
                "Account compromise events detected. Ensure PCI DSS requirements for secure authentication are met."
            )
        
        elif framework == 'gdpr' and event_summary.get('DATA_ACCESS', 0) > 100:
            recommendations.append(
                "High volume of data access events. Verify lawful basis and data minimization principles."
            )
        
        return recommendations