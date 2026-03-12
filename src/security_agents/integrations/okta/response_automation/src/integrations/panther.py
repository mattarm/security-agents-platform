"""
Panther SIEM Integration

Handles integration with Panther SIEM for receiving threat alerts
and triggering automated responses.
"""

import asyncio
import aiohttp
import logging
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import hmac
import hashlib
from urllib.parse import urlparse

from ..core.response_engine import ThreatEvent, ThreatLevel


@dataclass
class PantherAlert:
    """Represents a Panther alert"""
    alert_id: str
    rule_id: str
    rule_name: str
    severity: str
    description: str
    runbook: str
    tags: List[str]
    created_time: datetime
    events: List[Dict[str, Any]]
    destinations: List[str]
    alert_context: Dict[str, Any]


class PantherIntegration:
    """
    Panther SIEM integration for threat alert processing
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Panther integration"""
        self.config = config
        self.webhook_url = config.get('webhook_url')
        self.api_key = config.get('api_key')
        self.alert_types = config.get('alert_types', [])
        self.webhook_secret = config.get('webhook_secret')
        
        self.session: Optional[aiohttp.ClientSession] = None
        self.logger = logging.getLogger(__name__)
        
        # Threat level mapping from Panther severities
        self.severity_mapping = {
            'INFO': ThreatLevel.LOW,
            'LOW': ThreatLevel.LOW,
            'MEDIUM': ThreatLevel.MEDIUM,
            'HIGH': ThreatLevel.HIGH,
            'CRITICAL': ThreatLevel.CRITICAL
        }
        
        self.logger.info("Initialized Panther SIEM integration")

    async def __aenter__(self):
        """Async context manager entry"""
        await self._ensure_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()

    async def _ensure_session(self):
        """Ensure HTTP session is created"""
        if self.session is None:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json',
                'User-Agent': 'Identity-Threat-Response-System/1.0'
            }
            
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(headers=headers, timeout=timeout)

    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
            self.session = None

    async def process_webhook(self, payload: Dict[str, Any], headers: Dict[str, str]) -> List[ThreatEvent]:
        """
        Process incoming Panther webhook payload
        
        Args:
            payload: The webhook payload from Panther
            headers: HTTP headers from the webhook request
            
        Returns:
            List of ThreatEvent objects to be processed
        """
        self.logger.info("Processing Panther webhook payload")
        
        try:
            # Verify webhook signature if configured
            if self.webhook_secret:
                if not self._verify_webhook_signature(payload, headers):
                    raise ValueError("Invalid webhook signature")
            
            # Parse Panther alert
            alert = self._parse_panther_alert(payload)
            
            if not alert:
                self.logger.warning("No valid alert found in Panther payload")
                return []
            
            # Check if alert type is configured for processing
            if self.alert_types and alert.rule_name not in self.alert_types:
                self.logger.info(f"Alert type {alert.rule_name} not configured for processing")
                return []
            
            # Convert to threat events
            threat_events = await self._convert_to_threat_events(alert)
            
            self.logger.info(f"Converted Panther alert to {len(threat_events)} threat events")
            return threat_events
            
        except Exception as e:
            self.logger.error(f"Error processing Panther webhook: {e}")
            raise

    def _verify_webhook_signature(self, payload: Dict[str, Any], headers: Dict[str, str]) -> bool:
        """Verify webhook signature from Panther"""
        signature = headers.get('X-Panther-Signature')
        if not signature:
            return False
        
        # Calculate expected signature
        payload_json = json.dumps(payload, sort_keys=True)
        expected_signature = hmac.new(
            self.webhook_secret.encode('utf-8'),
            payload_json.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, f"sha256={expected_signature}")

    def _parse_panther_alert(self, payload: Dict[str, Any]) -> Optional[PantherAlert]:
        """Parse Panther alert from webhook payload"""
        try:
            # Panther webhook format may vary, this is a common structure
            alert_data = payload
            
            # Extract basic alert information
            alert_id = alert_data.get('alertId', alert_data.get('id'))
            if not alert_id:
                return None
            
            rule_id = alert_data.get('ruleId', '')
            rule_name = alert_data.get('ruleName', alert_data.get('title', ''))
            severity = alert_data.get('severity', 'MEDIUM')
            description = alert_data.get('description', alert_data.get('summary', ''))
            runbook = alert_data.get('runbook', alert_data.get('remediation', ''))
            tags = alert_data.get('tags', [])
            
            # Parse creation time
            created_time_str = alert_data.get('createdAt', alert_data.get('alertTime'))
            if created_time_str:
                try:
                    created_time = datetime.fromisoformat(created_time_str.replace('Z', '+00:00'))
                except:
                    created_time = datetime.now()
            else:
                created_time = datetime.now()
            
            # Extract events and context
            events = alert_data.get('events', [])
            destinations = alert_data.get('destinations', [])
            alert_context = alert_data.get('alertContext', alert_data.get('context', {}))
            
            return PantherAlert(
                alert_id=alert_id,
                rule_id=rule_id,
                rule_name=rule_name,
                severity=severity.upper(),
                description=description,
                runbook=runbook,
                tags=tags,
                created_time=created_time,
                events=events,
                destinations=destinations,
                alert_context=alert_context
            )
            
        except Exception as e:
            self.logger.error(f"Error parsing Panther alert: {e}")
            return None

    async def _convert_to_threat_events(self, alert: PantherAlert) -> List[ThreatEvent]:
        """Convert Panther alert to threat events"""
        threat_events = []
        
        # Determine threat level from severity
        threat_level = self.severity_mapping.get(alert.severity, ThreatLevel.MEDIUM)
        
        # Extract user information from events
        users_affected = self._extract_users_from_events(alert.events)
        
        if not users_affected:
            # Create a general threat event if no specific users identified
            threat_event = ThreatEvent(
                id=f"panther_{alert.alert_id}",
                source="panther",
                threat_type=self._map_rule_to_threat_type(alert.rule_name, alert.tags),
                level=threat_level,
                user_id="unknown",
                user_email="unknown",
                timestamp=alert.created_time,
                indicators=self._extract_indicators(alert),
                context={
                    'rule_id': alert.rule_id,
                    'rule_name': alert.rule_name,
                    'description': alert.description,
                    'runbook': alert.runbook,
                    'tags': alert.tags,
                    'alert_context': alert.alert_context
                }
            )
            threat_events.append(threat_event)
        else:
            # Create threat event for each affected user
            for user_info in users_affected:
                threat_event = ThreatEvent(
                    id=f"panther_{alert.alert_id}_{user_info.get('user_id', 'unknown')}",
                    source="panther",
                    threat_type=self._map_rule_to_threat_type(alert.rule_name, alert.tags),
                    level=threat_level,
                    user_id=user_info.get('user_id', 'unknown'),
                    user_email=user_info.get('user_email', 'unknown'),
                    timestamp=alert.created_time,
                    indicators=self._extract_indicators(alert),
                    context={
                        'rule_id': alert.rule_id,
                        'rule_name': alert.rule_name,
                        'description': alert.description,
                        'runbook': alert.runbook,
                        'tags': alert.tags,
                        'alert_context': alert.alert_context,
                        'user_context': user_info
                    },
                    ip_address=user_info.get('ip_address'),
                    user_agent=user_info.get('user_agent'),
                    device_id=user_info.get('device_id')
                )
                threat_events.append(threat_event)
        
        return threat_events

    def _extract_users_from_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract user information from Panther events"""
        users = []
        seen_users = set()
        
        for event in events:
            # Common field mappings for user extraction
            user_info = {}
            
            # Try various common field names
            user_id = (
                event.get('userId') or 
                event.get('user_id') or 
                event.get('p_any_userids', [None])[0] or
                event.get('actor', {}).get('id')
            )
            
            user_email = (
                event.get('userEmail') or 
                event.get('user_email') or 
                event.get('email') or
                event.get('actor', {}).get('email') or
                event.get('user', {}).get('email')
            )
            
            # IP address
            ip_address = (
                event.get('sourceIp') or 
                event.get('source_ip') or 
                event.get('client_ip') or
                event.get('p_any_ip_addresses', [None])[0]
            )
            
            # User agent
            user_agent = (
                event.get('userAgent') or 
                event.get('user_agent') or 
                event.get('client', {}).get('userAgent')
            )
            
            # Device information
            device_id = (
                event.get('deviceId') or 
                event.get('device_id') or 
                event.get('device', {}).get('id')
            )
            
            if user_id or user_email:
                # Use email as fallback for user_id if not available
                if not user_id and user_email:
                    user_id = user_email
                
                # Avoid duplicates
                user_key = f"{user_id}_{user_email}"
                if user_key not in seen_users:
                    seen_users.add(user_key)
                    
                    user_info = {
                        'user_id': user_id,
                        'user_email': user_email,
                        'ip_address': ip_address,
                        'user_agent': user_agent,
                        'device_id': device_id,
                        'source_event': event
                    }
                    users.append(user_info)
        
        return users

    def _map_rule_to_threat_type(self, rule_name: str, tags: List[str]) -> str:
        """Map Panther rule to threat type"""
        rule_name_lower = rule_name.lower()
        tags_lower = [tag.lower() for tag in tags]
        
        # Suspicious login patterns
        if any(pattern in rule_name_lower for pattern in [
            'suspicious login', 'impossible travel', 'brute force', 'failed login',
            'geographic anomaly', 'login from new location'
        ]):
            return 'SUSPICIOUS_LOGIN'
        
        # Privilege escalation patterns
        if any(pattern in rule_name_lower for pattern in [
            'privilege escalation', 'admin access', 'role change', 'permission elevation',
            'unauthorized admin', 'suspicious admin activity'
        ]):
            return 'PRIVILEGE_ESCALATION'
        
        # Account compromise patterns
        if any(pattern in rule_name_lower for pattern in [
            'account compromise', 'account takeover', 'unauthorized access',
            'suspicious activity', 'malicious activity', 'account hijack'
        ]):
            return 'ACCOUNT_COMPROMISE'
        
        # Credential stuffing patterns
        if any(pattern in rule_name_lower for pattern in [
            'credential stuffing', 'password spray', 'multiple failed logins',
            'brute force attack', 'mass login attempts'
        ]):
            return 'CREDENTIAL_STUFFING'
        
        # Check tags for additional context
        if 'credential_abuse' in tags_lower:
            return 'CREDENTIAL_STUFFING'
        elif 'privilege_abuse' in tags_lower:
            return 'PRIVILEGE_ESCALATION'
        elif 'account_abuse' in tags_lower:
            return 'ACCOUNT_COMPROMISE'
        elif 'suspicious_login' in tags_lower:
            return 'SUSPICIOUS_LOGIN'
        
        # Default to generic identity threat
        return 'IDENTITY_THREAT'

    def _extract_indicators(self, alert: PantherAlert) -> Dict[str, Any]:
        """Extract threat indicators from alert"""
        indicators = {
            'confidence': 0.7,  # Default confidence
            'event_count': len(alert.events),
            'severity': alert.severity,
            'rule_id': alert.rule_id
        }
        
        # Extract additional indicators from alert context
        context = alert.alert_context
        
        if context:
            # Common indicator fields
            indicators.update({
                'risk_score': context.get('riskScore', context.get('risk_score')),
                'anomaly_score': context.get('anomalyScore', context.get('anomaly_score')),
                'detection_count': context.get('detectionCount', context.get('detection_count')),
                'time_window': context.get('timeWindow', context.get('time_window')),
                'geographic_risk': context.get('geographicRisk', context.get('geographic_risk')),
                'device_risk': context.get('deviceRisk', context.get('device_risk'))
            })
        
        # Adjust confidence based on severity and context
        if alert.severity == 'CRITICAL':
            indicators['confidence'] = 0.95
        elif alert.severity == 'HIGH':
            indicators['confidence'] = 0.85
        elif alert.severity == 'MEDIUM':
            indicators['confidence'] = 0.7
        else:
            indicators['confidence'] = 0.5
        
        # Increase confidence if multiple indicators present
        if indicators.get('risk_score', 0) > 80:
            indicators['confidence'] = min(0.95, indicators['confidence'] + 0.1)
        
        if indicators.get('detection_count', 0) > 5:
            indicators['confidence'] = min(0.95, indicators['confidence'] + 0.05)
        
        return indicators

    async def send_alert_update(self, alert_id: str, status: str, comment: str = "") -> bool:
        """Send alert status update back to Panther"""
        if not self.webhook_url:
            self.logger.warning("No webhook URL configured for alert updates")
            return False
        
        try:
            await self._ensure_session()
            
            update_data = {
                'alertId': alert_id,
                'status': status,
                'comment': comment,
                'updatedBy': 'Identity-Threat-Response-System',
                'updatedAt': datetime.now().isoformat()
            }
            
            # Note: Actual Panther API endpoint for updates may differ
            update_url = f"{self.webhook_url}/alerts/{alert_id}/status"
            
            async with self.session.put(update_url, json=update_data) as response:
                if response.status == 200:
                    self.logger.info(f"Successfully updated Panther alert {alert_id}")
                    return True
                else:
                    self.logger.error(f"Failed to update Panther alert {alert_id}: {response.status}")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Error updating Panther alert {alert_id}: {e}")
            return False

    async def query_alerts(
        self, 
        start_time: datetime,
        end_time: Optional[datetime] = None,
        rule_ids: Optional[List[str]] = None,
        severity: Optional[str] = None
    ) -> List[PantherAlert]:
        """Query Panther for alerts within time range"""
        if not self.api_key:
            raise ValueError("API key required for Panther queries")
        
        try:
            await self._ensure_session()
            
            params = {
                'startTime': start_time.isoformat(),
            }
            
            if end_time:
                params['endTime'] = end_time.isoformat()
            if rule_ids:
                params['ruleIds'] = ','.join(rule_ids)
            if severity:
                params['severity'] = severity
            
            # Note: Actual Panther API endpoint for queries may differ
            query_url = f"{self.webhook_url}/alerts"
            
            async with self.session.get(query_url, params=params) as response:
                if response.status == 200:
                    alerts_data = await response.json()
                    alerts = []
                    
                    for alert_data in alerts_data.get('alerts', []):
                        alert = self._parse_panther_alert(alert_data)
                        if alert:
                            alerts.append(alert)
                    
                    return alerts
                else:
                    raise Exception(f"Panther API query failed: {response.status}")
                    
        except Exception as e:
            self.logger.error(f"Error querying Panther alerts: {e}")
            raise

    async def health_check(self) -> bool:
        """Perform health check on Panther integration"""
        if not self.api_key or not self.webhook_url:
            return False
        
        try:
            await self._ensure_session()
            
            # Simple connectivity test
            health_url = f"{self.webhook_url}/health"
            
            async with self.session.get(health_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                return response.status == 200
                
        except Exception as e:
            self.logger.error(f"Panther health check failed: {e}")
            return False