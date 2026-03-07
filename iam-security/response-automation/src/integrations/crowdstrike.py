"""
CrowdStrike Falcon Fusion Integration

Handles integration with CrowdStrike Falcon platform for automated
workflow execution and threat response.
"""

import asyncio
import aiohttp
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import uuid
import base64

from ..core.response_engine import ThreatEvent, ThreatLevel


@dataclass
class FusionWorkflow:
    """Represents a Falcon Fusion workflow"""
    workflow_id: str
    name: str
    description: str
    trigger_type: str
    parameters: Dict[str, Any]
    status: str


@dataclass
class WorkflowExecution:
    """Represents a workflow execution"""
    execution_id: str
    workflow_id: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime]
    result: Optional[Dict[str, Any]]
    error: Optional[str]


class CrowdStrikeIntegration:
    """
    CrowdStrike Falcon platform integration for automated workflows
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize CrowdStrike integration"""
        self.config = config
        self.client_id = config.get('client_id')
        self.client_secret = config.get('client_secret')
        self.base_url = config.get('base_url', 'https://api.crowdstrike.com')
        self.falcon_fusion = config.get('falcon_fusion', {})
        
        self.session: Optional[aiohttp.ClientSession] = None
        self.access_token: Optional[str] = None
        self.token_expires_at: Optional[datetime] = None
        
        self.logger = logging.getLogger(__name__)
        
        # Threat level mapping for CrowdStrike severity
        self.severity_mapping = {
            'low': ThreatLevel.LOW,
            'medium': ThreatLevel.MEDIUM,
            'high': ThreatLevel.HIGH,
            'critical': ThreatLevel.CRITICAL
        }
        
        # Workflow mappings from config
        self.workflow_ids = self.falcon_fusion.get('workflow_ids', {})
        
        self.logger.info("Initialized CrowdStrike Falcon integration")

    async def __aenter__(self):
        """Async context manager entry"""
        await self._ensure_session()
        await self._authenticate()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()

    async def _ensure_session(self):
        """Ensure HTTP session is created"""
        if self.session is None:
            timeout = aiohttp.ClientTimeout(total=30)
            connector = aiohttp.TCPConnector(limit=10)
            
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector
            )

    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
            self.session = None

    async def _authenticate(self):
        """Authenticate with CrowdStrike API and get access token"""
        if not self.client_id or not self.client_secret:
            raise ValueError("CrowdStrike client_id and client_secret are required")
        
        # Check if current token is still valid
        if (self.access_token and self.token_expires_at and 
            datetime.now() < self.token_expires_at - timedelta(minutes=5)):
            return
        
        await self._ensure_session()
        
        try:
            # Prepare OAuth2 client credentials request
            auth_url = f"{self.base_url}/oauth2/token"
            
            # Basic auth header
            credentials = f"{self.client_id}:{self.client_secret}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            
            headers = {
                'Authorization': f'Basic {encoded_credentials}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            data = {
                'grant_type': 'client_credentials'
            }
            
            async with self.session.post(auth_url, headers=headers, data=data) as response:
                if response.status == 200:
                    auth_data = await response.json()
                    self.access_token = auth_data['access_token']
                    expires_in = auth_data.get('expires_in', 3600)  # Default 1 hour
                    self.token_expires_at = datetime.now() + timedelta(seconds=expires_in)
                    
                    self.logger.info("Successfully authenticated with CrowdStrike")
                else:
                    error_text = await response.text()
                    raise Exception(f"CrowdStrike authentication failed: {response.status} - {error_text}")
                    
        except Exception as e:
            self.logger.error(f"Error authenticating with CrowdStrike: {e}")
            raise

    async def _make_authenticated_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Make authenticated request to CrowdStrike API"""
        
        await self._authenticate()  # Ensure valid token
        
        url = f"{self.base_url}{endpoint}"
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        try:
            async with self.session.request(
                method, url, json=data, params=params, headers=headers
            ) as response:
                
                if response.status == 401:
                    # Token expired, refresh and retry once
                    self.access_token = None
                    await self._authenticate()
                    headers['Authorization'] = f'Bearer {self.access_token}'
                    
                    async with self.session.request(
                        method, url, json=data, params=params, headers=headers
                    ) as retry_response:
                        
                        if retry_response.status >= 400:
                            error_text = await retry_response.text()
                            raise Exception(f"CrowdStrike API error: {retry_response.status} - {error_text}")
                        
                        return await retry_response.json() if retry_response.content_length else {}
                
                elif response.status >= 400:
                    error_text = await response.text()
                    raise Exception(f"CrowdStrike API error: {response.status} - {error_text}")
                
                return await response.json() if response.content_length else {}
                
        except aiohttp.ClientError as e:
            self.logger.error(f"HTTP client error: {e}")
            raise Exception(f"HTTP client error: {e}")

    async def trigger_workflow(
        self,
        workflow_type: str,
        threat_event: ThreatEvent,
        additional_params: Optional[Dict[str, Any]] = None
    ) -> WorkflowExecution:
        """
        Trigger a Falcon Fusion workflow for threat response
        
        Args:
            workflow_type: Type of workflow ('account_compromise', 'privilege_abuse', etc.)
            threat_event: The threat event triggering the workflow
            additional_params: Additional parameters for the workflow
            
        Returns:
            WorkflowExecution object with execution details
        """
        workflow_id = self.workflow_ids.get(workflow_type)
        if not workflow_id:
            raise ValueError(f"No workflow configured for type: {workflow_type}")
        
        self.logger.info(f"Triggering CrowdStrike workflow {workflow_id} for threat {threat_event.id}")
        
        # Prepare workflow parameters
        workflow_params = {
            'threat_event_id': threat_event.id,
            'user_id': threat_event.user_id,
            'user_email': threat_event.user_email,
            'threat_type': threat_event.threat_type,
            'threat_level': threat_event.level.value,
            'timestamp': threat_event.timestamp.isoformat(),
            'source_system': threat_event.source,
            'indicators': threat_event.indicators,
            'context': threat_event.context
        }
        
        # Add IP and device info if available
        if threat_event.ip_address:
            workflow_params['ip_address'] = threat_event.ip_address
        if threat_event.user_agent:
            workflow_params['user_agent'] = threat_event.user_agent
        if threat_event.device_id:
            workflow_params['device_id'] = threat_event.device_id
        
        # Merge additional parameters
        if additional_params:
            workflow_params.update(additional_params)
        
        try:
            # Execute workflow via CrowdStrike API
            execution_data = {
                'workflow_id': workflow_id,
                'parameters': workflow_params,
                'metadata': {
                    'triggered_by': 'Identity-Threat-Response-System',
                    'trigger_reason': f'Automated response to {threat_event.threat_type}',
                    'correlation_id': threat_event.id
                }
            }
            
            response = await self._make_authenticated_request(
                'POST',
                '/workflows/entities/execute/v1',
                data=execution_data
            )
            
            # Parse execution response
            execution_id = response.get('resources', [{}])[0].get('execution_id', str(uuid.uuid4()))
            
            execution = WorkflowExecution(
                execution_id=execution_id,
                workflow_id=workflow_id,
                status='started',
                started_at=datetime.now(),
                completed_at=None,
                result=None,
                error=None
            )
            
            self.logger.info(f"Successfully triggered workflow {workflow_id}, execution ID: {execution_id}")
            return execution
            
        except Exception as e:
            self.logger.error(f"Error triggering workflow {workflow_id}: {e}")
            
            # Return failed execution
            return WorkflowExecution(
                execution_id=str(uuid.uuid4()),
                workflow_id=workflow_id,
                status='failed',
                started_at=datetime.now(),
                completed_at=datetime.now(),
                result=None,
                error=str(e)
            )

    async def get_workflow_status(self, execution_id: str) -> WorkflowExecution:
        """Get status of workflow execution"""
        try:
            response = await self._make_authenticated_request(
                'GET',
                f'/workflows/entities/executions/v1',
                params={'ids': execution_id}
            )
            
            executions = response.get('resources', [])
            if not executions:
                raise Exception(f"Execution {execution_id} not found")
            
            execution_data = executions[0]
            
            # Parse execution status
            status = execution_data.get('status', 'unknown').lower()
            started_at_str = execution_data.get('created_timestamp')
            completed_at_str = execution_data.get('updated_timestamp')
            
            # Parse timestamps
            started_at = datetime.fromisoformat(started_at_str.replace('Z', '+00:00')) if started_at_str else datetime.now()
            completed_at = None
            if completed_at_str and status in ['completed', 'failed', 'cancelled']:
                completed_at = datetime.fromisoformat(completed_at_str.replace('Z', '+00:00'))
            
            return WorkflowExecution(
                execution_id=execution_id,
                workflow_id=execution_data.get('workflow_id', 'unknown'),
                status=status,
                started_at=started_at,
                completed_at=completed_at,
                result=execution_data.get('result'),
                error=execution_data.get('error')
            )
            
        except Exception as e:
            self.logger.error(f"Error getting workflow status {execution_id}: {e}")
            raise

    async def cancel_workflow(self, execution_id: str) -> bool:
        """Cancel running workflow execution"""
        try:
            response = await self._make_authenticated_request(
                'POST',
                f'/workflows/entities/executions/cancel/v1',
                data={'ids': [execution_id]}
            )
            
            # Check if cancellation was successful
            errors = response.get('errors', [])
            if errors:
                self.logger.error(f"Error cancelling workflow {execution_id}: {errors}")
                return False
            
            self.logger.info(f"Successfully cancelled workflow execution {execution_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error cancelling workflow {execution_id}: {e}")
            return False

    async def list_workflows(self) -> List[FusionWorkflow]:
        """List available Falcon Fusion workflows"""
        try:
            response = await self._make_authenticated_request(
                'GET',
                '/workflows/entities/definitions/v1',
                params={'limit': 100}
            )
            
            workflows = []
            for workflow_data in response.get('resources', []):
                workflow = FusionWorkflow(
                    workflow_id=workflow_data.get('id'),
                    name=workflow_data.get('name', ''),
                    description=workflow_data.get('description', ''),
                    trigger_type=workflow_data.get('trigger_type', 'manual'),
                    parameters=workflow_data.get('parameters', {}),
                    status=workflow_data.get('status', 'unknown')
                )
                workflows.append(workflow)
            
            return workflows
            
        except Exception as e:
            self.logger.error(f"Error listing workflows: {e}")
            return []

    async def create_custom_workflow(
        self,
        name: str,
        description: str,
        steps: List[Dict[str, Any]]
    ) -> str:
        """Create a custom workflow for identity response"""
        try:
            workflow_definition = {
                'name': name,
                'description': description,
                'category': 'Identity Response',
                'trigger_type': 'api',
                'steps': steps,
                'metadata': {
                    'created_by': 'Identity-Threat-Response-System',
                    'version': '1.0'
                }
            }
            
            response = await self._make_authenticated_request(
                'POST',
                '/workflows/entities/definitions/v1',
                data=workflow_definition
            )
            
            workflow_id = response.get('resources', [{}])[0].get('id')
            if workflow_id:
                self.logger.info(f"Created custom workflow: {name} ({workflow_id})")
                return workflow_id
            else:
                raise Exception("No workflow ID returned from creation")
                
        except Exception as e:
            self.logger.error(f"Error creating custom workflow {name}: {e}")
            raise

    async def process_detection_alert(self, detection_data: Dict[str, Any]) -> List[ThreatEvent]:
        """
        Process CrowdStrike detection alert and convert to threat events
        
        Args:
            detection_data: Detection data from CrowdStrike
            
        Returns:
            List of ThreatEvent objects
        """
        self.logger.info("Processing CrowdStrike detection alert")
        
        try:
            # Extract basic detection information
            detection_id = detection_data.get('detection_id', detection_data.get('id'))
            if not detection_id:
                return []
            
            # Map detection to threat type
            behavior_name = detection_data.get('behaviors', [{}])[0].get('behavior_name', '')
            threat_type = self._map_detection_to_threat_type(behavior_name, detection_data)
            
            # Determine threat level
            max_severity = detection_data.get('max_severity', 0)
            threat_level = self._map_severity_to_threat_level(max_severity)
            
            # Extract user information
            user_info = self._extract_user_from_detection(detection_data)
            
            # Create threat event
            threat_event = ThreatEvent(
                id=f"crowdstrike_{detection_id}",
                source="crowdstrike",
                threat_type=threat_type,
                level=threat_level,
                user_id=user_info.get('user_id', 'unknown'),
                user_email=user_info.get('user_email', 'unknown'),
                timestamp=self._parse_detection_timestamp(detection_data),
                indicators=self._extract_detection_indicators(detection_data),
                context={
                    'detection_id': detection_id,
                    'device_id': detection_data.get('device', {}).get('device_id'),
                    'hostname': detection_data.get('device', {}).get('hostname'),
                    'behaviors': detection_data.get('behaviors', []),
                    'tactics': detection_data.get('tactics', []),
                    'techniques': detection_data.get('techniques', [])
                },
                ip_address=user_info.get('ip_address'),
                user_agent=user_info.get('user_agent'),
                device_id=detection_data.get('device', {}).get('device_id')
            )
            
            return [threat_event]
            
        except Exception as e:
            self.logger.error(f"Error processing CrowdStrike detection: {e}")
            return []

    def _map_detection_to_threat_type(self, behavior_name: str, detection_data: Dict[str, Any]) -> str:
        """Map CrowdStrike detection to threat type"""
        behavior_name_lower = behavior_name.lower()
        
        # Look for credential-related behaviors
        if any(pattern in behavior_name_lower for pattern in [
            'credential', 'password', 'login', 'authentication', 'logon'
        ]):
            if 'brute' in behavior_name_lower or 'multiple' in behavior_name_lower:
                return 'CREDENTIAL_STUFFING'
            else:
                return 'SUSPICIOUS_LOGIN'
        
        # Look for privilege-related behaviors
        if any(pattern in behavior_name_lower for pattern in [
            'privilege', 'admin', 'elevation', 'escalation', 'sudo', 'runas'
        ]):
            return 'PRIVILEGE_ESCALATION'
        
        # Look for account compromise indicators
        if any(pattern in behavior_name_lower for pattern in [
            'compromise', 'takeover', 'unauthorized', 'suspicious', 'malicious'
        ]):
            return 'ACCOUNT_COMPROMISE'
        
        # Check tactics for additional context
        tactics = detection_data.get('tactics', [])
        if 'Credential Access' in tactics:
            return 'CREDENTIAL_STUFFING'
        elif 'Privilege Escalation' in tactics:
            return 'PRIVILEGE_ESCALATION'
        elif 'Initial Access' in tactics:
            return 'SUSPICIOUS_LOGIN'
        
        return 'IDENTITY_THREAT'

    def _map_severity_to_threat_level(self, severity: int) -> ThreatLevel:
        """Map CrowdStrike severity score to threat level"""
        if severity >= 80:
            return ThreatLevel.CRITICAL
        elif severity >= 60:
            return ThreatLevel.HIGH
        elif severity >= 40:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW

    def _extract_user_from_detection(self, detection_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract user information from CrowdStrike detection"""
        user_info = {}
        
        # Check various fields for user information
        device = detection_data.get('device', {})
        behaviors = detection_data.get('behaviors', [])
        
        # User ID/email from device
        user_info['user_id'] = device.get('user_id') or device.get('username')
        user_info['user_email'] = device.get('user_email')
        
        # Check behaviors for user context
        for behavior in behaviors:
            if 'user' in behavior.get('user_name', '').lower():
                user_info['user_id'] = behavior.get('user_name')
            
            # Extract IP address
            if 'remote_ip' in behavior:
                user_info['ip_address'] = behavior['remote_ip']
        
        # Device information
        user_info['device_id'] = device.get('device_id')
        user_info['hostname'] = device.get('hostname')
        
        return user_info

    def _parse_detection_timestamp(self, detection_data: Dict[str, Any]) -> datetime:
        """Parse detection timestamp"""
        timestamp_str = (
            detection_data.get('created_timestamp') or
            detection_data.get('first_behavior') or
            detection_data.get('timestamp')
        )
        
        if timestamp_str:
            try:
                return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            except:
                pass
        
        return datetime.now()

    def _extract_detection_indicators(self, detection_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract threat indicators from detection"""
        indicators = {
            'confidence': detection_data.get('confidence', 70) / 100.0,
            'severity': detection_data.get('max_severity', 0),
            'behavior_count': len(detection_data.get('behaviors', [])),
            'tactic_count': len(detection_data.get('tactics', [])),
            'technique_count': len(detection_data.get('techniques', []))
        }
        
        # Extract additional context
        if detection_data.get('status') == 'true_positive':
            indicators['confidence'] = min(0.95, indicators['confidence'] + 0.2)
        
        return indicators

    async def health_check(self) -> bool:
        """Perform health check on CrowdStrike integration"""
        try:
            await self._authenticate()
            
            # Simple API test
            response = await self._make_authenticated_request('GET', '/workflows/entities/definitions/v1?limit=1')
            return 'resources' in response
            
        except Exception as e:
            self.logger.error(f"CrowdStrike health check failed: {e}")
            return False