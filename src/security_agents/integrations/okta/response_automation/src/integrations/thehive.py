"""
TheHive Integration

Handles integration with TheHive incident response platform for
case management and escalation workflows.
"""

import asyncio
import aiohttp
import logging
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import uuid

from ..core.response_engine import ThreatEvent, ThreatLevel


@dataclass
class HiveCase:
    """Represents a case in TheHive"""
    case_id: str
    title: str
    description: str
    severity: int
    status: str
    tags: List[str]
    created_at: datetime
    created_by: str
    assignee: Optional[str] = None
    custom_fields: Optional[Dict[str, Any]] = None


@dataclass
class HiveTask:
    """Represents a task in TheHive"""
    task_id: str
    case_id: str
    title: str
    description: str
    status: str
    assignee: Optional[str] = None
    created_at: Optional[datetime] = None


@dataclass
class HiveObservable:
    """Represents an observable in TheHive"""
    observable_id: str
    case_id: str
    data_type: str
    data: str
    message: str
    tags: List[str]
    ioc: bool = False


class TheHiveIntegration:
    """
    TheHive incident response platform integration
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize TheHive integration"""
        self.config = config
        self.url = config.get('url')
        self.api_key = config.get('api_key')
        self.case_templates = config.get('case_templates', {})
        
        if not self.url or not self.api_key:
            raise ValueError("TheHive URL and API key are required")
        
        self.session: Optional[aiohttp.ClientSession] = None
        self.logger = logging.getLogger(__name__)
        
        # Severity mapping from threat levels
        self.severity_mapping = {
            ThreatLevel.LOW: 1,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.HIGH: 3,
            ThreatLevel.CRITICAL: 4
        }
        
        self.logger.info(f"Initialized TheHive integration for {self.url}")

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
            connector = aiohttp.TCPConnector(limit=10)
            
            self.session = aiohttp.ClientSession(
                headers=headers,
                timeout=timeout,
                connector=connector
            )

    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
            self.session = None

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Make authenticated request to TheHive API"""
        
        await self._ensure_session()
        url = f"{self.url}/api{endpoint}"
        
        try:
            async with self.session.request(
                method, url, json=data, params=params
            ) as response:
                
                if response.status >= 400:
                    error_text = await response.text()
                    raise Exception(f"TheHive API error: {response.status} - {error_text}")
                
                # Handle empty responses
                if response.content_length == 0:
                    return {}
                
                response_text = await response.text()
                if not response_text:
                    return {}
                
                return json.loads(response_text)
                
        except aiohttp.ClientError as e:
            self.logger.error(f"HTTP client error: {e}")
            raise Exception(f"HTTP client error: {e}")

    async def create_case(self, case_data: Dict[str, Any]) -> str:
        """
        Create a new case in TheHive
        
        Args:
            case_data: Case information including title, description, severity, etc.
            
        Returns:
            Case ID of the created case
        """
        self.logger.info(f"Creating TheHive case: {case_data.get('title')}")
        
        try:
            # Prepare case payload
            case_payload = {
                'title': case_data['title'],
                'description': case_data['description'],
                'severity': case_data.get('severity', 2),
                'startDate': int(datetime.now().timestamp() * 1000),  # TheHive uses milliseconds
                'tags': case_data.get('tags', []),
                'flag': case_data.get('flag', False),
                'tlp': case_data.get('tlp', 2),  # TLP:AMBER by default
                'pap': case_data.get('pap', 2),  # PAP:AMBER by default
            }
            
            # Add custom fields if provided
            if 'customFields' in case_data:
                case_payload['customFields'] = case_data['customFields']
            
            # Add template if specified
            if 'template' in case_data:
                case_payload['caseTemplate'] = case_data['template']
            
            response = await self._make_request('POST', '/case', data=case_payload)
            
            case_id = response.get('_id')
            if not case_id:
                raise Exception("No case ID returned from TheHive")
            
            self.logger.info(f"Successfully created TheHive case: {case_id}")
            return case_id
            
        except Exception as e:
            self.logger.error(f"Error creating TheHive case: {e}")
            raise

    async def create_case_from_threat_event(self, threat_event: ThreatEvent, response_actions: List[Dict[str, Any]]) -> str:
        """
        Create a case from a threat event with automated response context
        """
        self.logger.info(f"Creating case for threat event: {threat_event.id}")
        
        # Determine case template based on threat type
        template = self.case_templates.get(threat_event.threat_type.lower())
        
        # Build case data
        case_data = {
            'title': f"Identity Threat: {threat_event.threat_type} - {threat_event.user_email}",
            'description': self._build_case_description(threat_event, response_actions),
            'severity': self.severity_mapping.get(threat_event.level, 2),
            'tags': self._build_case_tags(threat_event),
            'template': template,
            'customFields': {
                'threat_event_id': threat_event.id,
                'user_id': threat_event.user_id,
                'user_email': threat_event.user_email,
                'threat_type': threat_event.threat_type,
                'threat_level': threat_event.level.value,
                'source_system': threat_event.source,
                'automated_response': True,
                'actions_taken': [action.get('action_type', 'unknown') for action in response_actions],
                'ip_address': threat_event.ip_address,
                'device_id': threat_event.device_id,
                'timestamp': threat_event.timestamp.isoformat()
            }
        }
        
        # Create the case
        case_id = await self.create_case(case_data)
        
        # Add observables
        await self._add_threat_observables(case_id, threat_event)
        
        # Create initial tasks
        await self._create_investigation_tasks(case_id, threat_event, response_actions)
        
        return case_id

    def _build_case_description(self, threat_event: ThreatEvent, response_actions: List[Dict[str, Any]]) -> str:
        """Build comprehensive case description"""
        description_parts = [
            f"**Automated Identity Threat Response**",
            f"",
            f"**Threat Summary:**",
            f"- Event ID: {threat_event.id}",
            f"- Type: {threat_event.threat_type}",
            f"- Level: {threat_event.level.value}",
            f"- User: {threat_event.user_email} ({threat_event.user_id})",
            f"- Source: {threat_event.source}",
            f"- Timestamp: {threat_event.timestamp.isoformat()}",
        ]
        
        if threat_event.ip_address:
            description_parts.append(f"- Source IP: {threat_event.ip_address}")
        
        if threat_event.device_id:
            description_parts.append(f"- Device ID: {threat_event.device_id}")
        
        # Add indicators
        if threat_event.indicators:
            description_parts.extend([
                f"",
                f"**Threat Indicators:**"
            ])
            for key, value in threat_event.indicators.items():
                description_parts.append(f"- {key.replace('_', ' ').title()}: {value}")
        
        # Add automated actions taken
        if response_actions:
            description_parts.extend([
                f"",
                f"**Automated Response Actions:**"
            ])
            for i, action in enumerate(response_actions, 1):
                action_type = action.get('action_type', 'unknown')
                status = action.get('status', 'unknown')
                description_parts.append(f"{i}. {action_type.replace('_', ' ').title()} - {status}")
        
        # Add context
        if threat_event.context:
            description_parts.extend([
                f"",
                f"**Additional Context:**",
                f"```json",
                json.dumps(threat_event.context, indent=2),
                f"```"
            ])
        
        description_parts.extend([
            f"",
            f"**Next Steps:**",
            f"1. Validate automated response actions",
            f"2. Investigate root cause and attack vector",
            f"3. Check for lateral movement or persistence",
            f"4. Verify user account integrity",
            f"5. Update security policies if needed"
        ])
        
        return "\n".join(description_parts)

    def _build_case_tags(self, threat_event: ThreatEvent) -> List[str]:
        """Build appropriate tags for the case"""
        tags = [
            'automated_response',
            'identity_threat',
            threat_event.threat_type.lower(),
            threat_event.level.value.lower(),
            threat_event.source
        ]
        
        # Add user-specific tag
        if threat_event.user_email and threat_event.user_email != 'unknown':
            tags.append(f"user:{threat_event.user_email.split('@')[0]}")
        
        # Add IP-based tag if available
        if threat_event.ip_address:
            tags.append('external_ip')
        
        return tags

    async def _add_threat_observables(self, case_id: str, threat_event: ThreatEvent):
        """Add relevant observables to the case"""
        observables = []
        
        # User email observable
        if threat_event.user_email and threat_event.user_email != 'unknown':
            observables.append({
                'dataType': 'mail',
                'data': threat_event.user_email,
                'message': 'Affected user email',
                'tags': ['user', 'target'],
                'ioc': False
            })
        
        # IP address observable
        if threat_event.ip_address:
            observables.append({
                'dataType': 'ip',
                'data': threat_event.ip_address,
                'message': 'Source IP address',
                'tags': ['source_ip', 'network'],
                'ioc': True
            })
        
        # User agent observable
        if threat_event.user_agent:
            observables.append({
                'dataType': 'user-agent',
                'data': threat_event.user_agent,
                'message': 'User agent string',
                'tags': ['user_agent'],
                'ioc': False
            })
        
        # Device ID observable
        if threat_event.device_id:
            observables.append({
                'dataType': 'other',
                'data': threat_event.device_id,
                'message': 'Device identifier',
                'tags': ['device_id'],
                'ioc': False
            })
        
        # Create observables in TheHive
        for observable_data in observables:
            try:
                await self._make_request(f'/case/{case_id}/artifact', 'POST', data=observable_data)
                self.logger.debug(f"Added observable: {observable_data['dataType']} - {observable_data['data']}")
            except Exception as e:
                self.logger.warning(f"Failed to add observable {observable_data['data']}: {e}")

    async def _create_investigation_tasks(self, case_id: str, threat_event: ThreatEvent, response_actions: List[Dict[str, Any]]):
        """Create investigation tasks based on threat type"""
        tasks = []
        
        # Common tasks for all identity threats
        tasks.extend([
            {
                'title': 'Validate Automated Response',
                'description': f'Verify that automated response actions were successful:\n' + 
                             '\n'.join([f"- {action.get('action_type', 'unknown')}" for action in response_actions])
            },
            {
                'title': 'User Account Verification',
                'description': f'Verify integrity of user account {threat_event.user_email}:\n' +
                             '- Check recent login activity\n' +
                             '- Verify account permissions\n' +
                             '- Review group memberships'
            }
        ])
        
        # Threat-specific tasks
        if threat_event.threat_type == 'SUSPICIOUS_LOGIN':
            tasks.extend([
                {
                    'title': 'Geolocation Analysis',
                    'description': 'Analyze login location and compare with user\'s normal patterns'
                },
                {
                    'title': 'Device Analysis',
                    'description': 'Investigate the device used for login attempt'
                }
            ])
        
        elif threat_event.threat_type == 'PRIVILEGE_ESCALATION':
            tasks.extend([
                {
                    'title': 'Privilege Change Investigation',
                    'description': 'Investigate unauthorized privilege escalation:\n' +
                                 '- Review recent role changes\n' +
                                 '- Check who granted privileges\n' +
                                 '- Analyze actions taken with elevated privileges'
                },
                {
                    'title': 'Lateral Movement Check',
                    'description': 'Check for signs of lateral movement using elevated privileges'
                }
            ])
        
        elif threat_event.threat_type == 'ACCOUNT_COMPROMISE':
            tasks.extend([
                {
                    'title': 'Compromise Timeline',
                    'description': 'Establish timeline of account compromise and malicious activity'
                },
                {
                    'title': 'Data Access Audit',
                    'description': 'Audit what data/systems were accessed during compromise'
                },
                {
                    'title': 'Persistence Check',
                    'description': 'Check for persistence mechanisms or backdoors'
                }
            ])
        
        elif threat_event.threat_type == 'CREDENTIAL_STUFFING':
            tasks.extend([
                {
                    'title': 'Source Analysis',
                    'description': 'Analyze attack source and credential databases used'
                },
                {
                    'title': 'Scope Assessment',
                    'description': 'Determine scope of credential stuffing attack across organization'
                }
            ])
        
        # Create tasks in TheHive
        for task_data in tasks:
            try:
                task_payload = {
                    'title': task_data['title'],
                    'description': task_data['description'],
                    'status': 'Waiting',
                    'flag': False
                }
                
                await self._make_request(f'/case/{case_id}/task', 'POST', data=task_payload)
                self.logger.debug(f"Created task: {task_data['title']}")
                
            except Exception as e:
                self.logger.warning(f"Failed to create task {task_data['title']}: {e}")

    async def update_case(self, case_id: str, updates: Dict[str, Any]) -> bool:
        """Update an existing case"""
        try:
            await self._make_request(f'/case/{case_id}', 'PATCH', data=updates)
            self.logger.info(f"Updated case {case_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error updating case {case_id}: {e}")
            return False

    async def add_case_comment(self, case_id: str, comment: str) -> bool:
        """Add a comment to a case"""
        try:
            comment_data = {
                'message': comment,
                'date': int(datetime.now().timestamp() * 1000)
            }
            
            await self._make_request(f'/case/{case_id}/comment', 'POST', data=comment_data)
            self.logger.debug(f"Added comment to case {case_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding comment to case {case_id}: {e}")
            return False

    async def close_case(self, case_id: str, resolution: str, impact_status: str = "NotApplicable") -> bool:
        """Close a case with resolution"""
        try:
            close_data = {
                'status': 'Resolved',
                'resolutionStatus': resolution,
                'impactStatus': impact_status,
                'summary': f'Case resolved by automated response system. Resolution: {resolution}',
                'endDate': int(datetime.now().timestamp() * 1000)
            }
            
            await self._make_request(f'/case/{case_id}', 'PATCH', data=close_data)
            self.logger.info(f"Closed case {case_id} with resolution: {resolution}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error closing case {case_id}: {e}")
            return False

    async def get_case(self, case_id: str) -> Optional[HiveCase]:
        """Get case information"""
        try:
            response = await self._make_request(f'/case/{case_id}', 'GET')
            
            if not response:
                return None
            
            # Parse creation time
            created_at = datetime.fromtimestamp(response.get('startDate', 0) / 1000)
            
            return HiveCase(
                case_id=response.get('_id'),
                title=response.get('title', ''),
                description=response.get('description', ''),
                severity=response.get('severity', 1),
                status=response.get('status', 'Open'),
                tags=response.get('tags', []),
                created_at=created_at,
                created_by=response.get('createdBy', 'unknown'),
                assignee=response.get('assignee'),
                custom_fields=response.get('customFields')
            )
            
        except Exception as e:
            self.logger.error(f"Error getting case {case_id}: {e}")
            return None

    async def search_cases(self, query: Dict[str, Any]) -> List[HiveCase]:
        """Search for cases"""
        try:
            response = await self._make_request('/case/_search', 'POST', data={'query': query})
            
            cases = []
            for case_data in response:
                created_at = datetime.fromtimestamp(case_data.get('startDate', 0) / 1000)
                
                case = HiveCase(
                    case_id=case_data.get('_id'),
                    title=case_data.get('title', ''),
                    description=case_data.get('description', ''),
                    severity=case_data.get('severity', 1),
                    status=case_data.get('status', 'Open'),
                    tags=case_data.get('tags', []),
                    created_at=created_at,
                    created_by=case_data.get('createdBy', 'unknown'),
                    assignee=case_data.get('assignee'),
                    custom_fields=case_data.get('customFields')
                )
                cases.append(case)
            
            return cases
            
        except Exception as e:
            self.logger.error(f"Error searching cases: {e}")
            return []

    async def create_task(self, case_id: str, task_data: Dict[str, Any]) -> str:
        """Create a new task in a case"""
        try:
            task_payload = {
                'title': task_data['title'],
                'description': task_data.get('description', ''),
                'status': task_data.get('status', 'Waiting'),
                'flag': task_data.get('flag', False)
            }
            
            if 'assignee' in task_data:
                task_payload['assignee'] = task_data['assignee']
            
            response = await self._make_request(f'/case/{case_id}/task', 'POST', data=task_payload)
            
            task_id = response.get('_id')
            if task_id:
                self.logger.debug(f"Created task {task_id} in case {case_id}")
                return task_id
            else:
                raise Exception("No task ID returned")
                
        except Exception as e:
            self.logger.error(f"Error creating task in case {case_id}: {e}")
            raise

    async def update_task_status(self, task_id: str, status: str) -> bool:
        """Update task status"""
        try:
            await self._make_request(f'/case/task/{task_id}', 'PATCH', data={'status': status})
            self.logger.debug(f"Updated task {task_id} status to {status}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error updating task {task_id}: {e}")
            return False

    async def health_check(self) -> bool:
        """Perform health check on TheHive integration"""
        try:
            await self._ensure_session()
            
            # Test API connectivity
            response = await self._make_request('/status', 'GET')
            return 'versions' in response
            
        except Exception as e:
            self.logger.error(f"TheHive health check failed: {e}")
            return False