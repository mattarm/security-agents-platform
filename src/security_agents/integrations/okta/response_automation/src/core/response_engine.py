"""
Identity Threat Response Engine

Central orchestration system for automated identity threat response.
Receives threats from SIEM, determines appropriate actions, and coordinates response.
"""

import asyncio
import logging
import time
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any
import yaml
import json
import uuid

from .okta_client import OktaClient
from .audit_logger import AuditLogger
from .circuit_breaker import CircuitBreaker
from ..response_actions import (
    AccountLockoutAction, MFAStepUpAction, SessionTerminationAction,
    RoleRevocationAction, DeviceDeregistrationAction, BulkAccountAction
)
from ..integrations.panther import PantherIntegration
from ..integrations.crowdstrike import CrowdStrikeIntegration
from ..integrations.thehive import TheHiveIntegration
from ..incident.notification_system import NotificationSystem


class ThreatLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ResponseStatus(Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"


@dataclass
class ThreatEvent:
    """Represents an identity threat event from SIEM"""
    id: str
    source: str  # panther, crowdstrike, manual
    threat_type: str
    level: ThreatLevel
    user_id: str
    user_email: str
    timestamp: datetime
    indicators: Dict[str, Any]
    context: Dict[str, Any]
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    device_id: Optional[str] = None


@dataclass
class ResponseAction:
    """Represents a response action to be taken"""
    id: str
    threat_event_id: str
    action_type: str
    parameters: Dict[str, Any]
    status: ResponseStatus
    created_at: datetime
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    requires_approval: bool = False
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None


class IdentityThreatResponseEngine:
    """
    Main response engine for identity threat automation
    """
    
    def __init__(self, config_path: str):
        """Initialize the response engine"""
        self.config = self._load_config(config_path)
        self.logger = logging.getLogger(__name__)
        
        # Initialize core components
        self.okta_client = OktaClient(self.config['okta'])
        self.audit_logger = AuditLogger(self.config['audit'])
        self.circuit_breaker = CircuitBreaker(self.config['fail_safe']['circuit_breaker'])
        
        # Initialize integrations
        self.panther = PantherIntegration(self.config['siem']['panther']) if self.config['siem']['panther']['enabled'] else None
        self.crowdstrike = CrowdStrikeIntegration(self.config['siem']['crowdstrike']) if self.config['siem']['crowdstrike']['enabled'] else None
        self.thehive = TheHiveIntegration(self.config['thehive'])
        
        # Initialize notification system
        self.notification_system = NotificationSystem(self.config['notifications'])
        
        # Initialize response actions
        self.response_actions = {
            'account_lockout': AccountLockoutAction(self.okta_client, self.config['response_actions']['account_lockout']),
            'mfa_step_up': MFAStepUpAction(self.okta_client, self.config['response_actions']['mfa_step_up']),
            'session_termination': SessionTerminationAction(self.okta_client, self.config['response_actions']['session_termination']),
            'role_revocation': RoleRevocationAction(self.okta_client, self.config['response_actions']['role_revocation']),
            'device_deregistration': DeviceDeregistrationAction(self.okta_client, self.config['response_actions']['device_deregistration']),
            'bulk_account_action': BulkAccountAction(self.okta_client, {})
        }
        
        # State tracking
        self.pending_actions: Dict[str, ResponseAction] = {}
        self.active_responses: Dict[str, List[ResponseAction]] = {}
        self.last_health_check = datetime.now()
        
        # Rate limiting
        self.action_timestamps: List[datetime] = []
        
        self.logger.info("Identity Threat Response Engine initialized")

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as file:
                return yaml.safe_load(file)
        except Exception as e:
            raise RuntimeError(f"Failed to load configuration: {e}")

    async def process_threat_event(self, event: ThreatEvent) -> List[ResponseAction]:
        """
        Main entry point for processing threat events
        """
        self.logger.info(f"Processing threat event {event.id}: {event.threat_type} for user {event.user_email}")
        
        # Log the threat event
        await self.audit_logger.log_event("THREAT_RECEIVED", {
            "event_id": event.id,
            "threat_type": event.threat_type,
            "level": event.level.value,
            "user_id": event.user_id,
            "source": event.source
        })
        
        try:
            # Check circuit breaker
            if not await self.circuit_breaker.can_execute():
                self.logger.warning("Circuit breaker open, rejecting threat processing")
                return []
            
            # Check fail-safe mechanisms
            if await self._check_emergency_stop():
                self.logger.warning("Emergency stop activated, halting processing")
                return []
            
            # Determine appropriate response actions
            planned_actions = await self._plan_response(event)
            
            # Check rate limits
            if not await self._check_rate_limits(len(planned_actions)):
                self.logger.warning("Rate limit exceeded, deferring actions")
                return []
            
            # Execute planned actions
            executed_actions = []
            for action in planned_actions:
                try:
                    if action.requires_approval:
                        # Queue for approval
                        self.pending_actions[action.id] = action
                        await self.notification_system.send_approval_request(action)
                        self.logger.info(f"Action {action.id} queued for approval")
                    else:
                        # Execute immediately
                        result = await self._execute_action(action)
                        executed_actions.append(result)
                        
                except Exception as e:
                    self.logger.error(f"Failed to execute action {action.id}: {e}")
                    action.status = ResponseStatus.FAILED
                    action.error = str(e)
                    await self.circuit_breaker.record_failure()
            
            # Store active responses
            self.active_responses[event.id] = executed_actions + list(self.pending_actions.values())
            
            # Create TheHive case if needed
            if event.level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                await self._create_incident_case(event, executed_actions)
            
            # Send notifications
            await self.notification_system.send_threat_notification(event, executed_actions)
            
            return executed_actions
            
        except Exception as e:
            self.logger.error(f"Error processing threat event {event.id}: {e}")
            await self.circuit_breaker.record_failure()
            raise

    async def _plan_response(self, event: ThreatEvent) -> List[ResponseAction]:
        """
        Determine appropriate response actions based on threat type and level
        """
        actions = []
        
        # Base response actions by threat type
        if event.threat_type == "SUSPICIOUS_LOGIN":
            actions.extend(await self._plan_suspicious_login_response(event))
        elif event.threat_type == "PRIVILEGE_ESCALATION":
            actions.extend(await self._plan_privilege_abuse_response(event))
        elif event.threat_type == "ACCOUNT_COMPROMISE":
            actions.extend(await self._plan_account_compromise_response(event))
        elif event.threat_type == "CREDENTIAL_STUFFING":
            actions.extend(await self._plan_credential_stuffing_response(event))
        else:
            # Default response for unknown threats
            actions.extend(await self._plan_default_response(event))
        
        # Escalate actions based on threat level
        if event.level == ThreatLevel.CRITICAL:
            actions.extend(await self._plan_critical_escalation(event))
        elif event.level == ThreatLevel.HIGH:
            actions.extend(await self._plan_high_escalation(event))
        
        return actions

    async def _plan_suspicious_login_response(self, event: ThreatEvent) -> List[ResponseAction]:
        """Plan response for suspicious login attempts"""
        actions = []
        
        # Always require MFA step-up for suspicious logins
        actions.append(ResponseAction(
            id=str(uuid.uuid4()),
            threat_event_id=event.id,
            action_type="mfa_step_up",
            parameters={"user_id": event.user_id, "duration_hours": 24},
            status=ResponseStatus.PENDING,
            created_at=datetime.now(),
            requires_approval=False
        ))
        
        # Terminate active sessions if high confidence
        if event.indicators.get('confidence', 0) > 0.8:
            actions.append(ResponseAction(
                id=str(uuid.uuid4()),
                threat_event_id=event.id,
                action_type="session_termination",
                parameters={"user_id": event.user_id, "all_sessions": True},
                status=ResponseStatus.PENDING,
                created_at=datetime.now(),
                requires_approval=False
            ))
        
        return actions

    async def _plan_privilege_abuse_response(self, event: ThreatEvent) -> List[ResponseAction]:
        """Plan response for privilege escalation/abuse"""
        actions = []
        
        # Immediately revoke elevated privileges
        actions.append(ResponseAction(
            id=str(uuid.uuid4()),
            threat_event_id=event.id,
            action_type="role_revocation",
            parameters={
                "user_id": event.user_id,
                "preserve_basic_access": True,
                "temporary_hours": 72
            },
            status=ResponseStatus.PENDING,
            created_at=datetime.now(),
            requires_approval=True  # Privilege changes require approval
        ))
        
        # Terminate sessions to force re-authentication
        actions.append(ResponseAction(
            id=str(uuid.uuid4()),
            threat_event_id=event.id,
            action_type="session_termination",
            parameters={"user_id": event.user_id, "all_sessions": True},
            status=ResponseStatus.PENDING,
            created_at=datetime.now(),
            requires_approval=False
        ))
        
        return actions

    async def _plan_account_compromise_response(self, event: ThreatEvent) -> List[ResponseAction]:
        """Plan response for account compromise"""
        actions = []
        
        # Immediately lock the account
        actions.append(ResponseAction(
            id=str(uuid.uuid4()),
            threat_event_id=event.id,
            action_type="account_lockout",
            parameters={"user_id": event.user_id, "duration_hours": 24},
            status=ResponseStatus.PENDING,
            created_at=datetime.now(),
            requires_approval=False
        ))
        
        # Terminate all sessions
        actions.append(ResponseAction(
            id=str(uuid.uuid4()),
            threat_event_id=event.id,
            action_type="session_termination",
            parameters={"user_id": event.user_id, "all_sessions": True},
            status=ResponseStatus.PENDING,
            created_at=datetime.now(),
            requires_approval=False
        ))
        
        # Deregister devices if device_id available
        if event.device_id:
            actions.append(ResponseAction(
                id=str(uuid.uuid4()),
                threat_event_id=event.id,
                action_type="device_deregistration",
                parameters={
                    "user_id": event.user_id,
                    "device_id": event.device_id,
                    "require_re_enrollment": True
                },
                status=ResponseStatus.PENDING,
                created_at=datetime.now(),
                requires_approval=False
            ))
        
        return actions

    async def _plan_credential_stuffing_response(self, event: ThreatEvent) -> List[ResponseAction]:
        """Plan response for credential stuffing attacks"""
        actions = []
        
        # Account lockout with shorter duration
        actions.append(ResponseAction(
            id=str(uuid.uuid4()),
            threat_event_id=event.id,
            action_type="account_lockout",
            parameters={"user_id": event.user_id, "duration_hours": 4},
            status=ResponseStatus.PENDING,
            created_at=datetime.now(),
            requires_approval=False
        ))
        
        # Force MFA enrollment/step-up
        actions.append(ResponseAction(
            id=str(uuid.uuid4()),
            threat_event_id=event.id,
            action_type="mfa_step_up",
            parameters={"user_id": event.user_id, "duration_hours": 168},
            status=ResponseStatus.PENDING,
            created_at=datetime.now(),
            requires_approval=False
        ))
        
        return actions

    async def _plan_default_response(self, event: ThreatEvent) -> List[ResponseAction]:
        """Default response for unknown threat types"""
        actions = []
        
        # Conservative response - MFA step-up only
        actions.append(ResponseAction(
            id=str(uuid.uuid4()),
            threat_event_id=event.id,
            action_type="mfa_step_up",
            parameters={"user_id": event.user_id, "duration_hours": 48},
            status=ResponseStatus.PENDING,
            created_at=datetime.now(),
            requires_approval=False
        ))
        
        return actions

    async def _plan_critical_escalation(self, event: ThreatEvent) -> List[ResponseAction]:
        """Additional actions for critical threats"""
        # For now, critical escalation is handled through notifications
        # Could add bulk actions, network isolation, etc.
        return []

    async def _plan_high_escalation(self, event: ThreatEvent) -> List[ResponseAction]:
        """Additional actions for high-level threats"""
        # For now, high escalation is handled through notifications
        return []

    async def _execute_action(self, action: ResponseAction) -> ResponseAction:
        """Execute a specific response action"""
        action.status = ResponseStatus.IN_PROGRESS
        action.executed_at = datetime.now()
        
        try:
            # Get the appropriate action handler
            handler = self.response_actions.get(action.action_type)
            if not handler:
                raise ValueError(f"Unknown action type: {action.action_type}")
            
            # Execute the action
            result = await handler.execute(action.parameters)
            
            # Update action status
            action.status = ResponseStatus.COMPLETED
            action.completed_at = datetime.now()
            action.result = result
            
            # Log successful execution
            await self.audit_logger.log_event("ACTION_EXECUTED", {
                "action_id": action.id,
                "action_type": action.action_type,
                "threat_event_id": action.threat_event_id,
                "result": result
            })
            
            await self.circuit_breaker.record_success()
            
        except Exception as e:
            action.status = ResponseStatus.FAILED
            action.error = str(e)
            action.completed_at = datetime.now()
            
            # Log failure
            await self.audit_logger.log_event("ACTION_FAILED", {
                "action_id": action.id,
                "action_type": action.action_type,
                "threat_event_id": action.threat_event_id,
                "error": str(e)
            })
            
            raise
        
        return action

    async def approve_action(self, action_id: str, approver: str) -> bool:
        """Approve a pending action"""
        if action_id not in self.pending_actions:
            return False
        
        action = self.pending_actions[action_id]
        action.approved_by = approver
        action.approved_at = datetime.now()
        
        try:
            # Execute the approved action
            result = await self._execute_action(action)
            
            # Remove from pending
            del self.pending_actions[action_id]
            
            # Log approval
            await self.audit_logger.log_event("ACTION_APPROVED", {
                "action_id": action_id,
                "approver": approver,
                "action_type": action.action_type
            })
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to execute approved action {action_id}: {e}")
            return False

    async def _check_emergency_stop(self) -> bool:
        """Check if emergency stop is activated"""
        stop_file = self.config['fail_safe']['emergency_stop']['stop_file']
        try:
            with open(stop_file, 'r'):
                return True
        except FileNotFoundError:
            return False

    async def _check_rate_limits(self, action_count: int) -> bool:
        """Check if rate limits would be exceeded"""
        now = datetime.now()
        
        # Clean old timestamps
        minute_ago = now - timedelta(minutes=1)
        self.action_timestamps = [ts for ts in self.action_timestamps if ts > minute_ago]
        
        # Check rate limit
        if len(self.action_timestamps) + action_count > self.config['rate_limiting']['actions_per_minute']:
            return False
        
        return True

    async def _create_incident_case(self, event: ThreatEvent, actions: List[ResponseAction]):
        """Create incident case in TheHive"""
        try:
            case_data = {
                "title": f"Identity Threat: {event.threat_type} - {event.user_email}",
                "description": f"Automated response to {event.threat_type} for user {event.user_email}",
                "severity": 3 if event.level == ThreatLevel.CRITICAL else 2,
                "tags": ["automated_response", event.threat_type.lower(), "identity_threat"],
                "customFields": {
                    "threat_event_id": event.id,
                    "user_id": event.user_id,
                    "source_system": event.source,
                    "actions_taken": [action.action_type for action in actions]
                }
            }
            
            case_id = await self.thehive.create_case(case_data)
            self.logger.info(f"Created TheHive case {case_id} for threat event {event.id}")
            
        except Exception as e:
            self.logger.error(f"Failed to create TheHive case: {e}")

    async def get_response_status(self, threat_event_id: str) -> Dict[str, Any]:
        """Get status of response actions for a threat event"""
        if threat_event_id not in self.active_responses:
            return {"error": "Threat event not found"}
        
        actions = self.active_responses[threat_event_id]
        return {
            "threat_event_id": threat_event_id,
            "total_actions": len(actions),
            "completed": len([a for a in actions if a.status == ResponseStatus.COMPLETED]),
            "failed": len([a for a in actions if a.status == ResponseStatus.FAILED]),
            "pending": len([a for a in actions if a.status == ResponseStatus.PENDING]),
            "in_progress": len([a for a in actions if a.status == ResponseStatus.IN_PROGRESS]),
            "requires_approval": len([a for a in actions if a.status == ResponseStatus.REQUIRES_APPROVAL]),
            "actions": [asdict(action) for action in actions]
        }

    async def health_check(self) -> Dict[str, Any]:
        """Perform system health check"""
        self.last_health_check = datetime.now()
        
        health = {
            "status": "healthy",
            "timestamp": self.last_health_check.isoformat(),
            "components": {},
            "metrics": {
                "pending_actions": len(self.pending_actions),
                "active_responses": len(self.active_responses),
                "circuit_breaker_state": await self.circuit_breaker.get_state()
            }
        }
        
        # Check Okta connectivity
        try:
            await self.okta_client.health_check()
            health["components"]["okta"] = "healthy"
        except Exception as e:
            health["components"]["okta"] = f"unhealthy: {e}"
            health["status"] = "degraded"
        
        # Check SIEM integrations
        if self.panther:
            try:
                await self.panther.health_check()
                health["components"]["panther"] = "healthy"
            except Exception as e:
                health["components"]["panther"] = f"unhealthy: {e}"
                health["status"] = "degraded"
        
        return health