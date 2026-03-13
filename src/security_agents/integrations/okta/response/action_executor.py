"""
Action Executor for Okta Security Response

Orchestrates automated response actions with approval workflows,
rollback capabilities, and comprehensive audit logging.
"""

import uuid
import json
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field
from collections import defaultdict
import asyncio
from concurrent.futures import ThreadPoolExecutor

import structlog

from ..analytics.threat_detector import ThreatAlert
from ..analytics.rules_engine import RuleMatch
from .okta_actions import OktaResponseActions
from .notification_manager import NotificationManager
from ..okta_security.exceptions import ResponseActionError

logger = structlog.get_logger()


class ActionStatus(Enum):
    """Status of response action"""
    PENDING = "pending"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ROLLED_BACK = "rolled_back"


class ActionSeverity(Enum):
    """Severity levels for actions requiring approval"""
    LOW = "low"           # Auto-approve
    MEDIUM = "medium"     # Require approval  
    HIGH = "high"         # Require senior approval
    CRITICAL = "critical" # Require emergency approval


@dataclass
class ResponseAction:
    """Represents a security response action"""
    action_id: str
    action_type: str
    description: str
    severity: ActionSeverity
    target_entities: Dict[str, List[str]]  # entity_type -> list of IDs
    parameters: Dict[str, Any]
    
    # State tracking
    status: ActionStatus = ActionStatus.PENDING
    created_at: datetime = field(default_factory=datetime.utcnow)
    approved_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    approved_by: Optional[str] = None
    
    # Source information
    triggered_by_alert: Optional[str] = None
    triggered_by_rule: Optional[str] = None
    
    # Execution details
    execution_result: Optional[Dict] = None
    error_message: Optional[str] = None
    rollback_info: Optional[Dict] = None
    
    # Audit trail
    audit_log: List[Dict] = field(default_factory=list)
    
    def add_audit_entry(self, action: str, details: Dict = None, user: str = None):
        """Add entry to audit log"""
        entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'action': action,
            'user': user,
            'details': details or {}
        }
        self.audit_log.append(entry)


class ActionExecutor:
    """
    Orchestrates automated security response actions with:
    - Approval workflows for high-impact actions
    - Rollback capabilities for reversible actions
    - Comprehensive audit logging
    - Rate limiting and safety checks
    """
    
    def __init__(
        self,
        okta_client,
        notification_manager: NotificationManager = None,
        require_approval: bool = True,
        auto_approve_low_severity: bool = True
    ):
        self.okta_actions = OktaResponseActions(okta_client)
        self.notification_manager = notification_manager
        self.require_approval = require_approval
        self.auto_approve_low_severity = auto_approve_low_severity
        
        # Action tracking
        self.pending_actions: Dict[str, ResponseAction] = {}
        self.completed_actions: Dict[str, ResponseAction] = {}
        
        # Action registry
        self.action_registry = self._build_action_registry()
        
        # Execution settings
        self.max_concurrent_actions = 5
        self.action_timeout = timedelta(minutes=10)
        
        # Threading for async execution
        self.executor = ThreadPoolExecutor(max_workers=self.max_concurrent_actions)
        
        # Safety limits
        self.rate_limits = {
            'suspend_user': {'max_per_hour': 10, 'current': 0, 'reset_time': datetime.utcnow()},
            'block_ip': {'max_per_hour': 50, 'current': 0, 'reset_time': datetime.utcnow()},
            'disable_application': {'max_per_hour': 5, 'current': 0, 'reset_time': datetime.utcnow()}
        }
        
        logger.info("Action executor initialized", 
                   require_approval=require_approval,
                   auto_approve_low=auto_approve_low_severity)
    
    def _build_action_registry(self) -> Dict[str, Dict]:
        """Build registry of available response actions"""
        return {
            'suspend_user': {
                'description': 'Suspend user account',
                'severity': ActionSeverity.HIGH,
                'reversible': True,
                'handler': self.okta_actions.suspend_user,
                'rollback_handler': self.okta_actions.unsuspend_user,
                'required_params': ['user_id'],
                'optional_params': ['reason']
            },
            'clear_user_sessions': {
                'description': 'Clear all user sessions',
                'severity': ActionSeverity.MEDIUM,
                'reversible': False,
                'handler': self.okta_actions.clear_user_sessions,
                'required_params': ['user_id'],
                'optional_params': ['reason']
            },
            'reset_user_mfa': {
                'description': 'Reset user MFA factors',
                'severity': ActionSeverity.HIGH,
                'reversible': False,
                'handler': self.okta_actions.reset_user_mfa,
                'required_params': ['user_id'],
                'optional_params': ['reason']
            },
            'enforce_mfa': {
                'description': 'Enforce MFA for user',
                'severity': ActionSeverity.MEDIUM,
                'reversible': True,
                'handler': self.okta_actions.enforce_mfa,
                'rollback_handler': self.okta_actions.remove_mfa_enforcement,
                'required_params': ['user_id'],
                'optional_params': []
            },
            'block_ip': {
                'description': 'Block IP address',
                'severity': ActionSeverity.LOW,
                'reversible': True,
                'handler': self.okta_actions.block_ip_address,
                'rollback_handler': self.okta_actions.unblock_ip_address,
                'required_params': ['ip_address'],
                'optional_params': ['reason', 'duration']
            },
            'disable_application': {
                'description': 'Disable application access',
                'severity': ActionSeverity.CRITICAL,
                'reversible': True,
                'handler': self.okta_actions.disable_application,
                'rollback_handler': self.okta_actions.enable_application,
                'required_params': ['app_id'],
                'optional_params': ['reason']
            },
            'remove_user_from_group': {
                'description': 'Remove user from security group',
                'severity': ActionSeverity.HIGH,
                'reversible': True,
                'handler': self.okta_actions.remove_user_from_group,
                'rollback_handler': self.okta_actions.add_user_to_group,
                'required_params': ['user_id', 'group_id'],
                'optional_params': ['reason']
            },
            'send_notification': {
                'description': 'Send security notification',
                'severity': ActionSeverity.LOW,
                'reversible': False,
                'handler': self._send_notification,
                'required_params': ['recipient', 'message'],
                'optional_params': ['severity', 'alert_id']
            }
        }
    
    def process_alert(self, alert: ThreatAlert, auto_execute: bool = False) -> List[ResponseAction]:
        """Process threat alert and create response actions"""
        actions = []
        
        try:
            # Determine recommended actions based on alert type and severity
            recommended_actions = self._determine_actions_for_alert(alert)
            
            for action_spec in recommended_actions:
                action = self._create_response_action(
                    action_type=action_spec['type'],
                    parameters=action_spec['parameters'],
                    triggered_by_alert=alert.alert_id,
                    description=action_spec.get('description')
                )
                
                actions.append(action)
                
                # Add to pending actions
                self.pending_actions[action.action_id] = action
                
                # Auto-execute if appropriate
                if auto_execute and self._should_auto_execute(action):
                    self.execute_action(action.action_id)
            
            logger.info("Alert processed for response actions",
                       alert_id=alert.alert_id,
                       actions_created=len(actions))
            
        except Exception as e:
            logger.error("Failed to process alert for actions", 
                        alert_id=alert.alert_id, 
                        error=str(e))
            raise ResponseActionError(f"Alert processing failed: {e}")
        
        return actions
    
    def process_rule_match(self, match: RuleMatch, auto_execute: bool = False) -> List[ResponseAction]:
        """Process rule match and create response actions"""
        actions = []
        
        try:
            # Get rule configuration for response actions
            if hasattr(match, 'auto_response') and match.auto_response:
                response_actions = getattr(match, 'response_actions', [])
                
                for action_type in response_actions:
                    if action_type in self.action_registry:
                        # Build parameters from match data
                        parameters = self._build_action_parameters(action_type, match)
                        
                        action = self._create_response_action(
                            action_type=action_type,
                            parameters=parameters,
                            triggered_by_rule=match.rule_id
                        )
                        
                        actions.append(action)
                        self.pending_actions[action.action_id] = action
                        
                        # Auto-execute if appropriate
                        if auto_execute and self._should_auto_execute(action):
                            self.execute_action(action.action_id)
            
            logger.info("Rule match processed for response actions",
                       rule_id=match.rule_id,
                       actions_created=len(actions))
            
        except Exception as e:
            logger.error("Failed to process rule match for actions",
                        rule_id=match.rule_id,
                        error=str(e))
        
        return actions
    
    def _determine_actions_for_alert(self, alert: ThreatAlert) -> List[Dict]:
        """Determine appropriate response actions for alert"""
        actions = []
        
        # Actions based on threat type
        if alert.threat_type == "Brute_Force_Attack":
            # Suspend affected users and block source IPs
            for user_id in alert.affected_users:
                actions.append({
                    'type': 'suspend_user',
                    'parameters': {'user_id': user_id, 'reason': f'Brute force attack detected: {alert.alert_id}'},
                    'description': f'Suspend user {user_id} due to brute force attack'
                })
                
                actions.append({
                    'type': 'clear_user_sessions',
                    'parameters': {'user_id': user_id, 'reason': f'Security incident: {alert.alert_id}'},
                    'description': f'Clear sessions for user {user_id}'
                })
            
            # Block IPs if available in events
            source_ips = set()
            for event in alert.events:
                ip = event.get('client', {}).get('ipAddress')
                if ip:
                    source_ips.add(ip)
            
            for ip in source_ips:
                actions.append({
                    'type': 'block_ip',
                    'parameters': {'ip_address': ip, 'reason': f'Brute force source: {alert.alert_id}'},
                    'description': f'Block IP {ip} for brute force activity'
                })
        
        elif alert.threat_type == "Session_Hijacking":
            # Clear sessions and enforce MFA
            for user_id in alert.affected_users:
                actions.append({
                    'type': 'clear_user_sessions',
                    'parameters': {'user_id': user_id, 'reason': f'Session hijacking detected: {alert.alert_id}'},
                    'description': f'Clear sessions for user {user_id} due to hijacking'
                })
                
                actions.append({
                    'type': 'enforce_mfa',
                    'parameters': {'user_id': user_id},
                    'description': f'Enforce MFA for user {user_id}'
                })
        
        elif alert.threat_type == "Impossible_Travel":
            # Clear sessions and require re-authentication
            for user_id in alert.affected_users:
                actions.append({
                    'type': 'clear_user_sessions',
                    'parameters': {'user_id': user_id, 'reason': f'Impossible travel detected: {alert.alert_id}'},
                    'description': f'Clear sessions for user {user_id} due to impossible travel'
                })
        
        elif alert.threat_type == "Privilege_Escalation":
            # Review and potentially remove privileges
            for user_id in alert.affected_users:
                actions.append({
                    'type': 'send_notification',
                    'parameters': {
                        'recipient': 'security-team@company.com',
                        'message': f'Privilege escalation detected for user {user_id}. Manual review required.',
                        'severity': 'HIGH',
                        'alert_id': alert.alert_id
                    },
                    'description': 'Notify security team of privilege escalation'
                })
        
        # Always send notification for high-severity alerts
        if alert.severity in ['HIGH', 'CRITICAL']:
            actions.append({
                'type': 'send_notification',
                'parameters': {
                    'recipient': 'security-team@company.com',
                    'message': f'High-severity security alert: {alert.description}',
                    'severity': alert.severity,
                    'alert_id': alert.alert_id
                },
                'description': 'Notify security team of high-severity alert'
            })
        
        return actions
    
    def _build_action_parameters(self, action_type: str, match: RuleMatch) -> Dict:
        """Build action parameters from rule match data"""
        parameters = {}
        
        # Extract common parameters from match
        affected_entities = match.affected_entities
        
        if action_type == 'suspend_user' and 'users' in affected_entities:
            parameters['user_id'] = affected_entities['users'][0]  # Take first user
            parameters['reason'] = f'Rule violation: {match.rule_name}'
        
        elif action_type == 'block_ip' and 'ip_addresses' in affected_entities:
            parameters['ip_address'] = affected_entities['ip_addresses'][0]
            parameters['reason'] = f'Rule violation: {match.rule_name}'
        
        elif action_type == 'clear_user_sessions' and 'users' in affected_entities:
            parameters['user_id'] = affected_entities['users'][0]
            parameters['reason'] = f'Security rule triggered: {match.rule_name}'
        
        return parameters
    
    def _create_response_action(
        self,
        action_type: str,
        parameters: Dict,
        triggered_by_alert: str = None,
        triggered_by_rule: str = None,
        description: str = None
    ) -> ResponseAction:
        """Create response action object"""
        
        if action_type not in self.action_registry:
            raise ResponseActionError(f"Unknown action type: {action_type}")
        
        action_config = self.action_registry[action_type]
        
        # Validate required parameters
        required_params = action_config.get('required_params', [])
        for param in required_params:
            if param not in parameters:
                raise ResponseActionError(f"Missing required parameter '{param}' for action '{action_type}'")
        
        # Extract target entities
        target_entities = {}
        if 'user_id' in parameters:
            target_entities['users'] = [parameters['user_id']]
        if 'ip_address' in parameters:
            target_entities['ip_addresses'] = [parameters['ip_address']]
        if 'app_id' in parameters:
            target_entities['applications'] = [parameters['app_id']]
        if 'group_id' in parameters:
            target_entities['groups'] = [parameters['group_id']]
        
        action = ResponseAction(
            action_id=str(uuid.uuid4()),
            action_type=action_type,
            description=description or action_config['description'],
            severity=action_config['severity'],
            target_entities=target_entities,
            parameters=parameters,
            triggered_by_alert=triggered_by_alert,
            triggered_by_rule=triggered_by_rule
        )
        
        action.add_audit_entry('created', {
            'action_type': action_type,
            'parameters': parameters,
            'triggered_by': triggered_by_alert or triggered_by_rule
        })
        
        return action
    
    def approve_action(self, action_id: str, approved_by: str) -> bool:
        """Approve a pending action"""
        if action_id not in self.pending_actions:
            logger.warning("Action not found for approval", action_id=action_id)
            return False
        
        action = self.pending_actions[action_id]
        
        if action.status != ActionStatus.PENDING:
            logger.warning("Action not in pending status", action_id=action_id, status=action.status.value)
            return False
        
        action.status = ActionStatus.APPROVED
        action.approved_at = datetime.utcnow()
        action.approved_by = approved_by
        
        action.add_audit_entry('approved', {'approved_by': approved_by}, approved_by)
        
        logger.info("Action approved", action_id=action_id, approved_by=approved_by)
        return True
    
    def execute_action(self, action_id: str, executor_user: str = 'system') -> bool:
        """Execute an approved action"""
        if action_id not in self.pending_actions:
            logger.error("Action not found for execution", action_id=action_id)
            return False
        
        action = self.pending_actions[action_id]
        
        # Check if action is approved (or auto-approvable)
        if action.status == ActionStatus.PENDING:
            if not self._should_auto_execute(action):
                logger.warning("Action requires approval before execution", action_id=action_id)
                return False
            else:
                # Auto-approve
                action.status = ActionStatus.APPROVED
                action.approved_at = datetime.utcnow()
                action.approved_by = 'system'
        
        if action.status != ActionStatus.APPROVED:
            logger.warning("Action not approved for execution", action_id=action_id, status=action.status.value)
            return False
        
        # Check rate limits
        if not self._check_rate_limit(action.action_type):
            logger.warning("Rate limit exceeded for action", action_id=action_id, action_type=action.action_type)
            return False
        
        # Execute in background
        self.executor.submit(self._execute_action_async, action, executor_user)
        
        return True
    
    def _execute_action_async(self, action: ResponseAction, executor_user: str):
        """Execute action asynchronously"""
        try:
            action.status = ActionStatus.EXECUTING
            action.executed_at = datetime.utcnow()
            action.add_audit_entry('execution_started', {'executor': executor_user}, executor_user)
            
            logger.info("Executing action", action_id=action.action_id, type=action.action_type)
            
            # Get action handler
            action_config = self.action_registry[action.action_type]
            handler = action_config['handler']
            
            # Execute the action
            result = handler(**action.parameters)
            
            # Record success
            action.status = ActionStatus.COMPLETED
            action.completed_at = datetime.utcnow()
            action.execution_result = result
            
            action.add_audit_entry('execution_completed', {
                'result': result,
                'duration_seconds': (action.completed_at - action.executed_at).total_seconds()
            }, executor_user)
            
            # Update rate limit counter
            self._update_rate_limit(action.action_type)
            
            # Move to completed actions
            self.completed_actions[action.action_id] = action
            if action.action_id in self.pending_actions:
                del self.pending_actions[action.action_id]
            
            # Send notification if configured
            if self.notification_manager:
                self.notification_manager.send_action_notification(action, 'completed')
            
            logger.info("Action execution completed", action_id=action.action_id, result=result)
            
        except Exception as e:
            # Record failure
            action.status = ActionStatus.FAILED
            action.error_message = str(e)
            action.add_audit_entry('execution_failed', {'error': str(e)}, executor_user)
            
            logger.error("Action execution failed", action_id=action.action_id, error=str(e))
            
            # Send failure notification
            if self.notification_manager:
                self.notification_manager.send_action_notification(action, 'failed')
    
    def rollback_action(self, action_id: str, rollback_user: str) -> bool:
        """Rollback a completed action if reversible"""
        if action_id not in self.completed_actions:
            logger.error("Action not found for rollback", action_id=action_id)
            return False
        
        action = self.completed_actions[action_id]
        
        if action.status != ActionStatus.COMPLETED:
            logger.warning("Action not in completed status", action_id=action_id, status=action.status.value)
            return False
        
        action_config = self.action_registry[action.action_type]
        if not action_config.get('reversible', False):
            logger.warning("Action is not reversible", action_id=action_id, action_type=action.action_type)
            return False
        
        rollback_handler = action_config.get('rollback_handler')
        if not rollback_handler:
            logger.error("No rollback handler configured", action_id=action_id)
            return False
        
        try:
            # Execute rollback
            action.add_audit_entry('rollback_started', {'rollback_user': rollback_user}, rollback_user)
            
            # Build rollback parameters (often same as original parameters)
            rollback_params = action.parameters.copy()
            rollback_result = rollback_handler(**rollback_params)
            
            action.status = ActionStatus.ROLLED_BACK
            action.rollback_info = {
                'rolled_back_at': datetime.utcnow().isoformat(),
                'rolled_back_by': rollback_user,
                'rollback_result': rollback_result
            }
            
            action.add_audit_entry('rollback_completed', {
                'result': rollback_result,
                'rolled_back_by': rollback_user
            }, rollback_user)
            
            logger.info("Action rolled back successfully", action_id=action_id)
            
            # Send notification
            if self.notification_manager:
                self.notification_manager.send_action_notification(action, 'rolled_back')
            
            return True
            
        except Exception as e:
            action.add_audit_entry('rollback_failed', {'error': str(e)}, rollback_user)
            logger.error("Action rollback failed", action_id=action_id, error=str(e))
            return False
    
    def cancel_action(self, action_id: str, cancelled_by: str) -> bool:
        """Cancel a pending action"""
        if action_id not in self.pending_actions:
            logger.warning("Action not found for cancellation", action_id=action_id)
            return False
        
        action = self.pending_actions[action_id]
        
        if action.status == ActionStatus.EXECUTING:
            logger.warning("Cannot cancel executing action", action_id=action_id)
            return False
        
        action.status = ActionStatus.CANCELLED
        action.add_audit_entry('cancelled', {'cancelled_by': cancelled_by}, cancelled_by)
        
        # Move to completed actions for audit trail
        self.completed_actions[action_id] = action
        del self.pending_actions[action_id]
        
        logger.info("Action cancelled", action_id=action_id, cancelled_by=cancelled_by)
        return True
    
    def _should_auto_execute(self, action: ResponseAction) -> bool:
        """Determine if action should be auto-executed"""
        if not self.auto_approve_low_severity:
            return False
        
        return action.severity == ActionSeverity.LOW
    
    def _check_rate_limit(self, action_type: str) -> bool:
        """Check if action is within rate limits"""
        if action_type not in self.rate_limits:
            return True
        
        limit_info = self.rate_limits[action_type]
        
        # Reset counter if hour has passed
        if datetime.utcnow() - limit_info['reset_time'] > timedelta(hours=1):
            limit_info['current'] = 0
            limit_info['reset_time'] = datetime.utcnow()
        
        return limit_info['current'] < limit_info['max_per_hour']
    
    def _update_rate_limit(self, action_type: str):
        """Update rate limit counter after successful action"""
        if action_type in self.rate_limits:
            self.rate_limits[action_type]['current'] += 1
    
    def _send_notification(self, recipient: str, message: str, severity: str = 'INFO', alert_id: str = None) -> Dict:
        """Send notification (internal handler)"""
        if self.notification_manager:
            return self.notification_manager.send_notification(recipient, message, severity, alert_id)
        else:
            logger.info("Notification would be sent", recipient=recipient, message=message)
            return {'status': 'simulated', 'recipient': recipient}
    
    def get_action_status(self, action_id: str) -> Optional[Dict]:
        """Get action status and details"""
        action = self.pending_actions.get(action_id) or self.completed_actions.get(action_id)
        
        if not action:
            return None
        
        return {
            'action_id': action.action_id,
            'action_type': action.action_type,
            'description': action.description,
            'severity': action.severity.value,
            'status': action.status.value,
            'target_entities': action.target_entities,
            'created_at': action.created_at.isoformat(),
            'approved_at': action.approved_at.isoformat() if action.approved_at else None,
            'executed_at': action.executed_at.isoformat() if action.executed_at else None,
            'completed_at': action.completed_at.isoformat() if action.completed_at else None,
            'approved_by': action.approved_by,
            'error_message': action.error_message,
            'execution_result': action.execution_result,
            'rollback_info': action.rollback_info,
            'audit_log': action.audit_log
        }
    
    def get_pending_actions(self) -> List[Dict]:
        """Get all pending actions requiring approval"""
        return [self.get_action_status(action_id) for action_id in self.pending_actions.keys()]
    
    def get_action_statistics(self) -> Dict:
        """Get action execution statistics"""
        total_actions = len(self.pending_actions) + len(self.completed_actions)
        
        status_counts = defaultdict(int)
        for action in list(self.pending_actions.values()) + list(self.completed_actions.values()):
            status_counts[action.status.value] += 1
        
        action_type_counts = defaultdict(int)
        for action in list(self.pending_actions.values()) + list(self.completed_actions.values()):
            action_type_counts[action.action_type] += 1
        
        return {
            'total_actions': total_actions,
            'pending_actions': len(self.pending_actions),
            'completed_actions': len(self.completed_actions),
            'status_distribution': dict(status_counts),
            'action_type_distribution': dict(action_type_counts),
            'rate_limit_status': {
                action_type: {
                    'current': info['current'],
                    'max_per_hour': info['max_per_hour'],
                    'reset_time': info['reset_time'].isoformat()
                }
                for action_type, info in self.rate_limits.items()
            }
        }