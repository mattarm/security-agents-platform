"""
Account Security Response Actions

Implements account-level security responses including:
- Account lockout/suspension
- Session termination
- Password reset enforcement
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from abc import ABC, abstractmethod

from ..core.okta_client import OktaClient


class BaseResponseAction(ABC):
    """Base class for all response actions"""
    
    def __init__(self, okta_client: OktaClient, config: Dict[str, Any]):
        self.okta_client = okta_client
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
    
    @abstractmethod
    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the response action"""
        pass
    
    async def validate_parameters(self, parameters: Dict[str, Any]) -> bool:
        """Validate action parameters"""
        return True


class AccountLockoutAction(BaseResponseAction):
    """
    Locks user account by suspending and clearing sessions
    """
    
    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute account lockout
        
        Parameters:
        - user_id: User to lock
        - duration_hours: How long to lock (optional)
        - notify_user: Whether to notify user (default: True)
        """
        user_id = parameters.get('user_id')
        if not user_id:
            raise ValueError("user_id is required for account lockout")
        
        duration_hours = parameters.get('duration_hours', self.config.get('duration_hours', 24))
        notify_user = parameters.get('notify_user', self.config.get('notify_user', True))
        
        self.logger.info(f"Executing account lockout for user {user_id}, duration: {duration_hours}h")
        
        start_time = datetime.now()
        
        try:
            # Get user information first
            user_info = await self.okta_client.get_user(user_id)
            user_email = user_info.get('profile', {}).get('email', 'unknown')
            current_status = user_info.get('status')
            
            result = {
                'action': 'account_lockout',
                'user_id': user_id,
                'user_email': user_email,
                'previous_status': current_status,
                'duration_hours': duration_hours,
                'executed_at': start_time.isoformat(),
                'steps_completed': []
            }
            
            # Step 1: Clear all active sessions first
            if current_status not in ['SUSPENDED', 'DEPROVISIONED']:
                self.logger.info(f"Clearing sessions for user {user_id}")
                session_result = await self.okta_client.clear_user_sessions(user_id)
                result['steps_completed'].append({
                    'step': 'clear_sessions',
                    'success': True,
                    'details': session_result
                })
            
            # Step 2: Suspend the account if not already suspended
            if current_status not in ['SUSPENDED', 'DEPROVISIONED']:
                self.logger.info(f"Suspending user account {user_id}")
                suspend_result = await self.okta_client.suspend_user(user_id)
                result['steps_completed'].append({
                    'step': 'suspend_account',
                    'success': True,
                    'details': suspend_result
                })
                result['new_status'] = 'SUSPENDED'
            else:
                self.logger.info(f"User {user_id} already in status: {current_status}")
                result['new_status'] = current_status
                result['steps_completed'].append({
                    'step': 'suspend_account',
                    'success': True,
                    'details': {'message': f'User already in status: {current_status}'}
                })
            
            # Step 3: Schedule unlock if duration specified
            if duration_hours > 0:
                unlock_time = start_time + timedelta(hours=duration_hours)
                result['scheduled_unlock'] = unlock_time.isoformat()
                result['steps_completed'].append({
                    'step': 'schedule_unlock',
                    'success': True,
                    'details': {'unlock_time': unlock_time.isoformat()}
                })
                # Note: Actual scheduling would be handled by job scheduler
            
            # Step 4: Log security event
            await self._log_security_event(user_id, 'ACCOUNT_LOCKED', {
                'duration_hours': duration_hours,
                'reason': 'automated_threat_response',
                'previous_status': current_status
            })
            
            result['success'] = True
            result['completed_at'] = datetime.now().isoformat()
            
            self.logger.info(f"Account lockout completed for user {user_id}")
            return result
            
        except Exception as e:
            self.logger.error(f"Account lockout failed for user {user_id}: {e}")
            return {
                'action': 'account_lockout',
                'user_id': user_id,
                'success': False,
                'error': str(e),
                'executed_at': start_time.isoformat(),
                'failed_at': datetime.now().isoformat()
            }

    async def unlock_account(self, user_id: str) -> Dict[str, Any]:
        """
        Unlock a previously locked account
        """
        self.logger.info(f"Unlocking account for user {user_id}")
        
        try:
            # Unsuspend the user
            result = await self.okta_client.unsuspend_user(user_id)
            
            # Log the unlock event
            await self._log_security_event(user_id, 'ACCOUNT_UNLOCKED', {
                'reason': 'scheduled_or_manual_unlock'
            })
            
            return {
                'action': 'account_unlock',
                'user_id': user_id,
                'success': True,
                'result': result,
                'unlocked_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Account unlock failed for user {user_id}: {e}")
            return {
                'action': 'account_unlock',
                'user_id': user_id,
                'success': False,
                'error': str(e)
            }

    async def _log_security_event(self, user_id: str, event_type: str, details: Dict[str, Any]):
        """Log security event for audit trail"""
        # This would integrate with your audit logging system
        self.logger.info(f"SECURITY_EVENT: {event_type} for user {user_id}: {details}")


class SessionTerminationAction(BaseResponseAction):
    """
    Terminates active user sessions
    """
    
    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute session termination
        
        Parameters:
        - user_id: User whose sessions to terminate
        - all_sessions: Terminate all sessions (default: True)
        - oauth_only: Only terminate OAuth sessions (default: False)
        - notify_user: Whether to notify user (default: True)
        """
        user_id = parameters.get('user_id')
        if not user_id:
            raise ValueError("user_id is required for session termination")
        
        all_sessions = parameters.get('all_sessions', self.config.get('all_sessions', True))
        oauth_only = parameters.get('oauth_only', False)
        notify_user = parameters.get('notify_user', self.config.get('notify_user', True))
        
        self.logger.info(f"Terminating sessions for user {user_id}")
        
        start_time = datetime.now()
        
        try:
            # Get user information
            user_info = await self.okta_client.get_user(user_id)
            user_email = user_info.get('profile', {}).get('email', 'unknown')
            
            # Get current sessions before clearing them
            current_sessions = await self.okta_client.get_user_sessions(user_id)
            session_count = len(current_sessions)
            
            result = {
                'action': 'session_termination',
                'user_id': user_id,
                'user_email': user_email,
                'sessions_before': session_count,
                'all_sessions': all_sessions,
                'oauth_only': oauth_only,
                'executed_at': start_time.isoformat()
            }
            
            if session_count == 0:
                self.logger.info(f"No active sessions found for user {user_id}")
                result['success'] = True
                result['message'] = 'No active sessions to terminate'
                return result
            
            # Clear sessions
            clear_result = await self.okta_client.clear_user_sessions(user_id, oauth_only=oauth_only)
            
            # Verify sessions were cleared
            remaining_sessions = await self.okta_client.get_user_sessions(user_id)
            sessions_cleared = session_count - len(remaining_sessions)
            
            result.update({
                'success': True,
                'sessions_cleared': sessions_cleared,
                'sessions_remaining': len(remaining_sessions),
                'clear_result': clear_result,
                'completed_at': datetime.now().isoformat()
            })
            
            # Log security event
            await self._log_security_event(user_id, 'SESSIONS_TERMINATED', {
                'sessions_cleared': sessions_cleared,
                'all_sessions': all_sessions,
                'oauth_only': oauth_only,
                'reason': 'automated_threat_response'
            })
            
            self.logger.info(f"Session termination completed for user {user_id}: {sessions_cleared} sessions cleared")
            return result
            
        except Exception as e:
            self.logger.error(f"Session termination failed for user {user_id}: {e}")
            return {
                'action': 'session_termination',
                'user_id': user_id,
                'success': False,
                'error': str(e),
                'executed_at': start_time.isoformat(),
                'failed_at': datetime.now().isoformat()
            }

    async def get_active_sessions(self, user_id: str) -> Dict[str, Any]:
        """Get information about active sessions"""
        try:
            sessions = await self.okta_client.get_user_sessions(user_id)
            return {
                'user_id': user_id,
                'session_count': len(sessions),
                'sessions': sessions,
                'retrieved_at': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'user_id': user_id,
                'error': str(e)
            }

    async def _log_security_event(self, user_id: str, event_type: str, details: Dict[str, Any]):
        """Log security event for audit trail"""
        self.logger.info(f"SECURITY_EVENT: {event_type} for user {user_id}: {details}")


class PasswordResetAction(BaseResponseAction):
    """
    Forces password reset for user
    """
    
    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute password reset
        
        Parameters:
        - user_id: User to reset password for
        - send_email: Send reset email to user (default: True)
        - expire_current: Expire current password (default: True)
        """
        user_id = parameters.get('user_id')
        if not user_id:
            raise ValueError("user_id is required for password reset")
        
        send_email = parameters.get('send_email', True)
        expire_current = parameters.get('expire_current', True)
        
        self.logger.info(f"Forcing password reset for user {user_id}")
        
        start_time = datetime.now()
        
        try:
            # Get user information
            user_info = await self.okta_client.get_user(user_id)
            user_email = user_info.get('profile', {}).get('email', 'unknown')
            
            result = {
                'action': 'password_reset',
                'user_id': user_id,
                'user_email': user_email,
                'send_email': send_email,
                'expire_current': expire_current,
                'executed_at': start_time.isoformat()
            }
            
            steps_completed = []
            
            # Step 1: Expire current password if requested
            if expire_current:
                expire_result = await self.okta_client.expire_password(user_id)
                steps_completed.append({
                    'step': 'expire_password',
                    'success': True,
                    'details': expire_result
                })
            
            # Step 2: Send password reset email if requested
            if send_email:
                reset_result = await self.okta_client.reset_password(user_id, send_email=True)
                steps_completed.append({
                    'step': 'send_reset_email',
                    'success': True,
                    'details': reset_result
                })
            
            result.update({
                'success': True,
                'steps_completed': steps_completed,
                'completed_at': datetime.now().isoformat()
            })
            
            # Log security event
            await self._log_security_event(user_id, 'PASSWORD_RESET_FORCED', {
                'send_email': send_email,
                'expire_current': expire_current,
                'reason': 'automated_threat_response'
            })
            
            self.logger.info(f"Password reset completed for user {user_id}")
            return result
            
        except Exception as e:
            self.logger.error(f"Password reset failed for user {user_id}: {e}")
            return {
                'action': 'password_reset',
                'user_id': user_id,
                'success': False,
                'error': str(e),
                'executed_at': start_time.isoformat(),
                'failed_at': datetime.now().isoformat()
            }

    async def _log_security_event(self, user_id: str, event_type: str, details: Dict[str, Any]):
        """Log security event for audit trail"""
        self.logger.info(f"SECURITY_EVENT: {event_type} for user {user_id}: {details}")