"""
Okta-Specific Response Actions

Direct Okta API integration for security response actions including
user management, session control, and access restrictions.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import time

import structlog

from ..okta_security.exceptions import ResponseActionError

logger = structlog.get_logger()


class OktaResponseActions:
    """
    Okta-specific security response actions using the Okta API.
    
    Provides high-level security operations with proper error handling,
    validation, and audit logging.
    """
    
    def __init__(self, okta_client):
        self.okta_client = okta_client
        
        # Track blocked IPs (since Okta doesn't have native IP blocking)
        self.blocked_ips = {}
        
        logger.info("Okta response actions initialized")
    
    def suspend_user(self, user_id: str, reason: str = "Security incident") -> Dict:
        """
        Suspend user account
        
        Args:
            user_id: Okta user ID
            reason: Reason for suspension
            
        Returns:
            Dict with result details
        """
        try:
            logger.info("Suspending user", user_id=user_id, reason=reason)
            
            # Get user details first for audit
            user_info = self.okta_client.get_user(user_id)
            
            # Suspend the user
            success = self.okta_client.suspend_user(user_id, reason)
            
            if success:
                result = {
                    'action': 'suspend_user',
                    'user_id': user_id,
                    'user_email': user_info.get('profile', {}).get('email'),
                    'reason': reason,
                    'status': 'success',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                logger.info("User suspended successfully", **result)
                return result
            else:
                raise ResponseActionError(f"Failed to suspend user {user_id}")
                
        except Exception as e:
            error_msg = f"Failed to suspend user {user_id}: {e}"
            logger.error("User suspension failed", user_id=user_id, error=str(e))
            raise ResponseActionError(error_msg)
    
    def unsuspend_user(self, user_id: str, reason: str = "Incident resolved") -> Dict:
        """
        Unsuspend user account (rollback)
        
        Args:
            user_id: Okta user ID
            reason: Reason for unsuspension
            
        Returns:
            Dict with result details
        """
        try:
            logger.info("Unsuspending user", user_id=user_id, reason=reason)
            
            # Unsuspend the user
            response = self.okta_client._make_request(
                'POST', 
                f'/users/{user_id}/lifecycle/unsuspend',
                data={'reason': reason}
            )
            
            if response.status_code == 200:
                result = {
                    'action': 'unsuspend_user',
                    'user_id': user_id,
                    'reason': reason,
                    'status': 'success',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                logger.info("User unsuspended successfully", **result)
                return result
            else:
                raise ResponseActionError(f"Failed to unsuspend user {user_id}")
                
        except Exception as e:
            error_msg = f"Failed to unsuspend user {user_id}: {e}"
            logger.error("User unsuspension failed", user_id=user_id, error=str(e))
            raise ResponseActionError(error_msg)
    
    def clear_user_sessions(self, user_id: str, reason: str = "Security incident") -> Dict:
        """
        Clear all user sessions
        
        Args:
            user_id: Okta user ID
            reason: Reason for clearing sessions
            
        Returns:
            Dict with result details
        """
        try:
            logger.info("Clearing user sessions", user_id=user_id, reason=reason)
            
            # Get current sessions for audit
            sessions = self.okta_client.get_user_sessions(user_id)
            session_count = len(sessions)
            
            # Clear all sessions
            success = self.okta_client.clear_user_sessions(user_id)
            
            if success:
                result = {
                    'action': 'clear_user_sessions',
                    'user_id': user_id,
                    'sessions_cleared': session_count,
                    'reason': reason,
                    'status': 'success',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                logger.info("User sessions cleared successfully", **result)
                return result
            else:
                raise ResponseActionError(f"Failed to clear sessions for user {user_id}")
                
        except Exception as e:
            error_msg = f"Failed to clear sessions for user {user_id}: {e}"
            logger.error("Session clearing failed", user_id=user_id, error=str(e))
            raise ResponseActionError(error_msg)
    
    def reset_user_mfa(self, user_id: str, reason: str = "Security incident") -> Dict:
        """
        Reset user MFA factors
        
        Args:
            user_id: Okta user ID
            reason: Reason for MFA reset
            
        Returns:
            Dict with result details
        """
        try:
            logger.info("Resetting user MFA", user_id=user_id, reason=reason)
            
            # Get current factors for audit
            factors_response = self.okta_client._make_request('GET', f'/users/{user_id}/factors')
            factors = factors_response.json() if factors_response.status_code == 200 else []
            factor_count = len(factors)
            
            # Reset MFA factors
            success = self.okta_client.reset_user_mfa(user_id)
            
            if success:
                result = {
                    'action': 'reset_user_mfa',
                    'user_id': user_id,
                    'factors_reset': factor_count,
                    'reason': reason,
                    'status': 'success',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                logger.info("User MFA reset successfully", **result)
                return result
            else:
                raise ResponseActionError(f"Failed to reset MFA for user {user_id}")
                
        except Exception as e:
            error_msg = f"Failed to reset MFA for user {user_id}: {e}"
            logger.error("MFA reset failed", user_id=user_id, error=str(e))
            raise ResponseActionError(error_msg)
    
    def enforce_mfa(self, user_id: str) -> Dict:
        """
        Enforce MFA for user by adding to MFA-required group
        
        Args:
            user_id: Okta user ID
            
        Returns:
            Dict with result details
        """
        try:
            logger.info("Enforcing MFA for user", user_id=user_id)
            
            # Find or create MFA enforcement group
            mfa_group_id = self._get_or_create_mfa_group()
            
            # Add user to MFA group
            response = self.okta_client._make_request(
                'PUT',
                f'/groups/{mfa_group_id}/users/{user_id}'
            )
            
            if response.status_code in [200, 204]:
                result = {
                    'action': 'enforce_mfa',
                    'user_id': user_id,
                    'mfa_group_id': mfa_group_id,
                    'status': 'success',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                logger.info("MFA enforced for user", **result)
                return result
            else:
                raise ResponseActionError(f"Failed to add user {user_id} to MFA group")
                
        except Exception as e:
            error_msg = f"Failed to enforce MFA for user {user_id}: {e}"
            logger.error("MFA enforcement failed", user_id=user_id, error=str(e))
            raise ResponseActionError(error_msg)
    
    def remove_mfa_enforcement(self, user_id: str) -> Dict:
        """
        Remove MFA enforcement for user (rollback)
        
        Args:
            user_id: Okta user ID
            
        Returns:
            Dict with result details
        """
        try:
            logger.info("Removing MFA enforcement for user", user_id=user_id)
            
            # Find MFA enforcement group
            mfa_group_id = self._get_or_create_mfa_group()
            
            # Remove user from MFA group
            response = self.okta_client._make_request(
                'DELETE',
                f'/groups/{mfa_group_id}/users/{user_id}'
            )
            
            if response.status_code in [200, 204, 404]:  # 404 is OK if not in group
                result = {
                    'action': 'remove_mfa_enforcement',
                    'user_id': user_id,
                    'mfa_group_id': mfa_group_id,
                    'status': 'success',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                logger.info("MFA enforcement removed for user", **result)
                return result
            else:
                raise ResponseActionError(f"Failed to remove user {user_id} from MFA group")
                
        except Exception as e:
            error_msg = f"Failed to remove MFA enforcement for user {user_id}: {e}"
            logger.error("MFA enforcement removal failed", user_id=user_id, error=str(e))
            raise ResponseActionError(error_msg)
    
    def block_ip_address(
        self, 
        ip_address: str, 
        reason: str = "Security incident",
        duration: int = 3600  # 1 hour default
    ) -> Dict:
        """
        Block IP address (simulated - Okta doesn't have native IP blocking)
        
        Args:
            ip_address: IP address to block
            reason: Reason for blocking
            duration: Duration in seconds
            
        Returns:
            Dict with result details
        """
        try:
            logger.info("Blocking IP address", ip_address=ip_address, reason=reason, duration=duration)
            
            # Since Okta doesn't have native IP blocking, we simulate it
            # In practice, this would integrate with network security tools
            
            block_until = datetime.utcnow() + timedelta(seconds=duration)
            
            self.blocked_ips[ip_address] = {
                'reason': reason,
                'blocked_at': datetime.utcnow().isoformat(),
                'block_until': block_until.isoformat(),
                'duration': duration
            }
            
            result = {
                'action': 'block_ip_address',
                'ip_address': ip_address,
                'reason': reason,
                'duration': duration,
                'block_until': block_until.isoformat(),
                'status': 'success',
                'note': 'IP blocking simulated - integrate with network security tools for real blocking',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            logger.info("IP address blocked (simulated)", **result)
            return result
            
        except Exception as e:
            error_msg = f"Failed to block IP {ip_address}: {e}"
            logger.error("IP blocking failed", ip_address=ip_address, error=str(e))
            raise ResponseActionError(error_msg)
    
    def unblock_ip_address(self, ip_address: str) -> Dict:
        """
        Unblock IP address (rollback)
        
        Args:
            ip_address: IP address to unblock
            
        Returns:
            Dict with result details
        """
        try:
            logger.info("Unblocking IP address", ip_address=ip_address)
            
            # Remove from blocked IPs
            if ip_address in self.blocked_ips:
                del self.blocked_ips[ip_address]
            
            result = {
                'action': 'unblock_ip_address',
                'ip_address': ip_address,
                'status': 'success',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            logger.info("IP address unblocked", **result)
            return result
            
        except Exception as e:
            error_msg = f"Failed to unblock IP {ip_address}: {e}"
            logger.error("IP unblocking failed", ip_address=ip_address, error=str(e))
            raise ResponseActionError(error_msg)
    
    def disable_application(self, app_id: str, reason: str = "Security incident") -> Dict:
        """
        Disable application access
        
        Args:
            app_id: Okta application ID
            reason: Reason for disabling
            
        Returns:
            Dict with result details
        """
        try:
            logger.info("Disabling application", app_id=app_id, reason=reason)
            
            # Get app details for audit
            app_response = self.okta_client._make_request('GET', f'/apps/{app_id}')
            app_info = app_response.json() if app_response.status_code == 200 else {}
            
            # Deactivate the application
            response = self.okta_client._make_request('POST', f'/apps/{app_id}/lifecycle/deactivate')
            
            if response.status_code == 200:
                result = {
                    'action': 'disable_application',
                    'app_id': app_id,
                    'app_name': app_info.get('name', 'Unknown'),
                    'app_label': app_info.get('label', 'Unknown'),
                    'reason': reason,
                    'status': 'success',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                logger.info("Application disabled successfully", **result)
                return result
            else:
                raise ResponseActionError(f"Failed to disable application {app_id}")
                
        except Exception as e:
            error_msg = f"Failed to disable application {app_id}: {e}"
            logger.error("Application disabling failed", app_id=app_id, error=str(e))
            raise ResponseActionError(error_msg)
    
    def enable_application(self, app_id: str) -> Dict:
        """
        Enable application access (rollback)
        
        Args:
            app_id: Okta application ID
            
        Returns:
            Dict with result details
        """
        try:
            logger.info("Enabling application", app_id=app_id)
            
            # Activate the application
            response = self.okta_client._make_request('POST', f'/apps/{app_id}/lifecycle/activate')
            
            if response.status_code == 200:
                result = {
                    'action': 'enable_application',
                    'app_id': app_id,
                    'status': 'success',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                logger.info("Application enabled successfully", **result)
                return result
            else:
                raise ResponseActionError(f"Failed to enable application {app_id}")
                
        except Exception as e:
            error_msg = f"Failed to enable application {app_id}: {e}"
            logger.error("Application enabling failed", app_id=app_id, error=str(e))
            raise ResponseActionError(error_msg)
    
    def remove_user_from_group(self, user_id: str, group_id: str, reason: str = "Security incident") -> Dict:
        """
        Remove user from security group
        
        Args:
            user_id: Okta user ID
            group_id: Okta group ID
            reason: Reason for removal
            
        Returns:
            Dict with result details
        """
        try:
            logger.info("Removing user from group", user_id=user_id, group_id=group_id, reason=reason)
            
            # Get group details for audit
            group_response = self.okta_client._make_request('GET', f'/groups/{group_id}')
            group_info = group_response.json() if group_response.status_code == 200 else {}
            
            # Remove user from group
            response = self.okta_client._make_request('DELETE', f'/groups/{group_id}/users/{user_id}')
            
            if response.status_code in [200, 204, 404]:  # 404 is OK if not in group
                result = {
                    'action': 'remove_user_from_group',
                    'user_id': user_id,
                    'group_id': group_id,
                    'group_name': group_info.get('profile', {}).get('name', 'Unknown'),
                    'reason': reason,
                    'status': 'success',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                logger.info("User removed from group successfully", **result)
                return result
            else:
                raise ResponseActionError(f"Failed to remove user {user_id} from group {group_id}")
                
        except Exception as e:
            error_msg = f"Failed to remove user {user_id} from group {group_id}: {e}"
            logger.error("Group removal failed", user_id=user_id, group_id=group_id, error=str(e))
            raise ResponseActionError(error_msg)
    
    def add_user_to_group(self, user_id: str, group_id: str, reason: str = "Privilege restoration") -> Dict:
        """
        Add user to security group (rollback)
        
        Args:
            user_id: Okta user ID
            group_id: Okta group ID
            reason: Reason for addition
            
        Returns:
            Dict with result details
        """
        try:
            logger.info("Adding user to group", user_id=user_id, group_id=group_id, reason=reason)
            
            # Add user to group
            response = self.okta_client._make_request('PUT', f'/groups/{group_id}/users/{user_id}')
            
            if response.status_code in [200, 204]:
                result = {
                    'action': 'add_user_to_group',
                    'user_id': user_id,
                    'group_id': group_id,
                    'reason': reason,
                    'status': 'success',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                logger.info("User added to group successfully", **result)
                return result
            else:
                raise ResponseActionError(f"Failed to add user {user_id} to group {group_id}")
                
        except Exception as e:
            error_msg = f"Failed to add user {user_id} to group {group_id}: {e}"
            logger.error("Group addition failed", user_id=user_id, group_id=group_id, error=str(e))
            raise ResponseActionError(error_msg)
    
    def expire_user_password(self, user_id: str, reason: str = "Security incident") -> Dict:
        """
        Force password expiration for user
        
        Args:
            user_id: Okta user ID
            reason: Reason for password expiration
            
        Returns:
            Dict with result details
        """
        try:
            logger.info("Expiring user password", user_id=user_id, reason=reason)
            
            # Expire password
            response = self.okta_client._make_request('POST', f'/users/{user_id}/lifecycle/expire_password')
            
            if response.status_code == 200:
                result = {
                    'action': 'expire_user_password',
                    'user_id': user_id,
                    'reason': reason,
                    'status': 'success',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                logger.info("User password expired successfully", **result)
                return result
            else:
                raise ResponseActionError(f"Failed to expire password for user {user_id}")
                
        except Exception as e:
            error_msg = f"Failed to expire password for user {user_id}: {e}"
            logger.error("Password expiration failed", user_id=user_id, error=str(e))
            raise ResponseActionError(error_msg)
    
    def _get_or_create_mfa_group(self) -> str:
        """Get or create MFA enforcement group"""
        mfa_group_name = "Security_MFA_Required"
        
        try:
            # Search for existing MFA group
            response = self.okta_client._make_request(
                'GET', 
                '/groups',
                params={'q': mfa_group_name}
            )
            
            groups = response.json() if response.status_code == 200 else []
            
            # Find exact match
            for group in groups:
                if group.get('profile', {}).get('name') == mfa_group_name:
                    return group['id']
            
            # Create new MFA group if not found
            group_data = {
                "profile": {
                    "name": mfa_group_name,
                    "description": "Users required to use MFA for security enforcement"
                }
            }
            
            response = self.okta_client._make_request('POST', '/groups', data=group_data)
            
            if response.status_code == 200:
                new_group = response.json()
                logger.info("Created MFA enforcement group", group_id=new_group['id'])
                return new_group['id']
            else:
                raise ResponseActionError("Failed to create MFA enforcement group")
                
        except Exception as e:
            logger.error("Failed to get/create MFA group", error=str(e))
            raise ResponseActionError(f"MFA group management failed: {e}")
    
    def get_blocked_ips(self) -> Dict:
        """Get currently blocked IP addresses"""
        current_time = datetime.utcnow()
        
        # Remove expired blocks
        expired_ips = []
        for ip, block_info in self.blocked_ips.items():
            block_until = datetime.fromisoformat(block_info['block_until'])
            if current_time > block_until:
                expired_ips.append(ip)
        
        for ip in expired_ips:
            del self.blocked_ips[ip]
        
        return {
            'blocked_ips': self.blocked_ips,
            'count': len(self.blocked_ips),
            'last_updated': current_time.isoformat()
        }
    
    def get_action_capabilities(self) -> Dict:
        """Get available action capabilities"""
        return {
            'user_management': [
                'suspend_user',
                'unsuspend_user',
                'clear_user_sessions',
                'reset_user_mfa',
                'expire_user_password'
            ],
            'access_control': [
                'enforce_mfa',
                'remove_mfa_enforcement',
                'remove_user_from_group',
                'add_user_to_group'
            ],
            'application_control': [
                'disable_application',
                'enable_application'
            ],
            'network_security': [
                'block_ip_address',  # Simulated
                'unblock_ip_address'  # Simulated
            ],
            'reversible_actions': [
                'suspend_user',
                'enforce_mfa',
                'remove_user_from_group',
                'disable_application',
                'block_ip_address'
            ],
            'high_impact_actions': [
                'suspend_user',
                'reset_user_mfa',
                'disable_application'
            ]
        }