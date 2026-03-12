"""
Privilege Management Response Actions

Implements privilege-related security responses including:
- Role and group privilege revocation
- MFA step-up enforcement
- Access level reduction
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from .account_actions import BaseResponseAction
from ..core.okta_client import OktaClient


class RoleRevocationAction(BaseResponseAction):
    """
    Revokes user privileges by removing from admin groups/roles
    """
    
    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute role revocation
        
        Parameters:
        - user_id: User to revoke privileges from
        - preserve_basic_access: Keep basic user access (default: True)
        - temporary_hours: Make revocation temporary (0 = permanent)
        - specific_groups: List of specific group IDs to remove from
        - specific_roles: List of specific role types to remove
        """
        user_id = parameters.get('user_id')
        if not user_id:
            raise ValueError("user_id is required for role revocation")
        
        preserve_basic_access = parameters.get('preserve_basic_access', self.config.get('preserve_basic_access', True))
        temporary_hours = parameters.get('temporary_hours', self.config.get('temporary_duration_hours', 0))
        specific_groups = parameters.get('specific_groups', [])
        specific_roles = parameters.get('specific_roles', [])
        
        self.logger.info(f"Revoking privileges for user {user_id}")
        
        start_time = datetime.now()
        
        try:
            # Get user information
            user_info = await self.okta_client.get_user(user_id)
            user_email = user_info.get('profile', {}).get('email', 'unknown')
            
            result = {
                'action': 'role_revocation',
                'user_id': user_id,
                'user_email': user_email,
                'preserve_basic_access': preserve_basic_access,
                'temporary_hours': temporary_hours,
                'executed_at': start_time.isoformat(),
                'removed_groups': [],
                'removed_roles': [],
                'preserved_access': []
            }
            
            # Step 1: Handle group removals
            current_groups = await self.okta_client.get_user_groups(user_id)
            
            for group in current_groups:
                group_id = group.get('id')
                group_name = group.get('profile', {}).get('name', group_id)
                
                should_remove = False
                
                if specific_groups:
                    # Remove only specified groups
                    should_remove = group_id in specific_groups
                else:
                    # Remove admin groups (check against configured admin groups)
                    admin_groups = getattr(self.okta_client, 'admin_groups', [])
                    should_remove = group_id in admin_groups
                
                # Apply preserve_basic_access logic
                if should_remove and preserve_basic_access:
                    # Don't remove basic user groups
                    if self._is_basic_user_group(group):
                        result['preserved_access'].append({
                            'type': 'group',
                            'id': group_id,
                            'name': group_name,
                            'reason': 'basic_user_access'
                        })
                        should_remove = False
                
                if should_remove:
                    try:
                        await self.okta_client.remove_user_from_group(user_id, group_id)
                        result['removed_groups'].append({
                            'id': group_id,
                            'name': group_name,
                            'success': True
                        })
                        self.logger.info(f"Removed user {user_id} from group {group_name}")
                    except Exception as e:
                        result['removed_groups'].append({
                            'id': group_id,
                            'name': group_name,
                            'success': False,
                            'error': str(e)
                        })
                        self.logger.error(f"Failed to remove user {user_id} from group {group_name}: {e}")
            
            # Step 2: Handle role removals
            current_roles = await self.okta_client.get_user_roles(user_id)
            
            for role in current_roles:
                role_id = role.get('id')
                role_type = role.get('type', '')
                
                should_remove = False
                
                if specific_roles:
                    # Remove only specified roles
                    should_remove = role_type in specific_roles
                else:
                    # Remove admin-level roles
                    admin_role_types = [
                        'SUPER_ADMIN', 'ORG_ADMIN', 'APP_ADMIN', 'USER_ADMIN', 
                        'HELP_DESK_ADMIN', 'GROUP_MEMBERSHIP_ADMIN', 'REPORT_ADMIN'
                    ]
                    should_remove = role_type in admin_role_types
                
                # Apply preserve_basic_access logic
                if should_remove and preserve_basic_access:
                    # Don't remove read-only or basic roles
                    if role_type in ['READ_ONLY_ADMIN', 'MOBILE_ADMIN']:
                        result['preserved_access'].append({
                            'type': 'role',
                            'id': role_id,
                            'type': role_type,
                            'reason': 'basic_admin_access'
                        })
                        should_remove = False
                
                if should_remove:
                    try:
                        await self.okta_client.remove_user_role(user_id, role_id)
                        result['removed_roles'].append({
                            'id': role_id,
                            'type': role_type,
                            'success': True
                        })
                        self.logger.info(f"Removed role {role_type} from user {user_id}")
                    except Exception as e:
                        result['removed_roles'].append({
                            'id': role_id,
                            'type': role_type,
                            'success': False,
                            'error': str(e)
                        })
                        self.logger.error(f"Failed to remove role {role_type} from user {user_id}: {e}")
            
            # Step 3: Schedule restoration if temporary
            if temporary_hours > 0:
                restore_time = start_time + timedelta(hours=temporary_hours)
                result['scheduled_restoration'] = {
                    'restore_time': restore_time.isoformat(),
                    'groups_to_restore': [g for g in result['removed_groups'] if g['success']],
                    'roles_to_restore': [r for r in result['removed_roles'] if r['success']]
                }
                # Note: Actual scheduling would be handled by job scheduler
            
            result.update({
                'success': True,
                'total_groups_removed': len([g for g in result['removed_groups'] if g['success']]),
                'total_roles_removed': len([r for r in result['removed_roles'] if r['success']]),
                'completed_at': datetime.now().isoformat()
            })
            
            # Log security event
            await self._log_security_event(user_id, 'PRIVILEGES_REVOKED', {
                'groups_removed': len([g for g in result['removed_groups'] if g['success']]),
                'roles_removed': len([r for r in result['removed_roles'] if r['success']]),
                'temporary_hours': temporary_hours,
                'preserve_basic_access': preserve_basic_access,
                'reason': 'automated_threat_response'
            })
            
            self.logger.info(f"Role revocation completed for user {user_id}")
            return result
            
        except Exception as e:
            self.logger.error(f"Role revocation failed for user {user_id}: {e}")
            return {
                'action': 'role_revocation',
                'user_id': user_id,
                'success': False,
                'error': str(e),
                'executed_at': start_time.isoformat(),
                'failed_at': datetime.now().isoformat()
            }

    def _is_basic_user_group(self, group: Dict[str, Any]) -> bool:
        """Determine if a group is a basic user group that should be preserved"""
        group_name = group.get('profile', {}).get('name', '').lower()
        
        # Define patterns for basic user groups
        basic_patterns = [
            'all users', 'everyone', 'basic users', 'standard users',
            'employees', 'staff', 'company', 'domain users'
        ]
        
        return any(pattern in group_name for pattern in basic_patterns)

    async def restore_privileges(
        self, 
        user_id: str, 
        groups_to_restore: List[Dict], 
        roles_to_restore: List[Dict]
    ) -> Dict[str, Any]:
        """Restore previously revoked privileges"""
        self.logger.info(f"Restoring privileges for user {user_id}")
        
        result = {
            'action': 'privilege_restoration',
            'user_id': user_id,
            'executed_at': datetime.now().isoformat(),
            'restored_groups': [],
            'restored_roles': [],
            'failed_restorations': []
        }
        
        # Restore groups
        for group_info in groups_to_restore:
            try:
                await self.okta_client.add_user_to_group(user_id, group_info['id'])
                result['restored_groups'].append(group_info)
                self.logger.info(f"Restored group {group_info['name']} for user {user_id}")
            except Exception as e:
                result['failed_restorations'].append({
                    'type': 'group',
                    'item': group_info,
                    'error': str(e)
                })
                self.logger.error(f"Failed to restore group {group_info['name']}: {e}")
        
        # Restore roles
        for role_info in roles_to_restore:
            try:
                role_data = {'type': role_info['type']}
                await self.okta_client.assign_user_role(user_id, role_data)
                result['restored_roles'].append(role_info)
                self.logger.info(f"Restored role {role_info['type']} for user {user_id}")
            except Exception as e:
                result['failed_restorations'].append({
                    'type': 'role',
                    'item': role_info,
                    'error': str(e)
                })
                self.logger.error(f"Failed to restore role {role_info['type']}: {e}")
        
        result['success'] = len(result['failed_restorations']) == 0
        return result

    async def _log_security_event(self, user_id: str, event_type: str, details: Dict[str, Any]):
        """Log security event for audit trail"""
        self.logger.info(f"SECURITY_EVENT: {event_type} for user {user_id}: {details}")


class MFAStepUpAction(BaseResponseAction):
    """
    Enforces MFA step-up by adding user to MFA policies
    """
    
    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute MFA step-up enforcement
        
        Parameters:
        - user_id: User to enforce MFA for
        - duration_hours: How long to enforce (0 = permanent)
        - policy_id: Specific MFA policy ID (uses config default if not provided)
        - force_re_enrollment: Reset existing MFA factors
        """
        user_id = parameters.get('user_id')
        if not user_id:
            raise ValueError("user_id is required for MFA step-up")
        
        duration_hours = parameters.get('duration_hours', self.config.get('duration_hours', 168))  # 1 week default
        policy_id = parameters.get('policy_id', self.config.get('policy_id'))
        force_re_enrollment = parameters.get('force_re_enrollment', False)
        
        if not policy_id:
            raise ValueError("MFA policy_id must be provided in parameters or config")
        
        self.logger.info(f"Enforcing MFA step-up for user {user_id}")
        
        start_time = datetime.now()
        
        try:
            # Get user information
            user_info = await self.okta_client.get_user(user_id)
            user_email = user_info.get('profile', {}).get('email', 'unknown')
            
            result = {
                'action': 'mfa_step_up',
                'user_id': user_id,
                'user_email': user_email,
                'policy_id': policy_id,
                'duration_hours': duration_hours,
                'force_re_enrollment': force_re_enrollment,
                'executed_at': start_time.isoformat(),
                'steps_completed': []
            }
            
            # Step 1: Get current MFA factors
            current_factors = await self.okta_client.get_user_factors(user_id)
            result['current_mfa_factors'] = len(current_factors)
            
            # Step 2: Reset MFA factors if requested
            if force_re_enrollment and current_factors:
                self.logger.info(f"Resetting MFA factors for user {user_id}")
                try:
                    reset_result = await self.okta_client.reset_user_factors(user_id)
                    result['steps_completed'].append({
                        'step': 'reset_mfa_factors',
                        'success': True,
                        'factors_reset': len(current_factors),
                        'details': reset_result
                    })
                except Exception as e:
                    result['steps_completed'].append({
                        'step': 'reset_mfa_factors',
                        'success': False,
                        'error': str(e)
                    })
                    # Continue anyway - policy enforcement is more important
            
            # Step 3: Add user to MFA policy
            try:
                policy_result = await self.okta_client.add_user_to_policy(policy_id, user_id)
                result['steps_completed'].append({
                    'step': 'add_to_mfa_policy',
                    'success': True,
                    'details': policy_result
                })
            except Exception as e:
                # Check if user is already in policy
                if "already exists" in str(e).lower() or "conflict" in str(e).lower():
                    result['steps_completed'].append({
                        'step': 'add_to_mfa_policy',
                        'success': True,
                        'details': {'message': 'User already in MFA policy'}
                    })
                else:
                    raise e
            
            # Step 4: Schedule policy removal if temporary
            if duration_hours > 0:
                removal_time = start_time + timedelta(hours=duration_hours)
                result['scheduled_removal'] = {
                    'removal_time': removal_time.isoformat(),
                    'policy_id': policy_id
                }
                result['steps_completed'].append({
                    'step': 'schedule_policy_removal',
                    'success': True,
                    'details': {'removal_time': removal_time.isoformat()}
                })
                # Note: Actual scheduling would be handled by job scheduler
            
            # Step 5: Clear sessions to force immediate MFA challenge
            try:
                session_result = await self.okta_client.clear_user_sessions(user_id)
                result['steps_completed'].append({
                    'step': 'clear_sessions_for_mfa',
                    'success': True,
                    'details': session_result
                })
            except Exception as e:
                result['steps_completed'].append({
                    'step': 'clear_sessions_for_mfa',
                    'success': False,
                    'error': str(e)
                })
                # Not critical if sessions can't be cleared
            
            result.update({
                'success': True,
                'completed_at': datetime.now().isoformat()
            })
            
            # Log security event
            await self._log_security_event(user_id, 'MFA_STEP_UP_ENFORCED', {
                'policy_id': policy_id,
                'duration_hours': duration_hours,
                'force_re_enrollment': force_re_enrollment,
                'previous_mfa_factors': len(current_factors),
                'reason': 'automated_threat_response'
            })
            
            self.logger.info(f"MFA step-up enforcement completed for user {user_id}")
            return result
            
        except Exception as e:
            self.logger.error(f"MFA step-up enforcement failed for user {user_id}: {e}")
            return {
                'action': 'mfa_step_up',
                'user_id': user_id,
                'success': False,
                'error': str(e),
                'executed_at': start_time.isoformat(),
                'failed_at': datetime.now().isoformat()
            }

    async def remove_mfa_enforcement(self, user_id: str, policy_id: str) -> Dict[str, Any]:
        """Remove user from MFA policy (for temporary enforcement)"""
        self.logger.info(f"Removing MFA enforcement for user {user_id}")
        
        try:
            result = await self.okta_client.remove_user_from_policy(policy_id, user_id)
            
            # Log the removal
            await self._log_security_event(user_id, 'MFA_ENFORCEMENT_REMOVED', {
                'policy_id': policy_id,
                'reason': 'scheduled_removal'
            })
            
            return {
                'action': 'mfa_enforcement_removal',
                'user_id': user_id,
                'policy_id': policy_id,
                'success': True,
                'result': result,
                'removed_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'action': 'mfa_enforcement_removal',
                'user_id': user_id,
                'success': False,
                'error': str(e)
            }

    async def check_mfa_status(self, user_id: str) -> Dict[str, Any]:
        """Check current MFA status for a user"""
        try:
            factors = await self.okta_client.get_user_factors(user_id)
            
            factor_summary = {}
            for factor in factors:
                factor_type = factor.get('factorType', 'unknown')
                status = factor.get('status', 'unknown')
                
                if factor_type not in factor_summary:
                    factor_summary[factor_type] = []
                factor_summary[factor_type].append(status)
            
            return {
                'user_id': user_id,
                'total_factors': len(factors),
                'factor_summary': factor_summary,
                'factors': factors,
                'checked_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'user_id': user_id,
                'error': str(e)
            }

    async def _log_security_event(self, user_id: str, event_type: str, details: Dict[str, Any]):
        """Log security event for audit trail"""
        self.logger.info(f"SECURITY_EVENT: {event_type} for user {user_id}: {details}")