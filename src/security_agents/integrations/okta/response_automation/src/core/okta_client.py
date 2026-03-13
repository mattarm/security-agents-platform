"""
Okta Admin API Client

Provides secure interface to Okta Admin API for automated identity response actions.
Handles authentication, rate limiting, and error handling.
"""

import asyncio
import aiohttp
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import json
import time
from urllib.parse import urljoin
import backoff


class OktaAPIError(Exception):
    """Okta API specific error"""
    def __init__(self, message: str, status_code: int = None, response_body: str = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class RateLimitExceeded(OktaAPIError):
    """Rate limit exceeded error"""
    pass


class OktaClient:
    """
    Okta Admin API client for identity management operations
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Okta client"""
        self.domain = config['domain']
        self.api_token = config['api_token']
        self.admin_groups = config.get('admin_groups', [])
        
        # Rate limiting configuration
        self.rate_limits = config.get('rate_limits', {})
        self.requests_per_minute = self.rate_limits.get('requests_per_minute', 100)
        self.concurrent_requests = self.rate_limits.get('concurrent_requests', 10)
        
        # Base URL for API calls
        self.base_url = f"https://{self.domain}/api/v1"
        
        # Session and rate limiting
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore = asyncio.Semaphore(self.concurrent_requests)
        self.request_timestamps: List[float] = []
        
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Initialized Okta client for domain: {self.domain}")

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
                'Authorization': f'SSWS {self.api_token}',
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'User-Agent': 'Identity-Threat-Response-System/1.0'
            }
            
            timeout = aiohttp.ClientTimeout(total=30)
            connector = aiohttp.TCPConnector(limit=self.concurrent_requests)
            
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

    async def _check_rate_limit(self):
        """Check and enforce rate limits"""
        now = time.time()
        
        # Clean old timestamps (older than 1 minute)
        minute_ago = now - 60
        self.request_timestamps = [ts for ts in self.request_timestamps if ts > minute_ago]
        
        # Check if we would exceed rate limit
        if len(self.request_timestamps) >= self.requests_per_minute:
            sleep_time = 60 - (now - self.request_timestamps[0])
            if sleep_time > 0:
                self.logger.warning(f"Rate limit reached, sleeping for {sleep_time:.2f} seconds")
                await asyncio.sleep(sleep_time)
                
        # Record this request
        self.request_timestamps.append(now)

    @backoff.on_exception(
        backoff.expo,
        (aiohttp.ClientError, OktaAPIError),
        max_tries=3,
        max_time=30
    )
    async def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Make authenticated request to Okta API with rate limiting and retry"""
        
        async with self.semaphore:  # Limit concurrent requests
            await self._check_rate_limit()
            await self._ensure_session()
            
            url = urljoin(self.base_url, endpoint)
            
            try:
                async with self.session.request(
                    method, url, json=data, params=params
                ) as response:
                    
                    # Handle rate limiting
                    if response.status == 429:
                        reset_time = int(response.headers.get('X-Rate-Limit-Reset', time.time() + 60))
                        sleep_time = max(0, reset_time - time.time())
                        raise RateLimitExceeded(f"Rate limit exceeded, retry after {sleep_time} seconds")
                    
                    # Parse response
                    response_text = await response.text()
                    
                    if response.status >= 400:
                        error_msg = f"Okta API error: {response.status} - {response_text}"
                        raise OktaAPIError(error_msg, response.status, response_text)
                    
                    # Return parsed JSON or empty dict for no content
                    if response_text:
                        return json.loads(response_text)
                    return {}
                    
            except aiohttp.ClientError as e:
                self.logger.error(f"HTTP client error: {e}")
                raise OktaAPIError(f"HTTP client error: {e}")

    # User Management Operations
    
    async def get_user(self, user_id: str) -> Dict[str, Any]:
        """Get user information by ID or email"""
        try:
            return await self._make_request('GET', f'/users/{user_id}')
        except OktaAPIError as e:
            if e.status_code == 404:
                raise OktaAPIError(f"User not found: {user_id}")
            raise

    async def suspend_user(self, user_id: str) -> Dict[str, Any]:
        """Suspend/lock a user account"""
        self.logger.info(f"Suspending user: {user_id}")
        return await self._make_request('POST', f'/users/{user_id}/lifecycle/suspend')

    async def unsuspend_user(self, user_id: str) -> Dict[str, Any]:
        """Unsuspend/unlock a user account"""
        self.logger.info(f"Unsuspending user: {user_id}")
        return await self._make_request('POST', f'/users/{user_id}/lifecycle/unsuspend')

    async def reset_password(self, user_id: str, send_email: bool = True) -> Dict[str, Any]:
        """Reset user password"""
        self.logger.info(f"Resetting password for user: {user_id}")
        params = {'sendEmail': 'true' if send_email else 'false'}
        return await self._make_request('POST', f'/users/{user_id}/lifecycle/reset_password', params=params)

    async def expire_password(self, user_id: str) -> Dict[str, Any]:
        """Expire user password (force change on next login)"""
        self.logger.info(f"Expiring password for user: {user_id}")
        return await self._make_request('POST', f'/users/{user_id}/lifecycle/expire_password')

    # Session Management
    
    async def clear_user_sessions(self, user_id: str, oauth_only: bool = False) -> Dict[str, Any]:
        """Clear all active sessions for a user"""
        self.logger.info(f"Clearing sessions for user: {user_id}")
        params = {'oauthTokens': 'true' if oauth_only else 'false'}
        return await self._make_request('DELETE', f'/users/{user_id}/sessions', params=params)

    async def get_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """Get active sessions for a user"""
        return await self._make_request('GET', f'/users/{user_id}/sessions')

    # Group/Role Management
    
    async def get_user_groups(self, user_id: str) -> List[Dict[str, Any]]:
        """Get groups assigned to a user"""
        return await self._make_request('GET', f'/users/{user_id}/groups')

    async def remove_user_from_group(self, user_id: str, group_id: str) -> Dict[str, Any]:
        """Remove user from a group"""
        self.logger.info(f"Removing user {user_id} from group {group_id}")
        return await self._make_request('DELETE', f'/groups/{group_id}/users/{user_id}')

    async def add_user_to_group(self, user_id: str, group_id: str) -> Dict[str, Any]:
        """Add user to a group"""
        self.logger.info(f"Adding user {user_id} to group {group_id}")
        return await self._make_request('PUT', f'/groups/{group_id}/users/{user_id}')

    async def get_user_roles(self, user_id: str) -> List[Dict[str, Any]]:
        """Get roles assigned to a user"""
        return await self._make_request('GET', f'/users/{user_id}/roles')

    async def remove_user_role(self, user_id: str, role_id: str) -> Dict[str, Any]:
        """Remove role from a user"""
        self.logger.info(f"Removing role {role_id} from user {user_id}")
        return await self._make_request('DELETE', f'/users/{user_id}/roles/{role_id}')

    async def assign_user_role(self, user_id: str, role_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assign role to a user"""
        self.logger.info(f"Assigning role to user {user_id}: {role_data.get('type')}")
        return await self._make_request('POST', f'/users/{user_id}/roles', data=role_data)

    # MFA Management
    
    async def get_user_factors(self, user_id: str) -> List[Dict[str, Any]]:
        """Get MFA factors for a user"""
        return await self._make_request('GET', f'/users/{user_id}/factors')

    async def enroll_user_factor(self, user_id: str, factor_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enroll a new MFA factor for user"""
        self.logger.info(f"Enrolling MFA factor for user {user_id}: {factor_data.get('factorType')}")
        return await self._make_request('POST', f'/users/{user_id}/factors', data=factor_data)

    async def reset_user_factors(self, user_id: str) -> Dict[str, Any]:
        """Reset all MFA factors for a user"""
        self.logger.warning(f"Resetting ALL MFA factors for user: {user_id}")
        return await self._make_request('DELETE', f'/users/{user_id}/factors')

    async def reset_user_factor(self, user_id: str, factor_id: str) -> Dict[str, Any]:
        """Reset specific MFA factor for a user"""
        self.logger.info(f"Resetting MFA factor {factor_id} for user {user_id}")
        return await self._make_request('DELETE', f'/users/{user_id}/factors/{factor_id}')

    # Device Management
    
    async def get_user_devices(self, user_id: str) -> List[Dict[str, Any]]:
        """Get devices registered to a user"""
        return await self._make_request('GET', f'/users/{user_id}/clients')

    async def clear_user_device_sessions(self, user_id: str, client_id: str) -> Dict[str, Any]:
        """Clear sessions for a specific device"""
        self.logger.info(f"Clearing device sessions for user {user_id}, device {client_id}")
        return await self._make_request('DELETE', f'/users/{user_id}/clients/{client_id}')

    # Policy Management
    
    async def add_user_to_policy(self, policy_id: str, user_id: str) -> Dict[str, Any]:
        """Add user to a policy (like MFA policy)"""
        user_data = {"id": user_id}
        return await self._make_request('PUT', f'/policies/{policy_id}/rules/targets/users/{user_id}', data=user_data)

    async def remove_user_from_policy(self, policy_id: str, user_id: str) -> Dict[str, Any]:
        """Remove user from a policy"""
        return await self._make_request('DELETE', f'/policies/{policy_id}/rules/targets/users/{user_id}')

    # Audit and Monitoring
    
    async def get_user_events(
        self,
        user_id: str,
        since: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get audit events for a user"""
        params = {
            'filter': f'actor.id eq "{user_id}"',
            'limit': limit
        }
        
        if since:
            params['since'] = since.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        
        response = await self._make_request('GET', '/logs', params=params)
        return response.get('events', [])

    async def get_failed_logins(
        self,
        user_id: str,
        since: Optional[datetime] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get failed login attempts for a user"""
        filter_expr = f'actor.id eq "{user_id}" and eventType eq "user.authentication.auth_via_mfa"'
        if since:
            since_str = since.strftime('%Y-%m-%dT%H:%M:%S.000Z')
            filter_expr += f' and published gt "{since_str}"'
        
        params = {
            'filter': filter_expr,
            'limit': limit
        }
        
        response = await self._make_request('GET', '/logs', params=params)
        events = response.get('events', [])
        
        # Filter for failed attempts
        return [event for event in events if event.get('outcome', {}).get('result') == 'FAILURE']

    # High-level Operations
    
    async def lock_account(self, user_id: str, notify_user: bool = True) -> Dict[str, Any]:
        """
        Lock user account (suspend + clear sessions)
        """
        self.logger.info(f"Locking account for user: {user_id}")
        
        # Get user info first
        user = await self.get_user(user_id)
        if user.get('status') == 'SUSPENDED':
            self.logger.info(f"User {user_id} already suspended")
            return user
        
        # Suspend user
        suspend_result = await self.suspend_user(user_id)
        
        # Clear all sessions
        await self.clear_user_sessions(user_id)
        
        return suspend_result

    async def unlock_account(self, user_id: str) -> Dict[str, Any]:
        """
        Unlock user account (unsuspend)
        """
        self.logger.info(f"Unlocking account for user: {user_id}")
        
        # Get user info first
        user = await self.get_user(user_id)
        if user.get('status') != 'SUSPENDED':
            self.logger.info(f"User {user_id} not suspended, current status: {user.get('status')}")
            return user
        
        return await self.unsuspend_user(user_id)

    async def revoke_admin_privileges(self, user_id: str, preserve_basic_access: bool = True) -> Dict[str, Any]:
        """
        Revoke administrative privileges from a user
        """
        self.logger.info(f"Revoking admin privileges for user: {user_id}")
        
        removed_groups = []
        
        # Get current groups
        current_groups = await self.get_user_groups(user_id)
        
        # Remove from admin groups
        for group in current_groups:
            group_id = group.get('id')
            if group_id in self.admin_groups:
                await self.remove_user_from_group(user_id, group_id)
                removed_groups.append(group.get('profile', {}).get('name', group_id))
        
        # Get and remove admin roles
        current_roles = await self.get_user_roles(user_id)
        removed_roles = []
        
        for role in current_roles:
            role_type = role.get('type', '')
            # Remove admin-level roles but preserve basic user roles if specified
            if role_type in ['SUPER_ADMIN', 'ORG_ADMIN', 'APP_ADMIN', 'USER_ADMIN', 'HELP_DESK_ADMIN']:
                if not (preserve_basic_access and role_type == 'READ_ONLY_ADMIN'):
                    await self.remove_user_role(user_id, role.get('id'))
                    removed_roles.append(role_type)
        
        return {
            "user_id": user_id,
            "removed_groups": removed_groups,
            "removed_roles": removed_roles,
            "preserved_basic_access": preserve_basic_access
        }

    async def enforce_mfa(self, user_id: str, policy_id: str) -> Dict[str, Any]:
        """
        Enforce MFA for a user by adding to MFA policy
        """
        self.logger.info(f"Enforcing MFA for user: {user_id}")
        
        try:
            return await self.add_user_to_policy(policy_id, user_id)
        except OktaAPIError as e:
            # User might already be in policy
            if e.status_code == 409:  # Conflict
                self.logger.info(f"User {user_id} already in MFA policy")
                return {"message": "User already in MFA policy", "user_id": user_id}
            raise

    async def bulk_operation(
        self,
        operation: str,
        user_ids: List[str],
        **kwargs
    ) -> Dict[str, Any]:
        """
        Perform bulk operations on multiple users
        """
        self.logger.info(f"Performing bulk {operation} on {len(user_ids)} users")
        
        results = {
            "operation": operation,
            "total_users": len(user_ids),
            "successful": [],
            "failed": []
        }
        
        # Map operations to methods
        operations = {
            "suspend": self.suspend_user,
            "unsuspend": self.unsuspend_user,
            "clear_sessions": self.clear_user_sessions,
            "reset_password": self.reset_password,
            "lock_account": self.lock_account,
            "unlock_account": self.unlock_account
        }
        
        if operation not in operations:
            raise ValueError(f"Unsupported bulk operation: {operation}")
        
        operation_func = operations[operation]
        
        # Execute operations with concurrency limiting
        tasks = []
        for user_id in user_ids:
            task = self._safe_bulk_operation(operation_func, user_id, kwargs, results)
            tasks.append(task)
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        self.logger.info(f"Bulk operation completed: {len(results['successful'])} successful, {len(results['failed'])} failed")
        return results

    async def _safe_bulk_operation(
        self,
        operation_func,
        user_id: str,
        kwargs: Dict,
        results: Dict
    ):
        """Safely execute bulk operation with error handling"""
        try:
            result = await operation_func(user_id, **kwargs)
            results["successful"].append({"user_id": user_id, "result": result})
        except Exception as e:
            self.logger.error(f"Bulk operation failed for user {user_id}: {e}")
            results["failed"].append({"user_id": user_id, "error": str(e)})

    async def health_check(self) -> bool:
        """Perform health check by testing API connectivity"""
        try:
            # Simple API call to test connectivity
            await self._make_request('GET', '/users/me')
            return True
        except Exception as e:
            self.logger.error(f"Okta health check failed: {e}")
            return False

    async def get_current_user(self) -> Dict[str, Any]:
        """Get current API user information"""
        return await self._make_request('GET', '/users/me')