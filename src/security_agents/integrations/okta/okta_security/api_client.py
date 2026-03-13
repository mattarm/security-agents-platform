"""
Okta Security API Client

Production-ready Okta API wrapper with rate limiting, circuit breakers,
and comprehensive error handling for security monitoring.
"""

import time
import asyncio
import logging
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
import json

import requests
import httpx
from okta.client import Client as OktaClient
from okta.config.config_validator import ConfigValidator
from okta.models import *
import structlog

from .auth_manager import AuthManager
from .exceptions import (
    OktaSecurityError, 
    RateLimitExceeded, 
    AuthenticationError,
    CircuitBreakerOpen
)

logger = structlog.get_logger()


@dataclass
class RateLimitInfo:
    """Rate limit tracking for Okta API calls"""
    limit: int
    remaining: int
    reset_time: int
    window_reset: datetime


class CircuitBreaker:
    """Circuit breaker pattern for API resilience"""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
    
    def can_execute(self) -> bool:
        if self.state == "CLOSED":
            return True
        elif self.state == "OPEN":
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = "HALF_OPEN"
                return True
            return False
        else:  # HALF_OPEN
            return True
    
    def record_success(self):
        self.failure_count = 0
        self.state = "CLOSED"
    
    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"


class OktaSecurityClient:
    """
    Enhanced Okta API client for security monitoring with:
    - Rate limiting and backoff
    - Circuit breaker pattern
    - Comprehensive error handling
    - Security event collection
    - Real-time streaming capabilities
    """
    
    def __init__(
        self, 
        org_url: str,
        api_token: str = None,
        oauth_client_id: str = None,
        oauth_private_key: str = None,
        rate_limit_buffer: int = 10,
        circuit_breaker_enabled: bool = True
    ):
        self.org_url = org_url.rstrip('/')
        self.rate_limit_buffer = rate_limit_buffer
        self.circuit_breaker = CircuitBreaker() if circuit_breaker_enabled else None
        self.rate_limits: Dict[str, RateLimitInfo] = {}
        
        # Initialize auth manager
        self.auth_manager = AuthManager(
            org_url=org_url,
            api_token=api_token,
            oauth_client_id=oauth_client_id,
            oauth_private_key=oauth_private_key
        )
        
        # Initialize Okta client
        self._init_okta_client()
        
        # Session for direct API calls
        self.session = requests.Session()
        self.session.headers.update({
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'User-Agent': 'OktaSecurityIntegration/1.0'
        })
        
        logger.info("Okta Security Client initialized", org_url=org_url)
    
    def _init_okta_client(self):
        """Initialize the official Okta Python SDK client"""
        try:
            config = {
                'orgUrl': self.org_url,
                'token': self.auth_manager.get_api_token(),
                'rateLimit': {
                    'maxRetries': 3,
                    'requestTimeout': 30
                }
            }
            
            self.client = OktaClient(config)
            logger.info("Okta SDK client initialized successfully")
            
        except Exception as e:
            logger.error("Failed to initialize Okta client", error=str(e))
            raise OktaSecurityError(f"Okta client initialization failed: {e}")
    
    def _check_circuit_breaker(self):
        """Check if circuit breaker allows execution"""
        if self.circuit_breaker and not self.circuit_breaker.can_execute():
            raise CircuitBreakerOpen("Circuit breaker is open, requests blocked")
    
    def _update_rate_limits(self, headers: Dict[str, str], endpoint: str):
        """Update rate limit tracking from response headers"""
        try:
            if 'x-rate-limit-limit' in headers:
                self.rate_limits[endpoint] = RateLimitInfo(
                    limit=int(headers.get('x-rate-limit-limit', 0)),
                    remaining=int(headers.get('x-rate-limit-remaining', 0)),
                    reset_time=int(headers.get('x-rate-limit-reset', 0)),
                    window_reset=datetime.fromtimestamp(
                        int(headers.get('x-rate-limit-reset', 0))
                    )
                )
                
                # Log rate limit warnings
                remaining = self.rate_limits[endpoint].remaining
                if remaining < self.rate_limit_buffer:
                    logger.warning(
                        "Rate limit approaching", 
                        endpoint=endpoint,
                        remaining=remaining,
                        reset_time=self.rate_limits[endpoint].window_reset
                    )
        except (ValueError, KeyError) as e:
            logger.warning("Failed to parse rate limit headers", error=str(e))
    
    def _wait_for_rate_limit(self, endpoint: str):
        """Wait if rate limit is exceeded"""
        if endpoint in self.rate_limits:
            rate_info = self.rate_limits[endpoint]
            if rate_info.remaining <= 0:
                wait_time = (rate_info.window_reset - datetime.now()).total_seconds()
                if wait_time > 0:
                    logger.info(f"Rate limit exceeded, waiting {wait_time}s", endpoint=endpoint)
                    time.sleep(min(wait_time, 300))  # Max 5 min wait
    
    def _make_request(
        self, 
        method: str, 
        endpoint: str, 
        params: Dict = None,
        data: Dict = None,
        timeout: int = 30
    ) -> requests.Response:
        """Make authenticated API request with error handling"""
        
        self._check_circuit_breaker()
        self._wait_for_rate_limit(endpoint)
        
        url = f"{self.org_url}/api/v1{endpoint}"
        headers = {
            'Authorization': f'SSWS {self.auth_manager.get_api_token()}',
            **self.session.headers
        }
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=data,
                timeout=timeout
            )
            
            # Update rate limits
            self._update_rate_limits(response.headers, endpoint)
            
            # Check for errors
            if response.status_code == 429:
                if self.circuit_breaker:
                    self.circuit_breaker.record_failure()
                raise RateLimitExceeded("Rate limit exceeded")
            
            if response.status_code == 401:
                raise AuthenticationError("Authentication failed - invalid token")
            
            if response.status_code >= 400:
                error_msg = f"API error {response.status_code}: {response.text}"
                if self.circuit_breaker:
                    self.circuit_breaker.record_failure()
                raise OktaSecurityError(error_msg)
            
            # Record success
            if self.circuit_breaker:
                self.circuit_breaker.record_success()
            
            return response
            
        except requests.RequestException as e:
            if self.circuit_breaker:
                self.circuit_breaker.record_failure()
            logger.error("Request failed", error=str(e), endpoint=endpoint)
            raise OktaSecurityError(f"Request failed: {e}")
    
    # System Log API - Critical for security monitoring
    def get_system_logs(
        self, 
        since: datetime = None,
        until: datetime = None,
        filter_expr: str = None,
        limit: int = 1000
    ) -> List[Dict]:
        """Fetch Okta system logs with comprehensive filtering"""
        
        params = {'limit': min(limit, 1000)}
        
        if since:
            params['since'] = since.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        if until:
            params['until'] = until.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        if filter_expr:
            params['filter'] = filter_expr
        
        response = self._make_request('GET', '/logs', params=params)
        return response.json()
    
    def stream_system_logs(self, callback, filter_expr: str = None):
        """Stream real-time system logs"""
        last_timestamp = datetime.utcnow()
        
        while True:
            try:
                logs = self.get_system_logs(
                    since=last_timestamp,
                    filter_expr=filter_expr,
                    limit=1000
                )
                
                for log in logs:
                    callback(log)
                    # Update timestamp to prevent duplicates
                    log_time = datetime.fromisoformat(
                        log['published'].replace('Z', '+00:00')
                    )
                    if log_time > last_timestamp:
                        last_timestamp = log_time
                
                # Wait before next poll
                time.sleep(30)  # 30-second polling interval
                
            except Exception as e:
                logger.error("Error in log streaming", error=str(e))
                time.sleep(60)  # Extended wait on error
    
    # User Management API
    def get_user(self, user_id: str) -> Dict:
        """Get detailed user information"""
        response = self._make_request('GET', f'/users/{user_id}')
        return response.json()
    
    def get_user_groups(self, user_id: str) -> List[Dict]:
        """Get user's group memberships"""
        response = self._make_request('GET', f'/users/{user_id}/groups')
        return response.json()
    
    def get_user_sessions(self, user_id: str) -> List[Dict]:
        """Get active user sessions"""
        response = self._make_request('GET', f'/users/{user_id}/sessions')
        return response.json()
    
    # Security Actions
    def suspend_user(self, user_id: str, reason: str = "Security incident") -> bool:
        """Suspend user account"""
        try:
            response = self._make_request(
                'POST', 
                f'/users/{user_id}/lifecycle/suspend',
                data={'reason': reason}
            )
            
            logger.info("User suspended", user_id=user_id, reason=reason)
            return response.status_code == 200
            
        except Exception as e:
            logger.error("Failed to suspend user", user_id=user_id, error=str(e))
            return False
    
    def clear_user_sessions(self, user_id: str) -> bool:
        """Clear all user sessions"""
        try:
            response = self._make_request('DELETE', f'/users/{user_id}/sessions')
            logger.info("User sessions cleared", user_id=user_id)
            return response.status_code == 204
            
        except Exception as e:
            logger.error("Failed to clear sessions", user_id=user_id, error=str(e))
            return False
    
    def reset_user_mfa(self, user_id: str) -> bool:
        """Reset user's MFA factors"""
        try:
            response = self._make_request('DELETE', f'/users/{user_id}/factors')
            logger.info("User MFA reset", user_id=user_id)
            return response.status_code == 200
            
        except Exception as e:
            logger.error("Failed to reset MFA", user_id=user_id, error=str(e))
            return False
    
    # Health and Monitoring
    def health_check(self) -> Dict[str, Any]:
        """Perform health check of Okta connectivity and permissions"""
        health_status = {
            'timestamp': datetime.utcnow().isoformat(),
            'okta_connectivity': False,
            'api_permissions': False,
            'rate_limit_status': {},
            'circuit_breaker_status': 'CLOSED'
        }
        
        try:
            # Test basic connectivity
            response = self._make_request('GET', '/org')
            health_status['okta_connectivity'] = True
            health_status['api_permissions'] = response.status_code == 200
            
            # Rate limit status
            health_status['rate_limit_status'] = {
                endpoint: {
                    'remaining': info.remaining,
                    'reset_time': info.window_reset.isoformat()
                }
                for endpoint, info in self.rate_limits.items()
            }
            
            # Circuit breaker status
            if self.circuit_breaker:
                health_status['circuit_breaker_status'] = self.circuit_breaker.state
                
        except Exception as e:
            logger.error("Health check failed", error=str(e))
            health_status['error'] = str(e)
        
        return health_status