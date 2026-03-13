"""
Authentication Manager for Okta Security Integration

Handles OAuth 2.0 flows, API token management, and credential rotation
for secure Okta API access.
"""

import time
import base64
import hashlib
import json
from typing import Dict, Optional
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import jwt
import requests
import structlog

from .exceptions import AuthenticationError, ConfigurationError

logger = structlog.get_logger()


class AuthManager:
    """
    Manages authentication credentials and token lifecycle for Okta API access.
    
    Supports both API tokens and OAuth 2.0 private key authentication with
    automatic token refresh and rotation capabilities.
    """
    
    def __init__(
        self,
        org_url: str,
        api_token: str = None,
        oauth_client_id: str = None,
        oauth_private_key: str = None,
        oauth_scopes: list = None
    ):
        self.org_url = org_url.rstrip('/')
        self.api_token = api_token
        self.oauth_client_id = oauth_client_id
        self.oauth_private_key = oauth_private_key
        self.oauth_scopes = oauth_scopes or [
            'okta.logs.read',
            'okta.users.read',
            'okta.users.manage',
            'okta.groups.read',
            'okta.apps.read'
        ]
        
        # OAuth state
        self.access_token: Optional[str] = None
        self.token_expires_at: Optional[datetime] = None
        self.refresh_token: Optional[str] = None
        
        # Validate configuration
        self._validate_config()
        
        logger.info("Auth manager initialized", 
                   org_url=org_url, 
                   auth_method="oauth" if oauth_client_id else "api_token")
    
    def _validate_config(self):
        """Validate authentication configuration"""
        if not self.api_token and not (self.oauth_client_id and self.oauth_private_key):
            raise ConfigurationError(
                "Either api_token or oauth credentials (client_id + private_key) must be provided"
            )
        
        if self.oauth_private_key:
            try:
                # Validate private key format
                serialization.load_pem_private_key(
                    self.oauth_private_key.encode(),
                    password=None
                )
            except Exception as e:
                raise ConfigurationError(f"Invalid private key format: {e}")
    
    def _create_client_assertion(self) -> str:
        """Create JWT client assertion for OAuth authentication"""
        if not self.oauth_private_key:
            raise AuthenticationError("OAuth private key not configured")
        
        # Load private key
        private_key = serialization.load_pem_private_key(
            self.oauth_private_key.encode(),
            password=None
        )
        
        # Create JWT header and payload
        now = int(time.time())
        payload = {
            'iss': self.oauth_client_id,
            'sub': self.oauth_client_id,
            'aud': f"{self.org_url}/oauth2/v1/token",
            'iat': now,
            'exp': now + 300,  # 5 minutes
            'jti': hashlib.sha256(f"{self.oauth_client_id}{now}".encode()).hexdigest()
        }
        
        # Sign JWT
        client_assertion = jwt.encode(
            payload,
            private_key,
            algorithm='RS256'
        )
        
        return client_assertion
    
    def _request_oauth_token(self) -> Dict:
        """Request OAuth access token using private key authentication"""
        try:
            client_assertion = self._create_client_assertion()
            
            token_data = {
                'grant_type': 'client_credentials',
                'scope': ' '.join(self.oauth_scopes),
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion': client_assertion
            }
            
            response = requests.post(
                f"{self.org_url}/oauth2/v1/token",
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=30
            )
            
            if response.status_code != 200:
                error_detail = response.json() if response.content else "Unknown error"
                raise AuthenticationError(f"OAuth token request failed: {error_detail}")
            
            return response.json()
            
        except requests.RequestException as e:
            raise AuthenticationError(f"OAuth token request failed: {e}")
    
    def _refresh_oauth_token(self):
        """Refresh OAuth access token"""
        logger.info("Refreshing OAuth access token")
        
        token_response = self._request_oauth_token()
        
        self.access_token = token_response['access_token']
        expires_in = token_response.get('expires_in', 3600)
        
        # Set expiration with 5-minute buffer
        self.token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in - 300)
        
        logger.info("OAuth token refreshed", 
                   expires_at=self.token_expires_at.isoformat())
    
    def _is_token_expired(self) -> bool:
        """Check if current OAuth token is expired or about to expire"""
        if not self.access_token or not self.token_expires_at:
            return True
        
        return datetime.utcnow() >= self.token_expires_at
    
    def get_access_token(self) -> str:
        """Get valid OAuth access token, refreshing if necessary"""
        if not self.oauth_client_id:
            raise AuthenticationError("OAuth not configured")
        
        if self._is_token_expired():
            self._refresh_oauth_token()
        
        return self.access_token
    
    def get_api_token(self) -> str:
        """Get API token (either direct API token or OAuth access token)"""
        if self.api_token:
            return self.api_token
        
        if self.oauth_client_id:
            return self.get_access_token()
        
        raise AuthenticationError("No authentication method configured")
    
    def get_auth_header(self) -> Dict[str, str]:
        """Get appropriate Authorization header"""
        if self.api_token:
            return {'Authorization': f'SSWS {self.api_token}'}
        
        if self.oauth_client_id:
            access_token = self.get_access_token()
            return {'Authorization': f'Bearer {access_token}'}
        
        raise AuthenticationError("No authentication method configured")
    
    def validate_credentials(self) -> bool:
        """Validate current credentials by making a test API call"""
        try:
            auth_header = self.get_auth_header()
            
            response = requests.get(
                f"{self.org_url}/api/v1/org",
                headers=auth_header,
                timeout=30
            )
            
            is_valid = response.status_code == 200
            
            if is_valid:
                logger.info("Credential validation successful")
            else:
                logger.warning("Credential validation failed", 
                             status_code=response.status_code)
            
            return is_valid
            
        except Exception as e:
            logger.error("Credential validation error", error=str(e))
            return False
    
    def revoke_tokens(self):
        """Revoke OAuth tokens (if using OAuth)"""
        if not self.oauth_client_id or not self.access_token:
            logger.info("No OAuth tokens to revoke")
            return
        
        try:
            client_assertion = self._create_client_assertion()
            
            revoke_data = {
                'token': self.access_token,
                'token_type_hint': 'access_token',
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion': client_assertion
            }
            
            response = requests.post(
                f"{self.org_url}/oauth2/v1/revoke",
                data=revoke_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=30
            )
            
            if response.status_code == 200:
                logger.info("OAuth tokens revoked successfully")
            else:
                logger.warning("Token revocation failed", 
                             status_code=response.status_code)
            
            # Clear local token state
            self.access_token = None
            self.token_expires_at = None
            
        except Exception as e:
            logger.error("Token revocation error", error=str(e))
    
    def rotate_api_token(self, new_token: str):
        """Rotate to a new API token"""
        old_token = self.api_token
        self.api_token = new_token
        
        # Validate new token
        if not self.validate_credentials():
            logger.error("New API token validation failed, rolling back")
            self.api_token = old_token
            raise AuthenticationError("New API token is invalid")
        
        logger.info("API token rotated successfully")
    
    def get_token_info(self) -> Dict:
        """Get information about current token state"""
        info = {
            'auth_method': 'oauth' if self.oauth_client_id else 'api_token',
            'has_api_token': bool(self.api_token),
            'has_oauth_config': bool(self.oauth_client_id and self.oauth_private_key)
        }
        
        if self.oauth_client_id:
            info.update({
                'oauth_client_id': self.oauth_client_id,
                'oauth_scopes': self.oauth_scopes,
                'access_token_expires_at': self.token_expires_at.isoformat() if self.token_expires_at else None,
                'token_expired': self._is_token_expired()
            })
        
        return info