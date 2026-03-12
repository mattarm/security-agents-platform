"""
Okta Identity Security Integration Package

A comprehensive security monitoring and response system for Okta-based
identity management with dual SIEM compatibility.
"""

__version__ = "1.0.0"
__author__ = "Security Team"

from .api_client import OktaSecurityClient
from .event_collector import EventCollector
from .auth_manager import AuthManager

__all__ = ["OktaSecurityClient", "EventCollector", "AuthManager"]