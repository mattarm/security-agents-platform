"""
Okta Security Integration Exceptions

Custom exception classes for specific error handling and monitoring.
"""


class OktaSecurityError(Exception):
    """Base exception for Okta security integration errors"""
    pass


class AuthenticationError(OktaSecurityError):
    """Raised when authentication with Okta fails"""
    pass


class RateLimitExceeded(OktaSecurityError):
    """Raised when Okta API rate limits are exceeded"""
    pass


class CircuitBreakerOpen(OktaSecurityError):
    """Raised when circuit breaker is open due to repeated failures"""
    pass


class ThreatDetectionError(OktaSecurityError):
    """Raised when threat detection processing fails"""
    pass


class ResponseActionError(OktaSecurityError):
    """Raised when automated response actions fail"""
    pass


class SIEMIntegrationError(OktaSecurityError):
    """Raised when SIEM forwarding fails"""
    pass


class ConfigurationError(OktaSecurityError):
    """Raised when configuration is invalid or missing"""
    pass