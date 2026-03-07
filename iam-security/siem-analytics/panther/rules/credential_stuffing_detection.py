"""
Panther Detection Rule: Credential Stuffing Attack Detection
Detects multiple failed login attempts across different accounts from the same source
"""

import json
from typing import List, Dict, Any
from datetime import datetime, timedelta

# Detection rule metadata
RULE_ID = "IAM.CredentialStuffing"
RULE_NAME = "Credential Stuffing Attack Detection"
LOG_TYPES = ["Okta.SystemLog"]
SEVERITY = "MEDIUM"
RUNBOOK = "https://runbooks.company.com/iam/credential-stuffing"

# Configuration
FAILED_LOGIN_THRESHOLD = 5
TIME_WINDOW_MINUTES = 5
UNIQUE_USER_THRESHOLD = 3


def rule(event: Dict[str, Any]) -> bool:
    """
    Detects credential stuffing attempts by monitoring failed login patterns
    
    Args:
        event: Okta system log event
        
    Returns:
        bool: True if credential stuffing detected
    """
    return (
        event.get("eventtype") == "user.authentication.auth_via_mfa" and
        event.get("outcome", {}).get("result") == "FAILURE" and
        event.get("securitycontext", {}).get("isproxy") is False
    )


def title(event: Dict[str, Any]) -> str:
    """Generate alert title"""
    source_ip = event.get("client", {}).get("ipaddress", "unknown")
    user = event.get("actor", {}).get("alternateId", "unknown")
    
    return f"Credential stuffing detected from {source_ip} targeting {user}"


def dedup(event: Dict[str, Any]) -> str:
    """Deduplication key for grouping related events"""
    source_ip = event.get("client", {}).get("ipaddress", "unknown")
    return f"credential_stuffing_{source_ip}"


def severity(event: Dict[str, Any]) -> str:
    """Dynamic severity based on attack characteristics"""
    client_info = event.get("client", {})
    
    # Increase severity for attacks from known bad actors
    if client_info.get("zone") == "BLOCKLIST":
        return "HIGH"
    
    # Increase severity for attacks targeting privileged accounts
    user_type = event.get("actor", {}).get("type", "")
    if "admin" in user_type.lower():
        return "HIGH"
        
    return "MEDIUM"


def destinations(event: Dict[str, Any]) -> List[str]:
    """Route alerts to appropriate teams"""
    base_destinations = ["security-team", "soc-alerts"]
    
    # Add SOC escalation for high-severity events
    if severity(event) == "HIGH":
        base_destinations.append("soc-escalation")
        
    return base_destinations


def alert_context(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Aggregate context across related events for enriched alerting
    """
    if not events:
        return {}
    
    # Aggregate statistics
    source_ips = set()
    targeted_users = set()
    user_agents = set()
    geo_locations = set()
    
    for event in events:
        client = event.get("client", {})
        source_ips.add(client.get("ipaddress", "unknown"))
        
        actor = event.get("actor", {})
        targeted_users.add(actor.get("alternateId", "unknown"))
        
        user_agents.add(client.get("useragent", {}).get("rawuseragent", "unknown"))
        
        geo_info = client.get("geographicalcontext", {})
        if geo_info:
            location = f"{geo_info.get('city', 'unknown')}, {geo_info.get('country', 'unknown')}"
            geo_locations.add(location)
    
    # Calculate attack metrics
    attack_duration = None
    if len(events) > 1:
        timestamps = [event.get("published") for event in events if event.get("published")]
        if timestamps:
            timestamps.sort()
            start_time = datetime.fromisoformat(timestamps[0].replace('Z', '+00:00'))
            end_time = datetime.fromisoformat(timestamps[-1].replace('Z', '+00:00'))
            attack_duration = (end_time - start_time).total_seconds()
    
    # Threat intelligence enrichment
    threat_indicators = []
    for ip in source_ips:
        # This would integrate with threat intel feeds in production
        if ip.startswith("10.") or ip.startswith("192.168."):
            threat_indicators.append(f"Internal IP: {ip}")
        else:
            threat_indicators.append(f"External IP: {ip}")
    
    return {
        "attack_summary": {
            "source_ips": list(source_ips),
            "source_ip_count": len(source_ips),
            "targeted_users": list(targeted_users),
            "targeted_user_count": len(targeted_users),
            "total_attempts": len(events),
            "attack_duration_seconds": attack_duration,
            "unique_user_agents": len(user_agents),
            "geo_locations": list(geo_locations)
        },
        "threat_intelligence": {
            "indicators": threat_indicators,
            "risk_score": calculate_risk_score(events),
            "attack_pattern": classify_attack_pattern(events)
        },
        "mitigation_recommendations": generate_mitigation_recommendations(events)
    }


def calculate_risk_score(events: List[Dict[str, Any]]) -> float:
    """
    Calculate risk score based on attack characteristics
    Score range: 0.0 - 1.0
    """
    if not events:
        return 0.0
    
    score = 0.0
    
    # Base score for credential stuffing attempt
    score += 0.3
    
    # Volume scoring
    attempt_count = len(events)
    if attempt_count > 20:
        score += 0.3
    elif attempt_count > 10:
        score += 0.2
    elif attempt_count > 5:
        score += 0.1
    
    # Unique user targeting
    unique_users = len(set(event.get("actor", {}).get("alternateId") for event in events))
    if unique_users > 10:
        score += 0.2
    elif unique_users > 5:
        score += 0.1
    
    # Time-based scoring (rapid attempts)
    if len(events) > 1:
        timestamps = [event.get("published") for event in events if event.get("published")]
        if timestamps and len(timestamps) > 1:
            timestamps.sort()
            start_time = datetime.fromisoformat(timestamps[0].replace('Z', '+00:00'))
            end_time = datetime.fromisoformat(timestamps[-1].replace('Z', '+00:00'))
            duration = (end_time - start_time).total_seconds()
            
            if duration < 60:  # Very rapid attempts
                score += 0.2
            elif duration < 300:  # Within 5 minutes
                score += 0.1
    
    return min(score, 1.0)


def classify_attack_pattern(events: List[Dict[str, Any]]) -> str:
    """
    Classify the type of credential stuffing attack based on patterns
    """
    if not events:
        return "unknown"
    
    unique_users = len(set(event.get("actor", {}).get("alternateId") for event in events))
    unique_ips = len(set(event.get("client", {}).get("ipaddress") for event in events))
    
    if unique_ips == 1 and unique_users > 10:
        return "single_source_spray"
    elif unique_ips > 5 and unique_users > unique_ips:
        return "distributed_spray"
    elif unique_users < 5 and len(events) > 20:
        return "targeted_bruteforce"
    else:
        return "credential_stuffing"


def generate_mitigation_recommendations(events: List[Dict[str, Any]]) -> List[str]:
    """
    Generate actionable mitigation recommendations
    """
    recommendations = []
    
    if not events:
        return recommendations
    
    # IP-based recommendations
    source_ips = set(event.get("client", {}).get("ipaddress") for event in events)
    if len(source_ips) == 1:
        ip = list(source_ips)[0]
        recommendations.append(f"Consider temporarily blocking source IP: {ip}")
    elif len(source_ips) < 5:
        recommendations.append("Consider implementing IP-based rate limiting")
    
    # User-based recommendations
    targeted_users = set(event.get("actor", {}).get("alternateId") for event in events)
    if len(targeted_users) < 10:
        recommendations.append("Consider forcing password resets for targeted accounts")
        recommendations.append("Enable additional MFA requirements for targeted users")
    
    # General recommendations
    recommendations.extend([
        "Review and tune authentication policies",
        "Consider implementing CAPTCHA for suspicious login patterns",
        "Review network security controls for attack source networks",
        "Update threat intelligence feeds with observed attack indicators"
    ])
    
    return recommendations