"""
Panther Detection Rule: Privilege Escalation Detection
Detects unusual privilege changes, role assignments, and administrative actions
"""

import json
from typing import List, Dict, Any, Set
from datetime import datetime, timedelta

# Detection rule metadata
RULE_ID = "IAM.PrivilegeEscalation"
RULE_NAME = "IAM Privilege Escalation Detection"
LOG_TYPES = ["Okta.SystemLog"]
SEVERITY = "HIGH"
RUNBOOK = "https://runbooks.company.com/iam/privilege-escalation"

# High-privilege groups to monitor
PRIVILEGED_GROUPS = {
    "Super Admins",
    "Application Admins", 
    "Read-only Admins",
    "Security Admins",
    "Directory Admins",
    "Billing Admins"
}

# High-privilege applications to monitor
PRIVILEGED_APPS = {
    "AWS SSO",
    "Azure AD",
    "Google Workspace Admin",
    "Salesforce Admin",
    "GitHub Enterprise",
    "Jira Admin",
    "Confluence Admin"
}


def rule(event: Dict[str, Any]) -> bool:
    """
    Detects privilege escalation attempts and unusual administrative actions
    
    Args:
        event: Okta system log event
        
    Returns:
        bool: True if privilege escalation detected
    """
    event_type = event.get("eventtype", "")
    
    # Detect privilege group changes
    if event_type in ["group.user_membership.add", "group.user_membership.remove"]:
        target_groups = extract_target_groups(event)
        if target_groups.intersection(PRIVILEGED_GROUPS):
            return True
    
    # Detect application privilege assignments
    if event_type in ["application.user_membership.add"]:
        target_apps = extract_target_applications(event)
        if target_apps.intersection(PRIVILEGED_APPS):
            return True
    
    # Detect role assignments and changes
    if event_type in [
        "user.lifecycle.activate",
        "user.account.privilege.grant",
        "user.account.privilege.revoke",
        "policy.lifecycle.activate",
        "policy.lifecycle.update"
    ]:
        return True
    
    # Detect unusual admin actions during off-hours
    if is_off_hours_admin_action(event):
        return True
    
    return False


def title(event: Dict[str, Any]) -> str:
    """Generate alert title based on escalation type"""
    event_type = event.get("eventtype", "")
    actor = event.get("actor", {}).get("alternateId", "unknown")
    target = extract_escalation_target(event)
    
    if "group" in event_type:
        return f"Privilege group modification by {actor}: {target}"
    elif "application" in event_type:
        return f"Privileged application access granted by {actor}: {target}"
    elif "off_hours" in determine_escalation_type(event):
        return f"Off-hours administrative action by {actor}: {event_type}"
    else:
        return f"Privilege escalation detected: {actor} -> {target}"


def dedup(event: Dict[str, Any]) -> str:
    """Deduplication key for grouping related privilege escalation events"""
    actor = event.get("actor", {}).get("alternateId", "unknown")
    event_type = event.get("eventtype", "")
    target = extract_escalation_target(event)
    
    return f"privilege_escalation_{actor}_{event_type}_{target}"


def severity(event: Dict[str, Any]) -> str:
    """Dynamic severity assessment based on escalation characteristics"""
    escalation_type = determine_escalation_type(event)
    actor = event.get("actor", {})
    
    # Critical severity conditions
    if "super_admin" in escalation_type or "security_admin" in escalation_type:
        return "CRITICAL"
    
    # High severity conditions  
    if any(condition in escalation_type for condition in [
        "off_hours", "external_user", "privileged_app", "bulk_assignment"
    ]):
        return "HIGH"
    
    # Medium severity for standard privilege changes
    if "group_assignment" in escalation_type or "role_assignment" in escalation_type:
        return "MEDIUM"
    
    return "HIGH"  # Default high for privilege escalation


def destinations(event: Dict[str, Any]) -> List[str]:
    """Route alerts to appropriate security teams"""
    base_destinations = ["security-team", "identity-team"]
    escalation_type = determine_escalation_type(event)
    
    # Critical escalations go to SOC and CISO
    if severity(event) == "CRITICAL":
        base_destinations.extend(["soc-escalation", "ciso-alerts"])
    
    # Off-hours escalations get additional routing
    if "off_hours" in escalation_type:
        base_destinations.append("on-call-security")
    
    # External user escalations get additional scrutiny
    if "external_user" in escalation_type:
        base_destinations.append("identity-governance")
        
    return base_destinations


def alert_context(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Enhanced context for privilege escalation alerts
    """
    if not events:
        return {}
    
    # Aggregate escalation details
    actors = set()
    targets = set()
    privilege_types = set()
    escalation_methods = set()
    
    for event in events:
        actors.add(event.get("actor", {}).get("alternateId", "unknown"))
        targets.add(extract_escalation_target(event))
        privilege_types.add(determine_privilege_type(event))
        escalation_methods.add(event.get("eventtype", "unknown"))
    
    # Timeline analysis
    timeline_analysis = analyze_escalation_timeline(events)
    
    # Risk assessment
    risk_assessment = assess_escalation_risk(events)
    
    # Historical context
    historical_context = get_historical_privilege_context(events)
    
    return {
        "escalation_summary": {
            "actors": list(actors),
            "targets": list(targets),
            "privilege_types": list(privilege_types),
            "escalation_methods": list(escalation_methods),
            "event_count": len(events),
            "unique_actors": len(actors),
            "unique_targets": len(targets)
        },
        "timeline_analysis": timeline_analysis,
        "risk_assessment": risk_assessment,
        "historical_context": historical_context,
        "recommended_actions": generate_escalation_response_actions(events)
    }


def extract_target_groups(event: Dict[str, Any]) -> Set[str]:
    """Extract target groups from group membership events"""
    targets = set()
    
    # Check various locations where group information might be stored
    target_info = event.get("target", [])
    if isinstance(target_info, list):
        for target in target_info:
            if target.get("type") == "UserGroup":
                targets.add(target.get("displayName", ""))
    
    # Check in legacyEventType for some event formats
    debug_context = event.get("debugcontext", {})
    debug_data = debug_context.get("debugdata", {})
    if "groupName" in debug_data:
        targets.add(debug_data["groupName"])
    
    return targets


def extract_target_applications(event: Dict[str, Any]) -> Set[str]:
    """Extract target applications from application membership events"""
    targets = set()
    
    target_info = event.get("target", [])
    if isinstance(target_info, list):
        for target in target_info:
            if target.get("type") == "AppInstance":
                targets.add(target.get("displayName", ""))
    
    return targets


def extract_escalation_target(event: Dict[str, Any]) -> str:
    """Extract the primary target of the escalation"""
    # Try groups first
    target_groups = extract_target_groups(event)
    if target_groups:
        return f"groups:{','.join(target_groups)}"
    
    # Try applications
    target_apps = extract_target_applications(event)
    if target_apps:
        return f"apps:{','.join(target_apps)}"
    
    # Try target user
    targets = event.get("target", [])
    if isinstance(targets, list) and targets:
        for target in targets:
            if target.get("type") == "User":
                return f"user:{target.get('alternateId', 'unknown')}"
    
    return event.get("eventtype", "unknown")


def determine_escalation_type(event: Dict[str, Any]) -> str:
    """Classify the type of privilege escalation"""
    event_type = event.get("eventtype", "")
    escalation_types = []
    
    # Check for high-privilege groups
    target_groups = extract_target_groups(event)
    if "Super Admins" in target_groups:
        escalation_types.append("super_admin")
    elif "Security Admins" in target_groups:
        escalation_types.append("security_admin")
    elif target_groups.intersection(PRIVILEGED_GROUPS):
        escalation_types.append("privileged_group")
    
    # Check for privileged applications
    target_apps = extract_target_applications(event)
    if target_apps.intersection(PRIVILEGED_APPS):
        escalation_types.append("privileged_app")
    
    # Check for timing
    if is_off_hours(event):
        escalation_types.append("off_hours")
    
    # Check for external users
    actor = event.get("actor", {})
    if is_external_user(actor):
        escalation_types.append("external_user")
    
    # Check for bulk operations
    if is_bulk_operation(event):
        escalation_types.append("bulk_assignment")
    
    return ",".join(escalation_types) if escalation_types else "standard"


def determine_privilege_type(event: Dict[str, Any]) -> str:
    """Determine the type of privilege being escalated"""
    event_type = event.get("eventtype", "")
    
    if "group" in event_type:
        return "group_membership"
    elif "application" in event_type:
        return "application_access"
    elif "policy" in event_type:
        return "policy_assignment"
    elif "role" in event_type:
        return "role_assignment"
    else:
        return "unknown_privilege"


def is_off_hours_admin_action(event: Dict[str, Any]) -> bool:
    """Check if this is an administrative action during off-hours"""
    if not is_off_hours(event):
        return False
    
    event_type = event.get("eventtype", "")
    admin_actions = [
        "user.lifecycle.create",
        "user.lifecycle.activate",
        "user.lifecycle.deactivate",
        "group.user_membership.add",
        "group.user_membership.remove",
        "application.user_membership.add",
        "policy.lifecycle.create",
        "policy.lifecycle.update"
    ]
    
    return event_type in admin_actions


def is_off_hours(event: Dict[str, Any]) -> bool:
    """Check if event occurred during off-hours (weekends or nights)"""
    published = event.get("published")
    if not published:
        return False
    
    try:
        event_time = datetime.fromisoformat(published.replace('Z', '+00:00'))
        # Convert to local business hours (assuming US Central Time for this example)
        # In production, this should be configurable based on organization timezone
        
        # Check if weekend
        if event_time.weekday() >= 5:  # Saturday=5, Sunday=6
            return True
        
        # Check if outside business hours (before 8 AM or after 6 PM)
        hour = event_time.hour
        if hour < 8 or hour >= 18:
            return True
            
    except (ValueError, AttributeError):
        return False
    
    return False


def is_external_user(actor: Dict[str, Any]) -> bool:
    """Check if the actor is an external user"""
    actor_id = actor.get("alternateId", "")
    
    # Check for common external user patterns
    external_patterns = [
        "@contractor.",
        "@vendor.",
        "@external.",
        "@guest.",
        "@temp."
    ]
    
    return any(pattern in actor_id.lower() for pattern in external_patterns)


def is_bulk_operation(event: Dict[str, Any]) -> bool:
    """Detect if this might be part of a bulk privilege assignment operation"""
    # This would need to be enhanced with stateful detection across multiple events
    # For now, check for indicators in the event itself
    
    debug_context = event.get("debugcontext", {})
    debug_data = debug_context.get("debugdata", {})
    
    # Look for bulk operation indicators
    if "bulk" in str(debug_data).lower():
        return True
    
    # Check for automated vs manual operations
    request_info = event.get("request", {})
    if request_info.get("ipChain", []):
        # Multiple IP addresses might indicate automation
        return len(request_info["ipChain"]) > 2
    
    return False


def analyze_escalation_timeline(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze the timeline of privilege escalation events"""
    if len(events) < 2:
        return {"timeline_pattern": "single_event"}
    
    timestamps = []
    for event in events:
        published = event.get("published")
        if published:
            try:
                timestamps.append(datetime.fromisoformat(published.replace('Z', '+00:00')))
            except ValueError:
                continue
    
    if len(timestamps) < 2:
        return {"timeline_pattern": "insufficient_timestamps"}
    
    timestamps.sort()
    
    # Calculate time between events
    intervals = []
    for i in range(1, len(timestamps)):
        interval = (timestamps[i] - timestamps[i-1]).total_seconds()
        intervals.append(interval)
    
    # Analyze patterns
    avg_interval = sum(intervals) / len(intervals)
    total_duration = (timestamps[-1] - timestamps[0]).total_seconds()
    
    # Classify timeline pattern
    if avg_interval < 60:  # Less than 1 minute between events
        pattern = "rapid_escalation"
    elif avg_interval < 300:  # Less than 5 minutes
        pattern = "quick_escalation"
    elif total_duration > 3600:  # More than 1 hour total
        pattern = "gradual_escalation"
    else:
        pattern = "normal_escalation"
    
    return {
        "timeline_pattern": pattern,
        "total_duration_seconds": total_duration,
        "average_interval_seconds": avg_interval,
        "event_count": len(events),
        "start_time": timestamps[0].isoformat(),
        "end_time": timestamps[-1].isoformat()
    }


def assess_escalation_risk(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Assess the risk level of the privilege escalation"""
    risk_score = 0.0
    risk_factors = []
    
    # Base risk for privilege escalation
    risk_score += 0.4
    
    # Analyze privilege types escalated
    privilege_types = set()
    for event in events:
        privilege_types.add(determine_privilege_type(event))
    
    if "group_membership" in privilege_types:
        risk_score += 0.2
        risk_factors.append("Group membership changes")
    
    if "application_access" in privilege_types:
        risk_score += 0.3
        risk_factors.append("Privileged application access")
    
    # Check for super admin escalation
    super_admin_detected = False
    for event in events:
        if "super_admin" in determine_escalation_type(event):
            risk_score += 0.4
            super_admin_detected = True
            break
    
    if super_admin_detected:
        risk_factors.append("Super admin privileges involved")
    
    # Off-hours activity
    off_hours_count = sum(1 for event in events if is_off_hours(event))
    if off_hours_count > 0:
        risk_score += 0.2
        risk_factors.append(f"Off-hours activity ({off_hours_count} events)")
    
    # Multiple targets
    unique_targets = len(set(extract_escalation_target(event) for event in events))
    if unique_targets > 3:
        risk_score += 0.1
        risk_factors.append(f"Multiple targets ({unique_targets})")
    
    # External users
    external_actors = sum(1 for event in events if is_external_user(event.get("actor", {})))
    if external_actors > 0:
        risk_score += 0.3
        risk_factors.append(f"External actors involved ({external_actors})")
    
    # Risk level classification
    if risk_score >= 0.9:
        risk_level = "CRITICAL"
    elif risk_score >= 0.7:
        risk_level = "HIGH"
    elif risk_score >= 0.5:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    return {
        "risk_score": min(risk_score, 1.0),
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "privilege_types_involved": list(privilege_types)
    }


def get_historical_privilege_context(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Get historical context for privilege escalation (placeholder for external data)"""
    # In production, this would query historical data
    actors = set(event.get("actor", {}).get("alternateId") for event in events)
    
    return {
        "actors_analyzed": list(actors),
        "note": "Historical analysis would require external data store integration",
        "recommended_lookback": "30 days for behavioral baseline comparison"
    }


def generate_escalation_response_actions(events: List[Dict[str, Any]]) -> List[str]:
    """Generate recommended response actions for privilege escalation"""
    actions = []
    
    if not events:
        return actions
    
    escalation_types = [determine_escalation_type(event) for event in events]
    actors = set(event.get("actor", {}).get("alternateId") for event in events)
    
    # Super admin escalations require immediate action
    if any("super_admin" in esc_type for esc_type in escalation_types):
        actions.extend([
            "IMMEDIATE: Verify super admin privilege assignment with security team",
            "IMMEDIATE: Review all recent activities by newly privileged users",
            "Consider temporary privilege suspension pending review"
        ])
    
    # Off-hours escalations need verification
    if any("off_hours" in esc_type for esc_type in escalation_types):
        actions.extend([
            "Verify off-hours privilege changes with requesting manager",
            "Check if change request tickets exist for these modifications",
            "Review authentication logs for the time period"
        ])
    
    # External user escalations need special handling
    if any("external_user" in esc_type for esc_type in escalation_types):
        actions.extend([
            "Verify external user privilege requirements with business owner",
            "Ensure external user access is time-limited",
            "Review external user background check status"
        ])
    
    # General recommendations
    actions.extend([
        "Document the business justification for privilege changes",
        "Update privilege access review schedules",
        f"Monitor activities of affected users: {', '.join(list(actors)[:5])}",
        "Consider implementing additional approval workflows for similar privilege levels"
    ])
    
    return actions