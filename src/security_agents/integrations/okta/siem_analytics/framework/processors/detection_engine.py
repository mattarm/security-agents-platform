"""
IAM Security Detection Engine
Core detection logic and pattern matching for identity threats
"""

import asyncio
import logging
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from collections import defaultdict, Counter

from ..adapters.platform_adapter import (
    NormalizedEvent, DetectionResult, DetectionType, AlertSeverity, PlatformType
)
from ...ueba.models.behavior_baseline import BehaviorBaselineEngine, BehaviorFeatures

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class DetectionPattern:
    """Detection pattern definition"""
    pattern_id: str
    name: str
    description: str
    detection_type: DetectionType
    severity: AlertSeverity
    confidence_threshold: float
    time_window: timedelta
    conditions: Dict[str, Any]


class ThreatPatternDetector:
    """Advanced threat pattern detection engine"""
    
    def __init__(self, ueba_engine: BehaviorBaselineEngine):
        self.ueba_engine = ueba_engine
        self.detection_patterns = self._initialize_patterns()
        
    def _initialize_patterns(self) -> Dict[str, DetectionPattern]:
        """Initialize detection patterns"""
        patterns = {}
        
        # Credential Stuffing Patterns
        patterns["credential_stuffing_basic"] = DetectionPattern(
            pattern_id="cs_basic",
            name="Basic Credential Stuffing",
            description="Multiple failed logins from single source targeting multiple users",
            detection_type=DetectionType.CREDENTIAL_STUFFING,
            severity=AlertSeverity.MEDIUM,
            confidence_threshold=0.7,
            time_window=timedelta(minutes=5),
            conditions={
                "min_failed_attempts": 5,
                "min_unique_users": 3,
                "max_time_window": 300  # seconds
            }
        )
        
        patterns["credential_stuffing_distributed"] = DetectionPattern(
            pattern_id="cs_distributed",
            name="Distributed Credential Stuffing",
            description="Coordinated credential stuffing from multiple sources",
            detection_type=DetectionType.CREDENTIAL_STUFFING,
            severity=AlertSeverity.HIGH,
            confidence_threshold=0.8,
            time_window=timedelta(minutes=15),
            conditions={
                "min_source_ips": 3,
                "min_total_attempts": 20,
                "min_unique_users": 10,
                "coordination_window": 900  # seconds
            }
        )
        
        # Privilege Escalation Patterns
        patterns["privilege_escalation_rapid"] = DetectionPattern(
            pattern_id="pe_rapid",
            name="Rapid Privilege Escalation",
            description="Multiple privilege changes in short timeframe",
            detection_type=DetectionType.PRIVILEGE_ESCALATION,
            severity=AlertSeverity.HIGH,
            confidence_threshold=0.9,
            time_window=timedelta(minutes=30),
            conditions={
                "min_escalations": 2,
                "max_time_window": 1800,  # seconds
                "privilege_groups": ["Super Admins", "Application Admins", "Security Admins"]
            }
        )
        
        patterns["privilege_escalation_off_hours"] = DetectionPattern(
            pattern_id="pe_off_hours",
            name="Off-Hours Privilege Escalation",
            description="Privilege escalation during non-business hours",
            detection_type=DetectionType.PRIVILEGE_ESCALATION,
            severity=AlertSeverity.HIGH,
            confidence_threshold=0.8,
            time_window=timedelta(hours=4),
            conditions={
                "business_hours_start": 8,
                "business_hours_end": 18,
                "include_weekends": True
            }
        )
        
        # Account Takeover Patterns
        patterns["account_takeover_behavioral"] = DetectionPattern(
            pattern_id="ato_behavioral",
            name="Behavioral Account Takeover",
            description="Account access with significant behavioral anomalies",
            detection_type=DetectionType.ACCOUNT_TAKEOVER,
            severity=AlertSeverity.HIGH,
            confidence_threshold=0.8,
            time_window=timedelta(hours=6),
            conditions={
                "min_anomaly_score": 0.7,
                "behavioral_factors": ["geo", "temporal", "device"],
                "success_after_failures": True
            }
        )
        
        patterns["account_takeover_impossible_travel"] = DetectionPattern(
            pattern_id="ato_impossible_travel",
            name="Impossible Travel Detection",
            description="Geographically impossible travel between login locations",
            detection_type=DetectionType.ACCOUNT_TAKEOVER,
            severity=AlertSeverity.MEDIUM,
            confidence_threshold=0.7,
            time_window=timedelta(hours=2),
            conditions={
                "max_travel_speed_kmh": 800,  # Commercial flight speed
                "min_distance_km": 500,
                "exclude_vpn_ranges": True
            }
        )
        
        # Lateral Movement Patterns
        patterns["lateral_movement_cross_app"] = DetectionPattern(
            pattern_id="lm_cross_app",
            name="Cross-Application Lateral Movement",
            description="Rapid access across multiple applications",
            detection_type=DetectionType.LATERAL_MOVEMENT,
            severity=AlertSeverity.MEDIUM,
            confidence_threshold=0.6,
            time_window=timedelta(hours=1),
            conditions={
                "min_applications": 5,
                "max_time_window": 3600,  # seconds
                "privileged_apps": ["AWS SSO", "Azure AD", "Google Workspace Admin"]
            }
        )
        
        patterns["lateral_movement_privileged"] = DetectionPattern(
            pattern_id="lm_privileged",
            name="Privileged Account Lateral Movement",
            description="Lateral movement using privileged accounts",
            detection_type=DetectionType.LATERAL_MOVEMENT,
            severity=AlertSeverity.HIGH,
            confidence_threshold=0.8,
            time_window=timedelta(hours=2),
            conditions={
                "privileged_patterns": ["admin", "service", "root"],
                "min_resource_access": 3,
                "cross_network_access": True
            }
        )
        
        # Insider Threat Patterns
        patterns["insider_threat_data_hoarding"] = DetectionPattern(
            pattern_id="it_data_hoarding",
            name="Data Hoarding Behavior",
            description="Unusual data access patterns indicating potential data exfiltration",
            detection_type=DetectionType.INSIDER_THREAT,
            severity=AlertSeverity.MEDIUM,
            confidence_threshold=0.7,
            time_window=timedelta(days=7),
            conditions={
                "data_access_multiplier": 3.0,  # 3x normal access
                "off_hours_percentage": 0.3,  # >30% off-hours access
                "data_applications": ["SharePoint", "Box", "Google Drive", "Confluence"]
            }
        )
        
        patterns["insider_threat_privilege_abuse"] = DetectionPattern(
            pattern_id="it_privilege_abuse",
            name="Privilege Abuse Detection",
            description="Abuse of administrative privileges for unauthorized access",
            detection_type=DetectionType.INSIDER_THREAT,
            severity=AlertSeverity.HIGH,
            confidence_threshold=0.8,
            time_window=timedelta(days=1),
            conditions={
                "admin_access_anomaly": 2.5,  # Standard deviations
                "user_access_pattern": "unusual",
                "policy_violations": True
            }
        )
        
        return patterns
    
    async def analyze_events(self, events: List[NormalizedEvent], platform: PlatformType) -> List[DetectionResult]:
        """Analyze events for threat patterns"""
        detections = []
        
        # Group events by type and time windows
        event_groups = self._group_events_by_patterns(events)
        
        # Run pattern matching for each group
        for pattern_id, pattern in self.detection_patterns.items():
            pattern_events = event_groups.get(pattern.detection_type, [])
            
            if not pattern_events:
                continue
                
            detection = await self._match_pattern(pattern, pattern_events, platform)
            if detection:
                detections.append(detection)
        
        return detections
    
    def _group_events_by_patterns(self, events: List[NormalizedEvent]) -> Dict[DetectionType, List[NormalizedEvent]]:
        """Group events by detection type for pattern matching"""
        groups = defaultdict(list)
        
        for event in events:
            # Categorize events by type
            if "authentication" in event.action.lower() and event.outcome != "SUCCESS":
                groups[DetectionType.CREDENTIAL_STUFFING].append(event)
            
            if any(term in event.action.lower() for term in ["group", "privilege", "admin", "role"]):
                groups[DetectionType.PRIVILEGE_ESCALATION].append(event)
            
            if event.outcome == "SUCCESS":
                groups[DetectionType.ACCOUNT_TAKEOVER].append(event)
                groups[DetectionType.LATERAL_MOVEMENT].append(event)
                groups[DetectionType.INSIDER_THREAT].append(event)
        
        return groups
    
    async def _match_pattern(self, pattern: DetectionPattern, events: List[NormalizedEvent], platform: PlatformType) -> Optional[DetectionResult]:
        """Match events against a specific detection pattern"""
        
        if pattern.detection_type == DetectionType.CREDENTIAL_STUFFING:
            return await self._detect_credential_stuffing_pattern(pattern, events, platform)
        elif pattern.detection_type == DetectionType.PRIVILEGE_ESCALATION:
            return await self._detect_privilege_escalation_pattern(pattern, events, platform)
        elif pattern.detection_type == DetectionType.ACCOUNT_TAKEOVER:
            return await self._detect_account_takeover_pattern(pattern, events, platform)
        elif pattern.detection_type == DetectionType.LATERAL_MOVEMENT:
            return await self._detect_lateral_movement_pattern(pattern, events, platform)
        elif pattern.detection_type == DetectionType.INSIDER_THREAT:
            return await self._detect_insider_threat_pattern(pattern, events, platform)
        
        return None
    
    async def _detect_credential_stuffing_pattern(self, pattern: DetectionPattern, events: List[NormalizedEvent], platform: PlatformType) -> Optional[DetectionResult]:
        """Detect credential stuffing patterns"""
        
        # Group events by source IP
        ip_groups = defaultdict(list)
        for event in events:
            ip_groups[event.source_ip].append(event)
        
        # Check for basic credential stuffing pattern
        if pattern.pattern_id == "cs_basic":
            for source_ip, ip_events in ip_groups.items():
                if len(ip_events) >= pattern.conditions["min_failed_attempts"]:
                    unique_users = len(set(e.user_id for e in ip_events))
                    
                    if unique_users >= pattern.conditions["min_unique_users"]:
                        # Check time window
                        timestamps = [e.timestamp for e in ip_events]
                        time_span = (max(timestamps) - min(timestamps)).total_seconds()
                        
                        if time_span <= pattern.conditions["max_time_window"]:
                            return self._create_detection_result(
                                pattern, ip_events, platform,
                                f"Credential stuffing from {source_ip}",
                                f"Multiple failed logins from {source_ip} targeting {unique_users} users",
                                confidence_score=min(0.9, 0.6 + (len(ip_events) / 20) + (unique_users / 10))
                            )
        
        # Check for distributed credential stuffing
        elif pattern.pattern_id == "cs_distributed":
            source_ips = list(ip_groups.keys())
            total_attempts = sum(len(events) for events in ip_groups.values())
            all_users = set()
            for ip_events in ip_groups.values():
                all_users.update(e.user_id for e in ip_events)
            
            if (len(source_ips) >= pattern.conditions["min_source_ips"] and
                total_attempts >= pattern.conditions["min_total_attempts"] and
                len(all_users) >= pattern.conditions["min_unique_users"]):
                
                all_events = [e for events in ip_groups.values() for e in events]
                timestamps = [e.timestamp for e in all_events]
                time_span = (max(timestamps) - min(timestamps)).total_seconds()
                
                if time_span <= pattern.conditions["coordination_window"]:
                    return self._create_detection_result(
                        pattern, all_events, platform,
                        "Distributed credential stuffing attack",
                        f"Coordinated attack from {len(source_ips)} sources targeting {len(all_users)} users",
                        confidence_score=0.9
                    )
        
        return None
    
    async def _detect_privilege_escalation_pattern(self, pattern: DetectionPattern, events: List[NormalizedEvent], platform: PlatformType) -> Optional[DetectionResult]:
        """Detect privilege escalation patterns"""
        
        if pattern.pattern_id == "pe_rapid":
            # Group by user
            user_groups = defaultdict(list)
            for event in events:
                user_groups[event.user_id].append(event)
            
            for user_id, user_events in user_groups.items():
                escalation_events = [e for e in user_events if any(group in str(e.raw_event) for group in pattern.conditions["privilege_groups"])]
                
                if len(escalation_events) >= pattern.conditions["min_escalations"]:
                    timestamps = [e.timestamp for e in escalation_events]
                    time_span = (max(timestamps) - min(timestamps)).total_seconds()
                    
                    if time_span <= pattern.conditions["max_time_window"]:
                        return self._create_detection_result(
                            pattern, escalation_events, platform,
                            f"Rapid privilege escalation for {user_id}",
                            f"Multiple privilege escalations in {time_span/60:.1f} minutes",
                            confidence_score=0.9
                        )
        
        elif pattern.pattern_id == "pe_off_hours":
            off_hours_events = []
            for event in events:
                if self._is_off_hours(event.timestamp, pattern.conditions):
                    off_hours_events.append(event)
            
            if off_hours_events:
                return self._create_detection_result(
                    pattern, off_hours_events, platform,
                    "Off-hours privilege escalation",
                    f"Privilege escalation during non-business hours affecting {len(set(e.user_id for e in off_hours_events))} users",
                    confidence_score=0.8
                )
        
        return None
    
    async def _detect_account_takeover_pattern(self, pattern: DetectionPattern, events: List[NormalizedEvent], platform: PlatformType) -> Optional[DetectionResult]:
        """Detect account takeover patterns"""
        
        if pattern.pattern_id == "ato_behavioral":
            # Use UEBA engine for behavioral analysis
            for event in events:
                if event.outcome == "SUCCESS":
                    # Convert to behavior features
                    features = self._convert_to_behavior_features(event)
                    
                    # Calculate anomaly score using UEBA engine
                    anomaly_score = self.ueba_engine.calculate_anomaly_score(event.user_id, features)
                    
                    if anomaly_score >= pattern.conditions["min_anomaly_score"]:
                        return self._create_detection_result(
                            pattern, [event], platform,
                            f"Behavioral anomaly for {event.user_id}",
                            f"Successful login with high anomaly score ({anomaly_score:.2f})",
                            confidence_score=anomaly_score
                        )
        
        elif pattern.pattern_id == "ato_impossible_travel":
            # Group by user for impossible travel detection
            user_groups = defaultdict(list)
            for event in events:
                if event.outcome == "SUCCESS" and event.latitude != 0 and event.longitude != 0:
                    user_groups[event.user_id].append(event)
            
            for user_id, user_events in user_groups.items():
                if len(user_events) >= 2:
                    # Sort by timestamp
                    user_events.sort(key=lambda x: x.timestamp)
                    
                    for i in range(1, len(user_events)):
                        prev_event = user_events[i-1]
                        curr_event = user_events[i]
                        
                        # Calculate travel details
                        distance_km = self._calculate_distance(
                            (prev_event.latitude, prev_event.longitude),
                            (curr_event.latitude, curr_event.longitude)
                        )
                        
                        time_diff = (curr_event.timestamp - prev_event.timestamp).total_seconds()
                        travel_speed = (distance_km / (time_diff / 3600)) if time_diff > 0 else 0
                        
                        if (distance_km >= pattern.conditions["min_distance_km"] and 
                            travel_speed > pattern.conditions["max_travel_speed_kmh"]):
                            
                            return self._create_detection_result(
                                pattern, [prev_event, curr_event], platform,
                                f"Impossible travel detected for {user_id}",
                                f"Travel from {prev_event.city} to {curr_event.city} ({distance_km:.0f}km) in {time_diff/60:.0f} minutes",
                                confidence_score=min(0.9, travel_speed / 1000)
                            )
        
        return None
    
    async def _detect_lateral_movement_pattern(self, pattern: DetectionPattern, events: List[NormalizedEvent], platform: PlatformType) -> Optional[DetectionResult]:
        """Detect lateral movement patterns"""
        
        if pattern.pattern_id == "lm_cross_app":
            # Group by user
            user_groups = defaultdict(list)
            for event in events:
                if event.outcome == "SUCCESS":
                    user_groups[event.user_id].append(event)
            
            for user_id, user_events in user_groups.items():
                # Count unique applications accessed
                applications = set(e.application for e in user_events if e.application != "unknown")
                
                if len(applications) >= pattern.conditions["min_applications"]:
                    timestamps = [e.timestamp for e in user_events]
                    time_span = (max(timestamps) - min(timestamps)).total_seconds()
                    
                    if time_span <= pattern.conditions["max_time_window"]:
                        # Check for privileged applications
                        privileged_apps = [app for app in applications if app in pattern.conditions["privileged_apps"]]
                        
                        confidence = 0.6 + (len(applications) / 20) + (len(privileged_apps) / 5)
                        
                        return self._create_detection_result(
                            pattern, user_events, platform,
                            f"Cross-application lateral movement by {user_id}",
                            f"Access to {len(applications)} applications in {time_span/60:.0f} minutes",
                            confidence_score=min(0.9, confidence)
                        )
        
        return None
    
    async def _detect_insider_threat_pattern(self, pattern: DetectionPattern, events: List[NormalizedEvent], platform: PlatformType) -> Optional[DetectionResult]:
        """Detect insider threat patterns"""
        
        if pattern.pattern_id == "it_data_hoarding":
            # Group by user for data access analysis
            user_groups = defaultdict(list)
            for event in events:
                if (event.outcome == "SUCCESS" and 
                    event.application in pattern.conditions["data_applications"]):
                    user_groups[event.user_id].append(event)
            
            for user_id, user_events in user_groups.items():
                if len(user_events) > 10:  # Minimum threshold for analysis
                    # Calculate off-hours access percentage
                    off_hours_events = [e for e in user_events if self._is_off_hours(e.timestamp, {"business_hours_start": 8, "business_hours_end": 18, "include_weekends": True})]
                    off_hours_percentage = len(off_hours_events) / len(user_events)
                    
                    # Check against baseline (simplified)
                    access_multiplier = len(user_events) / 10  # Simplified baseline
                    
                    if (access_multiplier >= pattern.conditions["data_access_multiplier"] and
                        off_hours_percentage >= pattern.conditions["off_hours_percentage"]):
                        
                        confidence = min(0.9, 0.5 + (access_multiplier / 10) + off_hours_percentage)
                        
                        return self._create_detection_result(
                            pattern, user_events, platform,
                            f"Data hoarding behavior by {user_id}",
                            f"Unusual data access pattern: {len(user_events)} accesses, {off_hours_percentage*100:.1f}% off-hours",
                            confidence_score=confidence
                        )
        
        return None
    
    def _create_detection_result(self, pattern: DetectionPattern, events: List[NormalizedEvent], 
                               platform: PlatformType, title: str, description: str, 
                               confidence_score: float) -> DetectionResult:
        """Create standardized detection result"""
        
        affected_users = list(set(e.user_id for e in events))
        affected_resources = list(set(e.resource for e in events if e.resource != "unknown"))
        
        # Calculate risk factors
        risk_factors = []
        if len(set(e.source_ip for e in events)) > 1:
            risk_factors.append("multiple_source_ips")
        if len(set(e.country for e in events)) > 1:
            risk_factors.append("multiple_countries")
        if any(self._is_off_hours(e.timestamp, {"business_hours_start": 8, "business_hours_end": 18}) for e in events):
            risk_factors.append("off_hours_activity")
        
        # Generate investigation queries
        investigation_queries = self._generate_investigation_queries(pattern, events)
        
        # Generate mitigation recommendations
        recommended_actions = self._generate_recommendations(pattern, events)
        
        return DetectionResult(
            detection_id=f"{pattern.pattern_id}_{platform.value}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            detection_type=pattern.detection_type,
            severity=pattern.severity,
            confidence_score=confidence_score,
            triggering_events=events,
            event_count=len(events),
            time_window=pattern.time_window,
            title=title,
            description=description,
            indicators=[f"{pattern.detection_type.value}_{pattern.pattern_id}"],
            affected_users=affected_users,
            affected_resources=affected_resources,
            risk_score=min(0.9, confidence_score * 0.8 + len(risk_factors) * 0.1),
            risk_factors=risk_factors,
            false_positive_likelihood=max(0.1, 1.0 - confidence_score),
            recommended_actions=recommended_actions,
            mitigation_steps=self._generate_mitigation_steps(pattern),
            investigation_queries=investigation_queries,
            detection_timestamp=datetime.now(),
            platform_source=platform,
            rule_version="1.0"
        )
    
    def _convert_to_behavior_features(self, event: NormalizedEvent) -> BehaviorFeatures:
        """Convert normalized event to UEBA behavior features"""
        from ...ueba.models.behavior_baseline import BehaviorFeatures
        
        return BehaviorFeatures(
            user_id=event.user_id,
            timestamp=event.timestamp,
            hour_of_day=event.timestamp.hour,
            day_of_week=event.timestamp.weekday(),
            is_weekend=event.timestamp.weekday() >= 5,
            is_business_hours=8 <= event.timestamp.hour < 18 and event.timestamp.weekday() < 5,
            country=event.country,
            city=event.city,
            latitude=event.latitude,
            longitude=event.longitude,
            device_type=event.device_info.get("type", "unknown"),
            os_type=event.device_info.get("type", "unknown"),
            browser_type=event.device_info.get("browser", "unknown"),
            ip_address=event.source_ip,
            network_zone="unknown",  # Would need network zone mapping
            application_name=event.application,
            authentication_method=event.authentication_method,
            session_duration=0,  # Would need session correlation
            is_new_device=False,  # Would need historical device tracking
            is_new_location=False,  # Would need historical location tracking
            failed_attempts_recent=0,  # Would need recent failure tracking
            privilege_level="standard"  # Would need privilege level mapping
        )
    
    def _calculate_distance(self, coord1: Tuple[float, float], coord2: Tuple[float, float]) -> float:
        """Calculate distance between coordinates in kilometers (Haversine formula)"""
        from math import radians, cos, sin, asin, sqrt
        
        lat1, lon1 = coord1
        lat2, lon2 = coord2
        
        # Convert to radians
        lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
        
        # Haversine formula
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * asin(sqrt(a))
        r = 6371  # Earth's radius in kilometers
        
        return c * r
    
    def _is_off_hours(self, timestamp: datetime, conditions: Dict[str, Any]) -> bool:
        """Check if timestamp is during off-hours"""
        hour = timestamp.hour
        day_of_week = timestamp.weekday()
        
        # Check business hours
        start_hour = conditions.get("business_hours_start", 8)
        end_hour = conditions.get("business_hours_end", 18)
        
        if hour < start_hour or hour >= end_hour:
            return True
        
        # Check weekends
        include_weekends = conditions.get("include_weekends", True)
        if include_weekends and day_of_week >= 5:  # Saturday=5, Sunday=6
            return True
        
        return False
    
    def _generate_investigation_queries(self, pattern: DetectionPattern, events: List[NormalizedEvent]) -> List[str]:
        """Generate investigation queries for the detection"""
        queries = []
        
        if pattern.detection_type == DetectionType.CREDENTIAL_STUFFING:
            source_ips = list(set(e.source_ip for e in events))
            queries.append(f"Search for additional activity from source IPs: {', '.join(source_ips[:5])}")
            
        elif pattern.detection_type == DetectionType.PRIVILEGE_ESCALATION:
            affected_users = list(set(e.user_id for e in events))
            queries.append(f"Review all privilege changes for users: {', '.join(affected_users[:5])}")
            
        elif pattern.detection_type == DetectionType.ACCOUNT_TAKEOVER:
            affected_users = list(set(e.user_id for e in events))
            queries.append(f"Review recent authentication history for: {', '.join(affected_users[:5])}")
            
        # Add time-based investigation
        start_time = min(e.timestamp for e in events)
        end_time = max(e.timestamp for e in events)
        queries.append(f"Review all activities between {start_time} and {end_time}")
        
        return queries
    
    def _generate_recommendations(self, pattern: DetectionPattern, events: List[NormalizedEvent]) -> List[str]:
        """Generate response recommendations"""
        recommendations = []
        
        if pattern.detection_type == DetectionType.CREDENTIAL_STUFFING:
            source_ips = list(set(e.source_ip for e in events))
            recommendations.extend([
                f"Consider blocking source IPs: {', '.join(source_ips[:3])}",
                "Implement rate limiting for authentication attempts",
                "Enable account lockout policies"
            ])
            
        elif pattern.detection_type == DetectionType.PRIVILEGE_ESCALATION:
            recommendations.extend([
                "Verify business justification for privilege changes",
                "Review approval workflows for privilege escalation",
                "Consider implementing just-in-time (JIT) access"
            ])
            
        elif pattern.detection_type == DetectionType.ACCOUNT_TAKEOVER:
            affected_users = list(set(e.user_id for e in events))
            recommendations.extend([
                f"Force password reset for affected users: {', '.join(affected_users[:3])}",
                "Enable additional MFA requirements",
                "Review recent access patterns"
            ])
            
        # Add general recommendations
        recommendations.append("Update threat intelligence feeds with indicators")
        recommendations.append("Document incident for future reference")
        
        return recommendations
    
    def _generate_mitigation_steps(self, pattern: DetectionPattern) -> List[str]:
        """Generate mitigation steps for the pattern type"""
        if pattern.detection_type == DetectionType.CREDENTIAL_STUFFING:
            return [
                "Implement CAPTCHA for suspicious login patterns",
                "Deploy IP-based rate limiting",
                "Enable account lockout mechanisms",
                "Implement geographic access controls"
            ]
            
        elif pattern.detection_type == DetectionType.PRIVILEGE_ESCALATION:
            return [
                "Implement multi-person approval for privilege changes",
                "Deploy just-in-time access controls",
                "Enable detailed audit logging for privilege changes",
                "Implement regular access reviews"
            ]
            
        elif pattern.detection_type == DetectionType.ACCOUNT_TAKEOVER:
            return [
                "Implement conditional access policies",
                "Deploy behavioral analytics",
                "Enable step-up authentication",
                "Implement session management controls"
            ]
            
        elif pattern.detection_type == DetectionType.LATERAL_MOVEMENT:
            return [
                "Implement network segmentation",
                "Deploy application-level access controls",
                "Enable cross-system activity correlation",
                "Implement principle of least privilege"
            ]
            
        elif pattern.detection_type == DetectionType.INSIDER_THREAT:
            return [
                "Implement data loss prevention (DLP)",
                "Deploy user activity monitoring",
                "Enable data access auditing",
                "Implement data classification and protection"
            ]
        
        return ["Review and update security policies"]