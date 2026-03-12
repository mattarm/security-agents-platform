"""
Correlation Engine for Okta Security Events

Advanced event correlation, session reconstruction, and attack pattern
detection with time-series analysis and behavioral modeling.
"""

import time
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, field
import json
from concurrent.futures import ThreadPoolExecutor

import pandas as pd
import numpy as np
from sklearn.cluster import DBSCAN
from scipy import stats
import structlog

logger = structlog.get_logger()


@dataclass
class UserSession:
    """Represents a reconstructed user session"""
    user_id: str
    session_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    events: List[Dict] = field(default_factory=list)
    locations: List[Dict] = field(default_factory=list)
    applications: Set[str] = field(default_factory=set)
    risk_score: int = 0
    anomaly_flags: List[str] = field(default_factory=list)
    
    def add_event(self, event: Dict):
        """Add event to session"""
        self.events.append(event)
        
        # Update session metadata
        event_time = datetime.fromisoformat(event['published'].replace('Z', '+00:00'))
        if event_time > self.start_time:
            self.end_time = event_time
        
        # Track locations
        if 'client' in event and 'geographicalContext' in event['client']:
            geo = event['client']['geographicalContext']
            location = {
                'country': geo.get('country'),
                'state': geo.get('state'),
                'city': geo.get('city'),
                'timestamp': event_time
            }
            self.locations.append(location)
        
        # Track applications
        if 'target' in event:
            for target in event['target']:
                if target.get('type') == 'Application':
                    self.applications.add(target.get('displayName', 'Unknown'))
    
    @property
    def duration(self) -> timedelta:
        """Get session duration"""
        if self.end_time:
            return self.end_time - self.start_time
        return timedelta(0)
    
    @property
    def unique_locations(self) -> int:
        """Get number of unique locations"""
        unique_locs = set()
        for loc in self.locations:
            unique_locs.add((loc['country'], loc['state'], loc['city']))
        return len(unique_locs)


@dataclass
class CorrelationRule:
    """Defines correlation patterns to detect"""
    name: str
    description: str
    time_window: timedelta
    event_types: List[str]
    min_events: int = 2
    max_events: int = 100
    user_scoped: bool = True
    enabled: bool = True


@dataclass
class AttackPattern:
    """Detected attack pattern"""
    pattern_id: str
    pattern_name: str
    confidence: float
    events: List[Dict]
    affected_users: Set[str]
    start_time: datetime
    end_time: datetime
    indicators: List[str]
    risk_score: int


class CorrelationEngine:
    """
    Advanced event correlation engine for detecting attack patterns,
    reconstructing user sessions, and identifying anomalous behavior.
    """
    
    def __init__(self, window_size: int = 3600):  # 1 hour window
        self.window_size = window_size
        self.event_buffer = deque(maxlen=10000)
        self.user_sessions: Dict[str, Dict[str, UserSession]] = defaultdict(dict)
        self.attack_patterns: List[AttackPattern] = []
        
        # Correlation rules
        self.correlation_rules = self._init_correlation_rules()
        
        # Statistics tracking
        self.stats = {
            'events_processed': 0,
            'sessions_created': 0,
            'patterns_detected': 0,
            'last_analysis': None
        }
        
        # Threading for background analysis
        self.executor = ThreadPoolExecutor(max_workers=2)
        
        logger.info("Correlation engine initialized", window_size=window_size)
    
    def _init_correlation_rules(self) -> List[CorrelationRule]:
        """Initialize default correlation rules"""
        return [
            CorrelationRule(
                name="credential_stuffing",
                description="Multiple failed logins followed by success",
                time_window=timedelta(minutes=30),
                event_types=[
                    "user.authentication.auth_via_mfa",
                    "user.session.start"
                ]
            ),
            CorrelationRule(
                name="impossible_travel",
                description="Authentication from impossible geographic locations",
                time_window=timedelta(hours=2),
                event_types=["user.session.start"],
                min_events=2
            ),
            CorrelationRule(
                name="privilege_escalation",
                description="Rapid privilege changes and access attempts",
                time_window=timedelta(hours=1),
                event_types=[
                    "group.user_membership.add",
                    "application.user_membership.add",
                    "user.account.privilege.grant"
                ]
            ),
            CorrelationRule(
                name="session_hijacking",
                description="Concurrent sessions from different locations",
                time_window=timedelta(minutes=15),
                event_types=["user.session.start"],
                min_events=2
            ),
            CorrelationRule(
                name="mass_enumeration",
                description="Multiple failed access attempts across users",
                time_window=timedelta(minutes=10),
                event_types=["user.authentication.auth_via_mfa"],
                user_scoped=False,
                min_events=10
            )
        ]
    
    def process_event(self, event: Dict):
        """Process incoming event for correlation analysis"""
        # Add to buffer
        event['correlation_timestamp'] = datetime.utcnow()
        self.event_buffer.append(event)
        
        self.stats['events_processed'] += 1
        
        # Update user sessions
        self._update_user_sessions(event)
        
        # Trigger correlation analysis periodically
        if self.stats['events_processed'] % 100 == 0:
            self.executor.submit(self._analyze_patterns)
    
    def _update_user_sessions(self, event: Dict):
        """Update user session tracking"""
        actor = event.get('actor', {})
        user_id = actor.get('id')
        
        if not user_id:
            return
        
        # Determine session ID (use Okta session token if available)
        session_id = self._extract_session_id(event)
        
        # Get or create session
        if session_id not in self.user_sessions[user_id]:
            session = UserSession(
                user_id=user_id,
                session_id=session_id,
                start_time=datetime.fromisoformat(event['published'].replace('Z', '+00:00'))
            )
            self.user_sessions[user_id][session_id] = session
            self.stats['sessions_created'] += 1
        else:
            session = self.user_sessions[user_id][session_id]
        
        session.add_event(event)
        
        # Analyze session for anomalies
        self._analyze_session(session)
    
    def _extract_session_id(self, event: Dict) -> str:
        """Extract or generate session ID from event"""
        # Try to extract from authentication context
        if 'authenticationContext' in event:
            auth_ctx = event['authenticationContext']
            if 'externalSessionId' in auth_ctx:
                return auth_ctx['externalSessionId']
        
        # Try to extract from debug context
        if 'debugContext' in event:
            debug_ctx = event['debugContext']
            if 'debugData' in debug_ctx and 'requestId' in debug_ctx['debugData']:
                return debug_ctx['debugData']['requestId']
        
        # Fallback: use transaction ID or generate from user+time
        transaction_id = event.get('transaction', {}).get('id')
        if transaction_id:
            return transaction_id
        
        # Last resort: generate session ID from user and day
        user_id = event.get('actor', {}).get('id', 'unknown')
        event_time = datetime.fromisoformat(event['published'].replace('Z', '+00:00'))
        day_key = event_time.strftime('%Y%m%d')
        
        return f"{user_id}_{day_key}_{event_time.hour}"
    
    def _analyze_session(self, session: UserSession):
        """Analyze session for anomalies and update risk score"""
        anomalies = []
        risk_score = 0
        
        # Impossible travel detection
        if self._detect_impossible_travel(session):
            anomalies.append('impossible_travel')
            risk_score += 50
        
        # Multiple location access
        if session.unique_locations > 3:
            anomalies.append('multiple_locations')
            risk_score += 20
        
        # Long session duration
        if session.duration > timedelta(hours=12):
            anomalies.append('extended_session')
            risk_score += 15
        
        # High number of applications accessed
        if len(session.applications) > 10:
            anomalies.append('high_app_usage')
            risk_score += 10
        
        # Update session
        session.anomaly_flags = anomalies
        session.risk_score = min(risk_score, 100)
        
        # Log high-risk sessions
        if risk_score > 60:
            logger.warning("High-risk session detected",
                         user_id=session.user_id,
                         session_id=session.session_id,
                         risk_score=risk_score,
                         anomalies=anomalies)
    
    def _detect_impossible_travel(self, session: UserSession) -> bool:
        """Detect impossible travel between locations"""
        if len(session.locations) < 2:
            return False
        
        # Sort locations by timestamp
        sorted_locations = sorted(session.locations, key=lambda x: x['timestamp'])
        
        for i in range(len(sorted_locations) - 1):
            loc1 = sorted_locations[i]
            loc2 = sorted_locations[i + 1]
            
            # Check if locations are different countries
            if loc1['country'] != loc2['country']:
                # Calculate time difference
                time_diff = (loc2['timestamp'] - loc1['timestamp']).total_seconds() / 3600  # hours
                
                # If less than 2 hours between different countries, flag as impossible
                if time_diff < 2:
                    return True
        
        return False
    
    def _analyze_patterns(self):
        """Analyze events for attack patterns"""
        self.stats['last_analysis'] = datetime.utcnow()
        
        # Get recent events for analysis
        cutoff_time = datetime.utcnow() - timedelta(seconds=self.window_size)
        recent_events = [
            event for event in self.event_buffer
            if event['correlation_timestamp'] > cutoff_time
        ]
        
        if not recent_events:
            return
        
        # Run correlation rules
        for rule in self.correlation_rules:
            if rule.enabled:
                patterns = self._apply_correlation_rule(rule, recent_events)
                self.attack_patterns.extend(patterns)
        
        # Clean up old patterns
        self._cleanup_old_patterns()
        
        logger.debug("Pattern analysis completed",
                    events_analyzed=len(recent_events),
                    patterns_found=len(self.attack_patterns))
    
    def _apply_correlation_rule(self, rule: CorrelationRule, events: List[Dict]) -> List[AttackPattern]:
        """Apply correlation rule to events"""
        patterns = []
        
        try:
            if rule.name == "credential_stuffing":
                patterns.extend(self._detect_credential_stuffing(events))
            elif rule.name == "impossible_travel":
                patterns.extend(self._detect_impossible_travel_pattern(events))
            elif rule.name == "privilege_escalation":
                patterns.extend(self._detect_privilege_escalation(events))
            elif rule.name == "session_hijacking":
                patterns.extend(self._detect_session_hijacking(events))
            elif rule.name == "mass_enumeration":
                patterns.extend(self._detect_mass_enumeration(events))
            
        except Exception as e:
            logger.error("Correlation rule failed", rule=rule.name, error=str(e))
        
        return patterns
    
    def _detect_credential_stuffing(self, events: List[Dict]) -> List[AttackPattern]:
        """Detect credential stuffing attacks"""
        patterns = []
        user_events = defaultdict(list)
        
        # Group events by user
        for event in events:
            if event.get('eventType') == 'user.authentication.auth_via_mfa':
                user_id = event.get('actor', {}).get('id')
                if user_id:
                    user_events[user_id].append(event)
        
        # Check each user for credential stuffing pattern
        for user_id, user_event_list in user_events.items():
            if len(user_event_list) < 5:  # Need multiple attempts
                continue
            
            # Sort by time
            user_event_list.sort(key=lambda x: x['published'])
            
            # Count failures and successes
            failures = [e for e in user_event_list 
                       if e.get('outcome', {}).get('result') == 'FAILURE']
            successes = [e for e in user_event_list 
                        if e.get('outcome', {}).get('result') == 'SUCCESS']
            
            # Pattern: multiple failures followed by success
            if len(failures) >= 5 and len(successes) >= 1:
                # Ensure success comes after failures
                last_failure = max(failures, key=lambda x: x['published'])
                first_success = min(successes, key=lambda x: x['published'])
                
                if first_success['published'] > last_failure['published']:
                    pattern = AttackPattern(
                        pattern_id=f"cred_stuff_{user_id}_{int(time.time())}",
                        pattern_name="Credential Stuffing",
                        confidence=0.8,
                        events=user_event_list,
                        affected_users={user_id},
                        start_time=datetime.fromisoformat(user_event_list[0]['published'].replace('Z', '+00:00')),
                        end_time=datetime.fromisoformat(user_event_list[-1]['published'].replace('Z', '+00:00')),
                        indicators=[f"{len(failures)} failed attempts", "Successful login after failures"],
                        risk_score=85
                    )
                    patterns.append(pattern)
        
        return patterns
    
    def _detect_impossible_travel_pattern(self, events: List[Dict]) -> List[AttackPattern]:
        """Detect impossible travel patterns across events"""
        patterns = []
        user_locations = defaultdict(list)
        
        # Extract location events
        for event in events:
            if 'client' in event and 'geographicalContext' in event['client']:
                user_id = event.get('actor', {}).get('id')
                if user_id:
                    geo = event['client']['geographicalContext']
                    user_locations[user_id].append({
                        'event': event,
                        'location': geo,
                        'timestamp': datetime.fromisoformat(event['published'].replace('Z', '+00:00'))
                    })
        
        # Check each user for impossible travel
        for user_id, locations in user_locations.items():
            if len(locations) < 2:
                continue
            
            locations.sort(key=lambda x: x['timestamp'])
            
            for i in range(len(locations) - 1):
                loc1, loc2 = locations[i], locations[i + 1]
                
                # Different countries within short time
                if (loc1['location'].get('country') != loc2['location'].get('country') and
                    (loc2['timestamp'] - loc1['timestamp']).total_seconds() < 7200):  # 2 hours
                    
                    pattern = AttackPattern(
                        pattern_id=f"impossible_travel_{user_id}_{int(time.time())}",
                        pattern_name="Impossible Travel",
                        confidence=0.9,
                        events=[loc1['event'], loc2['event']],
                        affected_users={user_id},
                        start_time=loc1['timestamp'],
                        end_time=loc2['timestamp'],
                        indicators=[
                            f"Travel from {loc1['location'].get('country')} to {loc2['location'].get('country')}",
                            f"Time window: {(loc2['timestamp'] - loc1['timestamp']).total_seconds() / 60:.1f} minutes"
                        ],
                        risk_score=95
                    )
                    patterns.append(pattern)
        
        return patterns
    
    def _detect_privilege_escalation(self, events: List[Dict]) -> List[AttackPattern]:
        """Detect privilege escalation patterns"""
        patterns = []
        privilege_events = []
        
        # Filter privilege-related events
        for event in events:
            event_type = event.get('eventType', '')
            if any(keyword in event_type for keyword in ['membership.add', 'privilege.grant', 'role.assign']):
                privilege_events.append(event)
        
        if len(privilege_events) < 3:
            return patterns
        
        # Group by time windows
        privilege_events.sort(key=lambda x: x['published'])
        
        # Look for multiple privilege grants in short time
        window_start = 0
        for i in range(len(privilege_events)):
            window_events = []
            start_time = datetime.fromisoformat(privilege_events[i]['published'].replace('Z', '+00:00'))
            
            for j in range(i, len(privilege_events)):
                event_time = datetime.fromisoformat(privilege_events[j]['published'].replace('Z', '+00:00'))
                if (event_time - start_time).total_seconds() <= 3600:  # 1 hour window
                    window_events.append(privilege_events[j])
                else:
                    break
            
            # If 3+ privilege events in window, flag as escalation
            if len(window_events) >= 3:
                affected_users = set()
                for event in window_events:
                    for target in event.get('target', []):
                        if target.get('type') == 'User':
                            affected_users.add(target.get('id'))
                
                pattern = AttackPattern(
                    pattern_id=f"priv_esc_{int(time.time())}_{i}",
                    pattern_name="Privilege Escalation",
                    confidence=0.75,
                    events=window_events,
                    affected_users=affected_users,
                    start_time=start_time,
                    end_time=datetime.fromisoformat(window_events[-1]['published'].replace('Z', '+00:00')),
                    indicators=[f"{len(window_events)} privilege grants", f"{len(affected_users)} users affected"],
                    risk_score=80
                )
                patterns.append(pattern)
        
        return patterns
    
    def _detect_session_hijacking(self, events: List[Dict]) -> List[AttackPattern]:
        """Detect potential session hijacking"""
        patterns = []
        user_sessions_check = defaultdict(list)
        
        # Group session events by user
        for event in events:
            if event.get('eventType') == 'user.session.start':
                user_id = event.get('actor', {}).get('id')
                if user_id and 'client' in event:
                    user_sessions_check[user_id].append(event)
        
        # Check for concurrent sessions from different IPs
        for user_id, session_events in user_sessions_check.items():
            if len(session_events) < 2:
                continue
            
            # Group by IP address and check for concurrent sessions
            ip_groups = defaultdict(list)
            for event in session_events:
                ip = event.get('client', {}).get('ipAddress', 'unknown')
                ip_groups[ip].append(event)
            
            # If multiple IPs with overlapping sessions, flag as hijacking
            if len(ip_groups) > 1:
                ips = list(ip_groups.keys())
                for i, ip1 in enumerate(ips):
                    for ip2 in ips[i+1:]:
                        events1 = ip_groups[ip1]
                        events2 = ip_groups[ip2]
                        
                        # Check for time overlap
                        for e1 in events1:
                            for e2 in events2:
                                time1 = datetime.fromisoformat(e1['published'].replace('Z', '+00:00'))
                                time2 = datetime.fromisoformat(e2['published'].replace('Z', '+00:00'))
                                
                                if abs((time2 - time1).total_seconds()) < 300:  # 5 minute window
                                    pattern = AttackPattern(
                                        pattern_id=f"hijack_{user_id}_{int(time.time())}",
                                        pattern_name="Session Hijacking",
                                        confidence=0.7,
                                        events=[e1, e2],
                                        affected_users={user_id},
                                        start_time=min(time1, time2),
                                        end_time=max(time1, time2),
                                        indicators=[f"Concurrent sessions from {ip1} and {ip2}"],
                                        risk_score=90
                                    )
                                    patterns.append(pattern)
        
        return patterns
    
    def _detect_mass_enumeration(self, events: List[Dict]) -> List[AttackPattern]:
        """Detect mass enumeration attacks"""
        patterns = []
        source_ips = defaultdict(list)
        
        # Group failed auth events by source IP
        for event in events:
            if (event.get('eventType') == 'user.authentication.auth_via_mfa' and
                event.get('outcome', {}).get('result') == 'FAILURE'):
                
                ip = event.get('client', {}).get('ipAddress')
                if ip:
                    source_ips[ip].append(event)
        
        # Check for mass enumeration from single IPs
        for ip, ip_events in source_ips.items():
            if len(ip_events) >= 20:  # 20+ failures from one IP
                affected_users = set()
                for event in ip_events:
                    user_id = event.get('actor', {}).get('id')
                    if user_id:
                        affected_users.add(user_id)
                
                # If targeting multiple users, it's enumeration
                if len(affected_users) >= 5:
                    pattern = AttackPattern(
                        pattern_id=f"enum_{ip}_{int(time.time())}",
                        pattern_name="Mass Enumeration",
                        confidence=0.85,
                        events=ip_events[:50],  # Limit events
                        affected_users=affected_users,
                        start_time=datetime.fromisoformat(ip_events[0]['published'].replace('Z', '+00:00')),
                        end_time=datetime.fromisoformat(ip_events[-1]['published'].replace('Z', '+00:00')),
                        indicators=[
                            f"{len(ip_events)} failed attempts",
                            f"{len(affected_users)} targeted users",
                            f"Source IP: {ip}"
                        ],
                        risk_score=75
                    )
                    patterns.append(pattern)
        
        return patterns
    
    def _cleanup_old_patterns(self):
        """Remove old attack patterns"""
        cutoff_time = datetime.utcnow() - timedelta(hours=24)
        self.attack_patterns = [
            pattern for pattern in self.attack_patterns
            if pattern.end_time > cutoff_time
        ]
    
    def get_user_sessions(self, user_id: str = None) -> Dict:
        """Get user sessions (all or for specific user)"""
        if user_id:
            return self.user_sessions.get(user_id, {})
        return dict(self.user_sessions)
    
    def get_attack_patterns(self, min_confidence: float = 0.0) -> List[AttackPattern]:
        """Get detected attack patterns"""
        return [
            pattern for pattern in self.attack_patterns
            if pattern.confidence >= min_confidence
        ]
    
    def get_high_risk_sessions(self, min_risk: int = 70) -> List[UserSession]:
        """Get high-risk user sessions"""
        high_risk = []
        for user_sessions in self.user_sessions.values():
            for session in user_sessions.values():
                if session.risk_score >= min_risk:
                    high_risk.append(session)
        
        return sorted(high_risk, key=lambda x: x.risk_score, reverse=True)
    
    def get_correlation_stats(self) -> Dict:
        """Get correlation engine statistics"""
        active_sessions = sum(len(sessions) for sessions in self.user_sessions.values())
        
        return {
            **self.stats,
            'active_sessions': active_sessions,
            'attack_patterns': len(self.attack_patterns),
            'correlation_rules': len([r for r in self.correlation_rules if r.enabled]),
            'buffer_size': len(self.event_buffer)
        }