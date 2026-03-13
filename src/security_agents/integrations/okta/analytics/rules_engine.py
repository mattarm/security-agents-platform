"""
Rules Engine for Okta Security Integration

Configurable rule-based threat detection with dynamic rule management,
custom conditions, and flexible alerting thresholds.
"""

import json
import re
from typing import Dict, List, Optional, Union, Any, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from collections import defaultdict, Counter
from enum import Enum
import operator
import structlog

logger = structlog.get_logger()


class RuleConditionType(Enum):
    """Types of rule conditions"""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    REGEX = "regex"
    IN_LIST = "in_list"
    NOT_IN_LIST = "not_in_list"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    BETWEEN = "between"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"


class RuleSeverity(Enum):
    """Rule severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class RuleCondition:
    """Individual rule condition"""
    field: str  # Event field to check (e.g., 'eventType', 'actor.id')
    condition_type: RuleConditionType
    value: Any  # Value to compare against
    case_sensitive: bool = True
    
    def evaluate(self, event: Dict) -> bool:
        """Evaluate condition against event"""
        try:
            # Extract field value from event using dot notation
            field_value = self._extract_field_value(event, self.field)
            
            if field_value is None and self.condition_type not in [RuleConditionType.NOT_EXISTS, RuleConditionType.EXISTS]:
                return False
            
            # Apply condition logic
            if self.condition_type == RuleConditionType.EXISTS:
                return field_value is not None
            
            elif self.condition_type == RuleConditionType.NOT_EXISTS:
                return field_value is None
            
            elif self.condition_type == RuleConditionType.EQUALS:
                return self._compare_values(field_value, self.value, operator.eq)
            
            elif self.condition_type == RuleConditionType.NOT_EQUALS:
                return self._compare_values(field_value, self.value, operator.ne)
            
            elif self.condition_type == RuleConditionType.CONTAINS:
                if isinstance(field_value, str) and isinstance(self.value, str):
                    if not self.case_sensitive:
                        return self.value.lower() in field_value.lower()
                    return self.value in field_value
                elif isinstance(field_value, (list, tuple)):
                    return self.value in field_value
                return False
            
            elif self.condition_type == RuleConditionType.NOT_CONTAINS:
                result = self._evaluate_contains(field_value)
                return not result
            
            elif self.condition_type == RuleConditionType.REGEX:
                if isinstance(field_value, str) and isinstance(self.value, str):
                    flags = 0 if self.case_sensitive else re.IGNORECASE
                    return bool(re.search(self.value, field_value, flags))
                return False
            
            elif self.condition_type == RuleConditionType.IN_LIST:
                if isinstance(self.value, (list, tuple)):
                    return field_value in self.value
                return False
            
            elif self.condition_type == RuleConditionType.NOT_IN_LIST:
                if isinstance(self.value, (list, tuple)):
                    return field_value not in self.value
                return True
            
            elif self.condition_type == RuleConditionType.GREATER_THAN:
                return self._compare_numeric(field_value, self.value, operator.gt)
            
            elif self.condition_type == RuleConditionType.LESS_THAN:
                return self._compare_numeric(field_value, self.value, operator.lt)
            
            elif self.condition_type == RuleConditionType.BETWEEN:
                if isinstance(self.value, (list, tuple)) and len(self.value) == 2:
                    min_val, max_val = self.value
                    return self._compare_numeric(field_value, min_val, operator.ge) and \
                           self._compare_numeric(field_value, max_val, operator.le)
                return False
            
            return False
            
        except Exception as e:
            logger.warning("Rule condition evaluation failed", 
                         field=self.field, 
                         condition=self.condition_type.value,
                         error=str(e))
            return False
    
    def _extract_field_value(self, event: Dict, field_path: str) -> Any:
        """Extract field value using dot notation (e.g., 'actor.id')"""
        try:
            value = event
            for part in field_path.split('.'):
                if isinstance(value, dict):
                    value = value.get(part)
                elif isinstance(value, list) and part.isdigit():
                    idx = int(part)
                    value = value[idx] if 0 <= idx < len(value) else None
                else:
                    return None
            return value
        except (KeyError, IndexError, TypeError):
            return None
    
    def _compare_values(self, field_value: Any, compare_value: Any, op: Callable) -> bool:
        """Compare values with type handling"""
        try:
            # Handle string comparison
            if isinstance(field_value, str) and isinstance(compare_value, str):
                if not self.case_sensitive:
                    return op(field_value.lower(), compare_value.lower())
                return op(field_value, compare_value)
            
            # Direct comparison for same types
            if type(field_value) == type(compare_value):
                return op(field_value, compare_value)
            
            # Try to convert types
            if isinstance(field_value, (int, float)) and isinstance(compare_value, str):
                try:
                    return op(field_value, float(compare_value))
                except ValueError:
                    pass
            
            if isinstance(field_value, str) and isinstance(compare_value, (int, float)):
                try:
                    return op(float(field_value), compare_value)
                except ValueError:
                    pass
            
            # Fallback to string comparison
            return op(str(field_value), str(compare_value))
            
        except Exception:
            return False
    
    def _compare_numeric(self, field_value: Any, compare_value: Any, op: Callable) -> bool:
        """Compare numeric values"""
        try:
            # Convert to numbers
            if isinstance(field_value, str):
                field_value = float(field_value)
            if isinstance(compare_value, str):
                compare_value = float(compare_value)
            
            return op(field_value, compare_value)
            
        except (ValueError, TypeError):
            return False


@dataclass 
class SecurityRule:
    """Security detection rule definition"""
    rule_id: str
    name: str
    description: str
    severity: RuleSeverity
    enabled: bool = True
    
    # Conditions (all must match for AND logic)
    conditions: List[RuleCondition] = field(default_factory=list)
    
    # Event aggregation settings
    time_window: Optional[timedelta] = None  # Time window for aggregation
    min_events: int = 1  # Minimum events to trigger
    max_events: int = None  # Maximum events before triggering
    group_by: List[str] = field(default_factory=list)  # Fields to group by
    
    # Rate limiting
    cooldown_period: Optional[timedelta] = None  # Don't fire again within this period
    
    # Metadata
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)  # MITRE ATT&CK, etc.
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    # Actions
    auto_response: bool = False
    response_actions: List[str] = field(default_factory=list)


@dataclass
class RuleMatch:
    """Represents a rule match/alert"""
    rule_id: str
    rule_name: str
    severity: RuleSeverity
    timestamp: datetime
    events: List[Dict]
    group_key: str
    description: str
    indicators: List[str]
    affected_entities: Dict[str, List[str]]  # entity_type -> list of IDs


class RuleEngine:
    """
    Advanced rule engine for threat detection with support for:
    - Complex conditional logic
    - Event aggregation and correlation
    - Time-based windowing
    - Rate limiting and cooldowns
    - Dynamic rule management
    """
    
    def __init__(self, rules_config_path: str = None):
        self.rules: Dict[str, SecurityRule] = {}
        self.rule_state: Dict[str, Dict] = defaultdict(dict)  # Track rule firing state
        self.event_buffer: Dict[str, List[Dict]] = defaultdict(list)  # Buffered events for windowing
        self.last_cleanup = datetime.utcnow()
        self.rules_config_path = rules_config_path
        
        # Load default rules
        self._load_default_rules()
        
        # Load custom rules if config provided
        if rules_config_path:
            self.load_rules_from_file(rules_config_path)
        
        logger.info("Rules engine initialized", rules_count=len(self.rules))
    
    def _load_default_rules(self):
        """Load default security rules"""
        
        # Rule 1: Multiple Failed Logins
        self.add_rule(SecurityRule(
            rule_id="OKTA-001",
            name="Multiple Failed Logins",
            description="Detect multiple failed login attempts indicating brute force attack",
            severity=RuleSeverity.HIGH,
            conditions=[
                RuleCondition("eventType", RuleConditionType.EQUALS, "user.authentication.auth_via_mfa"),
                RuleCondition("outcome.result", RuleConditionType.EQUALS, "FAILURE")
            ],
            time_window=timedelta(minutes=15),
            min_events=5,
            group_by=["actor.id", "client.ipAddress"],
            tags=["brute_force", "authentication"],
            references=["MITRE:T1110"],
            auto_response=True,
            response_actions=["suspend_user", "block_ip"],
            cooldown_period=timedelta(hours=1)
        ))
        
        # Rule 2: Login from Unknown Country
        self.add_rule(SecurityRule(
            rule_id="OKTA-002", 
            name="Login from Unknown Country",
            description="User login from a country not seen in last 30 days",
            severity=RuleSeverity.MEDIUM,
            conditions=[
                RuleCondition("eventType", RuleConditionType.EQUALS, "user.session.start"),
                RuleCondition("outcome.result", RuleConditionType.EQUALS, "SUCCESS")
            ],
            tags=["geographic", "anomaly"],
            references=["MITRE:T1078"]
        ))
        
        # Rule 3: Privilege Escalation
        self.add_rule(SecurityRule(
            rule_id="OKTA-003",
            name="Rapid Privilege Escalation", 
            description="Multiple privilege grants in short time window",
            severity=RuleSeverity.HIGH,
            conditions=[
                RuleCondition("eventType", RuleConditionType.REGEX, r"(group\.user_membership\.add|application\.user_membership\.add)")
            ],
            time_window=timedelta(minutes=30),
            min_events=3,
            group_by=["target.0.id"],  # Target user
            tags=["privilege_escalation"],
            references=["MITRE:T1078.004"],
            cooldown_period=timedelta(hours=2)
        ))
        
        # Rule 4: Admin Actions After Hours
        self.add_rule(SecurityRule(
            rule_id="OKTA-004",
            name="Administrative Actions After Hours",
            description="Administrative actions performed outside business hours",
            severity=RuleSeverity.MEDIUM,
            conditions=[
                RuleCondition("eventType", RuleConditionType.REGEX, r"(admin\.|group\..*\.add|application\..*\.add)"),
                # This will be handled in custom logic since time-based conditions need special handling
            ],
            tags=["administrative", "time_anomaly"],
            cooldown_period=timedelta(hours=4)
        ))
        
        # Rule 5: Concurrent Sessions from Different Locations
        self.add_rule(SecurityRule(
            rule_id="OKTA-005",
            name="Concurrent Sessions Different Locations",
            description="User sessions from different countries within short time",
            severity=RuleSeverity.HIGH,
            conditions=[
                RuleCondition("eventType", RuleConditionType.EQUALS, "user.session.start")
            ],
            time_window=timedelta(minutes=10),
            min_events=2,
            group_by=["actor.id"],
            tags=["impossible_travel", "session_hijacking"],
            references=["MITRE:T1185"],
            cooldown_period=timedelta(hours=1)
        ))
        
        # Rule 6: Mass User Enumeration
        self.add_rule(SecurityRule(
            rule_id="OKTA-006",
            name="Mass User Enumeration",
            description="High volume of authentication attempts across multiple users from single IP",
            severity=RuleSeverity.MEDIUM,
            conditions=[
                RuleCondition("eventType", RuleConditionType.CONTAINS, "authentication"),
                RuleCondition("outcome.result", RuleConditionType.EQUALS, "FAILURE")
            ],
            time_window=timedelta(minutes=30),
            min_events=20,
            group_by=["client.ipAddress"],
            tags=["enumeration", "reconnaissance"],
            references=["MITRE:T1087"],
            cooldown_period=timedelta(hours=2)
        ))
        
        # Rule 7: Suspicious Application Access
        self.add_rule(SecurityRule(
            rule_id="OKTA-007",
            name="High-Risk Application Access",
            description="Access to high-risk applications from unusual location or device",
            severity=RuleSeverity.MEDIUM,
            conditions=[
                RuleCondition("eventType", RuleConditionType.EQUALS, "application.user_membership.add"),
                RuleCondition("target.0.displayName", RuleConditionType.IN_LIST, [
                    "AWS", "Azure", "Google Cloud", "Admin Console", "GitHub Enterprise"
                ])
            ],
            tags=["application_access", "high_risk"],
            cooldown_period=timedelta(minutes=30)
        ))
        
        # Rule 8: Password Policy Bypass Attempts
        self.add_rule(SecurityRule(
            rule_id="OKTA-008",
            name="Password Policy Bypass",
            description="Multiple password change attempts indicating policy bypass",
            severity=RuleSeverity.MEDIUM,
            conditions=[
                RuleCondition("eventType", RuleConditionType.EQUALS, "user.account.update_password"),
                RuleCondition("outcome.result", RuleConditionType.EQUALS, "FAILURE")
            ],
            time_window=timedelta(minutes=10),
            min_events=3,
            group_by=["actor.id"],
            tags=["password_policy", "policy_bypass"],
            cooldown_period=timedelta(hours=1)
        ))
    
    def add_rule(self, rule: SecurityRule):
        """Add or update a security rule"""
        rule.updated_at = datetime.utcnow()
        self.rules[rule.rule_id] = rule
        logger.info("Rule added/updated", rule_id=rule.rule_id, name=rule.name)
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a security rule"""
        if rule_id in self.rules:
            del self.rules[rule_id]
            # Clean up rule state
            if rule_id in self.rule_state:
                del self.rule_state[rule_id]
            logger.info("Rule removed", rule_id=rule_id)
            return True
        return False
    
    def enable_rule(self, rule_id: str):
        """Enable a rule"""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = True
            logger.info("Rule enabled", rule_id=rule_id)
    
    def disable_rule(self, rule_id: str):
        """Disable a rule"""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = False
            logger.info("Rule disabled", rule_id=rule_id)
    
    def process_events(self, events: List[Dict]) -> List[RuleMatch]:
        """Process events against all enabled rules"""
        if not events:
            return []
        
        matches = []
        
        # Process each event against all rules
        for event in events:
            event_matches = self._process_single_event(event)
            matches.extend(event_matches)
        
        # Process time-windowed rules
        windowed_matches = self._process_windowed_rules()
        matches.extend(windowed_matches)
        
        # Cleanup old state periodically
        if datetime.utcnow() - self.last_cleanup > timedelta(hours=1):
            self._cleanup_state()
        
        # Sort matches by severity and timestamp
        matches = sorted(matches, key=lambda x: (x.severity.value, x.timestamp), reverse=True)
        
        logger.info("Rules engine processed events", 
                   events_count=len(events), 
                   matches_count=len(matches))
        
        return matches
    
    def _process_single_event(self, event: Dict) -> List[RuleMatch]:
        """Process single event against immediate rules (no time window)"""
        matches = []
        
        for rule in self.rules.values():
            if not rule.enabled:
                continue
            
            # Skip windowed rules here
            if rule.time_window:
                self._buffer_event_for_rule(rule, event)
                continue
            
            # Check if rule matches event
            if self._evaluate_rule_conditions(rule, event):
                # Check cooldown
                if self._is_rule_in_cooldown(rule, event):
                    continue
                
                match = self._create_rule_match(rule, [event], "immediate")
                matches.append(match)
                
                # Update rule state for cooldown tracking
                self._update_rule_state(rule, match)
        
        return matches
    
    def _process_windowed_rules(self) -> List[RuleMatch]:
        """Process rules that require time windowing"""
        matches = []
        
        for rule in self.rules.values():
            if not rule.enabled or not rule.time_window:
                continue
            
            # Get buffered events for this rule within time window
            cutoff_time = datetime.utcnow() - rule.time_window
            rule_buffer = self.event_buffer.get(rule.rule_id, [])
            
            # Filter events within window
            windowed_events = [
                event for event in rule_buffer
                if datetime.fromisoformat(event['published'].replace('Z', '+00:00')) > cutoff_time
            ]
            
            if len(windowed_events) < rule.min_events:
                continue
            
            # Group events by specified fields
            if rule.group_by:
                grouped_events = self._group_events(windowed_events, rule.group_by)
            else:
                grouped_events = {"all": windowed_events}
            
            # Check each group
            for group_key, group_events in grouped_events.items():
                if len(group_events) >= rule.min_events:
                    # Check max events threshold
                    if rule.max_events and len(group_events) > rule.max_events:
                        group_events = group_events[-rule.max_events:]  # Take most recent
                    
                    # Apply special logic for certain rule types
                    if self._apply_special_rule_logic(rule, group_events):
                        # Check cooldown
                        cooldown_key = f"{rule.rule_id}_{group_key}"
                        if self._is_rule_in_cooldown_by_key(cooldown_key, rule.cooldown_period):
                            continue
                        
                        match = self._create_rule_match(rule, group_events, group_key)
                        matches.append(match)
                        
                        # Update cooldown state
                        self.rule_state[cooldown_key] = {
                            'last_fired': datetime.utcnow(),
                            'match': match
                        }
        
        return matches
    
    def _buffer_event_for_rule(self, rule: SecurityRule, event: Dict):
        """Buffer event for time-windowed rule processing"""
        # First check if event matches rule conditions
        if self._evaluate_rule_conditions(rule, event):
            if rule.rule_id not in self.event_buffer:
                self.event_buffer[rule.rule_id] = []
            
            self.event_buffer[rule.rule_id].append(event)
            
            # Keep buffer size manageable
            if len(self.event_buffer[rule.rule_id]) > 1000:
                self.event_buffer[rule.rule_id] = self.event_buffer[rule.rule_id][-500:]
    
    def _evaluate_rule_conditions(self, rule: SecurityRule, event: Dict) -> bool:
        """Evaluate if event matches all rule conditions"""
        if not rule.conditions:
            return True
        
        # All conditions must match (AND logic)
        for condition in rule.conditions:
            if not condition.evaluate(event):
                return False
        
        return True
    
    def _apply_special_rule_logic(self, rule: SecurityRule, events: List[Dict]) -> bool:
        """Apply special logic for certain rule types"""
        
        # Special logic for impossible travel detection
        if rule.rule_id == "OKTA-005":
            return self._check_impossible_travel(events)
        
        # Special logic for admin after hours
        if rule.rule_id == "OKTA-004":
            return self._check_after_hours(events)
        
        # Special logic for geographic anomalies
        if rule.rule_id == "OKTA-002":
            return self._check_geographic_anomaly(events)
        
        # Default: rule matches if we have enough events
        return True
    
    def _check_impossible_travel(self, events: List[Dict]) -> bool:
        """Check for impossible travel between login locations"""
        if len(events) < 2:
            return False
        
        # Sort events by time
        sorted_events = sorted(events, key=lambda x: x['published'])
        
        # Check each consecutive pair for impossible travel
        for i in range(len(sorted_events) - 1):
            event1, event2 = sorted_events[i], sorted_events[i + 1]
            
            # Get locations
            geo1 = event1.get('client', {}).get('geographicalContext', {})
            geo2 = event2.get('client', {}).get('geographicalContext', {})
            
            country1 = geo1.get('country')
            country2 = geo2.get('country')
            
            if country1 and country2 and country1 != country2:
                # Calculate time difference
                time1 = datetime.fromisoformat(event1['published'].replace('Z', '+00:00'))
                time2 = datetime.fromisoformat(event2['published'].replace('Z', '+00:00'))
                time_diff = (time2 - time1).total_seconds() / 3600  # hours
                
                # If different countries within 2 hours, consider impossible
                if time_diff < 2:
                    return True
        
        return False
    
    def _check_after_hours(self, events: List[Dict]) -> bool:
        """Check if events occurred outside business hours"""
        for event in events:
            timestamp = datetime.fromisoformat(event['published'].replace('Z', '+00:00'))
            
            # Business hours: 9 AM - 5 PM, Monday - Friday
            if (timestamp.hour < 9 or timestamp.hour > 17 or 
                timestamp.weekday() >= 5):  # Saturday = 5, Sunday = 6
                return True
        
        return False
    
    def _check_geographic_anomaly(self, events: List[Dict]) -> bool:
        """Check for geographic anomalies (simplified implementation)"""
        # This would typically check against user's historical locations
        # For now, flag any non-US locations as anomalies
        for event in events:
            geo = event.get('client', {}).get('geographicalContext', {})
            country = geo.get('country')
            
            # Flag non-US/CA countries as anomalies (simplified)
            if country and country not in ['US', 'CA']:
                return True
        
        return False
    
    def _group_events(self, events: List[Dict], group_by: List[str]) -> Dict[str, List[Dict]]:
        """Group events by specified fields"""
        groups = defaultdict(list)
        
        for event in events:
            # Build group key from specified fields
            key_parts = []
            for field in group_by:
                value = self._extract_field_value(event, field)
                key_parts.append(str(value) if value is not None else "null")
            
            group_key = "|".join(key_parts)
            groups[group_key].append(event)
        
        return dict(groups)
    
    def _extract_field_value(self, event: Dict, field_path: str) -> Any:
        """Extract field value using dot notation"""
        try:
            value = event
            for part in field_path.split('.'):
                if isinstance(value, dict):
                    value = value.get(part)
                elif isinstance(value, list) and part.isdigit():
                    idx = int(part)
                    value = value[idx] if 0 <= idx < len(value) else None
                else:
                    return None
            return value
        except (KeyError, IndexError, TypeError):
            return None
    
    def _create_rule_match(self, rule: SecurityRule, events: List[Dict], group_key: str) -> RuleMatch:
        """Create rule match object"""
        
        # Extract affected entities
        affected_entities = defaultdict(set)
        
        for event in events:
            # Extract actor (user)
            actor_id = event.get('actor', {}).get('id')
            if actor_id:
                affected_entities['users'].add(actor_id)
            
            # Extract target entities
            for target in event.get('target', []):
                target_type = target.get('type', '').lower()
                target_id = target.get('id')
                if target_id:
                    if target_type == 'user':
                        affected_entities['users'].add(target_id)
                    elif target_type == 'application':
                        affected_entities['applications'].add(target_id)
                    elif target_type == 'group':
                        affected_entities['groups'].add(target_id)
            
            # Extract client IP
            client_ip = event.get('client', {}).get('ipAddress')
            if client_ip:
                affected_entities['ip_addresses'].add(client_ip)
        
        # Convert sets to lists
        affected_entities = {k: list(v) for k, v in affected_entities.items()}
        
        # Build indicators
        indicators = []
        
        if len(events) > 1:
            indicators.append(f"{len(events)} events in {rule.time_window}")
        
        event_types = set(event.get('eventType', 'unknown') for event in events)
        if len(event_types) == 1:
            indicators.append(f"Event type: {list(event_types)[0]}")
        else:
            indicators.append(f"Multiple event types: {', '.join(event_types)}")
        
        if 'users' in affected_entities:
            user_count = len(affected_entities['users'])
            if user_count == 1:
                indicators.append(f"Affected user: {affected_entities['users'][0]}")
            else:
                indicators.append(f"{user_count} affected users")
        
        return RuleMatch(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            severity=rule.severity,
            timestamp=datetime.utcnow(),
            events=events[:10],  # Limit events in match
            group_key=group_key,
            description=rule.description,
            indicators=indicators,
            affected_entities=affected_entities
        )
    
    def _is_rule_in_cooldown(self, rule: SecurityRule, event: Dict) -> bool:
        """Check if rule is in cooldown period"""
        if not rule.cooldown_period:
            return False
        
        rule_key = rule.rule_id
        if rule_key in self.rule_state:
            last_fired = self.rule_state[rule_key].get('last_fired')
            if last_fired and datetime.utcnow() - last_fired < rule.cooldown_period:
                return True
        
        return False
    
    def _is_rule_in_cooldown_by_key(self, key: str, cooldown_period: timedelta) -> bool:
        """Check if rule key is in cooldown"""
        if not cooldown_period:
            return False
        
        if key in self.rule_state:
            last_fired = self.rule_state[key].get('last_fired')
            if last_fired and datetime.utcnow() - last_fired < cooldown_period:
                return True
        
        return False
    
    def _update_rule_state(self, rule: SecurityRule, match: RuleMatch):
        """Update rule state after firing"""
        self.rule_state[rule.rule_id] = {
            'last_fired': datetime.utcnow(),
            'match': match
        }
    
    def _cleanup_state(self):
        """Clean up old rule state and event buffers"""
        cutoff_time = datetime.utcnow() - timedelta(hours=24)
        
        # Clean up rule state
        keys_to_remove = []
        for key, state in self.rule_state.items():
            if state.get('last_fired', datetime.min) < cutoff_time:
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self.rule_state[key]
        
        # Clean up event buffers
        for rule_id, events in self.event_buffer.items():
            rule = self.rules.get(rule_id)
            if rule and rule.time_window:
                buffer_cutoff = datetime.utcnow() - rule.time_window
                
                self.event_buffer[rule_id] = [
                    event for event in events
                    if datetime.fromisoformat(event['published'].replace('Z', '+00:00')) > buffer_cutoff
                ]
        
        self.last_cleanup = datetime.utcnow()
        logger.debug("Rule engine state cleaned up")
    
    def load_rules_from_file(self, file_path: str):
        """Load rules from JSON configuration file"""
        try:
            with open(file_path, 'r') as f:
                rules_data = json.load(f)
            
            for rule_data in rules_data.get('rules', []):
                rule = self._parse_rule_from_dict(rule_data)
                self.add_rule(rule)
            
            logger.info("Rules loaded from file", file=file_path, count=len(rules_data.get('rules', [])))
            
        except Exception as e:
            logger.error("Failed to load rules from file", file=file_path, error=str(e))
    
    def save_rules_to_file(self, file_path: str):
        """Save current rules to JSON file"""
        try:
            rules_data = {
                'version': '1.0',
                'rules': [self._rule_to_dict(rule) for rule in self.rules.values()]
            }
            
            with open(file_path, 'w') as f:
                json.dump(rules_data, f, indent=2, default=str)
            
            logger.info("Rules saved to file", file=file_path, count=len(self.rules))
            
        except Exception as e:
            logger.error("Failed to save rules to file", file=file_path, error=str(e))
    
    def _parse_rule_from_dict(self, rule_data: Dict) -> SecurityRule:
        """Parse rule from dictionary representation"""
        # Parse conditions
        conditions = []
        for cond_data in rule_data.get('conditions', []):
            condition = RuleCondition(
                field=cond_data['field'],
                condition_type=RuleConditionType(cond_data['condition_type']),
                value=cond_data['value'],
                case_sensitive=cond_data.get('case_sensitive', True)
            )
            conditions.append(condition)
        
        # Parse time window
        time_window = None
        if 'time_window_seconds' in rule_data:
            time_window = timedelta(seconds=rule_data['time_window_seconds'])
        
        # Parse cooldown period
        cooldown_period = None
        if 'cooldown_period_seconds' in rule_data:
            cooldown_period = timedelta(seconds=rule_data['cooldown_period_seconds'])
        
        return SecurityRule(
            rule_id=rule_data['rule_id'],
            name=rule_data['name'],
            description=rule_data['description'],
            severity=RuleSeverity(rule_data['severity']),
            enabled=rule_data.get('enabled', True),
            conditions=conditions,
            time_window=time_window,
            min_events=rule_data.get('min_events', 1),
            max_events=rule_data.get('max_events'),
            group_by=rule_data.get('group_by', []),
            cooldown_period=cooldown_period,
            tags=rule_data.get('tags', []),
            references=rule_data.get('references', []),
            auto_response=rule_data.get('auto_response', False),
            response_actions=rule_data.get('response_actions', [])
        )
    
    def _rule_to_dict(self, rule: SecurityRule) -> Dict:
        """Convert rule to dictionary representation"""
        rule_dict = asdict(rule)
        
        # Convert enums and timedeltas to serializable formats
        rule_dict['severity'] = rule.severity.value
        
        if rule.time_window:
            rule_dict['time_window_seconds'] = int(rule.time_window.total_seconds())
        
        if rule.cooldown_period:
            rule_dict['cooldown_period_seconds'] = int(rule.cooldown_period.total_seconds())
        
        # Convert conditions
        conditions_data = []
        for condition in rule.conditions:
            cond_dict = asdict(condition)
            cond_dict['condition_type'] = condition.condition_type.value
            conditions_data.append(cond_dict)
        
        rule_dict['conditions'] = conditions_data
        
        return rule_dict
    
    def get_rule_statistics(self) -> Dict:
        """Get rules engine statistics"""
        enabled_rules = sum(1 for rule in self.rules.values() if rule.enabled)
        
        severity_counts = Counter(rule.severity.value for rule in self.rules.values())
        
        return {
            'total_rules': len(self.rules),
            'enabled_rules': enabled_rules,
            'disabled_rules': len(self.rules) - enabled_rules,
            'severity_distribution': dict(severity_counts),
            'buffered_events': sum(len(events) for events in self.event_buffer.values()),
            'active_rule_states': len(self.rule_state)
        }
    
    def get_rules_by_tag(self, tag: str) -> List[SecurityRule]:
        """Get rules with specific tag"""
        return [rule for rule in self.rules.values() if tag in rule.tags]
    
    def get_rule(self, rule_id: str) -> Optional[SecurityRule]:
        """Get rule by ID"""
        return self.rules.get(rule_id)