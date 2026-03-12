"""
Cross-Platform Analytics Framework
Platform-agnostic adapter for Panther and CrowdStrike integration
"""

import json
import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PlatformType(Enum):
    """Supported SIEM platforms"""
    PANTHER = "panther"
    CROWDSTRIKE = "crowdstrike"
    

class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectionType(Enum):
    """Types of detections supported"""
    CREDENTIAL_STUFFING = "credential_stuffing"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ACCOUNT_TAKEOVER = "account_takeover" 
    LATERAL_MOVEMENT = "lateral_movement"
    INSIDER_THREAT = "insider_threat"
    BEHAVIOR_ANOMALY = "behavior_anomaly"


@dataclass
class NormalizedEvent:
    """Platform-agnostic event representation"""
    event_id: str
    timestamp: datetime
    event_type: str
    source_platform: PlatformType
    
    # User information
    user_id: str
    user_type: str
    user_groups: List[str]
    
    # Network information  
    source_ip: str
    user_agent: str
    device_info: Dict[str, Any]
    
    # Geographic information
    country: str
    city: str
    latitude: float
    longitude: float
    
    # Application context
    application: str
    resource: str
    action: str
    outcome: str
    
    # Risk context
    authentication_method: str
    session_id: str
    risk_score: float
    
    # Raw event data
    raw_event: Dict[str, Any]


@dataclass 
class DetectionResult:
    """Standardized detection result"""
    detection_id: str
    detection_type: DetectionType
    severity: AlertSeverity
    confidence_score: float
    
    # Event context
    triggering_events: List[NormalizedEvent]
    event_count: int
    time_window: timedelta
    
    # Detection details
    title: str
    description: str
    indicators: List[str]
    affected_users: List[str]
    affected_resources: List[str]
    
    # Risk assessment
    risk_score: float
    risk_factors: List[str]
    false_positive_likelihood: float
    
    # Response guidance
    recommended_actions: List[str]
    mitigation_steps: List[str]
    investigation_queries: List[str]
    
    # Metadata
    detection_timestamp: datetime
    platform_source: PlatformType
    rule_version: str


class PlatformAdapter(ABC):
    """Abstract base class for SIEM platform adapters"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.platform_type = None
        
    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to the platform"""
        pass
    
    @abstractmethod
    async def query_events(self, query: str, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Query events from the platform"""
        pass
    
    @abstractmethod
    async def send_alert(self, detection: DetectionResult) -> bool:
        """Send alert to the platform"""
        pass
    
    @abstractmethod
    def normalize_event(self, raw_event: Dict[str, Any]) -> NormalizedEvent:
        """Convert platform-specific event to normalized format"""
        pass
    
    @abstractmethod
    def create_detection_query(self, detection_type: DetectionType, parameters: Dict[str, Any]) -> str:
        """Generate platform-specific query for detection type"""
        pass


class PantherAdapter(PlatformAdapter):
    """Panther SIEM platform adapter"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.platform_type = PlatformType.PANTHER
        self.api_client = None
        
    async def connect(self) -> bool:
        """Establish connection to Panther"""
        try:
            # Initialize Panther API client
            from panther_analysis_tool.backend.client import PantherClient
            
            self.api_client = PantherClient(
                api_host=self.config.get("api_url"),
                api_token=self.config.get("api_token")
            )
            
            # Test connection
            await self.api_client.get_organization()
            logger.info("Successfully connected to Panther")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to Panther: {e}")
            return False
    
    async def query_events(self, query: str, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Query events from Panther Data Lake"""
        try:
            # Use Panther's data lake query API
            response = await self.api_client.query_datalake(
                sql_query=query,
                start_time=start_time.isoformat(),
                end_time=end_time.isoformat()
            )
            
            return response.get("results", [])
            
        except Exception as e:
            logger.error(f"Failed to query Panther events: {e}")
            return []
    
    async def send_alert(self, detection: DetectionResult) -> bool:
        """Send detection alert via Panther"""
        try:
            alert_data = {
                "rule_id": f"IAM.{detection.detection_type.value}",
                "title": detection.title,
                "severity": detection.severity.value,
                "description": detection.description,
                "runbook": self._get_runbook_url(detection.detection_type),
                "destinations": self._get_alert_destinations(detection.severity),
                "context": {
                    "detection_id": detection.detection_id,
                    "confidence_score": detection.confidence_score,
                    "risk_score": detection.risk_score,
                    "event_count": detection.event_count,
                    "affected_users": detection.affected_users,
                    "risk_factors": detection.risk_factors,
                    "recommended_actions": detection.recommended_actions
                }
            }
            
            # Send via Panther alert API
            response = await self.api_client.send_alert(alert_data)
            return response.get("success", False)
            
        except Exception as e:
            logger.error(f"Failed to send Panther alert: {e}")
            return False
    
    def normalize_event(self, raw_event: Dict[str, Any]) -> NormalizedEvent:
        """Convert Okta event from Panther to normalized format"""
        
        # Extract core event information
        event_id = raw_event.get("uuid", "")
        timestamp_str = raw_event.get("published", "")
        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00')) if timestamp_str else datetime.now()
        
        # Extract actor (user) information
        actor = raw_event.get("actor", {})
        user_id = actor.get("alternateId", "unknown")
        user_type = actor.get("type", "User")
        
        # Extract client information  
        client = raw_event.get("client", {})
        source_ip = client.get("ipaddress", "unknown")
        user_agent_info = client.get("useragent", {})
        user_agent = user_agent_info.get("rawuseragent", "unknown")
        
        # Extract geographic information
        geo_context = client.get("geographicalcontext", {})
        country = geo_context.get("country", "unknown")
        city = geo_context.get("city", "unknown")
        geolocation = geo_context.get("geolocation", {})
        latitude = float(geolocation.get("lat", 0))
        longitude = float(geolocation.get("lon", 0))
        
        # Extract application context
        target_info = raw_event.get("target", [])
        application = "unknown"
        resource = "unknown"
        if isinstance(target_info, list) and target_info:
            first_target = target_info[0]
            if first_target.get("type") == "AppInstance":
                application = first_target.get("displayName", "unknown")
                resource = first_target.get("id", "unknown")
        
        # Extract action and outcome
        event_type = raw_event.get("eventtype", "unknown")
        outcome_info = raw_event.get("outcome", {})
        outcome = outcome_info.get("result", "unknown")
        
        # Extract authentication context
        auth_context = raw_event.get("authenticationcontext", {})
        auth_method = auth_context.get("authenticationstep", "unknown")
        
        # Extract session information
        session_info = raw_event.get("session", {})
        session_id = session_info.get("id", "")
        
        # Device information
        device_info = {
            "type": user_agent_info.get("os", "unknown"),
            "browser": user_agent_info.get("browser", "unknown"),
            "raw_user_agent": user_agent
        }
        
        return NormalizedEvent(
            event_id=event_id,
            timestamp=timestamp,
            event_type=event_type,
            source_platform=PlatformType.PANTHER,
            user_id=user_id,
            user_type=user_type,
            user_groups=[],  # Would need additional lookup
            source_ip=source_ip,
            user_agent=user_agent,
            device_info=device_info,
            country=country,
            city=city,
            latitude=latitude,
            longitude=longitude,
            application=application,
            resource=resource,
            action=event_type,
            outcome=outcome,
            authentication_method=auth_method,
            session_id=session_id,
            risk_score=0.0,  # Would be calculated by UEBA engine
            raw_event=raw_event
        )
    
    def create_detection_query(self, detection_type: DetectionType, parameters: Dict[str, Any]) -> str:
        """Generate Panther SQL query for detection type"""
        
        base_table = "panther_logs.okta_systemlog"
        lookback_hours = parameters.get("lookback_hours", 24)
        
        if detection_type == DetectionType.CREDENTIAL_STUFFING:
            threshold = parameters.get("threshold", 5)
            time_window = parameters.get("time_window_minutes", 5)
            
            return f"""
            SELECT 
                client.ipaddress as source_ip,
                COUNT(*) as failed_attempts,
                array_agg(DISTINCT actor.alternateid) as targeted_users,
                MIN(published) as first_attempt,
                MAX(published) as last_attempt
            FROM {base_table}
            WHERE 
                eventtype = 'user.authentication.auth_via_mfa'
                AND outcome.result = 'FAILURE'
                AND published >= current_timestamp - interval '{lookback_hours}' hour
            GROUP BY client.ipaddress
            HAVING COUNT(*) >= {threshold}
                AND extract(epoch from (MAX(published) - MIN(published)))/60 <= {time_window}
                AND cardinality(array_agg(DISTINCT actor.alternateid)) >= 3
            ORDER BY failed_attempts DESC
            """
            
        elif detection_type == DetectionType.PRIVILEGE_ESCALATION:
            privileged_groups = parameters.get("privileged_groups", ["Super Admins", "Application Admins"])
            groups_filter = "', '".join(privileged_groups)
            
            return f"""
            SELECT 
                actor.alternateid as escalating_user,
                target[1].displayname as privilege_group,
                published as escalation_time,
                client.ipaddress as source_ip,
                client.geographicalcontext.country as country
            FROM {base_table}
            WHERE 
                eventtype = 'group.user_membership.add'
                AND target[1].displayname IN ('{groups_filter}')
                AND published >= current_timestamp - interval '{lookback_hours}' hour
            ORDER BY published DESC
            """
            
        # Add more detection types as needed
        return ""
    
    def _get_runbook_url(self, detection_type: DetectionType) -> str:
        """Get runbook URL for detection type"""
        runbook_base = "https://runbooks.company.com/iam"
        return f"{runbook_base}/{detection_type.value.replace('_', '-')}"
    
    def _get_alert_destinations(self, severity: AlertSeverity) -> List[str]:
        """Get alert destinations based on severity"""
        destinations = ["security-team"]
        
        if severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
            destinations.append("soc-alerts")
            
        if severity == AlertSeverity.CRITICAL:
            destinations.append("ciso-alerts")
            
        return destinations


class CrowdStrikeAdapter(PlatformAdapter):
    """CrowdStrike Falcon LogScale platform adapter"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.platform_type = PlatformType.CROWDSTRIKE
        self.falcon_client = None
        
    async def connect(self) -> bool:
        """Establish connection to CrowdStrike"""
        try:
            # Initialize CrowdStrike Falcon client
            from falconpy import LogScale
            
            self.falcon_client = LogScale(
                client_id=self.config.get("falcon_client_id"),
                client_secret=self.config.get("falcon_client_secret"),
                base_url=self._get_falcon_base_url()
            )
            
            # Test connection
            response = self.falcon_client.list_repos()
            if response["status_code"] == 200:
                logger.info("Successfully connected to CrowdStrike LogScale")
                return True
            else:
                logger.error(f"Failed to connect to CrowdStrike: {response}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to connect to CrowdStrike: {e}")
            return False
    
    async def query_events(self, query: str, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Query events from CrowdStrike LogScale"""
        try:
            # Execute LogScale query
            response = self.falcon_client.create_ingest_token(
                repository=self.config.get("repository", "okta_logs"),
                query=query,
                start=start_time.isoformat(),
                end=end_time.isoformat()
            )
            
            if response["status_code"] == 200:
                return response["body"].get("results", [])
            else:
                logger.error(f"LogScale query failed: {response}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to query CrowdStrike events: {e}")
            return []
    
    async def send_alert(self, detection: DetectionResult) -> bool:
        """Send detection alert via CrowdStrike"""
        try:
            # Create alert in LogScale or Falcon platform
            alert_data = {
                "timestamp": detection.detection_timestamp.isoformat(),
                "severity": detection.severity.value,
                "title": detection.title,
                "description": detection.description,
                "detection_type": detection.detection_type.value,
                "confidence_score": detection.confidence_score,
                "risk_score": detection.risk_score,
                "affected_users": detection.affected_users,
                "recommended_actions": detection.recommended_actions
            }
            
            # Send to LogScale repository for alerting
            response = self.falcon_client.send_data(
                repository=self.config.get("alerts_repository", "security_alerts"),
                data=alert_data
            )
            
            return response.get("status_code") == 200
            
        except Exception as e:
            logger.error(f"Failed to send CrowdStrike alert: {e}")
            return False
    
    def normalize_event(self, raw_event: Dict[str, Any]) -> NormalizedEvent:
        """Convert LogScale event to normalized format"""
        # Similar to PantherAdapter.normalize_event but handles LogScale format
        # Implementation would depend on how events are stored in LogScale
        
        return NormalizedEvent(
            event_id=raw_event.get("@id", ""),
            timestamp=datetime.fromisoformat(raw_event.get("@timestamp", "")),
            event_type=raw_event.get("eventtype", ""),
            source_platform=PlatformType.CROWDSTRIKE,
            user_id=raw_event.get("actor.alternateId", ""),
            user_type=raw_event.get("actor.type", ""),
            user_groups=[],
            source_ip=raw_event.get("client.ipAddress", ""),
            user_agent=raw_event.get("client.userAgent.rawUserAgent", ""),
            device_info={},
            country=raw_event.get("client.geographicalContext.country", ""),
            city=raw_event.get("client.geographicalContext.city", ""),
            latitude=float(raw_event.get("client.geographicalContext.geolocation.lat", 0)),
            longitude=float(raw_event.get("client.geographicalContext.geolocation.lon", 0)),
            application=raw_event.get("target.displayName", ""),
            resource="",
            action=raw_event.get("eventtype", ""),
            outcome=raw_event.get("outcome.result", ""),
            authentication_method=raw_event.get("authenticationContext.authenticationStep", ""),
            session_id=raw_event.get("session.id", ""),
            risk_score=0.0,
            raw_event=raw_event
        )
    
    def create_detection_query(self, detection_type: DetectionType, parameters: Dict[str, Any]) -> str:
        """Generate LogScale query for detection type"""
        
        if detection_type == DetectionType.CREDENTIAL_STUFFING:
            threshold = parameters.get("threshold", 5)
            time_window = parameters.get("time_window_minutes", 5)
            
            return f"""
            #repo=okta_logs
            | eventtype="user.authentication.sso" 
            | outcome.result="FAILURE"
            | groupBy([client.ipAddress], function=[
                count() as failed_attempts,
                values(actor.alternateId) as targeted_users,
                min(@timestamp) as first_attempt,
                max(@timestamp) as last_attempt
              ])
            | failed_attempts >= {threshold}
            | span := last_attempt - first_attempt
            | span <= {time_window}m
            | unique_users := length(targeted_users)
            | unique_users >= 3
            """
            
        elif detection_type == DetectionType.PRIVILEGE_ESCALATION:
            privileged_groups = parameters.get("privileged_groups", ["Super Admins", "Application Admins"])
            groups_filter = '", "'.join(privileged_groups)
            
            return f"""
            #repo=okta_logs
            | eventtype="group.user_membership.add"
            | target{{}}.displayName in ["{groups_filter}"]
            | groupBy([actor.alternateId], function=[
                count() as escalation_count,
                values(target{{}}.displayName) as privilege_groups,
                min(@timestamp) as first_escalation
              ])
            """
            
        return ""
    
    def _get_falcon_base_url(self) -> str:
        """Get Falcon base URL based on cloud region"""
        region = self.config.get("cloud_region", "us-1")
        region_urls = {
            "us-1": "https://api.crowdstrike.com",
            "us-2": "https://api.us-2.crowdstrike.com", 
            "eu-1": "https://api.eu-1.crowdstrike.com",
            "us-gov-1": "https://api.laggar.gcw.crowdstrike.com"
        }
        return region_urls.get(region, region_urls["us-1"])


class CrossPlatformAnalyticsEngine:
    """
    Main analytics engine that works across both platforms
    """
    
    def __init__(self, panther_config: Dict[str, Any] = None, crowdstrike_config: Dict[str, Any] = None):
        self.panther_adapter = PantherAdapter(panther_config) if panther_config else None
        self.crowdstrike_adapter = CrowdStrikeAdapter(crowdstrike_config) if crowdstrike_config else None
        
        self.active_platforms = []
        
    async def initialize(self):
        """Initialize platform connections"""
        if self.panther_adapter:
            if await self.panther_adapter.connect():
                self.active_platforms.append(PlatformType.PANTHER)
                
        if self.crowdstrike_adapter:
            if await self.crowdstrike_adapter.connect():
                self.active_platforms.append(PlatformType.CROWDSTRIKE)
        
        logger.info(f"Initialized with platforms: {[p.value for p in self.active_platforms]}")
    
    async def run_detection(self, detection_type: DetectionType, parameters: Dict[str, Any]) -> List[DetectionResult]:
        """Run detection across all active platforms"""
        results = []
        
        for platform in self.active_platforms:
            adapter = self._get_adapter(platform)
            
            try:
                # Create platform-specific query
                query = adapter.create_detection_query(detection_type, parameters)
                
                # Query events
                lookback_hours = parameters.get("lookback_hours", 24)
                end_time = datetime.now()
                start_time = end_time - timedelta(hours=lookback_hours)
                
                raw_events = await adapter.query_events(query, start_time, end_time)
                
                # Normalize events
                normalized_events = [adapter.normalize_event(event) for event in raw_events]
                
                # Run detection logic
                detection = await self._analyze_events(detection_type, normalized_events, platform)
                
                if detection:
                    results.append(detection)
                    
            except Exception as e:
                logger.error(f"Detection failed on {platform.value}: {e}")
        
        return results
    
    async def _analyze_events(self, detection_type: DetectionType, events: List[NormalizedEvent], platform: PlatformType) -> Optional[DetectionResult]:
        """Analyze events for detections"""
        if not events:
            return None
        
        # Basic detection logic - would be enhanced with UEBA engine
        if detection_type == DetectionType.CREDENTIAL_STUFFING:
            return self._detect_credential_stuffing(events, platform)
        elif detection_type == DetectionType.PRIVILEGE_ESCALATION:
            return self._detect_privilege_escalation(events, platform)
        
        return None
    
    def _detect_credential_stuffing(self, events: List[NormalizedEvent], platform: PlatformType) -> Optional[DetectionResult]:
        """Detect credential stuffing patterns"""
        if len(events) < 5:
            return None
        
        # Group by source IP
        ip_groups = {}
        for event in events:
            ip = event.source_ip
            if ip not in ip_groups:
                ip_groups[ip] = []
            ip_groups[ip].append(event)
        
        # Find IPs with high failure rates
        for ip, ip_events in ip_groups.items():
            if len(ip_events) >= 5:
                unique_users = len(set(event.user_id for event in ip_events))
                if unique_users >= 3:
                    return DetectionResult(
                        detection_id=f"cs_{platform.value}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                        detection_type=DetectionType.CREDENTIAL_STUFFING,
                        severity=AlertSeverity.MEDIUM,
                        confidence_score=0.8,
                        triggering_events=ip_events,
                        event_count=len(ip_events),
                        time_window=timedelta(minutes=5),
                        title=f"Credential stuffing detected from {ip}",
                        description=f"Multiple failed login attempts from {ip} targeting {unique_users} users",
                        indicators=[f"source_ip:{ip}", f"failed_attempts:{len(ip_events)}"],
                        affected_users=list(set(event.user_id for event in ip_events)),
                        affected_resources=[],
                        risk_score=0.7,
                        risk_factors=["multiple_targets", "high_volume"],
                        false_positive_likelihood=0.2,
                        recommended_actions=[f"Block source IP: {ip}", "Review targeted accounts"],
                        mitigation_steps=["Implement rate limiting", "Enable account lockouts"],
                        investigation_queries=[],
                        detection_timestamp=datetime.now(),
                        platform_source=platform,
                        rule_version="1.0"
                    )
        
        return None
    
    def _detect_privilege_escalation(self, events: List[NormalizedEvent], platform: PlatformType) -> Optional[DetectionResult]:
        """Detect privilege escalation patterns"""
        if not events:
            return None
        
        # Simple escalation detection
        escalation_events = [e for e in events if "admin" in e.action.lower() or "group" in e.action.lower()]
        
        if escalation_events:
            return DetectionResult(
                detection_id=f"pe_{platform.value}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                detection_type=DetectionType.PRIVILEGE_ESCALATION,
                severity=AlertSeverity.HIGH,
                confidence_score=0.9,
                triggering_events=escalation_events,
                event_count=len(escalation_events),
                time_window=timedelta(hours=1),
                title="Privilege escalation detected",
                description=f"Privilege changes detected for {len(set(e.user_id for e in escalation_events))} users",
                indicators=[],
                affected_users=list(set(e.user_id for e in escalation_events)),
                affected_resources=[],
                risk_score=0.8,
                risk_factors=["privilege_modification"],
                false_positive_likelihood=0.1,
                recommended_actions=["Verify privilege changes", "Review access requirements"],
                mitigation_steps=["Implement approval workflows"],
                investigation_queries=[],
                detection_timestamp=datetime.now(),
                platform_source=platform,
                rule_version="1.0"
            )
        
        return None
    
    def _get_adapter(self, platform: PlatformType) -> PlatformAdapter:
        """Get adapter for platform"""
        if platform == PlatformType.PANTHER:
            return self.panther_adapter
        elif platform == PlatformType.CROWDSTRIKE:
            return self.crowdstrike_adapter
        else:
            raise ValueError(f"Unsupported platform: {platform}")
    
    async def migrate_detection_rules(self, source_platform: PlatformType, target_platform: PlatformType):
        """Migrate detection rules between platforms"""
        logger.info(f"Migrating detection rules from {source_platform.value} to {target_platform.value}")
        
        # This would implement rule migration logic
        # For now, placeholder for the migration process
        migration_mappings = {
            "credential_stuffing": "iam_credential_stuffing_v1",
            "privilege_escalation": "iam_privilege_escalation_v1"
        }
        
        logger.info(f"Migration mappings prepared: {migration_mappings}")
        return migration_mappings