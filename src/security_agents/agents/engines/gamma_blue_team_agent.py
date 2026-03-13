#!/usr/bin/env python3
"""
Gamma Agent: Blue Team Defense Operations
Comprehensive SOC automation, incident response, and defensive security operations
"""

import asyncio
import logging
import json
import yaml
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import aiohttp
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AlertSeverity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class ContainmentAction(Enum):
    FIREWALL_BLOCK = "firewall_block"
    DNS_SINKHOLE = "dns_sinkhole"
    USER_ACCOUNT_DISABLE = "user_account_disable"
    NETWORK_ISOLATION = "network_isolation"
    SYSTEM_QUARANTINE = "system_quarantine"

@dataclass
class SecurityAlert:
    """Security alert data structure"""
    alert_id: str
    title: str
    description: str
    severity: AlertSeverity
    timestamp: datetime
    source_system: str
    iocs: List[str] = None
    affected_systems: List[str] = None
    raw_data: Dict[str, Any] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class IncidentCase:
    """Incident response case"""
    case_id: str
    alert_id: str
    title: str
    severity: AlertSeverity
    status: str
    created_at: datetime
    assigned_analyst: Optional[str] = None
    containment_actions: List[ContainmentAction] = None
    investigation_notes: List[str] = None
    
class GammaBlueTeamAgent:
    """Blue Team Defense Operations Agent"""
    
    def __init__(self, config_path: str = "config/gamma_config.yaml"):
        self.config = self.load_config(config_path)
        self.github_tools = {}
        self.active_cases = {}
        self.alert_history = []
        
        # Initialize GitHub tool integrations
        self.initialize_github_tools()
    
    def load_config(self, config_path: str) -> Dict[str, Any]:
        """Load agent configuration"""
        default_config = {
            "max_concurrent_operations": 5,
            "auto_containment": True,
            "default_containment_actions": [
                ContainmentAction.FIREWALL_BLOCK,
                ContainmentAction.DNS_SINKHOLE
            ],
            "integrations": {
                "thehive": {
                    "enabled": True,
                    "api_url": "http://localhost:9000/api",
                    "api_key": "your-api-key"
                },
                "sigma": {
                    "enabled": True,
                    "rules_path": "/opt/sigma/rules"
                },
                "wazuh": {
                    "enabled": True,
                    "api_url": "https://localhost:55000",
                    "username": "wazuh",
                    "password": "wazuh"
                },
                "velociraptor": {
                    "enabled": True,
                    "server_url": "https://localhost:8000"
                }
            },
            "soc_automation": {
                "auto_triage": True,
                "false_positive_threshold": 0.7,
                "escalation_threshold": AlertSeverity.HIGH.value
            }
        }
        
        try:
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)
        except FileNotFoundError:
            logger.warning(f"Config file {config_path} not found, using defaults")
        
        return default_config
    
    def initialize_github_tools(self):
        """Initialize GitHub security tool integrations"""
        from github_integrations.github_security_tools import GitHubToolIntegration, GitHubSecurityToolManager
        
        self.tool_manager = GitHubSecurityToolManager()
        
        # Initialize tool integrations
        for tool_name in ["thehive", "sigma", "wazuh", "velociraptor"]:
            if self.config["integrations"].get(tool_name, {}).get("enabled", False):
                self.github_tools[tool_name] = GitHubToolIntegration(tool_name, self.tool_manager)
    
    async def process_security_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Main entry point for processing security alerts"""
        try:
            # Parse alert data
            alert = self.parse_alert(alert_data)
            self.alert_history.append(alert)
            
            logger.info(f"Processing alert: {alert.alert_id} - {alert.title}")
            
            # Automated triage
            triage_result = await self.automated_triage(alert)
            
            # Create incident case if needed
            case = None
            if triage_result["requires_investigation"]:
                case = await self.create_incident_case(alert, triage_result)
            
            # Execute containment actions if needed
            containment_actions = []
            if triage_result["requires_containment"]:
                containment_actions = await self.execute_containment_actions(alert, triage_result)
            
            # Threat intelligence enrichment
            enrichment = await self.enrich_with_threat_intel(alert)
            
            # Generate response summary
            response = {
                "alert_id": alert.alert_id,
                "processing_status": "completed",
                "triage_result": triage_result,
                "case_created": case.case_id if case else None,
                "containment_actions": [action.value for action in containment_actions],
                "threat_intelligence": enrichment,
                "recommendations": await self.generate_recommendations(alert, triage_result)
            }
            
            logger.info(f"Alert processing completed: {alert.alert_id}")
            return response
            
        except Exception as e:
            logger.error(f"Error processing alert: {e}")
            return {
                "error": str(e),
                "processing_status": "failed"
            }
    
    def parse_alert(self, alert_data: Dict[str, Any]) -> SecurityAlert:
        """Parse incoming alert data"""
        return SecurityAlert(
            alert_id=alert_data.get("id", f"ALT-{datetime.now().strftime('%Y%m%d-%H%M%S')}"),
            title=alert_data.get("title", "Security Alert"),
            description=alert_data.get("description", ""),
            severity=AlertSeverity(alert_data.get("severity", AlertSeverity.MEDIUM.value)),
            timestamp=datetime.fromisoformat(alert_data.get("timestamp", datetime.now().isoformat())),
            source_system=alert_data.get("source", "unknown"),
            iocs=alert_data.get("iocs", []),
            affected_systems=alert_data.get("affected_systems", []),
            raw_data=alert_data
        )
    
    async def automated_triage(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Automated alert triage and classification"""
        logger.info(f"Performing automated triage for {alert.alert_id}")
        
        # Risk scoring
        risk_score = await self.calculate_risk_score(alert)
        
        # False positive detection
        false_positive_probability = await self.detect_false_positive(alert)
        
        # Determine required actions
        requires_investigation = (
            risk_score > 0.6 and 
            false_positive_probability < self.config["soc_automation"]["false_positive_threshold"]
        )
        
        requires_containment = (
            alert.severity.value >= self.config["soc_automation"]["escalation_threshold"] and
            requires_investigation
        )
        
        # Determine urgency
        urgency = self.calculate_urgency(alert, risk_score)
        
        return {
            "risk_score": risk_score,
            "false_positive_probability": false_positive_probability,
            "requires_investigation": requires_investigation,
            "requires_containment": requires_containment,
            "urgency": urgency,
            "analysis_timestamp": datetime.now().isoformat()
        }
    
    async def calculate_risk_score(self, alert: SecurityAlert) -> float:
        """Calculate risk score based on multiple factors"""
        score = 0.0
        
        # Severity-based scoring
        severity_weights = {
            AlertSeverity.LOW: 0.2,
            AlertSeverity.MEDIUM: 0.4,
            AlertSeverity.HIGH: 0.7,
            AlertSeverity.CRITICAL: 1.0
        }
        score += severity_weights.get(alert.severity, 0.5)
        
        # IOC-based scoring
        if alert.iocs:
            # Check against threat intelligence
            ioc_score = await self.score_iocs(alert.iocs)
            score += ioc_score * 0.3
        
        # Affected systems scoring
        if alert.affected_systems:
            critical_systems = await self.identify_critical_systems(alert.affected_systems)
            if critical_systems:
                score += 0.4
        
        # Historical pattern scoring
        historical_score = await self.analyze_historical_patterns(alert)
        score += historical_score * 0.2
        
        return min(score, 1.0)
    
    async def detect_false_positive(self, alert: SecurityAlert) -> float:
        """Detect probability of false positive"""
        # Analyze similar historical alerts
        similar_alerts = await self.find_similar_alerts(alert)
        
        if not similar_alerts:
            return 0.3  # Default uncertainty
        
        # Calculate false positive rate from historical data
        false_positive_count = sum(1 for a in similar_alerts if a.get("confirmed_false_positive", False))
        false_positive_rate = false_positive_count / len(similar_alerts)
        
        # Apply pattern recognition
        pattern_score = await self.analyze_alert_patterns(alert)
        
        # Combine scores
        final_score = (false_positive_rate * 0.7) + (pattern_score * 0.3)
        
        return min(final_score, 1.0)
    
    def calculate_urgency(self, alert: SecurityAlert, risk_score: float) -> str:
        """Calculate alert urgency level"""
        if risk_score >= 0.9 or alert.severity == AlertSeverity.CRITICAL:
            return "immediate"
        elif risk_score >= 0.7 or alert.severity == AlertSeverity.HIGH:
            return "high"
        elif risk_score >= 0.4:
            return "medium"
        else:
            return "low"
    
    async def create_incident_case(self, alert: SecurityAlert, triage_result: Dict[str, Any]) -> IncidentCase:
        """Create incident response case in TheHive"""
        logger.info(f"Creating incident case for alert {alert.alert_id}")
        
        case_id = f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # Create case in TheHive if integration is enabled
        if "thehive" in self.github_tools:
            try:
                async with self.github_tools["thehive"] as thehive:
                    case_data = {
                        "title": f"Security Incident: {alert.title}",
                        "description": f"""
Alert ID: {alert.alert_id}
Severity: {alert.severity.name}
Risk Score: {triage_result['risk_score']:.2f}
Urgency: {triage_result['urgency']}

Description:
{alert.description}

IOCs:
{', '.join(alert.iocs) if alert.iocs else 'None'}

Affected Systems:
{', '.join(alert.affected_systems) if alert.affected_systems else 'None'}
                        """.strip(),
                        "severity": alert.severity.value,
                        "tlp": 2,  # TLP:AMBER
                        "tags": [
                            f"alert_id:{alert.alert_id}",
                            f"source:{alert.source_system}",
                            f"urgency:{triage_result['urgency']}"
                        ]
                    }
                    
                    thehive_result = await thehive.execute_capability("case_management", case_data)
                    if thehive_result.get("status") == "case_created":
                        case_id = thehive_result["case"].get("_id", case_id)
                        
            except Exception as e:
                logger.error(f"Failed to create TheHive case: {e}")
        
        # Create local case record
        case = IncidentCase(
            case_id=case_id,
            alert_id=alert.alert_id,
            title=f"Security Incident: {alert.title}",
            severity=alert.severity,
            status="open",
            created_at=datetime.now()
        )
        
        self.active_cases[case_id] = case
        
        logger.info(f"Incident case created: {case_id}")
        return case
    
    async def execute_containment_actions(self, alert: SecurityAlert, triage_result: Dict[str, Any]) -> List[ContainmentAction]:
        """Execute automated containment actions"""
        logger.info(f"Executing containment actions for alert {alert.alert_id}")
        
        executed_actions = []
        
        # Determine appropriate containment actions
        containment_actions = self.determine_containment_actions(alert, triage_result)
        
        for action in containment_actions:
            try:
                success = await self.execute_single_containment_action(action, alert)
                if success:
                    executed_actions.append(action)
                    logger.info(f"Containment action executed: {action.value}")
                else:
                    logger.warning(f"Containment action failed: {action.value}")
                    
            except Exception as e:
                logger.error(f"Error executing containment action {action.value}: {e}")
        
        return executed_actions
    
    def determine_containment_actions(self, alert: SecurityAlert, triage_result: Dict[str, Any]) -> List[ContainmentAction]:
        """Determine appropriate containment actions based on alert characteristics"""
        actions = []
        
        # IOC-based containment
        if alert.iocs:
            for ioc in alert.iocs:
                if self.is_ip_address(ioc):
                    actions.append(ContainmentAction.FIREWALL_BLOCK)
                elif self.is_domain(ioc):
                    actions.append(ContainmentAction.DNS_SINKHOLE)
        
        # System-based containment
        if alert.affected_systems:
            # High-risk systems get network isolation
            if triage_result["risk_score"] > 0.8:
                actions.append(ContainmentAction.NETWORK_ISOLATION)
            
            # Critical alerts may require quarantine
            if alert.severity == AlertSeverity.CRITICAL:
                actions.append(ContainmentAction.SYSTEM_QUARANTINE)
        
        # User-based containment
        if self.involves_user_account(alert):
            actions.append(ContainmentAction.USER_ACCOUNT_DISABLE)
        
        return list(set(actions))  # Remove duplicates
    
    async def execute_single_containment_action(self, action: ContainmentAction, alert: SecurityAlert) -> bool:
        """Execute a single containment action"""
        if action == ContainmentAction.FIREWALL_BLOCK:
            return await self.block_ips_in_firewall(alert.iocs)
        elif action == ContainmentAction.DNS_SINKHOLE:
            return await self.sinkhole_domains(alert.iocs)
        elif action == ContainmentAction.USER_ACCOUNT_DISABLE:
            return await self.disable_user_accounts(alert)
        elif action == ContainmentAction.NETWORK_ISOLATION:
            return await self.isolate_systems(alert.affected_systems)
        elif action == ContainmentAction.SYSTEM_QUARANTINE:
            return await self.quarantine_systems(alert.affected_systems)
        else:
            logger.warning(f"Unknown containment action: {action}")
            return False
    
    async def enrich_with_threat_intel(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Enrich alert with threat intelligence"""
        enrichment = {
            "ioc_analysis": {},
            "threat_campaigns": [],
            "attribution": {},
            "similar_incidents": []
        }
        
        # Analyze IOCs against threat intelligence
        if alert.iocs:
            for ioc in alert.iocs:
                ioc_intel = await self.analyze_ioc(ioc)
                enrichment["ioc_analysis"][ioc] = ioc_intel
        
        # Check for known threat campaigns
        campaigns = await self.match_threat_campaigns(alert)
        enrichment["threat_campaigns"] = campaigns
        
        # Attempt attribution
        attribution = await self.perform_attribution_analysis(alert)
        enrichment["attribution"] = attribution
        
        return enrichment
    
    async def generate_recommendations(self, alert: SecurityAlert, triage_result: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Based on risk score
        if triage_result["risk_score"] > 0.8:
            recommendations.append("Immediate analyst review required")
            recommendations.append("Consider escalation to security management")
        
        # Based on urgency
        if triage_result["urgency"] == "immediate":
            recommendations.append("Activate incident response team")
            recommendations.append("Notify senior security staff")
        
        # IOC-specific recommendations
        if alert.iocs:
            recommendations.append("Perform IOC hunting across all systems")
            recommendations.append("Update threat intelligence feeds")
        
        # System-specific recommendations
        if alert.affected_systems:
            recommendations.append("Perform forensic imaging of affected systems")
            recommendations.append("Review system logs for additional indicators")
        
        # General recommendations
        recommendations.extend([
            "Document all investigation activities",
            "Preserve evidence according to policy",
            "Update detection rules based on findings"
        ])
        
        return recommendations
    
    # Helper methods
    async def score_iocs(self, iocs: List[str]) -> float:
        """Score IOCs based on threat intelligence"""
        # Placeholder implementation
        return 0.5
    
    async def identify_critical_systems(self, systems: List[str]) -> List[str]:
        """Identify critical systems from the list"""
        # Placeholder implementation
        critical_keywords = ["dc", "domain", "server", "prod"]
        return [s for s in systems if any(keyword in s.lower() for keyword in critical_keywords)]
    
    async def analyze_historical_patterns(self, alert: SecurityAlert) -> float:
        """Analyze historical patterns"""
        # Placeholder implementation
        return 0.3
    
    async def find_similar_alerts(self, alert: SecurityAlert) -> List[Dict[str, Any]]:
        """Find similar historical alerts"""
        # Placeholder implementation
        return []
    
    async def analyze_alert_patterns(self, alert: SecurityAlert) -> float:
        """Analyze alert patterns for false positive detection"""
        # Placeholder implementation
        return 0.2
    
    def is_ip_address(self, value: str) -> bool:
        """Check if value is an IP address"""
        import ipaddress
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    
    def is_domain(self, value: str) -> bool:
        """Check if value is a domain name"""
        import re
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(domain_pattern, value))
    
    def involves_user_account(self, alert: SecurityAlert) -> bool:
        """Check if alert involves user account activity"""
        user_indicators = ["login", "authentication", "user", "account", "credential"]
        alert_text = f"{alert.title} {alert.description}".lower()
        return any(indicator in alert_text for indicator in user_indicators)
    
    # Containment action implementations
    async def block_ips_in_firewall(self, iocs: List[str]) -> bool:
        """Block IP addresses in firewall"""
        # Placeholder implementation
        logger.info(f"Blocking IPs in firewall: {iocs}")
        return True
    
    async def sinkhole_domains(self, iocs: List[str]) -> bool:
        """Sinkhole malicious domains"""
        # Placeholder implementation
        logger.info(f"Sinkholing domains: {iocs}")
        return True
    
    async def disable_user_accounts(self, alert: SecurityAlert) -> bool:
        """Disable compromised user accounts"""
        # Placeholder implementation
        logger.info("Disabling user accounts")
        return True
    
    async def isolate_systems(self, systems: List[str]) -> bool:
        """Isolate systems from network"""
        # Placeholder implementation
        logger.info(f"Isolating systems: {systems}")
        return True
    
    async def quarantine_systems(self, systems: List[str]) -> bool:
        """Quarantine infected systems"""
        # Placeholder implementation
        logger.info(f"Quarantining systems: {systems}")
        return True
    
    # Threat intelligence methods
    async def analyze_ioc(self, ioc: str) -> Dict[str, Any]:
        """Analyze IOC against threat intelligence"""
        # Placeholder implementation
        return {"reputation": "unknown", "first_seen": None, "campaigns": []}
    
    async def match_threat_campaigns(self, alert: SecurityAlert) -> List[str]:
        """Match alert to known threat campaigns"""
        # Placeholder implementation
        return []
    
    async def perform_attribution_analysis(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Perform threat actor attribution analysis"""
        # Placeholder implementation
        return {"confidence": "low", "suspected_actors": []}

# CLI Interface
async def main():
    """Main function for Gamma Blue Team Agent"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Gamma Blue Team Defense Agent")
    parser.add_argument("action", choices=["process_alert", "list_cases", "status"])
    parser.add_argument("--alert-file", help="JSON file containing alert data")
    parser.add_argument("--alert-id", help="Specific alert ID to process")
    
    args = parser.parse_args()
    
    agent = GammaBlueTeamAgent()
    
    if args.action == "process_alert":
        if args.alert_file:
            with open(args.alert_file, 'r') as f:
                alert_data = json.load(f)
            
            result = await agent.process_security_alert(alert_data)
            print(json.dumps(result, indent=2, default=str))
        else:
            # Example alert for testing
            test_alert = {
                "id": "ALT-TEST-001",
                "title": "Suspicious Network Activity",
                "description": "Multiple failed login attempts from external IP",
                "severity": 3,
                "timestamp": datetime.now().isoformat(),
                "source": "network_monitor",
                "iocs": ["192.168.1.100", "malicious.example.com"],
                "affected_systems": ["web-server-01", "user-workstation-05"]
            }
            
            result = await agent.process_security_alert(test_alert)
            print(json.dumps(result, indent=2, default=str))
    
    elif args.action == "list_cases":
        print("Active Cases:")
        for case_id, case in agent.active_cases.items():
            print(f"  {case_id}: {case.title} [{case.status}]")
    
    elif args.action == "status":
        print(f"Gamma Blue Team Agent Status:")
        print(f"  Active Cases: {len(agent.active_cases)}")
        print(f"  Alerts Processed: {len(agent.alert_history)}")
        print(f"  GitHub Tools: {list(agent.github_tools.keys())}")

if __name__ == "__main__":
    asyncio.run(main())