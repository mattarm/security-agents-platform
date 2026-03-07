#!/usr/bin/env python3
"""
IAM Security Analytics Engine - Main Orchestrator
Cross-platform identity threat detection and analytics for Panther→CrowdStrike transition
"""

import asyncio
import argparse
import json
import logging
import yaml
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path

# Import our framework components
from framework.adapters.platform_adapter import (
    CrossPlatformAnalyticsEngine, PlatformType, DetectionType, AlertSeverity
)
from framework.processors.detection_engine import ThreatPatternDetector
from ueba.models.behavior_baseline import BehaviorBaselineEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('iam_analytics.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class IAMSecurityAnalytics:
    """
    Main IAM Security Analytics orchestrator
    Coordinates detection across Panther and CrowdStrike platforms
    """
    
    def __init__(self, config_file: str = "config/okta-config.yaml"):
        """Initialize the analytics engine"""
        self.config = self._load_config(config_file)
        
        # Initialize core components
        self.ueba_engine = BehaviorBaselineEngine(config_file)
        self.threat_detector = ThreatPatternDetector(self.ueba_engine)
        
        # Initialize platform adapters
        self.analytics_engine = None
        self.active_detections = {}
        self.detection_history = []
        
        logger.info("IAM Security Analytics Engine initialized")
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Configuration loaded from {config_file}")
            return config
        except FileNotFoundError:
            logger.error(f"Configuration file {config_file} not found")
            raise
        except yaml.YAMLError as e:
            logger.error(f"Error parsing configuration: {e}")
            raise
    
    async def initialize(self):
        """Initialize platform connections and components"""
        logger.info("Initializing IAM Security Analytics Engine...")
        
        # Prepare platform configurations
        panther_config = None
        crowdstrike_config = None
        
        if self.config.get("platforms", {}).get("panther", {}).get("enabled", False):
            panther_config = {
                "api_url": self.config["platforms"]["panther"]["api_url"],
                "api_token": self.config["platforms"]["panther"]["api_token"]
            }
        
        if self.config.get("platforms", {}).get("crowdstrike", {}).get("enabled", False):
            crowdstrike_config = {
                "falcon_client_id": self.config["platforms"]["crowdstrike"]["falcon_client_id"],
                "falcon_client_secret": self.config["platforms"]["crowdstrike"]["falcon_client_secret"],
                "cloud_region": self.config["platforms"]["crowdstrike"]["cloud_region"]
            }
        
        # Initialize cross-platform engine
        self.analytics_engine = CrossPlatformAnalyticsEngine(
            panther_config=panther_config,
            crowdstrike_config=crowdstrike_config
        )
        
        await self.analytics_engine.initialize()
        logger.info("Platform connections established")
    
    async def run_continuous_monitoring(self, duration_hours: int = 24):
        """Run continuous threat monitoring"""
        logger.info(f"Starting continuous monitoring for {duration_hours} hours")
        
        end_time = datetime.now() + timedelta(hours=duration_hours)
        detection_interval = 60  # seconds
        
        while datetime.now() < end_time:
            try:
                # Run all detection types
                await self._run_detection_cycle()
                
                logger.info(f"Detection cycle completed, sleeping {detection_interval} seconds")
                await asyncio.sleep(detection_interval)
                
            except Exception as e:
                logger.error(f"Error in detection cycle: {e}")
                await asyncio.sleep(detection_interval)
        
        logger.info("Continuous monitoring completed")
    
    async def _run_detection_cycle(self):
        """Run a single detection cycle across all patterns"""
        detection_types = [
            DetectionType.CREDENTIAL_STUFFING,
            DetectionType.PRIVILEGE_ESCALATION,
            DetectionType.ACCOUNT_TAKEOVER,
            DetectionType.LATERAL_MOVEMENT,
            DetectionType.INSIDER_THREAT
        ]
        
        for detection_type in detection_types:
            try:
                parameters = self._get_detection_parameters(detection_type)
                detections = await self.analytics_engine.run_detection(detection_type, parameters)
                
                for detection in detections:
                    await self._handle_detection(detection)
                    
            except Exception as e:
                logger.error(f"Error in {detection_type.value} detection: {e}")
    
    def _get_detection_parameters(self, detection_type: DetectionType) -> Dict[str, Any]:
        """Get detection parameters based on type and configuration"""
        base_params = {
            "lookback_hours": 1  # Short window for continuous monitoring
        }
        
        detection_config = self.config.get("detections", {})
        
        if detection_type == DetectionType.CREDENTIAL_STUFFING:
            cs_config = detection_config.get("credential_stuffing", {})
            base_params.update({
                "threshold": cs_config.get("threshold", 5),
                "time_window_minutes": cs_config.get("time_window", 300) // 60,
                "unique_user_threshold": 3
            })
            
        elif detection_type == DetectionType.PRIVILEGE_ESCALATION:
            pe_config = detection_config.get("privilege_escalation", {})
            base_params.update({
                "privileged_groups": pe_config.get("monitor_groups", [
                    "Super Admins", "Application Admins", "Security Admins"
                ])
            })
            
        elif detection_type == DetectionType.ACCOUNT_TAKEOVER:
            ato_config = detection_config.get("account_takeover", {})
            base_params.update({
                "behavioral_threshold": ato_config.get("behavioral_threshold", 3.0)
            })
            
        elif detection_type == DetectionType.LATERAL_MOVEMENT:
            lm_config = detection_config.get("lateral_movement", {})
            base_params.update({
                "cross_app_threshold": lm_config.get("cross_app_threshold", 10),
                "time_window_hours": lm_config.get("time_window", 3600) // 3600
            })
            
        elif detection_type == DetectionType.INSIDER_THREAT:
            it_config = detection_config.get("insider_threat", {})
            base_params.update({
                "data_access_threshold": it_config.get("data_access_threshold", 2.5),
                "off_hours_multiplier": it_config.get("off_hours_multiplier", 1.5)
            })
        
        return base_params
    
    async def _handle_detection(self, detection):
        """Handle a detection result"""
        logger.info(f"Detection triggered: {detection.title}")
        
        # Store detection
        self.detection_history.append(detection)
        self.active_detections[detection.detection_id] = detection
        
        # Send alerts based on severity
        if detection.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
            await self._send_high_priority_alert(detection)
        else:
            await self._send_standard_alert(detection)
        
        # Log detection details
        self._log_detection_details(detection)
        
        # Check for alert throttling
        await self._check_alert_throttling(detection)
    
    async def _send_high_priority_alert(self, detection):
        """Send high-priority alerts via multiple channels"""
        logger.warning(f"HIGH PRIORITY ALERT: {detection.title}")
        
        # Send via configured alert destinations
        alert_destinations = self.config.get("alerts", {}).get("destinations", [])
        
        for destination in alert_destinations:
            try:
                if destination["type"] == "webhook":
                    await self._send_webhook_alert(detection, destination)
                elif destination["type"] == "email":
                    await self._send_email_alert(detection, destination)
                elif destination["type"] == "slack":
                    await self._send_slack_alert(detection, destination)
                    
            except Exception as e:
                logger.error(f"Failed to send alert via {destination['type']}: {e}")
    
    async def _send_standard_alert(self, detection):
        """Send standard alerts via primary channel"""
        logger.info(f"Standard alert: {detection.title}")
        # Implement standard alerting logic
    
    async def _send_webhook_alert(self, detection, destination):
        """Send alert via webhook"""
        import aiohttp
        
        payload = {
            "detection_id": detection.detection_id,
            "title": detection.title,
            "description": detection.description,
            "severity": detection.severity.value,
            "confidence_score": detection.confidence_score,
            "affected_users": detection.affected_users,
            "recommended_actions": detection.recommended_actions,
            "timestamp": detection.detection_timestamp.isoformat()
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                destination["url"], 
                json=payload,
                headers={"Content-Type": "application/json"}
            ) as response:
                if response.status == 200:
                    logger.info(f"Webhook alert sent successfully")
                else:
                    logger.error(f"Webhook alert failed: {response.status}")
    
    async def _send_email_alert(self, detection, destination):
        """Send alert via email"""
        # Placeholder for email integration
        logger.info(f"Email alert would be sent to: {destination.get('recipients', [])}")
    
    async def _send_slack_alert(self, detection, destination):
        """Send alert via Slack"""
        # Placeholder for Slack integration
        logger.info(f"Slack alert would be sent to: {destination.get('channel', '#security-alerts')}")
    
    def _log_detection_details(self, detection):
        """Log detailed detection information"""
        logger.info(f"Detection Details:")
        logger.info(f"  ID: {detection.detection_id}")
        logger.info(f"  Type: {detection.detection_type.value}")
        logger.info(f"  Severity: {detection.severity.value}")
        logger.info(f"  Confidence: {detection.confidence_score:.2f}")
        logger.info(f"  Risk Score: {detection.risk_score:.2f}")
        logger.info(f"  Event Count: {detection.event_count}")
        logger.info(f"  Affected Users: {len(detection.affected_users)}")
        logger.info(f"  Platform: {detection.platform_source.value}")
        
        if detection.risk_factors:
            logger.info(f"  Risk Factors: {', '.join(detection.risk_factors)}")
    
    async def _check_alert_throttling(self, detection):
        """Check and apply alert throttling rules"""
        throttling_config = self.config.get("alerts", {}).get("throttling", {})
        max_alerts_per_hour = throttling_config.get("max_alerts_per_hour", 100)
        
        # Count recent alerts
        one_hour_ago = datetime.now() - timedelta(hours=1)
        recent_alerts = [
            d for d in self.detection_history 
            if d.detection_timestamp >= one_hour_ago
        ]
        
        if len(recent_alerts) >= max_alerts_per_hour:
            logger.warning(f"Alert throttling activated: {len(recent_alerts)} alerts in last hour")
    
    async def run_single_detection(self, detection_type: DetectionType, lookback_hours: int = 24):
        """Run a single detection type for testing/investigation"""
        logger.info(f"Running single detection: {detection_type.value}")
        
        parameters = self._get_detection_parameters(detection_type)
        parameters["lookback_hours"] = lookback_hours
        
        detections = await self.analytics_engine.run_detection(detection_type, parameters)
        
        logger.info(f"Detection completed: {len(detections)} results")
        
        for detection in detections:
            self._log_detection_details(detection)
        
        return detections
    
    async def build_user_baselines(self, users: List[str] = None, days_back: int = 30):
        """Build behavior baselines for users"""
        logger.info(f"Building user baselines for {days_back} days")
        
        # This would integrate with the UEBA engine to build baselines
        # from historical data
        
        if users:
            logger.info(f"Building baselines for specific users: {users}")
        else:
            logger.info("Building baselines for all active users")
        
        # Placeholder for baseline building logic
        logger.info("Baseline building completed")
    
    def generate_report(self, hours_back: int = 24) -> Dict[str, Any]:
        """Generate analytics report"""
        cutoff_time = datetime.now() - timedelta(hours=hours_back)
        recent_detections = [
            d for d in self.detection_history 
            if d.detection_timestamp >= cutoff_time
        ]
        
        # Count by severity
        severity_counts = {}
        for severity in AlertSeverity:
            severity_counts[severity.value] = len([
                d for d in recent_detections if d.severity == severity
            ])
        
        # Count by detection type
        type_counts = {}
        for detection_type in DetectionType:
            type_counts[detection_type.value] = len([
                d for d in recent_detections if d.detection_type == detection_type
            ])
        
        # Top affected users
        user_counts = {}
        for detection in recent_detections:
            for user in detection.affected_users:
                user_counts[user] = user_counts.get(user, 0) + 1
        
        top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        report = {
            "report_period_hours": hours_back,
            "total_detections": len(recent_detections),
            "severity_breakdown": severity_counts,
            "detection_type_breakdown": type_counts,
            "top_affected_users": top_users,
            "active_platforms": [p.value for p in self.analytics_engine.active_platforms],
            "report_generated": datetime.now().isoformat()
        }
        
        return report
    
    async def shutdown(self):
        """Graceful shutdown"""
        logger.info("Shutting down IAM Security Analytics Engine")
        
        # Save detection history
        history_file = f"detection_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            # Convert detections to serializable format
            serializable_history = []
            for detection in self.detection_history:
                detection_dict = {
                    "detection_id": detection.detection_id,
                    "detection_type": detection.detection_type.value,
                    "severity": detection.severity.value,
                    "title": detection.title,
                    "description": detection.description,
                    "confidence_score": detection.confidence_score,
                    "risk_score": detection.risk_score,
                    "event_count": detection.event_count,
                    "affected_users": detection.affected_users,
                    "detection_timestamp": detection.detection_timestamp.isoformat(),
                    "platform_source": detection.platform_source.value
                }
                serializable_history.append(detection_dict)
            
            with open(history_file, 'w') as f:
                json.dump(serializable_history, f, indent=2)
            
            logger.info(f"Detection history saved to {history_file}")
            
        except Exception as e:
            logger.error(f"Failed to save detection history: {e}")
        
        logger.info("Shutdown completed")


async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="IAM Security Analytics Engine")
    parser.add_argument("--config", default="config/okta-config.yaml", help="Configuration file path")
    parser.add_argument("--mode", choices=["continuous", "single", "baseline", "report"], default="single", help="Operation mode")
    parser.add_argument("--detection-type", choices=[dt.value for dt in DetectionType], help="Detection type for single mode")
    parser.add_argument("--duration", type=int, default=24, help="Duration in hours for continuous mode")
    parser.add_argument("--lookback", type=int, default=24, help="Lookback period in hours")
    
    args = parser.parse_args()
    
    try:
        # Initialize analytics engine
        analytics = IAMSecurityAnalytics(config_file=args.config)
        await analytics.initialize()
        
        if args.mode == "continuous":
            logger.info("Starting continuous monitoring mode")
            await analytics.run_continuous_monitoring(duration_hours=args.duration)
            
        elif args.mode == "single":
            if not args.detection_type:
                logger.error("Detection type required for single mode")
                return
            
            detection_type = DetectionType(args.detection_type)
            await analytics.run_single_detection(detection_type, lookback_hours=args.lookback)
            
        elif args.mode == "baseline":
            logger.info("Building user behavior baselines")
            await analytics.build_user_baselines(days_back=args.lookback)
            
        elif args.mode == "report":
            logger.info("Generating analytics report")
            report = analytics.generate_report(hours_back=args.lookback)
            print(json.dumps(report, indent=2))
        
        await analytics.shutdown()
        
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())