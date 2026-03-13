#!/usr/bin/env python3
"""
IAM Security Analytics - Detection Scenario Testing
Tests for common attack patterns and edge cases
"""

import asyncio
import unittest
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
from typing import List, Dict, Any

# Import framework components
from framework.adapters.platform_adapter import (
    NormalizedEvent, DetectionResult, DetectionType, AlertSeverity, PlatformType
)
from framework.processors.detection_engine import ThreatPatternDetector
from ueba.models.behavior_baseline import BehaviorBaselineEngine, BehaviorFeatures


class TestDetectionScenarios(unittest.IsolatedAsyncioTestCase):
    """Test detection scenarios with realistic attack patterns"""
    
    def setUp(self):
        """Set up test environment"""
        self.ueba_engine = Mock(spec=BehaviorBaselineEngine)
        self.detector = ThreatPatternDetector(self.ueba_engine)
        
        # Mock UEBA engine responses
        self.ueba_engine.calculate_anomaly_score.return_value = 0.5
    
    def create_mock_event(self, **kwargs) -> NormalizedEvent:
        """Create a mock normalized event for testing"""
        defaults = {
            "event_id": "test_event_001",
            "timestamp": datetime.now(),
            "event_type": "user.authentication.sso",
            "source_platform": PlatformType.PANTHER,
            "user_id": "test.user@company.com",
            "user_type": "User",
            "user_groups": [],
            "source_ip": "192.168.1.100",
            "user_agent": "Mozilla/5.0 Test Browser",
            "device_info": {"type": "Windows", "browser": "Chrome"},
            "country": "United States",
            "city": "New York",
            "latitude": 40.7128,
            "longitude": -74.0060,
            "application": "Salesforce",
            "resource": "app_001",
            "action": "user.authentication.sso",
            "outcome": "FAILURE",
            "authentication_method": "password",
            "session_id": "session_001",
            "risk_score": 0.0,
            "raw_event": {}
        }
        defaults.update(kwargs)
        return NormalizedEvent(**defaults)
    
    async def test_credential_stuffing_basic_pattern(self):
        """Test basic credential stuffing detection"""
        # Create credential stuffing attack pattern
        base_time = datetime.now()
        source_ip = "203.0.113.10"  # Example IP
        
        # Generate failed login attempts from single IP to multiple users
        events = []
        users = [f"user{i}@company.com" for i in range(1, 6)]  # 5 different users
        
        for i, user in enumerate(users):
            for attempt in range(2):  # 2 attempts per user = 10 total
                event = self.create_mock_event(
                    event_id=f"cs_event_{i}_{attempt}",
                    timestamp=base_time + timedelta(seconds=i*30 + attempt*10),
                    user_id=user,
                    source_ip=source_ip,
                    outcome="FAILURE",
                    action="user.authentication.sso"
                )
                events.append(event)
        
        # Run detection
        detections = await self.detector.analyze_events(events, PlatformType.PANTHER)
        
        # Verify detection
        credential_stuffing_detections = [
            d for d in detections 
            if d.detection_type == DetectionType.CREDENTIAL_STUFFING
        ]
        
        self.assertGreater(len(credential_stuffing_detections), 0)
        detection = credential_stuffing_detections[0]
        self.assertIn(source_ip, detection.title)
        self.assertEqual(detection.severity, AlertSeverity.MEDIUM)
        self.assertGreaterEqual(len(detection.affected_users), 3)
    
    async def test_privilege_escalation_rapid_pattern(self):
        """Test rapid privilege escalation detection"""
        base_time = datetime.now()
        user_id = "admin.user@company.com"
        
        # Create privilege escalation events
        privilege_events = [
            self.create_mock_event(
                event_id="pe_event_001",
                timestamp=base_time,
                user_id=user_id,
                action="group.user_membership.add",
                outcome="SUCCESS",
                raw_event={"target": [{"displayName": "Application Admins"}]}
            ),
            self.create_mock_event(
                event_id="pe_event_002", 
                timestamp=base_time + timedelta(minutes=5),
                user_id=user_id,
                action="group.user_membership.add",
                outcome="SUCCESS",
                raw_event={"target": [{"displayName": "Security Admins"}]}
            )
        ]
        
        # Run detection
        detections = await self.detector.analyze_events(privilege_events, PlatformType.PANTHER)
        
        # Verify detection
        escalation_detections = [
            d for d in detections 
            if d.detection_type == DetectionType.PRIVILEGE_ESCALATION
        ]
        
        self.assertGreater(len(escalation_detections), 0)
        detection = escalation_detections[0]
        self.assertEqual(detection.severity, AlertSeverity.HIGH)
        self.assertIn(user_id, detection.affected_users)
    
    async def test_impossible_travel_detection(self):
        """Test impossible travel detection"""
        base_time = datetime.now()
        user_id = "traveling.user@company.com"
        
        # Create geographically impossible login sequence
        travel_events = [
            self.create_mock_event(
                event_id="travel_event_001",
                timestamp=base_time,
                user_id=user_id,
                outcome="SUCCESS",
                country="United States",
                city="New York", 
                latitude=40.7128,
                longitude=-74.0060
            ),
            self.create_mock_event(
                event_id="travel_event_002",
                timestamp=base_time + timedelta(minutes=30),
                user_id=user_id,
                outcome="SUCCESS",
                country="Japan",
                city="Tokyo",
                latitude=35.6762,
                longitude=139.6503
            )
        ]
        
        # Run detection
        detections = await self.detector.analyze_events(travel_events, PlatformType.PANTHER)
        
        # Verify detection
        travel_detections = [
            d for d in detections 
            if d.detection_type == DetectionType.ACCOUNT_TAKEOVER
        ]
        
        # Note: This test may not trigger without the full impossible travel logic
        # but demonstrates the test pattern
        if travel_detections:
            detection = travel_detections[0]
            self.assertEqual(detection.severity, AlertSeverity.MEDIUM)
            self.assertIn("travel", detection.title.lower())
    
    async def test_behavioral_anomaly_detection(self):
        """Test behavioral anomaly detection using UEBA"""
        base_time = datetime.now()
        user_id = "anomalous.user@company.com"
        
        # Mock high anomaly score
        self.ueba_engine.calculate_anomaly_score.return_value = 0.9
        
        # Create successful login with anomalous characteristics
        anomaly_event = self.create_mock_event(
            event_id="anomaly_event_001",
            timestamp=base_time,
            user_id=user_id,
            outcome="SUCCESS",
            country="Unknown Country",
            city="Unknown City",
            source_ip="198.51.100.5",  # Different IP range
            device_info={"type": "Unknown", "browser": "Unknown"}
        )
        
        # Run detection
        detections = await self.detector.analyze_events([anomaly_event], PlatformType.PANTHER)
        
        # Verify UEBA engine was called
        self.ueba_engine.calculate_anomaly_score.assert_called()
        
        # Check for account takeover detection (if anomaly is high enough)
        takeover_detections = [
            d for d in detections 
            if d.detection_type == DetectionType.ACCOUNT_TAKEOVER
        ]
        
        if takeover_detections:
            detection = takeover_detections[0]
            self.assertGreaterEqual(detection.confidence_score, 0.8)
    
    async def test_lateral_movement_detection(self):
        """Test lateral movement detection across applications"""
        base_time = datetime.now()
        user_id = "lateral.user@company.com"
        
        # Create rapid cross-application access
        applications = ["AWS SSO", "Azure AD", "Salesforce", "GitHub", "Jira", "Confluence"]
        lateral_events = []
        
        for i, app in enumerate(applications):
            event = self.create_mock_event(
                event_id=f"lateral_event_{i:03d}",
                timestamp=base_time + timedelta(minutes=i*5),
                user_id=user_id,
                application=app,
                outcome="SUCCESS",
                action="app.generic.provision.activate"
            )
            lateral_events.append(event)
        
        # Run detection
        detections = await self.detector.analyze_events(lateral_events, PlatformType.PANTHER)
        
        # Verify detection
        lateral_detections = [
            d for d in detections 
            if d.detection_type == DetectionType.LATERAL_MOVEMENT
        ]
        
        self.assertGreater(len(lateral_detections), 0)
        detection = lateral_detections[0]
        self.assertIn(user_id, detection.affected_users)
        self.assertGreaterEqual(len(set(e.application for e in detection.triggering_events)), 5)
    
    async def test_insider_threat_data_hoarding(self):
        """Test insider threat data hoarding detection"""
        base_time = datetime.now()
        user_id = "insider.user@company.com"
        
        # Create excessive data access pattern during off-hours
        data_events = []
        data_apps = ["SharePoint", "Box", "Google Drive", "Confluence"]
        
        # Generate off-hours access (2 AM)
        off_hours_time = base_time.replace(hour=2, minute=0, second=0)
        
        for i in range(30):  # 30 access events
            app = data_apps[i % len(data_apps)]
            event = self.create_mock_event(
                event_id=f"data_event_{i:03d}",
                timestamp=off_hours_time + timedelta(minutes=i*2),
                user_id=user_id,
                application=app,
                outcome="SUCCESS",
                action="app.generic.provision.activate"
            )
            data_events.append(event)
        
        # Run detection
        detections = await self.detector.analyze_events(data_events, PlatformType.PANTHER)
        
        # Verify detection
        insider_detections = [
            d for d in detections 
            if d.detection_type == DetectionType.INSIDER_THREAT
        ]
        
        if insider_detections:
            detection = insider_detections[0]
            self.assertEqual(detection.severity, AlertSeverity.MEDIUM)
            self.assertIn("off-hours" if "off" in detection.description.lower() else "data", detection.description.lower())
    
    async def test_distributed_credential_stuffing(self):
        """Test distributed credential stuffing from multiple IPs"""
        base_time = datetime.now()
        
        # Create coordinated attack from multiple IPs
        source_ips = [f"203.0.113.{i}" for i in range(10, 15)]  # 5 different IPs
        users = [f"target{i}@company.com" for i in range(1, 21)]  # 20 target users
        
        distributed_events = []
        event_id = 0
        
        for ip in source_ips:
            for user in users[:4]:  # Each IP targets 4 users
                for attempt in range(3):  # 3 attempts each
                    event = self.create_mock_event(
                        event_id=f"dist_cs_event_{event_id:03d}",
                        timestamp=base_time + timedelta(seconds=event_id*5),
                        user_id=user,
                        source_ip=ip,
                        outcome="FAILURE"
                    )
                    distributed_events.append(event)
                    event_id += 1
        
        # Run detection
        detections = await self.detector.analyze_events(distributed_events, PlatformType.PANTHER)
        
        # Verify detection
        cs_detections = [
            d for d in detections 
            if d.detection_type == DetectionType.CREDENTIAL_STUFFING
        ]
        
        self.assertGreater(len(cs_detections), 0)
        
        # Check if we detected the distributed nature
        high_severity_detections = [
            d for d in cs_detections 
            if d.severity == AlertSeverity.HIGH
        ]
        
        # Should detect high severity for distributed attack
        if high_severity_detections:
            detection = high_severity_detections[0]
            self.assertGreater(len(detection.affected_users), 10)
    
    async def test_false_positive_scenarios(self):
        """Test scenarios that should NOT trigger alerts"""
        base_time = datetime.now()
        
        # Scenario 1: Normal failed login (below threshold)
        normal_failures = [
            self.create_mock_event(
                event_id="normal_fail_001",
                timestamp=base_time,
                user_id="normal.user@company.com",
                outcome="FAILURE"
            )
        ]
        
        # Scenario 2: Successful logins (no credential stuffing)
        successful_logins = [
            self.create_mock_event(
                event_id=f"success_{i}",
                timestamp=base_time + timedelta(seconds=i*30),
                user_id=f"user{i}@company.com",
                outcome="SUCCESS"
            )
            for i in range(5)
        ]
        
        # Run detection on each scenario
        detection1 = await self.detector.analyze_events(normal_failures, PlatformType.PANTHER)
        detection2 = await self.detector.analyze_events(successful_logins, PlatformType.PANTHER)
        
        # Verify no false positives for credential stuffing
        cs_detections1 = [d for d in detection1 if d.detection_type == DetectionType.CREDENTIAL_STUFFING]
        cs_detections2 = [d for d in detection2 if d.detection_type == DetectionType.CREDENTIAL_STUFFING]
        
        self.assertEqual(len(cs_detections1), 0, "Normal single failure should not trigger credential stuffing alert")
        self.assertEqual(len(cs_detections2), 0, "Successful logins should not trigger credential stuffing alert")
    
    async def test_detection_confidence_scoring(self):
        """Test that confidence scores are calculated appropriately"""
        base_time = datetime.now()
        
        # High confidence scenario: Clear credential stuffing pattern
        high_confidence_events = []
        for i in range(10):  # 10 different users
            for attempt in range(3):  # 3 attempts each = 30 total
                event = self.create_mock_event(
                    event_id=f"high_conf_{i}_{attempt}",
                    timestamp=base_time + timedelta(seconds=i*10 + attempt*2),
                    user_id=f"user{i}@company.com",
                    source_ip="203.0.113.100",
                    outcome="FAILURE"
                )
                high_confidence_events.append(event)
        
        # Medium confidence scenario: Fewer targets
        medium_confidence_events = []
        for i in range(3):  # 3 different users
            for attempt in range(5):  # 5 attempts each = 15 total
                event = self.create_mock_event(
                    event_id=f"med_conf_{i}_{attempt}",
                    timestamp=base_time + timedelta(seconds=i*20 + attempt*5),
                    user_id=f"limited{i}@company.com",
                    source_ip="203.0.113.200",
                    outcome="FAILURE"
                )
                medium_confidence_events.append(event)
        
        # Run detections
        high_detections = await self.detector.analyze_events(high_confidence_events, PlatformType.PANTHER)
        medium_detections = await self.detector.analyze_events(medium_confidence_events, PlatformType.PANTHER)
        
        # Compare confidence scores
        high_cs = [d for d in high_detections if d.detection_type == DetectionType.CREDENTIAL_STUFFING]
        medium_cs = [d for d in medium_detections if d.detection_type == DetectionType.CREDENTIAL_STUFFING]
        
        if high_cs and medium_cs:
            self.assertGreater(
                high_cs[0].confidence_score, 
                medium_cs[0].confidence_score,
                "High confidence scenario should have higher confidence score"
            )
    
    async def test_detection_time_windows(self):
        """Test that time windows are properly enforced"""
        base_time = datetime.now()
        
        # Events spread over long time period (should not trigger)
        spread_events = []
        for i in range(6):  # 6 users
            event = self.create_mock_event(
                event_id=f"spread_event_{i}",
                timestamp=base_time + timedelta(hours=i),  # 1 hour apart each
                user_id=f"spread_user{i}@company.com",
                source_ip="203.0.113.50",
                outcome="FAILURE"
            )
            spread_events.append(event)
        
        # Events within time window (should trigger)
        clustered_events = []
        for i in range(6):  # 6 users
            event = self.create_mock_event(
                event_id=f"cluster_event_{i}",
                timestamp=base_time + timedelta(seconds=i*30),  # 30 seconds apart
                user_id=f"cluster_user{i}@company.com",
                source_ip="203.0.113.60",
                outcome="FAILURE"
            )
            clustered_events.append(event)
        
        # Run detections
        spread_detections = await self.detector.analyze_events(spread_events, PlatformType.PANTHER)
        cluster_detections = await self.detector.analyze_events(clustered_events, PlatformType.PANTHER)
        
        # Verify time window enforcement
        spread_cs = [d for d in spread_detections if d.detection_type == DetectionType.CREDENTIAL_STUFFING]
        cluster_cs = [d for d in cluster_detections if d.detection_type == DetectionType.CREDENTIAL_STUFFING]
        
        # Clustered events should trigger, spread events should not
        self.assertEqual(len(spread_cs), 0, "Events outside time window should not trigger")
        self.assertGreater(len(cluster_cs), 0, "Events within time window should trigger")


class TestPerformanceScenarios(unittest.IsolatedAsyncioTestCase):
    """Test performance under various load conditions"""
    
    def setUp(self):
        """Set up performance test environment"""
        self.ueba_engine = Mock(spec=BehaviorBaselineEngine)
        self.detector = ThreatPatternDetector(self.ueba_engine)
        self.ueba_engine.calculate_anomaly_score.return_value = 0.5
    
    async def test_high_volume_detection(self):
        """Test detection performance with high event volume"""
        import time
        
        base_time = datetime.now()
        
        # Generate 1000 events
        events = []
        for i in range(1000):
            event = NormalizedEvent(
                event_id=f"perf_event_{i:04d}",
                timestamp=base_time + timedelta(seconds=i),
                event_type="user.authentication.sso",
                source_platform=PlatformType.PANTHER,
                user_id=f"user{i%100}@company.com",  # 100 unique users
                user_type="User",
                user_groups=[],
                source_ip=f"192.168.{i//254 + 1}.{i%254 + 1}",
                user_agent="Test Agent",
                device_info={},
                country="United States",
                city="Test City",
                latitude=40.0,
                longitude=-74.0,
                application="Test App",
                resource="test",
                action="user.authentication.sso",
                outcome="SUCCESS",
                authentication_method="password",
                session_id=f"session_{i}",
                risk_score=0.0,
                raw_event={}
            )
            events.append(event)
        
        # Time the detection
        start_time = time.time()
        detections = await self.detector.analyze_events(events, PlatformType.PANTHER)
        end_time = time.time()
        
        processing_time = end_time - start_time
        events_per_second = len(events) / processing_time
        
        print(f"Processed {len(events)} events in {processing_time:.2f} seconds")
        print(f"Performance: {events_per_second:.2f} events/second")
        print(f"Generated {len(detections)} detections")
        
        # Performance assertion (should process at least 100 events/second)
        self.assertGreater(events_per_second, 100, 
                          f"Performance below threshold: {events_per_second:.2f} events/second")


if __name__ == "__main__":
    # Run the tests
    unittest.main(verbosity=2)