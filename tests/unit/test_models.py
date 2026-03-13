"""Tests for shared models — the foundation everything else depends on."""

import pytest
from datetime import datetime

from security_agents.core.models import (
    IntelligencePacket, IntelligenceType, Priority, SecurityTask, TaskStatus,
    AgentInfo, AgentStatus, AgentType, AnalysisRequest,
    ThreatCampaign, ThreatActorProfile, ThreatActorCategory,
    EnrichedIOC, IOCType,
    SecurityVulnerability, SupplyChainRisk,
    SecurityAlert, IncidentCase, Severity,
    AttackTechnique, AttackPhase, RedTeamOperation, AttackPath,
    PhishingIndicator, PhishingCampaign,
    SkillResult, CorrelationResult,
)


class TestIntelligencePacket:
    def test_create_packet(self):
        pkt = IntelligencePacket(
            packet_id="PKT-001",
            source_agent="alpha_4_threat_intel",
            target_agents=["beta_4_devsecops"],
            intelligence_type=IntelligenceType.THREAT_CAMPAIGN,
            priority=Priority.HIGH,
            confidence=85.0,
            timestamp=datetime.now(),
            data={"campaign": "test"},
            correlation_keys=["192.168.1.1"],
        )
        assert pkt.packet_id == "PKT-001"
        assert pkt.processed_by == []
        assert pkt.confidence == 85.0

    def test_packet_to_dict(self):
        pkt = IntelligencePacket(
            packet_id="PKT-002",
            source_agent="gamma_blue_team",
            target_agents=["all"],
            intelligence_type=IntelligenceType.PHISHING,
            priority=Priority.CRITICAL,
            confidence=95.0,
            timestamp=datetime.now(),
            data={"phishing": True},
            correlation_keys=["evil.xyz"],
        )
        d = pkt.to_dict()
        assert d["packet_id"] == "PKT-002"
        assert isinstance(d, dict)

    def test_all_intelligence_types_exist(self):
        expected = {
            "threat_campaign", "vulnerability", "infrastructure",
            "actor_profile", "ioc_enrichment", "supply_chain",
            "correlation", "incident", "phishing", "identity_threat",
            "compliance", "metrics",
        }
        actual = {t.value for t in IntelligenceType}
        assert expected == actual


class TestSecurityTask:
    def test_create_task(self):
        task = SecurityTask(
            task_id="TASK-001",
            task_type="analyze_campaign",
            priority=Priority.HIGH,
            assigned_agent="alpha_4_threat_intel",
            status=TaskStatus.PENDING,
            created_at=datetime.now(),
        )
        assert task.status == TaskStatus.PENDING
        assert task.results is None
        assert task.parameters == {}

    def test_task_to_dict(self):
        task = SecurityTask(
            task_id="TASK-002",
            task_type="comprehensive_scan",
            priority=Priority.MEDIUM,
            assigned_agent="beta_4_devsecops",
            status=TaskStatus.COMPLETED,
            created_at=datetime.now(),
            parameters={"target": "/app"},
        )
        d = task.to_dict()
        assert d["task_id"] == "TASK-002"


class TestAgentTypes:
    def test_all_agent_types(self):
        expected = {
            "alpha_4_threat_intel", "beta_4_devsecops",
            "gamma_blue_team", "delta_red_team", "sigma_metrics",
        }
        actual = {t.value for t in AgentType}
        assert expected == actual


class TestPhishingModels:
    def test_phishing_indicator(self):
        ind = PhishingIndicator(
            indicator_id="PHI-001",
            email_subject="Urgent verify",
            sender_address="bad@evil.xyz",
            sender_domain="evil.xyz",
            recipient_count=5,
            urls_extracted=["https://evil.xyz/login"],
            attachments=[],
            authentication_results={"spf": "fail", "dkim": "fail", "dmarc": "fail"},
            risk_score=92.0,
            classification="phishing",
            confidence=95.0,
        )
        assert ind.classification == "phishing"
        assert ind.risk_score == 92.0

    def test_phishing_campaign(self):
        camp = PhishingCampaign(
            campaign_id="CAMP-001",
            name="Test Phishing",
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            total_emails=100,
            unique_targets=50,
            sender_infrastructure=["evil.xyz", "bad.tk"],
            payload_type="credential_harvest",
            lure_theme="Account verification",
        )
        assert camp.mitigation_status == "active"
        assert camp.total_emails == 100


class TestSkillResult:
    def test_success_result(self):
        r = SkillResult(
            success=True,
            skill_name="phishing_analysis",
            agent_id="gamma_blue_team",
            data={"score": 85},
        )
        assert r.success
        assert r.errors == []

    def test_failure_result(self):
        r = SkillResult(
            success=False,
            skill_name="phishing_analysis",
            agent_id="gamma_blue_team",
            errors=["API timeout"],
        )
        assert not r.success
        assert len(r.errors) == 1
