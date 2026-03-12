"""Tests for the Incident Response Skill."""

import pytest
from datetime import datetime, timedelta

from security_agents.skills.incident_response import (
    IncidentResponseSkill,
    IncidentPhase,
    IncidentSeverity,
    PlaybookStepType,
)
from security_agents.core.models import SkillResult


@pytest.fixture
async def ir_skill():
    """Create and initialize an incident response skill."""
    skill = IncidentResponseSkill(agent_id="gamma_blue_team")
    await skill.initialize()
    return skill


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestIncidentResponseInit:
    @pytest.mark.asyncio
    async def test_initialize(self, ir_skill):
        assert ir_skill.initialized
        assert ir_skill.SKILL_NAME == "incident_response"

    @pytest.mark.asyncio
    async def test_not_initialized_returns_error(self):
        skill = IncidentResponseSkill(agent_id="test")
        result = await skill.execute({"action": "classify_incident"})
        assert not result.success
        assert "not initialized" in result.errors[0]

    def test_metadata(self):
        skill = IncidentResponseSkill(agent_id="gamma_blue_team")
        meta = skill.get_metadata()
        assert meta["skill_name"] == "incident_response"
        assert "gamma_blue_team" in meta["compatible_agents"]


# ---------------------------------------------------------------------------
# Incident Classification
# ---------------------------------------------------------------------------


class TestClassifyIncident:
    @pytest.mark.asyncio
    async def test_classify_malware(self, ir_skill):
        result = await ir_skill.execute({
            "action": "classify_incident",
            "title": "Ransomware detected on workstation",
            "description": "CrowdStrike flagged ransomware encryption activity",
        })
        assert result.success
        assert result.data["classification"] == "malware_infection"
        assert result.data["confidence"] == 85.0
        assert result.data["recommended_playbook"] == "malware_infection"
        assert result.data["severity"] == "P2"

    @pytest.mark.asyncio
    async def test_classify_phishing(self, ir_skill):
        result = await ir_skill.execute({
            "action": "classify_incident",
            "title": "Phishing email with credential harvest link",
            "description": "User reported a spear phishing email",
        })
        assert result.success
        assert result.data["classification"] == "phishing_compromise"
        assert result.data["confidence"] == 85.0
        assert result.data["playbook_name"] == "Phishing Compromise Response"

    @pytest.mark.asyncio
    async def test_classify_data_breach(self, ir_skill):
        result = await ir_skill.execute({
            "action": "classify_incident",
            "title": "DLP alert: data exfiltration detected",
            "description": "Large data transfer to external cloud storage",
        })
        assert result.success
        assert result.data["classification"] == "data_breach"
        assert result.data["confidence"] == 80.0
        assert result.data["severity"] == "P1"

    @pytest.mark.asyncio
    async def test_classify_unauthorized_access(self, ir_skill):
        result = await ir_skill.execute({
            "action": "classify_incident",
            "title": "Brute force login attempts from external IP",
            "description": "Multiple failed login attempts detected",
        })
        assert result.success
        assert result.data["classification"] == "unauthorized_access"
        assert result.data["confidence"] == 75.0

    @pytest.mark.asyncio
    async def test_severity_escalates_with_many_affected_systems(self, ir_skill):
        result = await ir_skill.execute({
            "action": "classify_incident",
            "title": "Unauthorized access attempt",
            "description": "credential stuffing detected",
            "affected_systems": [f"host-{i}" for i in range(15)],
        })
        assert result.success
        assert result.data["severity"] == "P1"

    @pytest.mark.asyncio
    async def test_default_classification_when_ambiguous(self, ir_skill):
        result = await ir_skill.execute({
            "action": "classify_incident",
            "title": "Something weird happened",
            "description": "Unknown alert from monitoring",
        })
        assert result.success
        assert result.data["classification"] == "unauthorized_access"
        assert result.data["confidence"] == 50.0

    @pytest.mark.asyncio
    async def test_classification_includes_sla(self, ir_skill):
        result = await ir_skill.execute({
            "action": "classify_incident",
            "title": "Malware on server",
        })
        assert result.success
        sla = result.data["sla"]
        assert "response_minutes" in sla
        assert "containment_minutes" in sla
        assert "resolution_hours" in sla


# ---------------------------------------------------------------------------
# Playbook Management
# ---------------------------------------------------------------------------


class TestPlaybookManagement:
    @pytest.mark.asyncio
    async def test_get_playbook_malware(self, ir_skill):
        result = await ir_skill.execute({
            "action": "get_playbook",
            "playbook_id": "malware_infection",
        })
        assert result.success
        pb = result.data["playbook"]
        assert pb["name"] == "Malware Infection Response"
        assert "detection" in pb["phases"]
        assert "containment" in pb["phases"]

    @pytest.mark.asyncio
    async def test_get_unknown_playbook(self, ir_skill):
        result = await ir_skill.execute({
            "action": "get_playbook",
            "playbook_id": "nonexistent_playbook",
        })
        assert not result.success
        assert "not found" in result.errors[0]
        assert "Available:" in result.errors[0]

    @pytest.mark.asyncio
    async def test_list_playbooks(self, ir_skill):
        result = await ir_skill.execute({"action": "list_playbooks"})
        assert result.success
        playbooks = result.data["playbooks"]
        assert len(playbooks) == 4
        ids = [p["id"] for p in playbooks]
        assert "malware_infection" in ids
        assert "phishing_compromise" in ids
        assert "data_breach" in ids
        assert "unauthorized_access" in ids
        # Each playbook summary has step counts
        for p in playbooks:
            assert p["steps"] > 0
            assert p["phases"] > 0


# ---------------------------------------------------------------------------
# Incident Lifecycle
# ---------------------------------------------------------------------------


class TestIncidentLifecycle:
    @pytest.mark.asyncio
    async def test_start_incident(self, ir_skill):
        result = await ir_skill.execute({
            "action": "start_incident",
            "classification": "malware_infection",
            "title": "Ransomware on WS-042",
            "severity": "P1",
            "analyst": "analyst1",
            "affected_systems": ["WS-042"],
            "iocs": ["evil.exe"],
        })
        assert result.success
        inc = result.data["incident"]
        assert inc["incident_id"].startswith("INC-")
        assert inc["classification"] == "malware_infection"
        assert inc["severity"] == "P1"
        assert inc["current_phase"] == "detection"
        assert inc["status"] == "active"
        assert inc["assigned_to"] == "analyst1"
        assert "WS-042" in inc["affected_systems"]
        # SLA deadlines should be set
        assert "response_deadline" in inc["sla"]
        # Should emit an intelligence packet
        assert len(result.intelligence_packets) == 1
        pkt = result.intelligence_packets[0]
        assert pkt.data["severity"] == "P1"

    @pytest.mark.asyncio
    async def test_execute_step_advances_through_playbook(self, ir_skill):
        start = await ir_skill.execute({
            "action": "start_incident",
            "classification": "unauthorized_access",
        })
        inc_id = start.data["incident"]["incident_id"]

        # Execute first step in detection phase
        result = await ir_skill.execute({
            "action": "execute_step",
            "incident_id": inc_id,
            "result": "completed",
            "notes": "Validated alert",
        })
        assert result.success
        step = result.data["completed_step"]
        assert step["phase"] == "detection"
        assert step["result"] == "completed"
        assert result.data["steps_remaining_in_phase"] >= 0

    @pytest.mark.asyncio
    async def test_execute_step_missing_incident(self, ir_skill):
        result = await ir_skill.execute({
            "action": "execute_step",
            "incident_id": "INC-bogus",
        })
        assert not result.success
        assert "not found" in result.errors[0]

    @pytest.mark.asyncio
    async def test_execute_step_past_end_of_phase(self, ir_skill):
        start = await ir_skill.execute({
            "action": "start_incident",
            "classification": "unauthorized_access",
        })
        inc_id = start.data["incident"]["incident_id"]

        # Execute all steps in detection phase (unauthorized_access has 2 detection steps)
        playbook = IncidentResponseSkill.PLAYBOOKS["unauthorized_access"]
        detection_steps = len(playbook["phases"]["detection"])
        for _ in range(detection_steps):
            await ir_skill.execute({"action": "execute_step", "incident_id": inc_id})

        # One more should fail
        result = await ir_skill.execute({"action": "execute_step", "incident_id": inc_id})
        assert not result.success
        assert "advance_phase" in result.errors[0]

    @pytest.mark.asyncio
    async def test_advance_phase(self, ir_skill):
        start = await ir_skill.execute({
            "action": "start_incident",
            "classification": "unauthorized_access",
        })
        inc_id = start.data["incident"]["incident_id"]

        result = await ir_skill.execute({
            "action": "advance_phase",
            "incident_id": inc_id,
        })
        assert result.success
        assert result.data["previous_phase"] == "detection"
        assert result.data["current_phase"] == "triage"
        assert result.data["steps_in_phase"] > 0
        assert result.data["first_step"] is not None

    @pytest.mark.asyncio
    async def test_advance_phase_at_final_phase(self, ir_skill):
        start = await ir_skill.execute({
            "action": "start_incident",
            "classification": "unauthorized_access",
        })
        inc_id = start.data["incident"]["incident_id"]

        # Advance through all phases
        phases = [p.value for p in IncidentPhase]
        for _ in range(len(phases) - 1):
            result = await ir_skill.execute({
                "action": "advance_phase",
                "incident_id": inc_id,
            })
            assert result.success

        # One more should fail (already at lessons_learned)
        result = await ir_skill.execute({
            "action": "advance_phase",
            "incident_id": inc_id,
        })
        assert not result.success
        assert "final phase" in result.errors[0]

    @pytest.mark.asyncio
    async def test_close_incident(self, ir_skill):
        start = await ir_skill.execute({
            "action": "start_incident",
            "classification": "malware_infection",
            "title": "Test closure",
            "affected_systems": ["srv-01"],
        })
        inc_id = start.data["incident"]["incident_id"]

        result = await ir_skill.execute({
            "action": "close_incident",
            "incident_id": inc_id,
            "root_cause": "User downloaded malicious attachment",
            "resolution": "Host reimaged, credentials reset",
        })
        assert result.success
        summary = result.data["summary"]
        assert summary["incident_id"] == inc_id
        assert summary["classification"] == "malware_infection"
        assert summary["root_cause"] == "User downloaded malicious attachment"
        assert summary["resolution"] == "Host reimaged, credentials reset"
        assert summary["affected_systems"] == 1
        assert summary["duration_hours"] >= 0

    @pytest.mark.asyncio
    async def test_close_nonexistent_incident(self, ir_skill):
        result = await ir_skill.execute({
            "action": "close_incident",
            "incident_id": "INC-nope",
        })
        assert not result.success
        assert "not found" in result.errors[0]


# ---------------------------------------------------------------------------
# Evidence Recording
# ---------------------------------------------------------------------------


class TestRecordEvidence:
    @pytest.mark.asyncio
    async def test_record_evidence_with_chain_of_custody(self, ir_skill):
        start = await ir_skill.execute({
            "action": "start_incident",
            "classification": "data_breach",
        })
        inc_id = start.data["incident"]["incident_id"]

        result = await ir_skill.execute({
            "action": "record_evidence",
            "incident_id": inc_id,
            "type": "disk_image",
            "description": "Forensic image of SRV-DB01",
            "source": "SRV-DB01",
            "hash": "sha256:abc123def456",
            "analyst": "forensics_team",
        })
        assert result.success
        ev = result.data["evidence"]
        assert ev["evidence_id"].startswith("EV-")
        assert ev["type"] == "disk_image"
        assert ev["hash"] == "sha256:abc123def456"
        assert len(ev["chain_of_custody"]) == 1
        assert ev["chain_of_custody"][0]["action"] == "collected"

    @pytest.mark.asyncio
    async def test_record_evidence_missing_incident(self, ir_skill):
        result = await ir_skill.execute({
            "action": "record_evidence",
            "incident_id": "INC-missing",
            "description": "Should fail",
        })
        assert not result.success
        assert "not found" in result.errors[0]

    @pytest.mark.asyncio
    async def test_evidence_appears_in_incident(self, ir_skill):
        start = await ir_skill.execute({
            "action": "start_incident",
            "classification": "unauthorized_access",
        })
        inc_id = start.data["incident"]["incident_id"]

        await ir_skill.execute({
            "action": "record_evidence",
            "incident_id": inc_id,
            "description": "Auth logs",
        })
        await ir_skill.execute({
            "action": "record_evidence",
            "incident_id": inc_id,
            "description": "Firewall logs",
        })

        # Generate report to inspect evidence count
        report = await ir_skill.execute({
            "action": "generate_report",
            "incident_id": inc_id,
        })
        assert report.success
        assert report.data["report"]["evidence_count"] == 2


# ---------------------------------------------------------------------------
# SLA Checking
# ---------------------------------------------------------------------------


class TestCheckSLA:
    @pytest.mark.asyncio
    async def test_sla_within_limits(self, ir_skill):
        start = await ir_skill.execute({
            "action": "start_incident",
            "classification": "unauthorized_access",
            "severity": "P4",
        })
        inc_id = start.data["incident"]["incident_id"]

        result = await ir_skill.execute({
            "action": "check_sla",
            "incident_id": inc_id,
        })
        assert result.success
        assert result.data["any_breached"] is False
        assert result.data["severity"] == "P4"
        # Response SLA: should not be breached since we just created it
        assert result.data["sla_status"]["response"]["breached"] is False
        assert result.data["sla_status"]["response"]["remaining_minutes"] > 0

    @pytest.mark.asyncio
    async def test_sla_breach_detection(self, ir_skill):
        start = await ir_skill.execute({
            "action": "start_incident",
            "classification": "malware_infection",
            "severity": "P1",
        })
        inc_id = start.data["incident"]["incident_id"]

        # Manually push deadline into the past to simulate breach
        past = (datetime.now() - timedelta(hours=1)).isoformat()
        ir_skill.active_incidents[inc_id]["sla"]["response_deadline"] = past
        ir_skill.active_incidents[inc_id]["sla"]["containment_deadline"] = past
        ir_skill.active_incidents[inc_id]["sla"]["resolution_deadline"] = past

        result = await ir_skill.execute({
            "action": "check_sla",
            "incident_id": inc_id,
        })
        assert result.success
        assert result.data["any_breached"] is True
        assert result.data["sla_status"]["response"]["breached"] is True
        assert result.data["sla_status"]["response"]["remaining_minutes"] == 0
        assert len(result.warnings) == 1
        assert "SLA BREACH" in result.warnings[0]

    @pytest.mark.asyncio
    async def test_sla_missing_incident(self, ir_skill):
        result = await ir_skill.execute({
            "action": "check_sla",
            "incident_id": "INC-nope",
        })
        assert not result.success


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------


class TestGenerateReport:
    @pytest.mark.asyncio
    async def test_report_active_incident(self, ir_skill):
        start = await ir_skill.execute({
            "action": "start_incident",
            "classification": "phishing_compromise",
            "title": "Phishing Wave",
            "iocs": ["evil.com"],
            "affected_systems": ["mail-gw-01"],
        })
        inc_id = start.data["incident"]["incident_id"]

        result = await ir_skill.execute({
            "action": "generate_report",
            "incident_id": inc_id,
        })
        assert result.success
        assert result.data["source"] == "active"
        report = result.data["report"]
        assert report["title"] == "Phishing Wave"
        assert report["classification"] == "phishing_compromise"
        assert report["status"] == "active"
        assert "evil.com" in report["iocs"]
        assert len(report["timeline"]) >= 1

    @pytest.mark.asyncio
    async def test_report_closed_incident(self, ir_skill):
        start = await ir_skill.execute({
            "action": "start_incident",
            "classification": "unauthorized_access",
            "title": "Closed Incident Report Test",
        })
        inc_id = start.data["incident"]["incident_id"]

        await ir_skill.execute({
            "action": "close_incident",
            "incident_id": inc_id,
            "root_cause": "Weak password",
            "resolution": "Password policy updated",
        })

        result = await ir_skill.execute({
            "action": "generate_report",
            "incident_id": inc_id,
        })
        assert result.success
        assert result.data["source"] == "history"
        assert result.data["report"]["root_cause"] == "Weak password"

    @pytest.mark.asyncio
    async def test_report_nonexistent_incident(self, ir_skill):
        result = await ir_skill.execute({
            "action": "generate_report",
            "incident_id": "INC-ghost",
        })
        assert not result.success
        assert "not found" in result.errors[0]


# ---------------------------------------------------------------------------
# List Incidents
# ---------------------------------------------------------------------------


class TestListIncidents:
    @pytest.mark.asyncio
    async def test_list_incidents(self, ir_skill):
        await ir_skill.execute({
            "action": "start_incident",
            "classification": "malware_infection",
            "title": "Incident A",
        })
        await ir_skill.execute({
            "action": "start_incident",
            "classification": "data_breach",
            "title": "Incident B",
        })

        result = await ir_skill.execute({"action": "list_incidents"})
        assert result.success
        incidents = result.data["active_incidents"]
        assert len(incidents) >= 2
        titles = [i["title"] for i in incidents]
        assert "Incident A" in titles
        assert "Incident B" in titles

    @pytest.mark.asyncio
    async def test_closed_count_updates(self, ir_skill):
        start = await ir_skill.execute({
            "action": "start_incident",
            "classification": "unauthorized_access",
        })
        inc_id = start.data["incident"]["incident_id"]
        await ir_skill.execute({"action": "close_incident", "incident_id": inc_id})

        result = await ir_skill.execute({"action": "list_incidents"})
        assert result.success
        assert result.data["closed_count"] >= 1


# ---------------------------------------------------------------------------
# Unknown Action
# ---------------------------------------------------------------------------


class TestUnknownAction:
    @pytest.mark.asyncio
    async def test_unknown_action_returns_error(self, ir_skill):
        result = await ir_skill.execute({"action": "launch_missiles"})
        assert not result.success
        assert "Unknown action" in result.errors[0]
        assert "launch_missiles" in result.errors[0]
