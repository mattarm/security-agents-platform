"""Tests for the Threat Hunting Skill."""

import pytest
from datetime import datetime

from security_agents.skills.threat_hunting import ThreatHuntingSkill, HuntStatus, QueryLanguage
from security_agents.core.models import SkillResult


@pytest.fixture
async def hunt_skill():
    """Create and initialize a threat hunting skill."""
    skill = ThreatHuntingSkill(agent_id="gamma_blue_team")
    await skill.initialize()
    return skill


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestThreatHuntingInit:
    @pytest.mark.asyncio
    async def test_initialize(self, hunt_skill):
        assert hunt_skill.initialized
        assert hunt_skill.SKILL_NAME == "threat_hunting"

    @pytest.mark.asyncio
    async def test_not_initialized_returns_error(self):
        skill = ThreatHuntingSkill(agent_id="test")
        result = await skill.execute({"action": "generate_hypothesis"})
        assert not result.success
        assert "not initialized" in result.errors[0]

    def test_metadata(self):
        skill = ThreatHuntingSkill(agent_id="gamma_blue_team")
        meta = skill.get_metadata()
        assert meta["skill_name"] == "threat_hunting"
        assert "gamma_blue_team" in meta["compatible_agents"]
        assert meta["version"] == "1.0.0"


# ---------------------------------------------------------------------------
# Hypothesis Generation
# ---------------------------------------------------------------------------


class TestGenerateHypothesis:
    @pytest.mark.asyncio
    async def test_generates_all_areas_without_context(self, hunt_skill):
        result = await hunt_skill.execute({"action": "generate_hypothesis"})
        assert result.success
        hypotheses = result.data["hypotheses"]
        assert result.data["total"] == len(ThreatHuntingSkill.HUNT_HYPOTHESES)
        assert result.data["context_used"] is False
        # Each hypothesis should carry the expected keys
        for h in hypotheses:
            assert "hypothesis_id" in h
            assert h["hypothesis_id"].startswith("HYP-")
            assert "area" in h
            assert "relevance_score" in h
            assert "priority" in h
            assert h["priority"] in ("high", "medium", "low")

    @pytest.mark.asyncio
    async def test_focus_area_filters_to_one_hypothesis(self, hunt_skill):
        result = await hunt_skill.execute({
            "action": "generate_hypothesis",
            "focus_area": "persistence",
        })
        assert result.success
        assert result.data["total"] == 1
        assert result.data["hypotheses"][0]["area"] == "persistence"

    @pytest.mark.asyncio
    async def test_context_boosts_relevance(self, hunt_skill):
        """Providing context that matches keywords should raise the relevance score."""
        no_context = await hunt_skill.execute({
            "action": "generate_hypothesis",
            "focus_area": "lateral_movement",
        })
        with_context = await hunt_skill.execute({
            "action": "generate_hypothesis",
            "focus_area": "lateral_movement",
            "threat_context": "Adversary is using RDP to pivot between workstations",
        })
        assert with_context.success
        assert with_context.data["context_used"] is True
        score_no = no_context.data["hypotheses"][0]["relevance_score"]
        score_yes = with_context.data["hypotheses"][0]["relevance_score"]
        assert score_yes > score_no

    @pytest.mark.asyncio
    async def test_intelligence_technique_boosts_relevance(self, hunt_skill):
        result = await hunt_skill.execute({
            "action": "generate_hypothesis",
            "focus_area": "credential_access",
            "intelligence": {"techniques": ["T1003"]},
        })
        assert result.success
        score = result.data["hypotheses"][0]["relevance_score"]
        # T1003 is in credential_access techniques -> +20 boost -> 50+20 = 70+
        assert score >= 70

    @pytest.mark.asyncio
    async def test_active_incident_boosts_relevance(self, hunt_skill):
        result = await hunt_skill.execute({
            "action": "generate_hypothesis",
            "focus_area": "exfiltration",
            "intelligence": {"active_incident": True},
        })
        assert result.success
        score = result.data["hypotheses"][0]["relevance_score"]
        assert score >= 60  # base 50 + 10 from active_incident

    @pytest.mark.asyncio
    async def test_hypotheses_sorted_by_relevance(self, hunt_skill):
        result = await hunt_skill.execute({
            "action": "generate_hypothesis",
            "threat_context": "lateral movement via rdp",
        })
        scores = [h["relevance_score"] for h in result.data["hypotheses"]]
        assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------------------
# Query Generation
# ---------------------------------------------------------------------------


class TestGenerateQuery:
    @pytest.mark.asyncio
    async def test_kql_lateral_movement_query(self, hunt_skill):
        result = await hunt_skill.execute({
            "action": "generate_query",
            "area": "lateral_movement",
            "language": "kql",
            "threshold": 5,
            "timeframe": "24h",
        })
        assert result.success
        queries = result.data["queries"]
        assert len(queries) >= 1
        q = queries[0]
        assert q["language"] == "kql"
        assert "SecurityEvent" in q["query"]
        # threshold should be substituted
        assert "5" in q["query"]

    @pytest.mark.asyncio
    async def test_sigma_query(self, hunt_skill):
        result = await hunt_skill.execute({
            "action": "generate_query",
            "area": "lateral_movement",
            "language": "sigma",
        })
        assert result.success
        queries = result.data["queries"]
        assert len(queries) >= 1
        assert "title:" in queries[0]["query"]
        assert queries[0]["language"] == "sigma"

    @pytest.mark.asyncio
    async def test_query_with_iocs(self, hunt_skill):
        iocs = ["10.0.0.1", "evil.com", "abc123hash"]
        result = await hunt_skill.execute({
            "action": "generate_query",
            "area": "lateral_movement",
            "language": "kql",
            "iocs": iocs,
        })
        assert result.success
        # Should have at least the template query + the IOC query
        queries = result.data["queries"]
        assert len(queries) >= 2
        ioc_query = queries[-1]
        assert ioc_query["description"] == "IOC-based hunt query"
        assert "10.0.0.1" in ioc_query["query"]
        assert "evil.com" in ioc_query["query"]

    @pytest.mark.asyncio
    async def test_bad_language_returns_error(self, hunt_skill):
        result = await hunt_skill.execute({
            "action": "generate_query",
            "area": "lateral_movement",
            "language": "nosuchlang",
        })
        assert not result.success
        assert "Unsupported language" in result.errors[0]

    @pytest.mark.asyncio
    async def test_iocs_not_added_for_sigma(self, hunt_skill):
        """IOC query generation is only implemented for KQL; Sigma should skip it."""
        result = await hunt_skill.execute({
            "action": "generate_query",
            "area": "lateral_movement",
            "language": "sigma",
            "iocs": ["10.0.0.1"],
        })
        assert result.success
        # No IOC query appended for sigma (returns None from _generate_ioc_query)
        for q in result.data["queries"]:
            assert q["description"] != "IOC-based hunt query"


# ---------------------------------------------------------------------------
# Hunt Campaign Lifecycle
# ---------------------------------------------------------------------------


class TestHuntLifecycle:
    @pytest.mark.asyncio
    async def test_start_hunt(self, hunt_skill):
        result = await hunt_skill.execute({
            "action": "start_hunt",
            "name": "APT-29 Hunt",
            "hypothesis": "APT-29 using RDP for lateral movement",
            "area": "lateral_movement",
            "analyst": "analyst1",
        })
        assert result.success
        hunt = result.data["hunt"]
        assert hunt["hunt_id"].startswith("HUNT-")
        assert hunt["name"] == "APT-29 Hunt"
        assert hunt["status"] == "active"
        assert hunt["analyst"] == "analyst1"

    @pytest.mark.asyncio
    async def test_record_finding_on_active_hunt(self, hunt_skill):
        start = await hunt_skill.execute({"action": "start_hunt", "name": "Test Hunt"})
        hunt_id = start.data["hunt"]["hunt_id"]

        result = await hunt_skill.execute({
            "action": "record_finding",
            "hunt_id": hunt_id,
            "description": "Found suspicious lateral movement via PsExec",
            "severity": "high",
            "affected_systems": ["ws-001", "ws-002"],
            "iocs": ["10.0.0.5"],
            "mitre_techniques": ["T1021.002"],
        })
        assert result.success
        finding = result.data["finding"]
        assert finding["finding_id"].startswith("FND-")
        assert finding["severity"] == "high"
        assert "ws-001" in finding["affected_systems"]
        # High severity should generate intelligence packet
        assert len(result.intelligence_packets) == 1
        pkt = result.intelligence_packets[0]
        assert pkt.source_agent == "gamma_blue_team"

    @pytest.mark.asyncio
    async def test_record_finding_medium_no_packet(self, hunt_skill):
        start = await hunt_skill.execute({"action": "start_hunt", "name": "Medium Hunt"})
        hunt_id = start.data["hunt"]["hunt_id"]

        result = await hunt_skill.execute({
            "action": "record_finding",
            "hunt_id": hunt_id,
            "description": "Minor anomaly",
            "severity": "medium",
        })
        assert result.success
        assert len(result.intelligence_packets) == 0

    @pytest.mark.asyncio
    async def test_record_finding_invalid_hunt(self, hunt_skill):
        result = await hunt_skill.execute({
            "action": "record_finding",
            "hunt_id": "HUNT-nonexistent",
            "description": "Should fail",
        })
        assert not result.success
        assert "not found" in result.errors[0]

    @pytest.mark.asyncio
    async def test_complete_hunt_generates_summary(self, hunt_skill):
        start = await hunt_skill.execute({"action": "start_hunt", "name": "Completion Test"})
        hunt_id = start.data["hunt"]["hunt_id"]

        # Add a critical finding
        await hunt_skill.execute({
            "action": "record_finding",
            "hunt_id": hunt_id,
            "description": "Critical malware",
            "severity": "critical",
            "iocs": ["bad.exe"],
            "mitre_techniques": ["T1059"],
        })

        result = await hunt_skill.execute({
            "action": "complete_hunt",
            "hunt_id": hunt_id,
            "conclusion": "Confirmed APT activity",
        })
        assert result.success
        summary = result.data["summary"]
        assert summary["total_findings"] == 1
        assert summary["critical_findings"] == 1
        assert "bad.exe" in summary["unique_iocs"]
        assert "T1059" in summary["techniques_observed"]
        assert summary["conclusion"] == "Confirmed APT activity"

    @pytest.mark.asyncio
    async def test_complete_nonexistent_hunt(self, hunt_skill):
        result = await hunt_skill.execute({
            "action": "complete_hunt",
            "hunt_id": "HUNT-bogus",
        })
        assert not result.success
        assert "not found" in result.errors[0]

    @pytest.mark.asyncio
    async def test_list_hunts(self, hunt_skill):
        # Start two hunts
        await hunt_skill.execute({"action": "start_hunt", "name": "Hunt A"})
        await hunt_skill.execute({"action": "start_hunt", "name": "Hunt B"})

        result = await hunt_skill.execute({"action": "list_hunts"})
        assert result.success
        assert len(result.data["active_hunts"]) >= 2

    @pytest.mark.asyncio
    async def test_list_hunts_with_status_filter(self, hunt_skill):
        result = await hunt_skill.execute({"action": "list_hunts", "status": "completed"})
        assert result.success
        # All returned hunts should have completed status (may be 0)
        for h in result.data["active_hunts"]:
            assert h["status"] == "completed"


# ---------------------------------------------------------------------------
# Anomaly Detection
# ---------------------------------------------------------------------------


class TestDetectAnomalies:
    @pytest.mark.asyncio
    async def test_detect_anomaly_with_baseline(self, hunt_skill):
        result = await hunt_skill.execute({
            "action": "detect_anomalies",
            "data_points": [
                {"entity": "user1", "metric": "logins", "value": 100},
                {"entity": "user2", "metric": "logins", "value": 5},
            ],
            "baseline": {
                "user1_logins_mean": 10,
                "user1_logins_std": 3,
                "user2_logins_mean": 4,
                "user2_logins_std": 2,
            },
            "sensitivity": 2.0,
        })
        assert result.success
        assert result.data["total_checked"] == 2
        anomalies = result.data["anomalies"]
        # user1: z = (100-10)/3 = 30 -> anomaly; user2: z = (5-4)/2 = 0.5 -> not anomaly
        assert result.data["anomalies_found"] == 1
        assert anomalies[0]["entity"] == "user1"
        assert anomalies[0]["z_score"] == 30.0
        assert anomalies[0]["severity"] == "critical"  # z > 4

    @pytest.mark.asyncio
    async def test_severity_tiers(self, hunt_skill):
        """z > 4 = critical, z > 3 = high, else medium."""
        result = await hunt_skill.execute({
            "action": "detect_anomalies",
            "data_points": [
                {"entity": "a", "metric": "x", "value": 50},   # z = (50-0)/1 = 50 -> critical
                {"entity": "b", "metric": "x", "value": 3.5},  # z = 3.5 -> high
                {"entity": "c", "metric": "x", "value": 2.5},  # z = 2.5 -> medium
            ],
            "sensitivity": 2.0,
        })
        assert result.success
        severity_map = {a["entity"]: a["severity"] for a in result.data["anomalies"]}
        assert severity_map["a"] == "critical"
        assert severity_map["b"] == "high"
        assert severity_map["c"] == "medium"

    @pytest.mark.asyncio
    async def test_no_data_points_returns_error(self, hunt_skill):
        result = await hunt_skill.execute({"action": "detect_anomalies"})
        assert not result.success
        assert "data_points" in result.errors[0]

    @pytest.mark.asyncio
    async def test_no_anomalies_when_within_baseline(self, hunt_skill):
        result = await hunt_skill.execute({
            "action": "detect_anomalies",
            "data_points": [
                {"entity": "norm", "metric": "logins", "value": 10},
            ],
            "baseline": {
                "norm_logins_mean": 10,
                "norm_logins_std": 5,
            },
            "sensitivity": 2.0,
        })
        assert result.success
        assert result.data["anomalies_found"] == 0


# ---------------------------------------------------------------------------
# Specialized Hunt Packages
# ---------------------------------------------------------------------------


class TestSpecializedHunts:
    @pytest.mark.asyncio
    async def test_hunt_lateral_movement_package(self, hunt_skill):
        result = await hunt_skill.execute({
            "action": "hunt_lateral_movement",
            "timeframe": "3d",
        })
        assert result.success
        pkg = result.data["hunt_package"]
        assert pkg["area"] == "lateral_movement"
        assert pkg["timeframe"] == "3d"
        assert len(pkg["hypotheses"]) >= 1
        assert "kql" in pkg["queries"]
        assert "sigma" in pkg["queries"]
        assert len(pkg["data_sources"]) > 0
        assert len(pkg["mitre_techniques"]) > 0

    @pytest.mark.asyncio
    async def test_hunt_persistence_package(self, hunt_skill):
        result = await hunt_skill.execute({"action": "hunt_persistence"})
        assert result.success
        pkg = result.data["hunt_package"]
        assert pkg["area"] == "persistence"
        assert pkg["estimated_effort_hours"] == 3.0

    @pytest.mark.asyncio
    async def test_hunt_exfiltration_package(self, hunt_skill):
        result = await hunt_skill.execute({"action": "hunt_exfiltration"})
        assert result.success
        assert result.data["hunt_package"]["area"] == "exfiltration"
        assert result.data["hunt_package"]["estimated_effort_hours"] == 6.0

    @pytest.mark.asyncio
    async def test_hunt_c2_package(self, hunt_skill):
        result = await hunt_skill.execute({"action": "hunt_c2"})
        assert result.success
        pkg = result.data["hunt_package"]
        assert pkg["area"] == "command_and_control"
        assert "Beaconing patterns" in pkg["indicators_to_look_for"][0]

    @pytest.mark.asyncio
    async def test_hunt_package_includes_iocs_in_queries(self, hunt_skill):
        result = await hunt_skill.execute({
            "action": "hunt_lateral_movement",
            "iocs": ["192.168.1.99"],
        })
        assert result.success
        kql_queries = result.data["hunt_package"]["queries"]["kql"]
        # IOC query should be appended for KQL
        assert any("192.168.1.99" in q["query"] for q in kql_queries)


# ---------------------------------------------------------------------------
# Unknown Action
# ---------------------------------------------------------------------------


class TestUnknownAction:
    @pytest.mark.asyncio
    async def test_unknown_action_returns_error(self, hunt_skill):
        result = await hunt_skill.execute({"action": "does_not_exist"})
        assert not result.success
        assert "Unknown action" in result.errors[0]
        assert "does_not_exist" in result.errors[0]
