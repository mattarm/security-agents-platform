"""Tests for the Insider Threat Detection Skill."""

import pytest

from security_agents.skills.insider_threat import InsiderThreatSkill, IndicatorCategory, RiskLevel


@pytest.fixture
async def insider_skill():
    """Create and initialize an insider threat skill."""
    skill = InsiderThreatSkill(agent_id="gamma_blue_team", config={})
    await skill.initialize()
    return skill


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestInsiderThreatInit:
    @pytest.mark.asyncio
    async def test_initialize(self, insider_skill):
        assert insider_skill.initialized
        assert insider_skill.SKILL_NAME == "insider_threat"

    @pytest.mark.asyncio
    async def test_not_initialized_returns_error(self):
        skill = InsiderThreatSkill(agent_id="test", config={})
        result = await skill.execute({"action": "analyze_behavior"})
        assert not result.success
        assert "not initialized" in result.errors[0]

    def test_metadata(self):
        skill = InsiderThreatSkill(agent_id="gamma_blue_team", config={})
        meta = skill.get_metadata()
        assert meta["skill_name"] == "insider_threat"
        assert "gamma_blue_team" in meta["compatible_agents"]


# ---------------------------------------------------------------------------
# analyze_behavior
# ---------------------------------------------------------------------------


class TestAnalyzeBehavior:
    @pytest.mark.asyncio
    async def test_analyze_normal_behavior(self, insider_skill):
        result = await insider_skill.execute({
            "action": "analyze_behavior",
            "user_id": "user001",
            "events": [
                {"type": "login", "timestamp": "2026-03-10T09:00:00Z", "details": {"location": "office"}},
                {"type": "file_access", "timestamp": "2026-03-10T10:00:00Z", "details": {"file_count": 5}},
            ],
            "baseline": {
                "avg_login_hour": 9,
                "avg_file_access_count": 10,
            },
        })
        assert result.success
        assert "risk_score" in result.data or "indicators" in result.data

    @pytest.mark.asyncio
    async def test_analyze_suspicious_behavior(self, insider_skill):
        result = await insider_skill.execute({
            "action": "analyze_behavior",
            "user_id": "user002",
            "events": [
                {"type": "unusual_login_time", "timestamp": "2026-03-10T03:00:00Z", "details": {}},
                {"type": "large_download", "timestamp": "2026-03-10T03:15:00Z", "details": {"size_mb": 5000}},
                {"type": "usb_large_transfer", "timestamp": "2026-03-10T03:30:00Z", "details": {"size_mb": 3000}},
            ],
        })
        assert result.success
        assert result.data["risk_score"] > 0

    @pytest.mark.asyncio
    async def test_analyze_missing_user_id(self, insider_skill):
        result = await insider_skill.execute({
            "action": "analyze_behavior",
            "events": [{"type": "login"}],
        })
        assert not result.success
        assert "user_id" in result.errors[0].lower()

    @pytest.mark.asyncio
    async def test_analyze_with_hr_flags(self, insider_skill):
        result = await insider_skill.execute({
            "action": "analyze_behavior",
            "user_id": "user003",
            "events": [
                {"type": "login", "timestamp": "2026-03-10T09:00:00Z", "details": {}},
            ],
            "hr_flags": [
                {"type": "resignation_notice", "timestamp": "2026-03-01T00:00:00Z"},
                {"type": "denied_promotion_transfer", "timestamp": "2026-02-15T00:00:00Z"},
            ],
        })
        assert result.success
        # HR flags should increase risk score
        assert result.data["risk_score"] > 0

    @pytest.mark.asyncio
    async def test_analyze_empty_events(self, insider_skill):
        result = await insider_skill.execute({
            "action": "analyze_behavior",
            "user_id": "user004",
            "events": [],
        })
        assert result.success
        assert result.data["risk_score"] == 0 or "indicators" in result.data


# ---------------------------------------------------------------------------
# detect_anomalies
# ---------------------------------------------------------------------------


class TestDetectAnomalies:
    @pytest.mark.asyncio
    async def test_detect_anomalies(self, insider_skill):
        result = await insider_skill.execute({
            "action": "detect_anomalies",
            "user_activities": {
                "user010": {
                    "login_count": 50,
                    "file_access_count": 500,
                    "email_sent_count": 200,
                },
            },
        })
        assert result.success
        assert "anomalies" in result.data
        assert result.data["total_anomalies"] >= 0

    @pytest.mark.asyncio
    async def test_detect_no_anomalies(self, insider_skill):
        # First create a baseline via analyze_behavior
        await insider_skill.execute({
            "action": "analyze_behavior",
            "user_id": "user011",
            "events": [{"type": "login", "timestamp": "2026-03-10T09:00:00Z", "details": {}}],
        })
        result = await insider_skill.execute({
            "action": "detect_anomalies",
            "user_activities": {
                "user011": {"login_count": 1},
            },
        })
        assert result.success


# ---------------------------------------------------------------------------
# assess_risk
# ---------------------------------------------------------------------------


class TestAssessRisk:
    @pytest.mark.asyncio
    async def test_assess_risk(self, insider_skill):
        # First generate some behavior data
        await insider_skill.execute({
            "action": "analyze_behavior",
            "user_id": "user020",
            "events": [
                {"type": "privilege_escalation_attempt", "timestamp": "2026-03-10T10:00:00Z", "details": {}},
                {"type": "large_download", "timestamp": "2026-03-10T10:05:00Z", "details": {"size_mb": 10000}},
            ],
        })
        result = await insider_skill.execute({
            "action": "assess_risk",
            "user_id": "user020",
        })
        assert result.success
        assert "risk_level" in result.data
        assert result.data["risk_level"] in ("critical", "high", "medium", "low", "baseline")

    @pytest.mark.asyncio
    async def test_assess_risk_unknown_user(self, insider_skill):
        result = await insider_skill.execute({
            "action": "assess_risk",
            "user_id": "unknown_user",
        })
        # Should fail since no profile exists
        assert not result.success


# ---------------------------------------------------------------------------
# create_watchlist
# ---------------------------------------------------------------------------


class TestCreateWatchlist:
    @pytest.mark.asyncio
    async def test_add_to_watchlist(self, insider_skill):
        result = await insider_skill.execute({
            "action": "create_watchlist",
            "user_id": "user030",
            "reason": "departing_employee",
            "notes": "Last day is March 31",
        })
        assert result.success
        assert "user030" in insider_skill.watchlist

    @pytest.mark.asyncio
    async def test_watchlist_duplicate(self, insider_skill):
        await insider_skill.execute({
            "action": "create_watchlist",
            "user_id": "user031",
            "reason": "hr_flag",
        })
        result = await insider_skill.execute({
            "action": "create_watchlist",
            "user_id": "user031",
            "reason": "investigation",
        })
        # Should update or indicate already on watchlist
        assert result.success

    @pytest.mark.asyncio
    async def test_watchlist_missing_user_id(self, insider_skill):
        result = await insider_skill.execute({
            "action": "create_watchlist",
            "reason": "hr_flag",
        })
        assert not result.success or "user_id" in str(result.errors).lower()


# ---------------------------------------------------------------------------
# get_alerts
# ---------------------------------------------------------------------------


class TestGetAlerts:
    @pytest.mark.asyncio
    async def test_get_alerts_empty(self, insider_skill):
        result = await insider_skill.execute({"action": "get_alerts"})
        assert result.success
        assert result.data["total_alerts"] == 0

    @pytest.mark.asyncio
    async def test_get_alerts_after_suspicious_activity(self, insider_skill):
        await insider_skill.execute({
            "action": "analyze_behavior",
            "user_id": "user040",
            "events": [
                {"type": "security_control_bypass", "timestamp": "2026-03-10T02:00:00Z", "details": {}},
                {"type": "large_download", "timestamp": "2026-03-10T02:05:00Z", "details": {"size_mb": 50000}},
                {"type": "impossible_travel", "timestamp": "2026-03-10T02:10:00Z", "details": {}},
            ],
        })
        result = await insider_skill.execute({"action": "get_alerts"})
        assert result.success


# ---------------------------------------------------------------------------
# investigate_user
# ---------------------------------------------------------------------------


class TestInvestigateUser:
    @pytest.mark.asyncio
    async def test_investigate_user(self, insider_skill):
        await insider_skill.execute({
            "action": "analyze_behavior",
            "user_id": "user050",
            "events": [
                {"type": "permission_change_self", "timestamp": "2026-03-10T10:00:00Z", "details": {}},
            ],
        })
        result = await insider_skill.execute({
            "action": "investigate_user",
            "user_id": "user050",
            "reason": "Elevated risk score",
        })
        assert result.success
        assert "investigation" in result.data
        assert "investigation_id" in result.data["investigation"]

    @pytest.mark.asyncio
    async def test_investigate_unknown_user(self, insider_skill):
        result = await insider_skill.execute({
            "action": "investigate_user",
            "user_id": "ghost_user",
            "reason": "test",
        })
        assert result.success  # Should create investigation regardless


# ---------------------------------------------------------------------------
# generate_report
# ---------------------------------------------------------------------------


class TestInsiderReport:
    @pytest.mark.asyncio
    async def test_generate_report(self, insider_skill):
        await insider_skill.execute({
            "action": "analyze_behavior",
            "user_id": "user060",
            "events": [
                {"type": "large_download", "timestamp": "2026-03-10T10:00:00Z", "details": {}},
            ],
        })
        result = await insider_skill.execute({"action": "generate_report"})
        assert result.success
        assert "report" in result.data

    @pytest.mark.asyncio
    async def test_generate_report_empty(self, insider_skill):
        result = await insider_skill.execute({"action": "generate_report"})
        assert result.success
        assert "report" in result.data


# ---------------------------------------------------------------------------
# Unknown Action
# ---------------------------------------------------------------------------


class TestInsiderUnknownAction:
    @pytest.mark.asyncio
    async def test_unknown_action(self, insider_skill):
        result = await insider_skill.execute({"action": "nonexistent"})
        assert not result.success
        assert "Unknown action" in result.errors[0]
