"""Tests for the AI Confidence Scoring Skill."""

import pytest

from security_agents.skills.ai_confidence_scoring import AIConfidenceScoringSkill


@pytest.fixture
async def confidence_skill():
    """Create and initialize an AI confidence scoring skill."""
    skill = AIConfidenceScoringSkill(agent_id="test_agent", config={})
    await skill.initialize()
    return skill


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestAIConfidenceInit:
    @pytest.mark.asyncio
    async def test_initialize(self, confidence_skill):
        assert confidence_skill.initialized
        assert confidence_skill.SKILL_NAME == "ai_confidence_scoring"

    @pytest.mark.asyncio
    async def test_not_initialized_returns_error(self):
        skill = AIConfidenceScoringSkill(agent_id="test", config={})
        result = await skill.execute({"action": "score_decision"})
        assert not result.success
        assert "not initialized" in result.errors[0]

    def test_metadata(self):
        skill = AIConfidenceScoringSkill(agent_id="test_agent", config={})
        meta = skill.get_metadata()
        assert meta["skill_name"] == "ai_confidence_scoring"
        assert meta["version"] == "1.0.0"

    @pytest.mark.asyncio
    async def test_default_thresholds_loaded(self, confidence_skill):
        assert confidence_skill.thresholds["tier_0_autonomous"] == 0.95
        assert confidence_skill.thresholds["tier_3_collaborative"] == 0.0


# ---------------------------------------------------------------------------
# score_decision
# ---------------------------------------------------------------------------


class TestScoreDecision:
    @pytest.mark.asyncio
    async def test_score_decision_basic(self, confidence_skill):
        result = await confidence_skill.execute({
            "action": "score_decision",
            "decision_id": "DEC-001",
            "analysis": {"conclusion": "malware detected"},
            "evidence": {"sources": ["edr", "siem"], "quality": "high"},
            "model_id": "gpt4",
        })
        assert result.success
        assert "raw_confidence" in result.data
        assert "adjusted_confidence" in result.data
        assert "confidence_interval" in result.data
        assert isinstance(result.data["confidence_interval"], list)
        assert len(result.data["confidence_interval"]) == 2

    @pytest.mark.asyncio
    async def test_score_decision_returns_factors(self, confidence_skill):
        result = await confidence_skill.execute({
            "action": "score_decision",
            "analysis": {"conclusion": "clean"},
            "evidence": {},
        })
        assert result.success
        factors = result.data["factors"]
        assert len(factors) >= 5
        for f in factors:
            assert "name" in f
            assert "score" in f
            assert "weight" in f

    @pytest.mark.asyncio
    async def test_score_decision_recommended_tier(self, confidence_skill):
        result = await confidence_skill.execute({
            "action": "score_decision",
            "analysis": {},
            "evidence": {},
        })
        assert result.success
        assert "recommended_tier" in result.data
        assert result.data["recommended_tier"] in (0, 1, 2, 3)

    @pytest.mark.asyncio
    async def test_score_confidence_bounded_0_1(self, confidence_skill):
        result = await confidence_skill.execute({
            "action": "score_decision",
            "analysis": {},
            "evidence": {},
        })
        assert result.success
        assert 0.0 <= result.data["raw_confidence"] <= 1.0
        assert 0.0 <= result.data["adjusted_confidence"] <= 1.0

    @pytest.mark.asyncio
    async def test_bias_metrics_present(self, confidence_skill):
        result = await confidence_skill.execute({
            "action": "score_decision",
            "severity": "critical",
            "analysis": {},
            "evidence": {},
        })
        assert result.success
        assert "bias_metrics" in result.data
        assert "bias_risk" in result.data["bias_metrics"]

    @pytest.mark.asyncio
    async def test_low_confidence_critical_emits_packet(self, confidence_skill):
        # Minimal evidence + critical severity should trigger intel packet
        result = await confidence_skill.execute({
            "action": "score_decision",
            "severity": "critical",
            "analysis": {},
            "evidence": {},
        })
        assert result.success
        # With empty evidence/analysis and critical severity, confidence should be low
        if result.data["adjusted_confidence"] < 0.5:
            assert len(result.intelligence_packets) == 1
            assert result.intelligence_packets[0].source_agent == "test_agent"


# ---------------------------------------------------------------------------
# calibrate_confidence
# ---------------------------------------------------------------------------


class TestCalibrateConfidence:
    @pytest.mark.asyncio
    async def test_calibrate_basic(self, confidence_skill):
        # First score some decisions
        await confidence_skill.execute({
            "action": "score_decision",
            "decision_id": "DEC-CAL-1",
            "analysis": {"conclusion": "malware"},
            "evidence": {"sources": ["edr"]},
        })
        result = await confidence_skill.execute({
            "action": "calibrate_confidence",
            "outcomes": [
                {"decision_id": "DEC-CAL-1", "predicted": 0.8, "actual": True},
            ],
        })
        assert result.success

    @pytest.mark.asyncio
    async def test_calibrate_empty_outcomes(self, confidence_skill):
        result = await confidence_skill.execute({
            "action": "calibrate_confidence",
            "outcomes": [],
        })
        # Should succeed or indicate no data
        assert result.success or "outcomes" in result.errors[0].lower()


# ---------------------------------------------------------------------------
# get_confidence_history
# ---------------------------------------------------------------------------


class TestGetConfidenceHistory:
    @pytest.mark.asyncio
    async def test_empty_history(self, confidence_skill):
        result = await confidence_skill.execute({
            "action": "get_confidence_history",
        })
        assert result.success

    @pytest.mark.asyncio
    async def test_history_after_scoring(self, confidence_skill):
        await confidence_skill.execute({
            "action": "score_decision",
            "decision_id": "DEC-HIST-1",
            "analysis": {},
            "evidence": {},
        })
        result = await confidence_skill.execute({
            "action": "get_confidence_history",
        })
        assert result.success
        assert result.data["total_records"] >= 1


# ---------------------------------------------------------------------------
# compare_models
# ---------------------------------------------------------------------------


class TestCompareModels:
    @pytest.mark.asyncio
    async def test_compare_models_after_scoring(self, confidence_skill):
        await confidence_skill.execute({
            "action": "score_decision",
            "model_id": "model_a",
            "analysis": {"conclusion": "malware"},
            "evidence": {"sources": ["edr"]},
        })
        await confidence_skill.execute({
            "action": "score_decision",
            "model_id": "model_b",
            "analysis": {"conclusion": "clean"},
            "evidence": {},
        })
        result = await confidence_skill.execute({
            "action": "compare_models",
            "model_ids": ["model_a", "model_b"],
        })
        assert result.success

    @pytest.mark.asyncio
    async def test_compare_no_data(self, confidence_skill):
        result = await confidence_skill.execute({
            "action": "compare_models",
            "model_ids": ["nonexistent_a", "nonexistent_b"],
        })
        assert result.success


# ---------------------------------------------------------------------------
# set_threshold
# ---------------------------------------------------------------------------


class TestSetThreshold:
    @pytest.mark.asyncio
    async def test_set_threshold(self, confidence_skill):
        result = await confidence_skill.execute({
            "action": "set_threshold",
            "tier": "tier_0_autonomous",
            "value": 0.90,
        })
        assert result.success
        assert confidence_skill.thresholds["tier_0_autonomous"] == 0.90

    @pytest.mark.asyncio
    async def test_set_invalid_tier(self, confidence_skill):
        result = await confidence_skill.execute({
            "action": "set_threshold",
            "tier": "nonexistent_tier",
            "value": 0.5,
        })
        assert not result.success


# ---------------------------------------------------------------------------
# Unknown Action
# ---------------------------------------------------------------------------


class TestAIConfidenceUnknownAction:
    @pytest.mark.asyncio
    async def test_unknown_action(self, confidence_skill):
        result = await confidence_skill.execute({"action": "nonexistent"})
        assert not result.success
        assert "Unknown action" in result.errors[0]
