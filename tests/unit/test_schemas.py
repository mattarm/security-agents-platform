#!/usr/bin/env python3
"""Tests for Pydantic v2 schemas and LangGraph state."""

import pytest

from security_agents.core.schemas import (
    AgentResult,
    RouterDecision,
    SynthesisResult,
    OrchestratorState,
)


class TestAgentResult:
    def test_defaults(self):
        result = AgentResult(agent_id="alpha_4", agent_name="Alpha-4")
        assert result.status == "completed"
        assert result.findings == []
        assert result.risk_delta == 0.0

    def test_with_findings(self):
        result = AgentResult(
            agent_id="gamma",
            agent_name="Gamma Blue Team",
            findings=[{"type": "incident", "severity": "high"}],
            recommended_next_agents=["delta_red_team"],
        )
        assert len(result.findings) == 1
        assert "delta_red_team" in result.recommended_next_agents

    def test_serialization_roundtrip(self):
        result = AgentResult(agent_id="beta_4", agent_name="Beta-4")
        data = result.model_dump()
        restored = AgentResult(**data)
        assert restored.agent_id == result.agent_id
        assert restored.status == result.status


class TestRouterDecision:
    def test_create(self):
        decision = RouterDecision(
            agents=["alpha_4_threat_intel", "gamma_blue_team"],
            rationale="Phishing with APT indicators",
        )
        assert len(decision.agents) == 2
        assert decision.execution_order == "parallel"

    def test_with_overrides(self):
        decision = RouterDecision(
            agents=["alpha_4_threat_intel"],
            rationale="Critical threat",
            priority_overrides={"alpha_4_threat_intel": "critical"},
        )
        assert decision.priority_overrides["alpha_4_threat_intel"] == "critical"


class TestSynthesisResult:
    def test_create(self):
        result = SynthesisResult(
            executive_summary="Critical vulnerabilities found",
            risk_score=78.5,
            recommendations=["Patch CVE-2024-1234", "Rotate credentials"],
        )
        assert result.risk_score == 78.5
        assert len(result.recommendations) == 2

    def test_risk_score_bounds(self):
        with pytest.raises(Exception):
            SynthesisResult(
                executive_summary="x", risk_score=101.0, recommendations=[]
            )

        with pytest.raises(Exception):
            SynthesisResult(
                executive_summary="x", risk_score=-1.0, recommendations=[]
            )

    def test_optional_compliance_impact(self):
        result = SynthesisResult(
            executive_summary="No issues",
            risk_score=5.0,
            compliance_impact={"nist_csf_2_0": {"score_change": -2.0}},
        )
        assert result.compliance_impact is not None


class TestOrchestratorState:
    def test_is_typed_dict(self):
        """OrchestratorState should be a TypedDict with expected keys."""
        annotations = OrchestratorState.__annotations__
        assert "messages" in annotations
        assert "request" in annotations
        assert "agent_results" in annotations
        assert "intelligence_packets" in annotations
        assert "fusion_results" in annotations
        assert "autonomy_tier" in annotations
        assert "human_feedback" in annotations
        assert "current_phase" in annotations
