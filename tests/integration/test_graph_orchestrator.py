#!/usr/bin/env python3
"""Integration tests for the LangGraph orchestrator — end-to-end with mocked LLM."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from langchain_core.messages import AIMessage

from security_agents.core.graph_orchestrator import (
    intake_node,
    _deterministic_routing,
    fusion_node,
    autonomy_gate_node,
    build_orchestrator_graph,
)
from security_agents.core.schemas import OrchestratorState


def _make_state(**overrides) -> dict:
    """Create a minimal valid state."""
    base = {
        "messages": [],
        "request": {
            "analysis_type": "comprehensive",
            "target": "192.168.1.1 example.com",
            "priority": "high",
            "parameters": {},
        },
        "agent_results": [],
        "intelligence_packets": [],
        "fusion_results": {},
        "autonomy_tier": 0,
        "human_feedback": None,
        "current_phase": "submitted",
    }
    base.update(overrides)
    return base


class TestIntakeNode:
    def test_extracts_iocs(self):
        state = _make_state()
        result = intake_node(state)
        iocs = result["request"]["extracted_iocs"]
        assert "192.168.1.1" in iocs
        assert any("example.com" in ioc for ioc in iocs)

    def test_sets_phase(self):
        state = _make_state()
        result = intake_node(state)
        assert result["current_phase"] == "intake_complete"

    def test_generates_request_id(self):
        state = _make_state()
        result = intake_node(state)
        assert "request_id" in result["request"]

    def test_adds_message(self):
        state = _make_state()
        result = intake_node(state)
        assert len(result["messages"]) == 1


class TestDeterministicRouting:
    def test_comprehensive(self):
        result = _deterministic_routing({"analysis_type": "comprehensive"})
        assert len(result["agents"]) == 6
        assert "zeta_grc" in result["agents"]

    def test_threat_focused(self):
        result = _deterministic_routing({"analysis_type": "threat_focused"})
        assert "alpha_4_threat_intel" in result["agents"]

    def test_vulnerability_focused(self):
        result = _deterministic_routing({"analysis_type": "vulnerability_focused"})
        assert "beta_4_devsecops" in result["agents"]

    def test_incident_response(self):
        result = _deterministic_routing({"analysis_type": "incident_response"})
        assert "gamma_blue_team" in result["agents"]

    def test_grc(self):
        result = _deterministic_routing({"analysis_type": "grc"})
        assert "zeta_grc" in result["agents"]

    def test_unknown_type_fallback(self):
        result = _deterministic_routing({"analysis_type": "unknown_type"})
        assert "alpha_4_threat_intel" in result["agents"]


class TestFusionNode:
    @pytest.mark.asyncio
    async def test_aggregates_results(self):
        state = _make_state(
            agent_results=[
                {"findings": [{"type": "vuln"}]},
                {"findings": [{"type": "campaign"}, {"type": "ioc"}]},
            ],
        )
        result = await fusion_node(state)
        assert result["fusion_results"]["agent_count"] == 2
        assert result["fusion_results"]["total_findings"] == 3
        assert result["current_phase"] == "fusion_complete"


class TestAutonomyGate:
    def test_tier_0_passes(self):
        state = _make_state(autonomy_tier=0)
        result = autonomy_gate_node(state)
        assert result["current_phase"] == "approved"

    def test_tier_1_passes(self):
        state = _make_state(autonomy_tier=1)
        result = autonomy_gate_node(state)
        assert result["current_phase"] == "approved"

    def test_tier_2_requires_approval(self):
        state = _make_state(autonomy_tier=2)
        result = autonomy_gate_node(state)
        assert result["current_phase"] == "awaiting_approval"


class TestGraphStructure:
    def test_graph_builds(self):
        graph = build_orchestrator_graph()
        assert graph is not None

    def test_graph_compiles(self):
        graph = build_orchestrator_graph()
        compiled = graph.compile()
        assert compiled is not None

    def test_graph_has_expected_nodes(self):
        graph = build_orchestrator_graph()
        node_names = set(graph.nodes.keys())
        assert "intake" in node_names
        assert "router" in node_names
        assert "fusion" in node_names
        assert "synthesis" in node_names
        assert "agent_alpha_4_threat_intel" in node_names
        assert "agent_zeta_grc" in node_names
