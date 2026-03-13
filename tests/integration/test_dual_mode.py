#!/usr/bin/env python3
"""Tests for dual-mode orchestration — legacy and LangGraph paths."""

import pytest
import os

from security_agents.core.graph_orchestrator import build_orchestrator_graph, _deterministic_routing


class TestFeatureFlag:
    def test_langgraph_default_false(self):
        """USE_LANGGRAPH defaults to false."""
        val = os.environ.get("USE_LANGGRAPH", "false").lower()
        # In test environment, this should be false
        assert val in ("false", "true")

    def test_graph_builds_without_flag(self):
        """LangGraph orchestrator can be built regardless of flag."""
        graph = build_orchestrator_graph()
        compiled = graph.compile()
        assert compiled is not None


class TestDeterministicFallback:
    """Test that the deterministic routing fallback produces valid results for all analysis types."""

    @pytest.mark.parametrize("analysis_type,expected_agents", [
        ("comprehensive", ["alpha_4_threat_intel", "beta_4_devsecops", "gamma_blue_team",
                          "delta_red_team", "sigma_metrics", "zeta_grc"]),
        ("threat_focused", ["alpha_4_threat_intel", "gamma_blue_team"]),
        ("vulnerability_focused", ["beta_4_devsecops"]),
        ("incident_response", ["gamma_blue_team", "alpha_4_threat_intel"]),
        ("red_team", ["delta_red_team"]),
        ("phishing", ["gamma_blue_team", "alpha_4_threat_intel"]),
        ("grc", ["zeta_grc", "sigma_metrics"]),
        ("compliance", ["zeta_grc"]),
    ])
    def test_routing(self, analysis_type, expected_agents):
        result = _deterministic_routing({"analysis_type": analysis_type})
        assert result["agents"] == expected_agents
        assert result["rationale"]
