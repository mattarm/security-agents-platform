#!/usr/bin/env python3
"""Tests for LangGraph tool wrappers."""

import pytest

from security_agents.core.agent_tools import (
    ALPHA4_TOOLS, BETA4_TOOLS, GAMMA_TOOLS, DELTA_TOOLS, SIGMA_TOOLS,
    AGENT_TOOLS,
)


class TestToolRegistry:
    def test_alpha4_tools_count(self):
        assert len(ALPHA4_TOOLS) == 3

    def test_beta4_tools_count(self):
        assert len(BETA4_TOOLS) == 5

    def test_gamma_tools_count(self):
        assert len(GAMMA_TOOLS) == 5

    def test_delta_tools_count(self):
        assert len(DELTA_TOOLS) == 5

    def test_sigma_tools_count(self):
        assert len(SIGMA_TOOLS) == 4

    def test_agent_tools_dict(self):
        assert len(AGENT_TOOLS) == 6
        assert "alpha_4_threat_intel" in AGENT_TOOLS
        assert "sigma_metrics" in AGENT_TOOLS
        assert "zeta_grc" in AGENT_TOOLS

    def test_all_tools_have_names(self):
        for agent_id, tools in AGENT_TOOLS.items():
            for tool in tools:
                assert hasattr(tool, "name"), f"Tool in {agent_id} missing name"
                assert tool.name, f"Tool in {agent_id} has empty name"

    def test_all_tools_have_descriptions(self):
        for agent_id, tools in AGENT_TOOLS.items():
            for tool in tools:
                assert hasattr(tool, "description"), f"{tool.name} missing description"
                assert len(tool.description) > 20, f"{tool.name} description too short"

    def test_tool_names_unique_per_agent(self):
        for agent_id, tools in AGENT_TOOLS.items():
            names = [t.name for t in tools]
            assert len(names) == len(set(names)), f"Duplicate tool names in {agent_id}"
