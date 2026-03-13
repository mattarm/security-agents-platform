#!/usr/bin/env python3
"""Tests for system prompts — verify they load and contain required sections."""

import pytest

from security_agents.core.prompts import (
    ALPHA4_SYSTEM_PROMPT,
    BETA4_SYSTEM_PROMPT,
    GAMMA_SYSTEM_PROMPT,
    DELTA_SYSTEM_PROMPT,
    SIGMA_SYSTEM_PROMPT,
    ZETA_SYSTEM_PROMPT,
    ROUTER_SYSTEM_PROMPT,
    SYNTHESIS_SYSTEM_PROMPT,
    AGENT_PROMPTS,
)


class TestPromptLoading:
    def test_all_prompts_non_empty(self):
        for name, prompt in [
            ("alpha4", ALPHA4_SYSTEM_PROMPT),
            ("beta4", BETA4_SYSTEM_PROMPT),
            ("gamma", GAMMA_SYSTEM_PROMPT),
            ("delta", DELTA_SYSTEM_PROMPT),
            ("sigma", SIGMA_SYSTEM_PROMPT),
            ("zeta", ZETA_SYSTEM_PROMPT),
            ("router", ROUTER_SYSTEM_PROMPT),
            ("synthesis", SYNTHESIS_SYSTEM_PROMPT),
        ]:
            assert len(prompt) > 100, f"{name} prompt is too short"

    def test_agent_prompts_dict(self):
        assert len(AGENT_PROMPTS) == 6
        assert "alpha_4_threat_intel" in AGENT_PROMPTS
        assert "zeta_grc" in AGENT_PROMPTS


class TestPromptContent:
    @pytest.mark.parametrize("prompt,required_sections", [
        (ALPHA4_SYSTEM_PROMPT, ["Mandate", "Available Tools", "Escalation Thresholds", "Output Format"]),
        (BETA4_SYSTEM_PROMPT, ["Mandate", "Available Tools", "Escalation Thresholds", "Output Format"]),
        (GAMMA_SYSTEM_PROMPT, ["Mandate", "Available Tools", "Escalation Thresholds", "Output Format"]),
        (DELTA_SYSTEM_PROMPT, ["Mandate", "Available Tools", "Escalation Thresholds", "Output Format"]),
        (SIGMA_SYSTEM_PROMPT, ["Mandate", "Available Tools", "Escalation Thresholds", "Output Format"]),
        (ZETA_SYSTEM_PROMPT, ["Mandate", "Available Tools", "Escalation Thresholds", "Output Format"]),
    ])
    def test_agent_prompt_sections(self, prompt, required_sections):
        for section in required_sections:
            assert section in prompt, f"Missing section: {section}"

    def test_agent_prompts_mention_cross_collaboration(self):
        for agent_id, prompt in AGENT_PROMPTS.items():
            assert "Cross-Agent" in prompt, f"{agent_id} missing cross-agent collaboration section"

    def test_router_mentions_all_agents(self):
        for agent_id in [
            "alpha_4_threat_intel", "beta_4_devsecops", "gamma_blue_team",
            "delta_red_team", "sigma_metrics", "zeta_grc",
        ]:
            assert agent_id in ROUTER_SYSTEM_PROMPT, f"Router missing agent: {agent_id}"

    def test_synthesis_mentions_risk_score(self):
        assert "risk_score" in SYNTHESIS_SYSTEM_PROMPT.lower() or "Risk Score" in SYNTHESIS_SYSTEM_PROMPT

    def test_zeta_mentions_frameworks(self):
        for framework in ["NIST CSF", "ISO 27001", "ISO 42001", "MITRE ATT&CK", "ISO 31000"]:
            assert framework in ZETA_SYSTEM_PROMPT, f"Zeta prompt missing framework: {framework}"
