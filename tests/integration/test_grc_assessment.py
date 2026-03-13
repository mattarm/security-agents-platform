#!/usr/bin/env python3
"""Integration tests for full GRC assessment flow."""

import pytest

from security_agents.agents.engines.zeta_grc_engine import ZetaGRCEngine
from security_agents.core.grc_models import ControlStatus, RiskLevel


class TestFullAssessmentFlow:
    @pytest.fixture
    def engine(self):
        return ZetaGRCEngine()

    @pytest.mark.asyncio
    async def test_nist_assessment_end_to_end(self, engine):
        """Full NIST CSF 2.0 assessment → gap analysis → evidence → audit package."""
        # 1. Assess compliance
        posture = await engine.assess_compliance("nist_csf_2_0")
        assert 0.0 <= posture.overall_score <= 100.0
        assert len(posture.control_statuses) > 0

        # 2. Analyze gaps
        gaps = await engine.analyze_gaps("nist_csf_2_0", posture)
        assert isinstance(gaps, list)

        # 3. Collect evidence for gap controls
        if gaps:
            gap_controls = [g.control_id for g in gaps[:5]]
            evidence = await engine.collect_evidence(gap_controls)
            assert len(evidence) > 0

        # 4. Generate audit package
        package = await engine.generate_audit_package("nist_csf_2_0")
        assert package.framework_id == "nist_csf_2_0"
        assert package.posture is not None
        assert len(package.evidence) > 0

    @pytest.mark.asyncio
    async def test_iso27001_soa_flow(self, engine):
        """ISO 27001 assessment → SoA generation."""
        posture = await engine.assess_compliance("iso_27001_2022")
        assert len(posture.control_statuses) == 93

        soa = await engine.generate_soa()
        assert soa.total_controls == 93
        assert soa.applicable_count > 0

    @pytest.mark.asyncio
    async def test_cross_framework_analysis(self, engine):
        """Assess NIST CSF → cross-map gaps to ISO 27001."""
        posture = await engine.assess_compliance("nist_csf_2_0")
        gaps = await engine.analyze_gaps("nist_csf_2_0", posture)

        if gaps:
            mappings = await engine.map_controls(
                "nist_csf_2_0", "iso_27001_2022",
                [g.control_id for g in gaps[:5]],
            )
            assert isinstance(mappings, list)

    @pytest.mark.asyncio
    async def test_mitre_coverage_assessment(self, engine):
        """Assess MITRE coverage with sample detection rules."""
        rules = [
            {"id": "SIEM-001", "name": "Brute Force", "techniques": ["T1110"], "confidence": 85.0},
            {"id": "SIEM-002", "name": "Phishing", "techniques": ["T1566"], "confidence": 90.0},
        ]
        matrix = await engine.assess_mitre_coverage(rules)
        assert matrix.overall_coverage > 0.0
        assert len(matrix.priority_gaps) > 0
        # The two covered techniques should reduce gaps
        assert "T1110" not in [g.technique_id for g in matrix.priority_gaps]

    @pytest.mark.asyncio
    async def test_risk_register_workflow(self, engine):
        """Add risk → list → remove."""
        # Add
        result = await engine.manage_risk_register("team_a", "add", {
            "description": "Unpatched CVE-2024-1234",
            "likelihood": 4, "impact": 5,
            "controls": ["WAF", "IPS"],
        })
        assert result["action"] == "added"
        risk_id = result["risk"]["risk_id"]

        # List
        register = await engine.manage_risk_register("team_a", "list")
        assert len(register["entries"]) == 1
        assert register["entries"][0]["residual_risk"] < 20.0  # Controls reduce risk

        # Remove
        await engine.manage_risk_register("team_a", "remove", {"risk_id": risk_id})
        register = await engine.manage_risk_register("team_a", "list")
        assert len(register["entries"]) == 0

    @pytest.mark.asyncio
    async def test_ai_system_assessment(self, engine):
        """ISO 42001 assessment of platform agent."""
        result = await engine.assess_ai_system("alpha_4_threat_intel")
        assert result["system"]["system_id"] == "alpha_4_threat_intel"
        assert "impact_assessment" in result
        assert "data_governance" in result
        assert result["compliance_score"] > 0
