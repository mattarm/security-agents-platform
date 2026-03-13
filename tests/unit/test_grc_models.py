#!/usr/bin/env python3
"""Tests for GRC data models."""

import pytest
from datetime import datetime

from security_agents.core.grc_models import (
    Control, Framework, CrossMapping, ControlAssessment, Gap, CompliancePosture,
    DetectionMapping, TechniqueGap, CoverageMatrix,
    SoAEntry, StatementOfApplicability,
    AISystemRecord, ImpactAssessment, DataGovernance,
    RiskRegisterEntry, RiskTreatmentPlan,
    ComplianceEvidence, AuditPackage,
    ControlStatus, ImplementationStatus, RiskLevel, RiskTreatment,
    RelationshipType, EvidenceType, AIRiskLevel, AILifecycleStage, HumanOversightType,
)


class TestEnumerations:
    def test_control_status_values(self):
        assert ControlStatus.COMPLIANT == "compliant"
        assert ControlStatus.NON_COMPLIANT == "non_compliant"

    def test_risk_level_values(self):
        assert RiskLevel.CRITICAL == "critical"
        assert RiskLevel.NEGLIGIBLE == "negligible"

    def test_ai_risk_level_values(self):
        assert AIRiskLevel.UNACCEPTABLE == "unacceptable"
        assert AIRiskLevel.MINIMAL == "minimal"


class TestFrameworkModels:
    def test_control_creation(self):
        control = Control(
            id="A.5.1", framework_id="iso_27001", title="Policies",
            description="Information security policy",
        )
        assert control.id == "A.5.1"
        assert control.automation_level == "manual"

    def test_framework_creation(self):
        framework = Framework(
            id="test_fw", name="Test Framework", version="1.0",
            controls=[
                Control(id="C1", framework_id="test_fw", title="Control 1"),
            ],
        )
        assert len(framework.controls) == 1
        assert framework.structure_type == "hierarchical"

    def test_cross_mapping(self):
        mapping = CrossMapping(
            source_control="ID.AM-01",
            source_framework="nist_csf_2_0",
            target_framework="iso_27001_2022",
            target_controls=["A.5.9"],
            relationship=RelationshipType.EQUIVALENT,
            confidence=90.0,
        )
        assert mapping.relationship == RelationshipType.EQUIVALENT
        assert len(mapping.target_controls) == 1


class TestAssessmentModels:
    def test_control_assessment(self):
        assessment = ControlAssessment(
            control_id="A.5.1", framework_id="iso_27001_2022",
            status=ControlStatus.COMPLIANT,
        )
        assert assessment.assessor == "zeta_grc"

    def test_gap(self):
        gap = Gap(
            control_id="PR.AA-01", framework_id="nist_csf_2_0",
            severity=RiskLevel.HIGH, risk_score=75.0,
            remediation="Implement MFA",
        )
        assert gap.risk_score == 75.0

    def test_compliance_posture(self):
        posture = CompliancePosture(
            framework_id="nist_csf_2_0", framework_name="NIST CSF 2.0",
            overall_score=72.5,
            function_scores={"GV": 80.0, "ID": 65.0},
        )
        assert posture.overall_score == 72.5
        assert len(posture.function_scores) == 2


class TestMITREModels:
    def test_detection_mapping(self):
        mapping = DetectionMapping(
            rule_id="SIEM-001", rule_name="Brute Force Detection",
            techniques_covered=["T1110"],
            confidence=85.0,
        )
        assert "T1110" in mapping.techniques_covered

    def test_technique_gap(self):
        gap = TechniqueGap(
            technique_id="T1566", name="Phishing",
            tactic="Initial Access", priority_score=90.0,
        )
        assert gap.priority_score == 90.0

    def test_coverage_matrix(self):
        matrix = CoverageMatrix(
            tactic_coverage={"Initial Access": 60.0, "Execution": 40.0},
            overall_coverage=50.0,
        )
        assert matrix.overall_coverage == 50.0


class TestISO27001Models:
    def test_soa_entry(self):
        entry = SoAEntry(
            control_id="A.5.1", control_title="Policies",
            applicable=True, justification="In scope",
            implementation_status=ImplementationStatus.FULLY_IMPLEMENTED,
        )
        assert entry.applicable is True

    def test_statement_of_applicability(self):
        soa = StatementOfApplicability(
            scope="full", total_controls=93,
            applicable_count=90, implemented_count=45,
        )
        assert soa.total_controls == 93


class TestISO42001Models:
    def test_ai_system_record(self):
        record = AISystemRecord(
            system_id="alpha_4", name="Alpha-4 Agent",
            purpose="Threat intelligence",
            risk_level=AIRiskLevel.LIMITED,
        )
        assert record.lifecycle_stage == AILifecycleStage.OPERATION

    def test_impact_assessment(self):
        assessment = ImpactAssessment(
            system_id="alpha_4",
            affected_parties=["security_team"],
            residual_risk=RiskLevel.LOW,
        )
        assert assessment.residual_risk == RiskLevel.LOW

    def test_data_governance(self):
        gov = DataGovernance(
            system_id="alpha_4",
            data_sources=["CrowdStrike", "Okta"],
        )
        assert len(gov.data_sources) == 2


class TestRiskModels:
    def test_risk_register_entry(self):
        entry = RiskRegisterEntry(
            risk_id="RISK-001", description="Unpatched servers",
            likelihood=4, impact=5, inherent_risk=20.0,
            treatment=RiskTreatment.MITIGATE,
        )
        assert entry.inherent_risk == 20.0
        assert entry.treatment == RiskTreatment.MITIGATE

    def test_risk_treatment_plan(self):
        plan = RiskTreatmentPlan(
            risk_id="RISK-001",
            actions=["Implement patching schedule"],
            timeline="2 weeks",
        )
        assert plan.status == "planned"

    def test_risk_bounds(self):
        with pytest.raises(Exception):
            RiskRegisterEntry(risk_id="X", description="Y", likelihood=0)
        with pytest.raises(Exception):
            RiskRegisterEntry(risk_id="X", description="Y", likelihood=6)


class TestEvidenceModels:
    def test_compliance_evidence(self):
        evidence = ComplianceEvidence(
            id="EVD-001", type=EvidenceType.SCAN_RESULT,
            source="CrowdStrike",
            control_ids=["A.8.7"],
        )
        assert evidence.type == EvidenceType.SCAN_RESULT

    def test_audit_package(self):
        package = AuditPackage(
            framework_id="nist_csf_2_0",
            framework_name="NIST CSF 2.0",
            scope="full",
        )
        assert package.generated_by == "zeta_grc"


class TestSerialization:
    def test_roundtrip(self):
        entry = RiskRegisterEntry(
            risk_id="R-1", description="Test", likelihood=3, impact=3,
        )
        data = entry.model_dump()
        restored = RiskRegisterEntry(**data)
        assert restored.risk_id == entry.risk_id
        assert restored.inherent_risk == entry.inherent_risk
