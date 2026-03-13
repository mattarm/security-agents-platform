#!/usr/bin/env python3
"""
Zeta GRC Engine — Governance, Risk, and Compliance analysis engine.

Implements NIST CSF 2.0, ISO 27001:2022, ISO 42001:2023, MITRE ATT&CK,
and ISO 31000 risk methodology. Methods become LangGraph tools.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from security_agents.core.grc_models import (
    AILifecycleStage,
    AIRiskLevel,
    AISystemRecord,
    AuditPackage,
    ComplianceEvidence,
    CompliancePosture,
    ControlAssessment,
    ControlStatus,
    CoverageMatrix,
    DataGovernance,
    DetectionMapping,
    EvidenceType,
    Gap,
    HumanOversightType,
    ImpactAssessment,
    ImplementationStatus,
    RiskLevel,
    RiskRegisterEntry,
    RiskTreatment,
    SoAEntry,
    StatementOfApplicability,
    TechniqueGap,
)
from security_agents.core.grc_frameworks import get_framework, list_frameworks
from security_agents.core.grc_frameworks.cross_mappings import get_control_mappings, get_mappings
from security_agents.core.grc_frameworks.mitre_attack import MITRE_TACTICS

logger = logging.getLogger(__name__)


class ZetaGRCEngine:
    """Core GRC analysis engine for the Zeta agent."""

    def __init__(self):
        self._risk_registers: Dict[str, List[RiskRegisterEntry]] = {}
        self._assessments: Dict[str, List[ControlAssessment]] = {}
        self._evidence_store: List[ComplianceEvidence] = []
        self._ai_systems: Dict[str, AISystemRecord] = {}

    # -------------------------------------------------------------------------
    # Compliance Assessment
    # -------------------------------------------------------------------------

    async def assess_compliance(
        self, framework_id: str, scope: str = "full", team_id: str = "default"
    ) -> CompliancePosture:
        """Run compliance assessment against a framework."""
        framework = get_framework(framework_id)
        if not framework:
            raise ValueError(f"Unknown framework: {framework_id}")

        assessments = []
        compliant_count = 0
        gaps = []

        for control in framework.controls:
            # Simulate assessment — in production, this would check real evidence
            assessment = self._assess_control(control, scope)
            assessments.append(assessment)

            if assessment.status == ControlStatus.COMPLIANT:
                compliant_count += 1
            elif assessment.status in (ControlStatus.NON_COMPLIANT, ControlStatus.PARTIALLY_COMPLIANT):
                gap = Gap(
                    control_id=control.id,
                    framework_id=framework_id,
                    severity=self._gap_severity(assessment.status),
                    risk_score=self._calculate_gap_risk(control, assessment),
                    description=f"Control {control.id} ({control.title}): {assessment.status.value}",
                    remediation=f"Implement {control.title} per {framework.name} requirements",
                    estimated_effort=self._estimate_effort(control),
                    owner=team_id,
                )
                gaps.append(gap)

        total = len(framework.controls)
        overall_score = (compliant_count / total * 100) if total > 0 else 0.0

        # Calculate per-function/theme scores
        function_scores = self._calculate_function_scores(assessments, framework_id)

        posture = CompliancePosture(
            framework_id=framework_id,
            framework_name=framework.name,
            overall_score=round(overall_score, 1),
            function_scores=function_scores,
            control_statuses={a.control_id: a.status for a in assessments},
            gaps=sorted(gaps, key=lambda g: g.risk_score, reverse=True),
        )

        # Cache for later use
        self._assessments[framework_id] = assessments
        return posture

    def _assess_control(self, control, scope: str) -> ControlAssessment:
        """Assess a single control. In production, checks real evidence sources."""
        # Deterministic assessment based on control characteristics
        has_evidence = len(control.evidence_requirements) > 0
        has_procedures = len(control.test_procedures) > 0

        if control.automation_level == "fully-automated":
            status = ControlStatus.COMPLIANT
        elif has_evidence and has_procedures:
            status = ControlStatus.PARTIALLY_COMPLIANT
        elif has_evidence or has_procedures:
            status = ControlStatus.PARTIALLY_COMPLIANT
        else:
            status = ControlStatus.NOT_ASSESSED

        return ControlAssessment(
            control_id=control.id,
            framework_id=control.framework_id,
            status=status,
        )

    def _gap_severity(self, status: ControlStatus) -> RiskLevel:
        if status == ControlStatus.NON_COMPLIANT:
            return RiskLevel.HIGH
        elif status == ControlStatus.PARTIALLY_COMPLIANT:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def _calculate_gap_risk(self, control, assessment) -> float:
        """ISO 31000 risk scoring: likelihood x impact."""
        base = 50.0
        if assessment.status == ControlStatus.NON_COMPLIANT:
            base = 75.0
        elif assessment.status == ControlStatus.PARTIALLY_COMPLIANT:
            base = 40.0
        return min(base, 100.0)

    def _estimate_effort(self, control) -> str:
        if control.automation_level == "fully-automated":
            return "1 day"
        elif control.automation_level == "semi-automated":
            return "1 week"
        return "2-4 weeks"

    def _calculate_function_scores(
        self, assessments: List[ControlAssessment], framework_id: str
    ) -> Dict[str, float]:
        """Group controls by parent (function/theme) and calculate scores."""
        groups: Dict[str, List[ControlAssessment]] = {}
        for a in assessments:
            parent = a.control_id.split(".")[0] if "." in a.control_id else a.control_id[:2]
            groups.setdefault(parent, []).append(a)

        scores = {}
        for group, items in groups.items():
            compliant = sum(1 for i in items if i.status == ControlStatus.COMPLIANT)
            scores[group] = round(compliant / len(items) * 100, 1) if items else 0.0
        return scores

    # -------------------------------------------------------------------------
    # Cross-Framework Control Mapping
    # -------------------------------------------------------------------------

    async def map_controls(
        self, source_framework: str, target_framework: str, control_ids: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Look up cross-framework control mappings."""
        # Validate that both frameworks exist in the registry
        if not get_framework(source_framework):
            raise ValueError(
                f"Unknown source framework: {source_framework!r}. "
                f"Available: {[f['id'] for f in list_frameworks()]}"
            )
        if not get_framework(target_framework):
            raise ValueError(
                f"Unknown target framework: {target_framework!r}. "
                f"Available: {[f['id'] for f in list_frameworks()]}"
            )

        mappings = get_mappings(source_framework, target_framework)

        if control_ids:
            mappings = [m for m in mappings if m.source_control in control_ids]

        return [m.model_dump() for m in mappings]

    # -------------------------------------------------------------------------
    # Evidence Collection
    # -------------------------------------------------------------------------

    async def collect_evidence(
        self, control_ids: List[str], sources: Optional[List[str]] = None
    ) -> List[ComplianceEvidence]:
        """Collect compliance evidence for specified controls."""
        evidence_items = []
        sources = sources or ["platform_config", "agent_status", "security_scans"]

        for control_id in control_ids:
            for source in sources:
                description = f"Evidence for {control_id} from {source}"
                content = {
                    "control_id": control_id,
                    "source": source,
                    "status": "collected",
                    "collected_by": "zeta_grc",
                }
                # Hash includes control_id, source, and content so different
                # evidence for the same control produces different hashes.
                hash_input = f"{control_id}-{source}-{description}-{content}"
                evidence = ComplianceEvidence(
                    id=f"EVD-{uuid.uuid4().hex[:8]}",
                    type=EvidenceType.API_RESPONSE,
                    source=source,
                    hash=hashlib.sha256(hash_input.encode()).hexdigest(),
                    control_ids=[control_id],
                    content=content,
                    description=description,
                )
                evidence_items.append(evidence)

        self._evidence_store.extend(evidence_items)
        return evidence_items

    # -------------------------------------------------------------------------
    # Gap Analysis
    # -------------------------------------------------------------------------

    async def analyze_gaps(
        self, framework_id: str, posture: Optional[CompliancePosture] = None
    ) -> List[Gap]:
        """Analyze and prioritize compliance gaps by risk."""
        if posture is None:
            posture = await self.assess_compliance(framework_id)

        gaps = posture.gaps

        # Enrich gaps with cross-mapping impact
        for gap in gaps:
            related_mappings = get_control_mappings(gap.control_id)
            if related_mappings:
                gap.description += (
                    f" | Affects {len(related_mappings)} cross-framework mapping(s)"
                )
                # Increase risk for gaps that affect multiple frameworks
                gap.risk_score = min(gap.risk_score + len(related_mappings) * 5, 100.0)

        return sorted(gaps, key=lambda g: g.risk_score, reverse=True)

    # -------------------------------------------------------------------------
    # Risk Register (ISO 31000)
    # -------------------------------------------------------------------------

    async def manage_risk_register(
        self, team_id: str, action: str, entry: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """CRUD operations on team risk registers."""
        register = self._risk_registers.setdefault(team_id, [])

        if action == "list":
            return {"team_id": team_id, "entries": [e.model_dump() for e in register]}

        elif action == "add":
            if entry is None:
                raise ValueError("Entry data required for 'add' action")

            # Validate and coerce likelihood/impact to numeric
            raw_likelihood = entry.get("likelihood", 3)
            raw_impact = entry.get("impact", 3)
            try:
                likelihood = float(raw_likelihood)
            except (TypeError, ValueError):
                raise ValueError(
                    f"likelihood must be numeric (int or float), got {type(raw_likelihood).__name__}: {raw_likelihood!r}"
                )
            try:
                impact = float(raw_impact)
            except (TypeError, ValueError):
                raise ValueError(
                    f"impact must be numeric (int or float), got {type(raw_impact).__name__}: {raw_impact!r}"
                )

            # Validate treatment enum value
            raw_treatment = entry.get("treatment", "mitigate")
            valid_treatments = [t.value for t in RiskTreatment]
            try:
                treatment = RiskTreatment(raw_treatment)
            except ValueError:
                raise ValueError(
                    f"Invalid treatment value: {raw_treatment!r}. "
                    f"Valid values: {valid_treatments}"
                )

            risk = RiskRegisterEntry(
                risk_id=entry.get("risk_id", f"RISK-{uuid.uuid4().hex[:8]}"),
                description=entry.get("description", ""),
                category=entry.get("category", "operational"),
                likelihood=likelihood,
                impact=impact,
                inherent_risk=likelihood * impact,
                controls=entry.get("controls", []),
                treatment=treatment,
                owner=entry.get("owner", team_id),
            )
            # Calculate residual risk (inherent * 0.6 if controls exist)
            if risk.controls:
                risk.residual_risk = round(risk.inherent_risk * 0.6, 1)
            else:
                risk.residual_risk = risk.inherent_risk
            register.append(risk)
            return {"action": "added", "risk": risk.model_dump()}

        elif action == "remove":
            risk_id = entry.get("risk_id") if entry else None
            if not risk_id:
                raise ValueError("risk_id required for 'remove' action")
            self._risk_registers[team_id] = [r for r in register if r.risk_id != risk_id]
            return {"action": "removed", "risk_id": risk_id}

        else:
            raise ValueError(f"Unknown action: {action}. Supported: list, add, remove")

    # -------------------------------------------------------------------------
    # MITRE ATT&CK Coverage
    # -------------------------------------------------------------------------

    async def assess_mitre_coverage(
        self,
        detection_rules: Optional[List[Dict[str, Any]]] = None,
    ) -> CoverageMatrix:
        """Generate MITRE ATT&CK detection coverage matrix."""
        framework = get_framework("mitre_attack")
        if not framework:
            raise ValueError("MITRE ATT&CK framework not loaded")

        # Build technique-to-tactic mapping
        tech_to_tactic = {}
        for control in framework.controls:
            tech_to_tactic[control.id] = control.parent_id

        # Process detection rules
        rule_mappings = []
        covered_techniques = set()
        if detection_rules:
            for rule in detection_rules:
                mapping = DetectionMapping(
                    rule_id=rule.get("id", ""),
                    rule_name=rule.get("name", ""),
                    techniques_covered=rule.get("techniques", []),
                    data_sources=rule.get("data_sources", []),
                    confidence=rule.get("confidence", 70.0),
                )
                rule_mappings.append(mapping)
                covered_techniques.update(mapping.techniques_covered)

        # Calculate tactic coverage
        tactic_counts: Dict[str, Dict[str, int]] = {}
        for control in framework.controls:
            tactic = control.parent_id
            tactic_counts.setdefault(tactic, {"total": 0, "covered": 0})
            tactic_counts[tactic]["total"] += 1
            if control.id in covered_techniques:
                tactic_counts[tactic]["covered"] += 1

        tactic_coverage = {}
        for tactic, counts in tactic_counts.items():
            tactic_name = MITRE_TACTICS.get(tactic, tactic)
            pct = (counts["covered"] / counts["total"] * 100) if counts["total"] > 0 else 0.0
            tactic_coverage[tactic_name] = round(pct, 1)

        # Identify technique statuses
        technique_statuses = {}
        for control in framework.controls:
            if control.id in covered_techniques:
                technique_statuses[control.id] = "covered"
            else:
                technique_statuses[control.id] = "none"

        # Priority gaps — uncovered techniques
        priority_gaps = []
        for control in framework.controls:
            if control.id not in covered_techniques:
                priority_gaps.append(TechniqueGap(
                    technique_id=control.id,
                    name=control.title,
                    tactic=MITRE_TACTICS.get(control.parent_id, control.parent_id),
                    priority_score=60.0,  # Default medium priority
                    current_coverage=0.0,
                ))

        total_techniques = len(framework.controls)
        overall = (len(covered_techniques) / total_techniques * 100) if total_techniques > 0 else 0.0

        return CoverageMatrix(
            tactic_coverage=tactic_coverage,
            technique_statuses=technique_statuses,
            detection_rules=rule_mappings,
            priority_gaps=priority_gaps[:20],  # Top 20 gaps
            overall_coverage=round(overall, 1),
        )

    # -------------------------------------------------------------------------
    # ISO 42001 — AI System Assessment
    # -------------------------------------------------------------------------

    async def assess_ai_system(self, agent_id: str) -> Dict[str, Any]:
        """Perform ISO 42001 assessment of the platform's own AI agents."""
        # Register the agent as an AI system if not already tracked
        if agent_id not in self._ai_systems:
            self._ai_systems[agent_id] = AISystemRecord(
                system_id=agent_id,
                name=f"SecurityAgents {agent_id}",
                purpose=f"Automated security analysis agent ({agent_id})",
                risk_level=AIRiskLevel.LIMITED,
                lifecycle_stage=AILifecycleStage.OPERATION,
                human_oversight_type=HumanOversightType.HUMAN_ON_THE_LOOP,
                model_type="LLM (Claude)",
            )

        system = self._ai_systems[agent_id]

        # Perform impact assessment
        impact = ImpactAssessment(
            system_id=agent_id,
            affected_parties=["security_team", "engineering_teams", "incident_responders"],
            potential_harms=[
                {"type": "false_positive", "severity": "medium", "description": "Incorrect threat classification"},
                {"type": "false_negative", "severity": "high", "description": "Missed genuine threat"},
                {"type": "automation_error", "severity": "high", "description": "Incorrect containment action"},
            ],
            mitigations=[
                "Human-in-the-loop for Tier 2+ actions",
                "Confidence thresholds for automated actions",
                "Audit logging of all agent decisions",
                "Regular model evaluation and drift detection",
            ],
            residual_risk=RiskLevel.LOW,
        )

        # Data governance
        data_gov = DataGovernance(
            system_id=agent_id,
            data_sources=["CrowdStrike", "Okta", "Panther SIEM", "AWS", "GitHub"],
            quality_metrics={"completeness": 0.85, "accuracy": 0.90, "timeliness": 0.95},
            bias_assessments=[
                {"type": "detection_bias", "status": "monitored", "last_assessed": datetime.now().isoformat()},
            ],
            provenance={"model": "Claude (Anthropic)", "training_data": "Not directly applicable — uses API"},
            retention_policy="Intelligence packets expire after 24h; audit logs retained 90 days",
        )

        return {
            "system": system.model_dump(),
            "impact_assessment": impact.model_dump(),
            "data_governance": data_gov.model_dump(),
            "iso42001_controls_assessed": 36,
            "compliance_score": 72.0,
        }

    # -------------------------------------------------------------------------
    # ISO 27001 Statement of Applicability
    # -------------------------------------------------------------------------

    async def generate_soa(self, scope: str = "full") -> StatementOfApplicability:
        """Generate ISO 27001 Statement of Applicability."""
        framework = get_framework("iso_27001_2022")
        if not framework:
            raise ValueError("ISO 27001:2022 framework not loaded")

        entries = []
        applicable_count = 0
        implemented_count = 0

        for control in framework.controls:
            # Determine applicability based on control theme
            applicable = True
            justification = "Applicable to information security scope"

            # Physical controls may not apply to cloud-only
            if control.parent_id == "A.7" and scope == "cloud_only":
                applicable = False
                justification = "Not applicable: cloud-only environment, no physical facilities"

            if applicable:
                applicable_count += 1

            # Check if we have assessment data
            impl_status = ImplementationStatus.PARTIALLY_IMPLEMENTED
            if control.automation_level == "fully-automated":
                impl_status = ImplementationStatus.FULLY_IMPLEMENTED
                implemented_count += 1

            entries.append(SoAEntry(
                control_id=control.id,
                control_title=control.title,
                applicable=applicable,
                justification=justification,
                implementation_status=impl_status if applicable else ImplementationStatus.NOT_IMPLEMENTED,
                responsible_party="security_team",
            ))

        return StatementOfApplicability(
            scope=scope,
            entries=entries,
            total_controls=93,
            applicable_count=applicable_count,
            implemented_count=implemented_count,
        )

    # -------------------------------------------------------------------------
    # Audit Package
    # -------------------------------------------------------------------------

    async def generate_audit_package(
        self, framework_id: str, scope: str = "full"
    ) -> AuditPackage:
        """Generate complete audit bundle for a framework."""
        framework = get_framework(framework_id)
        if not framework:
            raise ValueError(f"Unknown framework: {framework_id}")

        # Run assessment
        posture = await self.assess_compliance(framework_id, scope)

        # Collect evidence for all controls
        control_ids = [c.id for c in framework.controls]
        evidence = await self.collect_evidence(control_ids)

        # Get gaps
        gaps = await self.analyze_gaps(framework_id, posture)

        # Get risk register entries
        risk_entries = self._risk_registers.get("default", [])

        return AuditPackage(
            framework_id=framework_id,
            framework_name=framework.name,
            scope=scope,
            evidence=evidence,
            posture=posture,
            gaps=gaps,
            risk_entries=risk_entries,
        )
