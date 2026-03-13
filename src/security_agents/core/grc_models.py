#!/usr/bin/env python3
"""
GRC Data Models — Pydantic v2 models for Governance, Risk, and Compliance.

Organized by layer:
- Framework layer: Framework definitions, controls, cross-mappings
- Assessment layer: Control assessments, compliance posture, gaps
- MITRE-specific: Detection mappings, coverage matrices
- ISO 27001: Statement of Applicability
- ISO 42001: AI management system records
- ISO 31000: Risk register, treatment plans
- Evidence & Audit: Evidence collection, audit packages
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# =============================================================================
# Enumerations
# =============================================================================

class ControlStatus(str, Enum):
    NOT_ASSESSED = "not_assessed"
    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    EXCEPTION_GRANTED = "exception_granted"


class ImplementationStatus(str, Enum):
    NOT_IMPLEMENTED = "not_implemented"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    FULLY_IMPLEMENTED = "fully_implemented"
    PLANNED = "planned"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


class RiskTreatment(str, Enum):
    ACCEPT = "accept"
    MITIGATE = "mitigate"
    TRANSFER = "transfer"
    AVOID = "avoid"


class RelationshipType(str, Enum):
    EQUIVALENT = "equivalent"
    PARTIAL = "partial"
    RELATED = "related"


class EvidenceType(str, Enum):
    CONFIGURATION = "configuration"
    LOG = "log"
    POLICY = "policy"
    SCAN_RESULT = "scan_result"
    ATTESTATION = "attestation"
    SCREENSHOT = "screenshot"
    API_RESPONSE = "api_response"
    REPORT = "report"


class AIRiskLevel(str, Enum):
    UNACCEPTABLE = "unacceptable"
    HIGH = "high"
    LIMITED = "limited"
    MINIMAL = "minimal"


class AILifecycleStage(str, Enum):
    DESIGN = "design"
    DEVELOPMENT = "development"
    TESTING = "testing"
    DEPLOYMENT = "deployment"
    OPERATION = "operation"
    RETIREMENT = "retirement"


class HumanOversightType(str, Enum):
    HUMAN_IN_THE_LOOP = "human_in_the_loop"
    HUMAN_ON_THE_LOOP = "human_on_the_loop"
    HUMAN_IN_COMMAND = "human_in_command"
    FULLY_AUTONOMOUS = "fully_autonomous"


# =============================================================================
# Framework Layer
# =============================================================================

class Control(BaseModel):
    """A single control within a framework."""
    id: str
    framework_id: str
    parent_id: Optional[str] = None
    title: str
    description: str = ""
    test_procedures: List[str] = Field(default_factory=list)
    evidence_requirements: List[str] = Field(default_factory=list)
    automation_level: str = "manual"  # manual, semi-automated, fully-automated


class Framework(BaseModel):
    """A compliance/security framework."""
    id: str
    name: str
    version: str
    structure_type: str = "hierarchical"  # hierarchical, flat, matrix
    controls: List[Control] = Field(default_factory=list)


class CrossMapping(BaseModel):
    """Mapping between controls across frameworks."""
    source_control: str
    source_framework: str
    target_framework: str
    target_controls: List[str]
    relationship: RelationshipType = RelationshipType.RELATED
    confidence: float = Field(ge=0.0, le=100.0, default=80.0)


# =============================================================================
# Assessment Layer
# =============================================================================

class ControlAssessment(BaseModel):
    """Assessment of a single control."""
    control_id: str
    framework_id: str
    status: ControlStatus = ControlStatus.NOT_ASSESSED
    evidence: List[str] = Field(default_factory=list)
    assessor: str = "zeta_grc"
    assessed_at: datetime = Field(default_factory=datetime.now)
    notes: str = ""


class Gap(BaseModel):
    """A compliance gap identified during assessment."""
    control_id: str
    framework_id: str
    severity: RiskLevel = RiskLevel.MEDIUM
    risk_score: float = Field(ge=0.0, le=100.0, default=50.0)
    description: str = ""
    remediation: str = ""
    estimated_effort: str = ""  # e.g., "2 weeks", "1 sprint"
    owner: str = ""


class CompliancePosture(BaseModel):
    """Overall compliance posture for a framework."""
    framework_id: str
    framework_name: str
    overall_score: float = Field(ge=0.0, le=100.0, default=0.0)
    function_scores: Dict[str, float] = Field(default_factory=dict)
    control_statuses: Dict[str, ControlStatus] = Field(default_factory=dict)
    gaps: List[Gap] = Field(default_factory=list)
    tier_assessment: Optional[str] = None
    assessed_at: datetime = Field(default_factory=datetime.now)


# =============================================================================
# MITRE ATT&CK Specific
# =============================================================================

class DetectionMapping(BaseModel):
    """Mapping of a detection rule to MITRE techniques."""
    rule_id: str
    rule_name: str = ""
    techniques_covered: List[str] = Field(default_factory=list)
    data_sources: List[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=100.0, default=70.0)


class TechniqueGap(BaseModel):
    """A MITRE technique with insufficient detection coverage."""
    technique_id: str
    name: str
    tactic: str
    priority_score: float = Field(ge=0.0, le=100.0, default=50.0)
    threat_frequency: str = "medium"  # low, medium, high, critical
    current_coverage: float = Field(ge=0.0, le=100.0, default=0.0)


class CoverageMatrix(BaseModel):
    """MITRE ATT&CK detection coverage matrix."""
    tactic_coverage: Dict[str, float] = Field(default_factory=dict)
    technique_statuses: Dict[str, str] = Field(default_factory=dict)  # technique_id -> covered/partial/none
    detection_rules: List[DetectionMapping] = Field(default_factory=list)
    priority_gaps: List[TechniqueGap] = Field(default_factory=list)
    overall_coverage: float = Field(ge=0.0, le=100.0, default=0.0)


# =============================================================================
# ISO 27001:2022
# =============================================================================

class SoAEntry(BaseModel):
    """Statement of Applicability entry for a single ISO 27001 Annex A control."""
    control_id: str
    control_title: str = ""
    applicable: bool = True
    justification: str = ""
    implementation_status: ImplementationStatus = ImplementationStatus.NOT_IMPLEMENTED
    evidence_refs: List[str] = Field(default_factory=list)
    responsible_party: str = ""


class StatementOfApplicability(BaseModel):
    """ISO 27001 Statement of Applicability."""
    scope: str = ""
    entries: List[SoAEntry] = Field(default_factory=list)
    version: str = "1.0"
    approved_by: str = ""
    approved_at: Optional[datetime] = None
    total_controls: int = 93
    applicable_count: int = 0
    implemented_count: int = 0


# =============================================================================
# ISO 42001:2023 — AI Management Systems
# =============================================================================

class AISystemRecord(BaseModel):
    """Record of an AI system under governance."""
    system_id: str
    name: str
    purpose: str = ""
    risk_level: AIRiskLevel = AIRiskLevel.LIMITED
    lifecycle_stage: AILifecycleStage = AILifecycleStage.OPERATION
    human_oversight_type: HumanOversightType = HumanOversightType.HUMAN_ON_THE_LOOP
    data_sources: List[str] = Field(default_factory=list)
    model_type: str = ""
    deployment_date: Optional[datetime] = None


class ImpactAssessment(BaseModel):
    """AI system impact assessment per ISO 42001."""
    system_id: str
    affected_parties: List[str] = Field(default_factory=list)
    potential_harms: List[Dict[str, Any]] = Field(default_factory=list)
    mitigations: List[str] = Field(default_factory=list)
    residual_risk: RiskLevel = RiskLevel.LOW
    assessment_date: datetime = Field(default_factory=datetime.now)


class DataGovernance(BaseModel):
    """Data governance record for an AI system."""
    system_id: str
    data_sources: List[str] = Field(default_factory=list)
    quality_metrics: Dict[str, float] = Field(default_factory=dict)
    bias_assessments: List[Dict[str, Any]] = Field(default_factory=list)
    provenance: Dict[str, str] = Field(default_factory=dict)
    retention_policy: str = ""


# =============================================================================
# ISO 31000 — Risk Management
# =============================================================================

class RiskRegisterEntry(BaseModel):
    """Entry in the risk register."""
    risk_id: str
    description: str
    category: str = ""  # operational, strategic, compliance, technical
    likelihood: int = Field(ge=1, le=5, default=3)
    impact: int = Field(ge=1, le=5, default=3)
    inherent_risk: float = Field(ge=0.0, le=25.0, default=9.0)
    controls: List[str] = Field(default_factory=list)
    residual_risk: float = Field(ge=0.0, le=25.0, default=9.0)
    treatment: RiskTreatment = RiskTreatment.MITIGATE
    owner: str = ""
    review_date: Optional[datetime] = None
    status: str = "open"  # open, mitigated, accepted, closed


class RiskTreatmentPlan(BaseModel):
    """Plan for treating an identified risk."""
    risk_id: str
    actions: List[str] = Field(default_factory=list)
    timeline: str = ""
    responsible: str = ""
    status: str = "planned"  # planned, in_progress, completed
    budget: Optional[float] = None


# =============================================================================
# Evidence & Audit
# =============================================================================

class ComplianceEvidence(BaseModel):
    """A piece of compliance evidence."""
    id: str
    type: EvidenceType = EvidenceType.API_RESPONSE
    source: str = ""
    collected_at: datetime = Field(default_factory=datetime.now)
    hash: str = ""  # SHA-256 of content for integrity
    control_ids: List[str] = Field(default_factory=list)
    content: Dict[str, Any] = Field(default_factory=dict)
    description: str = ""


class AuditPackage(BaseModel):
    """Complete audit bundle for a framework assessment."""
    framework_id: str
    framework_name: str = ""
    scope: str = ""
    evidence: List[ComplianceEvidence] = Field(default_factory=list)
    posture: Optional[CompliancePosture] = None
    gaps: List[Gap] = Field(default_factory=list)
    risk_entries: List[RiskRegisterEntry] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=datetime.now)
    generated_by: str = "zeta_grc"
