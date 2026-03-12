#!/usr/bin/env python3
"""
Third-Party Vendor Risk Skill — Assess, score, and track vendor security posture.

Primary owners: Beta-4 (DevSecOps), Sigma (Metrics)

Capabilities:
  - TPRM questionnaire templates across 6 risk domains
  - Risk scoring: security, privacy, compliance, financial, operational, reputational
  - Vendor tiering (critical, high, medium, low) based on data access and business impact
  - Inherent vs. residual risk tracking
  - SLA tracking for remediation commitments
  - Vendor comparison and portfolio risk analysis
"""

import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Any, Optional

from security_agents.core.models import SkillResult, IntelligencePacket, IntelligenceType, Priority
from security_agents.skills.base_skill import BaseSecuritySkill

# =============================================================================
# Enumerations
# =============================================================================

class VendorTier(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class RiskDomain(Enum):
    SECURITY = "security"
    PRIVACY = "privacy"
    COMPLIANCE = "compliance"
    FINANCIAL = "financial"
    OPERATIONAL = "operational"
    REPUTATIONAL = "reputational"

class RemediationStatus(Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    OVERDUE = "overdue"
    ACCEPTED = "accepted"
    WAIVED = "waived"

class AssessmentStatus(Enum):
    DRAFT = "draft"
    IN_PROGRESS = "in_progress"
    UNDER_REVIEW = "under_review"
    COMPLETED = "completed"
    EXPIRED = "expired"

# =============================================================================
# Questionnaire Templates
# =============================================================================

QUESTIONNAIRE_TEMPLATES: Dict[str, List[Dict[str, Any]]] = {
    "security": [
        {"id": "SEC-001", "question": "Does the vendor maintain a formal information security policy reviewed at least annually?", "weight": 3, "domain": "security"},
        {"id": "SEC-002", "question": "Does the vendor encrypt data at rest using AES-256 or equivalent?", "weight": 5, "domain": "security"},
        {"id": "SEC-003", "question": "Does the vendor encrypt data in transit using TLS 1.2 or higher?", "weight": 5, "domain": "security"},
        {"id": "SEC-004", "question": "Does the vendor perform regular vulnerability scanning and penetration testing?", "weight": 4, "domain": "security"},
        {"id": "SEC-005", "question": "Does the vendor have an incident response plan that has been tested within the last 12 months?", "weight": 5, "domain": "security"},
        {"id": "SEC-006", "question": "Does the vendor implement multi-factor authentication for administrative access?", "weight": 4, "domain": "security"},
        {"id": "SEC-007", "question": "Does the vendor maintain a software development lifecycle (SDLC) with security gates?", "weight": 3, "domain": "security"},
        {"id": "SEC-008", "question": "Does the vendor perform background checks on employees with access to customer data?", "weight": 3, "domain": "security"},
        {"id": "SEC-009", "question": "Does the vendor have a vulnerability disclosure and patch management program?", "weight": 4, "domain": "security"},
        {"id": "SEC-010", "question": "Does the vendor segment its network to isolate customer environments?", "weight": 4, "domain": "security"},
    ],
    "privacy": [
        {"id": "PRV-001", "question": "Does the vendor have a designated Data Protection Officer (DPO)?", "weight": 3, "domain": "privacy"},
        {"id": "PRV-002", "question": "Does the vendor provide a data processing agreement (DPA) compliant with GDPR?", "weight": 4, "domain": "privacy"},
        {"id": "PRV-003", "question": "Does the vendor have documented data retention and deletion policies?", "weight": 4, "domain": "privacy"},
        {"id": "PRV-004", "question": "Does the vendor process personal data only as documented in the service agreement?", "weight": 5, "domain": "privacy"},
        {"id": "PRV-005", "question": "Does the vendor support data subject access requests (DSARs) within 30 days?", "weight": 3, "domain": "privacy"},
        {"id": "PRV-006", "question": "Does the vendor maintain records of processing activities?", "weight": 3, "domain": "privacy"},
        {"id": "PRV-007", "question": "Does the vendor conduct privacy impact assessments (PIAs) for new processing activities?", "weight": 3, "domain": "privacy"},
        {"id": "PRV-008", "question": "Does the vendor restrict cross-border data transfers to approved jurisdictions?", "weight": 4, "domain": "privacy"},
    ],
    "compliance": [
        {"id": "CMP-001", "question": "Does the vendor maintain SOC 2 Type II certification?", "weight": 5, "domain": "compliance"},
        {"id": "CMP-002", "question": "Does the vendor maintain ISO 27001 certification?", "weight": 4, "domain": "compliance"},
        {"id": "CMP-003", "question": "Does the vendor undergo independent security audits at least annually?", "weight": 4, "domain": "compliance"},
        {"id": "CMP-004", "question": "Does the vendor provide audit reports or certification evidence upon request?", "weight": 3, "domain": "compliance"},
        {"id": "CMP-005", "question": "Does the vendor comply with industry-specific regulations (HIPAA, PCI-DSS, FedRAMP)?", "weight": 5, "domain": "compliance"},
        {"id": "CMP-006", "question": "Does the vendor have a documented compliance monitoring program?", "weight": 3, "domain": "compliance"},
    ],
    "financial": [
        {"id": "FIN-001", "question": "Is the vendor financially stable with positive operating history (3+ years)?", "weight": 4, "domain": "financial"},
        {"id": "FIN-002", "question": "Does the vendor carry cyber insurance with adequate coverage limits?", "weight": 3, "domain": "financial"},
        {"id": "FIN-003", "question": "Does the vendor have a documented business continuity plan?", "weight": 4, "domain": "financial"},
        {"id": "FIN-004", "question": "Has the vendor experienced any material financial events (acquisition, funding loss) in the last 12 months?", "weight": 3, "domain": "financial"},
    ],
    "operational": [
        {"id": "OPS-001", "question": "Does the vendor guarantee an SLA of 99.9% or higher uptime?", "weight": 4, "domain": "operational"},
        {"id": "OPS-002", "question": "Does the vendor have a disaster recovery plan with defined RTO and RPO?", "weight": 5, "domain": "operational"},
        {"id": "OPS-003", "question": "Does the vendor provide 24/7 support for critical issues?", "weight": 3, "domain": "operational"},
        {"id": "OPS-004", "question": "Does the vendor have documented change management procedures?", "weight": 3, "domain": "operational"},
        {"id": "OPS-005", "question": "Does the vendor notify customers of material changes to infrastructure or security posture?", "weight": 4, "domain": "operational"},
        {"id": "OPS-006", "question": "Does the vendor support data portability and provide export upon termination?", "weight": 3, "domain": "operational"},
    ],
    "reputational": [
        {"id": "REP-001", "question": "Has the vendor experienced a publicly disclosed data breach in the last 3 years?", "weight": 5, "domain": "reputational"},
        {"id": "REP-002", "question": "Has the vendor been subject to regulatory enforcement actions?", "weight": 4, "domain": "reputational"},
        {"id": "REP-003", "question": "Does the vendor have a positive reputation in industry analyst reports?", "weight": 2, "domain": "reputational"},
        {"id": "REP-004", "question": "Does the vendor publicly disclose their security practices or certifications?", "weight": 2, "domain": "reputational"},
    ],
}

# Tiering criteria
TIER_CRITERIA = {
    VendorTier.CRITICAL: {
        "description": "Processes or stores highly sensitive data (PII, PHI, financial); critical to business operations; high integration depth",
        "review_frequency_days": 90,
        "required_certifications": ["SOC 2 Type II", "ISO 27001"],
        "min_questionnaire_domains": 6,
    },
    VendorTier.HIGH: {
        "description": "Accesses sensitive data or systems; significant business impact if unavailable",
        "review_frequency_days": 180,
        "required_certifications": ["SOC 2 Type II"],
        "min_questionnaire_domains": 4,
    },
    VendorTier.MEDIUM: {
        "description": "Limited data access; moderate business impact; replaceable with effort",
        "review_frequency_days": 365,
        "required_certifications": [],
        "min_questionnaire_domains": 3,
    },
    VendorTier.LOW: {
        "description": "No sensitive data access; minimal business impact; easily replaceable",
        "review_frequency_days": 730,
        "required_certifications": [],
        "min_questionnaire_domains": 1,
    },
}

class VendorRiskSkill(BaseSecuritySkill):
    """Assess and manage third-party vendor security risk."""

    SKILL_NAME = "vendor_risk"
    DESCRIPTION = (
        "Assess third-party vendor security posture across six risk domains with "
        "questionnaire management, risk scoring, tiering, and remediation tracking"
    )
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS = ["beta_4_devsecops", "sigma_metrics"]
    REQUIRED_INTEGRATIONS = []

    async def _setup(self):
        self.vendors: Dict[str, Dict[str, Any]] = {}  # vendor_id -> vendor data
        self.assessments: Dict[str, Dict[str, Any]] = {}  # assessment_id -> assessment
        self.remediations: List[Dict[str, Any]] = []

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        action = parameters.get("action", "assess_vendor")

        dispatch = {
            "assess_vendor": self._assess_vendor,
            "create_questionnaire": self._create_questionnaire,
            "score_risk": self._score_risk,
            "track_remediation": self._track_remediation,
            "list_vendors": self._list_vendors,
            "compare_vendors": self._compare_vendors,
            "generate_report": self._generate_report,
        }

        handler = dispatch.get(action)
        if not handler:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Unknown action '{action}'. Supported: {list(dispatch.keys())}"],
            )
        return await handler(parameters)

    # =========================================================================
    # Assess Vendor
    # =========================================================================

    async def _assess_vendor(self, params: Dict[str, Any]) -> SkillResult:
        """Register or update a vendor assessment with profile and risk context."""
        vendor_name = params.get("vendor_name", "")
        vendor_id = params.get("vendor_id", "")
        data_types = params.get("data_types", [])  # types of data shared: pii, phi, financial, etc.
        integration_type = params.get("integration_type", "")  # saas, api, on_prem, etc.
        business_criticality = params.get("business_criticality", "medium")  # critical, high, medium, low
        contract_end_date = params.get("contract_end_date")
        services_provided = params.get("services_provided", [])
        certifications = params.get("certifications", [])
        responses = params.get("questionnaire_responses", {})  # {question_id: {answer: bool, notes: str}}

        if not vendor_name:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'vendor_name' is required"],
            )

        if not vendor_id:
            vendor_id = f"VND-{uuid.uuid4().hex[:8]}"

        # Determine tier
        tier = self._determine_tier(data_types, business_criticality, integration_type)
        tier_info = TIER_CRITERIA[tier]

        # Calculate inherent risk (before controls)
        inherent_risk = self._calculate_inherent_risk(data_types, integration_type, business_criticality)

        # Calculate residual risk (after controls, based on questionnaire)
        residual_risk = inherent_risk
        control_effectiveness = 0.0
        if responses:
            control_effectiveness = self._evaluate_controls(responses)
            residual_risk = round(inherent_risk * (1 - control_effectiveness / 100), 1)

        vendor = {
            "vendor_id": vendor_id,
            "vendor_name": vendor_name,
            "tier": tier.value,
            "tier_description": tier_info["description"],
            "data_types": data_types,
            "integration_type": integration_type,
            "business_criticality": business_criticality,
            "services_provided": services_provided,
            "certifications": certifications,
            "contract_end_date": contract_end_date,
            "inherent_risk_score": inherent_risk,
            "residual_risk_score": residual_risk,
            "control_effectiveness": round(control_effectiveness, 1),
            "review_frequency_days": tier_info["review_frequency_days"],
            "next_review_date": (datetime.now() + timedelta(days=tier_info["review_frequency_days"])).isoformat(),
            "assessment_status": "completed" if responses else "pending",
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "questionnaire_responses": responses,
            "domain_scores": {},
        }

        # Score per domain if responses provided
        if responses:
            domain_scores = self._score_by_domain(responses)
            vendor["domain_scores"] = domain_scores

        self.vendors[vendor_id] = vendor

        # Generate intelligence if high-risk vendor
        packets = []
        if residual_risk >= 70:
            packets.append(IntelligencePacket(
                packet_id=f"PKT-VR-{uuid.uuid4().hex[:8]}",
                source_agent=self.agent_id,
                target_agents=["all"],
                intelligence_type=IntelligenceType.SUPPLY_CHAIN,
                priority=Priority.HIGH,
                confidence=80.0,
                timestamp=datetime.now(),
                data={
                    "vendor_name": vendor_name,
                    "vendor_id": vendor_id,
                    "residual_risk": residual_risk,
                    "tier": tier.value,
                    "message": f"High-risk vendor '{vendor_name}' (tier: {tier.value}, residual risk: {residual_risk})",
                },
                correlation_keys=[vendor_id, "vendor_risk", "supply_chain"],
            ))

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "vendor": vendor,
                "risk_summary": {
                    "inherent_risk": inherent_risk,
                    "residual_risk": residual_risk,
                    "control_effectiveness": round(control_effectiveness, 1),
                    "risk_reduction": round(inherent_risk - residual_risk, 1),
                    "tier": tier.value,
                },
                "missing_certifications": [
                    c for c in tier_info.get("required_certifications", [])
                    if c not in certifications
                ],
            },
            intelligence_packets=packets,
            warnings=[
                f"Vendor '{vendor_name}' residual risk score is {residual_risk} — above threshold"
            ] if residual_risk >= 70 else [],
        )

    # =========================================================================
    # Create Questionnaire
    # =========================================================================

    async def _create_questionnaire(self, params: Dict[str, Any]) -> SkillResult:
        """Generate a TPRM questionnaire tailored to vendor tier and risk domains."""
        vendor_id = params.get("vendor_id", "")
        domains = params.get("domains", [])  # specific domains to include
        tier_override = params.get("tier")  # override auto-detected tier
        custom_questions = params.get("custom_questions", [])

        vendor = self.vendors.get(vendor_id, {})
        vendor_name = vendor.get("vendor_name", params.get("vendor_name", "unknown"))
        tier_str = tier_override or vendor.get("tier", "medium")
        tier = VendorTier(tier_str) if tier_str in [t.value for t in VendorTier] else VendorTier.MEDIUM
        tier_info = TIER_CRITERIA[tier]

        # Select domains based on tier
        if not domains:
            all_domains = list(QUESTIONNAIRE_TEMPLATES.keys())
            min_domains = tier_info["min_questionnaire_domains"]
            # Always include security; add others by priority
            domain_priority = ["security", "compliance", "privacy", "operational", "financial", "reputational"]
            domains = domain_priority[:max(min_domains, len(domain_priority))]

        questions = []
        for domain in domains:
            domain_questions = QUESTIONNAIRE_TEMPLATES.get(domain, [])
            questions.extend(domain_questions)

        # Add custom questions
        for i, cq in enumerate(custom_questions):
            questions.append({
                "id": f"CUSTOM-{i+1:03d}",
                "question": cq.get("question", ""),
                "weight": cq.get("weight", 3),
                "domain": cq.get("domain", "security"),
            })

        assessment_id = f"ASSESS-{uuid.uuid4().hex[:8]}"
        assessment = {
            "assessment_id": assessment_id,
            "vendor_id": vendor_id,
            "vendor_name": vendor_name,
            "tier": tier.value,
            "status": AssessmentStatus.DRAFT.value,
            "domains_covered": domains,
            "questions": questions,
            "total_questions": len(questions),
            "created_at": datetime.now().isoformat(),
            "due_date": (datetime.now() + timedelta(days=30)).isoformat(),
            "responses": {},
        }

        self.assessments[assessment_id] = assessment

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "assessment": assessment,
                "questionnaire_summary": {
                    "total_questions": len(questions),
                    "domains_covered": domains,
                    "max_possible_score": sum(q["weight"] for q in questions) * 5,
                    "due_date": assessment["due_date"],
                },
            },
        )

    # =========================================================================
    # Score Risk
    # =========================================================================

    async def _score_risk(self, params: Dict[str, Any]) -> SkillResult:
        """Calculate comprehensive risk scores from questionnaire responses."""
        vendor_id = params.get("vendor_id", "")
        responses = params.get("responses", {})  # {question_id: {answer: bool/int(1-5), notes: str}}

        vendor = self.vendors.get(vendor_id)
        if not vendor:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Vendor '{vendor_id}' not found. Register with assess_vendor first."],
            )

        if not responses:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'responses' required — dict of question_id -> {answer, notes}"],
            )

        # Score by domain
        domain_scores = self._score_by_domain(responses)

        # Overall weighted score
        total_weight = sum(ds.get("total_weight", 0) for ds in domain_scores.values())
        total_weighted_score = sum(ds.get("weighted_score", 0) for ds in domain_scores.values())
        overall_score = round((total_weighted_score / total_weight * 100) if total_weight > 0 else 0, 1)

        # Update vendor
        inherent = vendor["inherent_risk_score"]
        control_effectiveness = overall_score
        residual = round(inherent * (1 - control_effectiveness / 100), 1)

        vendor["domain_scores"] = domain_scores
        vendor["residual_risk_score"] = residual
        vendor["control_effectiveness"] = control_effectiveness
        vendor["questionnaire_responses"] = responses
        vendor["assessment_status"] = "completed"
        vendor["updated_at"] = datetime.now().isoformat()

        # Identify gaps (low-scoring domains)
        gaps = []
        for domain, score_data in domain_scores.items():
            if score_data.get("percentage", 0) < 50:
                gaps.append({
                    "domain": domain,
                    "score_percentage": score_data["percentage"],
                    "gap_questions": score_data.get("failed_questions", []),
                    "recommendation": f"Vendor needs improvement in {domain} controls",
                })

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "vendor_id": vendor_id,
                "vendor_name": vendor["vendor_name"],
                "domain_scores": domain_scores,
                "overall_control_score": overall_score,
                "inherent_risk": inherent,
                "residual_risk": residual,
                "risk_reduction": round(inherent - residual, 1),
                "gaps": gaps,
                "risk_level": self._risk_level_from_score(residual),
                "recommendation": self._vendor_recommendation(residual, vendor["tier"]),
            },
        )

    # =========================================================================
    # Track Remediation
    # =========================================================================

    async def _track_remediation(self, params: Dict[str, Any]) -> SkillResult:
        """Create or update remediation tracking for vendor risk findings."""
        vendor_id = params.get("vendor_id", "")
        action_type = params.get("remediation_action", "create")  # create, update, list
        finding_description = params.get("finding", "")
        risk_domain = params.get("domain", "security")
        due_date = params.get("due_date")
        status = params.get("status")
        remediation_id = params.get("remediation_id")

        vendor = self.vendors.get(vendor_id)
        if not vendor:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Vendor '{vendor_id}' not found."],
            )

        if action_type == "create":
            if not finding_description:
                return SkillResult(
                    success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                    errors=["'finding' description required to create a remediation item"],
                )

            rem = {
                "remediation_id": f"REM-{uuid.uuid4().hex[:8]}",
                "vendor_id": vendor_id,
                "vendor_name": vendor["vendor_name"],
                "finding": finding_description,
                "domain": risk_domain,
                "status": RemediationStatus.OPEN.value,
                "created_at": datetime.now().isoformat(),
                "due_date": due_date or (datetime.now() + timedelta(days=90)).isoformat(),
                "updated_at": datetime.now().isoformat(),
                "notes": [],
            }
            self.remediations.append(rem)

            return SkillResult(
                success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                data={"remediation": rem},
            )

        elif action_type == "update":
            if not remediation_id:
                return SkillResult(
                    success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                    errors=["'remediation_id' required for update"],
                )

            rem = next((r for r in self.remediations if r["remediation_id"] == remediation_id), None)
            if not rem:
                return SkillResult(
                    success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                    errors=[f"Remediation '{remediation_id}' not found"],
                )

            if status:
                rem["status"] = status
            if params.get("note"):
                rem["notes"].append({
                    "text": params["note"],
                    "timestamp": datetime.now().isoformat(),
                })
            rem["updated_at"] = datetime.now().isoformat()

            return SkillResult(
                success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                data={"remediation": rem},
            )

        else:  # list
            vendor_rems = [r for r in self.remediations if r["vendor_id"] == vendor_id]

            # Check for overdue items
            now = datetime.now()
            for r in vendor_rems:
                if r["status"] in (RemediationStatus.OPEN.value, RemediationStatus.IN_PROGRESS.value):
                    try:
                        due = datetime.fromisoformat(r["due_date"])
                        if now > due:
                            r["status"] = RemediationStatus.OVERDUE.value
                    except (ValueError, TypeError):
                        pass

            return SkillResult(
                success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                data={
                    "vendor_id": vendor_id,
                    "vendor_name": vendor["vendor_name"],
                    "remediations": vendor_rems,
                    "total": len(vendor_rems),
                    "status_breakdown": {
                        s.value: sum(1 for r in vendor_rems if r["status"] == s.value)
                        for s in RemediationStatus
                    },
                    "overdue_count": sum(1 for r in vendor_rems if r["status"] == RemediationStatus.OVERDUE.value),
                },
            )

    # =========================================================================
    # List Vendors
    # =========================================================================

    async def _list_vendors(self, params: Dict[str, Any]) -> SkillResult:
        """List all vendors with optional filtering."""
        tier_filter = params.get("tier")
        risk_threshold = params.get("risk_threshold")  # min residual risk score

        vendors = list(self.vendors.values())

        if tier_filter:
            vendors = [v for v in vendors if v.get("tier") == tier_filter]
        if risk_threshold is not None:
            vendors = [v for v in vendors if v.get("residual_risk_score", 0) >= risk_threshold]

        vendors.sort(key=lambda v: v.get("residual_risk_score", 0), reverse=True)

        tier_summary = {}
        for tier in VendorTier:
            tier_vendors = [v for v in self.vendors.values() if v.get("tier") == tier.value]
            if tier_vendors:
                tier_summary[tier.value] = {
                    "count": len(tier_vendors),
                    "avg_residual_risk": round(
                        sum(v.get("residual_risk_score", 0) for v in tier_vendors) / len(tier_vendors), 1
                    ),
                    "highest_risk_vendor": max(tier_vendors, key=lambda v: v.get("residual_risk_score", 0)).get("vendor_name"),
                }

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "vendors": [
                    {
                        "vendor_id": v["vendor_id"],
                        "vendor_name": v["vendor_name"],
                        "tier": v["tier"],
                        "inherent_risk": v.get("inherent_risk_score", 0),
                        "residual_risk": v.get("residual_risk_score", 0),
                        "control_effectiveness": v.get("control_effectiveness", 0),
                        "assessment_status": v.get("assessment_status", "pending"),
                        "next_review_date": v.get("next_review_date"),
                    }
                    for v in vendors
                ],
                "total_vendors": len(vendors),
                "tier_summary": tier_summary,
                "portfolio_risk": round(
                    sum(v.get("residual_risk_score", 0) for v in self.vendors.values()) / len(self.vendors), 1
                ) if self.vendors else 0,
            },
        )

    # =========================================================================
    # Compare Vendors
    # =========================================================================

    async def _compare_vendors(self, params: Dict[str, Any]) -> SkillResult:
        """Compare risk postures of multiple vendors."""
        vendor_ids = params.get("vendor_ids", [])

        if len(vendor_ids) < 2:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["At least 2 vendor_ids required for comparison"],
            )

        vendors = []
        for vid in vendor_ids:
            v = self.vendors.get(vid)
            if v:
                vendors.append(v)

        if len(vendors) < 2:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Only {len(vendors)} of {len(vendor_ids)} vendors found in inventory"],
            )

        comparison = []
        for v in vendors:
            comparison.append({
                "vendor_id": v["vendor_id"],
                "vendor_name": v["vendor_name"],
                "tier": v["tier"],
                "inherent_risk": v.get("inherent_risk_score", 0),
                "residual_risk": v.get("residual_risk_score", 0),
                "control_effectiveness": v.get("control_effectiveness", 0),
                "domain_scores": v.get("domain_scores", {}),
                "certifications": v.get("certifications", []),
            })

        # Rank vendors
        comparison.sort(key=lambda c: c["residual_risk"])

        # Domain comparison matrix
        all_domains = set()
        for v in vendors:
            all_domains.update(v.get("domain_scores", {}).keys())

        domain_comparison = {}
        for domain in all_domains:
            domain_comparison[domain] = {
                v["vendor_name"]: v.get("domain_scores", {}).get(domain, {}).get("percentage", 0)
                for v in vendors
            }

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "comparison": comparison,
                "best_overall": comparison[0]["vendor_name"] if comparison else None,
                "worst_overall": comparison[-1]["vendor_name"] if comparison else None,
                "domain_comparison": domain_comparison,
                "recommendation": f"'{comparison[0]['vendor_name']}' has the lowest residual risk ({comparison[0]['residual_risk']})" if comparison else "",
            },
        )

    # =========================================================================
    # Generate Report
    # =========================================================================

    async def _generate_report(self, params: Dict[str, Any]) -> SkillResult:
        """Generate a comprehensive vendor risk report."""
        vendor_id = params.get("vendor_id")  # single vendor or portfolio-wide
        include_details = params.get("include_details", True)

        if vendor_id:
            vendor = self.vendors.get(vendor_id)
            if not vendor:
                return SkillResult(
                    success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                    errors=[f"Vendor '{vendor_id}' not found"],
                )

            vendor_rems = [r for r in self.remediations if r["vendor_id"] == vendor_id]

            report = {
                "report_id": f"RPT-{uuid.uuid4().hex[:8]}",
                "report_type": "single_vendor",
                "generated_at": datetime.now().isoformat(),
                "vendor": vendor,
                "risk_summary": {
                    "tier": vendor["tier"],
                    "inherent_risk": vendor.get("inherent_risk_score", 0),
                    "residual_risk": vendor.get("residual_risk_score", 0),
                    "control_effectiveness": vendor.get("control_effectiveness", 0),
                    "risk_level": self._risk_level_from_score(vendor.get("residual_risk_score", 0)),
                },
                "domain_scores": vendor.get("domain_scores", {}),
                "remediations": vendor_rems,
                "open_remediations": sum(1 for r in vendor_rems if r["status"] in ("open", "in_progress", "overdue")),
                "recommendations": self._vendor_specific_recommendations(vendor),
            }

        else:
            # Portfolio-wide report
            vendors = list(self.vendors.values())
            report = {
                "report_id": f"RPT-{uuid.uuid4().hex[:8]}",
                "report_type": "portfolio",
                "generated_at": datetime.now().isoformat(),
                "summary": {
                    "total_vendors": len(vendors),
                    "tier_breakdown": {
                        t.value: sum(1 for v in vendors if v.get("tier") == t.value)
                        for t in VendorTier
                    },
                    "average_residual_risk": round(
                        sum(v.get("residual_risk_score", 0) for v in vendors) / len(vendors), 1
                    ) if vendors else 0,
                    "high_risk_vendors": [
                        v["vendor_name"] for v in vendors if v.get("residual_risk_score", 0) >= 70
                    ],
                    "pending_assessments": sum(1 for v in vendors if v.get("assessment_status") == "pending"),
                    "total_remediations": len(self.remediations),
                    "overdue_remediations": sum(1 for r in self.remediations if r["status"] == "overdue"),
                },
                "vendors": vendors if include_details else [
                    {"vendor_name": v["vendor_name"], "tier": v["tier"], "residual_risk": v.get("residual_risk_score", 0)}
                    for v in vendors
                ],
                "recommendations": self._portfolio_recommendations(vendors),
            }

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={"report": report},
        )

    # =========================================================================
    # Internal Helpers
    # =========================================================================

    def _determine_tier(self, data_types: List[str], business_criticality: str, integration_type: str) -> VendorTier:
        """Determine vendor tier based on data access and criticality."""
        sensitive_data = {"pii", "phi", "financial", "credentials", "intellectual_property"}
        has_sensitive = bool(set(dt.lower() for dt in data_types) & sensitive_data)

        if business_criticality == "critical" or (has_sensitive and integration_type in ("saas", "api", "on_prem")):
            return VendorTier.CRITICAL
        elif business_criticality == "high" or has_sensitive:
            return VendorTier.HIGH
        elif business_criticality == "medium":
            return VendorTier.MEDIUM
        return VendorTier.LOW

    def _calculate_inherent_risk(self, data_types: List[str], integration_type: str, criticality: str) -> float:
        """Calculate inherent risk score (0-100) before any controls."""
        score = 20.0  # base score

        # Data sensitivity
        data_risk = {
            "pii": 20, "phi": 25, "financial": 20, "credentials": 25,
            "intellectual_property": 15, "internal": 10, "public": 2,
        }
        for dt in data_types:
            score += data_risk.get(dt.lower(), 5)

        # Integration depth
        integration_risk = {"saas": 15, "api": 12, "on_prem": 10, "managed_service": 8, "consulting": 5}
        score += integration_risk.get(integration_type.lower(), 5)

        # Business criticality
        criticality_risk = {"critical": 20, "high": 15, "medium": 10, "low": 5}
        score += criticality_risk.get(criticality.lower(), 5)

        return min(100.0, round(score, 1))

    def _evaluate_controls(self, responses: Dict[str, Dict[str, Any]]) -> float:
        """Evaluate control effectiveness from questionnaire responses (0-100%)."""
        total_weight = 0
        total_score = 0

        all_questions = {}
        for domain_questions in QUESTIONNAIRE_TEMPLATES.values():
            for q in domain_questions:
                all_questions[q["id"]] = q

        for q_id, response in responses.items():
            question = all_questions.get(q_id)
            if not question:
                continue

            weight = question.get("weight", 3)
            total_weight += weight

            answer = response.get("answer")
            if isinstance(answer, bool):
                total_score += weight if answer else 0
            elif isinstance(answer, (int, float)):
                total_score += weight * (min(5, max(0, answer)) / 5)

        return (total_score / total_weight * 100) if total_weight > 0 else 0

    def _score_by_domain(self, responses: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Score responses grouped by risk domain."""
        domain_scores: Dict[str, Dict[str, Any]] = {}

        for domain, questions in QUESTIONNAIRE_TEMPLATES.items():
            total_weight = 0
            earned_weight = 0
            failed = []

            for q in questions:
                response = responses.get(q["id"])
                if not response:
                    continue

                weight = q.get("weight", 3)
                total_weight += weight

                answer = response.get("answer")
                if isinstance(answer, bool):
                    if answer:
                        earned_weight += weight
                    else:
                        failed.append(q["id"])
                elif isinstance(answer, (int, float)):
                    earned_weight += weight * (min(5, max(0, answer)) / 5)
                    if answer < 3:
                        failed.append(q["id"])

            if total_weight > 0:
                pct = round((earned_weight / total_weight) * 100, 1)
                domain_scores[domain] = {
                    "percentage": pct,
                    "weighted_score": earned_weight,
                    "total_weight": total_weight,
                    "questions_answered": sum(1 for q in questions if q["id"] in responses),
                    "total_questions": len(questions),
                    "failed_questions": failed,
                    "rating": "strong" if pct >= 80 else "adequate" if pct >= 60 else "weak" if pct >= 40 else "critical_gap",
                }

        return domain_scores

    def _risk_level_from_score(self, score: float) -> str:
        """Convert risk score to risk level."""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 20:
            return "low"
        return "minimal"

    def _vendor_recommendation(self, residual_risk: float, tier: str) -> str:
        """Generate a recommendation based on risk and tier."""
        if residual_risk >= 80:
            return "CRITICAL: Vendor poses unacceptable risk. Require immediate remediation plan or consider termination."
        elif residual_risk >= 60:
            return "HIGH: Significant risk gaps. Require formal remediation plan with 90-day SLA."
        elif residual_risk >= 40:
            return "MEDIUM: Moderate risk. Track remediation items and re-assess at next review cycle."
        elif residual_risk >= 20:
            return "LOW: Acceptable risk posture. Continue standard monitoring cadence."
        return "MINIMAL: Strong vendor security posture. Maintain regular review schedule."

    def _vendor_specific_recommendations(self, vendor: Dict[str, Any]) -> List[str]:
        """Generate vendor-specific recommendations."""
        recs = []
        domain_scores = vendor.get("domain_scores", {})

        for domain, scores in domain_scores.items():
            if scores.get("percentage", 100) < 50:
                recs.append(f"PRIORITY: Vendor has critical gaps in {domain} domain ({scores['percentage']}% score). Require remediation plan.")

        if not vendor.get("certifications"):
            tier = vendor.get("tier", "low")
            required = TIER_CRITERIA.get(VendorTier(tier), {}).get("required_certifications", [])
            if required:
                recs.append(f"Vendor is missing required certifications for {tier} tier: {', '.join(required)}")

        recs.append(f"Next assessment due: {vendor.get('next_review_date', 'TBD')}")
        return recs

    def _portfolio_recommendations(self, vendors: List[Dict[str, Any]]) -> List[str]:
        """Generate portfolio-level recommendations."""
        recs = []
        high_risk = [v for v in vendors if v.get("residual_risk_score", 0) >= 70]
        if high_risk:
            recs.append(f"IMMEDIATE: {len(high_risk)} vendor(s) exceed risk threshold: {', '.join(v['vendor_name'] for v in high_risk)}")

        pending = [v for v in vendors if v.get("assessment_status") == "pending"]
        if pending:
            recs.append(f"Complete pending assessments for {len(pending)} vendor(s): {', '.join(v['vendor_name'] for v in pending)}")

        overdue = sum(1 for r in self.remediations if r["status"] == "overdue")
        if overdue:
            recs.append(f"Address {overdue} overdue remediation item(s) — escalate to vendor management.")

        recs.extend([
            "Maintain vendor inventory with regular updates to data access and integration scope.",
            "Review vendor tiering annually or after significant scope changes.",
            "Include vendor risk metrics in quarterly security program reporting.",
        ])
        return recs
