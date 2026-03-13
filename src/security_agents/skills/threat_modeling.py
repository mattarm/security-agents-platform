#!/usr/bin/env python3
"""
Threat Modeling Skill — Structured threat analysis using STRIDE and PASTA methodologies.

Primary owners: Delta (Red Team), Beta-4 (DevSecOps)

Capabilities:
  - STRIDE methodology (Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation)
  - PASTA 7-stage threat modeling process
  - Threat library with common patterns per component type
  - Automated mitigation suggestions mapped to NIST SP 800-53 controls
  - Risk scoring matrix (likelihood x impact)
  - DFD-based analysis with trust boundary identification
  - Comprehensive threat model reports with prioritized findings
"""

import hashlib
import uuid
from datetime import datetime
from enum import Enum
from typing import Dict, List, Any, Optional

from security_agents.core.models import SkillResult, IntelligencePacket, IntelligenceType, Priority
from security_agents.skills.base_skill import BaseSecuritySkill

# =============================================================================
# Enumerations
# =============================================================================

class StrideCategory(Enum):
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"

class PastaStage(Enum):
    DEFINE_OBJECTIVES = "stage_1_define_objectives"
    DEFINE_TECHNICAL_SCOPE = "stage_2_define_technical_scope"
    APPLICATION_DECOMPOSITION = "stage_3_application_decomposition"
    THREAT_ANALYSIS = "stage_4_threat_analysis"
    VULNERABILITY_ANALYSIS = "stage_5_vulnerability_analysis"
    ATTACK_MODELING = "stage_6_attack_modeling"
    RISK_AND_IMPACT = "stage_7_risk_and_impact"

class ComponentType(Enum):
    WEB_APPLICATION = "web_application"
    API_SERVICE = "api_service"
    DATABASE = "database"
    MESSAGE_QUEUE = "message_queue"
    AUTH_SERVICE = "auth_service"
    FILE_STORAGE = "file_storage"
    NETWORK_GATEWAY = "network_gateway"
    MOBILE_APP = "mobile_app"
    MICROSERVICE = "microservice"
    SERVERLESS_FUNCTION = "serverless_function"
    CONTAINER = "container"
    CI_CD_PIPELINE = "ci_cd_pipeline"

class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"

# =============================================================================
# STRIDE Threat Definitions Per Component Type
# =============================================================================

STRIDE_DESCRIPTIONS: Dict[StrideCategory, Dict[str, str]] = {
    StrideCategory.SPOOFING: {
        "name": "Spoofing",
        "description": "Impersonating a user, component, or system to gain unauthorized access",
        "security_property": "Authentication",
    },
    StrideCategory.TAMPERING: {
        "name": "Tampering",
        "description": "Unauthorized modification of data or code in transit or at rest",
        "security_property": "Integrity",
    },
    StrideCategory.REPUDIATION: {
        "name": "Repudiation",
        "description": "Ability to deny performing an action without proof to the contrary",
        "security_property": "Non-repudiation",
    },
    StrideCategory.INFORMATION_DISCLOSURE: {
        "name": "Information Disclosure",
        "description": "Exposure of sensitive data to unauthorized parties",
        "security_property": "Confidentiality",
    },
    StrideCategory.DENIAL_OF_SERVICE: {
        "name": "Denial of Service",
        "description": "Disruption of service availability for legitimate users",
        "security_property": "Availability",
    },
    StrideCategory.ELEVATION_OF_PRIVILEGE: {
        "name": "Elevation of Privilege",
        "description": "Gaining capabilities beyond those initially granted",
        "security_property": "Authorization",
    },
}

# Threat library: common threats per component type mapped to STRIDE categories
THREAT_LIBRARY: Dict[str, List[Dict[str, Any]]] = {
    "web_application": [
        {"stride": "spoofing", "threat": "Session hijacking via stolen cookies", "likelihood": 4, "impact": 4, "cwe": "CWE-384"},
        {"stride": "spoofing", "threat": "Cross-site request forgery (CSRF)", "likelihood": 3, "impact": 3, "cwe": "CWE-352"},
        {"stride": "tampering", "threat": "Cross-site scripting (XSS) for DOM manipulation", "likelihood": 4, "impact": 4, "cwe": "CWE-79"},
        {"stride": "tampering", "threat": "SQL injection for data modification", "likelihood": 3, "impact": 5, "cwe": "CWE-89"},
        {"stride": "repudiation", "threat": "Insufficient logging of user actions", "likelihood": 3, "impact": 3, "cwe": "CWE-778"},
        {"stride": "information_disclosure", "threat": "Verbose error messages leaking stack traces", "likelihood": 4, "impact": 3, "cwe": "CWE-209"},
        {"stride": "information_disclosure", "threat": "Insecure direct object references (IDOR)", "likelihood": 3, "impact": 4, "cwe": "CWE-639"},
        {"stride": "denial_of_service", "threat": "Application-layer DoS via expensive queries", "likelihood": 3, "impact": 4, "cwe": "CWE-400"},
        {"stride": "elevation_of_privilege", "threat": "Broken access control allowing admin escalation", "likelihood": 3, "impact": 5, "cwe": "CWE-269"},
    ],
    "api_service": [
        {"stride": "spoofing", "threat": "JWT token forgery due to weak signing", "likelihood": 3, "impact": 5, "cwe": "CWE-347"},
        {"stride": "spoofing", "threat": "API key theft from client-side exposure", "likelihood": 4, "impact": 4, "cwe": "CWE-522"},
        {"stride": "tampering", "threat": "Mass assignment via unvalidated request bodies", "likelihood": 3, "impact": 4, "cwe": "CWE-915"},
        {"stride": "tampering", "threat": "Request parameter pollution", "likelihood": 2, "impact": 3, "cwe": "CWE-235"},
        {"stride": "repudiation", "threat": "Missing audit trail for API mutations", "likelihood": 3, "impact": 3, "cwe": "CWE-778"},
        {"stride": "information_disclosure", "threat": "Excessive data exposure in API responses", "likelihood": 4, "impact": 4, "cwe": "CWE-213"},
        {"stride": "information_disclosure", "threat": "GraphQL introspection leaking schema details", "likelihood": 3, "impact": 3, "cwe": "CWE-200"},
        {"stride": "denial_of_service", "threat": "Rate limiting bypass causing resource exhaustion", "likelihood": 3, "impact": 4, "cwe": "CWE-770"},
        {"stride": "elevation_of_privilege", "threat": "Broken function-level authorization", "likelihood": 3, "impact": 5, "cwe": "CWE-285"},
    ],
    "database": [
        {"stride": "spoofing", "threat": "Default or weak database credentials", "likelihood": 3, "impact": 5, "cwe": "CWE-798"},
        {"stride": "tampering", "threat": "Direct data manipulation bypassing application logic", "likelihood": 2, "impact": 5, "cwe": "CWE-284"},
        {"stride": "repudiation", "threat": "Missing database audit logging", "likelihood": 3, "impact": 3, "cwe": "CWE-778"},
        {"stride": "information_disclosure", "threat": "Unencrypted data at rest", "likelihood": 3, "impact": 5, "cwe": "CWE-311"},
        {"stride": "information_disclosure", "threat": "Unencrypted database connections", "likelihood": 3, "impact": 4, "cwe": "CWE-319"},
        {"stride": "denial_of_service", "threat": "Resource exhaustion via unoptimized queries", "likelihood": 3, "impact": 4, "cwe": "CWE-400"},
        {"stride": "elevation_of_privilege", "threat": "Overly permissive database roles", "likelihood": 3, "impact": 4, "cwe": "CWE-250"},
    ],
    "auth_service": [
        {"stride": "spoofing", "threat": "Credential stuffing with breached password lists", "likelihood": 4, "impact": 5, "cwe": "CWE-307"},
        {"stride": "spoofing", "threat": "MFA bypass via session fixation", "likelihood": 2, "impact": 5, "cwe": "CWE-384"},
        {"stride": "tampering", "threat": "Token manipulation to alter claims", "likelihood": 2, "impact": 5, "cwe": "CWE-565"},
        {"stride": "repudiation", "threat": "Authentication events not logged", "likelihood": 3, "impact": 4, "cwe": "CWE-778"},
        {"stride": "information_disclosure", "threat": "User enumeration via login error messages", "likelihood": 4, "impact": 3, "cwe": "CWE-203"},
        {"stride": "denial_of_service", "threat": "Account lockout abuse for legitimate users", "likelihood": 3, "impact": 3, "cwe": "CWE-645"},
        {"stride": "elevation_of_privilege", "threat": "Privilege escalation via role manipulation in tokens", "likelihood": 2, "impact": 5, "cwe": "CWE-269"},
    ],
    "message_queue": [
        {"stride": "spoofing", "threat": "Unauthenticated message publishing", "likelihood": 3, "impact": 4, "cwe": "CWE-306"},
        {"stride": "tampering", "threat": "Message modification in transit without integrity checks", "likelihood": 3, "impact": 4, "cwe": "CWE-354"},
        {"stride": "repudiation", "threat": "Missing message provenance tracking", "likelihood": 3, "impact": 3, "cwe": "CWE-778"},
        {"stride": "information_disclosure", "threat": "Sensitive data in unencrypted message payloads", "likelihood": 3, "impact": 4, "cwe": "CWE-319"},
        {"stride": "denial_of_service", "threat": "Queue flooding causing consumer starvation", "likelihood": 3, "impact": 4, "cwe": "CWE-400"},
        {"stride": "elevation_of_privilege", "threat": "Deserialization attacks via crafted messages", "likelihood": 2, "impact": 5, "cwe": "CWE-502"},
    ],
    "file_storage": [
        {"stride": "spoofing", "threat": "Unauthorized access via misconfigured bucket policies", "likelihood": 4, "impact": 5, "cwe": "CWE-732"},
        {"stride": "tampering", "threat": "File replacement without integrity verification", "likelihood": 3, "impact": 4, "cwe": "CWE-354"},
        {"stride": "information_disclosure", "threat": "Publicly accessible storage buckets", "likelihood": 4, "impact": 5, "cwe": "CWE-552"},
        {"stride": "denial_of_service", "threat": "Storage quota exhaustion via unlimited uploads", "likelihood": 3, "impact": 3, "cwe": "CWE-400"},
        {"stride": "elevation_of_privilege", "threat": "Path traversal in file upload/download", "likelihood": 3, "impact": 4, "cwe": "CWE-22"},
    ],
    "container": [
        {"stride": "spoofing", "threat": "Compromised base image from untrusted registry", "likelihood": 3, "impact": 5, "cwe": "CWE-829"},
        {"stride": "tampering", "threat": "Container escape via kernel vulnerability", "likelihood": 2, "impact": 5, "cwe": "CWE-250"},
        {"stride": "information_disclosure", "threat": "Secrets hardcoded in container image layers", "likelihood": 4, "impact": 4, "cwe": "CWE-798"},
        {"stride": "denial_of_service", "threat": "Resource limits not set allowing noisy neighbor", "likelihood": 3, "impact": 3, "cwe": "CWE-770"},
        {"stride": "elevation_of_privilege", "threat": "Container running as root with host mounts", "likelihood": 3, "impact": 5, "cwe": "CWE-250"},
    ],
    "ci_cd_pipeline": [
        {"stride": "spoofing", "threat": "Compromised CI/CD credentials allowing impersonation", "likelihood": 3, "impact": 5, "cwe": "CWE-522"},
        {"stride": "tampering", "threat": "Build artifact manipulation in supply chain", "likelihood": 2, "impact": 5, "cwe": "CWE-494"},
        {"stride": "tampering", "threat": "Pipeline configuration injection", "likelihood": 3, "impact": 5, "cwe": "CWE-94"},
        {"stride": "information_disclosure", "threat": "Secrets exposed in build logs", "likelihood": 4, "impact": 4, "cwe": "CWE-532"},
        {"stride": "elevation_of_privilege", "threat": "Self-hosted runner compromise granting infrastructure access", "likelihood": 2, "impact": 5, "cwe": "CWE-269"},
    ],
}

# Default threat library for component types not explicitly listed
DEFAULT_THREATS: List[Dict[str, Any]] = [
    {"stride": "spoofing", "threat": "Weak or missing authentication", "likelihood": 3, "impact": 4, "cwe": "CWE-306"},
    {"stride": "tampering", "threat": "Missing input validation", "likelihood": 3, "impact": 4, "cwe": "CWE-20"},
    {"stride": "repudiation", "threat": "Insufficient logging and monitoring", "likelihood": 3, "impact": 3, "cwe": "CWE-778"},
    {"stride": "information_disclosure", "threat": "Sensitive data exposure", "likelihood": 3, "impact": 4, "cwe": "CWE-200"},
    {"stride": "denial_of_service", "threat": "Resource exhaustion", "likelihood": 3, "impact": 3, "cwe": "CWE-400"},
    {"stride": "elevation_of_privilege", "threat": "Insufficient authorization checks", "likelihood": 3, "impact": 4, "cwe": "CWE-285"},
]

# NIST SP 800-53 control mappings per STRIDE category
NIST_CONTROLS: Dict[str, List[Dict[str, str]]] = {
    "spoofing": [
        {"control_id": "IA-2", "name": "Identification and Authentication", "description": "Uniquely identify and authenticate organizational users"},
        {"control_id": "IA-5", "name": "Authenticator Management", "description": "Manage system authenticators (passwords, tokens, certificates)"},
        {"control_id": "SC-23", "name": "Session Authenticity", "description": "Protect the authenticity of communications sessions"},
        {"control_id": "IA-8", "name": "Identification and Authentication (Non-Org Users)", "description": "Authenticate non-organizational users"},
    ],
    "tampering": [
        {"control_id": "SI-7", "name": "Software, Firmware, and Information Integrity", "description": "Employ integrity verification tools to detect unauthorized changes"},
        {"control_id": "SC-8", "name": "Transmission Confidentiality and Integrity", "description": "Protect the integrity of transmitted information"},
        {"control_id": "SI-10", "name": "Information Input Validation", "description": "Check the validity of information inputs"},
        {"control_id": "CM-5", "name": "Access Restrictions for Change", "description": "Define and enforce access restrictions for system changes"},
    ],
    "repudiation": [
        {"control_id": "AU-2", "name": "Audit Events", "description": "Identify events that need to be audited"},
        {"control_id": "AU-3", "name": "Content of Audit Records", "description": "Produce audit records containing sufficient information"},
        {"control_id": "AU-6", "name": "Audit Review, Analysis, and Reporting", "description": "Review and analyze audit records for indications of inappropriate activity"},
        {"control_id": "AU-12", "name": "Audit Generation", "description": "Provide audit record generation capability"},
    ],
    "information_disclosure": [
        {"control_id": "SC-28", "name": "Protection of Information at Rest", "description": "Protect the confidentiality of information at rest"},
        {"control_id": "SC-8", "name": "Transmission Confidentiality and Integrity", "description": "Protect the confidentiality of transmitted information"},
        {"control_id": "AC-4", "name": "Information Flow Enforcement", "description": "Enforce approved authorizations for controlling information flow"},
        {"control_id": "SC-13", "name": "Cryptographic Protection", "description": "Implement FIPS-validated cryptography"},
    ],
    "denial_of_service": [
        {"control_id": "SC-5", "name": "Denial of Service Protection", "description": "Protect against or limit the effects of denial of service attacks"},
        {"control_id": "CP-9", "name": "Information System Backup", "description": "Conduct backups of system-level and user-level information"},
        {"control_id": "SC-6", "name": "Resource Availability", "description": "Protect the availability of resources by allocating them by priority"},
        {"control_id": "SI-17", "name": "Fail-Safe Procedures", "description": "Implement fail-safe procedures when failures occur"},
    ],
    "elevation_of_privilege": [
        {"control_id": "AC-6", "name": "Least Privilege", "description": "Employ the principle of least privilege"},
        {"control_id": "AC-3", "name": "Access Enforcement", "description": "Enforce approved authorizations for logical access"},
        {"control_id": "AC-5", "name": "Separation of Duties", "description": "Separate duties of individuals to prevent malicious activity"},
        {"control_id": "CM-7", "name": "Least Functionality", "description": "Configure the system to provide only essential capabilities"},
    ],
}

# Risk matrix: likelihood (1-5) x impact (1-5)
RISK_MATRIX = {
    (1, 1): ("negligible", 1), (1, 2): ("low", 2), (1, 3): ("low", 3), (1, 4): ("medium", 4), (1, 5): ("medium", 5),
    (2, 1): ("low", 2), (2, 2): ("low", 4), (2, 3): ("medium", 6), (2, 4): ("medium", 8), (2, 5): ("high", 10),
    (3, 1): ("low", 3), (3, 2): ("medium", 6), (3, 3): ("medium", 9), (3, 4): ("high", 12), (3, 5): ("high", 15),
    (4, 1): ("medium", 4), (4, 2): ("medium", 8), (4, 3): ("high", 12), (4, 4): ("high", 16), (4, 5): ("critical", 20),
    (5, 1): ("medium", 5), (5, 2): ("high", 10), (5, 3): ("high", 15), (5, 4): ("critical", 20), (5, 5): ("critical", 25),
}

class ThreatModelingSkill(BaseSecuritySkill):
    """Structured threat modeling using STRIDE and PASTA methodologies."""

    SKILL_NAME = "threat_modeling"
    DESCRIPTION = (
        "Perform structured threat modeling using STRIDE and PASTA methodologies, "
        "with automated threat identification, risk scoring, and NIST control mapping"
    )
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS = ["delta_red_team", "beta_4_devsecops"]
    REQUIRED_INTEGRATIONS = []

    async def _setup(self):
        self.models: Dict[str, Dict[str, Any]] = {}  # model_id -> model data
        self.threats: List[Dict[str, Any]] = []
        self.mitigations: List[Dict[str, Any]] = []

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        action = parameters.get("action", "create_model")

        dispatch = {
            "create_model": self._create_model,
            "analyze_stride": self._analyze_stride,
            "analyze_pasta": self._analyze_pasta,
            "identify_threats": self._identify_threats,
            "generate_mitigations": self._generate_mitigations,
            "assess_risk": self._assess_risk,
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
    # Create Threat Model
    # =========================================================================

    async def _create_model(self, params: Dict[str, Any]) -> SkillResult:
        """Create a new threat model with system components and data flows."""
        name = params.get("name", "")
        description = params.get("description", "")
        components = params.get("components", [])  # [{name, type, trust_level, description}]
        data_flows = params.get("data_flows", [])  # [{source, destination, data_type, protocol, crosses_trust_boundary}]
        trust_boundaries = params.get("trust_boundaries", [])  # [{name, description, components}]
        assumptions = params.get("assumptions", [])

        if not name:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'name' is required for the threat model"],
            )

        if not components:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["At least one component is required in 'components' list"],
            )

        model_id = f"TM-{uuid.uuid4().hex[:8]}"

        # Validate component types
        valid_types = {ct.value for ct in ComponentType}
        for comp in components:
            if comp.get("type") and comp["type"] not in valid_types:
                comp["type_warning"] = f"Unknown type '{comp['type']}'. Valid: {sorted(valid_types)}"

        # Identify trust boundary crossings in data flows
        boundary_components = {}
        for tb in trust_boundaries:
            for comp_name in tb.get("components", []):
                boundary_components[comp_name] = tb.get("name", "unknown")

        for flow in data_flows:
            src_boundary = boundary_components.get(flow.get("source", ""), "external")
            dst_boundary = boundary_components.get(flow.get("destination", ""), "external")
            flow["crosses_trust_boundary"] = flow.get("crosses_trust_boundary", src_boundary != dst_boundary)
            flow["source_trust_zone"] = src_boundary
            flow["destination_trust_zone"] = dst_boundary

        model = {
            "model_id": model_id,
            "name": name,
            "description": description,
            "created_at": datetime.now().isoformat(),
            "status": "draft",
            "components": components,
            "data_flows": data_flows,
            "trust_boundaries": trust_boundaries,
            "assumptions": assumptions,
            "threats": [],
            "mitigations": [],
            "risk_summary": None,
        }

        self.models[model_id] = model

        # Calculate attack surface metrics
        boundary_crossing_flows = sum(1 for f in data_flows if f.get("crosses_trust_boundary"))

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "model_id": model_id,
                "model": model,
                "metrics": {
                    "total_components": len(components),
                    "total_data_flows": len(data_flows),
                    "trust_boundaries": len(trust_boundaries),
                    "boundary_crossing_flows": boundary_crossing_flows,
                    "attack_surface_indicator": boundary_crossing_flows * len(components),
                },
            },
        )

    # =========================================================================
    # STRIDE Analysis
    # =========================================================================

    async def _analyze_stride(self, params: Dict[str, Any]) -> SkillResult:
        """Perform STRIDE analysis on a threat model or specific component."""
        model_id = params.get("model_id", "")
        component_filter = params.get("component")  # optional: analyze specific component

        model = self.models.get(model_id)
        if not model:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Threat model '{model_id}' not found. Create one first with 'create_model'."],
            )

        stride_results = []
        components = model["components"]
        if component_filter:
            components = [c for c in components if c.get("name") == component_filter]
            if not components:
                return SkillResult(
                    success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                    errors=[f"Component '{component_filter}' not found in model '{model_id}'."],
                )

        for component in components:
            comp_name = component.get("name", "unknown")
            comp_type = component.get("type", "")
            threats_for_type = THREAT_LIBRARY.get(comp_type, DEFAULT_THREATS)

            for category in StrideCategory:
                cat_threats = [t for t in threats_for_type if t["stride"] == category.value]
                stride_info = STRIDE_DESCRIPTIONS[category]

                for threat_entry in cat_threats:
                    likelihood = threat_entry.get("likelihood", 3)
                    impact = threat_entry.get("impact", 3)
                    risk_level, risk_score = RISK_MATRIX.get((likelihood, impact), ("medium", 9))

                    threat_record = {
                        "threat_id": f"THR-{uuid.uuid4().hex[:8]}",
                        "model_id": model_id,
                        "component": comp_name,
                        "component_type": comp_type,
                        "stride_category": category.value,
                        "stride_name": stride_info["name"],
                        "security_property": stride_info["security_property"],
                        "threat_description": threat_entry["threat"],
                        "cwe": threat_entry.get("cwe", ""),
                        "likelihood": likelihood,
                        "impact": impact,
                        "risk_level": risk_level,
                        "risk_score": risk_score,
                        "nist_controls": NIST_CONTROLS.get(category.value, []),
                    }
                    stride_results.append(threat_record)

            # Analyze data flows crossing trust boundaries for this component
            for flow in model.get("data_flows", []):
                if flow.get("crosses_trust_boundary") and (
                    flow.get("source") == comp_name or flow.get("destination") == comp_name
                ):
                    stride_results.append({
                        "threat_id": f"THR-{uuid.uuid4().hex[:8]}",
                        "model_id": model_id,
                        "component": comp_name,
                        "component_type": comp_type,
                        "stride_category": "tampering",
                        "stride_name": "Tampering",
                        "security_property": "Integrity",
                        "threat_description": (
                            f"Data flow '{flow.get('source')}' -> '{flow.get('destination')}' "
                            f"crosses trust boundary ({flow.get('source_trust_zone')} -> "
                            f"{flow.get('destination_trust_zone')}). "
                            f"Data type '{flow.get('data_type', 'unknown')}' via "
                            f"{flow.get('protocol', 'unknown')} may be intercepted or modified."
                        ),
                        "cwe": "CWE-319",
                        "likelihood": 3,
                        "impact": 4,
                        "risk_level": "high",
                        "risk_score": 12,
                        "nist_controls": NIST_CONTROLS["tampering"],
                        "data_flow": flow,
                    })

        # Store threats in model
        model["threats"].extend(stride_results)
        self.threats.extend(stride_results)

        # Summarize by category
        category_summary = {}
        for cat in StrideCategory:
            cat_threats = [t for t in stride_results if t["stride_category"] == cat.value]
            if cat_threats:
                category_summary[cat.value] = {
                    "count": len(cat_threats),
                    "highest_risk": max(t["risk_score"] for t in cat_threats),
                    "critical_count": sum(1 for t in cat_threats if t["risk_level"] == "critical"),
                    "high_count": sum(1 for t in cat_threats if t["risk_level"] == "high"),
                }

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "model_id": model_id,
                "methodology": "STRIDE",
                "threats": stride_results,
                "total_threats": len(stride_results),
                "category_summary": category_summary,
                "risk_distribution": {
                    level: sum(1 for t in stride_results if t["risk_level"] == level)
                    for level in ["critical", "high", "medium", "low", "negligible"]
                },
            },
            warnings=[
                f"Found {sum(1 for t in stride_results if t['risk_level'] == 'critical')} critical-risk threats requiring immediate attention"
            ] if any(t["risk_level"] == "critical" for t in stride_results) else [],
        )

    # =========================================================================
    # PASTA Analysis
    # =========================================================================

    async def _analyze_pasta(self, params: Dict[str, Any]) -> SkillResult:
        """Perform PASTA (Process for Attack Simulation and Threat Analysis) 7-stage analysis."""
        model_id = params.get("model_id", "")
        business_objectives = params.get("business_objectives", [])
        compliance_requirements = params.get("compliance_requirements", [])
        threat_actors = params.get("threat_actors", [])  # [{name, capability, motivation}]
        known_vulnerabilities = params.get("known_vulnerabilities", [])

        model = self.models.get(model_id)
        if not model:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Threat model '{model_id}' not found."],
            )

        stages: Dict[str, Dict[str, Any]] = {}

        # Stage 1: Define Business Objectives
        stages["stage_1_define_objectives"] = {
            "name": "Define Business Objectives",
            "status": "completed",
            "business_objectives": business_objectives or ["Protect customer data", "Maintain service availability", "Meet regulatory compliance"],
            "compliance_requirements": compliance_requirements or ["SOC 2 Type II", "GDPR"],
            "risk_appetite": params.get("risk_appetite", "moderate"),
        }

        # Stage 2: Define Technical Scope
        stages["stage_2_define_technical_scope"] = {
            "name": "Define Technical Scope",
            "status": "completed",
            "components": [c.get("name") for c in model["components"]],
            "component_types": list(set(c.get("type", "unknown") for c in model["components"])),
            "data_flows": len(model.get("data_flows", [])),
            "trust_boundaries": len(model.get("trust_boundaries", [])),
            "technologies_identified": list(set(
                c.get("type", "unknown") for c in model["components"]
            )),
        }

        # Stage 3: Application Decomposition
        dfd_elements = {
            "processes": [c for c in model["components"] if c.get("type") in ("web_application", "api_service", "microservice", "serverless_function")],
            "data_stores": [c for c in model["components"] if c.get("type") in ("database", "file_storage", "message_queue")],
            "external_entities": [c for c in model["components"] if c.get("type") in ("mobile_app", "network_gateway")],
            "data_flows": model.get("data_flows", []),
            "trust_boundaries": model.get("trust_boundaries", []),
        }
        stages["stage_3_application_decomposition"] = {
            "name": "Application Decomposition",
            "status": "completed",
            "dfd_elements": {k: len(v) for k, v in dfd_elements.items()},
            "entry_points": [
                f.get("source") for f in model.get("data_flows", [])
                if f.get("crosses_trust_boundary")
            ],
            "assets": self._identify_assets(model),
        }

        # Stage 4: Threat Analysis
        applicable_threat_actors = threat_actors or [
            {"name": "External Attacker", "capability": "medium", "motivation": "financial_gain"},
            {"name": "Insider Threat", "capability": "high", "motivation": "data_theft"},
            {"name": "Automated Scanner", "capability": "low", "motivation": "opportunistic"},
        ]
        relevant_threats = []
        for comp in model["components"]:
            comp_type = comp.get("type", "")
            comp_threats = THREAT_LIBRARY.get(comp_type, DEFAULT_THREATS)
            for t in comp_threats:
                relevant_threats.append({
                    "component": comp.get("name"),
                    "threat": t["threat"],
                    "stride": t["stride"],
                    "cwe": t.get("cwe", ""),
                })

        stages["stage_4_threat_analysis"] = {
            "name": "Threat Analysis",
            "status": "completed",
            "threat_actors": applicable_threat_actors,
            "relevant_threats": relevant_threats,
            "total_threats_identified": len(relevant_threats),
        }

        # Stage 5: Vulnerability Analysis
        vuln_analysis = []
        for comp in model["components"]:
            comp_type = comp.get("type", "")
            comp_threats = THREAT_LIBRARY.get(comp_type, DEFAULT_THREATS)
            for t in comp_threats:
                vuln_analysis.append({
                    "component": comp.get("name"),
                    "vulnerability_class": t["threat"],
                    "cwe": t.get("cwe", ""),
                    "exploitability": "high" if t.get("likelihood", 3) >= 4 else "medium" if t.get("likelihood", 3) >= 3 else "low",
                })
        if known_vulnerabilities:
            for vuln in known_vulnerabilities:
                vuln_analysis.append({
                    "component": vuln.get("component", "unknown"),
                    "vulnerability_class": vuln.get("description", "Known vulnerability"),
                    "cve": vuln.get("cve", ""),
                    "exploitability": vuln.get("exploitability", "unknown"),
                })

        stages["stage_5_vulnerability_analysis"] = {
            "name": "Vulnerability Analysis",
            "status": "completed",
            "vulnerabilities": vuln_analysis,
            "total_vulnerabilities": len(vuln_analysis),
            "known_cves": [v.get("cve") for v in known_vulnerabilities if v.get("cve")],
        }

        # Stage 6: Attack Modeling
        attack_trees = []
        for actor in applicable_threat_actors:
            for threat in relevant_threats[:5]:  # Top 5 threats per actor
                attack_trees.append({
                    "actor": actor["name"],
                    "goal": threat["threat"],
                    "target_component": threat["component"],
                    "attack_steps": self._generate_attack_steps(threat, actor),
                    "estimated_difficulty": actor.get("capability", "medium"),
                })

        stages["stage_6_attack_modeling"] = {
            "name": "Attack Modeling",
            "status": "completed",
            "attack_trees": attack_trees,
            "total_attack_scenarios": len(attack_trees),
        }

        # Stage 7: Risk and Impact Analysis
        risk_items = []
        for threat in relevant_threats:
            comp_type = next(
                (c.get("type", "") for c in model["components"] if c.get("name") == threat["component"]),
                ""
            )
            threat_data = next(
                (t for t in THREAT_LIBRARY.get(comp_type, DEFAULT_THREATS) if t["threat"] == threat["threat"]),
                {"likelihood": 3, "impact": 3}
            )
            likelihood = threat_data.get("likelihood", 3)
            impact = threat_data.get("impact", 3)
            risk_level, risk_score = RISK_MATRIX.get((likelihood, impact), ("medium", 9))
            risk_items.append({
                "threat": threat["threat"],
                "component": threat["component"],
                "likelihood": likelihood,
                "impact": impact,
                "risk_level": risk_level,
                "risk_score": risk_score,
                "business_impact": self._assess_business_impact(impact, business_objectives),
            })

        risk_items.sort(key=lambda x: x["risk_score"], reverse=True)

        stages["stage_7_risk_and_impact"] = {
            "name": "Risk and Impact Analysis",
            "status": "completed",
            "risk_items": risk_items,
            "aggregate_risk_score": sum(r["risk_score"] for r in risk_items),
            "risk_distribution": {
                level: sum(1 for r in risk_items if r["risk_level"] == level)
                for level in ["critical", "high", "medium", "low", "negligible"]
            },
            "top_risks": risk_items[:10],
        }

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "model_id": model_id,
                "methodology": "PASTA",
                "stages": stages,
                "summary": {
                    "total_threats": len(relevant_threats),
                    "total_vulnerabilities": len(vuln_analysis),
                    "total_attack_scenarios": len(attack_trees),
                    "aggregate_risk_score": stages["stage_7_risk_and_impact"]["aggregate_risk_score"],
                    "top_risk": risk_items[0] if risk_items else None,
                },
            },
        )

    # =========================================================================
    # Identify Threats
    # =========================================================================

    async def _identify_threats(self, params: Dict[str, Any]) -> SkillResult:
        """Identify threats for a component type using the built-in threat library."""
        component_type = params.get("component_type", "")
        component_name = params.get("component_name", component_type)
        custom_threats = params.get("custom_threats", [])

        threats = THREAT_LIBRARY.get(component_type, DEFAULT_THREATS)

        identified = []
        for t in threats:
            likelihood = t.get("likelihood", 3)
            impact = t.get("impact", 3)
            risk_level, risk_score = RISK_MATRIX.get((likelihood, impact), ("medium", 9))
            identified.append({
                "threat_id": f"THR-{uuid.uuid4().hex[:8]}",
                "component": component_name,
                "component_type": component_type,
                "stride_category": t["stride"],
                "description": t["threat"],
                "cwe": t.get("cwe", ""),
                "likelihood": likelihood,
                "impact": impact,
                "risk_level": risk_level,
                "risk_score": risk_score,
                "source": "threat_library",
            })

        for ct in custom_threats:
            likelihood = ct.get("likelihood", 3)
            impact = ct.get("impact", 3)
            risk_level, risk_score = RISK_MATRIX.get((likelihood, impact), ("medium", 9))
            identified.append({
                "threat_id": f"THR-{uuid.uuid4().hex[:8]}",
                "component": component_name,
                "component_type": component_type,
                "stride_category": ct.get("stride", "tampering"),
                "description": ct.get("threat", ct.get("description", "")),
                "cwe": ct.get("cwe", ""),
                "likelihood": likelihood,
                "impact": impact,
                "risk_level": risk_level,
                "risk_score": risk_score,
                "source": "custom",
            })

        identified.sort(key=lambda x: x["risk_score"], reverse=True)
        self.threats.extend(identified)

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "component": component_name,
                "component_type": component_type,
                "threats": identified,
                "total_threats": len(identified),
                "risk_distribution": {
                    level: sum(1 for t in identified if t["risk_level"] == level)
                    for level in ["critical", "high", "medium", "low", "negligible"]
                },
                "available_component_types": sorted(THREAT_LIBRARY.keys()),
            },
        )

    # =========================================================================
    # Generate Mitigations
    # =========================================================================

    async def _generate_mitigations(self, params: Dict[str, Any]) -> SkillResult:
        """Generate mitigation recommendations mapped to NIST controls for identified threats."""
        model_id = params.get("model_id")
        threat_ids = params.get("threat_ids", [])
        stride_filter = params.get("stride_category")

        # Gather threats to mitigate
        if model_id and model_id in self.models:
            target_threats = self.models[model_id].get("threats", [])
        elif threat_ids:
            target_threats = [t for t in self.threats if t.get("threat_id") in threat_ids]
        else:
            target_threats = self.threats

        if stride_filter:
            target_threats = [t for t in target_threats if t.get("stride_category") == stride_filter]

        if not target_threats:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["No threats found to generate mitigations for. Run STRIDE or identify_threats first."],
            )

        mitigations = []
        for threat in target_threats:
            stride_cat = threat.get("stride_category", "")
            nist_ctrls = NIST_CONTROLS.get(stride_cat, [])
            specific_mitigations = self._get_specific_mitigations(threat)

            mitigation = {
                "mitigation_id": f"MIT-{uuid.uuid4().hex[:8]}",
                "threat_id": threat.get("threat_id", ""),
                "threat_description": threat.get("threat_description", threat.get("description", "")),
                "component": threat.get("component", ""),
                "stride_category": stride_cat,
                "risk_level": threat.get("risk_level", "medium"),
                "risk_score": threat.get("risk_score", 0),
                "nist_controls": nist_ctrls,
                "specific_mitigations": specific_mitigations,
                "implementation_priority": self._get_implementation_priority(threat),
                "estimated_effort": self._estimate_effort(specific_mitigations),
            }
            mitigations.append(mitigation)

        mitigations.sort(key=lambda m: m["risk_score"], reverse=True)
        self.mitigations.extend(mitigations)

        if model_id and model_id in self.models:
            self.models[model_id]["mitigations"].extend(mitigations)

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "mitigations": mitigations,
                "total_mitigations": len(mitigations),
                "unique_nist_controls": list(set(
                    c["control_id"] for m in mitigations for c in m["nist_controls"]
                )),
                "priority_breakdown": {
                    p: sum(1 for m in mitigations if m["implementation_priority"] == p)
                    for p in ["immediate", "short_term", "medium_term", "long_term"]
                },
            },
        )

    # =========================================================================
    # Assess Risk
    # =========================================================================

    async def _assess_risk(self, params: Dict[str, Any]) -> SkillResult:
        """Assess risk using the likelihood x impact matrix."""
        model_id = params.get("model_id")
        likelihood = params.get("likelihood")  # 1-5
        impact = params.get("impact")  # 1-5
        threat_description = params.get("threat_description", "")

        # Single threat risk assessment
        if likelihood is not None and impact is not None:
            likelihood = max(1, min(5, int(likelihood)))
            impact = max(1, min(5, int(impact)))
            risk_level, risk_score = RISK_MATRIX.get((likelihood, impact), ("medium", 9))

            return SkillResult(
                success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                data={
                    "threat_description": threat_description,
                    "likelihood": likelihood,
                    "impact": impact,
                    "risk_level": risk_level,
                    "risk_score": risk_score,
                    "max_possible_score": 25,
                    "risk_percentage": round((risk_score / 25) * 100, 1),
                    "recommendation": self._risk_recommendation(risk_level),
                },
            )

        # Model-wide risk assessment
        if model_id and model_id in self.models:
            model = self.models[model_id]
            threats = model.get("threats", [])

            if not threats:
                return SkillResult(
                    success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                    errors=["No threats in model. Run analyze_stride or identify_threats first."],
                )

            total_score = sum(t.get("risk_score", 0) for t in threats)
            max_score = len(threats) * 25
            overall_risk_pct = round((total_score / max_score) * 100, 1) if max_score > 0 else 0

            component_risk = {}
            for t in threats:
                comp = t.get("component", "unknown")
                if comp not in component_risk:
                    component_risk[comp] = {"total_score": 0, "threat_count": 0, "highest": 0}
                component_risk[comp]["total_score"] += t.get("risk_score", 0)
                component_risk[comp]["threat_count"] += 1
                component_risk[comp]["highest"] = max(component_risk[comp]["highest"], t.get("risk_score", 0))

            model["risk_summary"] = {
                "overall_risk_percentage": overall_risk_pct,
                "total_risk_score": total_score,
                "threat_count": len(threats),
            }

            return SkillResult(
                success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                data={
                    "model_id": model_id,
                    "overall_risk_percentage": overall_risk_pct,
                    "total_risk_score": total_score,
                    "max_possible_score": max_score,
                    "threat_count": len(threats),
                    "risk_distribution": {
                        level: sum(1 for t in threats if t.get("risk_level") == level)
                        for level in ["critical", "high", "medium", "low", "negligible"]
                    },
                    "component_risk": component_risk,
                    "top_risks": sorted(threats, key=lambda t: t.get("risk_score", 0), reverse=True)[:10],
                    "risk_matrix": self._render_risk_matrix(),
                },
            )

        return SkillResult(
            success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            errors=["Provide 'likelihood' and 'impact' (1-5) or 'model_id' for a model-wide assessment."],
        )

    # =========================================================================
    # Generate Report
    # =========================================================================

    async def _generate_report(self, params: Dict[str, Any]) -> SkillResult:
        """Generate a comprehensive threat model report."""
        model_id = params.get("model_id", "")
        include_mitigations = params.get("include_mitigations", True)

        model = self.models.get(model_id)
        if not model:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Threat model '{model_id}' not found."],
            )

        threats = model.get("threats", [])
        mitigations_data = model.get("mitigations", [])

        severity_counts = {
            level: sum(1 for t in threats if t.get("risk_level") == level)
            for level in ["critical", "high", "medium", "low", "negligible"]
        }

        stride_counts = {
            cat.value: sum(1 for t in threats if t.get("stride_category") == cat.value)
            for cat in StrideCategory
        }

        report = {
            "report_id": f"RPT-{uuid.uuid4().hex[:8]}",
            "model_id": model_id,
            "model_name": model.get("name", ""),
            "generated_at": datetime.now().isoformat(),
            "executive_summary": {
                "total_components": len(model.get("components", [])),
                "total_data_flows": len(model.get("data_flows", [])),
                "trust_boundaries": len(model.get("trust_boundaries", [])),
                "total_threats": len(threats),
                "severity_breakdown": severity_counts,
                "stride_breakdown": stride_counts,
                "risk_summary": model.get("risk_summary"),
                "overall_assessment": self._overall_assessment(severity_counts),
            },
            "components": model.get("components", []),
            "data_flows": model.get("data_flows", []),
            "trust_boundaries": model.get("trust_boundaries", []),
            "threats_by_severity": {
                level: [t for t in threats if t.get("risk_level") == level]
                for level in ["critical", "high", "medium", "low", "negligible"]
            },
            "threats_by_stride": {
                cat.value: [t for t in threats if t.get("stride_category") == cat.value]
                for cat in StrideCategory
            },
            "assumptions": model.get("assumptions", []),
            "recommendations": self._generate_recommendations(threats, severity_counts),
        }

        if include_mitigations and mitigations_data:
            report["mitigations"] = mitigations_data
            report["mitigation_coverage"] = {
                "threats_with_mitigations": len(set(m.get("threat_id") for m in mitigations_data)),
                "threats_without_mitigations": len(threats) - len(set(m.get("threat_id") for m in mitigations_data)),
                "unique_nist_controls": list(set(
                    c["control_id"] for m in mitigations_data for c in m.get("nist_controls", [])
                )),
            }

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={"report": report},
        )

    # =========================================================================
    # Internal Helpers
    # =========================================================================

    def _identify_assets(self, model: Dict[str, Any]) -> List[Dict[str, str]]:
        """Identify assets from model components and data flows."""
        assets = []
        for comp in model.get("components", []):
            assets.append({
                "name": comp.get("name", ""),
                "type": "component",
                "classification": "high" if comp.get("type") in ("database", "auth_service", "file_storage") else "medium",
            })
        data_types = set()
        for flow in model.get("data_flows", []):
            dt = flow.get("data_type", "")
            if dt and dt not in data_types:
                data_types.add(dt)
                assets.append({"name": dt, "type": "data", "classification": "high" if "credential" in dt.lower() or "pii" in dt.lower() else "medium"})
        return assets

    def _generate_attack_steps(self, threat: Dict[str, Any], actor: Dict[str, Any]) -> List[str]:
        """Generate realistic attack steps for a threat scenario."""
        steps_map = {
            "spoofing": [
                "Enumerate authentication endpoints",
                "Test for weak credential policies",
                "Attempt credential reuse from known breaches",
                "Exploit authentication bypass vulnerabilities",
            ],
            "tampering": [
                "Intercept data in transit",
                "Identify input validation weaknesses",
                "Craft malicious payloads",
                "Verify data modification persists",
            ],
            "repudiation": [
                "Identify logging gaps in the application",
                "Perform actions during log rotation windows",
                "Manipulate timestamps or log entries if accessible",
            ],
            "information_disclosure": [
                "Enumerate application endpoints and error pages",
                "Test for verbose error messages",
                "Attempt directory traversal or IDOR",
                "Extract sensitive data from responses",
            ],
            "denial_of_service": [
                "Profile application resource consumption",
                "Identify computationally expensive operations",
                "Send concurrent requests to exhaust resources",
                "Verify service degradation",
            ],
            "elevation_of_privilege": [
                "Map access control boundaries",
                "Test for horizontal and vertical privilege escalation",
                "Attempt role manipulation in tokens/sessions",
                "Verify unauthorized access to protected resources",
            ],
        }
        return steps_map.get(threat.get("stride", ""), ["Reconnaissance", "Exploitation", "Verification"])

    def _assess_business_impact(self, impact: int, objectives: List[str]) -> str:
        """Map numeric impact to business impact description."""
        if impact >= 5:
            return "Severe: potential data breach, regulatory penalties, significant revenue loss"
        elif impact >= 4:
            return "Major: service disruption, customer trust erosion, compliance risk"
        elif impact >= 3:
            return "Moderate: limited data exposure, operational degradation"
        elif impact >= 2:
            return "Minor: minimal business disruption, internal impact only"
        return "Negligible: no significant business impact expected"

    def _get_specific_mitigations(self, threat: Dict[str, Any]) -> List[str]:
        """Return specific mitigation steps for a given threat."""
        stride_mitigations = {
            "spoofing": [
                "Implement multi-factor authentication (MFA)",
                "Enforce strong password policies with complexity requirements",
                "Use short-lived, cryptographically signed tokens (JWT with RS256)",
                "Implement account lockout after failed attempts",
                "Deploy mutual TLS for service-to-service authentication",
            ],
            "tampering": [
                "Validate and sanitize all inputs at trust boundaries",
                "Implement Content Security Policy (CSP) headers",
                "Use parameterized queries for all database operations",
                "Sign and verify data integrity using HMAC or digital signatures",
                "Enforce TLS 1.2+ for all data in transit",
            ],
            "repudiation": [
                "Implement comprehensive audit logging for all state-changing operations",
                "Use tamper-proof, append-only log storage",
                "Include user identity, timestamp, action, and resource in all log entries",
                "Forward logs to a centralized SIEM in real-time",
                "Implement digital signatures for critical transaction records",
            ],
            "information_disclosure": [
                "Encrypt sensitive data at rest using AES-256",
                "Implement proper error handling that masks internal details",
                "Apply field-level encryption for PII and credentials",
                "Configure strict CORS and security headers",
                "Conduct data classification and apply appropriate controls per level",
            ],
            "denial_of_service": [
                "Implement rate limiting and request throttling",
                "Deploy WAF rules for common DoS patterns",
                "Set resource quotas and connection limits",
                "Use CDN and load balancing for traffic distribution",
                "Implement circuit breakers for downstream dependencies",
            ],
            "elevation_of_privilege": [
                "Enforce principle of least privilege in all access decisions",
                "Implement role-based access control (RBAC) with regular reviews",
                "Validate authorization server-side for every request",
                "Use capability-based security tokens with minimal scope",
                "Conduct regular access control audits and penetration testing",
            ],
        }
        return stride_mitigations.get(threat.get("stride_category", ""), [
            "Review and harden the affected component",
            "Implement defense-in-depth controls",
            "Monitor for exploitation attempts",
        ])

    def _get_implementation_priority(self, threat: Dict[str, Any]) -> str:
        """Determine implementation priority based on risk score."""
        score = threat.get("risk_score", 0)
        if score >= 20:
            return "immediate"
        elif score >= 12:
            return "short_term"
        elif score >= 6:
            return "medium_term"
        return "long_term"

    def _estimate_effort(self, mitigations: List[str]) -> str:
        """Rough effort estimate based on number and type of mitigations."""
        count = len(mitigations)
        if count >= 5:
            return "high"
        elif count >= 3:
            return "medium"
        return "low"

    def _risk_recommendation(self, risk_level: str) -> str:
        """Return a recommendation based on risk level."""
        recommendations = {
            "critical": "Immediate remediation required. Escalate to security leadership. Do not deploy until mitigated.",
            "high": "Remediate before next release. Implement compensating controls if immediate fix is not possible.",
            "medium": "Plan remediation within current sprint/iteration. Monitor for exploitation attempts.",
            "low": "Address during regular maintenance. Document accepted risk if deferring.",
            "negligible": "Acceptable risk. Document and revisit during periodic threat model reviews.",
        }
        return recommendations.get(risk_level, "Review and assess further.")

    def _render_risk_matrix(self) -> Dict[str, Any]:
        """Return the risk matrix for reference."""
        return {
            "axes": {"x": "Impact (1-5)", "y": "Likelihood (1-5)"},
            "levels": {
                "critical": "Risk score 20-25 (red)",
                "high": "Risk score 10-16 (orange)",
                "medium": "Risk score 4-9 (yellow)",
                "low": "Risk score 2-4 (green)",
                "negligible": "Risk score 1 (blue)",
            },
            "formula": "Risk Score = Likelihood x Impact",
        }

    def _overall_assessment(self, severity_counts: Dict[str, int]) -> str:
        """Generate overall assessment text."""
        critical = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)
        total = sum(severity_counts.values())

        if critical > 0:
            return f"CRITICAL RISK: {critical} critical-risk threats identified requiring immediate attention. Total of {total} threats across all severity levels."
        elif high > 0:
            return f"HIGH RISK: {high} high-risk threats identified. Remediation should be prioritized. Total of {total} threats."
        elif total > 0:
            return f"MODERATE RISK: {total} threats identified, none at critical or high severity. Standard remediation timelines apply."
        return "LOW RISK: No significant threats identified in the current model."

    def _generate_recommendations(self, threats: List[Dict], severity_counts: Dict[str, int]) -> List[str]:
        """Generate strategic recommendations."""
        recs = []
        if severity_counts.get("critical", 0) > 0:
            recs.append("IMMEDIATE: Address all critical-risk threats before production deployment. Engage security engineering for review.")
        if severity_counts.get("high", 0) > 0:
            recs.append("Schedule high-risk threat remediation in the current development cycle.")

        stride_cats = set(t.get("stride_category", "") for t in threats)
        if "spoofing" in stride_cats:
            recs.append("Strengthen authentication controls across all trust boundary crossings.")
        if "elevation_of_privilege" in stride_cats:
            recs.append("Conduct an access control audit and enforce least-privilege across all components.")
        if "information_disclosure" in stride_cats:
            recs.append("Review data classification and ensure encryption at rest and in transit for sensitive data.")

        recs.extend([
            "Schedule regular threat model reviews (quarterly or after significant architecture changes).",
            "Integrate threat modeling into the SDLC — review models as part of design reviews.",
            "Track mitigation implementation and verify effectiveness through security testing.",
        ])
        return recs
