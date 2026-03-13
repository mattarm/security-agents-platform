#!/usr/bin/env python3
"""
Shared Security Models - Single source of truth for all agent data types.
All agents import from here instead of defining their own duplicates.
"""

from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict, field
from enum import Enum


# =============================================================================
# Enumerations
# =============================================================================

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IntelligenceType(Enum):
    THREAT_CAMPAIGN = "threat_campaign"
    VULNERABILITY = "vulnerability"
    INFRASTRUCTURE = "infrastructure"
    ACTOR_PROFILE = "actor_profile"
    IOC_ENRICHMENT = "ioc_enrichment"
    SUPPLY_CHAIN = "supply_chain"
    CORRELATION = "correlation"
    INCIDENT = "incident"
    PHISHING = "phishing"
    IDENTITY_THREAT = "identity_threat"
    COMPLIANCE = "compliance"
    METRICS = "metrics"


class Priority(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AgentType(Enum):
    ALPHA_4 = "alpha_4_threat_intel"
    BETA_4 = "beta_4_devsecops"
    GAMMA = "gamma_blue_team"
    DELTA = "delta_red_team"
    SIGMA = "sigma_metrics"


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentStatus(Enum):
    INITIALIZING = "initializing"
    ACTIVE = "active"
    BUSY = "busy"
    ERROR = "error"
    OFFLINE = "offline"


class IOCType(Enum):
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email_address"
    FILE_PATH = "file_path"


class AttackPhase(Enum):
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class ThreatActorCategory(Enum):
    APT = "advanced_persistent_threat"
    CRIMINAL = "criminal_organization"
    HACKTIVIST = "hacktivist_group"
    NATION_STATE = "nation_state"
    UNKNOWN = "unknown"


class MetricType(Enum):
    OUTCOME = "outcome"
    PERFORMANCE = "performance"
    ACTIVITY = "activity"
    RISK = "risk"


# =============================================================================
# Intelligence & Fusion Data Types
# =============================================================================

@dataclass
class IntelligencePacket:
    """Standardized intelligence packet for cross-agent communication."""
    packet_id: str
    source_agent: str
    target_agents: List[str]
    intelligence_type: IntelligenceType
    priority: Priority
    confidence: float  # 0-100
    timestamp: datetime
    data: Dict[str, Any]
    correlation_keys: List[str]
    expiry: Optional[datetime] = None
    processed_by: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CorrelationResult:
    """Result of cross-domain intelligence correlation."""
    correlation_id: str
    correlation_type: str
    confidence: float
    risk_score: float
    involved_packets: List[str]
    evidence: List[Dict[str, Any]]
    business_impact: str
    recommendations: List[str]
    created_at: datetime


# =============================================================================
# Task & Agent Management
# =============================================================================

@dataclass
class AnalysisRequest:
    """High-level analysis request submitted to the orchestrator."""
    request_id: str
    requester: str
    analysis_type: str  # comprehensive, threat_focused, vulnerability_focused, incident_response, phishing, red_team
    target: str
    priority: Priority
    parameters: Dict[str, Any]
    created_at: datetime
    estimated_duration: Optional[int] = None  # seconds


@dataclass
class SecurityTask:
    """Security analysis task for agent execution."""
    task_id: str
    task_type: str
    priority: Priority
    assigned_agent: str
    status: TaskStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    results: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AgentInfo:
    """Agent registration and runtime status."""
    agent_id: str
    agent_type: str
    status: AgentStatus
    capabilities: List[str]
    last_heartbeat: datetime
    tasks_completed: int = 0
    tasks_failed: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Threat Intelligence Data Types
# =============================================================================

@dataclass
class ThreatCampaign:
    """Threat campaign tracking."""
    campaign_id: str
    name: str
    threat_actor: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    ttps: List[str]
    iocs: List[str]
    target_industries: List[str]
    target_regions: List[str]
    attribution_evidence: List[Dict] = field(default_factory=list)
    risk_score: float = 0.0


@dataclass
class ThreatActorProfile:
    """Unified threat actor profile usable by all agents."""
    name: str
    aliases: List[str]
    category: ThreatActorCategory
    target_sectors: List[str]
    target_countries: List[str]
    mitre_techniques: List[str]
    confidence_score: float
    first_seen: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    intelligence_source: str = "platform"


@dataclass
class EnrichedIOC:
    """IOC enriched with intelligence context."""
    value: str
    ioc_type: IOCType
    threat_types: List[str]
    confidence_score: float
    related_campaigns: List[str] = field(default_factory=list)
    related_actors: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


# =============================================================================
# Vulnerability & DevSecOps Data Types
# =============================================================================

@dataclass
class SecurityVulnerability:
    """Comprehensive vulnerability representation."""
    vuln_id: str
    cvss_score: float
    severity: str
    category: str  # SAST, DAST, SCA, SECRET, CONFIG
    title: str
    description: str
    file_path: str
    remediation: str
    business_impact: str
    confidence: float
    cwe_id: Optional[str] = None
    line_number: Optional[int] = None
    code_context: Optional[str] = None
    proof_of_concept: Optional[str] = None
    false_positive_likelihood: float = 0.0


@dataclass
class SupplyChainRisk:
    """Supply chain security risk analysis."""
    component_name: str
    component_version: str
    risk_level: str
    vulnerability_count: int
    license_risk: str
    maintenance_status: str
    alternatives: List[str] = field(default_factory=list)
    mitigation_steps: List[str] = field(default_factory=list)
    sbom_entry: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Incident & Blue Team Data Types
# =============================================================================

@dataclass
class SecurityAlert:
    """Security alert data structure."""
    alert_id: str
    title: str
    description: str
    severity: Severity
    timestamp: datetime
    source_system: str
    iocs: List[str] = field(default_factory=list)
    affected_systems: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IncidentCase:
    """Incident response case."""
    case_id: str
    alert_id: str
    title: str
    severity: Severity
    status: str
    created_at: datetime
    assigned_analyst: Optional[str] = None
    containment_actions: List[str] = field(default_factory=list)
    investigation_notes: List[str] = field(default_factory=list)


# =============================================================================
# Red Team Data Types
# =============================================================================

@dataclass
class AttackTechnique:
    """MITRE ATT&CK technique definition."""
    technique_id: str
    name: str
    phase: AttackPhase
    description: str
    platforms: List[str]
    prerequisites: List[str] = field(default_factory=list)
    detection_methods: List[str] = field(default_factory=list)


@dataclass
class RedTeamOperation:
    """Red team operation configuration."""
    operation_id: str
    name: str
    target_environment: str
    adversary_profile: str
    start_time: datetime
    duration_hours: int
    status: str
    techniques: List[AttackTechnique] = field(default_factory=list)
    safety_controls: List[str] = field(default_factory=list)
    objectives: List[str] = field(default_factory=list)
    results: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackPath:
    """Attack path analysis result."""
    path_id: str
    source_node: str
    target_node: str
    steps: List[Dict[str, str]]
    risk_score: float
    estimated_time: int  # minutes
    difficulty: str


# =============================================================================
# Phishing & Email Security Data Types
# =============================================================================

@dataclass
class PhishingIndicator:
    """Phishing email analysis result."""
    indicator_id: str
    email_subject: str
    sender_address: str
    sender_domain: str
    recipient_count: int
    urls_extracted: List[str]
    attachments: List[Dict[str, str]]
    authentication_results: Dict[str, str]  # SPF, DKIM, DMARC
    risk_score: float
    classification: str  # phishing, spear_phishing, bec, credential_harvest, malware_delivery, clean
    confidence: float
    iocs_extracted: List[str] = field(default_factory=list)
    campaign_id: Optional[str] = None
    timestamp: Optional[datetime] = None


@dataclass
class PhishingCampaign:
    """Tracked phishing campaign."""
    campaign_id: str
    name: str
    first_seen: datetime
    last_seen: datetime
    total_emails: int
    unique_targets: int
    sender_infrastructure: List[str]
    payload_type: str  # credential_harvest, malware, bec
    lure_theme: str
    indicators: List[PhishingIndicator] = field(default_factory=list)
    attributed_actor: Optional[str] = None
    mitigation_status: str = "active"


# =============================================================================
# Skill Result Types
# =============================================================================

@dataclass
class SkillResult:
    """Standardized result from any skill execution."""
    success: bool
    skill_name: str
    agent_id: str
    data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    execution_time_ms: float = 0.0
    intelligence_packets: List[IntelligencePacket] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
