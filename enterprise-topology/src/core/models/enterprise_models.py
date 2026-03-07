"""
Enterprise Topology Models - Core Data Structures
Comprehensive models for enterprise technology governance
"""

from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field, validator
from decimal import Decimal

# ===== ENUMS =====

class CustomerTier(str, Enum):
    ENTERPRISE = "ENTERPRISE"
    BUSINESS = "BUSINESS" 
    STANDARD = "STANDARD"
    TRIAL = "TRIAL"

class SLATier(str, Enum):
    PLATINUM = "PLATINUM"  # 99.99% uptime
    GOLD = "GOLD"          # 99.9% uptime  
    SILVER = "SILVER"      # 99.5% uptime
    BRONZE = "BRONZE"      # 99% uptime

class CriticalityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class Environment(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"

class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    ORACLE = "oracle"

# ===== BUSINESS LAYER MODELS =====

class Customer(BaseModel):
    """Enterprise customer entity"""
    id: str
    name: str
    tier: CustomerTier
    contract_value: Decimal = Field(description="Annual contract value in USD")
    sla_tier: SLATier
    industry: Optional[str] = None
    region: Optional[str] = None
    contact_email: Optional[str] = None
    onboarding_date: Optional[datetime] = None
    renewal_date: Optional[datetime] = None
    health_score: Optional[float] = Field(None, ge=0, le=1, description="Customer health score 0-1")
    
    class Config:
        json_encoders = {
            Decimal: str,
            datetime: lambda v: v.isoformat()
        }

class Product(BaseModel):
    """Product or service offering"""
    id: str
    name: str
    description: Optional[str] = None
    revenue_contribution: Decimal = Field(description="Annual revenue contribution")
    customer_count: int = Field(description="Number of customers using this product")
    lifecycle_stage: str = Field(default="active", description="Product lifecycle stage")
    owner_team: Optional[str] = None

class SLARequirement(BaseModel):
    """Service Level Agreement requirements"""
    id: str
    customer_id: str
    product_id: str
    uptime_requirement: float = Field(ge=0, le=1, description="Required uptime percentage")
    response_time_ms: Optional[int] = Field(None, description="Max response time in milliseconds")
    recovery_time_minutes: Optional[int] = Field(None, description="Max recovery time in minutes")
    penalty_per_breach: Optional[Decimal] = None

# ===== PROCESS LAYER MODELS =====

class JiraProject(BaseModel):
    """JIRA project entity"""
    id: str
    key: str
    name: str
    project_type: str
    owner_team: str
    business_owner: Optional[str] = None
    customer_facing: bool = False
    priority_level: CriticalityLevel = CriticalityLevel.MEDIUM
    
class JiraIssue(BaseModel):
    """JIRA issue entity"""
    id: str
    key: str
    summary: str
    project_key: str
    issue_type: str
    status: str
    priority: str
    assignee: Optional[str] = None
    reporter: str
    created_date: datetime
    updated_date: datetime
    customer_impact: bool = False
    estimated_customer_count: Optional[int] = None

class ConfluenceSpace(BaseModel):
    """Confluence space entity"""
    id: str
    key: str
    name: str
    owner_team: str
    space_type: str = "global"
    last_updated: datetime
    page_count: Optional[int] = None

class ConfluencePage(BaseModel):
    """Confluence page entity"""
    id: str
    title: str
    space_key: str
    content_type: str = "page"
    author: str
    created_date: datetime
    last_modified: datetime
    version: int
    system_references: List[str] = Field(default_factory=list)
    process_references: List[str] = Field(default_factory=list)

# ===== TECHNOLOGY LAYER MODELS =====

class GitHubRepository(BaseModel):
    """GitHub repository entity"""
    id: str
    name: str
    full_name: str
    organization: str
    primary_language: Optional[str] = None
    owner_team: str
    codeowners: List[str] = Field(default_factory=list)
    is_private: bool = True
    default_branch: str = "main"
    last_commit_date: Optional[datetime] = None
    open_issues_count: Optional[int] = None
    security_score: Optional[float] = Field(None, ge=0, le=1)

class CloudResource(BaseModel):
    """Cloud resource entity"""
    id: str
    resource_id: str
    resource_type: str
    provider: CloudProvider
    region: str
    environment: Environment
    owner_team: str
    customer_tags: List[str] = Field(default_factory=list)
    monthly_cost: Optional[Decimal] = None
    criticality: CriticalityLevel = CriticalityLevel.MEDIUM
    compliance_tags: List[str] = Field(default_factory=list)

class SecurityAsset(BaseModel):
    """CrowdStrike security asset"""
    id: str
    device_id: str
    hostname: str
    os_type: str
    os_version: Optional[str] = None
    ip_address: Optional[str] = None
    environment: Environment
    owner_team: str
    customer_context: List[str] = Field(default_factory=list)
    last_seen: datetime
    security_posture_score: Optional[float] = Field(None, ge=0, le=1)

class System(BaseModel):
    """Application system entity"""
    id: str
    name: str
    system_type: str
    environment: Environment
    criticality: CriticalityLevel
    owner_team: str
    business_owner: Optional[str] = None
    customer_facing: bool = False
    uptime_requirement: Optional[float] = Field(None, ge=0, le=1)
    estimated_users: Optional[int] = None

# ===== PEOPLE LAYER MODELS =====

class Team(BaseModel):
    """Team entity"""
    id: str
    name: str
    department: str
    manager: Optional[str] = None
    contact_email: Optional[str] = None
    timezone: str = "UTC"
    on_call_rotation: bool = False
    expertise_areas: List[str] = Field(default_factory=list)
    capacity_utilization: Optional[float] = Field(None, ge=0, le=1)

class Person(BaseModel):
    """Individual person entity"""
    id: str
    name: str
    email: str
    team_id: str
    role: str
    expertise_areas: List[str] = Field(default_factory=list)
    timezone: str = "UTC"
    is_on_call: bool = False

# ===== RELATIONSHIP MODELS =====

class Relationship(BaseModel):
    """Base relationship model"""
    source_id: str
    target_id: str
    relationship_type: str
    strength: float = Field(1.0, ge=0, le=1, description="Relationship strength 0-1")
    created_date: datetime = Field(default_factory=datetime.now)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class CustomerImpactRelationship(Relationship):
    """Customer impact relationship"""
    estimated_impact_score: float = Field(ge=0, le=1)
    revenue_at_risk: Optional[Decimal] = None
    sla_implications: Optional[List[str]] = None

class OwnershipRelationship(Relationship):
    """Technology ownership relationship"""
    ownership_type: str = Field(description="primary, secondary, backup")
    responsibility_scope: List[str] = Field(default_factory=list)

class DependencyRelationship(Relationship):
    """System dependency relationship"""
    dependency_type: str = Field(description="hard, soft, optional")
    failure_impact: CriticalityLevel = CriticalityLevel.MEDIUM
    
# ===== ANALYSIS MODELS =====

class CustomerImpactAssessment(BaseModel):
    """Customer impact analysis result"""
    customer_id: str
    technology_footprint_size: int
    risk_exposure_score: float = Field(ge=0, le=1)
    monthly_infrastructure_cost: Decimal
    sla_compliance_rate: float = Field(ge=0, le=1)
    security_posture_score: float = Field(ge=0, le=1)
    overall_health_score: float = Field(ge=0, le=1)
    recommendations: List[str] = Field(default_factory=list)

class TechnologyOwnershipGap(BaseModel):
    """Technology ownership gap analysis"""
    technology_id: str
    technology_name: str
    gap_type: str = Field(description="missing_owner, unclear_owner, multiple_owners")
    customer_impact: CriticalityLevel
    recommended_action: str
    estimated_resolution_effort_hours: Optional[int] = None

class RiskAssessment(BaseModel):
    """Risk assessment result"""
    asset_id: str
    asset_name: str
    risk_score: float = Field(ge=0, le=1)
    risk_factors: List[str]
    customer_exposure: List[str]
    mitigation_recommendations: List[str]
    estimated_mitigation_cost: Optional[Decimal] = None

# ===== DASHBOARD MODELS =====

class EnterpriseDashboardData(BaseModel):
    """Enterprise dashboard data model"""
    total_customers: int
    total_revenue: Decimal
    total_systems: int
    total_repositories: int
    total_cloud_resources: int
    average_customer_health: float
    sla_compliance_rate: float
    security_posture_average: float
    top_risks: List[RiskAssessment]
    ownership_gaps: List[TechnologyOwnershipGap]
    customer_impact_summary: List[CustomerImpactAssessment]

class QueryResult(BaseModel):
    """Generic query result model"""
    query_type: str
    execution_time_ms: int
    result_count: int
    results: List[Dict[str, Any]]
    metadata: Dict[str, Any] = Field(default_factory=dict)

# ===== CONFIGURATION MODELS =====

class PlatformConfig(BaseModel):
    """Platform integration configuration"""
    platform_name: str
    enabled: bool
    base_url: str
    auth_type: str = "oauth"
    rate_limit_per_minute: int = 60
    timeout_seconds: int = 30
    retry_attempts: int = 3

class EnterpriseConfig(BaseModel):
    """Main enterprise configuration"""
    organization_name: str
    platforms: Dict[str, PlatformConfig]
    neo4j_config: Dict[str, Any]
    kafka_config: Dict[str, Any]
    redis_config: Dict[str, Any]
    dashboard_config: Dict[str, Any]