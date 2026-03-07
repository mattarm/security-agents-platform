"""
Systems API Routes
System management and analysis endpoints
"""

from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional, Dict, Any

router = APIRouter()

@router.get("/")
async def list_systems(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    environment: Optional[str] = Query(None, description="Filter by environment"),
    criticality: Optional[str] = Query(None, description="Filter by criticality"),
    owner_team: Optional[str] = Query(None, description="Filter by owner team")
):
    """List all systems with optional filtering"""
    
    # Mock data - would query knowledge graph
    systems = [
        {
            "id": "sys_001",
            "name": "core-api",
            "system_type": "microservice",
            "environment": "production",
            "criticality": "CRITICAL",
            "owner_team": "platform-team",
            "customer_facing": True,
            "uptime_requirement": 0.999,
            "estimated_users": 10000,
            "health_score": 0.95
        },
        {
            "id": "sys_002",
            "name": "user-service",
            "system_type": "microservice", 
            "environment": "production",
            "criticality": "HIGH",
            "owner_team": "user-team",
            "customer_facing": True,
            "uptime_requirement": 0.995,
            "estimated_users": 8500,
            "health_score": 0.89
        },
        {
            "id": "sys_003",
            "name": "analytics-pipeline",
            "system_type": "data_processing",
            "environment": "production", 
            "criticality": "MEDIUM",
            "owner_team": "data-team",
            "customer_facing": False,
            "uptime_requirement": 0.99,
            "estimated_users": 0,
            "health_score": 0.78
        }
    ]
    
    # Apply filters
    filtered_systems = systems
    
    if environment:
        filtered_systems = [s for s in filtered_systems if s["environment"] == environment]
    
    if criticality:
        filtered_systems = [s for s in filtered_systems if s["criticality"] == criticality]
    
    if owner_team:
        filtered_systems = [s for s in filtered_systems if s["owner_team"] == owner_team]
    
    # Apply pagination
    paginated_systems = filtered_systems[offset:offset + limit]
    
    return {
        "systems": paginated_systems,
        "total_count": len(filtered_systems),
        "limit": limit,
        "offset": offset
    }

@router.get("/{system_id}")
async def get_system(system_id: str):
    """Get detailed system information"""
    
    if system_id == "sys_001":
        return {
            "system": {
                "id": "sys_001",
                "name": "core-api",
                "system_type": "microservice",
                "environment": "production",
                "criticality": "CRITICAL",
                "owner_team": "platform-team",
                "business_owner": "john.doe@company.com",
                "customer_facing": True,
                "uptime_requirement": 0.999,
                "estimated_users": 10000
            },
            "customers_served": [
                {"id": "cust_001", "name": "Enterprise Corp", "tier": "ENTERPRISE"},
                {"id": "cust_002", "name": "Global Industries", "tier": "BUSINESS"}
            ],
            "dependencies": [
                {"id": "sys_002", "name": "user-service", "type": "service"},
                {"id": "db_001", "name": "core-database", "type": "database"}
            ],
            "dependents": [
                {"id": "sys_004", "name": "mobile-api", "type": "service"}
            ],
            "repositories": [
                {"id": "repo_001", "name": "core-platform-api", "url": "github.com/company/core-platform-api"}
            ],
            "cloud_resources": [
                {"id": "aws_001", "type": "EC2", "instance_type": "m5.large", "region": "us-east-1"},
                {"id": "aws_002", "type": "RDS", "engine": "postgresql", "region": "us-east-1"}
            ],
            "metrics": {
                "uptime": 0.998,
                "response_time_p95": 145,
                "error_rate": 0.001,
                "throughput_rps": 850
            }
        }
    else:
        raise HTTPException(status_code=404, detail="System not found")

@router.get("/{system_id}/blast-radius")
async def get_system_blast_radius(
    system_id: str,
    max_depth: int = Query(3, ge=1, le=10, description="Maximum dependency depth to analyze")
):
    """Calculate blast radius for system failure"""
    
    return {
        "system_id": system_id,
        "system_name": "core-api",
        "blast_radius": {
            "directly_affected_systems": 3,
            "total_affected_systems": 8,
            "affected_customers": 45,
            "total_revenue_at_risk": 12500000,
            "estimated_downtime_cost_per_hour": 75000
        },
        "affected_systems": [
            {
                "id": "sys_004", 
                "name": "mobile-api",
                "dependency_type": "hard",
                "customer_impact": "HIGH"
            },
            {
                "id": "sys_005",
                "name": "web-frontend", 
                "dependency_type": "hard",
                "customer_impact": "CRITICAL"
            },
            {
                "id": "sys_006",
                "name": "reporting-service",
                "dependency_type": "soft",
                "customer_impact": "MEDIUM"
            }
        ],
        "affected_customers": [
            {
                "id": "cust_001",
                "name": "Enterprise Corp",
                "contract_value": 2000000,
                "sla_impact": "violation"
            },
            {
                "id": "cust_002", 
                "name": "Global Industries",
                "contract_value": 500000,
                "sla_impact": "warning"
            }
        ],
        "mitigation_strategies": [
            "Implement circuit breaker pattern for dependent services",
            "Add redundancy to core-api infrastructure",
            "Create fallback mechanisms for critical customer flows"
        ]
    }

@router.get("/{system_id}/ownership")
async def get_system_ownership(system_id: str):
    """Get detailed ownership information for a system"""
    
    return {
        "system_id": system_id,
        "system_name": "core-api",
        "ownership": {
            "primary_team": {
                "name": "platform-team",
                "contact": "platform-team@company.com",
                "responsibility_scope": ["development", "deployment", "operations"]
            },
            "secondary_teams": [
                {
                    "name": "sre-team",
                    "contact": "sre-team@company.com", 
                    "responsibility_scope": ["infrastructure", "monitoring"]
                }
            ],
            "business_owner": {
                "name": "John Doe",
                "email": "john.doe@company.com",
                "role": "Product Manager"
            }
        },
        "escalation_path": [
            {"level": 1, "contact": "platform-team@company.com", "sla_minutes": 15},
            {"level": 2, "contact": "platform-manager@company.com", "sla_minutes": 60},
            {"level": 3, "contact": "engineering-director@company.com", "sla_minutes": 240}
        ],
        "on_call_schedule": {
            "primary": "platform-team",
            "backup": "sre-team", 
            "current_on_call": "alice@company.com"
        }
    }

@router.post("/{system_id}/health-check")
async def trigger_system_health_check(system_id: str):
    """Trigger comprehensive health check for a system"""
    
    return {
        "system_id": system_id,
        "health_check_initiated": True,
        "job_id": f"health_check_{system_id}_{int(datetime.utcnow().timestamp())}",
        "estimated_completion": "2 minutes",
        "checks_included": [
            "endpoint_availability",
            "database_connectivity", 
            "external_dependencies",
            "resource_utilization",
            "security_posture"
        ]
    }

@router.get("/teams/{team_name}/systems")
async def get_team_systems(team_name: str):
    """Get all systems owned by a specific team"""
    
    team_systems = {
        "platform-team": [
            {
                "id": "sys_001",
                "name": "core-api",
                "criticality": "CRITICAL",
                "environment": "production",
                "customer_count": 45,
                "health_score": 0.95
            },
            {
                "id": "sys_007",
                "name": "platform-gateway",
                "criticality": "HIGH", 
                "environment": "production",
                "customer_count": 156,
                "health_score": 0.92
            }
        ],
        "user-team": [
            {
                "id": "sys_002",
                "name": "user-service",
                "criticality": "HIGH",
                "environment": "production", 
                "customer_count": 156,
                "health_score": 0.89
            }
        ]
    }
    
    systems = team_systems.get(team_name, [])
    
    if not systems:
        raise HTTPException(status_code=404, detail=f"No systems found for team {team_name}")
    
    return {
        "team_name": team_name,
        "systems": systems,
        "total_systems": len(systems),
        "total_customers_affected": sum(s["customer_count"] for s in systems),
        "average_health_score": sum(s["health_score"] for s in systems) / len(systems)
    }