"""
Enterprise Knowledge Graph Implementation
Neo4j-based knowledge graph for enterprise technology topology
"""

import asyncio
from typing import List, Dict, Any, Optional, Union, Tuple
from datetime import datetime
import logging
from neo4j import GraphDatabase, basic_auth
from neo4j.exceptions import ServiceUnavailable, TransientError

from ..models.enterprise_models import (
    Customer, Product, SLARequirement,
    JiraProject, JiraIssue, ConfluenceSpace, ConfluencePage,
    GitHubRepository, CloudResource, SecurityAsset, System,
    Team, Person, Relationship, CustomerImpactAssessment
)

logger = logging.getLogger(__name__)

class EnterpriseKnowledgeGraph:
    """Enterprise technology topology knowledge graph"""
    
    def __init__(self, uri: str, user: str, password: str):
        """Initialize Neo4j connection"""
        self.driver = GraphDatabase.driver(uri, auth=basic_auth(user, password))
        self.session = None
        
    async def initialize_schema(self) -> bool:
        """Initialize the enterprise graph schema"""
        try:
            async with self.driver.session() as session:
                # Create indexes for performance
                await self._create_indexes(session)
                
                # Create constraints for data integrity
                await self._create_constraints(session)
                
                # Create initial schema nodes
                await self._create_schema_nodes(session)
                
            logger.info("Enterprise knowledge graph schema initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize schema: {e}")
            return False
    
    async def _create_indexes(self, session) -> None:
        """Create performance indexes"""
        indexes = [
            # Customer indexes
            "CREATE INDEX customer_id IF NOT EXISTS FOR (c:Customer) ON (c.id)",
            "CREATE INDEX customer_name IF NOT EXISTS FOR (c:Customer) ON (c.name)",
            "CREATE INDEX customer_tier IF NOT EXISTS FOR (c:Customer) ON (c.tier)",
            
            # Product indexes
            "CREATE INDEX product_id IF NOT EXISTS FOR (p:Product) ON (p.id)",
            "CREATE INDEX product_name IF NOT EXISTS FOR (p:Product) ON (p.name)",
            
            # JIRA indexes
            "CREATE INDEX jira_project_key IF NOT EXISTS FOR (jp:JiraProject) ON (jp.key)",
            "CREATE INDEX jira_issue_key IF NOT EXISTS FOR (ji:JiraIssue) ON (ji.key)",
            
            # GitHub indexes
            "CREATE INDEX github_repo_name IF NOT EXISTS FOR (gr:GitHubRepository) ON (gr.name)",
            "CREATE INDEX github_repo_owner IF NOT EXISTS FOR (gr:GitHubRepository) ON (gr.owner_team)",
            
            # Cloud resource indexes
            "CREATE INDEX cloud_resource_id IF NOT EXISTS FOR (cr:CloudResource) ON (cr.resource_id)",
            "CREATE INDEX cloud_provider IF NOT EXISTS FOR (cr:CloudResource) ON (cr.provider)",
            
            # Security asset indexes
            "CREATE INDEX security_asset_device IF NOT EXISTS FOR (sa:SecurityAsset) ON (sa.device_id)",
            "CREATE INDEX security_asset_hostname IF NOT EXISTS FOR (sa:SecurityAsset) ON (sa.hostname)",
            
            # System indexes
            "CREATE INDEX system_name IF NOT EXISTS FOR (s:System) ON (s.name)",
            "CREATE INDEX system_criticality IF NOT EXISTS FOR (s:System) ON (s.criticality)",
            
            # Team indexes
            "CREATE INDEX team_name IF NOT EXISTS FOR (t:Team) ON (t.name)",
            "CREATE INDEX person_email IF NOT EXISTS FOR (p:Person) ON (p.email)"
        ]
        
        for index_query in indexes:
            await session.run(index_query)
    
    async def _create_constraints(self, session) -> None:
        """Create data integrity constraints"""
        constraints = [
            # Unique constraints
            "CREATE CONSTRAINT customer_id_unique IF NOT EXISTS FOR (c:Customer) REQUIRE c.id IS UNIQUE",
            "CREATE CONSTRAINT product_id_unique IF NOT EXISTS FOR (p:Product) REQUIRE p.id IS UNIQUE",
            "CREATE CONSTRAINT jira_project_key_unique IF NOT EXISTS FOR (jp:JiraProject) REQUIRE jp.key IS UNIQUE",
            "CREATE CONSTRAINT github_repo_id_unique IF NOT EXISTS FOR (gr:GitHubRepository) REQUIRE gr.id IS UNIQUE",
            "CREATE CONSTRAINT cloud_resource_id_unique IF NOT EXISTS FOR (cr:CloudResource) REQUIRE cr.resource_id IS UNIQUE",
            "CREATE CONSTRAINT security_asset_device_unique IF NOT EXISTS FOR (sa:SecurityAsset) REQUIRE sa.device_id IS UNIQUE",
            "CREATE CONSTRAINT system_id_unique IF NOT EXISTS FOR (s:System) REQUIRE s.id IS UNIQUE",
            "CREATE CONSTRAINT team_id_unique IF NOT EXISTS FOR (t:Team) REQUIRE t.id IS UNIQUE",
            "CREATE CONSTRAINT person_id_unique IF NOT EXISTS FOR (p:Person) REQUIRE p.id IS UNIQUE",
        ]
        
        for constraint_query in constraints:
            await session.run(constraint_query)
    
    async def _create_schema_nodes(self, session) -> None:
        """Create initial schema and metadata nodes"""
        schema_query = """
        // Create schema metadata
        MERGE (schema:Schema {name: 'EnterpriseTopology', version: '1.0'})
        SET schema.created_date = datetime(),
            schema.description = 'Enterprise Technology Topology Knowledge Graph'
        
        // Create node type metadata
        MERGE (customer_type:NodeType {name: 'Customer'})
        MERGE (product_type:NodeType {name: 'Product'})  
        MERGE (jira_type:NodeType {name: 'JiraProject'})
        MERGE (github_type:NodeType {name: 'GitHubRepository'})
        MERGE (cloud_type:NodeType {name: 'CloudResource'})
        MERGE (security_type:NodeType {name: 'SecurityAsset'})
        MERGE (system_type:NodeType {name: 'System'})
        MERGE (team_type:NodeType {name: 'Team'})
        """
        
        await session.run(schema_query)

    # ===== CUSTOMER OPERATIONS =====
    
    async def create_customer(self, customer: Customer) -> bool:
        """Create or update customer node"""
        query = """
        MERGE (c:Customer {id: $id})
        SET c.name = $name,
            c.tier = $tier,
            c.contract_value = $contract_value,
            c.sla_tier = $sla_tier,
            c.industry = $industry,
            c.region = $region,
            c.contact_email = $contact_email,
            c.onboarding_date = $onboarding_date,
            c.renewal_date = $renewal_date,
            c.health_score = $health_score,
            c.updated_date = datetime()
        RETURN c.id as customer_id
        """
        
        try:
            async with self.driver.session() as session:
                result = await session.run(query, **customer.dict())
                record = await result.single()
                return record is not None
        except Exception as e:
            logger.error(f"Failed to create customer {customer.id}: {e}")
            return False

    async def get_customer_technology_footprint(self, customer_id: str) -> Dict[str, Any]:
        """Get complete technology footprint for a customer"""
        query = """
        MATCH (customer:Customer {id: $customer_id})
        
        // Get all systems serving this customer
        OPTIONAL MATCH (customer)<-[:SERVES]-(system:System)
        
        // Get repositories related to customer systems
        OPTIONAL MATCH (system)<-[:DEPLOYED_TO]-(repo:GitHubRepository)
        
        // Get cloud resources for customer systems
        OPTIONAL MATCH (system)<-[:RUNS_ON]-(resource:CloudResource)
        
        // Get security assets monitoring customer systems
        OPTIONAL MATCH (system)<-[:MONITORS]-(asset:SecurityAsset)
        
        // Get teams responsible for customer technology
        OPTIONAL MATCH (system)-[:OWNED_BY]->(team:Team)
        
        RETURN customer,
               collect(DISTINCT system) as systems,
               collect(DISTINCT repo) as repositories,
               collect(DISTINCT resource) as cloud_resources,
               collect(DISTINCT asset) as security_assets,
               collect(DISTINCT team) as responsible_teams
        """
        
        try:
            async with self.driver.session() as session:
                result = await session.run(query, customer_id=customer_id)
                record = await result.single()
                
                if record:
                    return {
                        "customer": dict(record["customer"]),
                        "systems": [dict(s) for s in record["systems"]],
                        "repositories": [dict(r) for r in record["repositories"]],
                        "cloud_resources": [dict(cr) for cr in record["cloud_resources"]],
                        "security_assets": [dict(sa) for sa in record["security_assets"]],
                        "responsible_teams": [dict(t) for t in record["responsible_teams"]]
                    }
                return {}
        except Exception as e:
            logger.error(f"Failed to get customer footprint for {customer_id}: {e}")
            return {}

    # ===== SYSTEM OPERATIONS =====
    
    async def create_system(self, system: System) -> bool:
        """Create or update system node"""
        query = """
        MERGE (s:System {id: $id})
        SET s.name = $name,
            s.system_type = $system_type,
            s.environment = $environment,
            s.criticality = $criticality,
            s.owner_team = $owner_team,
            s.business_owner = $business_owner,
            s.customer_facing = $customer_facing,
            s.uptime_requirement = $uptime_requirement,
            s.estimated_users = $estimated_users,
            s.updated_date = datetime()
        RETURN s.id as system_id
        """
        
        try:
            async with self.driver.session() as session:
                result = await session.run(query, **system.dict())
                record = await result.single()
                return record is not None
        except Exception as e:
            logger.error(f"Failed to create system {system.id}: {e}")
            return False

    # ===== RELATIONSHIP OPERATIONS =====
    
    async def create_customer_system_relationship(self, customer_id: str, system_id: str, 
                                                  relationship_metadata: Dict[str, Any] = None) -> bool:
        """Create relationship between customer and system"""
        query = """
        MATCH (c:Customer {id: $customer_id})
        MATCH (s:System {id: $system_id})
        MERGE (s)-[r:SERVES]->(c)
        SET r.created_date = datetime()
        """
        
        if relationship_metadata:
            for key, value in relationship_metadata.items():
                query += f", r.{key} = ${key}"
        
        query += " RETURN r"
        
        try:
            async with self.driver.session() as session:
                params = {"customer_id": customer_id, "system_id": system_id}
                if relationship_metadata:
                    params.update(relationship_metadata)
                
                result = await session.run(query, **params)
                record = await result.single()
                return record is not None
        except Exception as e:
            logger.error(f"Failed to create customer-system relationship: {e}")
            return False

    async def create_ownership_relationship(self, technology_id: str, team_id: str, 
                                          ownership_type: str = "primary") -> bool:
        """Create ownership relationship between team and technology"""
        query = """
        MATCH (tech) WHERE tech.id = $technology_id
        MATCH (t:Team {id: $team_id})
        MERGE (tech)-[r:OWNED_BY]->(t)
        SET r.ownership_type = $ownership_type,
            r.created_date = datetime()
        RETURN r
        """
        
        try:
            async with self.driver.session() as session:
                result = await session.run(query, 
                    technology_id=technology_id,
                    team_id=team_id, 
                    ownership_type=ownership_type
                )
                record = await result.single()
                return record is not None
        except Exception as e:
            logger.error(f"Failed to create ownership relationship: {e}")
            return False

    # ===== ANALYSIS OPERATIONS =====
    
    async def analyze_customer_risk_exposure(self, customer_id: str) -> Dict[str, Any]:
        """Analyze risk exposure for a customer"""
        query = """
        MATCH (customer:Customer {id: $customer_id})
        MATCH (customer)<-[:SERVES]-(system:System)
        
        // Get security vulnerabilities affecting customer
        OPTIONAL MATCH (system)<-[:MONITORS]-(asset:SecurityAsset)-[:HAS_VULNERABILITY]->(vuln:Vulnerability)
        
        // Get system dependencies and potential blast radius
        OPTIONAL MATCH (system)-[:DEPENDS_ON*1..3]->(dependency:System)
        
        // Get compliance requirements
        OPTIONAL MATCH (system)-[:MUST_COMPLY_WITH]->(compliance:ComplianceRequirement)
        
        RETURN customer.name as customer_name,
               customer.contract_value as contract_value,
               count(DISTINCT system) as total_systems,
               count(DISTINCT vuln) as total_vulnerabilities,
               count(DISTINCT dependency) as dependency_count,
               count(DISTINCT compliance) as compliance_requirements,
               collect(DISTINCT vuln.severity) as vulnerability_severities,
               avg(system.criticality) as average_system_criticality
        """
        
        try:
            async with self.driver.session() as session:
                result = await session.run(query, customer_id=customer_id)
                record = await result.single()
                
                if record:
                    # Calculate risk score based on multiple factors
                    vuln_count = record["total_vulnerabilities"]
                    dependency_count = record["dependency_count"]
                    avg_criticality = record["average_system_criticality"] or 0
                    
                    # Simple risk scoring algorithm
                    risk_score = min(1.0, (vuln_count * 0.1 + dependency_count * 0.05 + avg_criticality * 0.3) / 3.0)
                    
                    return {
                        "customer_name": record["customer_name"],
                        "contract_value": record["contract_value"],
                        "total_systems": record["total_systems"],
                        "total_vulnerabilities": vuln_count,
                        "dependency_count": dependency_count,
                        "compliance_requirements": record["compliance_requirements"],
                        "vulnerability_severities": record["vulnerability_severities"],
                        "calculated_risk_score": risk_score
                    }
                return {}
        except Exception as e:
            logger.error(f"Failed to analyze customer risk for {customer_id}: {e}")
            return {}

    async def find_technology_ownership_gaps(self) -> List[Dict[str, Any]]:
        """Find technology without clear ownership"""
        query = """
        // Find systems without owners
        MATCH (s:System)
        WHERE NOT exists((s)-[:OWNED_BY]->(:Team))
        
        // Get customer impact for unowned systems
        OPTIONAL MATCH (s)-[:SERVES]->(customer:Customer)
        
        RETURN s.id as system_id,
               s.name as system_name,
               s.criticality as criticality,
               s.customer_facing as customer_facing,
               collect(customer.name) as affected_customers,
               'missing_owner' as gap_type
        
        UNION
        
        // Find systems with multiple primary owners
        MATCH (s:System)-[r:OWNED_BY {ownership_type: 'primary'}]->(t:Team)
        WITH s, count(t) as owner_count
        WHERE owner_count > 1
        
        OPTIONAL MATCH (s)-[:SERVES]->(customer:Customer)
        
        RETURN s.id as system_id,
               s.name as system_name,
               s.criticality as criticality,
               s.customer_facing as customer_facing,
               collect(customer.name) as affected_customers,
               'multiple_owners' as gap_type
        """
        
        try:
            async with self.driver.session() as session:
                result = await session.run(query)
                gaps = []
                
                async for record in result:
                    gaps.append({
                        "system_id": record["system_id"],
                        "system_name": record["system_name"],
                        "criticality": record["criticality"],
                        "customer_facing": record["customer_facing"],
                        "affected_customers": record["affected_customers"],
                        "gap_type": record["gap_type"]
                    })
                
                return gaps
        except Exception as e:
            logger.error(f"Failed to find ownership gaps: {e}")
            return []

    async def calculate_blast_radius(self, system_id: str, max_depth: int = 3) -> Dict[str, Any]:
        """Calculate blast radius for a system failure"""
        query = """
        MATCH (source:System {id: $system_id})
        
        // Find all systems that depend on this system
        MATCH (source)<-[:DEPENDS_ON*1..$max_depth]-(affected:System)
        
        // Get customers served by affected systems
        OPTIONAL MATCH (affected)-[:SERVES]->(customer:Customer)
        
        // Get teams responsible for affected systems
        OPTIONAL MATCH (affected)-[:OWNED_BY]->(team:Team)
        
        RETURN source.name as source_system,
               collect(DISTINCT affected.name) as affected_systems,
               collect(DISTINCT customer.name) as affected_customers,
               collect(DISTINCT team.name) as responsible_teams,
               count(DISTINCT affected) as total_affected_systems,
               count(DISTINCT customer) as total_affected_customers,
               sum(customer.contract_value) as total_revenue_at_risk
        """
        
        try:
            async with self.driver.session() as session:
                result = await session.run(query, system_id=system_id, max_depth=max_depth)
                record = await result.single()
                
                if record:
                    return {
                        "source_system": record["source_system"],
                        "affected_systems": record["affected_systems"],
                        "affected_customers": record["affected_customers"],
                        "responsible_teams": record["responsible_teams"],
                        "total_affected_systems": record["total_affected_systems"],
                        "total_affected_customers": record["total_affected_customers"],
                        "total_revenue_at_risk": record["total_revenue_at_risk"]
                    }
                return {}
        except Exception as e:
            logger.error(f"Failed to calculate blast radius for {system_id}: {e}")
            return {}

    # ===== UTILITY OPERATIONS =====
    
    async def health_check(self) -> bool:
        """Check Neo4j connection health"""
        try:
            async with self.driver.session() as session:
                result = await session.run("RETURN 1 as health")
                record = await result.single()
                return record["health"] == 1
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False
    
    async def get_graph_statistics(self) -> Dict[str, Any]:
        """Get overall graph statistics"""
        query = """
        // Count nodes by type
        CALL apoc.meta.stats() YIELD labels, relTypesCount
        RETURN labels, relTypesCount
        """
        
        try:
            async with self.driver.session() as session:
                result = await session.run(query)
                record = await result.single()
                
                if record:
                    return {
                        "node_counts": dict(record["labels"]),
                        "relationship_counts": dict(record["relTypesCount"]),
                        "total_nodes": sum(record["labels"].values()),
                        "total_relationships": sum(record["relTypesCount"].values())
                    }
                return {}
        except Exception as e:
            # Fallback to basic counts if APOC is not available
            basic_query = """
            MATCH (n) RETURN count(n) as node_count
            """
            async with self.driver.session() as session:
                result = await session.run(basic_query)
                record = await result.single()
                return {"total_nodes": record["node_count"] if record else 0}
    
    def close(self):
        """Close Neo4j driver"""
        if self.driver:
            self.driver.close()

# ===== UTILITY FUNCTIONS =====

async def create_demo_data(graph: EnterpriseKnowledgeGraph) -> bool:
    """Create demo data for testing and demonstration"""
    try:
        # Create demo customers
        customers = [
            Customer(
                id="cust_001",
                name="Enterprise Corp",
                tier="ENTERPRISE",
                contract_value=2000000,
                sla_tier="PLATINUM",
                industry="Technology",
                region="North America"
            ),
            Customer(
                id="cust_002", 
                name="Global Industries",
                tier="BUSINESS",
                contract_value=500000,
                sla_tier="GOLD",
                industry="Manufacturing",
                region="Europe"
            )
        ]
        
        for customer in customers:
            await graph.create_customer(customer)
        
        # Create demo systems
        systems = [
            System(
                id="sys_001",
                name="core-api",
                system_type="microservice",
                environment="production",
                criticality="CRITICAL",
                owner_team="platform-team",
                customer_facing=True
            ),
            System(
                id="sys_002",
                name="user-service", 
                system_type="microservice",
                environment="production",
                criticality="HIGH",
                owner_team="user-team",
                customer_facing=True
            )
        ]
        
        for system in systems:
            await graph.create_system(system)
        
        # Create customer-system relationships
        await graph.create_customer_system_relationship("cust_001", "sys_001")
        await graph.create_customer_system_relationship("cust_001", "sys_002") 
        await graph.create_customer_system_relationship("cust_002", "sys_001")
        
        logger.info("Demo data created successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create demo data: {e}")
        return False