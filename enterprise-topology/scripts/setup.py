#!/usr/bin/env python3
"""
Enterprise Topology Intelligence - Setup Script
Initialize the platform and create demo environment
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.graph.enterprise_graph import EnterpriseKnowledgeGraph, create_demo_data
from core.models.enterprise_models import Customer, System, Team

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def setup_platform():
    """Complete platform setup"""
    
    logger.info("🚀 Setting up Enterprise Topology Intelligence Platform")
    
    # Configuration
    neo4j_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user = os.getenv("NEO4J_USER", "neo4j") 
    neo4j_password = os.getenv("NEO4J_PASSWORD", "enterprise-topology")
    
    try:
        # Initialize knowledge graph
        logger.info("📊 Initializing knowledge graph...")
        graph = EnterpriseKnowledgeGraph(neo4j_uri, neo4j_user, neo4j_password)
        
        # Test connection
        health = await graph.health_check()
        if not health:
            logger.error("❌ Failed to connect to Neo4j")
            return False
        
        logger.info("✅ Neo4j connection successful")
        
        # Initialize schema
        logger.info("🏗️ Creating database schema...")
        schema_success = await graph.initialize_schema()
        if not schema_success:
            logger.error("❌ Failed to initialize schema")
            return False
        
        logger.info("✅ Database schema created")
        
        # Create comprehensive demo data
        logger.info("📝 Creating comprehensive demo data...")
        demo_success = await create_comprehensive_demo_data(graph)
        if not demo_success:
            logger.error("❌ Failed to create demo data")
            return False
        
        logger.info("✅ Demo data created successfully")
        
        # Verify setup
        stats = await graph.get_graph_statistics()
        logger.info(f"📈 Graph Statistics: {stats}")
        
        graph.close()
        
        logger.info("🎉 Platform setup completed successfully!")
        logger.info("🌐 You can now start the platform with: python src/main.py")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Setup failed: {e}")
        return False

async def create_comprehensive_demo_data(graph: EnterpriseKnowledgeGraph) -> bool:
    """Create comprehensive demo data for the platform"""
    
    try:
        logger.info("Creating enterprise customers...")
        
        # Create demo customers
        customers = [
            Customer(
                id="cust_001",
                name="Enterprise Corp",
                tier="ENTERPRISE",
                contract_value=2000000,
                sla_tier="PLATINUM",
                industry="Technology",
                region="North America",
                contact_email="cto@enterprisecorp.com",
                health_score=0.92
            ),
            Customer(
                id="cust_002", 
                name="Global Industries",
                tier="BUSINESS",
                contract_value=500000,
                sla_tier="GOLD",
                industry="Manufacturing",
                region="Europe",
                contact_email="it.director@globalindustries.com",
                health_score=0.87
            ),
            Customer(
                id="cust_003",
                name="StartupTech",
                tier="STANDARD", 
                contract_value=75000,
                sla_tier="SILVER",
                industry="Startup",
                region="North America",
                contact_email="tech@startuptech.io",
                health_score=0.95
            )
        ]
        
        for customer in customers:
            await graph.create_customer(customer)
        
        logger.info("Creating production systems...")
        
        # Create demo systems
        systems = [
            System(
                id="sys_001",
                name="core-api",
                system_type="microservice",
                environment="production",
                criticality="CRITICAL",
                owner_team="platform-team",
                business_owner="john.doe@company.com",
                customer_facing=True,
                uptime_requirement=0.999,
                estimated_users=10000
            ),
            System(
                id="sys_002",
                name="user-service", 
                system_type="microservice",
                environment="production",
                criticality="HIGH",
                owner_team="user-team",
                business_owner="jane.smith@company.com",
                customer_facing=True,
                uptime_requirement=0.995,
                estimated_users=8500
            ),
            System(
                id="sys_003",
                name="analytics-pipeline",
                system_type="data_processing",
                environment="production",
                criticality="MEDIUM", 
                owner_team="data-team",
                customer_facing=False,
                uptime_requirement=0.99,
                estimated_users=0
            ),
            System(
                id="sys_004",
                name="mobile-api",
                system_type="api_gateway",
                environment="production",
                criticality="HIGH",
                owner_team="mobile-team",
                customer_facing=True,
                uptime_requirement=0.995,
                estimated_users=5000
            ),
            System(
                id="sys_005",
                name="payment-service",
                system_type="microservice", 
                environment="production",
                criticality="CRITICAL",
                owner_team="payments-team",
                customer_facing=True,
                uptime_requirement=0.999,
                estimated_users=12000
            )
        ]
        
        for system in systems:
            await graph.create_system(system)
        
        logger.info("Creating customer-system relationships...")
        
        # Create customer-system relationships
        relationships = [
            ("cust_001", "sys_001"),  # Enterprise Corp uses core-api
            ("cust_001", "sys_002"),  # Enterprise Corp uses user-service
            ("cust_001", "sys_004"),  # Enterprise Corp uses mobile-api
            ("cust_001", "sys_005"),  # Enterprise Corp uses payment-service
            ("cust_002", "sys_001"),  # Global Industries uses core-api
            ("cust_002", "sys_002"),  # Global Industries uses user-service
            ("cust_002", "sys_005"),  # Global Industries uses payment-service
            ("cust_003", "sys_001"),  # StartupTech uses core-api
            ("cust_003", "sys_002"),  # StartupTech uses user-service
        ]
        
        for customer_id, system_id in relationships:
            await graph.create_customer_system_relationship(customer_id, system_id)
        
        logger.info("Creating team ownership relationships...")
        
        # Create ownership relationships
        ownerships = [
            ("sys_001", "team_platform", "primary"),
            ("sys_002", "team_user", "primary"),
            ("sys_003", "team_data", "primary"),
            ("sys_004", "team_mobile", "primary"), 
            ("sys_005", "team_payments", "primary"),
        ]
        
        for tech_id, team_id, ownership_type in ownerships:
            await graph.create_ownership_relationship(tech_id, team_id, ownership_type)
        
        logger.info("Demo data creation completed successfully!")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create demo data: {e}")
        return False

def check_prerequisites():
    """Check that all prerequisites are met"""
    
    logger.info("🔍 Checking prerequisites...")
    
    # Check Python version
    if sys.version_info < (3, 8):
        logger.error("❌ Python 3.8+ is required")
        return False
    
    logger.info("✅ Python version check passed")
    
    # Check if Neo4j is accessible
    neo4j_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    logger.info(f"🔌 Checking Neo4j connection to {neo4j_uri}")
    
    # You could add actual Neo4j connectivity check here
    
    logger.info("✅ Prerequisites check completed")
    return True

def print_next_steps():
    """Print next steps for the user"""
    
    print("\n🎉 Setup completed successfully!")
    print("\n📋 Next Steps:")
    print("1. Start the platform:")
    print("   python src/main.py")
    print("\n2. Access the API documentation:")
    print("   http://localhost:8000/docs")
    print("\n3. View the dashboard:")
    print("   http://localhost:3000")
    print("\n4. Check platform status:")
    print("   curl http://localhost:8000/api/v1/status")
    print("\n5. Explore customer data:")
    print("   curl http://localhost:8000/api/v1/customers/")
    print("\n🚀 Happy enterprise topology mapping!")

if __name__ == "__main__":
    print("🏢 Enterprise Topology Intelligence - Setup")
    print("=" * 50)
    
    # Check prerequisites
    if not check_prerequisites():
        sys.exit(1)
    
    # Run setup
    success = asyncio.run(setup_platform())
    
    if success:
        print_next_steps()
        sys.exit(0)
    else:
        logger.error("❌ Setup failed")
        sys.exit(1)