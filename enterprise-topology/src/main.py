"""
Enterprise Topology Intelligence - Main Application
Comprehensive enterprise technology governance platform
"""

import asyncio
import logging
import os
import signal
import sys
from contextlib import asynccontextmanager
from typing import Dict, Any

import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from core.graph.enterprise_graph import EnterpriseKnowledgeGraph, create_demo_data
from core.models.enterprise_models import (
    Customer, GitHubRepository, System, 
    EnterpriseDashboardData, CustomerImpactAssessment
)
from integrations.github.github_client import GitHubEnterpriseClient
from api.routes import customers, systems, analytics, health

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global components
graph: EnterpriseKnowledgeGraph = None
github_client: GitHubEnterpriseClient = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    global graph, github_client
    
    # Startup
    logger.info("🚀 Starting Enterprise Topology Intelligence Platform")
    
    try:
        # Initialize Neo4j knowledge graph
        neo4j_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        neo4j_user = os.getenv("NEO4J_USER", "neo4j")
        neo4j_password = os.getenv("NEO4J_PASSWORD", "enterprise-topology")
        
        graph = EnterpriseKnowledgeGraph(neo4j_uri, neo4j_user, neo4j_password)
        
        # Initialize graph schema
        schema_initialized = await graph.initialize_schema()
        if not schema_initialized:
            logger.error("Failed to initialize knowledge graph schema")
            sys.exit(1)
        
        logger.info("✅ Knowledge graph initialized")
        
        # Initialize GitHub client
        github_token = os.getenv("GITHUB_TOKEN")
        github_org = os.getenv("GITHUB_ORGANIZATION")
        
        if github_token and github_org:
            github_client = GitHubEnterpriseClient(github_token, github_org)
            github_initialized = await github_client.initialize()
            
            if github_initialized:
                logger.info("✅ GitHub integration initialized")
            else:
                logger.warning("⚠️ GitHub integration failed - continuing without GitHub")
        else:
            logger.info("ℹ️ GitHub credentials not provided - skipping GitHub integration")
        
        # Create demo data if no data exists
        stats = await graph.get_graph_statistics()
        if stats.get("total_nodes", 0) < 5:
            logger.info("Creating demo data...")
            demo_created = await create_demo_data(graph)
            if demo_created:
                logger.info("✅ Demo data created")
            else:
                logger.warning("⚠️ Failed to create demo data")
        
        logger.info("🎯 Enterprise Topology Intelligence Platform is ready!")
        
        yield
        
    except Exception as e:
        logger.error(f"Failed to initialize application: {e}")
        sys.exit(1)
    
    # Shutdown
    logger.info("🛑 Shutting down Enterprise Topology Intelligence Platform")
    
    if graph:
        graph.close()
    
    if github_client:
        github_client.close()
    
    logger.info("👋 Application shutdown complete")

# Create FastAPI application
app = FastAPI(
    title="Enterprise Topology Intelligence",
    description="Comprehensive enterprise technology governance and customer impact analysis",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(customers.router, prefix="/api/v1/customers", tags=["customers"])
app.include_router(systems.router, prefix="/api/v1/systems", tags=["systems"])
app.include_router(analytics.router, prefix="/api/v1/analytics", tags=["analytics"])
app.include_router(health.router, prefix="/api/v1/health", tags=["health"])

# ===== ROOT ENDPOINTS =====

@app.get("/")
async def root():
    """Root endpoint with platform information"""
    return {
        "name": "Enterprise Topology Intelligence",
        "version": "1.0.0",
        "description": "Comprehensive enterprise technology governance platform",
        "status": "operational",
        "components": {
            "knowledge_graph": "neo4j",
            "github_integration": "enabled" if github_client else "disabled",
            "api": "fastapi",
            "dashboard": "react"
        }
    }

@app.get("/api/v1/status")
async def get_platform_status():
    """Get comprehensive platform status"""
    global graph, github_client
    
    status = {
        "platform": "operational",
        "timestamp": asyncio.get_event_loop().time(),
        "components": {}
    }
    
    # Check knowledge graph health
    if graph:
        graph_healthy = await graph.health_check()
        status["components"]["knowledge_graph"] = {
            "status": "healthy" if graph_healthy else "unhealthy",
            "type": "neo4j"
        }
        
        if graph_healthy:
            stats = await graph.get_graph_statistics()
            status["components"]["knowledge_graph"]["statistics"] = stats
    else:
        status["components"]["knowledge_graph"] = {"status": "not_initialized"}
    
    # Check GitHub integration
    if github_client:
        status["components"]["github"] = {
            "status": "enabled",
            "organization": github_client.organization_name
        }
    else:
        status["components"]["github"] = {"status": "disabled"}
    
    return status

# ===== DASHBOARD ENDPOINTS =====

class AnalysisRequest(BaseModel):
    customer_id: Optional[str] = None
    analysis_type: str = "full"
    include_recommendations: bool = True

@app.post("/api/v1/dashboard/analyze")
async def run_enterprise_analysis(request: AnalysisRequest):
    """Run comprehensive enterprise analysis"""
    global graph
    
    if not graph:
        raise HTTPException(status_code=503, detail="Knowledge graph not available")
    
    try:
        if request.customer_id:
            # Customer-specific analysis
            customer_footprint = await graph.get_customer_technology_footprint(request.customer_id)
            risk_analysis = await graph.analyze_customer_risk_exposure(request.customer_id)
            
            return {
                "analysis_type": "customer_specific",
                "customer_id": request.customer_id,
                "technology_footprint": customer_footprint,
                "risk_analysis": risk_analysis,
                "timestamp": asyncio.get_event_loop().time()
            }
        else:
            # Enterprise-wide analysis
            ownership_gaps = await graph.find_technology_ownership_gaps()
            graph_stats = await graph.get_graph_statistics()
            
            return {
                "analysis_type": "enterprise_wide",
                "ownership_gaps": ownership_gaps,
                "graph_statistics": graph_stats,
                "timestamp": asyncio.get_event_loop().time()
            }
    
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/api/v1/dashboard/summary")
async def get_enterprise_dashboard_summary():
    """Get enterprise dashboard summary"""
    global graph
    
    if not graph:
        raise HTTPException(status_code=503, detail="Knowledge graph not available")
    
    try:
        # Get basic statistics
        stats = await graph.get_graph_statistics()
        
        # Get ownership gaps
        ownership_gaps = await graph.find_technology_ownership_gaps()
        
        return {
            "statistics": stats,
            "ownership_gaps_count": len(ownership_gaps),
            "critical_ownership_gaps": [
                gap for gap in ownership_gaps 
                if gap.get("criticality") in ["CRITICAL", "HIGH"]
            ][:5],  # Top 5 critical gaps
            "timestamp": asyncio.get_event_loop().time()
        }
    
    except Exception as e:
        logger.error(f"Dashboard summary failed: {e}")
        raise HTTPException(status_code=500, detail=f"Dashboard summary failed: {str(e)}")

# ===== DATA INGESTION ENDPOINTS =====

@app.post("/api/v1/ingest/github")
async def ingest_github_data(background_tasks: BackgroundTasks):
    """Trigger GitHub data ingestion"""
    global github_client, graph
    
    if not github_client:
        raise HTTPException(status_code=503, detail="GitHub client not available")
    
    if not graph:
        raise HTTPException(status_code=503, detail="Knowledge graph not available")
    
    # Run ingestion in background
    background_tasks.add_task(run_github_ingestion)
    
    return {
        "message": "GitHub data ingestion started",
        "status": "running",
        "timestamp": asyncio.get_event_loop().time()
    }

async def run_github_ingestion():
    """Background task to ingest GitHub data"""
    global github_client, graph
    
    try:
        logger.info("Starting GitHub data ingestion...")
        
        # Get all repositories
        repositories = await github_client.get_all_repositories()
        logger.info(f"Found {len(repositories)} repositories")
        
        # Store repositories in knowledge graph
        success_count = 0
        for repo in repositories:
            try:
                # Create repository node (we'll need to implement this in the graph)
                # For now, just log
                logger.info(f"Processing repository: {repo.name} (owner: {repo.owner_team})")
                success_count += 1
            except Exception as e:
                logger.error(f"Failed to process repository {repo.name}: {e}")
        
        logger.info(f"GitHub ingestion completed: {success_count}/{len(repositories)} repositories processed")
        
    except Exception as e:
        logger.error(f"GitHub ingestion failed: {e}")

# ===== QUERY ENDPOINTS =====

@app.post("/api/v1/query/cypher")
async def execute_cypher_query(query: Dict[str, Any]):
    """Execute custom Cypher query (admin use only)"""
    global graph
    
    if not graph:
        raise HTTPException(status_code=503, detail="Knowledge graph not available")
    
    # In production, add authentication/authorization here
    
    cypher_query = query.get("query")
    parameters = query.get("parameters", {})
    
    if not cypher_query:
        raise HTTPException(status_code=400, detail="Query is required")
    
    try:
        # Execute query directly on graph driver
        async with graph.driver.session() as session:
            result = await session.run(cypher_query, parameters)
            records = []
            
            async for record in result:
                records.append(dict(record))
            
            return {
                "query": cypher_query,
                "parameters": parameters,
                "results": records,
                "count": len(records)
            }
    
    except Exception as e:
        logger.error(f"Cypher query failed: {e}")
        raise HTTPException(status_code=500, detail=f"Query execution failed: {str(e)}")

# ===== SIGNAL HANDLERS =====

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    logger.info(f"Received signal {signum}, initiating shutdown...")
    sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# ===== MAIN ENTRY POINT =====

if __name__ == "__main__":
    # Configuration from environment variables
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    log_level = os.getenv("LOG_LEVEL", "info")
    
    # Run the application
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        log_level=log_level,
        reload=os.getenv("ENVIRONMENT") == "development",
        workers=1  # Single worker for now to share state
    )