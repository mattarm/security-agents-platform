#!/usr/bin/env python3
"""
SecOps AI Platform - Main Application Entry Point
Tiger Team Beta-2: AI Orchestration with Graduated Autonomy
"""

import asyncio
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Dict, Any

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ValidationError
import uvicorn

from ai_engine.orchestrator import AIOrchestrator, SecurityAlert, AlertSeverity
from config import Settings, load_config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('secops-ai.log')
    ]
)

logger = logging.getLogger(__name__)

# Global configuration and orchestrator
settings: Settings = None
ai_orchestrator: AIOrchestrator = None

# FastAPI application
app = FastAPI(
    title="SecOps AI Platform",
    description="AI Orchestration with Graduated Autonomy for Enterprise SOC",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models for API
class AlertRequest(BaseModel):
    """Security alert request model"""
    title: str
    description: str
    severity: str
    source: str
    evidence: Dict[str, Any] = {}
    metadata: Dict[str, Any] = {}

class AlertResponse(BaseModel):
    """Security alert analysis response"""
    alert_id: str
    analysis_id: str
    category: str
    confidence_score: float
    recommended_action: str
    autonomy_tier: int
    reasoning_chain: list
    processing_time_ms: int
    compliance_status: str
    status: str

class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    timestamp: str
    components: Dict[str, Any]
    metrics: Dict[str, Any]

@app.on_event("startup")
async def startup_event():
    """Initialize AI orchestration system on startup"""
    global settings, ai_orchestrator
    
    try:
        # Load configuration
        settings = load_config()
        
        # Initialize AI orchestrator
        config = {
            'bedrock_config': {
                'region': settings.aws_region,
                'vpc_endpoint_url': settings.bedrock_vpc_endpoint,
                'access_key_id': settings.aws_access_key_id,
                'secret_access_key': settings.aws_secret_access_key
            },
            'confidence_config': {
                'bias_thresholds': {
                    'demographic_parity': 0.10,
                    'equal_opportunity': 0.10,
                    'calibration_error': 0.05
                }
            },
            'autonomy_config': {
                'slack_webhook': settings.slack_webhook_url,
                'approval_groups': {
                    'tier2': ['soc-analysts', 'security-leads'],
                    'tier3': ['soc-analysts', 'security-leads', 'incident-response']
                }
            },
            'audit_config': {
                'audit_db_path': settings.audit_db_path,
                'retention_days': 2555,  # 7 years
                'encryption_key': settings.audit_encryption_key
            },
            'compliance_config': {
                'enabled_frameworks': ['SOC2', 'ISO27001']
            }
        }
        
        ai_orchestrator = AIOrchestrator(config)
        await ai_orchestrator.model_router.initialize()
        
        logger.info("SecOps AI Platform initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize AI platform: {str(e)}")
        raise

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("SecOps AI Platform shutting down")

@app.get("/", response_model=Dict[str, str])
async def root():
    """Root endpoint with platform information"""
    return {
        "name": "SecOps AI Platform",
        "version": "1.0.0",
        "description": "AI Orchestration with Graduated Autonomy",
        "status": "operational"
    }

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Comprehensive health check endpoint"""
    
    if not ai_orchestrator:
        raise HTTPException(status_code=503, detail="AI orchestrator not initialized")
    
    try:
        health_data = await ai_orchestrator.health_check()
        
        return HealthResponse(
            status=health_data['status'],
            timestamp=health_data['timestamp'],
            components=health_data['components'],
            metrics=health_data['metrics']
        )
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        raise HTTPException(status_code=503, detail=f"Health check failed: {str(e)}")

@app.post("/analyze", response_model=AlertResponse)
async def analyze_security_alert(
    alert_request: AlertRequest,
    background_tasks: BackgroundTasks
):
    """
    Analyze security alert with AI orchestration
    
    This is the main endpoint for processing security alerts through the
    graduated autonomy framework with Claude AI analysis.
    """
    
    if not ai_orchestrator:
        raise HTTPException(status_code=503, detail="AI orchestrator not initialized")
    
    try:
        # Convert request to SecurityAlert
        alert_severity = AlertSeverity(alert_request.severity.lower())
        
        alert = SecurityAlert(
            id=f"alert_{int(datetime.now(timezone.utc).timestamp())}_{hash(alert_request.title) % 10000:04d}",
            timestamp=datetime.now(timezone.utc),
            severity=alert_severity,
            source=alert_request.source,
            title=alert_request.title,
            description=alert_request.description,
            evidence=alert_request.evidence,
            metadata=alert_request.metadata
        )
        
        # Process alert through AI orchestration
        analysis_result = await ai_orchestrator.process_security_alert(alert)
        
        # Determine overall status
        if analysis_result.confidence_score >= 0.95:
            status = "autonomous_action_taken"
        elif analysis_result.confidence_score >= 0.80:
            status = "assisted_processing"
        elif analysis_result.confidence_score >= 0.60:
            status = "approval_required"
        else:
            status = "human_collaboration_needed"
        
        return AlertResponse(
            alert_id=alert.id,
            analysis_id=analysis_result.analysis_id,
            category=analysis_result.category.value,
            confidence_score=analysis_result.confidence_score,
            recommended_action=analysis_result.recommended_action,
            autonomy_tier=ai_orchestrator.autonomy_controller._determine_autonomy_tier(alert, analysis_result).value,
            reasoning_chain=analysis_result.reasoning_chain,
            processing_time_ms=analysis_result.processing_time_ms,
            compliance_status="compliant",  # Would get from compliance validation
            status=status
        )
        
    except ValidationError as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Invalid request: {str(e)}")
        
    except Exception as e:
        logger.error(f"Analysis failed for alert: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/approve/{approval_id}")
async def approve_action(
    approval_id: str,
    response: str,
    user_id: str
):
    """Handle human approval for supervised actions (Tier 2)"""
    
    if not ai_orchestrator:
        raise HTTPException(status_code=503, detail="AI orchestrator not initialized")
    
    valid_responses = ['approve', 'modify', 'escalate', 'reject']
    if response not in valid_responses:
        raise HTTPException(status_code=400, detail=f"Invalid response. Must be one of: {valid_responses}")
    
    try:
        result = await ai_orchestrator.autonomy_controller.handle_approval_response(
            approval_id, response, user_id
        )
        
        return {
            "approval_id": approval_id,
            "response": response,
            "user_id": user_id,
            "result": result,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Approval handling failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Approval handling failed: {str(e)}")

@app.get("/metrics")
async def get_metrics():
    """Get platform performance and cost metrics"""
    
    if not ai_orchestrator:
        raise HTTPException(status_code=503, detail="AI orchestrator not initialized")
    
    try:
        metrics = await ai_orchestrator.get_performance_metrics()
        return metrics
        
    except Exception as e:
        logger.error(f"Metrics retrieval failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Metrics retrieval failed: {str(e)}")

@app.get("/audit/search")
async def search_audit_trail(
    start_date: str = None,
    end_date: str = None,
    alert_id: str = None,
    event_type: str = None,
    limit: int = 100
):
    """Search audit trail with filters"""
    
    if not ai_orchestrator:
        raise HTTPException(status_code=503, detail="AI orchestrator not initialized")
    
    try:
        filters = {}
        if start_date:
            filters['start_date'] = start_date
        if end_date:
            filters['end_date'] = end_date
        if alert_id:
            filters['alert_id'] = alert_id
        if event_type:
            filters['event_type'] = event_type
        filters['limit'] = limit
        
        audit_results = await ai_orchestrator.audit_logger.search_audit_trail(filters)
        
        return {
            "results": audit_results,
            "filters": filters,
            "count": len(audit_results)
        }
        
    except Exception as e:
        logger.error(f"Audit search failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Audit search failed: {str(e)}")

@app.get("/compliance/report")
async def generate_compliance_report(
    start_date: str,
    end_date: str,
    report_type: str = "SOC2"
):
    """Generate compliance report for audit purposes"""
    
    if not ai_orchestrator:
        raise HTTPException(status_code=503, detail="AI orchestrator not initialized")
    
    try:
        from datetime import datetime
        start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
        end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
        
        report = await ai_orchestrator.audit_logger.generate_compliance_report(
            start_dt, end_dt, report_type
        )
        
        return report
        
    except Exception as e:
        logger.error(f"Compliance report generation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")

def create_app() -> FastAPI:
    """Factory function to create FastAPI app"""
    return app

def main():
    """Main entry point for running the application"""
    
    # Load configuration
    settings = load_config()
    
    # Run the application
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level="info" if not settings.debug else "debug",
        access_log=True
    )

if __name__ == "__main__":
    main()