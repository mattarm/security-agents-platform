#!/usr/bin/env python3
"""
Production API Server - Enterprise REST API for SecurityAgents Platform
FastAPI-based API for external integrations and client applications
"""

from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
import asyncio
import uvicorn
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
import uuid
import logging
import os
from pathlib import Path

# Import our orchestration system
from agent_orchestration_system import (
    SecurityAgentOrchestrator, AnalysisRequest, Priority, 
    AgentStatus, TaskStatus
)
from intelligence_fusion_engine import IntelligenceType

# Security
security = HTTPBearer()

# API Models
class AnalysisRequestModel(BaseModel):
    """API model for analysis requests"""
    analysis_type: str = Field(..., description="Type of analysis: comprehensive, threat_focused, vulnerability_focused")
    target: str = Field(..., description="Target for analysis (path, URL, or identifier)")
    priority: str = Field(default="medium", description="Priority level: critical, high, medium, low, info")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Additional analysis parameters")
    requester: Optional[str] = Field(default=None, description="Requester identifier")
    
    class Config:
        schema_extra = {
            "example": {
                "analysis_type": "comprehensive",
                "target": "/path/to/codebase",
                "priority": "high",
                "parameters": {
                    "include_architecture_analysis": True,
                    "include_supply_chain": True,
                    "context": "Production security assessment"
                },
                "requester": "security_team"
            }
        }

class AnalysisResponseModel(BaseModel):
    """API model for analysis responses"""
    request_id: str
    status: str
    task_count: int
    task_ids: List[str]
    estimated_completion: datetime
    message: Optional[str] = None

class TaskStatusModel(BaseModel):
    """API model for task status"""
    task_id: str
    task_type: str
    priority: str
    assigned_agent: str
    status: str
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    progress_percentage: Optional[int]
    error_message: Optional[str]

class AgentStatusModel(BaseModel):
    """API model for agent status"""
    agent_id: str
    agent_type: str
    status: str
    capabilities: List[str]
    tasks_completed: int
    tasks_failed: int
    uptime_seconds: float
    last_heartbeat: datetime

class SystemMetricsModel(BaseModel):
    """API model for system metrics"""
    requests_processed: int
    tasks_completed: int
    tasks_failed: int
    active_agents: int
    intelligence_correlations: int
    uptime_seconds: float
    queue_size: int
    avg_response_time: float

class ThreatIntelligenceModel(BaseModel):
    """API model for threat intelligence"""
    intelligence_type: str
    confidence: float
    priority: str
    timestamp: datetime
    source_agent: str
    correlation_keys: List[str]
    summary: str
    risk_score: Optional[float] = None

class VulnerabilityModel(BaseModel):
    """API model for vulnerability findings"""
    vuln_id: str
    severity: str
    title: str
    description: str
    file_path: str
    line_number: Optional[int]
    cwe_id: Optional[str]
    cvss_score: float
    remediation: str
    confidence: float

class SecurityAgentsAPI:
    """Production-ready FastAPI application"""
    
    def __init__(self):
        self.app = FastAPI(
            title="SecurityAgents Platform API",
            description="Enterprise Security Intelligence Platform API",
            version="2.0.0",
            docs_url="/docs",
            redoc_url="/redoc"
        )
        
        self.orchestrator = None
        self.api_keys = self.load_api_keys()
        
        # Configure middleware
        self.setup_middleware()
        
        # Setup routes
        self.setup_routes()
        
        # Setup logging
        self.setup_logging()
        
        print("🚀 SecurityAgents API Server initialized")

    def load_api_keys(self) -> Dict[str, Dict[str, Any]]:
        """Load API keys and permissions"""
        # In production, this would come from a secure store
        return {
            "demo-key-123": {
                "name": "Demo Client",
                "permissions": ["read", "write"],
                "rate_limit": 100,
                "expires": None
            },
            "admin-key-456": {
                "name": "Admin Client", 
                "permissions": ["read", "write", "admin"],
                "rate_limit": 1000,
                "expires": None
            }
        }

    def setup_middleware(self):
        """Configure FastAPI middleware"""
        
        # CORS
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # Configure appropriately for production
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Compression
        self.app.add_middleware(GZipMiddleware, minimum_size=1000)

    def setup_logging(self):
        """Configure API logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    async def verify_api_key(self, credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
        """Verify API key and return client info"""
        token = credentials.credentials
        
        if token not in self.api_keys:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        return self.api_keys[token]

    def setup_routes(self):
        """Setup all API routes"""
        
        @self.app.on_event("startup")
        async def startup_event():
            """Initialize orchestrator on startup"""
            self.orchestrator = SecurityAgentOrchestrator()
            # Start orchestrator in background
            asyncio.create_task(self.orchestrator.start())
            # Wait for initialization
            await asyncio.sleep(2)
            self.logger.info("✅ API Server startup complete")

        @self.app.on_event("shutdown")
        async def shutdown_event():
            """Cleanup on shutdown"""
            if self.orchestrator:
                self.orchestrator.shutdown_event.set()
            self.logger.info("✅ API Server shutdown complete")

        @self.app.get("/", tags=["Health"])
        async def root():
            """Root endpoint with API information"""
            return {
                "service": "SecurityAgents Platform API",
                "version": "2.0.0",
                "status": "operational",
                "timestamp": datetime.now().isoformat(),
                "endpoints": {
                    "docs": "/docs",
                    "health": "/health",
                    "analysis": "/analysis",
                    "status": "/status"
                }
            }

        @self.app.get("/health", tags=["Health"])
        async def health_check():
            """Health check endpoint"""
            if not self.orchestrator:
                raise HTTPException(status_code=503, detail="Orchestrator not initialized")
            
            status = await self.orchestrator.get_orchestrator_status()
            
            is_healthy = (
                status['status'] == 'running' and
                status['metrics']['active_agents'] > 0
            )
            
            return {
                "healthy": is_healthy,
                "status": status['status'],
                "active_agents": status['metrics']['active_agents'],
                "uptime_seconds": status['uptime_seconds'],
                "timestamp": datetime.now().isoformat()
            }

        @self.app.post("/analysis", response_model=AnalysisResponseModel, tags=["Analysis"])
        async def submit_analysis(
            request: AnalysisRequestModel,
            background_tasks: BackgroundTasks,
            client_info: Dict = Depends(self.verify_api_key)
        ):
            """Submit a security analysis request"""
            
            if not self.orchestrator:
                raise HTTPException(status_code=503, detail="Orchestrator not available")
            
            # Validate priority
            try:
                priority = Priority[request.priority.upper()]
            except KeyError:
                raise HTTPException(status_code=400, detail=f"Invalid priority: {request.priority}")
            
            # Create analysis request
            analysis_request = AnalysisRequest(
                request_id=str(uuid.uuid4()),
                requester=request.requester or client_info["name"],
                analysis_type=request.analysis_type,
                target=request.target,
                priority=priority,
                parameters=request.parameters,
                created_at=datetime.now()
            )
            
            try:
                # Submit to orchestrator
                response = await self.orchestrator.submit_analysis_request(analysis_request)
                
                self.logger.info(f"📥 Analysis request submitted: {analysis_request.request_id} by {client_info['name']}")
                
                return AnalysisResponseModel(
                    request_id=response['request_id'],
                    status=response['status'],
                    task_count=response['task_count'],
                    task_ids=response['task_ids'],
                    estimated_completion=response['estimated_completion']
                )
                
            except Exception as e:
                self.logger.error(f"❌ Analysis request failed: {str(e)}")
                raise HTTPException(status_code=500, detail=f"Analysis request failed: {str(e)}")

        @self.app.get("/analysis/{request_id}", tags=["Analysis"])
        async def get_analysis_status(
            request_id: str,
            client_info: Dict = Depends(self.verify_api_key)
        ):
            """Get status of an analysis request"""
            
            if not self.orchestrator:
                raise HTTPException(status_code=503, detail="Orchestrator not available")
            
            # Find tasks for this request
            matching_tasks = [
                task for task_id, task in self.orchestrator.tasks.items()
                if task_id.startswith(request_id)
            ]
            
            if not matching_tasks:
                raise HTTPException(status_code=404, detail="Analysis request not found")
            
            # Calculate overall status
            task_statuses = [task.status for task in matching_tasks]
            
            if all(status == TaskStatus.COMPLETED for status in task_statuses):
                overall_status = "completed"
            elif any(status == TaskStatus.RUNNING for status in task_statuses):
                overall_status = "running"
            elif any(status == TaskStatus.FAILED for status in task_statuses):
                overall_status = "failed"
            elif all(status == TaskStatus.PENDING for status in task_statuses):
                overall_status = "pending"
            else:
                overall_status = "mixed"
            
            # Aggregate results
            all_results = {}
            for task in matching_tasks:
                if task.results:
                    all_results[task.task_id] = task.results
            
            return {
                "request_id": request_id,
                "overall_status": overall_status,
                "task_count": len(matching_tasks),
                "tasks": [
                    {
                        "task_id": task.task_id,
                        "task_type": task.task_type,
                        "status": task.status.value,
                        "assigned_agent": task.assigned_agent,
                        "created_at": task.created_at,
                        "started_at": task.started_at,
                        "completed_at": task.completed_at,
                        "error_message": task.error_message
                    }
                    for task in matching_tasks
                ],
                "results": all_results
            }

        @self.app.get("/analysis/{request_id}/results", tags=["Analysis"])
        async def get_analysis_results(
            request_id: str,
            format: str = "json",
            client_info: Dict = Depends(self.verify_api_key)
        ):
            """Get detailed results of a completed analysis"""
            
            if not self.orchestrator:
                raise HTTPException(status_code=503, detail="Orchestrator not available")
            
            # Find completed tasks for this request
            matching_tasks = [
                task for task_id, task in self.orchestrator.tasks.items()
                if (task_id.startswith(request_id) and 
                    task.status == TaskStatus.COMPLETED and 
                    task.results)
            ]
            
            if not matching_tasks:
                raise HTTPException(status_code=404, detail="No completed results found for this request")
            
            # Aggregate and format results
            aggregated_results = {
                "request_id": request_id,
                "completed_at": max(task.completed_at for task in matching_tasks),
                "task_count": len(matching_tasks),
                "summary": self.generate_results_summary(matching_tasks),
                "detailed_results": {}
            }
            
            for task in matching_tasks:
                aggregated_results["detailed_results"][task.task_type] = task.results
            
            return aggregated_results

        @self.app.get("/tasks", response_model=List[TaskStatusModel], tags=["Tasks"])
        async def list_tasks(
            status: Optional[str] = None,
            agent: Optional[str] = None,
            limit: int = 50,
            client_info: Dict = Depends(self.verify_api_key)
        ):
            """List tasks with optional filtering"""
            
            if not self.orchestrator:
                raise HTTPException(status_code=503, detail="Orchestrator not available")
            
            tasks = list(self.orchestrator.tasks.values())
            
            # Apply filters
            if status:
                try:
                    status_enum = TaskStatus[status.upper()]
                    tasks = [t for t in tasks if t.status == status_enum]
                except KeyError:
                    raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
            
            if agent:
                tasks = [t for t in tasks if t.assigned_agent == agent]
            
            # Sort by creation time (newest first) and limit
            tasks.sort(key=lambda t: t.created_at, reverse=True)
            tasks = tasks[:limit]
            
            return [
                TaskStatusModel(
                    task_id=task.task_id,
                    task_type=task.task_type,
                    priority=task.priority.value,
                    assigned_agent=task.assigned_agent,
                    status=task.status.value,
                    created_at=task.created_at,
                    started_at=task.started_at,
                    completed_at=task.completed_at,
                    progress_percentage=self.calculate_task_progress(task),
                    error_message=task.error_message
                )
                for task in tasks
            ]

        @self.app.get("/agents", response_model=List[AgentStatusModel], tags=["Agents"])
        async def list_agents(client_info: Dict = Depends(self.verify_api_key)):
            """Get status of all agents"""
            
            if not self.orchestrator:
                raise HTTPException(status_code=503, detail="Orchestrator not available")
            
            agents = []
            for agent_id, agent_info in self.orchestrator.agents.items():
                agents.append(AgentStatusModel(
                    agent_id=agent_info.agent_id,
                    agent_type=agent_info.agent_type,
                    status=agent_info.status.value,
                    capabilities=agent_info.capabilities,
                    tasks_completed=agent_info.tasks_completed,
                    tasks_failed=agent_info.tasks_failed,
                    uptime_seconds=agent_info.uptime.total_seconds(),
                    last_heartbeat=agent_info.last_heartbeat
                ))
            
            return agents

        @self.app.get("/agents/{agent_id}", response_model=AgentStatusModel, tags=["Agents"])
        async def get_agent_status(
            agent_id: str,
            client_info: Dict = Depends(self.verify_api_key)
        ):
            """Get detailed status of a specific agent"""
            
            if not self.orchestrator:
                raise HTTPException(status_code=503, detail="Orchestrator not available")
            
            if agent_id not in self.orchestrator.agents:
                raise HTTPException(status_code=404, detail="Agent not found")
            
            agent_info = self.orchestrator.agents[agent_id]
            
            return AgentStatusModel(
                agent_id=agent_info.agent_id,
                agent_type=agent_info.agent_type,
                status=agent_info.status.value,
                capabilities=agent_info.capabilities,
                tasks_completed=agent_info.tasks_completed,
                tasks_failed=agent_info.tasks_failed,
                uptime_seconds=agent_info.uptime.total_seconds(),
                last_heartbeat=agent_info.last_heartbeat
            )

        @self.app.get("/status", response_model=SystemMetricsModel, tags=["Status"])
        async def get_system_status(client_info: Dict = Depends(self.verify_api_key)):
            """Get comprehensive system status and metrics"""
            
            if not self.orchestrator:
                raise HTTPException(status_code=503, detail="Orchestrator not available")
            
            status = await self.orchestrator.get_orchestrator_status()
            
            return SystemMetricsModel(
                requests_processed=status['metrics']['requests_processed'],
                tasks_completed=status['metrics']['tasks_completed'],
                tasks_failed=status['metrics']['tasks_failed'],
                active_agents=status['metrics']['active_agents'],
                intelligence_correlations=status['metrics']['intelligence_correlations'],
                uptime_seconds=status['uptime_seconds'],
                queue_size=status['queue_size'],
                avg_response_time=status['metrics']['avg_response_time']
            )

        @self.app.get("/intelligence", tags=["Intelligence"])
        async def get_threat_intelligence(
            limit: int = 20,
            intelligence_type: Optional[str] = None,
            client_info: Dict = Depends(self.verify_api_key)
        ):
            """Get recent threat intelligence"""
            
            if not self.orchestrator:
                raise HTTPException(status_code=503, detail="Orchestrator not available")
            
            # Get intelligence from fusion engine
            intelligence_packets = []
            
            for packet_id, packet in list(self.orchestrator.fusion_engine.intelligence_store.items())[-limit:]:
                if intelligence_type and packet.intelligence_type.value != intelligence_type:
                    continue
                    
                intelligence_packets.append({
                    "packet_id": packet.packet_id,
                    "intelligence_type": packet.intelligence_type.value,
                    "priority": packet.priority.value,
                    "confidence": packet.confidence,
                    "timestamp": packet.timestamp,
                    "source_agent": packet.source_agent,
                    "correlation_keys": packet.correlation_keys,
                    "summary": self.summarize_intelligence_packet(packet),
                    "risk_score": self.extract_risk_from_packet(packet)
                })
            
            return {
                "intelligence_count": len(intelligence_packets),
                "intelligence": intelligence_packets
            }

        @self.app.post("/intelligence/correlate", tags=["Intelligence"])
        async def correlate_custom_intelligence(
            indicators: List[str],
            context: str = "",
            client_info: Dict = Depends(self.verify_api_key)
        ):
            """Correlate custom threat indicators"""
            
            if not self.orchestrator:
                raise HTTPException(status_code=503, detail="Orchestrator not available")
            
            if not indicators:
                raise HTTPException(status_code=400, detail="No indicators provided")
            
            # Create a custom analysis request for correlation
            analysis_request = AnalysisRequest(
                request_id=str(uuid.uuid4()),
                requester=client_info["name"],
                analysis_type="threat_focused",
                target="custom_indicators",
                priority=Priority.HIGH,
                parameters={
                    "indicators": indicators,
                    "context": context
                },
                created_at=datetime.now()
            )
            
            try:
                response = await self.orchestrator.submit_analysis_request(analysis_request)
                return {
                    "correlation_request_id": response['request_id'],
                    "status": "submitted",
                    "indicators_count": len(indicators),
                    "estimated_completion": response['estimated_completion']
                }
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Correlation request failed: {str(e)}")

        @self.app.get("/metrics/dashboard", tags=["Metrics"])
        async def get_dashboard_metrics(client_info: Dict = Depends(self.verify_api_key)):
            """Get metrics for dashboard visualization"""
            
            if not self.orchestrator:
                raise HTTPException(status_code=503, detail="Orchestrator not available")
            
            status = await self.orchestrator.get_orchestrator_status()
            
            # Calculate additional metrics
            current_time = datetime.now()
            last_hour_tasks = [
                task for task in self.orchestrator.tasks.values()
                if (task.completed_at and 
                    current_time - task.completed_at < timedelta(hours=1))
            ]
            
            return {
                "timestamp": current_time.isoformat(),
                "system_health": {
                    "status": status['status'],
                    "uptime_hours": status['uptime_seconds'] / 3600,
                    "active_agents": status['metrics']['active_agents'],
                    "queue_size": status['queue_size']
                },
                "performance": {
                    "requests_per_hour": len(last_hour_tasks),
                    "success_rate": self.calculate_success_rate(last_hour_tasks),
                    "avg_response_time": status['metrics']['avg_response_time']
                },
                "intelligence": {
                    "correlations_found": status['metrics']['intelligence_correlations'],
                    "active_intelligence": status['fusion_engine']['intelligence_store_size'],
                    "connected_agents": status['fusion_engine']['subscribed_agents']
                },
                "recent_activity": self.get_recent_activity_summary()
            }

    def generate_results_summary(self, tasks: List) -> Dict[str, Any]:
        """Generate a summary of analysis results"""
        summary = {
            "total_vulnerabilities": 0,
            "critical_findings": 0,
            "threat_campaigns_detected": 0,
            "overall_risk_score": 0.0,
            "key_findings": []
        }
        
        for task in tasks:
            if task.results:
                results = task.results
                
                # DevSecOps results
                if 'vulnerability_count' in results:
                    summary["total_vulnerabilities"] += results["vulnerability_count"]
                
                # Threat intelligence results
                if 'campaign' in results and results['campaign']:
                    summary["threat_campaigns_detected"] += 1
                
                # Risk scores
                if 'risk_score' in results:
                    summary["overall_risk_score"] = max(summary["overall_risk_score"], results["risk_score"])
        
        return summary

    def calculate_task_progress(self, task) -> Optional[int]:
        """Calculate task progress percentage"""
        if task.status == TaskStatus.PENDING:
            return 0
        elif task.status == TaskStatus.RUNNING:
            # Estimate based on elapsed time
            if task.started_at:
                elapsed = (datetime.now() - task.started_at).total_seconds()
                estimated_duration = 300  # 5 minutes default
                progress = min(int((elapsed / estimated_duration) * 100), 90)
                return progress
            return 10
        elif task.status == TaskStatus.COMPLETED:
            return 100
        elif task.status == TaskStatus.FAILED:
            return 0
        else:
            return None

    def summarize_intelligence_packet(self, packet) -> str:
        """Generate a brief summary of an intelligence packet"""
        data = packet.data
        intel_type = packet.intelligence_type.value
        
        if intel_type == 'threat_campaign':
            return f"Threat campaign: {data.get('name', 'Unknown')} by {data.get('threat_actor', 'Unknown')}"
        elif intel_type == 'vulnerability':
            return f"Vulnerability: {data.get('title', 'Unknown')} ({data.get('severity', 'Unknown')})"
        else:
            return f"Intelligence: {intel_type}"

    def extract_risk_from_packet(self, packet) -> Optional[float]:
        """Extract risk score from intelligence packet"""
        return packet.data.get('risk_score') or packet.data.get('cvss_score')

    def calculate_success_rate(self, tasks: List) -> float:
        """Calculate success rate for a list of tasks"""
        if not tasks:
            return 100.0
        
        completed_tasks = [t for t in tasks if t.status in [TaskStatus.COMPLETED, TaskStatus.FAILED]]
        if not completed_tasks:
            return 100.0
        
        successful_tasks = [t for t in completed_tasks if t.status == TaskStatus.COMPLETED]
        return (len(successful_tasks) / len(completed_tasks)) * 100

    def get_recent_activity_summary(self) -> List[Dict[str, Any]]:
        """Get summary of recent system activity"""
        # This would typically include recent tasks, correlations, etc.
        return [
            {
                "timestamp": datetime.now().isoformat(),
                "activity_type": "system_status",
                "message": "SecurityAgents platform operational",
                "details": {}
            }
        ]

    def run(self, host: str = "0.0.0.0", port: int = 8080, reload: bool = False):
        """Run the API server"""
        uvicorn.run(
            "production_api_server:api.app",
            host=host,
            port=port,
            reload=reload,
            access_log=True,
            log_level="info"
        )

# Global API instance
api = SecurityAgentsAPI()

# CLI interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="SecurityAgents Production API Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind to")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    
    args = parser.parse_args()
    
    print(f"🚀 Starting SecurityAgents API Server on {args.host}:{args.port}")
    api.run(host=args.host, port=args.port, reload=args.reload)