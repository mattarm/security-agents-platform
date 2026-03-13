"""
Health Check API Routes
System health and diagnostics endpoints
"""

from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from datetime import datetime
import psutil
import os

router = APIRouter()

@router.get("/")
async def health_check():
    """Basic health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }

@router.get("/detailed")
async def detailed_health_check():
    """Detailed system health information"""
    
    # System metrics
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    health_data = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "system": {
            "cpu_percent": cpu_percent,
            "memory": {
                "total": memory.total,
                "available": memory.available,
                "percent": memory.percent
            },
            "disk": {
                "total": disk.total,
                "free": disk.free,
                "percent": (disk.used / disk.total) * 100
            }
        },
        "environment": {
            "python_version": os.sys.version,
            "environment": os.getenv("ENVIRONMENT", "unknown")
        },
        "components": {
            "neo4j": {"status": "checking"},
            "github": {"status": "checking"},
            "kafka": {"status": "checking"}
        }
    }
    
    # Determine overall health
    if cpu_percent > 90 or memory.percent > 90:
        health_data["status"] = "degraded"
    
    if cpu_percent > 95 or memory.percent > 95:
        health_data["status"] = "unhealthy"
    
    return health_data

@router.get("/readiness")
async def readiness_check():
    """Kubernetes readiness probe endpoint"""
    # Check if all critical components are ready
    components_ready = {
        "neo4j": True,  # Would check actual Neo4j connectivity
        "api": True
    }
    
    all_ready = all(components_ready.values())
    
    if all_ready:
        return {"status": "ready", "components": components_ready}
    else:
        raise HTTPException(status_code=503, detail={"status": "not_ready", "components": components_ready})

@router.get("/liveness")
async def liveness_check():
    """Kubernetes liveness probe endpoint"""
    # Basic liveness check - if this endpoint responds, the app is alive
    return {"status": "alive", "timestamp": datetime.utcnow().isoformat()}