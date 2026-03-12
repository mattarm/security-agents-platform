"""
Identity Threat Response System - Main Application

Main entry point for the automated identity threat response system.
Handles webhook endpoints, background processing, and system coordination.
"""

import asyncio
import logging
import signal
import sys
import os
from pathlib import Path
from typing import Dict, Any
import yaml
from datetime import datetime
import uvicorn
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import json

# Add src to path for imports
sys.path.append(str(Path(__file__).parent / "src"))

from src.core.response_engine import IdentityThreatResponseEngine, ThreatEvent, ThreatLevel
from src.integrations.panther import PantherIntegration
from src.integrations.crowdstrike import CrowdStrikeIntegration
from src.integrations.thehive import TheHiveIntegration
from src.incident.notification_system import NotificationSystem


class IdentityResponseApplication:
    """Main application class for the identity threat response system"""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """Initialize the application"""
        self.config = self._load_config(config_path)
        self.app = FastAPI(
            title="Identity Threat Response System",
            description="Automated response to identity-based security threats",
            version="1.0.0"
        )
        
        # Configure CORS
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # Configure appropriately for production
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Initialize core components
        self.response_engine = None
        self.panther_integration = None
        self.crowdstrike_integration = None
        self.thehive_integration = None
        self.notification_system = None
        
        # Setup logging
        self._setup_logging()
        
        # Setup API routes
        self._setup_routes()
        
        # Graceful shutdown handling
        self.shutdown_event = asyncio.Event()
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("Identity Threat Response System initialized")

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as file:
                config = yaml.safe_load(file)
                
            # Expand environment variables
            self._expand_env_vars(config)
            
            return config
        except Exception as e:
            print(f"Error loading config: {e}")
            sys.exit(1)

    def _expand_env_vars(self, obj):
        """Recursively expand environment variables in config"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                obj[key] = self._expand_env_vars(value)
        elif isinstance(obj, list):
            obj = [self._expand_env_vars(item) for item in obj]
        elif isinstance(obj, str) and obj.startswith('${') and obj.endswith('}'):
            env_var = obj[2:-1]
            obj = os.getenv(env_var, obj)
        return obj

    def _setup_logging(self):
        """Setup application logging"""
        log_level = self.config.get('audit', {}).get('log_level', 'INFO')
        log_file = self.config.get('audit', {}).get('log_file', 'logs/application.log')
        
        # Ensure log directory exists
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )

    def _setup_routes(self):
        """Setup FastAPI routes"""
        
        @self.app.on_event("startup")
        async def startup():
            await self.initialize_components()

        @self.app.on_event("shutdown")
        async def shutdown():
            await self.cleanup()

        @self.app.get("/")
        async def root():
            return {"message": "Identity Threat Response System", "status": "running"}

        @self.app.get("/health")
        async def health_check():
            """System health check endpoint"""
            try:
                if not self.response_engine:
                    return JSONResponse(
                        status_code=503,
                        content={"status": "unhealthy", "message": "System not initialized"}
                    )
                
                health = await self.response_engine.health_check()
                status_code = 200 if health["status"] == "healthy" else 503
                
                return JSONResponse(status_code=status_code, content=health)
                
            except Exception as e:
                return JSONResponse(
                    status_code=503,
                    content={"status": "unhealthy", "error": str(e)}
                )

        @self.app.post("/webhooks/panther")
        async def panther_webhook(request: Request, background_tasks: BackgroundTasks):
            """Handle Panther SIEM webhooks"""
            try:
                payload = await request.json()
                headers = dict(request.headers)
                
                if not self.panther_integration:
                    raise HTTPException(status_code=503, detail="Panther integration not available")
                
                # Process webhook in background
                background_tasks.add_task(
                    self._process_panther_webhook, payload, headers
                )
                
                return {"status": "accepted", "timestamp": datetime.now().isoformat()}
                
            except Exception as e:
                self.logger.error(f"Error processing Panther webhook: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.post("/webhooks/crowdstrike")
        async def crowdstrike_webhook(request: Request, background_tasks: BackgroundTasks):
            """Handle CrowdStrike detection webhooks"""
            try:
                payload = await request.json()
                
                if not self.crowdstrike_integration:
                    raise HTTPException(status_code=503, detail="CrowdStrike integration not available")
                
                # Process webhook in background
                background_tasks.add_task(
                    self._process_crowdstrike_webhook, payload
                )
                
                return {"status": "accepted", "timestamp": datetime.now().isoformat()}
                
            except Exception as e:
                self.logger.error(f"Error processing CrowdStrike webhook: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.post("/manual/threat")
        async def manual_threat_submission(request: Request, background_tasks: BackgroundTasks):
            """Manual threat event submission endpoint"""
            try:
                payload = await request.json()
                
                # Create threat event from manual submission
                threat_event = ThreatEvent(
                    id=f"manual_{datetime.now().timestamp()}",
                    source="manual",
                    threat_type=payload['threat_type'],
                    level=ThreatLevel(payload['level']),
                    user_id=payload['user_id'],
                    user_email=payload['user_email'],
                    timestamp=datetime.now(),
                    indicators=payload.get('indicators', {}),
                    context=payload.get('context', {}),
                    ip_address=payload.get('ip_address'),
                    user_agent=payload.get('user_agent'),
                    device_id=payload.get('device_id')
                )
                
                # Process threat event in background
                background_tasks.add_task(
                    self._process_threat_event, threat_event
                )
                
                return {
                    "status": "accepted",
                    "threat_event_id": threat_event.id,
                    "timestamp": datetime.now().isoformat()
                }
                
            except Exception as e:
                self.logger.error(f"Error processing manual threat submission: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/status/{threat_event_id}")
        async def get_threat_status(threat_event_id: str):
            """Get status of threat event response"""
            try:
                if not self.response_engine:
                    raise HTTPException(status_code=503, detail="Response engine not available")
                
                status = await self.response_engine.get_response_status(threat_event_id)
                return status
                
            except Exception as e:
                self.logger.error(f"Error getting threat status: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.post("/approve/{action_id}")
        async def approve_action(action_id: str, request: Request):
            """Approve a pending response action"""
            try:
                payload = await request.json()
                approver = payload.get('approver', 'unknown')
                
                if not self.response_engine:
                    raise HTTPException(status_code=503, detail="Response engine not available")
                
                success = await self.response_engine.approve_action(action_id, approver)
                
                if success:
                    return {"status": "approved", "action_id": action_id, "approver": approver}
                else:
                    raise HTTPException(status_code=404, detail="Action not found or already processed")
                    
            except Exception as e:
                self.logger.error(f"Error approving action: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/metrics")
        async def get_metrics():
            """Get system metrics and statistics"""
            try:
                if not self.response_engine:
                    raise HTTPException(status_code=503, detail="Response engine not available")
                
                health = await self.response_engine.health_check()
                
                return {
                    "system_health": health,
                    "timestamp": datetime.now().isoformat()
                }
                
            except Exception as e:
                self.logger.error(f"Error getting metrics: {e}")
                raise HTTPException(status_code=500, detail=str(e))

    async def initialize_components(self):
        """Initialize all system components"""
        self.logger.info("Initializing system components...")
        
        try:
            # Initialize response engine
            self.response_engine = IdentityThreatResponseEngine("config/config.yaml")
            
            # Initialize integrations
            if self.config['siem']['panther']['enabled']:
                self.panther_integration = PantherIntegration(self.config['siem']['panther'])
            
            if self.config['siem']['crowdstrike']['enabled']:
                self.crowdstrike_integration = CrowdStrikeIntegration(self.config['siem']['crowdstrike'])
            
            # Initialize TheHive integration
            self.thehive_integration = TheHiveIntegration(self.config['thehive'])
            
            # Initialize notification system
            self.notification_system = NotificationSystem(self.config['notifications'])
            
            self.logger.info("All components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing components: {e}")
            raise

    async def cleanup(self):
        """Cleanup system components"""
        self.logger.info("Shutting down system components...")
        
        try:
            if self.panther_integration:
                await self.panther_integration.close()
            
            if self.crowdstrike_integration:
                await self.crowdstrike_integration.close()
            
            if self.thehive_integration:
                await self.thehive_integration.close()
            
            if self.notification_system:
                await self.notification_system.close()
                
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

    async def _process_panther_webhook(self, payload: Dict[str, Any], headers: Dict[str, str]):
        """Process Panther webhook in background"""
        try:
            if not self.panther_integration:
                return
            
            # Convert webhook to threat events
            threat_events = await self.panther_integration.process_webhook(payload, headers)
            
            # Process each threat event
            for threat_event in threat_events:
                await self._process_threat_event(threat_event)
                
        except Exception as e:
            self.logger.error(f"Error processing Panther webhook: {e}")

    async def _process_crowdstrike_webhook(self, payload: Dict[str, Any]):
        """Process CrowdStrike webhook in background"""
        try:
            if not self.crowdstrike_integration:
                return
            
            # Convert detection to threat events
            threat_events = await self.crowdstrike_integration.process_detection_alert(payload)
            
            # Process each threat event
            for threat_event in threat_events:
                await self._process_threat_event(threat_event)
                
        except Exception as e:
            self.logger.error(f"Error processing CrowdStrike webhook: {e}")

    async def _process_threat_event(self, threat_event: ThreatEvent):
        """Process a threat event through the response engine"""
        try:
            self.logger.info(f"Processing threat event: {threat_event.id}")
            
            # Process through response engine
            response_actions = await self.response_engine.process_threat_event(threat_event)
            
            self.logger.info(f"Processed threat event {threat_event.id}: {len(response_actions)} actions executed")
            
        except Exception as e:
            self.logger.error(f"Error processing threat event {threat_event.id}: {e}")

    def setup_signal_handlers(self):
        """Setup graceful shutdown signal handlers"""
        def signal_handler(signum, frame):
            self.logger.info(f"Received signal {signum}, initiating graceful shutdown...")
            self.shutdown_event.set()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    def run(self, host: str = "0.0.0.0", port: int = 8000, workers: int = 1):
        """Run the application"""
        self.setup_signal_handlers()
        
        self.logger.info(f"Starting Identity Threat Response System on {host}:{port}")
        
        # Run with uvicorn
        uvicorn.run(
            self.app,
            host=host,
            port=port,
            workers=workers,
            log_level="info",
            access_log=True
        )


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Identity Threat Response System')
    parser.add_argument('--config', '-c', default='config/config.yaml',
                       help='Configuration file path')
    parser.add_argument('--host', default='0.0.0.0',
                       help='Host to bind to')
    parser.add_argument('--port', type=int, default=8000,
                       help='Port to bind to')
    parser.add_argument('--workers', type=int, default=1,
                       help='Number of worker processes')
    
    args = parser.parse_args()
    
    # Validate config file exists
    if not Path(args.config).exists():
        print(f"Error: Configuration file {args.config} not found")
        print("Please copy config/config.example.yaml to config/config.yaml and configure")
        sys.exit(1)
    
    # Create and run application
    app = IdentityResponseApplication(args.config)
    app.run(host=args.host, port=args.port, workers=args.workers)


if __name__ == "__main__":
    main()