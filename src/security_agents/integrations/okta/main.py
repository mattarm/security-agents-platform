"""
Okta Identity Security Integration - Main Application

Comprehensive identity security monitoring and response platform
integrating Okta with advanced threat detection and SIEM forwarding.
"""

import asyncio
import signal
import sys
import os
import yaml
import logging
from typing import Dict, List, Optional
from datetime import datetime
import threading
import time
from pathlib import Path

import structlog
import click
from prometheus_client import start_http_server, Counter, Histogram, Gauge
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from okta_security import OktaSecurityClient, EventCollector, AuthManager
from analytics import CorrelationEngine, ThreatDetector, RulesEngine
from response import ActionExecutor, OktaResponseActions, NotificationManager
from siem import UniversalFormatter, PantherForwarder, CrowdStrikeForwarder
from siem.panther_forwarder import PantherConfig
from siem.crowdstrike_forwarder import CrowdStrikeConfig

# Setup structured logging
structlog.configure(
    processors=[
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

# Prometheus metrics
EVENTS_PROCESSED = Counter('okta_events_processed_total', 'Total events processed')
THREATS_DETECTED = Counter('okta_threats_detected_total', 'Total threats detected')
ACTIONS_EXECUTED = Counter('okta_actions_executed_total', 'Total response actions executed')
PROCESSING_TIME = Histogram('okta_processing_seconds', 'Time spent processing events')
ACTIVE_SESSIONS = Gauge('okta_active_sessions', 'Number of active user sessions tracked')
SIEM_EVENTS_FORWARDED = Counter('okta_siem_events_forwarded_total', 'Events forwarded to SIEM', ['destination'])


class OktaSecurityIntegration:
    """
    Main application class orchestrating the complete Okta security platform.
    
    Integrates:
    - Okta API client and event collection
    - Analytics engines (correlation, threat detection, rules)
    - Response system with automated actions
    - SIEM forwarding to multiple platforms
    - Monitoring and health checks
    """
    
    def __init__(self, config_path: str = "config/config.yml"):
        self.config = self._load_config(config_path)
        self.running = False
        
        # Initialize components
        self.okta_client: Optional[OktaSecurityClient] = None
        self.event_collector: Optional[EventCollector] = None
        self.correlation_engine: Optional[CorrelationEngine] = None
        self.threat_detector: Optional[ThreatDetector] = None
        self.rules_engine: Optional[RulesEngine] = None
        self.action_executor: Optional[ActionExecutor] = None
        self.notification_manager: Optional[NotificationManager] = None
        self.panther_forwarder: Optional[PantherForwarder] = None
        self.crowdstrike_forwarder: Optional[CrowdStrikeForwarder] = None
        
        # Health check API
        self.app = FastAPI(title="Okta Security Integration", version="1.0.0")
        self._setup_health_endpoints()
        
        # Shutdown handling
        self._setup_signal_handlers()
        
        logger.info("Okta Security Integration initialized", config_file=config_path)
    
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file"""
        try:
            config_file = Path(config_path)
            if not config_file.exists():
                # Try example config
                example_config = config_file.parent / "config.example.yml"
                if example_config.exists():
                    logger.warning("Using example config file", 
                                 original=config_path, 
                                 fallback=str(example_config))
                    config_file = example_config
                else:
                    raise FileNotFoundError(f"Configuration file not found: {config_path}")
            
            with open(config_file) as f:
                config = yaml.safe_load(f)
            
            # Environment variable substitution
            config = self._substitute_env_vars(config)
            
            logger.info("Configuration loaded successfully", config_file=str(config_file))
            return config
            
        except Exception as e:
            logger.error("Failed to load configuration", error=str(e))
            raise
    
    def _substitute_env_vars(self, config: Dict) -> Dict:
        """Recursively substitute environment variables in config"""
        if isinstance(config, dict):
            return {k: self._substitute_env_vars(v) for k, v in config.items()}
        elif isinstance(config, list):
            return [self._substitute_env_vars(item) for item in config]
        elif isinstance(config, str) and config.startswith('${') and config.endswith('}'):
            env_var = config[2:-1]
            default_value = None
            
            # Handle default values: ${VAR:default}
            if ':' in env_var:
                env_var, default_value = env_var.split(':', 1)
            
            return os.getenv(env_var, default_value)
        else:
            return config
    
    def _setup_signal_handlers(self):
        """Setup graceful shutdown handlers"""
        def signal_handler(signum, frame):
            logger.info("Received shutdown signal", signal=signum)
            self.shutdown()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def _setup_health_endpoints(self):
        """Setup health check and monitoring endpoints"""
        
        @self.app.get("/health")
        async def health_check():
            """Comprehensive health check"""
            health_status = {
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'healthy',
                'components': {}
            }
            
            try:
                # Check Okta connectivity
                if self.okta_client:
                    okta_health = self.okta_client.health_check()
                    health_status['components']['okta'] = okta_health
                
                # Check event collector
                if self.event_collector:
                    collector_health = self.event_collector.health_check()
                    health_status['components']['event_collector'] = collector_health
                
                # Check analytics engines
                if self.correlation_engine:
                    corr_stats = self.correlation_engine.get_correlation_stats()
                    health_status['components']['correlation_engine'] = {
                        'status': 'healthy',
                        'active_sessions': corr_stats.get('active_sessions', 0),
                        'patterns_detected': corr_stats.get('attack_patterns', 0)
                    }
                
                # Check SIEM forwarders
                if self.panther_forwarder:
                    panther_health = self.panther_forwarder.test_connectivity()
                    health_status['components']['panther'] = panther_health
                
                if self.crowdstrike_forwarder:
                    cs_health = self.crowdstrike_forwarder.test_connectivity()
                    health_status['components']['crowdstrike'] = cs_health
                
                # Overall status assessment
                component_statuses = [
                    comp.get('overall_status', comp.get('status') == 'healthy')
                    for comp in health_status['components'].values()
                ]
                
                if all(component_statuses):
                    health_status['status'] = 'healthy'
                elif any(component_statuses):
                    health_status['status'] = 'degraded'
                else:
                    health_status['status'] = 'unhealthy'
                
            except Exception as e:
                health_status['status'] = 'error'
                health_status['error'] = str(e)
            
            status_code = 200 if health_status['status'] in ['healthy', 'degraded'] else 503
            return JSONResponse(content=health_status, status_code=status_code)
        
        @self.app.get("/metrics")
        async def metrics():
            """Prometheus metrics endpoint"""
            from prometheus_client import generate_latest
            return Response(content=generate_latest(), media_type="text/plain")
        
        @self.app.get("/statistics")
        async def statistics():
            """Detailed statistics endpoint"""
            stats = {
                'timestamp': datetime.utcnow().isoformat(),
                'uptime': time.time() - self.start_time if hasattr(self, 'start_time') else 0
            }
            
            try:
                if self.event_collector:
                    stats['event_collection'] = self.event_collector.get_streaming_stats()
                
                if self.correlation_engine:
                    stats['correlation'] = self.correlation_engine.get_correlation_stats()
                
                if self.threat_detector:
                    stats['threat_detection'] = self.threat_detector.get_threat_statistics()
                
                if self.rules_engine:
                    stats['rules_engine'] = self.rules_engine.get_rule_statistics()
                
                if self.action_executor:
                    stats['response_actions'] = self.action_executor.get_action_statistics()
                
                if self.notification_manager:
                    stats['notifications'] = self.notification_manager.get_notification_statistics()
                
                if self.panther_forwarder:
                    stats['panther_siem'] = self.panther_forwarder.get_statistics()
                
                if self.crowdstrike_forwarder:
                    stats['crowdstrike_siem'] = self.crowdstrike_forwarder.get_statistics()
                
            except Exception as e:
                stats['error'] = str(e)
            
            return stats
    
    async def initialize(self):
        """Initialize all components"""
        logger.info("Initializing Okta Security Integration components")
        
        try:
            # Initialize Okta client
            okta_config = self.config.get('okta', {})
            self.okta_client = OktaSecurityClient(
                org_url=okta_config['org_url'],
                api_token=okta_config.get('api_token'),
                oauth_client_id=okta_config.get('oauth', {}).get('client_id'),
                oauth_private_key=okta_config.get('oauth', {}).get('private_key_path'),
                rate_limit_buffer=okta_config.get('rate_limit_buffer', 10),
                circuit_breaker_enabled=okta_config.get('circuit_breaker_enabled', True)
            )
            
            # Initialize event collector
            collection_config = self.config.get('event_collection', {})
            if collection_config.get('enabled', True):
                self.event_collector = EventCollector(
                    okta_client=self.okta_client,
                    redis_url=collection_config.get('redis', {}).get('url', 'redis://localhost:6379'),
                    buffer_size=collection_config.get('buffer_size', 10000),
                    poll_interval=collection_config.get('poll_interval', 30),
                    enable_enrichment=collection_config.get('enable_enrichment', True)
                )
                
                # Add event handlers
                self.event_collector.add_handler(self._process_event)
            
            # Initialize analytics engines
            analytics_config = self.config.get('analytics', {})
            
            # Correlation engine
            corr_config = analytics_config.get('correlation', {})
            self.correlation_engine = CorrelationEngine(
                window_size=corr_config.get('window_size', 3600)
            )
            
            # Threat detector
            threat_config = analytics_config.get('threat_detection', {})
            if threat_config.get('enable_ml_detection', True):
                self.threat_detector = ThreatDetector(
                    model_path=threat_config.get('model_path', './models/')
                )
            
            # Rules engine
            rules_config = analytics_config.get('rules', {})
            self.rules_engine = RulesEngine(
                rules_config_path=rules_config.get('config_path')
            )
            
            # Initialize response system
            response_config = self.config.get('response', {})
            if response_config.get('enabled', True):
                # Notification manager
                notification_config = self.config.get('notifications', {})
                if notification_config.get('enabled', True):
                    self.notification_manager = NotificationManager(notification_config)
                
                # Action executor
                self.action_executor = ActionExecutor(
                    okta_client=self.okta_client,
                    notification_manager=self.notification_manager,
                    require_approval=response_config.get('require_approval', True),
                    auto_approve_low_severity=response_config.get('auto_approve_low_severity', True)
                )
            
            # Initialize SIEM forwarders
            siem_config = self.config.get('siem', {})
            
            # Panther
            panther_config = siem_config.get('panther', {})
            if panther_config.get('enabled', False):
                self.panther_forwarder = PantherForwarder(PantherConfig(
                    http_endpoint=panther_config.get('http_endpoint'),
                    auth_token=panther_config.get('auth_token'),
                    s3_bucket=panther_config.get('s3_bucket'),
                    s3_prefix=panther_config.get('s3_prefix', 'okta-logs'),
                    s3_region=panther_config.get('s3_region', 'us-east-1'),
                    aws_access_key_id=panther_config.get('aws_access_key_id'),
                    aws_secret_access_key=panther_config.get('aws_secret_access_key'),
                    delivery_method=panther_config.get('delivery_method', 'http'),
                    batch_size=panther_config.get('batch_size', 1000),
                    batch_timeout=panther_config.get('batch_timeout', 300),
                    compression=panther_config.get('compression', True),
                    max_retries=panther_config.get('max_retries', 3),
                    retry_delay=panther_config.get('retry_delay', 5)
                ))
            
            # CrowdStrike
            cs_config = siem_config.get('crowdstrike', {})
            if cs_config.get('enabled', False):
                self.crowdstrike_forwarder = CrowdStrikeForwarder(CrowdStrikeConfig(
                    logscale_url=cs_config.get('logscale_url'),
                    repository=cs_config.get('repository', 'okta-logs'),
                    ingest_token=cs_config.get('ingest_token'),
                    api_token=cs_config.get('api_token'),
                    datasource=cs_config.get('datasource', 'okta-identity-security'),
                    parser=cs_config.get('parser', 'json'),
                    batch_size=cs_config.get('batch_size', 1000),
                    batch_timeout=cs_config.get('batch_timeout', 60),
                    compression=cs_config.get('compression', True),
                    max_retries=cs_config.get('max_retries', 3),
                    retry_delay=cs_config.get('retry_delay', 2)
                ))
            
            logger.info("All components initialized successfully")
            
        except Exception as e:
            logger.error("Component initialization failed", error=str(e))
            raise
    
    async def start(self):
        """Start the security integration platform"""
        self.start_time = time.time()
        logger.info("Starting Okta Security Integration platform")
        
        try:
            # Initialize all components
            await self.initialize()
            
            # Start monitoring server if enabled
            monitoring_config = self.config.get('monitoring', {})
            if monitoring_config.get('enabled', True):
                if monitoring_config.get('prometheus', {}).get('enabled', True):
                    prometheus_port = monitoring_config.get('prometheus', {}).get('port', 8080)
                    start_http_server(prometheus_port)
                    logger.info("Prometheus metrics server started", port=prometheus_port)
                
                # Start health check API
                if monitoring_config.get('health_check', {}).get('enabled', True):
                    health_port = monitoring_config.get('health_check', {}).get('port', 8080)
                    config = uvicorn.Config(
                        self.app,
                        host="0.0.0.0",
                        port=health_port,
                        log_config=None  # Disable uvicorn's logging
                    )
                    server = uvicorn.Server(config)
                    
                    # Start server in background
                    threading.Thread(target=server.run, daemon=True).start()
                    logger.info("Health check API started", port=health_port)
            
            # Start event collection
            if self.event_collector:
                self.event_collector.start_streaming()
                logger.info("Event streaming started")
            
            self.running = True
            logger.info("Okta Security Integration platform started successfully")
            
            # Keep main thread alive
            while self.running:
                await asyncio.sleep(1)
            
        except Exception as e:
            logger.error("Platform startup failed", error=str(e))
            raise
    
    def _process_event(self, event: Dict):
        """Process incoming Okta event through analytics pipeline"""
        try:
            EVENTS_PROCESSED.inc()
            
            with PROCESSING_TIME.time():
                # Process through correlation engine
                if self.correlation_engine:
                    self.correlation_engine.process_event(event)
                
                # Process through rules engine
                if self.rules_engine:
                    rule_matches = self.rules_engine.process_events([event])
                    
                    for match in rule_matches:
                        logger.info("Rule triggered", 
                                   rule_id=match.rule_id,
                                   rule_name=match.rule_name,
                                   severity=match.severity.value)
                        
                        # Create response actions if enabled
                        if self.action_executor and hasattr(match, 'auto_response') and match.auto_response:
                            actions = self.action_executor.process_rule_match(match, auto_execute=True)
                            ACTIONS_EXECUTED.inc(len(actions))
                
                # Process through threat detector
                if self.threat_detector:
                    threats = self.threat_detector.detect_threats([event])
                    
                    for threat in threats:
                        logger.warning("Threat detected",
                                     threat_type=threat.threat_type,
                                     severity=threat.severity,
                                     confidence=threat.confidence)
                        
                        THREATS_DETECTED.inc()
                        
                        # Send threat notification
                        if self.notification_manager:
                            self.notification_manager.send_threat_alert(threat)
                        
                        # Create response actions if enabled
                        if self.action_executor:
                            actions = self.action_executor.process_alert(threat, auto_execute=True)
                            ACTIONS_EXECUTED.inc(len(actions))
                
                # Forward to SIEM platforms
                if self.panther_forwarder:
                    success = self.panther_forwarder.forward_event(event)
                    if success:
                        SIEM_EVENTS_FORWARDED.labels(destination='panther').inc()
                
                if self.crowdstrike_forwarder:
                    success = self.crowdstrike_forwarder.forward_event(event)
                    if success:
                        SIEM_EVENTS_FORWARDED.labels(destination='crowdstrike').inc()
                
                # Update active sessions metric
                if self.correlation_engine:
                    stats = self.correlation_engine.get_correlation_stats()
                    ACTIVE_SESSIONS.set(stats.get('active_sessions', 0))
            
        except Exception as e:
            logger.error("Event processing failed", 
                        event_id=event.get('uuid'),
                        error=str(e))
    
    def shutdown(self):
        """Graceful shutdown"""
        logger.info("Shutting down Okta Security Integration platform")
        
        self.running = False
        
        try:
            # Stop event collection
            if self.event_collector:
                self.event_collector.stop_streaming()
                logger.info("Event streaming stopped")
            
            # Flush SIEM forwarders
            if self.panther_forwarder:
                self.panther_forwarder.shutdown()
                logger.info("Panther forwarder shut down")
            
            if self.crowdstrike_forwarder:
                self.crowdstrike_forwarder.shutdown()
                logger.info("CrowdStrike forwarder shut down")
            
            logger.info("Platform shutdown complete")
            
        except Exception as e:
            logger.error("Shutdown error", error=str(e))


# CLI Interface
@click.group()
def cli():
    """Okta Identity Security Integration Platform"""
    pass


@cli.command()
@click.option('--config', '-c', default='config/config.yml', help='Configuration file path')
@click.option('--debug', is_flag=True, help='Enable debug logging')
def run(config, debug):
    """Run the security integration platform"""
    
    # Configure logging
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=log_level)
    
    # Create and run platform
    platform = OktaSecurityIntegration(config)
    
    try:
        asyncio.run(platform.start())
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error("Platform error", error=str(e))
        sys.exit(1)


@cli.command()
@click.option('--config', '-c', default='config/config.yml', help='Configuration file path')
def test_connectivity(config):
    """Test connectivity to all configured services"""
    
    platform = OktaSecurityIntegration(config)
    
    async def test_all():
        await platform.initialize()
        
        print("\\n=== Okta Security Integration - Connectivity Test ===\\n")
        
        # Test Okta
        if platform.okta_client:
            print("Testing Okta connectivity...")
            health = platform.okta_client.health_check()
            print(f"  Okta API: {'✓' if health['okta_connectivity'] else '✗'}")
            print(f"  API Permissions: {'✓' if health['api_permissions'] else '✗'}")
        
        # Test SIEM forwarders
        if platform.panther_forwarder:
            print("\\nTesting Panther connectivity...")
            result = platform.panther_forwarder.test_connectivity()
            print(f"  HTTP Endpoint: {'✓' if result.get('http_connectivity') else '✗'}")
            print(f"  S3 Access: {'✓' if result.get('s3_connectivity') else '✗'}")
            print(f"  Overall: {'✓' if result.get('overall_status') else '✗'}")
        
        if platform.crowdstrike_forwarder:
            print("\\nTesting CrowdStrike connectivity...")
            result = platform.crowdstrike_forwarder.test_connectivity()
            print(f"  LogScale API: {'✓' if result.get('logscale_connectivity') else '✗'}")
            print(f"  Repository Access: {'✓' if result.get('repository_access') else '✗'}")
            print(f"  Ingest Test: {'✓' if result.get('ingest_test') else '✗'}")
            print(f"  Overall: {'✓' if result.get('overall_status') else '✗'}")
        
        print("\\nConnectivity test completed.\\n")
    
    try:
        asyncio.run(test_all())
    except Exception as e:
        print(f"Connectivity test failed: {e}")
        sys.exit(1)


@cli.command()
@click.option('--config', '-c', default='config/config.yml', help='Configuration file path')
@click.option('--hours', default=1, help='Hours of events to collect')
def collect_events(config, hours):
    """Collect events for testing and model training"""
    
    platform = OktaSecurityIntegration(config)
    
    async def collect():
        await platform.initialize()
        
        print(f"Collecting {hours} hours of events for analysis...")
        
        # Get events from last N hours
        from datetime import datetime, timedelta
        since = datetime.utcnow() - timedelta(hours=hours)
        
        events = platform.okta_client.get_system_logs(
            since=since,
            limit=10000
        )
        
        print(f"Collected {len(events)} events")
        
        # Save to file for analysis
        import json
        output_file = f"events_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(output_file, 'w') as f:
            json.dump(events, f, indent=2, default=str)
        
        print(f"Events saved to {output_file}")
    
    try:
        asyncio.run(collect())
    except Exception as e:
        print(f"Event collection failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    cli()