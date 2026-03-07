#!/usr/bin/env python3
"""
Agent Orchestration System - Production-Ready Multi-Agent Security Platform
Coordinates Alpha-4 Threat Intel, Beta-4 DevSecOps, and Intelligence Fusion
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import uuid
from pathlib import Path
import signal
import sys

# Import our agent systems
from intelligence_fusion_engine import IntelligenceFusionEngine, IntelligencePacket, IntelligenceType, Priority
from tiger_team_alpha_4 import AdvancedThreatIntelligence, ThreatCampaign
from tiger_team_beta_4 import AdvancedDevSecOpsEngine, SecurityVulnerability

class AgentStatus(Enum):
    INITIALIZING = "initializing"
    ACTIVE = "active"
    BUSY = "busy"
    ERROR = "error"
    OFFLINE = "offline"

class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class AgentInfo:
    """Agent information and status"""
    agent_id: str
    agent_type: str
    status: AgentStatus
    capabilities: List[str]
    last_heartbeat: datetime
    tasks_completed: int
    tasks_failed: int
    uptime: timedelta
    metadata: Dict[str, Any]

@dataclass
class SecurityTask:
    """Security analysis task for agent execution"""
    task_id: str
    task_type: str
    priority: Priority
    assigned_agent: str
    status: TaskStatus
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    parameters: Dict[str, Any]
    results: Optional[Dict[str, Any]]
    error_message: Optional[str]

@dataclass
class AnalysisRequest:
    """High-level analysis request"""
    request_id: str
    requester: str
    analysis_type: str  # comprehensive, threat_focused, vulnerability_focused
    target: str
    priority: Priority
    parameters: Dict[str, Any]
    created_at: datetime
    estimated_duration: Optional[int]  # seconds

class SecurityAgentOrchestrator:
    """Production-ready orchestration system for security agents"""
    
    def __init__(self, config_file: str = None):
        self.config = self.load_configuration(config_file)
        self.agents = {}  # agent_id -> AgentInfo
        self.tasks = {}  # task_id -> SecurityTask
        self.task_queue = asyncio.Queue()
        self.results_queue = asyncio.Queue()
        
        # Initialize agent systems
        self.fusion_engine = IntelligenceFusionEngine()
        self.threat_intel_agent = None
        self.devsecops_agent = None
        
        # Orchestration state
        self.running = False
        self.shutdown_event = asyncio.Event()
        
        # Metrics and monitoring
        self.metrics = {
            'requests_processed': 0,
            'tasks_completed': 0,
            'tasks_failed': 0,
            'avg_response_time': 0.0,
            'active_agents': 0,
            'intelligence_correlations': 0,
            'uptime_start': datetime.now()
        }
        
        # Set up logging
        self.setup_logging()
        self.logger = logging.getLogger(__name__)
        
        print("🎯 Security Agent Orchestrator initialized")

    def load_configuration(self, config_file: str = None) -> Dict[str, Any]:
        """Load orchestrator configuration"""
        default_config = {
            'agents': {
                'alpha_4_threat_intel': {
                    'enabled': True,
                    'max_concurrent_tasks': 3,
                    'timeout': 300,
                    'capabilities': ['threat_campaigns', 'actor_profiling', 'ioc_enrichment']
                },
                'beta_4_devsecops': {
                    'enabled': True,
                    'max_concurrent_tasks': 5,
                    'timeout': 600,
                    'capabilities': ['sast_analysis', 'container_security', 'iac_security', 'supply_chain']
                }
            },
            'fusion_engine': {
                'enabled': True,
                'correlation_rules_file': None,
                'intelligence_retention_hours': 24
            },
            'orchestration': {
                'max_queue_size': 100,
                'heartbeat_interval': 30,
                'cleanup_interval': 300,
                'task_timeout': 900
            },
            'api': {
                'host': '0.0.0.0',
                'port': 8080,
                'cors_enabled': True
            },
            'logging': {
                'level': 'INFO',
                'file': 'orchestrator.log'
            }
        }
        
        if config_file and Path(config_file).exists():
            try:
                with open(config_file, 'r') as f:
                    custom_config = json.load(f)
                default_config.update(custom_config)
            except Exception as e:
                print(f"⚠️ Failed to load config file {config_file}: {e}")
        
        return default_config

    def setup_logging(self):
        """Configure logging for the orchestrator"""
        log_config = self.config.get('logging', {})
        
        logging.basicConfig(
            level=getattr(logging, log_config.get('level', 'INFO')),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(log_config.get('file', 'orchestrator.log'))
            ]
        )

    async def initialize_agents(self):
        """Initialize all configured agents"""
        
        self.logger.info("🚀 Initializing security agents...")
        
        # Initialize Alpha-4 Threat Intelligence Agent
        if self.config['agents']['alpha_4_threat_intel']['enabled']:
            self.threat_intel_agent = AdvancedThreatIntelligence()
            
            agent_info = AgentInfo(
                agent_id='alpha_4_threat_intel',
                agent_type='threat_intelligence',
                status=AgentStatus.INITIALIZING,
                capabilities=self.config['agents']['alpha_4_threat_intel']['capabilities'],
                last_heartbeat=datetime.now(),
                tasks_completed=0,
                tasks_failed=0,
                uptime=timedelta(),
                metadata={'version': '2.0', 'specialization': 'threat_campaigns'}
            )
            
            self.agents['alpha_4_threat_intel'] = agent_info
            
            # Subscribe to intelligence fusion
            self.fusion_engine.subscribe_agent('alpha_4_threat_intel', [
                IntelligenceType.VULNERABILITY,
                IntelligenceType.INFRASTRUCTURE,
                IntelligenceType.CORRELATION
            ])
            
            agent_info.status = AgentStatus.ACTIVE
            self.logger.info("✅ Alpha-4 Threat Intelligence Agent initialized")
        
        # Initialize Beta-4 DevSecOps Agent
        if self.config['agents']['beta_4_devsecops']['enabled']:
            self.devsecops_agent = AdvancedDevSecOpsEngine()
            
            agent_info = AgentInfo(
                agent_id='beta_4_devsecops',
                agent_type='devsecops',
                status=AgentStatus.INITIALIZING,
                capabilities=self.config['agents']['beta_4_devsecops']['capabilities'],
                last_heartbeat=datetime.now(),
                tasks_completed=0,
                tasks_failed=0,
                uptime=timedelta(),
                metadata={'version': '2.0', 'specialization': 'comprehensive_security'}
            )
            
            self.agents['beta_4_devsecops'] = agent_info
            
            # Subscribe to intelligence fusion
            self.fusion_engine.subscribe_agent('beta_4_devsecops', [
                IntelligenceType.THREAT_CAMPAIGN,
                IntelligenceType.ACTOR_PROFILE,
                IntelligenceType.IOC_ENRICHMENT,
                IntelligenceType.CORRELATION
            ])
            
            agent_info.status = AgentStatus.ACTIVE
            self.logger.info("✅ Beta-4 DevSecOps Agent initialized")
        
        # Update metrics
        self.metrics['active_agents'] = len([a for a in self.agents.values() if a.status == AgentStatus.ACTIVE])
        
        self.logger.info(f"🎯 {self.metrics['active_agents']} agents active and ready")

    async def start(self):
        """Start the orchestration system"""
        
        self.logger.info("🚀 Starting Security Agent Orchestrator...")
        
        # Initialize agents
        await self.initialize_agents()
        
        # Set running state
        self.running = True
        self.metrics['uptime_start'] = datetime.now()
        
        # Start background tasks
        tasks = [
            asyncio.create_task(self.task_processor()),
            asyncio.create_task(self.heartbeat_monitor()),
            asyncio.create_task(self.cleanup_worker()),
            asyncio.create_task(self.intelligence_processor())
        ]
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        self.logger.info("✅ Orchestrator running - all systems operational")
        
        try:
            # Wait for shutdown signal
            await self.shutdown_event.wait()
        except Exception as e:
            self.logger.error(f"❌ Orchestrator error: {e}")
        finally:
            # Cancel background tasks
            for task in tasks:
                task.cancel()
            
            await self.shutdown()

    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"📡 Received signal {signum}, initiating graceful shutdown...")
        self.shutdown_event.set()

    async def shutdown(self):
        """Graceful shutdown of the orchestrator"""
        
        self.logger.info("🛑 Shutting down Security Agent Orchestrator...")
        
        # Stop accepting new requests
        self.running = False
        
        # Set all agents to offline
        for agent_info in self.agents.values():
            agent_info.status = AgentStatus.OFFLINE
        
        # Cancel pending tasks
        pending_tasks = [task for task in self.tasks.values() 
                        if task.status in [TaskStatus.PENDING, TaskStatus.RUNNING]]
        
        for task in pending_tasks:
            task.status = TaskStatus.CANCELLED
            task.completed_at = datetime.now()
            task.error_message = "System shutdown"
        
        self.logger.info(f"📊 Final metrics: {self.metrics}")
        self.logger.info("✅ Orchestrator shutdown complete")

    async def submit_analysis_request(self, request: AnalysisRequest) -> Dict[str, Any]:
        """Submit a high-level security analysis request"""
        
        if not self.running:
            raise RuntimeError("Orchestrator is not running")
        
        self.logger.info(f"📥 Received analysis request: {request.analysis_type} for {request.target}")
        
        # Decompose request into tasks
        tasks = await self.decompose_analysis_request(request)
        
        # Submit tasks for execution
        task_ids = []
        for task in tasks:
            await self.task_queue.put(task)
            self.tasks[task.task_id] = task
            task_ids.append(task.task_id)
        
        # Update metrics
        self.metrics['requests_processed'] += 1
        
        return {
            'request_id': request.request_id,
            'status': 'accepted',
            'task_count': len(tasks),
            'task_ids': task_ids,
            'estimated_completion': self.estimate_completion_time(tasks)
        }

    async def decompose_analysis_request(self, request: AnalysisRequest) -> List[SecurityTask]:
        """Break down analysis request into specific agent tasks"""
        
        tasks = []
        
        if request.analysis_type in ['comprehensive', 'vulnerability_focused']:
            # DevSecOps analysis task
            devsecops_task = SecurityTask(
                task_id=f"{request.request_id}-devsecops",
                task_type='comprehensive_security_analysis',
                priority=request.priority,
                assigned_agent='beta_4_devsecops',
                status=TaskStatus.PENDING,
                created_at=datetime.now(),
                started_at=None,
                completed_at=None,
                parameters={
                    'target_path': request.target,
                    'include_architecture': True,
                    'include_supply_chain': True,
                    **request.parameters
                },
                results=None,
                error_message=None
            )
            tasks.append(devsecops_task)
        
        if request.analysis_type in ['comprehensive', 'threat_focused']:
            # Threat intelligence task
            threat_task = SecurityTask(
                task_id=f"{request.request_id}-threat-intel",
                task_type='threat_campaign_analysis',
                priority=request.priority,
                assigned_agent='alpha_4_threat_intel',
                status=TaskStatus.PENDING,
                created_at=datetime.now(),
                started_at=None,
                completed_at=None,
                parameters={
                    'analysis_scope': request.target,
                    'context': request.parameters.get('context', ''),
                    **request.parameters
                },
                results=None,
                error_message=None
            )
            tasks.append(threat_task)
        
        return tasks

    async def task_processor(self):
        """Background task processor"""
        
        self.logger.info("🔄 Task processor started")
        
        while self.running:
            try:
                # Get next task from queue
                task = await asyncio.wait_for(self.task_queue.get(), timeout=1.0)
                
                # Execute task
                await self.execute_task(task)
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"❌ Task processor error: {e}")

    async def execute_task(self, task: SecurityTask):
        """Execute a security task using the appropriate agent"""
        
        self.logger.info(f"⚡ Executing task: {task.task_id} ({task.task_type})")
        
        # Update task status
        task.status = TaskStatus.RUNNING
        task.started_at = datetime.now()
        
        # Set agent to busy
        if task.assigned_agent in self.agents:
            self.agents[task.assigned_agent].status = AgentStatus.BUSY
        
        try:
            # Route to appropriate agent
            if task.assigned_agent == 'alpha_4_threat_intel':
                results = await self.execute_threat_intel_task(task)
            elif task.assigned_agent == 'beta_4_devsecops':
                results = await self.execute_devsecops_task(task)
            else:
                raise ValueError(f"Unknown agent: {task.assigned_agent}")
            
            # Update task with results
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.now()
            task.results = results
            
            # Update agent metrics
            if task.assigned_agent in self.agents:
                agent_info = self.agents[task.assigned_agent]
                agent_info.tasks_completed += 1
                agent_info.status = AgentStatus.ACTIVE
            
            # Update global metrics
            self.metrics['tasks_completed'] += 1
            
            # Process intelligence output through fusion engine
            await self.process_task_intelligence(task, results)
            
            self.logger.info(f"✅ Task completed: {task.task_id}")
            
        except Exception as e:
            # Handle task failure
            task.status = TaskStatus.FAILED
            task.completed_at = datetime.now()
            task.error_message = str(e)
            
            # Update agent metrics
            if task.assigned_agent in self.agents:
                agent_info = self.agents[task.assigned_agent]
                agent_info.tasks_failed += 1
                agent_info.status = AgentStatus.ACTIVE
            
            # Update global metrics
            self.metrics['tasks_failed'] += 1
            
            self.logger.error(f"❌ Task failed: {task.task_id} - {e}")

    async def execute_threat_intel_task(self, task: SecurityTask) -> Dict[str, Any]:
        """Execute threat intelligence task"""
        
        if task.task_type == 'threat_campaign_analysis':
            # Extract indicators for analysis
            indicators = task.parameters.get('indicators', [])
            context = task.parameters.get('context', '')
            
            if not indicators:
                # Generate indicators from analysis scope
                indicators = self.extract_indicators_from_scope(task.parameters.get('analysis_scope', ''))
            
            # Run threat campaign analysis
            campaign = await self.threat_intel_agent.analyze_threat_campaign(indicators, context)
            
            if campaign:
                return {
                    'analysis_type': 'threat_campaign',
                    'campaign': asdict(campaign),
                    'indicators_analyzed': len(indicators),
                    'confidence': campaign.confidence,
                    'risk_score': campaign.risk_score
                }
            else:
                return {
                    'analysis_type': 'threat_campaign',
                    'campaign': None,
                    'indicators_analyzed': len(indicators),
                    'message': 'No significant threat campaigns identified'
                }
        
        else:
            raise ValueError(f"Unknown threat intel task type: {task.task_type}")

    async def execute_devsecops_task(self, task: SecurityTask) -> Dict[str, Any]:
        """Execute DevSecOps task"""
        
        if task.task_type == 'comprehensive_security_analysis':
            target_path = task.parameters.get('target_path')
            include_architecture = task.parameters.get('include_architecture', True)
            include_supply_chain = task.parameters.get('include_supply_chain', True)
            
            # Run comprehensive security analysis
            results = await self.devsecops_agent.comprehensive_security_analysis(
                target_path=target_path,
                include_architecture=include_architecture,
                include_supply_chain=include_supply_chain
            )
            
            return {
                'analysis_type': 'devsecops_comprehensive',
                'results': results,
                'vulnerability_count': len(results.get('vulnerabilities', [])),
                'risk_score': results.get('metrics', {}).get('risk_score', 0)
            }
        
        else:
            raise ValueError(f"Unknown DevSecOps task type: {task.task_type}")

    def extract_indicators_from_scope(self, scope: str) -> List[str]:
        """Extract potential threat indicators from analysis scope"""
        import re
        
        indicators = []
        
        # Extract IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, scope)
        indicators.extend(ips)
        
        # Extract domains
        domain_pattern = r'\b[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, scope)
        indicators.extend(domains)
        
        # Extract URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, scope)
        indicators.extend(urls)
        
        return list(set(indicators))  # Remove duplicates

    async def process_task_intelligence(self, task: SecurityTask, results: Dict[str, Any]):
        """Process task results through intelligence fusion engine"""
        
        # Create intelligence packets from task results
        packets = []
        
        if task.assigned_agent == 'alpha_4_threat_intel':
            if 'campaign' in results and results['campaign']:
                packet = IntelligencePacket(
                    packet_id=f"{task.task_id}-campaign",
                    source_agent='alpha_4_threat_intel',
                    target_agents=['beta_4_devsecops'],
                    intelligence_type=IntelligenceType.THREAT_CAMPAIGN,
                    priority=Priority.HIGH if results.get('risk_score', 0) > 70 else Priority.MEDIUM,
                    confidence=results.get('confidence', 70.0),
                    timestamp=datetime.now(),
                    data=results['campaign'],
                    correlation_keys=results['campaign'].get('related_indicators', [])
                )
                packets.append(packet)
        
        elif task.assigned_agent == 'beta_4_devsecops':
            vulns = results.get('results', {}).get('vulnerabilities', [])
            
            for vuln in vulns[:5]:  # Limit to top 5 vulnerabilities
                packet = IntelligencePacket(
                    packet_id=f"{task.task_id}-vuln-{vuln.get('vuln_id', 'unknown')}",
                    source_agent='beta_4_devsecops',
                    target_agents=['alpha_4_threat_intel'],
                    intelligence_type=IntelligenceType.VULNERABILITY,
                    priority=Priority.CRITICAL if vuln.get('severity') == 'CRITICAL' else Priority.HIGH,
                    confidence=vuln.get('confidence', 80.0),
                    timestamp=datetime.now(),
                    data=vuln,
                    correlation_keys=self.extract_correlation_keys_from_vuln(vuln)
                )
                packets.append(packet)
        
        # Process packets through fusion engine
        for packet in packets:
            correlations = await self.fusion_engine.process_intelligence(packet)
            if correlations:
                self.metrics['intelligence_correlations'] += len(correlations)

    def extract_correlation_keys_from_vuln(self, vuln: Dict[str, Any]) -> List[str]:
        """Extract correlation keys from vulnerability data"""
        keys = []
        
        # Add file path as correlation key
        file_path = vuln.get('file_path', '')
        if file_path:
            keys.append(file_path)
        
        # Add any URLs/domains mentioned in context
        context = vuln.get('code_context', '') or vuln.get('description', '')
        if context:
            import re
            domains = re.findall(r'[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}', context)
            keys.extend(domains)
        
        return keys

    async def heartbeat_monitor(self):
        """Monitor agent heartbeats and health"""
        
        interval = self.config['orchestration']['heartbeat_interval']
        
        while self.running:
            try:
                current_time = datetime.now()
                
                for agent_id, agent_info in self.agents.items():
                    # Update heartbeat
                    agent_info.last_heartbeat = current_time
                    
                    # Update uptime
                    if agent_info.status == AgentStatus.ACTIVE:
                        agent_info.uptime = current_time - self.metrics['uptime_start']
                
                # Update metrics
                self.metrics['active_agents'] = len([a for a in self.agents.values() 
                                                   if a.status == AgentStatus.ACTIVE])
                
                await asyncio.sleep(interval)
                
            except Exception as e:
                self.logger.error(f"❌ Heartbeat monitor error: {e}")

    async def cleanup_worker(self):
        """Background cleanup of expired tasks and intelligence"""
        
        interval = self.config['orchestration']['cleanup_interval']
        
        while self.running:
            try:
                current_time = datetime.now()
                
                # Clean up completed tasks older than 1 hour
                completed_cutoff = current_time - timedelta(hours=1)
                expired_tasks = [
                    task_id for task_id, task in self.tasks.items()
                    if (task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED] and
                        task.completed_at and task.completed_at < completed_cutoff)
                ]
                
                for task_id in expired_tasks:
                    del self.tasks[task_id]
                
                if expired_tasks:
                    self.logger.info(f"🧹 Cleaned up {len(expired_tasks)} expired tasks")
                
                # Clean up intelligence fusion engine
                await self.fusion_engine.cleanup_expired_intelligence()
                
                await asyncio.sleep(interval)
                
            except Exception as e:
                self.logger.error(f"❌ Cleanup worker error: {e}")

    async def intelligence_processor(self):
        """Process intelligence correlations and alerts"""
        
        while self.running:
            try:
                # Get fusion metrics
                metrics = await self.fusion_engine.get_fusion_metrics()
                
                # Update our metrics
                self.metrics['intelligence_correlations'] = metrics.get('active_correlations', 0)
                
                # Log periodic intelligence status
                if metrics['packets_processed'] > 0:
                    self.logger.info(f"🧠 Intelligence: {metrics['packets_processed']} packets, "
                                   f"{metrics['correlations_found']} correlations")
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"❌ Intelligence processor error: {e}")

    def estimate_completion_time(self, tasks: List[SecurityTask]) -> datetime:
        """Estimate completion time for a list of tasks"""
        
        # Simple estimation based on task types
        estimated_seconds = 0
        
        for task in tasks:
            if task.task_type == 'comprehensive_security_analysis':
                estimated_seconds += 300  # 5 minutes
            elif task.task_type == 'threat_campaign_analysis':
                estimated_seconds += 120  # 2 minutes
            else:
                estimated_seconds += 60   # 1 minute default
        
        return datetime.now() + timedelta(seconds=estimated_seconds)

    async def get_orchestrator_status(self) -> Dict[str, Any]:
        """Get comprehensive orchestrator status"""
        
        # Calculate uptime
        uptime = datetime.now() - self.metrics['uptime_start']
        
        # Get task statistics
        task_stats = {
            'total': len(self.tasks),
            'pending': len([t for t in self.tasks.values() if t.status == TaskStatus.PENDING]),
            'running': len([t for t in self.tasks.values() if t.status == TaskStatus.RUNNING]),
            'completed': len([t for t in self.tasks.values() if t.status == TaskStatus.COMPLETED]),
            'failed': len([t for t in self.tasks.values() if t.status == TaskStatus.FAILED])
        }
        
        # Get agent statuses
        agent_statuses = {agent_id: asdict(agent_info) for agent_id, agent_info in self.agents.items()}
        
        # Get fusion engine metrics
        fusion_metrics = await self.fusion_engine.get_fusion_metrics()
        
        return {
            'status': 'running' if self.running else 'stopped',
            'uptime_seconds': uptime.total_seconds(),
            'metrics': self.metrics,
            'task_statistics': task_stats,
            'agent_statuses': agent_statuses,
            'fusion_engine': fusion_metrics,
            'queue_size': self.task_queue.qsize()
        }

# CLI and testing interface
async def demo_orchestration():
    """Demonstrate the orchestration system"""
    
    print("🚀 Security Agent Orchestrator Demo")
    
    # Create orchestrator
    orchestrator = SecurityAgentOrchestrator()
    
    # Start orchestration system
    start_task = asyncio.create_task(orchestrator.start())
    
    # Wait a moment for initialization
    await asyncio.sleep(2)
    
    # Create demo analysis request
    demo_request = AnalysisRequest(
        request_id=str(uuid.uuid4()),
        requester='demo_user',
        analysis_type='comprehensive',
        target='/path/to/demo/target',
        priority=Priority.HIGH,
        parameters={
            'include_threat_intel': True,
            'include_architecture_analysis': True,
            'context': 'Demo security analysis for testing orchestration'
        },
        created_at=datetime.now()
    )
    
    try:
        # Submit analysis request
        response = await orchestrator.submit_analysis_request(demo_request)
        print(f"📥 Analysis request submitted: {response}")
        
        # Wait for processing
        await asyncio.sleep(10)
        
        # Get status
        status = await orchestrator.get_orchestrator_status()
        print(f"📊 Orchestrator Status:")
        print(f"  • Uptime: {status['uptime_seconds']:.1f} seconds")
        print(f"  • Active Agents: {status['metrics']['active_agents']}")
        print(f"  • Tasks Completed: {status['task_statistics']['completed']}")
        print(f"  • Intelligence Correlations: {status['metrics']['intelligence_correlations']}")
        
        # Shutdown
        orchestrator.shutdown_event.set()
        await start_task
        
    except KeyboardInterrupt:
        orchestrator.shutdown_event.set()
        await start_task

if __name__ == "__main__":
    asyncio.run(demo_orchestration())