#!/usr/bin/env python3
"""
Security Agent Orchestrator v2 — Registry-based, all-agent orchestration.

Replaces the hardcoded Alpha-4/Beta-4-only orchestrator with dynamic
agent discovery, registration, and polymorphic task dispatch.
All five agents (Alpha-4, Beta-4, Gamma, Delta, Sigma) are first-class.
"""

import asyncio
import json
import logging
import re
import signal
import uuid
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional

from security_agents.core.models import (
    AgentStatus, AgentInfo, SecurityTask, TaskStatus,
    IntelligencePacket, IntelligenceType, Priority, AnalysisRequest,
)

# Backward-compatible re-export for existing code
from security_agents.core.models import SecurityTask, TaskStatus, Priority

from security_agents.core.intelligence_fusion_engine import IntelligenceFusionEngine
from security_agents.core.base_agent import BaseSecurityAgent
from security_agents.core.agent_registry import AgentRegistry

# Import all agents so they self-register via @register_agent
import security_agents.agents  # noqa: F401  — triggers registration

logger = logging.getLogger(__name__)


# AnalysisRequest kept for backward compat (also defined in models.py)
# If not already there, define it here:
try:
    from security_agents.core.models import AnalysisRequest
except ImportError:
    from dataclasses import dataclass, field

    @dataclass
    class AnalysisRequest:
        request_id: str
        requester: str
        analysis_type: str
        target: str
        priority: Priority
        parameters: Dict[str, Any]
        created_at: datetime
        estimated_duration: Optional[int] = None


class SecurityAgentOrchestrator:
    """
    Production-ready orchestration system for all security agents.

    Key improvements over v1:
    - All 5 agents are registered and routable (not just Alpha-4 & Beta-4)
    - Task dispatch is polymorphic via BaseSecurityAgent.execute()
    - Agent skills are composable and shared
    - Intelligence fusion wired to all agents
    """

    def __init__(self, config_file: Optional[str] = None):
        self.config = self._load_configuration(config_file)

        # Core subsystems
        self.fusion_engine = IntelligenceFusionEngine()
        self._agents: Dict[str, BaseSecurityAgent] = {}
        self.tasks: Dict[str, SecurityTask] = {}
        self.task_queue: asyncio.Queue = asyncio.Queue()

        # Runtime state
        self.running = False
        self.shutdown_event = asyncio.Event()

        # Metrics
        self.metrics = {
            "requests_processed": 0,
            "tasks_completed": 0,
            "tasks_failed": 0,
            "avg_response_time": 0.0,
            "active_agents": 0,
            "intelligence_correlations": 0,
            "uptime_start": datetime.now(),
        }

        self._setup_logging()
        self.logger = logging.getLogger("orchestrator")
        self.logger.info("Security Agent Orchestrator v2 initialized")

    # -------------------------------------------------------------------------
    # Configuration
    # -------------------------------------------------------------------------

    def _load_configuration(self, config_file: Optional[str] = None) -> Dict[str, Any]:
        default_config = {
            "agents": {
                "alpha_4_threat_intel": {"enabled": True, "max_concurrent_tasks": 3, "timeout": 300},
                "beta_4_devsecops": {"enabled": True, "max_concurrent_tasks": 5, "timeout": 600},
                "gamma_blue_team": {"enabled": True, "max_concurrent_tasks": 5, "timeout": 300},
                "delta_red_team": {"enabled": True, "max_concurrent_tasks": 2, "timeout": 900},
                "sigma_metrics": {"enabled": True, "max_concurrent_tasks": 3, "timeout": 120},
                "zeta_grc": {"enabled": True, "max_concurrent_tasks": 3, "timeout": 300},
            },
            "fusion_engine": {"enabled": True, "intelligence_retention_hours": 24},
            "orchestration": {
                "max_queue_size": 100,
                "heartbeat_interval": 30,
                "cleanup_interval": 300,
                "task_timeout": 900,
            },
            "api": {"host": "0.0.0.0", "port": 8080, "cors_enabled": True},
            "logging": {"level": "INFO", "file": "orchestrator.log"},
        }

        if config_file and Path(config_file).exists():
            try:
                with open(config_file, "r") as f:
                    custom = json.load(f)
                default_config.update(custom)
            except Exception as e:
                logger.warning(f"Failed to load config {config_file}: {e}")

        return default_config

    def _setup_logging(self):
        log_cfg = self.config.get("logging", {})
        logging.basicConfig(
            level=getattr(logging, log_cfg.get("level", "INFO")),
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(log_cfg.get("file", "orchestrator.log")),
            ],
        )

    # -------------------------------------------------------------------------
    # Agent Lifecycle
    # -------------------------------------------------------------------------

    async def initialize_agents(self):
        """Initialize ALL registered agents based on config."""
        self.logger.info("Initializing security agents...")

        agent_configs = self.config.get("agents", {})

        # Create agents from registry
        self._agents = AgentRegistry.create_all(agent_configs, only_enabled=True)

        # Initialize each agent and wire into fusion engine
        for agent_id, agent in list(self._agents.items()):
            success = await agent.initialize()
            if not success:
                self.logger.error(f"Agent {agent_id} failed to initialize — removing")
                del self._agents[agent_id]
                continue

            # Subscribe to fusion engine
            self.fusion_engine.subscribe_agent(
                agent_id, list(agent.SUBSCRIPTIONS)
            )

            # Register skills
            await self._register_agent_skills(agent)

            self.logger.info(
                f"Agent {agent.DISPLAY_NAME} active — "
                f"capabilities={agent.CAPABILITIES}"
            )

        self.metrics["active_agents"] = len(self._agents)
        self.logger.info(f"{self.metrics['active_agents']} agents active and ready")

    async def _register_agent_skills(self, agent: BaseSecurityAgent):
        """Register all compatible skills with an agent."""
        # Skill registry: (module, class_name, skill_name)
        skill_definitions = [
            ("security_agents.skills.phishing_analysis", "PhishingAnalysisSkill", "phishing_analysis"),
            ("security_agents.skills.threat_hunting", "ThreatHuntingSkill", "threat_hunting"),
            ("security_agents.skills.incident_response", "IncidentResponseSkill", "incident_response"),
            ("security_agents.skills.vulnerability_management", "VulnerabilityManagementSkill", "vulnerability_management"),
            ("security_agents.skills.cloud_security_posture", "CloudSecurityPostureSkill", "cloud_security_posture"),
            ("security_agents.skills.identity_threat_detection", "IdentityThreatDetectionSkill", "identity_threat_detection"),
            ("security_agents.skills.supply_chain_security", "SupplyChainSecuritySkill", "supply_chain_security"),
            ("security_agents.skills.soar_integration", "SOARIntegrationSkill", "soar_integration"),
            ("security_agents.skills.forensics_collection", "ForensicsCollectionSkill", "forensics_collection"),
            ("security_agents.skills.compliance_audit", "ComplianceAuditSkill", "compliance_audit"),
            ("security_agents.skills.ai_confidence_scoring", "AIConfidenceScoringSkill", "ai_confidence_scoring"),
            ("security_agents.skills.ioc_enrichment", "IOCEnrichmentSkill", "ioc_enrichment"),
            ("security_agents.skills.slack_war_room", "SlackWarRoomSkill", "slack_war_room"),
            ("security_agents.skills.enterprise_topology", "EnterpriseTopologySkill", "enterprise_topology"),
            ("security_agents.skills.aws_infrastructure", "AWSInfrastructureSkill", "aws_infrastructure"),
            ("security_agents.skills.secrets_scanning", "SecretsScanningSkill", "secrets_scanning"),
            ("security_agents.skills.siem_rule_management", "SIEMRuleManagementSkill", "siem_rule_management"),
            ("security_agents.skills.threat_modeling", "ThreatModelingSkill", "threat_modeling"),
            ("security_agents.skills.attack_surface_management", "AttackSurfaceManagementSkill", "attack_surface_management"),
            ("security_agents.skills.vendor_risk", "VendorRiskSkill", "vendor_risk"),
            ("security_agents.skills.insider_threat", "InsiderThreatSkill", "insider_threat"),
            ("security_agents.skills.deception_technology", "DeceptionTechnologySkill", "deception_technology"),
            ("security_agents.skills.pentest_management", "PentestManagementSkill", "pentest_management"),
            ("security_agents.skills.compliance_check", "ComplianceCheckSkill", "compliance_check"),
            ("security_agents.skills.control_mapping", "ControlMappingSkill", "control_mapping"),
            ("security_agents.skills.evidence_collection", "EvidenceCollectionSkill", "evidence_collection"),
            ("security_agents.skills.risk_scoring", "RiskScoringSkill", "risk_scoring"),
        ]

        for module_path, class_name, skill_name in skill_definitions:
            try:
                import importlib
                mod = importlib.import_module(module_path)
                skill_class = getattr(mod, class_name)

                # Only register if this agent is compatible
                compatible = skill_class.COMPATIBLE_AGENTS
                if compatible and agent.AGENT_ID not in compatible:
                    continue

                skill_instance = skill_class(agent_id=agent.AGENT_ID, config=agent.config)
                await skill_instance.initialize()
                agent.register_skill(skill_name, skill_instance)
            except Exception as e:
                self.logger.warning(f"Failed to register {skill_name} for {agent.AGENT_ID}: {e}")

    # -------------------------------------------------------------------------
    # Start / Stop
    # -------------------------------------------------------------------------

    async def start(self):
        """Start the orchestration system."""
        self.logger.info("Starting Security Agent Orchestrator v2...")

        await self.initialize_agents()
        self.running = True
        self.metrics["uptime_start"] = datetime.now()

        background_tasks = [
            asyncio.create_task(self._task_processor()),
            asyncio.create_task(self._heartbeat_monitor()),
            asyncio.create_task(self._cleanup_worker()),
            asyncio.create_task(self._intelligence_processor()),
        ]

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        self.logger.info("Orchestrator running — all systems operational")

        try:
            await self.shutdown_event.wait()
        except Exception as e:
            self.logger.error(f"Orchestrator error: {e}")
        finally:
            for t in background_tasks:
                t.cancel()
            await self.shutdown()

    def _signal_handler(self, signum, frame):
        self.logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        self.shutdown_event.set()

    async def shutdown(self):
        """Graceful shutdown."""
        self.logger.info("Shutting down orchestrator...")
        self.running = False

        # Shut down agents
        for agent in self._agents.values():
            await agent.shutdown()

        # Cancel pending tasks
        for task in self.tasks.values():
            if task.status in (TaskStatus.PENDING, TaskStatus.RUNNING):
                task.status = TaskStatus.CANCELLED
                task.completed_at = datetime.now()
                task.error_message = "System shutdown"

        self.logger.info(f"Final metrics: {self.metrics}")
        self.logger.info("Orchestrator shutdown complete")

    # -------------------------------------------------------------------------
    # Task Submission & Decomposition
    # -------------------------------------------------------------------------

    async def submit_analysis_request(self, request: AnalysisRequest) -> Dict[str, Any]:
        """Submit a high-level security analysis request."""
        if not self.running:
            raise RuntimeError("Orchestrator is not running")

        self.logger.info(f"Received analysis request: {request.analysis_type} for {request.target}")

        tasks = await self.decompose_request(request)

        task_ids = []
        for task in tasks:
            await self.task_queue.put(task)
            self.tasks[task.task_id] = task
            task_ids.append(task.task_id)

        self.metrics["requests_processed"] += 1

        return {
            "request_id": request.request_id,
            "status": "accepted",
            "task_count": len(tasks),
            "task_ids": task_ids,
            "estimated_completion": self._estimate_completion(tasks).isoformat(),
        }

    async def decompose_request(self, request: AnalysisRequest) -> List[SecurityTask]:
        """Decompose analysis request into agent-specific tasks."""
        tasks = []
        now = datetime.now()

        if request.analysis_type in ("comprehensive", "vulnerability_focused"):
            if "beta_4_devsecops" in self._agents:
                tasks.append(SecurityTask(
                    task_id=f"{request.request_id}-devsecops",
                    task_type="comprehensive_scan",
                    priority=request.priority,
                    assigned_agent="beta_4_devsecops",
                    status=TaskStatus.PENDING,
                    created_at=now,
                    parameters={
                        "target_path": request.target,
                        "include_architecture": True,
                        "include_supply_chain": True,
                        **request.parameters,
                    },
                ))

        if request.analysis_type in ("comprehensive", "threat_focused"):
            if "alpha_4_threat_intel" in self._agents:
                iocs = self._extract_indicators(request.target)
                tasks.append(SecurityTask(
                    task_id=f"{request.request_id}-threat-intel",
                    task_type="analyze_campaign",
                    priority=request.priority,
                    assigned_agent="alpha_4_threat_intel",
                    status=TaskStatus.PENDING,
                    created_at=now,
                    parameters={
                        "iocs": iocs,
                        "context": request.parameters.get("context", ""),
                        **request.parameters,
                    },
                ))

        if request.analysis_type in ("comprehensive", "incident_response"):
            if "gamma_blue_team" in self._agents:
                tasks.append(SecurityTask(
                    task_id=f"{request.request_id}-blue-team",
                    task_type="process_alert" if request.analysis_type == "incident_response" else "hunt_threats",
                    priority=request.priority,
                    assigned_agent="gamma_blue_team",
                    status=TaskStatus.PENDING,
                    created_at=now,
                    parameters={
                        "alert_data": request.parameters.get("alert_data", {
                            "title": f"Analysis request: {request.target}",
                            "severity": request.priority.value,
                            "source": "orchestrator",
                        }),
                        **request.parameters,
                    },
                ))

        if request.analysis_type in ("comprehensive", "red_team"):
            if "delta_red_team" in self._agents:
                tasks.append(SecurityTask(
                    task_id=f"{request.request_id}-red-team",
                    task_type="attack_path_analysis",
                    priority=request.priority,
                    assigned_agent="delta_red_team",
                    status=TaskStatus.PENDING,
                    created_at=now,
                    parameters={
                        "target_environment": request.target,
                        **request.parameters,
                    },
                ))

        # Sigma always runs for comprehensive — collects cross-agent metrics
        if request.analysis_type == "comprehensive":
            if "sigma_metrics" in self._agents:
                tasks.append(SecurityTask(
                    task_id=f"{request.request_id}-metrics",
                    task_type="collect_metrics",
                    priority=Priority.LOW,
                    assigned_agent="sigma_metrics",
                    status=TaskStatus.PENDING,
                    created_at=now,
                    parameters=request.parameters,
                ))

        # Phishing-specific request
        if request.analysis_type == "phishing":
            if "gamma_blue_team" in self._agents:
                tasks.append(SecurityTask(
                    task_id=f"{request.request_id}-phishing",
                    task_type="analyze_phishing",
                    priority=request.priority,
                    assigned_agent="gamma_blue_team",
                    status=TaskStatus.PENDING,
                    created_at=now,
                    parameters=request.parameters,
                ))

        # GRC / Compliance requests
        if request.analysis_type in ("grc", "compliance"):
            if "zeta_grc" in self._agents:
                tasks.append(SecurityTask(
                    task_id=f"{request.request_id}-grc",
                    task_type="assess_compliance",
                    priority=request.priority,
                    assigned_agent="zeta_grc",
                    status=TaskStatus.PENDING,
                    created_at=now,
                    parameters=request.parameters,
                ))

        # Include GRC in comprehensive analysis
        if request.analysis_type == "comprehensive":
            if "zeta_grc" in self._agents:
                tasks.append(SecurityTask(
                    task_id=f"{request.request_id}-grc",
                    task_type="assess_compliance",
                    priority=Priority.LOW,
                    assigned_agent="zeta_grc",
                    status=TaskStatus.PENDING,
                    created_at=now,
                    parameters=request.parameters,
                ))

        return tasks

    # -------------------------------------------------------------------------
    # Task Execution — polymorphic, no hardcoded routing
    # -------------------------------------------------------------------------

    async def _task_processor(self):
        """Background task processor."""
        self.logger.info("Task processor started")

        while self.running:
            try:
                task = await asyncio.wait_for(self.task_queue.get(), timeout=1.0)
                await self._execute_task(task)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Task processor error: {e}")

    async def _execute_task(self, task: SecurityTask):
        """
        Execute a task by dispatching to the assigned agent.
        No hardcoded if/elif — uses the agent's polymorphic execute().
        """
        self.logger.info(f"Executing task: {task.task_id} ({task.task_type}) -> {task.assigned_agent}")

        agent = self._agents.get(task.assigned_agent)
        if not agent:
            task.status = TaskStatus.FAILED
            task.error_message = f"Agent '{task.assigned_agent}' not available"
            task.completed_at = datetime.now()
            self.metrics["tasks_failed"] += 1
            self.logger.error(task.error_message)
            return

        try:
            # Polymorphic dispatch — agent.execute() handles status bookkeeping
            results = await agent.execute(task)

            self.metrics["tasks_completed"] += 1

            # Process intelligence through fusion engine
            await self._process_task_intelligence(task, results)

            self.logger.info(f"Task completed: {task.task_id}")

        except Exception as e:
            self.metrics["tasks_failed"] += 1
            self.logger.error(f"Task failed: {task.task_id} — {e}")

    async def _process_task_intelligence(self, task: SecurityTask, results: Dict[str, Any]):
        """Route intelligence packets from task results through the fusion engine."""
        packets_data = results.get("intelligence_packets", [])

        for pkt_data in packets_data:
            if isinstance(pkt_data, dict):
                try:
                    packet = IntelligencePacket(
                        packet_id=pkt_data.get("packet_id", f"PKT-{uuid.uuid4().hex[:8]}"),
                        source_agent=pkt_data.get("source_agent", task.assigned_agent),
                        target_agents=pkt_data.get("target_agents", ["all"]),
                        intelligence_type=IntelligenceType(pkt_data["intelligence_type"])
                            if isinstance(pkt_data.get("intelligence_type"), str)
                            else pkt_data.get("intelligence_type", IntelligenceType.CORRELATION),
                        priority=Priority(pkt_data["priority"])
                            if isinstance(pkt_data.get("priority"), str)
                            else pkt_data.get("priority", Priority.MEDIUM),
                        confidence=pkt_data.get("confidence", 70.0),
                        timestamp=datetime.now(),
                        data=pkt_data.get("data", {}),
                        correlation_keys=pkt_data.get("correlation_keys", []),
                    )
                    correlations = await self.fusion_engine.process_intelligence(packet)
                    if correlations:
                        self.metrics["intelligence_correlations"] += len(correlations)
                except Exception as e:
                    self.logger.warning(f"Failed to process intelligence packet: {e}")

    # -------------------------------------------------------------------------
    # Background Workers
    # -------------------------------------------------------------------------

    async def _heartbeat_monitor(self):
        interval = self.config["orchestration"]["heartbeat_interval"]
        while self.running:
            try:
                for agent in self._agents.values():
                    agent.heartbeat()
                self.metrics["active_agents"] = sum(
                    1 for a in self._agents.values() if a.status == AgentStatus.ACTIVE
                )
                await asyncio.sleep(interval)
            except Exception as e:
                self.logger.error(f"Heartbeat monitor error: {e}")

    async def _cleanup_worker(self):
        interval = self.config["orchestration"]["cleanup_interval"]
        while self.running:
            try:
                cutoff = datetime.now() - timedelta(hours=1)
                expired = [
                    tid for tid, t in self.tasks.items()
                    if t.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED)
                    and t.completed_at and t.completed_at < cutoff
                ]
                for tid in expired:
                    del self.tasks[tid]
                if expired:
                    self.logger.info(f"Cleaned up {len(expired)} expired tasks")

                await self.fusion_engine.cleanup_expired_intelligence()
                await asyncio.sleep(interval)
            except Exception as e:
                self.logger.error(f"Cleanup worker error: {e}")

    async def _intelligence_processor(self):
        while self.running:
            try:
                metrics = await self.fusion_engine.get_fusion_metrics()
                self.metrics["intelligence_correlations"] = metrics.get("active_correlations", 0)
                if metrics["packets_processed"] > 0:
                    self.logger.info(
                        f"Intelligence: {metrics['packets_processed']} packets, "
                        f"{metrics['correlations_found']} correlations"
                    )
                await asyncio.sleep(60)
            except Exception as e:
                self.logger.error(f"Intelligence processor error: {e}")

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _extract_indicators(self, scope: str) -> List[str]:
        indicators = []
        indicators.extend(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", scope))
        indicators.extend(re.findall(r"\b[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}\b", scope))
        indicators.extend(re.findall(r"https?://[^\s<>\"{}|\\^`\[\]]+", scope))
        return list(set(indicators))

    def _estimate_completion(self, tasks: List[SecurityTask]) -> datetime:
        estimates = {
            "comprehensive_scan": 300,
            "analyze_campaign": 120,
            "process_alert": 60,
            "attack_path_analysis": 180,
            "collect_metrics": 30,
        }
        total = sum(estimates.get(t.task_type, 60) for t in tasks)
        return datetime.now() + timedelta(seconds=total)

    # -------------------------------------------------------------------------
    # Status & Introspection
    # -------------------------------------------------------------------------

    async def get_status(self) -> Dict[str, Any]:
        """Get comprehensive orchestrator status."""
        uptime = datetime.now() - self.metrics["uptime_start"]

        task_stats = {
            "total": len(self.tasks),
            "pending": sum(1 for t in self.tasks.values() if t.status == TaskStatus.PENDING),
            "running": sum(1 for t in self.tasks.values() if t.status == TaskStatus.RUNNING),
            "completed": sum(1 for t in self.tasks.values() if t.status == TaskStatus.COMPLETED),
            "failed": sum(1 for t in self.tasks.values() if t.status == TaskStatus.FAILED),
        }

        agent_statuses = {}
        for aid, agent in self._agents.items():
            info = agent.get_info()
            agent_statuses[aid] = {
                "display_name": agent.DISPLAY_NAME,
                "status": info.status.value,
                "capabilities": info.capabilities,
                "tasks_completed": info.tasks_completed,
                "tasks_failed": info.tasks_failed,
                "skills": list(agent.skills.keys()),
            }

        fusion_metrics = await self.fusion_engine.get_fusion_metrics()

        return {
            "status": "running" if self.running else "stopped",
            "uptime_seconds": uptime.total_seconds(),
            "metrics": self.metrics,
            "task_statistics": task_stats,
            "agents": agent_statuses,
            "registered_agents": AgentRegistry.list_agents(),
            "fusion_engine": fusion_metrics,
            "queue_size": self.task_queue.qsize(),
        }

    def get_agent(self, agent_id: str) -> Optional[BaseSecurityAgent]:
        """Get a running agent instance by ID."""
        return self._agents.get(agent_id)

    def list_agents(self) -> List[str]:
        """List active agent IDs."""
        return list(self._agents.keys())


# -------------------------------------------------------------------------
# CLI demo
# -------------------------------------------------------------------------

async def demo_orchestration():
    """Demonstrate the v2 orchestration system with all 5 agents."""
    print("=" * 60)
    print("Security Agent Orchestrator v2 — Demo")
    print("=" * 60)

    orchestrator = SecurityAgentOrchestrator()
    start_task = asyncio.create_task(orchestrator.start())

    await asyncio.sleep(2)

    # Submit a comprehensive analysis
    request = AnalysisRequest(
        request_id=str(uuid.uuid4()),
        requester="demo_user",
        analysis_type="comprehensive",
        target="/path/to/demo/target",
        priority=Priority.HIGH,
        parameters={
            "context": "Demo analysis — exercising all 5 agents",
            "alert_data": {
                "title": "Demo alert",
                "severity": "high",
                "source": "demo",
            },
        },
        created_at=datetime.now(),
    )

    try:
        response = await orchestrator.submit_analysis_request(request)
        print(f"\nAnalysis request submitted: {json.dumps(response, indent=2, default=str)}")

        await asyncio.sleep(5)

        status = await orchestrator.get_status()
        print(f"\nOrchestrator Status:")
        print(f"  Active agents: {status['metrics']['active_agents']}")
        for aid, info in status["agents"].items():
            print(f"    {info['display_name']}: {info['status']} "
                  f"(completed={info['tasks_completed']}, skills={info['skills']})")
        print(f"  Tasks completed: {status['task_statistics']['completed']}")
        print(f"  Correlations: {status['metrics']['intelligence_correlations']}")

        # Demo: phishing analysis
        phishing_request = AnalysisRequest(
            request_id=str(uuid.uuid4()),
            requester="demo_user",
            analysis_type="phishing",
            target="phishing_email",
            priority=Priority.HIGH,
            parameters={
                "action": "analyze_email",
                "subject": "Urgent: Verify your account immediately",
                "sender": "support@secure-login.xyz",
                "body": "Dear Customer, your account has been suspended. Click here to verify.",
                "urls": ["https://secure-login.xyz/verify?user=target"],
                "headers": {"Authentication-Results": "spf=fail; dkim=fail; dmarc=fail"},
                "attachments": [],
                "recipients": ["victim@company.com"],
            },
            created_at=datetime.now(),
        )

        phishing_response = await orchestrator.submit_analysis_request(phishing_request)
        print(f"\nPhishing analysis submitted: {json.dumps(phishing_response, indent=2, default=str)}")

        await asyncio.sleep(3)

        orchestrator.shutdown_event.set()
        await start_task

    except KeyboardInterrupt:
        orchestrator.shutdown_event.set()
        await start_task


if __name__ == "__main__":
    asyncio.run(demo_orchestration())
