#!/usr/bin/env python3
"""
Delta Agent: Red Team Offense Operations
Penetration testing, adversary simulation, and attack automation using MITRE ATT&CK framework
"""

import asyncio
import logging
import json
import yaml
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import aiohttp
from enum import Enum
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AttackPhase(Enum):
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"

class OperationStatus(Enum):
    PLANNING = "planning"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    TERMINATED = "terminated"

@dataclass
class AttackTechnique:
    """MITRE ATT&CK technique definition"""
    technique_id: str
    name: str
    phase: AttackPhase
    description: str
    platforms: List[str]
    prerequisites: List[str] = None
    detection_methods: List[str] = None
    
@dataclass
class RedTeamOperation:
    """Red team operation configuration"""
    operation_id: str
    name: str
    target_environment: str
    adversary_profile: str
    start_time: datetime
    duration_hours: int
    status: OperationStatus
    techniques: List[AttackTechnique] = None
    safety_controls: List[str] = None
    objectives: List[str] = None
    results: Dict[str, Any] = None

@dataclass
class AttackPath:
    """Attack path analysis result"""
    path_id: str
    source_node: str
    target_node: str
    steps: List[Dict[str, str]]
    risk_score: float
    estimated_time: int  # minutes
    difficulty: str  # easy, medium, hard

class DeltaRedTeamAgent:
    """Red Team Offense Operations Agent"""
    
    def __init__(self, config_path: str = "config/delta_config.yaml"):
        self.config = self.load_config(config_path)
        self.github_tools = {}
        self.active_operations = {}
        self.attack_techniques_db = {}
        self.adversary_profiles = {}
        
        # Initialize GitHub tool integrations
        self.initialize_github_tools()
        
        # Load MITRE ATT&CK techniques
        self.load_attack_techniques()
        
        # Load adversary profiles
        self.load_adversary_profiles()
    
    def load_config(self, config_path: str) -> Dict[str, Any]:
        """Load agent configuration"""
        default_config = {
            "max_concurrent_operations": 3,
            "safety_controls": {
                "production_protection": True,
                "data_exfiltration_simulation_only": True,
                "automated_cleanup": True,
                "time_boxed_operations": True,
                "approval_required_techniques": [
                    "T1485",  # Data Destruction
                    "T1486",  # Data Encrypted for Impact
                    "T1490"   # Inhibit System Recovery
                ]
            },
            "integrations": {
                "caldera": {
                    "enabled": True,
                    "api_url": "http://localhost:8888/api/v2",
                    "username": "admin",
                    "password": "admin"
                },
                "atomic_red_team": {
                    "enabled": True,
                    "local_path": "/opt/atomic-red-team",
                    "execution_framework": "powershell"
                },
                "bloodhound": {
                    "enabled": True,
                    "neo4j_url": "bolt://localhost:7687",
                    "neo4j_user": "neo4j",
                    "neo4j_password": "password"
                },
                "empire": {
                    "enabled": True,
                    "api_url": "http://localhost:1337",
                    "local_path": "/opt/empire"
                }
            },
            "adversary_emulation": {
                "default_duration_hours": 4,
                "stealth_mode": True,
                "cleanup_delay_minutes": 30
            }
        }
        
        try:
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)
        except FileNotFoundError:
            logger.warning(f"Config file {config_path} not found, using defaults")
        
        return default_config
    
    def initialize_github_tools(self):
        """Initialize GitHub security tool integrations"""
        from github_integrations.github_security_tools import GitHubToolIntegration, GitHubSecurityToolManager
        
        self.tool_manager = GitHubSecurityToolManager()
        
        # Initialize tool integrations
        red_team_tools = ["mitre_caldera", "atomic_red_team", "bloodhound", "empire"]
        for tool_name in red_team_tools:
            if self.config["integrations"].get(tool_name.replace("mitre_", ""), {}).get("enabled", False):
                self.github_tools[tool_name] = GitHubToolIntegration(tool_name, self.tool_manager)
    
    def load_attack_techniques(self):
        """Load MITRE ATT&CK techniques database"""
        # Simplified technique database (in production, load from MITRE CTI STIX data)
        techniques = [
            {
                "technique_id": "T1059.001",
                "name": "PowerShell",
                "phase": AttackPhase.EXECUTION,
                "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
                "platforms": ["Windows"],
                "prerequisites": ["PowerShell access"],
                "detection_methods": ["Process monitoring", "PowerShell logging"]
            },
            {
                "technique_id": "T1021.001", 
                "name": "Remote Desktop Protocol",
                "phase": AttackPhase.LATERAL_MOVEMENT,
                "description": "Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP).",
                "platforms": ["Windows"],
                "prerequisites": ["Valid credentials", "RDP enabled"],
                "detection_methods": ["Network monitoring", "Authentication logs"]
            },
            {
                "technique_id": "T1003.001",
                "name": "LSASS Memory",
                "phase": AttackPhase.CREDENTIAL_ACCESS,
                "description": "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).",
                "platforms": ["Windows"],
                "prerequisites": ["Administrator privileges"],
                "detection_methods": ["Process monitoring", "Memory analysis"]
            },
            {
                "technique_id": "T1055",
                "name": "Process Injection",
                "phase": AttackPhase.PRIVILEGE_ESCALATION,
                "description": "Adversaries may inject code into processes in order to evade process-based defenses.",
                "platforms": ["Windows", "Linux", "macOS"],
                "prerequisites": ["Process access"],
                "detection_methods": ["Process monitoring", "DLL monitoring"]
            },
            {
                "technique_id": "T1547.001",
                "name": "Registry Run Keys / Startup Folder",
                "phase": AttackPhase.PERSISTENCE,
                "description": "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.",
                "platforms": ["Windows"],
                "prerequisites": ["User or admin access"],
                "detection_methods": ["File monitoring", "Registry monitoring"]
            }
        ]
        
        for tech_data in techniques:
            technique = AttackTechnique(**tech_data)
            self.attack_techniques_db[technique.technique_id] = technique
    
    def load_adversary_profiles(self):
        """Load adversary emulation profiles"""
        self.adversary_profiles = {
            "APT-28": {
                "name": "Fancy Bear / APT 28",
                "description": "Russian military intelligence-linked group",
                "preferred_techniques": ["T1059.001", "T1021.001", "T1003.001"],
                "target_sectors": ["Government", "Military", "Defense"],
                "ttp_characteristics": {
                    "initial_access": ["Spear phishing", "Strategic web compromise"],
                    "persistence": ["Registry modifications", "Scheduled tasks"],
                    "lateral_movement": ["RDP", "PsExec"],
                    "command_control": ["HTTP/HTTPS", "DNS tunneling"]
                }
            },
            "APT-29": {
                "name": "Cozy Bear / APT 29",
                "description": "Russian foreign intelligence service-linked group",
                "preferred_techniques": ["T1055", "T1547.001", "T1059.001"],
                "target_sectors": ["Government", "Healthcare", "Technology"],
                "ttp_characteristics": {
                    "initial_access": ["Supply chain compromise", "Trusted relationships"],
                    "persistence": ["Cloud account compromise", "Valid accounts"],
                    "lateral_movement": ["Internal spear phishing", "Remote services"],
                    "command_control": ["Cloud services", "Web protocols"]
                }
            },
            "Lazarus": {
                "name": "Lazarus Group",
                "description": "North Korean state-sponsored group",
                "preferred_techniques": ["T1059.001", "T1055", "T1003.001"],
                "target_sectors": ["Financial", "Cryptocurrency", "Entertainment"],
                "ttp_characteristics": {
                    "initial_access": ["Spear phishing", "Supply chain"],
                    "persistence": ["Backdoors", "Registry modifications"],
                    "lateral_movement": ["SMB/Windows Admin Shares", "Remote Desktop Protocol"],
                    "command_control": ["Custom protocols", "HTTP/HTTPS"]
                }
            }
        }
    
    async def start_adversary_emulation(self, operation_config: Dict[str, Any]) -> Dict[str, Any]:
        """Start adversary emulation campaign"""
        try:
            # Create operation
            operation = self.create_operation(operation_config)
            
            logger.info(f"Starting adversary emulation: {operation.operation_id}")
            
            # Safety checks
            safety_check = await self.perform_safety_checks(operation)
            if not safety_check["approved"]:
                return {
                    "status": "rejected",
                    "reason": safety_check["reason"],
                    "operation_id": operation.operation_id
                }
            
            # Generate attack plan
            attack_plan = await self.generate_attack_plan(operation)
            
            # Initialize CALDERA operation if available
            caldera_operation = None
            if "mitre_caldera" in self.github_tools:
                caldera_operation = await self.create_caldera_operation(operation, attack_plan)
            
            # Analyze attack paths with BloodHound if available
            attack_paths = []
            if "bloodhound" in self.github_tools:
                attack_paths = await self.analyze_attack_paths(operation.target_environment)
            
            # Start operation execution
            operation.status = OperationStatus.RUNNING
            self.active_operations[operation.operation_id] = operation
            
            # Execute operation
            execution_task = asyncio.create_task(self.execute_operation(operation, attack_plan))
            
            return {
                "status": "started",
                "operation_id": operation.operation_id,
                "caldera_operation_id": caldera_operation.get("id") if caldera_operation else None,
                "attack_paths": len(attack_paths),
                "planned_techniques": len(attack_plan["techniques"]),
                "estimated_duration": operation.duration_hours,
                "safety_controls": operation.safety_controls
            }
            
        except Exception as e:
            logger.error(f"Error starting adversary emulation: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    def create_operation(self, config: Dict[str, Any]) -> RedTeamOperation:
        """Create red team operation from configuration"""
        operation_id = f"OP-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
        
        return RedTeamOperation(
            operation_id=operation_id,
            name=config.get("name", f"Red Team Operation {operation_id}"),
            target_environment=config["target_environment"],
            adversary_profile=config.get("adversary_profile", "APT-28"),
            start_time=datetime.now(),
            duration_hours=config.get("duration_hours", self.config["adversary_emulation"]["default_duration_hours"]),
            status=OperationStatus.PLANNING,
            objectives=config.get("objectives", [
                "Establish persistence",
                "Escalate privileges", 
                "Move laterally",
                "Access sensitive data (simulation)"
            ]),
            safety_controls=self.get_default_safety_controls()
        )
    
    def get_default_safety_controls(self) -> List[str]:
        """Get default safety controls for operations"""
        return [
            "Production environment protection enabled",
            "Data exfiltration simulation only",
            "Automated cleanup after operation",
            "Time-boxed execution",
            "Real-time monitoring",
            "Emergency stop capability"
        ]
    
    async def perform_safety_checks(self, operation: RedTeamOperation) -> Dict[str, Any]:
        """Perform safety checks before operation execution"""
        checks = []
        
        # Check target environment
        if await self.is_production_environment(operation.target_environment):
            if self.config["safety_controls"]["production_protection"]:
                return {
                    "approved": False,
                    "reason": "Production environment protection is enabled"
                }
            else:
                checks.append("WARNING: Production environment targeted")
        
        # Check for high-risk techniques
        high_risk_techniques = await self.identify_high_risk_techniques(operation)
        if high_risk_techniques:
            approval_required = any(
                tech in self.config["safety_controls"]["approval_required_techniques"]
                for tech in high_risk_techniques
            )
            if approval_required:
                return {
                    "approved": False,
                    "reason": f"Manual approval required for techniques: {high_risk_techniques}"
                }
        
        # Check duration limits
        max_duration = 24  # hours
        if operation.duration_hours > max_duration:
            return {
                "approved": False,
                "reason": f"Operation duration exceeds maximum ({max_duration} hours)"
            }
        
        return {
            "approved": True,
            "checks": checks,
            "timestamp": datetime.now().isoformat()
        }
    
    async def generate_attack_plan(self, operation: RedTeamOperation) -> Dict[str, Any]:
        """Generate attack plan based on adversary profile and objectives"""
        adversary = self.adversary_profiles.get(operation.adversary_profile, {})
        
        # Select techniques based on adversary profile
        selected_techniques = []
        preferred_techniques = adversary.get("preferred_techniques", [])
        
        for technique_id in preferred_techniques:
            if technique_id in self.attack_techniques_db:
                selected_techniques.append(self.attack_techniques_db[technique_id])
        
        # Organize techniques by attack phase
        phases = {}
        for technique in selected_techniques:
            phase = technique.phase
            if phase not in phases:
                phases[phase] = []
            phases[phase].append(technique)
        
        # Create execution timeline
        timeline = await self.create_execution_timeline(phases, operation.duration_hours)
        
        return {
            "adversary_profile": adversary,
            "techniques": selected_techniques,
            "phases": phases,
            "timeline": timeline,
            "safety_considerations": await self.generate_safety_considerations(selected_techniques)
        }
    
    async def create_caldera_operation(self, operation: RedTeamOperation, attack_plan: Dict[str, Any]) -> Dict[str, Any]:
        """Create CALDERA operation"""
        try:
            async with self.github_tools["mitre_caldera"] as caldera:
                operation_data = {
                    "name": operation.name,
                    "adversary": {"name": operation.adversary_profile},
                    "group": operation.target_environment,
                    "auto_close": self.config["adversary_emulation"]["stealth_mode"],
                    "state": "paused",  # Start paused for safety
                    "autonomous": 1  # Semi-autonomous execution
                }
                
                result = await caldera.execute_capability("adversary_emulation", operation_data)
                
                if result.get("status") == "operation_created":
                    logger.info(f"CALDERA operation created: {result['operation']['id']}")
                    return result["operation"]
                else:
                    logger.error(f"Failed to create CALDERA operation: {result}")
                    return {}
                    
        except Exception as e:
            logger.error(f"Error creating CALDERA operation: {e}")
            return {}
    
    async def analyze_attack_paths(self, target_environment: str) -> List[AttackPath]:
        """Analyze attack paths using BloodHound"""
        try:
            if "bloodhound" not in self.github_tools:
                return []
            
            async with self.github_tools["bloodhound"] as bloodhound:
                # Query for attack paths
                path_analysis = await bloodhound.execute_capability(
                    "ad_analysis",
                    {"target_domain": target_environment}
                )
                
                # Convert to AttackPath objects
                attack_paths = []
                if path_analysis.get("status") == "analysis_initiated":
                    # Placeholder for actual BloodHound data processing
                    sample_paths = [
                        {
                            "path_id": "PATH-001",
                            "source_node": "User@DOMAIN.LOCAL",
                            "target_node": "Domain Admins@DOMAIN.LOCAL",
                            "steps": [
                                {"action": "Kerberoast", "target": "Service Account"},
                                {"action": "Credential Access", "target": "Hash"},
                                {"action": "DCSync", "target": "Domain Controller"}
                            ],
                            "risk_score": 0.8,
                            "estimated_time": 120,
                            "difficulty": "medium"
                        }
                    ]
                    
                    for path_data in sample_paths:
                        attack_path = AttackPath(**path_data)
                        attack_paths.append(attack_path)
                
                return attack_paths
                
        except Exception as e:
            logger.error(f"Error analyzing attack paths: {e}")
            return []
    
    async def execute_operation(self, operation: RedTeamOperation, attack_plan: Dict[str, Any]):
        """Execute red team operation"""
        logger.info(f"Executing operation: {operation.operation_id}")
        
        try:
            results = {
                "start_time": datetime.now().isoformat(),
                "executed_techniques": [],
                "successful_techniques": [],
                "failed_techniques": [],
                "compromised_systems": [],
                "evidence_collected": [],
                "detection_evasion": []
            }
            
            # Execute techniques according to timeline
            for phase_name, techniques in attack_plan["phases"].items():
                logger.info(f"Executing phase: {phase_name.value}")
                
                for technique in techniques:
                    if operation.status != OperationStatus.RUNNING:
                        break
                    
                    technique_result = await self.execute_technique(technique, operation)
                    results["executed_techniques"].append({
                        "technique_id": technique.technique_id,
                        "name": technique.name,
                        "result": technique_result
                    })
                    
                    if technique_result.get("success", False):
                        results["successful_techniques"].append(technique.technique_id)
                    else:
                        results["failed_techniques"].append(technique.technique_id)
                    
                    # Add delay between techniques for stealth
                    if self.config["adversary_emulation"]["stealth_mode"]:
                        await asyncio.sleep(30)  # 30 second delay
            
            # Operation completed
            operation.status = OperationStatus.COMPLETED
            operation.results = results
            
            # Schedule cleanup
            cleanup_delay = self.config["adversary_emulation"]["cleanup_delay_minutes"] * 60
            asyncio.create_task(self.schedule_cleanup(operation, cleanup_delay))
            
            logger.info(f"Operation completed: {operation.operation_id}")
            
        except Exception as e:
            logger.error(f"Error executing operation: {e}")
            operation.status = OperationStatus.FAILED
            operation.results = {"error": str(e)}
    
    async def execute_technique(self, technique: AttackTechnique, operation: RedTeamOperation) -> Dict[str, Any]:
        """Execute individual attack technique"""
        logger.info(f"Executing technique: {technique.technique_id} - {technique.name}")
        
        try:
            # Check if Atomic Red Team test is available
            if "atomic_red_team" in self.github_tools:
                atomic_result = await self.execute_atomic_test(technique)
                if atomic_result:
                    return atomic_result
            
            # Fallback to manual simulation
            return await self.simulate_technique(technique, operation)
            
        except Exception as e:
            logger.error(f"Error executing technique {technique.technique_id}: {e}")
            return {
                "success": False,
                "error": str(e),
                "technique_id": technique.technique_id
            }
    
    async def execute_atomic_test(self, technique: AttackTechnique) -> Dict[str, Any]:
        """Execute Atomic Red Team test for technique"""
        try:
            async with self.github_tools["atomic_red_team"] as atomic:
                result = await atomic.execute_capability(
                    "detection_testing",
                    {"technique": technique.technique_id}
                )
                
                if result.get("status") == "test_executed":
                    return {
                        "success": True,
                        "method": "atomic_red_team",
                        "technique_id": technique.technique_id,
                        "command": result.get("command"),
                        "timestamp": datetime.now().isoformat()
                    }
                else:
                    return None
                    
        except Exception as e:
            logger.error(f"Error executing atomic test for {technique.technique_id}: {e}")
            return None
    
    async def simulate_technique(self, technique: AttackTechnique, operation: RedTeamOperation) -> Dict[str, Any]:
        """Simulate technique execution (safe simulation mode)"""
        # Simulate execution based on technique type
        simulation_result = {
            "success": True,
            "method": "simulation",
            "technique_id": technique.technique_id,
            "simulated_actions": [],
            "timestamp": datetime.now().isoformat()
        }
        
        # Technique-specific simulation
        if technique.phase == AttackPhase.RECONNAISSANCE:
            simulation_result["simulated_actions"] = [
                "Network scanning simulation",
                "Service enumeration simulation",
                "Target identification simulation"
            ]
        
        elif technique.phase == AttackPhase.INITIAL_ACCESS:
            simulation_result["simulated_actions"] = [
                "Spear phishing simulation",
                "Exploit delivery simulation",
                "Foothold establishment simulation"
            ]
        
        elif technique.phase == AttackPhase.CREDENTIAL_ACCESS:
            simulation_result["simulated_actions"] = [
                "Credential dumping simulation",
                "Password spraying simulation",
                "Hash cracking simulation"
            ]
        
        # Add small delay to simulate execution time
        await asyncio.sleep(5)
        
        return simulation_result
    
    async def schedule_cleanup(self, operation: RedTeamOperation, delay_seconds: int):
        """Schedule automated cleanup of operation artifacts"""
        await asyncio.sleep(delay_seconds)
        
        logger.info(f"Starting cleanup for operation: {operation.operation_id}")
        
        try:
            cleanup_results = {
                "files_removed": [],
                "registry_keys_cleaned": [],
                "processes_terminated": [],
                "network_connections_closed": []
            }
            
            # Simulate cleanup activities
            if operation.results:
                for technique_result in operation.results.get("executed_techniques", []):
                    technique_id = technique_result["technique_id"]
                    await self.cleanup_technique_artifacts(technique_id, cleanup_results)
            
            logger.info(f"Cleanup completed for operation: {operation.operation_id}")
            operation.results["cleanup"] = cleanup_results
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
    
    async def cleanup_technique_artifacts(self, technique_id: str, cleanup_results: Dict[str, Any]):
        """Clean up artifacts from specific technique"""
        # Technique-specific cleanup simulation
        technique = self.attack_techniques_db.get(technique_id)
        if not technique:
            return
        
        if technique.phase == AttackPhase.PERSISTENCE:
            cleanup_results["registry_keys_cleaned"].extend([
                f"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{technique_id}",
                f"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\{technique_id}"
            ])
        
        elif technique.phase == AttackPhase.EXECUTION:
            cleanup_results["files_removed"].extend([
                f"/tmp/payload_{technique_id}.ps1",
                f"C:\\Windows\\Temp\\script_{technique_id}.bat"
            ])
        
        elif technique.phase == AttackPhase.COMMAND_AND_CONTROL:
            cleanup_results["network_connections_closed"].extend([
                f"TCP connection to C2 server (technique: {technique_id})"
            ])
    
    async def terminate_operation(self, operation_id: str) -> Dict[str, Any]:
        """Terminate running operation"""
        if operation_id not in self.active_operations:
            return {"status": "not_found"}
        
        operation = self.active_operations[operation_id]
        operation.status = OperationStatus.TERMINATED
        
        # Trigger immediate cleanup
        await self.schedule_cleanup(operation, 0)
        
        logger.info(f"Operation terminated: {operation_id}")
        
        return {
            "status": "terminated",
            "operation_id": operation_id,
            "termination_time": datetime.now().isoformat()
        }
    
    async def get_operation_status(self, operation_id: str) -> Dict[str, Any]:
        """Get current operation status"""
        if operation_id not in self.active_operations:
            return {"status": "not_found"}
        
        operation = self.active_operations[operation_id]
        
        return {
            "operation_id": operation.operation_id,
            "name": operation.name,
            "status": operation.status.value,
            "target_environment": operation.target_environment,
            "adversary_profile": operation.adversary_profile,
            "start_time": operation.start_time.isoformat(),
            "duration_hours": operation.duration_hours,
            "objectives": operation.objectives,
            "results": operation.results
        }
    
    def list_active_operations(self) -> List[Dict[str, Any]]:
        """List all active operations"""
        return [
            {
                "operation_id": op.operation_id,
                "name": op.name,
                "status": op.status.value,
                "start_time": op.start_time.isoformat(),
                "target_environment": op.target_environment
            }
            for op in self.active_operations.values()
        ]
    
    # Helper methods
    async def is_production_environment(self, target: str) -> bool:
        """Check if target is production environment"""
        prod_indicators = ["prod", "production", "live", "prd"]
        return any(indicator in target.lower() for indicator in prod_indicators)
    
    async def identify_high_risk_techniques(self, operation: RedTeamOperation) -> List[str]:
        """Identify high-risk techniques in operation"""
        high_risk = []
        adversary = self.adversary_profiles.get(operation.adversary_profile, {})
        
        for technique_id in adversary.get("preferred_techniques", []):
            technique = self.attack_techniques_db.get(technique_id)
            if technique and technique.phase in [AttackPhase.IMPACT, AttackPhase.EXFILTRATION]:
                high_risk.append(technique_id)
        
        return high_risk
    
    async def create_execution_timeline(self, phases: Dict[AttackPhase, List[AttackTechnique]], duration_hours: int) -> List[Dict[str, Any]]:
        """Create execution timeline for techniques"""
        timeline = []
        
        # Standard phase ordering
        phase_order = [
            AttackPhase.RECONNAISSANCE,
            AttackPhase.INITIAL_ACCESS,
            AttackPhase.EXECUTION,
            AttackPhase.PERSISTENCE,
            AttackPhase.PRIVILEGE_ESCALATION,
            AttackPhase.DEFENSE_EVASION,
            AttackPhase.CREDENTIAL_ACCESS,
            AttackPhase.DISCOVERY,
            AttackPhase.LATERAL_MOVEMENT,
            AttackPhase.COLLECTION,
            AttackPhase.COMMAND_AND_CONTROL,
            AttackPhase.EXFILTRATION
        ]
        
        current_time = 0
        phase_duration = duration_hours * 60 // len(phase_order)  # minutes per phase
        
        for phase in phase_order:
            if phase in phases:
                techniques_in_phase = phases[phase]
                technique_duration = phase_duration // len(techniques_in_phase)
                
                for technique in techniques_in_phase:
                    timeline.append({
                        "start_time_minutes": current_time,
                        "duration_minutes": technique_duration,
                        "phase": phase.value,
                        "technique_id": technique.technique_id,
                        "technique_name": technique.name
                    })
                    current_time += technique_duration
        
        return timeline
    
    async def generate_safety_considerations(self, techniques: List[AttackTechnique]) -> List[str]:
        """Generate safety considerations for techniques"""
        considerations = []
        
        for technique in techniques:
            if technique.phase == AttackPhase.IMPACT:
                considerations.append(f"HIGH RISK: {technique.name} can cause system damage")
            elif technique.phase == AttackPhase.EXFILTRATION:
                considerations.append(f"DATA RISK: {technique.name} involves data access")
            elif "administrator" in " ".join(technique.prerequisites or []).lower():
                considerations.append(f"PRIVILEGE RISK: {technique.name} requires elevated privileges")
        
        return list(set(considerations))

# CLI Interface
async def main():
    """Main function for Delta Red Team Agent"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Delta Red Team Offense Agent")
    parser.add_argument("action", choices=["start", "status", "terminate", "list"])
    parser.add_argument("--config", help="Operation configuration file (JSON)")
    parser.add_argument("--operation-id", help="Specific operation ID")
    parser.add_argument("--target", help="Target environment")
    parser.add_argument("--adversary", help="Adversary profile", default="APT-28")
    parser.add_argument("--duration", type=int, help="Duration in hours", default=4)
    
    args = parser.parse_args()
    
    agent = DeltaRedTeamAgent()
    
    if args.action == "start":
        if args.config:
            with open(args.config, 'r') as f:
                config = json.load(f)
        else:
            if not args.target:
                print("Error: --target required when not using --config")
                return
            
            config = {
                "target_environment": args.target,
                "adversary_profile": args.adversary,
                "duration_hours": args.duration,
                "objectives": [
                    "Establish persistence",
                    "Escalate privileges",
                    "Move laterally",
                    "Simulate data access"
                ]
            }
        
        result = await agent.start_adversary_emulation(config)
        print(json.dumps(result, indent=2))
    
    elif args.action == "status":
        if args.operation_id:
            status = await agent.get_operation_status(args.operation_id)
            print(json.dumps(status, indent=2, default=str))
        else:
            operations = agent.list_active_operations()
            print("Active Operations:")
            for op in operations:
                print(f"  {op['operation_id']}: {op['name']} [{op['status']}]")
    
    elif args.action == "terminate":
        if not args.operation_id:
            print("Error: --operation-id required for terminate")
            return
        
        result = await agent.terminate_operation(args.operation_id)
        print(json.dumps(result, indent=2))
    
    elif args.action == "list":
        operations = agent.list_active_operations()
        print(json.dumps(operations, indent=2))

if __name__ == "__main__":
    asyncio.run(main())