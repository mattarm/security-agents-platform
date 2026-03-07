#!/usr/bin/env python3
"""
Slack War Room Bot for SecurityAgents SOC Operations
Interactive SOC operations through Slack war rooms with enhanced SecurityAgents
"""

import asyncio
import logging
import json
import os
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
import sqlite3
import threading

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WarRoomType(Enum):
    INCIDENT_RESPONSE = "incident_response"
    THREAT_HUNTING = "threat_hunting"
    VULNERABILITY_RESPONSE = "vulnerability_response"
    PURPLE_TEAM_EXERCISE = "purple_team_exercise"

class WarRoomStatus(Enum):
    ACTIVE = "active"
    INVESTIGATING = "investigating"
    RESOLVING = "resolving"
    RESOLVED = "resolved"
    ARCHIVED = "archived"

class EvidenceType(Enum):
    LOG_ENTRY = "log_entry"
    SCREENSHOT = "screenshot"
    COMMAND_OUTPUT = "command_output"
    ANALYSIS_RESULT = "analysis_result"
    TIMELINE_EVENT = "timeline_event"

@dataclass
class WarRoom:
    """War room data structure"""
    id: str
    channel_id: str
    channel_name: str
    type: WarRoomType
    status: WarRoomStatus
    title: str
    description: str
    severity: str
    created_at: datetime
    created_by: str
    assigned_agents: List[str]
    team_members: List[str]
    evidence_count: int
    last_activity: datetime

@dataclass
class Evidence:
    """Evidence data structure"""
    id: str
    war_room_id: str
    type: EvidenceType
    title: str
    content: str
    collected_by: str
    collected_at: datetime
    metadata: Dict[str, Any]
    hash_value: str

class WarRoomDatabase:
    """Database management for war rooms and evidence"""
    
    def __init__(self, db_path: str = "war_rooms.db"):
        self.db_path = db_path
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # War rooms table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS war_rooms (
                id TEXT PRIMARY KEY,
                channel_id TEXT UNIQUE,
                channel_name TEXT,
                type TEXT,
                status TEXT,
                title TEXT,
                description TEXT,
                severity TEXT,
                created_at TIMESTAMP,
                created_by TEXT,
                assigned_agents TEXT,
                team_members TEXT,
                evidence_count INTEGER DEFAULT 0,
                last_activity TIMESTAMP
            )
        ''')
        
        # Evidence table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                war_room_id TEXT,
                type TEXT,
                title TEXT,
                content TEXT,
                collected_by TEXT,
                collected_at TIMESTAMP,
                metadata TEXT,
                hash_value TEXT,
                FOREIGN KEY (war_room_id) REFERENCES war_rooms (id)
            )
        ''')
        
        # Agent interactions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS agent_interactions (
                id TEXT PRIMARY KEY,
                war_room_id TEXT,
                agent_name TEXT,
                command TEXT,
                response TEXT,
                executed_by TEXT,
                executed_at TIMESTAMP,
                FOREIGN KEY (war_room_id) REFERENCES war_rooms (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def create_war_room(self, war_room: WarRoom) -> bool:
        """Create new war room in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO war_rooms 
                (id, channel_id, channel_name, type, status, title, description, severity,
                 created_at, created_by, assigned_agents, team_members, evidence_count, last_activity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                war_room.id, war_room.channel_id, war_room.channel_name,
                war_room.type.value, war_room.status.value,
                war_room.title, war_room.description, war_room.severity,
                war_room.created_at, war_room.created_by,
                json.dumps(war_room.assigned_agents),
                json.dumps(war_room.team_members),
                war_room.evidence_count, war_room.last_activity
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            logger.error(f"Failed to create war room: {e}")
            return False
    
    def get_war_room_by_channel(self, channel_id: str) -> Optional[WarRoom]:
        """Get war room by Slack channel ID"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM war_rooms WHERE channel_id = ?', (channel_id,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return WarRoom(
                    id=row[0], channel_id=row[1], channel_name=row[2],
                    type=WarRoomType(row[3]), status=WarRoomStatus(row[4]),
                    title=row[5], description=row[6], severity=row[7],
                    created_at=datetime.fromisoformat(row[8]), created_by=row[9],
                    assigned_agents=json.loads(row[10]),
                    team_members=json.loads(row[11]),
                    evidence_count=row[12], last_activity=datetime.fromisoformat(row[13])
                )
            return None
            
        except Exception as e:
            logger.error(f"Failed to get war room: {e}")
            return None
    
    def add_evidence(self, evidence: Evidence) -> bool:
        """Add evidence to war room"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO evidence 
                (id, war_room_id, type, title, content, collected_by, collected_at, metadata, hash_value)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                evidence.id, evidence.war_room_id, evidence.type.value,
                evidence.title, evidence.content, evidence.collected_by,
                evidence.collected_at, json.dumps(evidence.metadata),
                evidence.hash_value
            ))
            
            # Update evidence count
            cursor.execute('''
                UPDATE war_rooms 
                SET evidence_count = evidence_count + 1, last_activity = ?
                WHERE id = ?
            ''', (datetime.now(), evidence.war_room_id))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            logger.error(f"Failed to add evidence: {e}")
            return False

class SecurityAgentsIntegration:
    """Integration layer for enhanced SecurityAgents"""
    
    def __init__(self):
        self.agents_available = {
            "alpha-4": "Enhanced Threat Intelligence",
            "gamma": "SOC Operations",
            "beta-4": "DevSecOps Security",
            "delta": "Red Team Operations"
        }
    
    async def execute_alpha_4_command(self, command: str, parameters: str) -> Dict[str, Any]:
        """Execute Alpha-4 threat intelligence command"""
        
        # Simulate Alpha-4 enhanced capabilities
        if command == "actor":
            return {
                "command": f"alpha actor {parameters}",
                "result": {
                    "actor_name": parameters,
                    "confidence": 0.95,
                    "ttps": ["T1059.001", "T1055", "T1083"],
                    "campaigns": ["Campaign-2024-001", "Campaign-2024-007"],
                    "attribution": "High confidence based on CrowdStrike intelligence",
                    "threat_level": "High",
                    "target_sectors": ["Financial", "Government", "Healthcare"]
                },
                "execution_time": 2.3,
                "source": "CrowdStrike Falcon Intelligence + MITRE ATT&CK"
            }
        
        elif command == "ioc":
            return {
                "command": f"alpha ioc {parameters}",
                "result": {
                    "indicator": parameters,
                    "threat_classification": "Malicious",
                    "confidence": 0.89,
                    "first_seen": "2024-02-15T10:30:00Z",
                    "last_seen": "2024-03-06T18:45:00Z",
                    "related_campaigns": ["APT28-Campaign-2024"],
                    "attribution": "APT28/Fancy Bear",
                    "kill_chain_phase": "Command and Control"
                },
                "execution_time": 1.8,
                "source": "CrowdStrike Global Intelligence"
            }
        
        elif command == "hunt":
            return {
                "command": f"alpha hunt {parameters}",
                "result": {
                    "actor": parameters,
                    "hunt_queries": {
                        "falcon_fql": [
                            f"behaviors.technique:'T1059.001' AND device_id:* | head 100",
                            f"behaviors.cmdline:/.*powershell.*{parameters}.*/i | head 50"
                        ],
                        "sigma_rules": [
                            f"title: {parameters} PowerShell Activity Detection",
                            "detection: CommandLine contains '{parameters}'"
                        ]
                    },
                    "recommended_timeframe": "7d",
                    "expected_artifacts": ["Process creation", "Network connections", "File modifications"]
                },
                "execution_time": 1.5,
                "source": "Alpha-4 Enhanced Hunt Query Generator"
            }
        
        return {"error": f"Unknown Alpha-4 command: {command}"}
    
    async def execute_gamma_command(self, command: str, parameters: str) -> Dict[str, Any]:
        """Execute Gamma SOC operations command"""
        
        if command == "incident":
            return {
                "command": f"gamma incident {parameters}",
                "result": {
                    "incident_id": parameters,
                    "severity": "High",
                    "status": "Active Investigation",
                    "affected_hosts": 3,
                    "detection_count": 15,
                    "behavior_analysis": {
                        "lateral_movement": True,
                        "persistence": True,
                        "data_exfiltration": False
                    },
                    "containment_recommendations": [
                        "Isolate affected hosts from network",
                        "Disable compromised user accounts",
                        "Monitor for additional C2 communications"
                    ],
                    "timeline": [
                        {"time": "14:23:15", "event": "Initial malware execution"},
                        {"time": "14:25:42", "event": "Persistence mechanism installed"},
                        {"time": "14:28:11", "event": "Lateral movement to DC01"}
                    ]
                },
                "execution_time": 3.2,
                "source": "Gamma Enhanced Incident Analysis"
            }
        
        elif command == "hunt":
            return {
                "command": f"gamma hunt {parameters}",
                "result": {
                    "hypothesis": parameters,
                    "hunt_results": {
                        "suspicious_activities": 7,
                        "validated_threats": 4,
                        "false_positives": 3
                    },
                    "findings": [
                        {"host": "WS-001", "activity": "Suspicious PowerShell", "confidence": 0.85},
                        {"host": "SRV-05", "activity": "Unusual network traffic", "confidence": 0.92},
                        {"host": "WS-078", "activity": "Privilege escalation attempt", "confidence": 0.78}
                    ],
                    "recommendations": [
                        "Investigate WS-001 PowerShell activity",
                        "Analyze SRV-05 network connections",
                        "Review WS-078 user privileges"
                    ]
                },
                "execution_time": 45.7,
                "source": "Gamma Automated Threat Hunting"
            }
        
        elif command == "contain":
            return {
                "command": f"gamma contain {parameters}",
                "result": {
                    "containment_id": f"CONT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                    "affected_hosts": parameters.split(','),
                    "actions_taken": [
                        "Network isolation applied",
                        "Host quarantine initiated",
                        "User accounts disabled",
                        "Monitoring enhanced"
                    ],
                    "containment_status": "Successful",
                    "estimated_impact": "Minimal business disruption"
                },
                "execution_time": 8.5,
                "source": "Gamma Automated Containment"
            }
        
        return {"error": f"Unknown Gamma command: {command}"}
    
    async def execute_beta_4_command(self, command: str, parameters: str) -> Dict[str, Any]:
        """Execute Beta-4 DevSecOps command"""
        
        if command == "scan":
            return {
                "command": f"beta-4 scan {parameters}",
                "result": {
                    "container": parameters,
                    "security_score": 82.5,
                    "vulnerabilities": {
                        "critical": 1,
                        "high": 3,
                        "medium": 8,
                        "low": 15
                    },
                    "compliance_status": "Pass",
                    "runtime_analysis": {
                        "suspicious_processes": 0,
                        "network_anomalies": 2,
                        "file_integrity": "Clean"
                    },
                    "recommendations": [
                        "Update base image to latest version",
                        "Apply security patches for CVE-2024-0001",
                        "Review network configuration"
                    ]
                },
                "execution_time": 12.3,
                "source": "Beta-4 Enhanced Container Security"
            }
        
        elif command == "k8s":
            return {
                "command": f"beta-4 k8s {parameters}",
                "result": {
                    "cluster": parameters,
                    "security_posture": 78.2,
                    "node_security": 85.0,
                    "pod_security": 72.5,
                    "rbac_compliance": 88.0,
                    "network_policies": 65.0,
                    "falcon_coverage": 94.5,
                    "findings": [
                        "3 pods running as root",
                        "Network policies missing for 15 namespaces",
                        "2 nodes require security updates"
                    ],
                    "priority_actions": [
                        "Implement pod security standards",
                        "Deploy missing network policies",
                        "Update node security patches"
                    ]
                },
                "execution_time": 18.7,
                "source": "Beta-4 Kubernetes Security Assessment"
            }
        
        return {"error": f"Unknown Beta-4 command: {command}"}
    
    async def execute_delta_command(self, command: str, parameters: str) -> Dict[str, Any]:
        """Execute Delta red team command"""
        
        if command == "exercise":
            return {
                "command": f"delta exercise {parameters}",
                "result": {
                    "exercise_id": f"EX-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                    "exercise_type": "Purple Team",
                    "techniques_tested": 8,
                    "techniques_detected": 6,
                    "detection_rate": 75.0,
                    "prevention_rate": 50.0,
                    "findings": [
                        "PowerShell detection working effectively",
                        "Lateral movement partially detected",
                        "Persistence mechanism missed"
                    ],
                    "improvements_needed": [
                        "Enhance persistence detection rules",
                        "Improve lateral movement monitoring",
                        "Add behavioral analysis alerts"
                    ]
                },
                "execution_time": 3600.0,  # 1 hour exercise
                "source": "Delta Purple Team Automation"
            }
        
        elif command == "simulate":
            return {
                "command": f"delta simulate {parameters}",
                "result": {
                    "simulation_id": f"SIM-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                    "threat_actor": parameters,
                    "campaign_fidelity": 95.2,
                    "techniques_executed": 12,
                    "detection_events": 8,
                    "containment_actions": 3,
                    "behavioral_analysis": {
                        "ttps_accuracy": 94.5,
                        "timeline_realism": 96.0,
                        "defense_response": 87.5
                    },
                    "lessons_learned": [
                        "Detection coverage strong for initial access",
                        "Response time needs improvement",
                        "Communication protocols effective"
                    ]
                },
                "execution_time": 7200.0,  # 2 hour simulation
                "source": "Delta Threat Actor Simulation"
            }
        
        return {"error": f"Unknown Delta command: {command}"}

class SlackWarRoomBot:
    """Main Slack War Room Bot implementation"""
    
    def __init__(self):
        self.app = App(
            token=os.environ.get("SLACK_BOT_TOKEN"),
            signing_secret=os.environ.get("SLACK_SIGNING_SECRET")
        )
        
        self.db = WarRoomDatabase()
        self.agents = SecurityAgentsIntegration()
        
        self.setup_handlers()
    
    def setup_handlers(self):
        """Setup Slack event handlers"""
        
        # War room creation commands
        @self.app.command("/create-war-room")
        async def create_war_room_handler(ack, respond, command):
            await ack()
            await self.handle_create_war_room(respond, command)
        
        # Alpha-4 commands
        @self.app.command("/alpha")
        async def alpha_command_handler(ack, respond, command):
            await ack()
            await self.handle_alpha_command(respond, command)
        
        # Gamma commands
        @self.app.command("/gamma")
        async def gamma_command_handler(ack, respond, command):
            await ack()
            await self.handle_gamma_command(respond, command)
        
        # Beta-4 commands
        @self.app.command("/beta")
        async def beta_command_handler(ack, respond, command):
            await ack()
            await self.handle_beta_command(respond, command)
        
        # Delta commands
        @self.app.command("/delta")
        async def delta_command_handler(ack, respond, command):
            await ack()
            await self.handle_delta_command(respond, command)
        
        # Evidence collection
        @self.app.command("/evidence")
        async def evidence_command_handler(ack, respond, command):
            await ack()
            await self.handle_evidence_command(respond, command)
        
        # War room status
        @self.app.command("/war-room-status")
        async def status_command_handler(ack, respond, command):
            await ack()
            await self.handle_status_command(respond, command)
    
    async def handle_create_war_room(self, respond, command):
        """Handle war room creation"""
        try:
            # Parse command parameters
            params = command['text'].strip().split()
            if len(params) < 3:
                await respond("Usage: `/create-war-room <type> <severity> <title>`")
                return
            
            war_room_type = params[0]
            severity = params[1]
            title = ' '.join(params[2:])
            
            # Create war room
            war_room_id = str(uuid.uuid4())
            channel_name = f"war-room-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            
            # TODO: Create actual Slack channel
            channel_id = f"C{uuid.uuid4().hex[:10].upper()}"  # Simulated
            
            war_room = WarRoom(
                id=war_room_id,
                channel_id=channel_id,
                channel_name=channel_name,
                type=WarRoomType(war_room_type),
                status=WarRoomStatus.ACTIVE,
                title=title,
                description=f"War room for {title}",
                severity=severity,
                created_at=datetime.now(),
                created_by=command['user_id'],
                assigned_agents=self.determine_agents_for_type(war_room_type),
                team_members=[command['user_id']],
                evidence_count=0,
                last_activity=datetime.now()
            )
            
            # Save to database
            if self.db.create_war_room(war_room):
                await respond({
                    "text": f"War room created successfully!",
                    "blocks": [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"🚨 *War Room Created*\n\n*Type:* {war_room_type}\n*Severity:* {severity}\n*Title:* {title}\n*Channel:* #{channel_name}\n*Assigned Agents:* {', '.join(war_room.assigned_agents)}"
                            }
                        },
                        {
                            "type": "actions",
                            "elements": [
                                {
                                    "type": "button",
                                    "text": {"type": "plain_text", "text": "Join War Room"},
                                    "value": channel_id,
                                    "action_id": "join_war_room"
                                }
                            ]
                        }
                    ]
                })
            else:
                await respond("Failed to create war room. Please try again.")
                
        except Exception as e:
            logger.error(f"Failed to create war room: {e}")
            await respond("Error creating war room. Please check parameters.")
    
    def determine_agents_for_type(self, war_room_type: str) -> List[str]:
        """Determine which agents to assign based on war room type"""
        agent_assignments = {
            "incident_response": ["gamma", "alpha-4"],
            "threat_hunting": ["alpha-4", "gamma"],
            "vulnerability_response": ["beta-4", "gamma"],
            "purple_team_exercise": ["delta", "gamma"]
        }
        
        return agent_assignments.get(war_room_type, ["gamma"])
    
    async def handle_alpha_command(self, respond, command):
        """Handle Alpha-4 threat intelligence commands"""
        try:
            parts = command['text'].strip().split(maxsplit=1)
            if len(parts) < 2:
                await respond("Usage: `/alpha <command> <parameters>`\nCommands: actor, ioc, campaign, hunt, brief")
                return
            
            cmd = parts[0]
            params = parts[1] if len(parts) > 1 else ""
            
            # Execute Alpha-4 command
            result = await self.agents.execute_alpha_4_command(cmd, params)
            
            # Record interaction and collect evidence
            await self.record_agent_interaction(command['channel_id'], "alpha-4", command['text'], result, command['user_id'])
            
            # Format response
            if "error" in result:
                await respond(f"❌ {result['error']}")
            else:
                await respond({
                    "text": f"Alpha-4 analysis complete",
                    "blocks": [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"🧠 *Alpha-4 Threat Intelligence*\n\n*Command:* `{result['command']}`\n*Execution Time:* {result['execution_time']}s\n*Source:* {result['source']}"
                            }
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"```{json.dumps(result['result'], indent=2)}```"
                            }
                        }
                    ]
                })
                
        except Exception as e:
            logger.error(f"Alpha-4 command error: {e}")
            await respond("Error executing Alpha-4 command. Please try again.")
    
    async def handle_gamma_command(self, respond, command):
        """Handle Gamma SOC operations commands"""
        try:
            parts = command['text'].strip().split(maxsplit=1)
            if len(parts) < 2:
                await respond("Usage: `/gamma <command> <parameters>`\nCommands: incident, hunt, contain, timeline, posture")
                return
            
            cmd = parts[0]
            params = parts[1] if len(parts) > 1 else ""
            
            # Execute Gamma command
            result = await self.agents.execute_gamma_command(cmd, params)
            
            # Record interaction
            await self.record_agent_interaction(command['channel_id'], "gamma", command['text'], result, command['user_id'])
            
            # Format response
            if "error" in result:
                await respond(f"❌ {result['error']}")
            else:
                await respond({
                    "text": f"Gamma SOC analysis complete",
                    "blocks": [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"🛡️ *Gamma SOC Operations*\n\n*Command:* `{result['command']}`\n*Execution Time:* {result['execution_time']}s\n*Source:* {result['source']}"
                            }
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"```{json.dumps(result['result'], indent=2)}```"
                            }
                        }
                    ]
                })
                
        except Exception as e:
            logger.error(f"Gamma command error: {e}")
            await respond("Error executing Gamma command. Please try again.")
    
    async def handle_beta_command(self, respond, command):
        """Handle Beta-4 DevSecOps commands"""
        try:
            parts = command['text'].strip().split(maxsplit=1)
            if len(parts) < 2:
                await respond("Usage: `/beta <command> <parameters>`\nCommands: scan, k8s, pipeline, supply-chain, remediate")
                return
            
            cmd = parts[0]
            params = parts[1] if len(parts) > 1 else ""
            
            # Execute Beta-4 command
            result = await self.agents.execute_beta_4_command(cmd, params)
            
            # Record interaction
            await self.record_agent_interaction(command['channel_id'], "beta-4", command['text'], result, command['user_id'])
            
            # Format response
            if "error" in result:
                await respond(f"❌ {result['error']}")
            else:
                await respond({
                    "text": f"Beta-4 security analysis complete",
                    "blocks": [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"⚙️ *Beta-4 DevSecOps*\n\n*Command:* `{result['command']}`\n*Execution Time:* {result['execution_time']}s\n*Source:* {result['source']}"
                            }
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"```{json.dumps(result['result'], indent=2)}```"
                            }
                        }
                    ]
                })
                
        except Exception as e:
            logger.error(f"Beta-4 command error: {e}")
            await respond("Error executing Beta-4 command. Please try again.")
    
    async def handle_delta_command(self, respond, command):
        """Handle Delta red team commands"""
        try:
            parts = command['text'].strip().split(maxsplit=1)
            if len(parts) < 2:
                await respond("Usage: `/delta <command> <parameters>`\nCommands: exercise, simulate, test, bypass, validate")
                return
            
            cmd = parts[0]
            params = parts[1] if len(parts) > 1 else ""
            
            # Execute Delta command
            result = await self.agents.execute_delta_command(cmd, params)
            
            # Record interaction
            await self.record_agent_interaction(command['channel_id'], "delta", command['text'], result, command['user_id'])
            
            # Format response
            if "error" in result:
                await respond(f"❌ {result['error']}")
            else:
                await respond({
                    "text": f"Delta red team analysis complete",
                    "blocks": [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"⚔️ *Delta Red Team*\n\n*Command:* `{result['command']}`\n*Execution Time:* {result['execution_time']}s\n*Source:* {result['source']}"
                            }
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"```{json.dumps(result['result'], indent=2)}```"
                            }
                        }
                    ]
                })
                
        except Exception as e:
            logger.error(f"Delta command error: {e}")
            await respond("Error executing Delta command. Please try again.")
    
    async def record_agent_interaction(self, channel_id: str, agent_name: str, command: str, response: Dict, user_id: str):
        """Record agent interaction as evidence"""
        try:
            war_room = self.db.get_war_room_by_channel(channel_id)
            if war_room:
                # Create evidence record
                evidence = Evidence(
                    id=str(uuid.uuid4()),
                    war_room_id=war_room.id,
                    type=EvidenceType.COMMAND_OUTPUT,
                    title=f"{agent_name.title()} Command: {command}",
                    content=json.dumps(response, indent=2),
                    collected_by=user_id,
                    collected_at=datetime.now(),
                    metadata={
                        "agent": agent_name,
                        "command": command,
                        "execution_time": response.get("execution_time", 0),
                        "source": response.get("source", "Unknown")
                    },
                    hash_value="sha256_placeholder"  # TODO: Implement actual hashing
                )
                
                self.db.add_evidence(evidence)
                
        except Exception as e:
            logger.error(f"Failed to record agent interaction: {e}")
    
    async def handle_evidence_command(self, respond, command):
        """Handle evidence collection command"""
        try:
            # Evidence collection implementation
            await respond("📋 Evidence collection feature coming soon!")
            
        except Exception as e:
            logger.error(f"Evidence command error: {e}")
            await respond("Error processing evidence command.")
    
    async def handle_status_command(self, respond, command):
        """Handle war room status command"""
        try:
            war_room = self.db.get_war_room_by_channel(command['channel_id'])
            
            if war_room:
                await respond({
                    "text": f"War room status",
                    "blocks": [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"📊 *War Room Status*\n\n*ID:* {war_room.id}\n*Type:* {war_room.type.value}\n*Status:* {war_room.status.value}\n*Title:* {war_room.title}\n*Severity:* {war_room.severity}\n*Evidence Count:* {war_room.evidence_count}\n*Assigned Agents:* {', '.join(war_room.assigned_agents)}\n*Team Members:* {len(war_room.team_members)}\n*Last Activity:* {war_room.last_activity}"
                            }
                        }
                    ]
                })
            else:
                await respond("This channel is not a war room.")
                
        except Exception as e:
            logger.error(f"Status command error: {e}")
            await respond("Error retrieving war room status.")
    
    def start(self):
        """Start the Slack War Room Bot"""
        handler = SocketModeHandler(self.app, os.environ["SLACK_APP_TOKEN"])
        logger.info("🚀 Starting Slack War Room Bot...")
        handler.start()

# Main execution
if __name__ == "__main__":
    bot = SlackWarRoomBot()
    bot.start()