#!/usr/bin/env python3
"""
SecurityAgents CrowdStrike Falcon MCP Integration Framework
Unified MCP client for all SecurityAgents with CrowdStrike Falcon platform
"""

import asyncio
import logging
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

# MCP imports
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.sse import sse_client
from mcp.types import Tool, Resource

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityAgent(Enum):
    ALPHA_4 = "alpha-4"  # Threat Intelligence
    GAMMA = "gamma"      # Blue Team Defense
    BETA_4 = "beta-4"    # DevSecOps
    DELTA = "delta"      # Red Team

@dataclass
class MCPQuery:
    """Structured MCP query for SecurityAgents"""
    tool_name: str
    parameters: Dict[str, Any]
    agent: SecurityAgent
    workflow: str
    priority: str = "normal"
    
class FalconMCPClient:
    """CrowdStrike Falcon MCP Client for SecurityAgents"""
    
    def __init__(self, transport: str = "stdio"):
        self.transport = transport
        self.session: Optional[ClientSession] = None
        self.available_tools: Dict[str, Tool] = {}
        self.available_resources: Dict[str, Resource] = {}
        self.agent_modules = self._get_agent_module_mapping()
        
    def _get_agent_module_mapping(self) -> Dict[SecurityAgent, List[str]]:
        """Map SecurityAgents to relevant CrowdStrike modules"""
        return {
            SecurityAgent.ALPHA_4: [
                "falcon_search_actors",
                "falcon_search_indicators", 
                "falcon_get_mitre_report",
                "falcon_search_reports",
                "falcon_search_detections",
                "falcon_search_incidents",
                "falcon_search_iocs",
                "falcon_add_ioc"
            ],
            SecurityAgent.GAMMA: [
                "falcon_search_detections",
                "falcon_get_detection_details",
                "falcon_search_incidents", 
                "falcon_get_incident_details",
                "falcon_search_behaviors",
                "falcon_get_behavior_details",
                "falcon_search_hosts",
                "falcon_show_crowd_score",
                "search_ngsiem"
            ],
            SecurityAgent.BETA_4: [
                "falcon_search_vulnerabilities",
                "falcon_search_serverless_vulnerabilities",
                "falcon_search_images_vulnerabilities",
                "falcon_search_applications",
                "falcon_search_unmanaged_assets",
                "falcon_search_kubernetes_containers"
            ],
            SecurityAgent.DELTA: [
                "falcon_search_hosts",
                "falcon_search_detections",
                "falcon_search_applications",
                "idp_investigate_entity",
                "falcon_search_actors",
                "falcon_show_crowd_score"
            ]
        }
    
    async def connect(self) -> bool:
        """Connect to CrowdStrike Falcon MCP server"""
        try:
            if self.transport == "stdio":
                server_params = StdioServerParameters(
                    command="falcon-mcp",
                    args=[]
                )
                async with stdio_client(server_params) as (read, write):
                    async with ClientSession(read, write) as session:
                        self.session = session
                        await self._initialize_session()
                        return True
                        
            elif self.transport == "sse":
                async with sse_client("http://127.0.0.1:8000/sse") as (read, write):
                    async with ClientSession(read, write) as session:
                        self.session = session
                        await self._initialize_session()
                        return True
                    
        except Exception as e:
            logger.error(f"Failed to connect to Falcon MCP: {e}")
            return False
    
    async def _initialize_session(self):
        """Initialize MCP session and discover capabilities"""
        if not self.session:
            return
            
        # Initialize session
        await self.session.initialize()
        
        # Discover available tools
        tools_result = await self.session.list_tools()
        self.available_tools = {tool.name: tool for tool in tools_result.tools}
        
        # Discover available resources  
        resources_result = await self.session.list_resources()
        self.available_resources = {res.uri: res for res in resources_result.resources}
        
        logger.info(f"Connected to Falcon MCP: {len(self.available_tools)} tools, {len(self.available_resources)} resources")
    
    async def execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a CrowdStrike Falcon MCP tool"""
        if not self.session:
            raise RuntimeError("Not connected to Falcon MCP")
            
        if tool_name not in self.available_tools:
            raise ValueError(f"Tool {tool_name} not available")
        
        try:
            result = await self.session.call_tool(tool_name, parameters)
            return {
                "success": True,
                "tool": tool_name,
                "parameters": parameters,
                "result": result.content,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error executing tool {tool_name}: {e}")
            return {
                "success": False,
                "tool": tool_name,
                "parameters": parameters,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    async def get_resource(self, resource_uri: str) -> Dict[str, Any]:
        """Get a CrowdStrike Falcon MCP resource (like FQL guides)"""
        if not self.session:
            raise RuntimeError("Not connected to Falcon MCP")
            
        if resource_uri not in self.available_resources:
            raise ValueError(f"Resource {resource_uri} not available")
        
        try:
            result = await self.session.read_resource(resource_uri)
            return {
                "success": True,
                "resource": resource_uri,
                "content": result.contents,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error reading resource {resource_uri}: {e}")
            return {
                "success": False,
                "resource": resource_uri,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def get_agent_tools(self, agent: SecurityAgent) -> List[str]:
        """Get available tools for a specific SecurityAgent"""
        agent_tools = self.agent_modules.get(agent, [])
        return [tool for tool in agent_tools if tool in self.available_tools]
    
    def get_agent_resources(self, agent: SecurityAgent) -> List[str]:
        """Get available resources for a specific SecurityAgent"""
        # Map agents to relevant FQL guide resources
        resource_mapping = {
            SecurityAgent.ALPHA_4: [
                "falcon://intel/actors/fql-guide",
                "falcon://intel/indicators/fql-guide", 
                "falcon://intel/reports/fql-guide",
                "falcon://detections/search/fql-guide",
                "falcon://incidents/search/fql-guide"
            ],
            SecurityAgent.GAMMA: [
                "falcon://detections/search/fql-guide",
                "falcon://incidents/search/fql-guide",
                "falcon://incidents/behaviors/fql-guide",
                "falcon://hosts/search/fql-guide"
            ],
            SecurityAgent.BETA_4: [
                "falcon://spotlight/vulnerabilities/fql-guide",
                "falcon://serverless/vulnerabilities/fql-guide",
                "falcon://cloud/images-vulnerabilities/fql-guide",
                "falcon://discover/applications/fql-guide"
            ],
            SecurityAgent.DELTA: [
                "falcon://hosts/search/fql-guide",
                "falcon://detections/search/fql-guide"
            ]
        }
        
        agent_resources = resource_mapping.get(agent, [])
        return [res for res in agent_resources if res in self.available_resources]


class FQLQueryBuilder:
    """Build FQL queries for CrowdStrike Falcon platform"""
    
    @staticmethod
    def build_threat_actor_query(actor_name: str) -> str:
        """Build FQL query for threat actor research"""
        return f"name.raw:'{actor_name}' OR aliases:'{actor_name}'"
    
    @staticmethod
    def build_detection_hunt_query(tactics: List[str], timeframe: str = "24h") -> str:
        """Build FQL query for threat hunting"""
        tactic_filter = " OR ".join([f"behaviors.tactic:'{tactic}'" for tactic in tactics])
        return f"({tactic_filter}) AND first_behavior:>now-{timeframe}"
    
    @staticmethod  
    def build_vulnerability_query(severity: str, asset_criticality: str = None) -> str:
        """Build FQL query for vulnerability prioritization"""
        query = f"cve.severity:'{severity}'"
        if asset_criticality:
            query += f" AND asset.criticality:'{asset_criticality}'"
        return query + " AND cve.exploitability_score:>'7.0'"
    
    @staticmethod
    def build_incident_correlation_query(confidence_threshold: float = 0.8) -> str:
        """Build FQL query for incident correlation"""
        return f"confidence:>{confidence_threshold} AND status:!'closed'"
    
    @staticmethod
    def build_host_investigation_query(hostname: str = None, ip: str = None) -> str:
        """Build FQL query for host investigation"""
        if hostname:
            return f"hostname:'{hostname}' OR computer_name:'{hostname}'"
        elif ip:
            return f"local_ip:'{ip}' OR external_ip:'{ip}'"
        else:
            raise ValueError("Either hostname or ip must be provided")


class SecurityAgentsMCPIntegration:
    """Main integration class for SecurityAgents with CrowdStrike MCP"""
    
    def __init__(self, agent: SecurityAgent, transport: str = "stdio"):
        self.agent = agent
        self.mcp_client = FalconMCPClient(transport)
        self.query_builder = FQLQueryBuilder()
        self.session_active = False
        
    async def initialize(self) -> bool:
        """Initialize the MCP integration"""
        success = await self.mcp_client.connect()
        if success:
            self.session_active = True
            logger.info(f"Initialized CrowdStrike MCP integration for {self.agent.value}")
            
            # Log available capabilities for this agent
            tools = self.mcp_client.get_agent_tools(self.agent)
            resources = self.mcp_client.get_agent_resources(self.agent)
            logger.info(f"Agent {self.agent.value} has access to {len(tools)} tools and {len(resources)} resources")
            
        return success
    
    async def execute_workflow(self, workflow_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute agent-specific workflow using CrowdStrike MCP"""
        if not self.session_active:
            raise RuntimeError("MCP integration not initialized")
        
        # Route to agent-specific workflow implementation
        workflow_handlers = {
            SecurityAgent.ALPHA_4: self._alpha_4_workflows,
            SecurityAgent.GAMMA: self._gamma_workflows, 
            SecurityAgent.BETA_4: self._beta_4_workflows,
            SecurityAgent.DELTA: self._delta_workflows
        }
        
        handler = workflow_handlers.get(self.agent)
        if not handler:
            raise ValueError(f"No workflow handler for agent {self.agent}")
        
        return await handler(workflow_name, parameters)
    
    async def _alpha_4_workflows(self, workflow: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Alpha-4 Threat Intelligence workflows"""
        if workflow == "threat_actor_investigation":
            return await self._investigate_threat_actor(params)
        elif workflow == "ioc_enrichment":
            return await self._enrich_iocs(params)
        elif workflow == "campaign_analysis":
            return await self._analyze_campaign(params)
        else:
            raise ValueError(f"Unknown Alpha-4 workflow: {workflow}")
    
    async def _gamma_workflows(self, workflow: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Gamma Blue Team Defense workflows"""
        if workflow == "incident_response":
            return await self._respond_to_incident(params)
        elif workflow == "threat_hunting":
            return await self._execute_threat_hunt(params)
        elif workflow == "security_posture":
            return await self._assess_security_posture(params)
        else:
            raise ValueError(f"Unknown Gamma workflow: {workflow}")
    
    async def _beta_4_workflows(self, workflow: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Beta-4 DevSecOps workflows"""  
        if workflow == "vulnerability_assessment":
            return await self._assess_vulnerabilities(params)
        elif workflow == "container_security":
            return await self._scan_containers(params)
        elif workflow == "application_inventory":
            return await self._inventory_applications(params)
        else:
            raise ValueError(f"Unknown Beta-4 workflow: {workflow}")
    
    async def _delta_workflows(self, workflow: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Delta Red Team workflows"""
        if workflow == "reconnaissance":
            return await self._execute_reconnaissance(params)
        elif workflow == "purple_team_validation":
            return await self._validate_purple_team(params)
        else:
            raise ValueError(f"Unknown Delta workflow: {workflow}")
    
    # Alpha-4 Workflow Implementations
    async def _investigate_threat_actor(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Investigate threat actor using CrowdStrike intelligence"""
        actor_name = params.get("actor_name")
        if not actor_name:
            raise ValueError("actor_name parameter required")
        
        results = {}
        
        # Step 1: Search for threat actor
        actor_query = self.query_builder.build_threat_actor_query(actor_name)
        actors_result = await self.mcp_client.execute_tool(
            "falcon_search_actors",
            {"filter": actor_query}
        )
        results["actor_search"] = actors_result
        
        if actors_result["success"] and actors_result["result"]:
            actor_id = actors_result["result"][0].get("id")
            
            # Step 2: Get MITRE ATT&CK report
            mitre_result = await self.mcp_client.execute_tool(
                "falcon_get_mitre_report", 
                {"actor_id": actor_id, "format": "json"}
            )
            results["mitre_report"] = mitre_result
            
            # Step 3: Search for related indicators
            indicators_result = await self.mcp_client.execute_tool(
                "falcon_search_indicators",
                {"filter": f"actors:'{actor_name}'"}
            )
            results["related_indicators"] = indicators_result
        
        return results
    
    async def _enrich_iocs(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich IOCs with CrowdStrike intelligence"""
        iocs = params.get("iocs", [])
        if not iocs:
            raise ValueError("iocs parameter required")
        
        results = {"enriched_iocs": []}
        
        for ioc in iocs:
            # Search for IOC in CrowdStrike intelligence
            indicator_result = await self.mcp_client.execute_tool(
                "falcon_search_indicators",
                {"filter": f"indicator:'{ioc}'"}
            )
            
            enrichment = {
                "ioc": ioc,
                "crowdstrike_intel": indicator_result,
                "enriched": indicator_result["success"]
            }
            
            # If found, add to custom IOCs for tracking
            if indicator_result["success"] and indicator_result["result"]:
                add_result = await self.mcp_client.execute_tool(
                    "falcon_add_ioc",
                    {
                        "value": ioc,
                        "type": "auto_detected",
                        "source": "crowdstrike_intelligence",
                        "description": f"IOC enriched from CrowdStrike intelligence"
                    }
                )
                enrichment["added_to_custom"] = add_result
            
            results["enriched_iocs"].append(enrichment)
        
        return results
    
    async def _analyze_campaign(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze threat campaign using detections and incidents"""
        campaign_indicators = params.get("indicators", [])
        timeframe = params.get("timeframe", "7d")
        
        results = {}
        
        # Search for related detections
        if campaign_indicators:
            indicator_filter = " OR ".join([f"behaviors.ioc:'{ioc}'" for ioc in campaign_indicators])
            detections_result = await self.mcp_client.execute_tool(
                "falcon_search_detections",
                {"filter": f"({indicator_filter}) AND first_behavior:>now-{timeframe}"}
            )
            results["campaign_detections"] = detections_result
        
        # Search for related incidents
        incidents_result = await self.mcp_client.execute_tool(
            "falcon_search_incidents",
            {"filter": f"created_timestamp:>now-{timeframe}"}
        )
        results["related_incidents"] = incidents_result
        
        return results
    
    # Gamma Workflow Implementations  
    async def _respond_to_incident(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Automated incident response workflow"""
        incident_id = params.get("incident_id")
        if not incident_id:
            raise ValueError("incident_id parameter required")
        
        results = {}
        
        # Get incident details
        incident_result = await self.mcp_client.execute_tool(
            "falcon_get_incident_details",
            {"ids": [incident_id]}
        )
        results["incident_details"] = incident_result
        
        if incident_result["success"]:
            # Get related behaviors  
            behaviors_result = await self.mcp_client.execute_tool(
                "falcon_search_behaviors",
                {"filter": f"incident_id:'{incident_id}'"}
            )
            results["behaviors"] = behaviors_result
            
            # Get affected hosts
            if behaviors_result["success"] and behaviors_result["result"]:
                host_ids = []
                for behavior in behaviors_result["result"]:
                    if behavior.get("device_id"):
                        host_ids.append(behavior["device_id"])
                
                if host_ids:
                    hosts_result = await self.mcp_client.execute_tool(
                        "falcon_get_host_details",
                        {"ids": list(set(host_ids))}
                    )
                    results["affected_hosts"] = hosts_result
        
        return results
    
    async def _execute_threat_hunt(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute threat hunting campaign"""
        tactics = params.get("tactics", ["Persistence", "Privilege Escalation"])
        timeframe = params.get("timeframe", "24h")
        
        # Build and execute hunt query
        hunt_query = self.query_builder.build_detection_hunt_query(tactics, timeframe)
        
        hunt_result = await self.mcp_client.execute_tool(
            "falcon_search_detections",
            {"filter": hunt_query}
        )
        
        return {"hunt_results": hunt_result}
    
    async def _assess_security_posture(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Assess organizational security posture"""
        posture_result = await self.mcp_client.execute_tool("falcon_show_crowd_score", {})
        
        return {"security_posture": posture_result}
    
    # Beta-4 Workflow Implementations
    async def _assess_vulnerabilities(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Assess vulnerabilities using Spotlight"""
        severity = params.get("severity", "Critical")
        criticality = params.get("asset_criticality")
        
        vuln_query = self.query_builder.build_vulnerability_query(severity, criticality)
        
        vuln_result = await self.mcp_client.execute_tool(
            "falcon_search_vulnerabilities",
            {"filter": vuln_query}
        )
        
        return {"vulnerability_assessment": vuln_result}
    
    async def _scan_containers(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Scan container images for vulnerabilities"""
        image_name = params.get("image_name")
        namespace = params.get("namespace")
        
        results = {}
        
        # Scan container images
        if image_name:
            images_result = await self.mcp_client.execute_tool(
                "falcon_search_images_vulnerabilities",
                {"filter": f"registry_image.repository:'{image_name}'"}
            )
            results["image_vulnerabilities"] = images_result
        
        # Check running containers  
        if namespace:
            containers_result = await self.mcp_client.execute_tool(
                "falcon_search_kubernetes_containers",
                {"filter": f"namespace:'{namespace}'"}
            )
            results["running_containers"] = containers_result
        
        return results
    
    async def _inventory_applications(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Inventory applications and assets"""
        results = {}
        
        # Get application inventory
        apps_result = await self.mcp_client.execute_tool("falcon_search_applications", {})
        results["applications"] = apps_result
        
        # Check for unmanaged assets
        unmanaged_result = await self.mcp_client.execute_tool("falcon_search_unmanaged_assets", {})
        results["unmanaged_assets"] = unmanaged_result
        
        return results
    
    # Delta Workflow Implementations
    async def _execute_reconnaissance(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute reconnaissance for red team operations"""
        target_domain = params.get("target_domain")
        
        results = {}
        
        # Enumerate hosts
        if target_domain:
            hosts_result = await self.mcp_client.execute_tool(
                "falcon_search_hosts",
                {"filter": f"hostname:'*{target_domain}*'"}
            )
            results["target_hosts"] = hosts_result
        
        # Check applications
        apps_result = await self.mcp_client.execute_tool("falcon_search_applications", {})
        results["target_applications"] = apps_result
        
        return results
    
    async def _validate_purple_team(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate purple team exercise effectiveness"""
        exercise_id = params.get("exercise_id")
        campaign_tag = params.get("campaign_tag", "red_team_exercise")
        
        results = {}
        
        # Check for detections during exercise
        detections_result = await self.mcp_client.execute_tool(
            "falcon_search_detections", 
            {"filter": f"behaviors.metadata.campaign:'{campaign_tag}'"}
        )
        results["exercise_detections"] = detections_result
        
        # Check security posture impact
        posture_result = await self.mcp_client.execute_tool("falcon_show_crowd_score", {})
        results["security_posture"] = posture_result
        
        return results


# Example usage and testing
async def main():
    """Example usage of SecurityAgents CrowdStrike MCP integration"""
    
    # Test Alpha-4 (Threat Intelligence) integration
    alpha_4 = SecurityAgentsMCPIntegration(SecurityAgent.ALPHA_4)
    
    if await alpha_4.initialize():
        print("✅ Alpha-4 MCP integration initialized")
        
        # Example: Investigate threat actor  
        try:
            result = await alpha_4.execute_workflow(
                "threat_actor_investigation",
                {"actor_name": "FANCY BEAR"}
            )
            print(f"Threat actor investigation result: {result}")
        except Exception as e:
            print(f"Workflow error: {e}")
    else:
        print("❌ Failed to initialize Alpha-4 MCP integration")


if __name__ == "__main__":
    asyncio.run(main())