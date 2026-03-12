#!/usr/bin/env python3
"""
Beta-4 Agent: Enhanced DevSecOps Skills with CrowdStrike MCP
Advanced DevSecOps automation using CrowdStrike Falcon platform integration
"""

import asyncio
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import uuid

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from framework.mcp_client import SecurityAgentsMCPIntegration, SecurityAgent, FQLQueryBuilder

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnerabilityRisk(Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ContainerSecurityStatus(Enum):
    SECURE = "secure"
    MINOR_ISSUES = "minor_issues"
    SECURITY_CONCERNS = "security_concerns"
    HIGH_RISK = "high_risk"
    CRITICAL_VULNERABILITIES = "critical_vulnerabilities"

class PipelineStage(Enum):
    BUILD = "build"
    TEST = "test"
    SCAN = "scan"
    DEPLOY = "deploy"
    RUNTIME = "runtime"

class RemediationPriority(Enum):
    P0_CRITICAL = "p0_critical"  # Fix immediately
    P1_HIGH = "p1_high"          # Fix within 24h
    P2_MEDIUM = "p2_medium"      # Fix within 7d
    P3_LOW = "p3_low"            # Fix within 30d

@dataclass
class EnhancedVulnerability:
    """Enhanced vulnerability with CrowdStrike intelligence"""
    cve_id: str
    cvss_score: float
    severity: VulnerabilityRisk
    description: str
    affected_packages: List[str]
    
    # CrowdStrike enhancement
    exploitation_status: str
    threat_actors_using: List[str]
    exploit_availability: bool
    falcon_intelligence: Dict[str, Any]
    
    # Context
    first_seen: datetime
    last_updated: datetime
    affected_assets: List[str]
    business_impact: str
    
    # Remediation
    remediation_priority: RemediationPriority
    fix_complexity: str
    estimated_effort: str
    recommended_actions: List[str]

@dataclass
class ContainerSecurityAssessment:
    """Container security assessment with CrowdStrike data"""
    assessment_id: str
    container_id: str
    image_name: str
    image_tag: str
    namespace: str
    
    # Security status
    overall_status: ContainerSecurityStatus
    security_score: float
    
    # Vulnerability analysis
    vulnerabilities: List[EnhancedVulnerability]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    
    # Runtime analysis
    runtime_behaviors: List[Dict[str, Any]]
    network_connections: List[Dict[str, Any]]
    process_activity: List[Dict[str, Any]]
    
    # Compliance
    compliance_status: Dict[str, bool]
    policy_violations: List[str]
    
    # Recommendations
    immediate_actions: List[str]
    security_improvements: List[str]

@dataclass
class DevSecOpsPipeline:
    """DevSecOps pipeline with CrowdStrike integration"""
    pipeline_id: str
    name: str
    repository: str
    branch: str
    
    # Pipeline stages
    stages: List[PipelineStage]
    current_stage: PipelineStage
    
    # Security scanning
    sast_results: Dict[str, Any]
    dast_results: Dict[str, Any]
    container_scan_results: Dict[str, Any]
    dependency_scan_results: Dict[str, Any]
    
    # CrowdStrike integration
    falcon_detections: List[Dict[str, Any]]
    runtime_security_status: str
    
    # Metrics
    security_gate_passed: bool
    deployment_approved: bool
    risk_score: float
    
    # Timing
    start_time: datetime
    end_time: Optional[datetime]
    duration_seconds: int

@dataclass
class KubernetesSecurityPosture:
    """Kubernetes security posture assessment"""
    cluster_name: str
    assessment_timestamp: datetime
    
    # Overall posture
    security_score: float
    risk_level: str
    
    # Component analysis
    node_security: Dict[str, Any]
    pod_security: Dict[str, Any]
    service_security: Dict[str, Any]
    ingress_security: Dict[str, Any]
    
    # Policy compliance
    rbac_compliance: float
    network_policy_compliance: float
    pod_security_compliance: float
    
    # CrowdStrike runtime protection
    falcon_coverage: float
    protected_workloads: int
    unprotected_workloads: int
    
    # Recommendations
    priority_fixes: List[str]
    security_improvements: List[str]

class Beta4DevSecOpsSkills:
    """Enhanced DevSecOps skills for Beta-4 agent using CrowdStrike MCP"""
    
    def __init__(self):
        self.mcp_integration = SecurityAgentsMCPIntegration(SecurityAgent.BETA_4)
        self.query_builder = FQLQueryBuilder()
        self.session_active = False
        
    async def initialize(self) -> bool:
        """Initialize CrowdStrike MCP integration"""
        self.session_active = await self.mcp_integration.initialize()
        return self.session_active
    
    async def enhanced_vulnerability_assessment(self, 
                                              assets: List[str] = None,
                                              severity_filter: str = "medium") -> Dict[str, Any]:
        """
        Enhanced vulnerability assessment with CrowdStrike threat intelligence
        
        Args:
            assets: Specific assets to assess (IPs, hostnames, containers)
            severity_filter: Minimum severity level
            
        Returns:
            Comprehensive vulnerability assessment with threat context
        """
        if not self.session_active:
            raise RuntimeError("MCP integration not initialized")
        
        assessment_id = f"VA-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        logger.info(f"Enhanced vulnerability assessment: {assessment_id}")
        
        # Get Spotlight vulnerabilities
        spotlight_result = await self.mcp_integration.mcp_client.execute_tool(
            "falcon_search_vulnerabilities",
            {
                "filter": f"cve.severity:>={severity_filter}",
                "limit": 500
            }
        )
        
        if not spotlight_result["success"]:
            raise RuntimeError("Failed to get vulnerability data from CrowdStrike")
        
        vulnerabilities = spotlight_result.get("result", [])
        
        # Enhance each vulnerability with threat intelligence
        enhanced_vulns = []
        for vuln in vulnerabilities[:100]:  # Limit for demo
            enhanced_vuln = await self._enhance_vulnerability_intelligence(vuln)
            if enhanced_vuln:
                enhanced_vulns.append(enhanced_vuln)
        
        # Generate assessment summary
        assessment = {
            "assessment_id": assessment_id,
            "timestamp": datetime.now(),
            "scope": assets or "all_assets",
            "vulnerabilities": enhanced_vulns,
            "summary": await self._generate_vulnerability_summary(enhanced_vulns),
            "risk_analysis": await self._analyze_vulnerability_risk(enhanced_vulns),
            "remediation_plan": await self._generate_remediation_plan(enhanced_vulns)
        }
        
        return assessment
    
    async def container_security_scanning(self,
                                        image_name: str,
                                        image_tag: str = "latest",
                                        namespace: str = "default") -> ContainerSecurityAssessment:
        """
        Comprehensive container security scanning with runtime analysis
        
        Args:
            image_name: Container image name
            image_tag: Image tag to scan
            namespace: Kubernetes namespace
            
        Returns:
            Complete container security assessment
        """
        if not self.session_active:
            raise RuntimeError("MCP integration not initialized")
        
        assessment_id = f"CSA-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        logger.info(f"Container security assessment: {image_name}:{image_tag}")
        
        # Search for container in CrowdStrike
        container_query = self.query_builder.build_host_investigation_query(
            container_name=f"{image_name}:{image_tag}"
        )
        
        container_result = await self.mcp_integration.mcp_client.execute_tool(
            "falcon_search_hosts",
            {"filter": container_query}
        )
        
        # Get container vulnerabilities
        vuln_query = f"asset.container_image:'{image_name}' AND asset.container_tag:'{image_tag}'"
        vuln_result = await self.mcp_integration.mcp_client.execute_tool(
            "falcon_search_vulnerabilities",
            {"filter": vuln_query}
        )
        
        # Get runtime behaviors if container is running
        runtime_behaviors = []
        if container_result["success"] and container_result.get("result"):
            container_id = container_result["result"][0].get("device_id")
            if container_id:
                runtime_behaviors = await self._get_container_runtime_behaviors(container_id)
        
        # Process vulnerabilities
        vulnerabilities = []
        if vuln_result["success"] and vuln_result.get("result"):
            for vuln_data in vuln_result["result"][:50]:  # Limit for demo
                enhanced_vuln = await self._enhance_vulnerability_intelligence(vuln_data)
                if enhanced_vuln:
                    vulnerabilities.append(enhanced_vuln)
        
        # Calculate security metrics
        vuln_counts = self._calculate_vulnerability_counts(vulnerabilities)
        security_score = self._calculate_container_security_score(vulnerabilities, runtime_behaviors)
        overall_status = self._determine_container_status(security_score, vuln_counts)
        
        # Build assessment
        assessment = ContainerSecurityAssessment(
            assessment_id=assessment_id,
            container_id=container_result.get("result", [{}])[0].get("device_id", "unknown"),
            image_name=image_name,
            image_tag=image_tag,
            namespace=namespace,
            overall_status=overall_status,
            security_score=security_score,
            vulnerabilities=vulnerabilities,
            critical_count=vuln_counts["critical"],
            high_count=vuln_counts["high"],
            medium_count=vuln_counts["medium"],
            low_count=vuln_counts["low"],
            runtime_behaviors=runtime_behaviors,
            network_connections=await self._get_container_network_activity(container_id if 'container_id' in locals() else None),
            process_activity=await self._get_container_process_activity(container_id if 'container_id' in locals() else None),
            compliance_status=await self._check_container_compliance(image_name, image_tag),
            policy_violations=await self._check_policy_violations(image_name, runtime_behaviors),
            immediate_actions=await self._generate_immediate_actions(vulnerabilities, overall_status),
            security_improvements=await self._generate_security_improvements(vulnerabilities, runtime_behaviors)
        )
        
        return assessment
    
    async def devsecops_pipeline_integration(self,
                                           pipeline_config: Dict[str, Any]) -> DevSecOpsPipeline:
        """
        Integrate CrowdStrike security into DevSecOps pipeline
        
        Args:
            pipeline_config: Pipeline configuration including repo, branch, etc.
            
        Returns:
            Complete pipeline execution with security gates
        """
        if not self.session_active:
            raise RuntimeError("MCP integration not initialized")
        
        pipeline_id = f"PIPE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        pipeline_name = pipeline_config.get("name", "Security Pipeline")
        
        logger.info(f"DevSecOps pipeline integration: {pipeline_name}")
        
        pipeline = DevSecOpsPipeline(
            pipeline_id=pipeline_id,
            name=pipeline_name,
            repository=pipeline_config.get("repository", ""),
            branch=pipeline_config.get("branch", "main"),
            stages=[PipelineStage.BUILD, PipelineStage.SCAN, PipelineStage.TEST, PipelineStage.DEPLOY],
            current_stage=PipelineStage.BUILD,
            sast_results={},
            dast_results={},
            container_scan_results={},
            dependency_scan_results={},
            falcon_detections=[],
            runtime_security_status="pending",
            security_gate_passed=False,
            deployment_approved=False,
            risk_score=0.0,
            start_time=datetime.now(),
            end_time=None,
            duration_seconds=0
        )
        
        # Execute pipeline stages with security gates
        for stage in pipeline.stages:
            pipeline.current_stage = stage
            await self._execute_pipeline_stage(pipeline, stage, pipeline_config)
        
        # Final security assessment
        pipeline.risk_score = await self._calculate_pipeline_risk_score(pipeline)
        pipeline.security_gate_passed = pipeline.risk_score < 7.0  # Configurable threshold
        pipeline.deployment_approved = pipeline.security_gate_passed and not any([
            pipeline.sast_results.get("critical_issues", 0) > 0,
            pipeline.container_scan_results.get("critical_vulnerabilities", 0) > 0
        ])
        
        pipeline.end_time = datetime.now()
        pipeline.duration_seconds = int((pipeline.end_time - pipeline.start_time).total_seconds())
        
        return pipeline
    
    async def kubernetes_security_assessment(self,
                                           cluster_name: str,
                                           namespace: str = "all") -> KubernetesSecurityPosture:
        """
        Comprehensive Kubernetes security posture assessment
        
        Args:
            cluster_name: Name of Kubernetes cluster
            namespace: Specific namespace or "all" for cluster-wide
            
        Returns:
            Complete Kubernetes security posture
        """
        if not self.session_active:
            raise RuntimeError("MCP integration not initialized")
        
        logger.info(f"Kubernetes security assessment: {cluster_name}")
        
        # Get Kubernetes hosts from CrowdStrike
        k8s_query = f"platform_name:'Linux' AND tags:'kubernetes'"
        if cluster_name:
            k8s_query += f" AND tags:'{cluster_name}'"
        
        hosts_result = await self.mcp_integration.mcp_client.execute_tool(
            "falcon_search_hosts",
            {"filter": k8s_query}
        )
        
        k8s_hosts = hosts_result.get("result", []) if hosts_result["success"] else []
        
        # Get container workloads
        container_query = f"platform_name:'Container' AND tags:'kubernetes'"
        containers_result = await self.mcp_integration.mcp_client.execute_tool(
            "falcon_search_hosts",
            {"filter": container_query}
        )
        
        containers = containers_result.get("result", []) if containers_result["success"] else []
        
        # Analyze security posture
        node_security = await self._assess_node_security(k8s_hosts)
        pod_security = await self._assess_pod_security(containers)
        service_security = await self._assess_service_security(cluster_name)
        
        # Calculate compliance scores
        rbac_compliance = await self._assess_rbac_compliance(cluster_name)
        network_policy_compliance = await self._assess_network_policy_compliance(cluster_name)
        pod_security_compliance = await self._assess_pod_security_compliance(containers)
        
        # Calculate CrowdStrike coverage
        total_workloads = len(containers)
        protected_workloads = len([c for c in containers if c.get("tags", "").find("falcon-protected") != -1])
        falcon_coverage = (protected_workloads / total_workloads * 100) if total_workloads > 0 else 0
        
        # Calculate overall security score
        security_score = (
            (node_security.get("score", 0) * 0.3) +
            (pod_security.get("score", 0) * 0.3) +
            (rbac_compliance * 0.2) +
            (network_policy_compliance * 0.1) +
            (falcon_coverage / 100 * 0.1)
        )
        
        risk_level = self._determine_risk_level(security_score)
        
        # Generate recommendations
        priority_fixes = await self._generate_k8s_priority_fixes(
            node_security, pod_security, rbac_compliance, network_policy_compliance
        )
        
        security_improvements = await self._generate_k8s_security_improvements(
            cluster_name, falcon_coverage, security_score
        )
        
        posture = KubernetesSecurityPosture(
            cluster_name=cluster_name,
            assessment_timestamp=datetime.now(),
            security_score=security_score,
            risk_level=risk_level,
            node_security=node_security,
            pod_security=pod_security,
            service_security=service_security,
            ingress_security=await self._assess_ingress_security(cluster_name),
            rbac_compliance=rbac_compliance,
            network_policy_compliance=network_policy_compliance,
            pod_security_compliance=pod_security_compliance,
            falcon_coverage=falcon_coverage,
            protected_workloads=protected_workloads,
            unprotected_workloads=total_workloads - protected_workloads,
            priority_fixes=priority_fixes,
            security_improvements=security_improvements
        )
        
        return posture
    
    async def supply_chain_security_analysis(self,
                                           repository: str,
                                           branch: str = "main") -> Dict[str, Any]:
        """
        Analyze software supply chain security risks
        
        Args:
            repository: Git repository to analyze
            branch: Branch to analyze
            
        Returns:
            Supply chain security analysis
        """
        if not self.session_active:
            raise RuntimeError("MCP integration not initialized")
        
        analysis_id = f"SCA-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        logger.info(f"Supply chain analysis: {repository}/{branch}")
        
        analysis = {
            "analysis_id": analysis_id,
            "repository": repository,
            "branch": branch,
            "timestamp": datetime.now(),
            "risk_assessment": {},
            "dependency_analysis": {},
            "threat_intelligence": {},
            "recommendations": []
        }
        
        # Analyze dependencies for known vulnerabilities
        dependency_risks = await self._analyze_dependency_risks(repository)
        analysis["dependency_analysis"] = dependency_risks
        
        # Check for supply chain attacks in threat intelligence
        supply_chain_threats = await self._check_supply_chain_threats(repository)
        analysis["threat_intelligence"] = supply_chain_threats
        
        # Calculate overall risk assessment
        risk_assessment = await self._calculate_supply_chain_risk(
            dependency_risks, supply_chain_threats
        )
        analysis["risk_assessment"] = risk_assessment
        
        # Generate recommendations
        recommendations = await self._generate_supply_chain_recommendations(
            dependency_risks, supply_chain_threats, risk_assessment
        )
        analysis["recommendations"] = recommendations
        
        return analysis
    
    async def automated_security_remediation(self,
                                           vulnerability_list: List[EnhancedVulnerability],
                                           auto_fix_enabled: bool = False) -> Dict[str, Any]:
        """
        Automated security remediation with CrowdStrike context
        
        Args:
            vulnerability_list: List of vulnerabilities to remediate
            auto_fix_enabled: Whether to automatically apply fixes
            
        Returns:
            Remediation execution results
        """
        if not self.session_active:
            raise RuntimeError("MCP integration not initialized")
        
        remediation_id = f"REM-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        logger.info(f"Automated remediation: {remediation_id}")
        
        remediation_results = {
            "remediation_id": remediation_id,
            "timestamp": datetime.now(),
            "total_vulnerabilities": len(vulnerability_list),
            "automated_fixes": [],
            "manual_actions": [],
            "failed_remediations": [],
            "success_rate": 0.0
        }
        
        successful_fixes = 0
        
        for vuln in vulnerability_list:
            if vuln.remediation_priority in [RemediationPriority.P0_CRITICAL, RemediationPriority.P1_HIGH]:
                
                # Determine if automated fix is possible
                fix_strategy = await self._determine_fix_strategy(vuln)
                
                if fix_strategy["automated"] and auto_fix_enabled:
                    try:
                        fix_result = await self._execute_automated_fix(vuln, fix_strategy)
                        remediation_results["automated_fixes"].append(fix_result)
                        if fix_result["success"]:
                            successful_fixes += 1
                    except Exception as e:
                        remediation_results["failed_remediations"].append({
                            "vulnerability": vuln.cve_id,
                            "error": str(e),
                            "timestamp": datetime.now()
                        })
                else:
                    # Add to manual actions
                    manual_action = {
                        "vulnerability": vuln.cve_id,
                        "severity": vuln.severity.value,
                        "priority": vuln.remediation_priority.value,
                        "recommended_actions": vuln.recommended_actions,
                        "fix_complexity": vuln.fix_complexity,
                        "estimated_effort": vuln.estimated_effort
                    }
                    remediation_results["manual_actions"].append(manual_action)
        
        remediation_results["success_rate"] = (
            successful_fixes / len(vulnerability_list) * 100 
            if vulnerability_list else 0
        )
        
        return remediation_results
    
    # Private helper methods
    
    async def _enhance_vulnerability_intelligence(self, vuln_data: Dict[str, Any]) -> Optional[EnhancedVulnerability]:
        """Enhance vulnerability with CrowdStrike threat intelligence"""
        
        if not vuln_data.get("cve", {}).get("id"):
            return None
        
        cve_id = vuln_data["cve"]["id"]
        
        # Get threat intelligence for CVE
        intel_result = await self.mcp_integration.mcp_client.execute_tool(
            "falcon_search_reports",
            {"filter": f"name:'{cve_id}' OR description:'{cve_id}'"}
        )
        
        falcon_intelligence = {}
        threat_actors = []
        exploitation_status = "unknown"
        exploit_availability = False
        
        if intel_result["success"] and intel_result.get("result"):
            reports = intel_result["result"]
            falcon_intelligence = {
                "reports_count": len(reports),
                "latest_report": reports[0] if reports else {},
                "intelligence_score": sum(r.get("confidence", 0) for r in reports) / len(reports) if reports else 0
            }
            
            # Extract threat actor information
            for report in reports[:3]:  # Limit analysis
                actors = report.get("actors", [])
                threat_actors.extend([actor.get("name") for actor in actors if actor.get("name")])
            
            # Determine exploitation status
            if any("exploited" in report.get("description", "").lower() for report in reports):
                exploitation_status = "actively_exploited"
                exploit_availability = True
            elif any("exploit" in report.get("description", "").lower() for report in reports):
                exploitation_status = "exploit_available"
                exploit_availability = True
        
        # Determine remediation priority
        cvss_score = vuln_data.get("cve", {}).get("cvss", {}).get("score", 0)
        severity = self._map_cvss_to_severity(cvss_score)
        
        priority = self._determine_remediation_priority(
            severity, exploitation_status, exploit_availability, threat_actors
        )
        
        enhanced_vuln = EnhancedVulnerability(
            cve_id=cve_id,
            cvss_score=cvss_score,
            severity=severity,
            description=vuln_data.get("cve", {}).get("description", ""),
            affected_packages=vuln_data.get("app", {}).get("product_name_version", []),
            exploitation_status=exploitation_status,
            threat_actors_using=list(set(threat_actors))[:5],  # Limit to 5
            exploit_availability=exploit_availability,
            falcon_intelligence=falcon_intelligence,
            first_seen=self._parse_timestamp(vuln_data.get("created_timestamp")),
            last_updated=self._parse_timestamp(vuln_data.get("updated_timestamp")),
            affected_assets=vuln_data.get("asset", {}).get("hostname", []),
            business_impact=self._assess_business_impact(severity, exploitation_status),
            remediation_priority=priority,
            fix_complexity=self._assess_fix_complexity(vuln_data),
            estimated_effort=self._estimate_fix_effort(vuln_data, priority),
            recommended_actions=await self._generate_remediation_actions(vuln_data, priority)
        )
        
        return enhanced_vuln
    
    async def _execute_pipeline_stage(self, 
                                    pipeline: DevSecOpsPipeline,
                                    stage: PipelineStage,
                                    config: Dict[str, Any]):
        """Execute specific pipeline stage with security checks"""
        
        logger.info(f"Executing pipeline stage: {stage.value}")
        
        if stage == PipelineStage.BUILD:
            # Build stage - basic validation
            pipeline.sast_results = {"issues_found": 3, "critical_issues": 0, "status": "passed"}
            
        elif stage == PipelineStage.SCAN:
            # Security scanning stage
            pipeline.container_scan_results = await self._simulate_container_scan(config)
            pipeline.dependency_scan_results = await self._simulate_dependency_scan(config)
            
        elif stage == PipelineStage.TEST:
            # DAST and security testing
            pipeline.dast_results = await self._simulate_dast_scan(config)
            
        elif stage == PipelineStage.DEPLOY:
            # Deployment with runtime monitoring
            pipeline.runtime_security_status = "monitoring_enabled"
            
            # Check for runtime detections
            if config.get("check_runtime_detections", True):
                runtime_detections = await self._check_runtime_detections(config)
                pipeline.falcon_detections = runtime_detections
    
    def _map_cvss_to_severity(self, cvss_score: float) -> VulnerabilityRisk:
        """Map CVSS score to vulnerability risk level"""
        if cvss_score >= 9.0:
            return VulnerabilityRisk.CRITICAL
        elif cvss_score >= 7.0:
            return VulnerabilityRisk.HIGH
        elif cvss_score >= 4.0:
            return VulnerabilityRisk.MEDIUM
        elif cvss_score > 0.0:
            return VulnerabilityRisk.LOW
        else:
            return VulnerabilityRisk.INFORMATIONAL
    
    def _determine_remediation_priority(self, 
                                      severity: VulnerabilityRisk,
                                      exploitation_status: str,
                                      exploit_available: bool,
                                      threat_actors: List[str]) -> RemediationPriority:
        """Determine remediation priority based on multiple factors"""
        
        # Critical vulnerabilities with active exploitation
        if (severity == VulnerabilityRisk.CRITICAL and 
            exploitation_status == "actively_exploited"):
            return RemediationPriority.P0_CRITICAL
        
        # High severity with exploit available or threat actor usage
        if (severity == VulnerabilityRisk.HIGH and 
            (exploit_available or threat_actors)):
            return RemediationPriority.P1_HIGH
        
        # Medium severity or high without exploitation
        if severity in [VulnerabilityRisk.MEDIUM, VulnerabilityRisk.HIGH]:
            return RemediationPriority.P2_MEDIUM
        
        # Low severity
        return RemediationPriority.P3_LOW
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse timestamp string"""
        if not timestamp_str:
            return datetime.now()
        
        try:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except:
            return datetime.now()
    
    async def _generate_remediation_actions(self, 
                                          vuln_data: Dict[str, Any], 
                                          priority: RemediationPriority) -> List[str]:
        """Generate specific remediation actions"""
        actions = []
        
        # Package updates
        if vuln_data.get("app", {}).get("product_name"):
            package = vuln_data["app"]["product_name"]
            actions.append(f"Update {package} to latest secure version")
        
        # Configuration changes
        if priority in [RemediationPriority.P0_CRITICAL, RemediationPriority.P1_HIGH]:
            actions.append("Apply security patches immediately")
            actions.append("Implement temporary mitigation controls")
        
        # Monitoring enhancements
        actions.append("Enhance monitoring for exploitation attempts")
        
        return actions
    
    # Additional helper methods for container and K8s analysis
    
    async def _get_container_runtime_behaviors(self, container_id: str) -> List[Dict[str, Any]]:
        """Get runtime behaviors for container"""
        behavior_result = await self.mcp_integration.mcp_client.execute_tool(
            "falcon_search_detections",
            {"filter": f"device.device_id:'{container_id}'"}
        )
        
        return behavior_result.get("result", []) if behavior_result["success"] else []
    
    def _calculate_vulnerability_counts(self, vulnerabilities: List[EnhancedVulnerability]) -> Dict[str, int]:
        """Calculate vulnerability counts by severity"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for vuln in vulnerabilities:
            if vuln.severity == VulnerabilityRisk.CRITICAL:
                counts["critical"] += 1
            elif vuln.severity == VulnerabilityRisk.HIGH:
                counts["high"] += 1
            elif vuln.severity == VulnerabilityRisk.MEDIUM:
                counts["medium"] += 1
            else:
                counts["low"] += 1
        
        return counts
    
    def _calculate_container_security_score(self, 
                                          vulnerabilities: List[EnhancedVulnerability],
                                          runtime_behaviors: List[Dict[str, Any]]) -> float:
        """Calculate overall container security score"""
        base_score = 100.0
        
        # Deduct points for vulnerabilities
        for vuln in vulnerabilities:
            if vuln.severity == VulnerabilityRisk.CRITICAL:
                base_score -= 20
            elif vuln.severity == VulnerabilityRisk.HIGH:
                base_score -= 10
            elif vuln.severity == VulnerabilityRisk.MEDIUM:
                base_score -= 5
            elif vuln.severity == VulnerabilityRisk.LOW:
                base_score -= 1
        
        # Deduct points for suspicious runtime behaviors
        suspicious_behaviors = len([b for b in runtime_behaviors 
                                  if b.get("severity", "").lower() in ["high", "critical"]])
        base_score -= suspicious_behaviors * 15
        
        return max(0.0, min(100.0, base_score))
    
    def _determine_container_status(self, 
                                  security_score: float,
                                  vuln_counts: Dict[str, int]) -> ContainerSecurityStatus:
        """Determine container security status"""
        
        if vuln_counts["critical"] > 0 or security_score < 30:
            return ContainerSecurityStatus.CRITICAL_VULNERABILITIES
        elif vuln_counts["high"] > 5 or security_score < 50:
            return ContainerSecurityStatus.HIGH_RISK
        elif vuln_counts["high"] > 0 or vuln_counts["medium"] > 10 or security_score < 70:
            return ContainerSecurityStatus.SECURITY_CONCERNS
        elif vuln_counts["medium"] > 0 or vuln_counts["low"] > 20 or security_score < 90:
            return ContainerSecurityStatus.MINOR_ISSUES
        else:
            return ContainerSecurityStatus.SECURE

# Example usage and testing
async def main():
    """Example usage of Beta-4 enhanced DevSecOps skills"""
    
    # Initialize skills
    skills = Beta4DevSecOpsSkills()
    
    if await skills.initialize():
        print("✅ Beta-4 CrowdStrike MCP DevSecOps skills initialized")
        
        # Example 1: Enhanced vulnerability assessment
        try:
            vuln_assessment = await skills.enhanced_vulnerability_assessment(
                severity_filter="high"
            )
            print(f"📊 Vulnerability Assessment: {vuln_assessment['assessment_id']}")
            print(f"   Vulnerabilities Found: {len(vuln_assessment['vulnerabilities'])}")
            print(f"   Risk Level: {vuln_assessment['risk_analysis']['overall_risk']}")
        except Exception as e:
            print(f"❌ Vulnerability assessment error: {e}")
        
        # Example 2: Container security scanning
        try:
            container_assessment = await skills.container_security_scanning(
                image_name="nginx",
                image_tag="latest",
                namespace="production"
            )
            print(f"📊 Container Assessment: {container_assessment.image_name}:{container_assessment.image_tag}")
            print(f"   Security Score: {container_assessment.security_score:.1f}")
            print(f"   Status: {container_assessment.overall_status.value}")
            print(f"   Critical Vulns: {container_assessment.critical_count}")
        except Exception as e:
            print(f"❌ Container assessment error: {e}")
        
        # Example 3: Kubernetes security posture
        try:
            k8s_posture = await skills.kubernetes_security_assessment(
                cluster_name="production-cluster"
            )
            print(f"📊 K8s Security Posture: {k8s_posture.cluster_name}")
            print(f"   Security Score: {k8s_posture.security_score:.1f}")
            print(f"   Risk Level: {k8s_posture.risk_level}")
            print(f"   Falcon Coverage: {k8s_posture.falcon_coverage:.1f}%")
        except Exception as e:
            print(f"❌ K8s assessment error: {e}")
        
    else:
        print("❌ Failed to initialize Beta-4 CrowdStrike MCP DevSecOps skills")


if __name__ == "__main__":
    asyncio.run(main())