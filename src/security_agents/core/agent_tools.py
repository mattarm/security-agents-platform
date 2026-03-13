#!/usr/bin/env python3
"""
LangGraph Tool Wrappers — @tool-decorated functions wrapping legacy agent engines.

Each agent adapter's process_task() branches become tool functions that Claude
can invoke within a LangGraph ReAct loop. The legacy engine methods are called
internally — engine files in agents/engines/ are NOT modified.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from langchain_core.tools import tool

logger = logging.getLogger(__name__)

# =============================================================================
# Path sanitization for Beta-4 scan tools
# =============================================================================

ALLOWED_SCAN_ROOTS = ["/app", "/src", "/tmp", os.getcwd()]


def _validate_scan_path(target_path: str) -> Optional[str]:
    """Validate that a scan target path is within allowed roots.

    Returns None if valid, or an error message string if invalid.
    """
    resolved = Path(target_path).resolve()
    for root in ALLOWED_SCAN_ROOTS:
        root_resolved = Path(root).resolve()
        try:
            resolved.relative_to(root_resolved)
            return None
        except ValueError:
            continue
    return (
        f"Path '{resolved}' is outside allowed scan roots: {ALLOWED_SCAN_ROOTS}. "
        "Scan rejected for security reasons."
    )


# =============================================================================
# Lazy engine singletons — instantiated on first tool call
# =============================================================================

_engines: Dict[str, Any] = {}


def _get_alpha4_engine():
    try:
        if "alpha4" not in _engines:
            from security_agents.agents.engines.tiger_team_alpha_4 import AdvancedThreatIntelligence
            _engines["alpha4"] = AdvancedThreatIntelligence()
        return _engines["alpha4"]
    except Exception as e:
        logger.error("Failed to initialize Alpha-4 engine: %s", e, exc_info=True)
        return None


def _get_beta4_engine(workspace_path: str = "."):
    try:
        if "beta4" not in _engines:
            from security_agents.agents.engines.tiger_team_beta_4 import AdvancedDevSecOpsEngine
            _engines["beta4"] = AdvancedDevSecOpsEngine(workspace_path=workspace_path)
        return _engines["beta4"]
    except Exception as e:
        logger.error("Failed to initialize Beta-4 engine: %s", e, exc_info=True)
        return None


def _get_gamma_engine(config_path: str = "config/gamma_config.yaml"):
    try:
        if "gamma" not in _engines:
            from security_agents.agents.engines.gamma_blue_team_agent import GammaBlueTeamAgent
            _engines["gamma"] = GammaBlueTeamAgent(config_path=config_path)
        return _engines["gamma"]
    except Exception as e:
        logger.error("Failed to initialize Gamma engine: %s", e, exc_info=True)
        return None


def _get_delta_engine(config_path: str = "config/delta_config.yaml"):
    try:
        if "delta" not in _engines:
            from security_agents.agents.engines.delta_red_team_agent import DeltaRedTeamAgent
            _engines["delta"] = DeltaRedTeamAgent(config_path=config_path)
        return _engines["delta"]
    except Exception as e:
        logger.error("Failed to initialize Delta engine: %s", e, exc_info=True)
        return None


def _get_sigma_engine():
    try:
        if "sigma" not in _engines:
            from security_agents.agents.engines.sigma_metrics_agent import SigmaMetricsAgent
            _engines["sigma"] = SigmaMetricsAgent()
        return _engines["sigma"]
    except Exception as e:
        logger.error("Failed to initialize Sigma engine: %s", e, exc_info=True)
        return None


def _get_zeta_engine():
    try:
        if "zeta" not in _engines:
            from security_agents.agents.engines.zeta_grc_engine import ZetaGRCEngine
            _engines["zeta"] = ZetaGRCEngine()
        return _engines["zeta"]
    except Exception as e:
        logger.error("Failed to initialize Zeta GRC engine: %s", e, exc_info=True)
        return None


def _get_phishing_skill():
    try:
        if "phishing_skill" not in _engines:
            from security_agents.skills.phishing_analysis import PhishingAnalysisSkill
            skill = PhishingAnalysisSkill(agent_id="gamma_blue_team")
            _engines["phishing_skill"] = skill
        return _engines["phishing_skill"]
    except Exception as e:
        logger.error("Failed to initialize PhishingAnalysisSkill: %s", e, exc_info=True)
        return None


def _error_dict(tool_name: str, error: Exception) -> Dict[str, Any]:
    """Return a structured error dict for tool failures."""
    return {"error": str(error), "tool": tool_name, "success": False}


# =============================================================================
# Alpha-4 Threat Intelligence Tools
# =============================================================================

@tool
async def analyze_campaign(iocs: List[str], context: str = "") -> Dict[str, Any]:
    """Analyze threat campaign from IOCs and context. Identifies threat actors,
    TTPs, campaign attribution, and risk scoring. Use when investigating
    suspicious indicators or tracking adversary infrastructure."""
    try:
        engine = _get_alpha4_engine()
        if engine is None:
            return _error_dict("analyze_campaign", RuntimeError("Alpha-4 engine unavailable"))
        campaign = await engine.analyze_threat_campaign(iocs, context)
        if campaign:
            return {
                "campaign_id": campaign.campaign_id,
                "name": campaign.name,
                "threat_actor": campaign.threat_actor,
                "confidence": campaign.confidence,
                "risk_score": campaign.risk_score,
                "ttps": campaign.ttps,
                "ioc_count": len(campaign.iocs),
                "target_industries": campaign.target_industries,
            }
        return {"campaign": None, "message": "No campaign identified from provided IOCs"}
    except Exception as e:
        logger.error("analyze_campaign failed: %s", e, exc_info=True)
        return _error_dict("analyze_campaign", e)


@tool
async def enrich_iocs(iocs: List[str]) -> Dict[str, Any]:
    """Enrich indicators of compromise with threat intelligence context.
    Clusters IOCs by campaign and returns enrichment data. Use for
    IOC triage and prioritization."""
    try:
        engine = _get_alpha4_engine()
        if engine is None:
            return _error_dict("enrich_iocs", RuntimeError("Alpha-4 engine unavailable"))
        results = []
        for ioc in iocs:
            cluster = await engine.cluster_iocs_by_campaign([ioc])
            results.append({"ioc": ioc, "clusters": len(cluster) if cluster else 0})
        return {"enrichment_results": results, "total_iocs": len(iocs)}
    except Exception as e:
        logger.error("enrich_iocs failed: %s", e, exc_info=True)
        return _error_dict("enrich_iocs", e)


@tool
async def alpha4_hunt_threats(iocs: List[str], context: str = "") -> Dict[str, Any]:
    """Hunt for threats using IOCs and contextual information. Searches for
    campaign connections and threat actor activity. Use for proactive
    threat hunting based on known indicators."""
    try:
        engine = _get_alpha4_engine()
        if engine is None:
            return _error_dict("alpha4_hunt_threats", RuntimeError("Alpha-4 engine unavailable"))
        campaign = await engine.analyze_threat_campaign(iocs, context)
        return {
            "campaign_found": campaign is not None,
            "campaign_name": campaign.name if campaign else None,
            "risk_score": campaign.risk_score if campaign else 0.0,
        }
    except Exception as e:
        logger.error("alpha4_hunt_threats failed: %s", e, exc_info=True)
        return _error_dict("alpha4_hunt_threats", e)


# =============================================================================
# Beta-4 DevSecOps Tools
# =============================================================================

@tool
async def comprehensive_scan(target_path: str = ".", include_architecture: bool = True,
                              include_supply_chain: bool = True) -> Dict[str, Any]:
    """Run comprehensive security analysis including SAST, container scanning,
    IaC analysis, and optionally architecture review and supply chain assessment.
    Use for full security posture evaluation of a codebase."""
    try:
        path_error = _validate_scan_path(target_path)
        if path_error:
            return {"error": path_error, "tool": "comprehensive_scan", "success": False}
        engine = _get_beta4_engine()
        if engine is None:
            return _error_dict("comprehensive_scan", RuntimeError("Beta-4 engine unavailable"))
        results = await engine.comprehensive_security_analysis(
            target_path=Path(target_path),
            include_architecture=include_architecture,
            include_supply_chain=include_supply_chain,
        )
        return results
    except Exception as e:
        logger.error("comprehensive_scan failed: %s", e, exc_info=True)
        return _error_dict("comprehensive_scan", e)


@tool
async def sast_scan(target_path: str = ".") -> Dict[str, Any]:
    """Perform static application security testing (SAST) on source code.
    Identifies vulnerabilities like SQL injection, XSS, command injection,
    insecure deserialization, and other code-level security issues."""
    try:
        path_error = _validate_scan_path(target_path)
        if path_error:
            return {"error": path_error, "tool": "sast_scan", "success": False}
        engine = _get_beta4_engine()
        if engine is None:
            return _error_dict("sast_scan", RuntimeError("Beta-4 engine unavailable"))
        from dataclasses import asdict
        vulns = await engine.perform_advanced_sast(Path(target_path))
        return {"vulnerabilities": [asdict(v) for v in vulns], "count": len(vulns)}
    except Exception as e:
        logger.error("sast_scan failed: %s", e, exc_info=True)
        return _error_dict("sast_scan", e)


@tool
async def container_scan(target_path: str = ".") -> Dict[str, Any]:
    """Scan container images and Dockerfiles for security issues.
    Checks for vulnerable base images, exposed secrets, privilege escalation
    risks, and container configuration problems."""
    try:
        path_error = _validate_scan_path(target_path)
        if path_error:
            return {"error": path_error, "tool": "container_scan", "success": False}
        engine = _get_beta4_engine()
        if engine is None:
            return _error_dict("container_scan", RuntimeError("Beta-4 engine unavailable"))
        from dataclasses import asdict
        vulns = await engine.analyze_container_security(Path(target_path))
        return {"vulnerabilities": [asdict(v) for v in vulns], "count": len(vulns)}
    except Exception as e:
        logger.error("container_scan failed: %s", e, exc_info=True)
        return _error_dict("container_scan", e)


@tool
async def supply_chain_scan(target_path: str = ".") -> Dict[str, Any]:
    """Analyze software supply chain for security risks. Checks dependencies
    for known vulnerabilities, license risks, maintenance status, and
    potential supply chain compromise indicators."""
    try:
        path_error = _validate_scan_path(target_path)
        if path_error:
            return {"error": path_error, "tool": "supply_chain_scan", "success": False}
        engine = _get_beta4_engine()
        if engine is None:
            return _error_dict("supply_chain_scan", RuntimeError("Beta-4 engine unavailable"))
        from dataclasses import asdict
        risks = await engine.analyze_dependencies(Path(target_path))
        return {"supply_chain_risks": [asdict(r) for r in risks], "count": len(risks)}
    except Exception as e:
        logger.error("supply_chain_scan failed: %s", e, exc_info=True)
        return _error_dict("supply_chain_scan", e)


@tool
async def iac_scan(target_path: str = ".") -> Dict[str, Any]:
    """Scan Infrastructure-as-Code files (Terraform, CloudFormation, Kubernetes)
    for security misconfigurations, overly permissive policies, and
    compliance violations."""
    try:
        path_error = _validate_scan_path(target_path)
        if path_error:
            return {"error": path_error, "tool": "iac_scan", "success": False}
        engine = _get_beta4_engine()
        if engine is None:
            return _error_dict("iac_scan", RuntimeError("Beta-4 engine unavailable"))
        from dataclasses import asdict
        vulns = await engine.analyze_infrastructure_as_code(Path(target_path))
        return {"vulnerabilities": [asdict(v) for v in vulns], "count": len(vulns)}
    except Exception as e:
        logger.error("iac_scan failed: %s", e, exc_info=True)
        return _error_dict("iac_scan", e)


# =============================================================================
# Gamma Blue Team Tools
# =============================================================================

@tool
async def process_alert(alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """Process a security alert through the full SOC workflow: parsing,
    automated triage, threat intel enrichment, case creation, and
    containment recommendation. Use for new alert investigation."""
    try:
        engine = _get_gamma_engine()
        if engine is None:
            return _error_dict("process_alert", RuntimeError("Gamma engine unavailable"))
        result = await engine.process_security_alert(alert_data)
        return result
    except Exception as e:
        logger.error("process_alert failed: %s", e, exc_info=True)
        return _error_dict("process_alert", e)


@tool
async def triage_alert(alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """Perform automated triage on a security alert. Returns severity
    classification, confidence score, and recommended response actions.
    Use for quick alert prioritization."""
    try:
        engine = _get_gamma_engine()
        if engine is None:
            return _error_dict("triage_alert", RuntimeError("Gamma engine unavailable"))
        alert = engine.parse_alert(alert_data)
        triage = await engine.automated_triage(alert)
        return {"triage_result": triage}
    except Exception as e:
        logger.error("triage_alert failed: %s", e, exc_info=True)
        return _error_dict("triage_alert", e)


@tool
async def gamma_hunt_threats(alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """Hunt for threats by enriching alert data with threat intelligence.
    Cross-references indicators with known campaigns and actor profiles.
    Use for proactive blue team threat hunting."""
    try:
        engine = _get_gamma_engine()
        if engine is None:
            return _error_dict("gamma_hunt_threats", RuntimeError("Gamma engine unavailable"))
        alert = engine.parse_alert(alert_data)
        enrichment = await engine.enrich_with_threat_intel(alert)
        return {"hunting_results": enrichment}
    except Exception as e:
        logger.error("gamma_hunt_threats failed: %s", e, exc_info=True)
        return _error_dict("gamma_hunt_threats", e)


@tool
async def analyze_phishing(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze a suspected phishing email. Checks SPF/DKIM/DMARC authentication,
    URL reputation, attachment risk, BEC patterns, and campaign correlation.
    Use for reported phishing email investigation."""
    try:
        skill = _get_phishing_skill()
        if skill is None:
            return _error_dict("analyze_phishing", RuntimeError("PhishingAnalysisSkill unavailable"))
        if not skill.initialized:
            await skill.initialize()
        # Determine action from email_data or default to analyze_email
        parameters = dict(email_data)
        parameters.setdefault("action", "analyze_email")
        result = await skill.execute(parameters)
        return {
            "success": result.success,
            "skill": result.skill_name,
            "data": result.data if hasattr(result, "data") else {},
            "errors": result.errors if hasattr(result, "errors") else [],
            "indicators": [ind.__dict__ if hasattr(ind, "__dict__") else ind
                           for ind in (result.indicators if hasattr(result, "indicators") else [])],
        }
    except Exception as e:
        logger.error("analyze_phishing failed: %s", e, exc_info=True)
        return _error_dict("analyze_phishing", e)


@tool
async def execute_containment(alert_data: Dict[str, Any],
                               triage_result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Execute containment actions for a security incident. May include
    network isolation, account lockout, process termination, or rule deployment.
    Use after triage confirms a true positive requiring response."""
    try:
        engine = _get_gamma_engine()
        if engine is None:
            return _error_dict("execute_containment", RuntimeError("Gamma engine unavailable"))
        alert = engine.parse_alert(alert_data)
        actions = await engine.execute_containment_actions(alert, triage_result or {})
        return {
            "containment_actions": [a.value if hasattr(a, "value") else str(a) for a in actions]
        }
    except Exception as e:
        logger.error("execute_containment failed: %s", e, exc_info=True)
        return _error_dict("execute_containment", e)


# =============================================================================
# Delta Red Team Tools
# =============================================================================

@tool
async def adversary_emulation(operation_config: Dict[str, Any]) -> Dict[str, Any]:
    """Start an adversary emulation operation using CALDERA-style simulation.
    Emulates real-world attack techniques to test defensive capabilities.
    Use for scheduled red team exercises or purple team validation."""
    try:
        engine = _get_delta_engine()
        if engine is None:
            return _error_dict("adversary_emulation", RuntimeError("Delta engine unavailable"))
        result = await engine.start_adversary_emulation(operation_config)
        return result
    except Exception as e:
        logger.error("adversary_emulation failed: %s", e, exc_info=True)
        return _error_dict("adversary_emulation", e)


@tool
async def attack_path_analysis(target_environment: str = "default") -> Dict[str, Any]:
    """Analyze attack paths in the target environment using BloodHound-style
    graph analysis. Identifies privilege escalation routes, lateral movement
    opportunities, and high-risk paths to critical assets."""
    try:
        engine = _get_delta_engine()
        if engine is None:
            return _error_dict("attack_path_analysis", RuntimeError("Delta engine unavailable"))
        paths = await engine.analyze_attack_paths(target_environment)
        return {
            "attack_paths": [
                {
                    "path_id": p.path_id,
                    "source": p.source_node,
                    "target": p.target_node,
                    "risk_score": p.risk_score,
                    "difficulty": p.difficulty,
                    "steps": len(p.steps),
                }
                for p in paths
            ],
            "total_paths": len(paths),
        }
    except Exception as e:
        logger.error("attack_path_analysis failed: %s", e, exc_info=True)
        return _error_dict("attack_path_analysis", e)


@tool
async def detection_validation(operation_config: Dict[str, Any]) -> Dict[str, Any]:
    """Validate detection capabilities by running controlled attack simulations.
    Tests whether SIEM rules, EDR detections, and alert pipelines correctly
    identify and alert on known attack techniques."""
    try:
        engine = _get_delta_engine()
        if engine is None:
            return _error_dict("detection_validation", RuntimeError("Delta engine unavailable"))
        operation_config.setdefault("name", "Detection Validation")
        operation_config.setdefault("target_environment", "staging")
        result = await engine.start_adversary_emulation(operation_config)
        return {"validation_results": result}
    except Exception as e:
        logger.error("detection_validation failed: %s", e, exc_info=True)
        return _error_dict("detection_validation", e)


@tool
async def operation_status(operation_id: str) -> Dict[str, Any]:
    """Check the current status of a running red team operation.
    Returns operation phase, progress, techniques executed, and findings."""
    try:
        engine = _get_delta_engine()
        if engine is None:
            return _error_dict("operation_status", RuntimeError("Delta engine unavailable"))
        status = await engine.get_operation_status(operation_id)
        return status
    except Exception as e:
        logger.error("operation_status failed: %s", e, exc_info=True)
        return _error_dict("operation_status", e)


@tool
async def terminate_operation(operation_id: str) -> Dict[str, Any]:
    """Terminate a running red team operation. Initiates safe shutdown,
    reverts changes where possible, and generates partial results report."""
    try:
        engine = _get_delta_engine()
        if engine is None:
            return _error_dict("terminate_operation", RuntimeError("Delta engine unavailable"))
        result = await engine.terminate_operation(operation_id)
        return result
    except Exception as e:
        logger.error("terminate_operation failed: %s", e, exc_info=True)
        return _error_dict("terminate_operation", e)


# =============================================================================
# Sigma Metrics Tools
# =============================================================================

@tool
async def executive_dashboard() -> Dict[str, Any]:
    """Generate executive security dashboard with KPIs, achievement rates,
    and areas needing attention. Use for leadership briefings and
    security program health monitoring."""
    try:
        engine = _get_sigma_engine()
        if engine is None:
            return _error_dict("executive_dashboard", RuntimeError("Sigma engine unavailable"))
        dashboard = await engine.generate_executive_dashboard()
        return dashboard
    except Exception as e:
        logger.error("executive_dashboard failed: %s", e, exc_info=True)
        return _error_dict("executive_dashboard", e)


@tool
async def strategic_report() -> Dict[str, Any]:
    """Generate strategic security report. Includes trend analysis, risk posture
    changes, and program maturity assessment. Use for monthly/quarterly
    leadership reviews."""
    try:
        engine = _get_sigma_engine()
        if engine is None:
            return _error_dict("strategic_report", RuntimeError("Sigma engine unavailable"))
        result = await engine.run_scheduled_reporting()
        return result
    except Exception as e:
        logger.error("strategic_report failed: %s", e, exc_info=True)
        return _error_dict("strategic_report", e)


@tool
async def tactical_report() -> Dict[str, Any]:
    """Generate tactical security report for operational teams. Includes
    alert volumes, response times, detection efficacy, and team workload.
    Use for weekly SOC team reviews."""
    try:
        engine = _get_sigma_engine()
        if engine is None:
            return _error_dict("tactical_report", RuntimeError("Sigma engine unavailable"))
        result = await engine.run_scheduled_reporting()
        return result
    except Exception as e:
        logger.error("tactical_report failed: %s", e, exc_info=True)
        return _error_dict("tactical_report", e)


@tool
async def collect_metrics() -> Dict[str, Any]:
    """Collect current security metrics from all sources. Gathers data from
    agents, fusion engine, SIEM, and external tools. Use to refresh
    metric baselines before generating reports."""
    try:
        engine = _get_sigma_engine()
        if engine is None:
            return _error_dict("collect_metrics", RuntimeError("Sigma engine unavailable"))
        metrics = await engine.collector.collect_all_metrics()
        return {"metrics": metrics}
    except Exception as e:
        logger.error("collect_metrics failed: %s", e, exc_info=True)
        return _error_dict("collect_metrics", e)


# =============================================================================
# Zeta GRC Tools
# =============================================================================

@tool
async def zeta_assess_compliance(framework_id: str = "nist_csf_2_0", scope: str = "full",
                                  team_id: str = "default") -> Dict[str, Any]:
    """Run compliance assessment against a framework (NIST CSF 2.0, ISO 27001,
    ISO 42001, MITRE ATT&CK). Returns overall score, per-function scores,
    control statuses, and identified gaps."""
    try:
        engine = _get_zeta_engine()
        if engine is None:
            return _error_dict("zeta_assess_compliance", RuntimeError("Zeta GRC engine unavailable"))
        posture = await engine.assess_compliance(framework_id, scope, team_id)
        return posture.model_dump()
    except Exception as e:
        logger.error("zeta_assess_compliance failed: %s", e, exc_info=True)
        return _error_dict("zeta_assess_compliance", e)


@tool
async def zeta_map_controls(source_framework: str, target_framework: str,
                             control_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    """Look up cross-framework control mappings between any two supported frameworks.
    Returns matched controls with relationship type and confidence."""
    try:
        engine = _get_zeta_engine()
        if engine is None:
            return _error_dict("zeta_map_controls", RuntimeError("Zeta GRC engine unavailable"))
        mappings = await engine.map_controls(source_framework, target_framework, control_ids)
        return {"mappings": mappings, "count": len(mappings)}
    except Exception as e:
        logger.error("zeta_map_controls failed: %s", e, exc_info=True)
        return _error_dict("zeta_map_controls", e)


@tool
async def zeta_collect_evidence(control_ids: List[str],
                                 sources: Optional[List[str]] = None) -> Dict[str, Any]:
    """Collect compliance evidence for specified controls from platform integrations.
    Sources include CrowdStrike, Okta, AWS, Panther SIEM, and GitHub."""
    try:
        engine = _get_zeta_engine()
        if engine is None:
            return _error_dict("zeta_collect_evidence", RuntimeError("Zeta GRC engine unavailable"))
        evidence = await engine.collect_evidence(control_ids, sources)
        return {"evidence": [e.model_dump() for e in evidence], "count": len(evidence)}
    except Exception as e:
        logger.error("zeta_collect_evidence failed: %s", e, exc_info=True)
        return _error_dict("zeta_collect_evidence", e)


@tool
async def zeta_analyze_gaps(framework_id: str = "nist_csf_2_0") -> Dict[str, Any]:
    """Identify and prioritize compliance gaps by risk score.
    Cross-references gaps with other frameworks to show cascading impact."""
    try:
        engine = _get_zeta_engine()
        if engine is None:
            return _error_dict("zeta_analyze_gaps", RuntimeError("Zeta GRC engine unavailable"))
        gaps = await engine.analyze_gaps(framework_id)
        return {"gaps": [g.model_dump() for g in gaps], "count": len(gaps)}
    except Exception as e:
        logger.error("zeta_analyze_gaps failed: %s", e, exc_info=True)
        return _error_dict("zeta_analyze_gaps", e)


@tool
async def zeta_manage_risk_register(team_id: str = "default", action: str = "list",
                                     entry: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Manage team risk registers using ISO 31000 methodology.
    Actions: 'list' (view all), 'add' (create entry), 'remove' (delete by risk_id)."""
    try:
        engine = _get_zeta_engine()
        if engine is None:
            return _error_dict("zeta_manage_risk_register", RuntimeError("Zeta GRC engine unavailable"))
        return await engine.manage_risk_register(team_id, action, entry)
    except Exception as e:
        logger.error("zeta_manage_risk_register failed: %s", e, exc_info=True)
        return _error_dict("zeta_manage_risk_register", e)


@tool
async def zeta_assess_mitre_coverage(detection_rules: Optional[List[Dict[str, Any]]] = None,
                                      siem_sources: Optional[List[str]] = None) -> Dict[str, Any]:
    """Generate MITRE ATT&CK detection coverage matrix. Shows per-tactic coverage
    percentages, technique gaps, and priority recommendations."""
    try:
        engine = _get_zeta_engine()
        if engine is None:
            return _error_dict("zeta_assess_mitre_coverage", RuntimeError("Zeta GRC engine unavailable"))
        matrix = await engine.assess_mitre_coverage(detection_rules, siem_sources)
        return matrix.model_dump()
    except Exception as e:
        logger.error("zeta_assess_mitre_coverage failed: %s", e, exc_info=True)
        return _error_dict("zeta_assess_mitre_coverage", e)


@tool
async def zeta_assess_ai_system(agent_id: str) -> Dict[str, Any]:
    """Perform ISO 42001 AI management assessment on a platform agent.
    Evaluates impact, data governance, human oversight, and compliance."""
    try:
        engine = _get_zeta_engine()
        if engine is None:
            return _error_dict("zeta_assess_ai_system", RuntimeError("Zeta GRC engine unavailable"))
        return await engine.assess_ai_system(agent_id)
    except Exception as e:
        logger.error("zeta_assess_ai_system failed: %s", e, exc_info=True)
        return _error_dict("zeta_assess_ai_system", e)


@tool
async def zeta_generate_soa(scope: str = "full") -> Dict[str, Any]:
    """Generate ISO 27001 Statement of Applicability covering all 93 Annex A controls.
    Includes applicability justification and implementation status for each control."""
    try:
        engine = _get_zeta_engine()
        if engine is None:
            return _error_dict("zeta_generate_soa", RuntimeError("Zeta GRC engine unavailable"))
        soa = await engine.generate_soa(scope)
        return soa.model_dump()
    except Exception as e:
        logger.error("zeta_generate_soa failed: %s", e, exc_info=True)
        return _error_dict("zeta_generate_soa", e)


@tool
async def zeta_generate_audit_package(framework_id: str = "nist_csf_2_0",
                                       scope: str = "full") -> Dict[str, Any]:
    """Generate complete audit bundle: assessment, evidence, gaps, and risk entries.
    Suitable for external auditor review."""
    try:
        engine = _get_zeta_engine()
        if engine is None:
            return _error_dict("zeta_generate_audit_package", RuntimeError("Zeta GRC engine unavailable"))
        package = await engine.generate_audit_package(framework_id, scope)
        return package.model_dump()
    except Exception as e:
        logger.error("zeta_generate_audit_package failed: %s", e, exc_info=True)
        return _error_dict("zeta_generate_audit_package", e)


# =============================================================================
# Tool Registry — used by agent sub-graphs to get the right tools
# =============================================================================

ALPHA4_TOOLS = [analyze_campaign, enrich_iocs, alpha4_hunt_threats]
BETA4_TOOLS = [comprehensive_scan, sast_scan, container_scan, supply_chain_scan, iac_scan]
GAMMA_TOOLS = [process_alert, triage_alert, gamma_hunt_threats, analyze_phishing, execute_containment]
DELTA_TOOLS = [adversary_emulation, attack_path_analysis, detection_validation, operation_status, terminate_operation]
SIGMA_TOOLS = [executive_dashboard, strategic_report, tactical_report, collect_metrics]
ZETA_TOOLS = [
    zeta_assess_compliance, zeta_map_controls, zeta_collect_evidence, zeta_analyze_gaps,
    zeta_manage_risk_register, zeta_assess_mitre_coverage, zeta_assess_ai_system,
    zeta_generate_soa, zeta_generate_audit_package,
]

AGENT_TOOLS = {
    "alpha_4_threat_intel": ALPHA4_TOOLS,
    "beta_4_devsecops": BETA4_TOOLS,
    "gamma_blue_team": GAMMA_TOOLS,
    "delta_red_team": DELTA_TOOLS,
    "sigma_metrics": SIGMA_TOOLS,
    "zeta_grc": ZETA_TOOLS,
}
