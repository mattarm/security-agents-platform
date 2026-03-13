"""Zeta GRC sub-graph."""

from langchain_core.tools import tool
from typing import Any, Dict, List, Optional

from security_agents.core.agent_graphs.base import build_react_agent
from security_agents.core.prompts.zeta import ZETA_SYSTEM_PROMPT


# Zeta-specific tools wrapping the GRC engine
_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from security_agents.agents.engines.zeta_grc_engine import ZetaGRCEngine
        _engine = ZetaGRCEngine()
    return _engine


@tool
async def assess_compliance(framework_id: str = "nist_csf_2_0", scope: str = "full",
                             team_id: str = "default") -> Dict[str, Any]:
    """Run compliance assessment against a framework (NIST CSF 2.0, ISO 27001, ISO 42001, MITRE ATT&CK).
    Returns overall score, per-function scores, control statuses, and identified gaps."""
    engine = _get_engine()
    posture = await engine.assess_compliance(framework_id, scope, team_id)
    return posture.model_dump()


@tool
async def map_controls(source_framework: str, target_framework: str,
                        control_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    """Look up cross-framework control mappings between any two supported frameworks.
    Returns matched controls with relationship type and confidence."""
    engine = _get_engine()
    mappings = await engine.map_controls(source_framework, target_framework, control_ids)
    return {"mappings": mappings, "count": len(mappings)}


@tool
async def collect_evidence(control_ids: List[str],
                            sources: Optional[List[str]] = None) -> Dict[str, Any]:
    """Collect compliance evidence for specified controls from platform integrations.
    Sources include CrowdStrike, Okta, AWS, Panther SIEM, and GitHub."""
    engine = _get_engine()
    evidence = await engine.collect_evidence(control_ids, sources)
    return {"evidence": [e.model_dump() for e in evidence], "count": len(evidence)}


@tool
async def analyze_gaps(framework_id: str = "nist_csf_2_0") -> Dict[str, Any]:
    """Identify and prioritize compliance gaps by risk score.
    Cross-references gaps with other frameworks to show cascading impact."""
    engine = _get_engine()
    gaps = await engine.analyze_gaps(framework_id)
    return {"gaps": [g.model_dump() for g in gaps], "count": len(gaps)}


@tool
async def manage_risk_register(team_id: str = "default", action: str = "list",
                                entry: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Manage team risk registers using ISO 31000 methodology.
    Actions: 'list' (view all), 'add' (create entry), 'remove' (delete by risk_id)."""
    engine = _get_engine()
    return await engine.manage_risk_register(team_id, action, entry)


@tool
async def assess_mitre_coverage(detection_rules: Optional[List[Dict[str, Any]]] = None,
                                 siem_sources: Optional[List[str]] = None) -> Dict[str, Any]:
    """Generate MITRE ATT&CK detection coverage matrix. Shows per-tactic coverage
    percentages, technique gaps, and priority recommendations."""
    engine = _get_engine()
    matrix = await engine.assess_mitre_coverage(detection_rules, siem_sources)
    return matrix.model_dump()


@tool
async def assess_ai_system(agent_id: str) -> Dict[str, Any]:
    """Perform ISO 42001 AI management assessment on a platform agent.
    Evaluates impact, data governance, human oversight, and compliance."""
    engine = _get_engine()
    return await engine.assess_ai_system(agent_id)


@tool
async def generate_soa(scope: str = "full") -> Dict[str, Any]:
    """Generate ISO 27001 Statement of Applicability covering all 93 Annex A controls.
    Includes applicability justification and implementation status for each control."""
    engine = _get_engine()
    soa = await engine.generate_soa(scope)
    return soa.model_dump()


@tool
async def generate_audit_package(framework_id: str = "nist_csf_2_0",
                                  scope: str = "full") -> Dict[str, Any]:
    """Generate complete audit bundle: assessment, evidence, gaps, and risk entries.
    Suitable for external auditor review."""
    engine = _get_engine()
    package = await engine.generate_audit_package(framework_id, scope)
    return package.model_dump()


ZETA_TOOLS = [
    assess_compliance, map_controls, collect_evidence, analyze_gaps,
    manage_risk_register, assess_mitre_coverage, assess_ai_system,
    generate_soa, generate_audit_package,
]


def build_zeta_graph():
    """Build Zeta GRC ReAct agent (uses Opus for compliance interpretation)."""
    return build_react_agent(
        model_name="claude-opus-4-6",
        tools=ZETA_TOOLS,
        system_prompt=ZETA_SYSTEM_PROMPT,
        agent_id="zeta_grc",
    )
