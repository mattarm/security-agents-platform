#!/usr/bin/env python3
"""
LangGraph Orchestrator — LLM-powered multi-agent orchestration.

Replaces deterministic if/elif routing with Claude-driven reasoning.
StateGraph with nodes: intake -> router -> agent fan-out -> fusion -> autonomy_gate -> synthesis.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langgraph.graph import END, START, StateGraph
from langgraph.types import Send, interrupt

from security_agents.core.schemas import (
    AgentResult,
    OrchestratorState,
)
from security_agents.core.prompts import ROUTER_SYSTEM_PROMPT, SYNTHESIS_SYSTEM_PROMPT
from security_agents.core.agent_graphs import AGENT_GRAPH_BUILDERS

logger = logging.getLogger(__name__)


# =============================================================================
# Node implementations
# =============================================================================

def intake_node(state: OrchestratorState) -> dict:
    """Validate request, extract indicators, determine scope. Deterministic."""
    request = state.get("request", {})
    target = request.get("target", "")

    # Extract IOCs from target string
    iocs = []
    iocs.extend(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", target))
    iocs.extend(re.findall(r"\b[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}\b", target))
    iocs.extend(re.findall(r"https?://[^\s<>\"{}|\\^`\[\]]+", target))

    request["extracted_iocs"] = list(set(iocs))
    request["request_id"] = request.get("request_id", str(uuid.uuid4()))

    return {
        "request": request,
        "current_phase": "intake_complete",
        "messages": [
            HumanMessage(content=f"Analysis request: {request.get('analysis_type', 'comprehensive')} "
                        f"for target: {target}")
        ],
    }


async def router_node(state: OrchestratorState) -> dict:
    """LLM-powered agent routing. Claude decides which agents to invoke."""
    request = state["request"]

    llm = ChatAnthropic(model="claude-opus-4-6", max_tokens=1024)

    routing_prompt = (
        f"Analysis request:\n"
        f"- Type: {request.get('analysis_type', 'comprehensive')}\n"
        f"- Target: {request.get('target', 'unknown')}\n"
        f"- Priority: {request.get('priority', 'medium')}\n"
        f"- Parameters: {json.dumps(request.get('parameters', {}), default=str)}\n"
        f"- Extracted IOCs: {request.get('extracted_iocs', [])}\n\n"
        f"Decide which agents to invoke. Return a JSON object with:\n"
        f"- agents: list of agent IDs\n"
        f"- rationale: brief explanation\n"
        f"- execution_order: 'parallel' or 'sequential'\n\n"
        f"Valid agent IDs: alpha_4_threat_intel, beta_4_devsecops, gamma_blue_team, "
        f"delta_red_team, sigma_metrics, zeta_grc"
    )

    try:
        response = await llm.ainvoke([
            SystemMessage(content=ROUTER_SYSTEM_PROMPT),
            HumanMessage(content=routing_prompt),
        ])

        content = response.content

        # Try parsing the full response as JSON first
        try:
            decision = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            # Try to find a JSON object containing "agents" anywhere in the response
            try:
                start = content.index("{")
                end = content.rindex("}") + 1
                decision = json.loads(content[start:end])
            except (ValueError, json.JSONDecodeError):
                logger.warning("Could not parse JSON from LLM routing response, falling back to deterministic routing")
                decision = _deterministic_routing(request)

    except Exception as e:
        logger.warning(f"LLM routing call failed ({type(e).__name__}: {e}), falling back to deterministic routing")
        decision = _deterministic_routing(request)

    selected_agents = decision.get("agents", ["alpha_4_threat_intel"])
    rationale = decision.get("rationale", "Default routing")

    return {
        "current_phase": "routing_complete",
        "messages": [
            AIMessage(content=f"Router decision: {selected_agents} — {rationale}")
        ],
        "request": {**request, "_routed_agents": selected_agents},
    }


def _deterministic_routing(request: dict) -> dict:
    """Fallback deterministic routing when LLM routing fails."""
    analysis_type = request.get("analysis_type", "comprehensive")

    routing_map = {
        "comprehensive": ["alpha_4_threat_intel", "beta_4_devsecops", "gamma_blue_team",
                         "delta_red_team", "sigma_metrics", "zeta_grc"],
        "threat_focused": ["alpha_4_threat_intel", "gamma_blue_team"],
        "vulnerability_focused": ["beta_4_devsecops"],
        "incident_response": ["gamma_blue_team", "alpha_4_threat_intel"],
        "red_team": ["delta_red_team"],
        "phishing": ["gamma_blue_team", "alpha_4_threat_intel"],
        "grc": ["zeta_grc", "sigma_metrics"],
        "compliance": ["zeta_grc"],
    }

    agents = routing_map.get(analysis_type, ["alpha_4_threat_intel"])
    return {"agents": agents, "rationale": f"Deterministic routing for {analysis_type}"}


async def agent_node(state: OrchestratorState, agent_id: str) -> dict:
    """Execute a single agent's sub-graph."""
    request = state["request"]
    builder = AGENT_GRAPH_BUILDERS.get(agent_id)

    if not builder:
        logger.error(f"No graph builder for agent: {agent_id}")
        return {
            "agent_results": [AgentResult(
                agent_id=agent_id, agent_name=agent_id,
                status="error", errors=[f"No graph builder for {agent_id}"]
            ).model_dump()],
        }

    try:
        graph = builder()
        agent_input = {
            "messages": [
                HumanMessage(content=f"Analyze: {request.get('target', '')}. "
                            f"Type: {request.get('analysis_type', 'comprehensive')}. "
                            f"Parameters: {json.dumps(request.get('parameters', {}), default=str)}. "
                            f"IOCs: {request.get('extracted_iocs', [])}")
            ]
        }

        result = await graph.ainvoke(agent_input)

        # Extract the last AI message as the result
        ai_messages = [m for m in result.get("messages", []) if isinstance(m, AIMessage)]
        last_message = ai_messages[-1].content if ai_messages else "No output"

        return {
            "agent_results": [AgentResult(
                agent_id=agent_id,
                agent_name=agent_id,
                status="completed",
                findings=[{"summary": last_message}],
            ).model_dump()],
            "messages": [AIMessage(content=f"[{agent_id}] {last_message[:500]}")],
        }

    except Exception as e:
        logger.error(f"Agent {agent_id} failed: {e}")
        return {
            "agent_results": [AgentResult(
                agent_id=agent_id, agent_name=agent_id,
                status="error", errors=[str(e)]
            ).model_dump()],
        }


async def fusion_node(state: OrchestratorState) -> dict:
    """Correlate intelligence across agent results."""
    agent_results = state.get("agent_results", [])
    intelligence_packets = state.get("intelligence_packets", [])

    # Aggregate findings across agents
    all_findings = []
    for result in agent_results:
        if isinstance(result, dict):
            all_findings.extend(result.get("findings", []))

    return {
        "fusion_results": {
            "agent_count": len(agent_results),
            "total_findings": len(all_findings),
            "intelligence_packets": len(intelligence_packets),
            "correlated_at": datetime.now().isoformat(),
        },
        "current_phase": "fusion_complete",
    }


def autonomy_gate_node(state: OrchestratorState) -> dict:
    """Check if any actions need human approval based on autonomy tier."""
    tier = state.get("autonomy_tier", 0)

    if tier >= 2:
        logger.info(f"Autonomy tier {tier}: requiring human approval via interrupt")
        try:
            interrupt({
                "reason": "Tier 2+ action requires human approval",
                "autonomy_tier": tier,
                "current_phase": state.get("current_phase"),
                "agent_results_count": len(state.get("agent_results", [])),
            })
        except RuntimeError:
            # Called outside a graph context (e.g., unit tests) — fall through
            logger.warning("interrupt() called outside graph context; skipping")
        return {
            "current_phase": "awaiting_approval",
            "messages": [AIMessage(content=f"Autonomy tier {tier}: actions require human approval")],
        }

    return {"current_phase": "approved"}


async def synthesis_node(state: OrchestratorState) -> dict:
    """Combine all results into final structured output. LLM-powered."""
    agent_results = state.get("agent_results", [])
    fusion_results = state.get("fusion_results", {})
    request = state.get("request", {})

    llm = ChatAnthropic(model="claude-opus-4-6", max_tokens=2048)

    synthesis_prompt = (
        f"Original request: {request.get('analysis_type')} for {request.get('target')}\n\n"
        f"Agent results ({len(agent_results)} agents):\n"
        f"{json.dumps(agent_results, indent=2, default=str)[:3000]}\n\n"
        f"Fusion results:\n{json.dumps(fusion_results, default=str)}\n\n"
        f"Produce an executive summary with: risk_score (0-100), key_findings, "
        f"recommendations, and next_steps. Return as JSON."
    )

    try:
        response = await llm.ainvoke([
            SystemMessage(content=SYNTHESIS_SYSTEM_PROMPT),
            HumanMessage(content=synthesis_prompt),
        ])

        return {
            "current_phase": "complete",
            "messages": [AIMessage(content=response.content)],
        }

    except Exception as e:
        logger.warning(f"Synthesis LLM call failed ({type(e).__name__}: {e}), returning structured fallback")

        agent_ids = [r.get("agent_id", "unknown") for r in agent_results if isinstance(r, dict)]
        total_findings = fusion_results.get("total_findings", 0)

        fallback_summary = json.dumps({
            "risk_score": None,
            "key_findings": [f"{total_findings} finding(s) from {len(agent_results)} agent(s)"],
            "agents_reporting": agent_ids,
            "fusion_results": fusion_results,
            "recommendations": ["Review raw agent results — LLM synthesis unavailable"],
            "next_steps": ["Retry analysis when LLM service is available"],
            "error": str(e),
        }, default=str)

        return {
            "current_phase": "complete",
            "messages": [AIMessage(content=fallback_summary)],
        }


# =============================================================================
# Fan-out logic — route from router to agent sub-graphs
# =============================================================================

def route_to_agents(state: OrchestratorState) -> list[Send]:
    """Fan out to selected agent sub-graphs based on router decision."""
    request = state["request"]
    selected_agents = request.get("_routed_agents", ["alpha_4_threat_intel"])

    invalid_agents = [a for a in selected_agents if a not in AGENT_GRAPH_BUILDERS]
    if invalid_agents:
        logger.warning(f"Router returned invalid agent IDs not in AGENT_GRAPH_BUILDERS: {invalid_agents}")

    sends = []
    for agent_id in selected_agents:
        if agent_id in AGENT_GRAPH_BUILDERS:
            sends.append(Send(f"agent_{agent_id}", state))

    if not sends:
        sends.append(Send("agent_alpha_4_threat_intel", state))

    return sends


def should_gate(state: OrchestratorState) -> str:
    """Determine if autonomy gate should interrupt."""
    tier = state.get("autonomy_tier", 0)
    if tier >= 2:
        return "autonomy_gate"
    return "synthesis"


# =============================================================================
# Graph builder
# =============================================================================

def build_orchestrator_graph() -> StateGraph:
    """Build the complete orchestrator StateGraph.

    Returns an uncompiled StateGraph — call .compile() with optional checkpointer.
    """
    graph = StateGraph(OrchestratorState)

    # Add nodes
    graph.add_node("intake", intake_node)
    graph.add_node("router", router_node)

    # Add agent nodes — one per possible agent
    for agent_id in AGENT_GRAPH_BUILDERS:
        # Use a closure to capture agent_id
        def make_agent_node(aid):
            async def _node(state):
                return await agent_node(state, aid)
            _node.__name__ = f"agent_{aid}"
            return _node
        graph.add_node(f"agent_{agent_id}", make_agent_node(agent_id))

    graph.add_node("fusion", fusion_node)
    graph.add_node("autonomy_gate", autonomy_gate_node)
    graph.add_node("synthesis", synthesis_node)

    # Edges
    graph.add_edge(START, "intake")
    graph.add_edge("intake", "router")

    # Router fans out to agents via Send
    graph.add_conditional_edges("router", route_to_agents)

    # All agents converge at fusion
    for agent_id in AGENT_GRAPH_BUILDERS:
        graph.add_edge(f"agent_{agent_id}", "fusion")

    # Fusion -> conditional gate
    graph.add_conditional_edges("fusion", should_gate, {
        "autonomy_gate": "autonomy_gate",
        "synthesis": "synthesis",
    })
    graph.add_edge("autonomy_gate", "synthesis")
    graph.add_edge("synthesis", END)

    return graph
