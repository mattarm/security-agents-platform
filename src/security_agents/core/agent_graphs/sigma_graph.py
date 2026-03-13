"""Sigma Metrics sub-graph."""

from security_agents.core.agent_graphs.base import build_react_agent
from security_agents.core.agent_tools import SIGMA_TOOLS
from security_agents.core.prompts.sigma import SIGMA_SYSTEM_PROMPT


def build_sigma_graph():
    """Build Sigma Metrics ReAct agent (uses Haiku for lightweight tasks)."""
    return build_react_agent(
        model_name="claude-haiku-4-5-20251001",
        tools=SIGMA_TOOLS,
        system_prompt=SIGMA_SYSTEM_PROMPT,
        agent_id="sigma_metrics",
    )
