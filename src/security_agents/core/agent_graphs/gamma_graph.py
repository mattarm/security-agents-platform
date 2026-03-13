"""Gamma Blue Team sub-graph."""

from security_agents.core.agent_graphs.base import build_react_agent
from security_agents.core.agent_tools import GAMMA_TOOLS
from security_agents.core.prompts.gamma import GAMMA_SYSTEM_PROMPT


def build_gamma_graph():
    """Build Gamma Blue Team ReAct agent."""
    return build_react_agent(
        model_name="claude-sonnet-4-6",
        tools=GAMMA_TOOLS,
        system_prompt=GAMMA_SYSTEM_PROMPT,
        agent_id="gamma_blue_team",
    )
