"""Alpha-4 Threat Intelligence sub-graph."""

from security_agents.core.agent_graphs.base import build_react_agent
from security_agents.core.agent_tools import ALPHA4_TOOLS
from security_agents.core.prompts.alpha4 import ALPHA4_SYSTEM_PROMPT


def build_alpha4_graph():
    """Build Alpha-4 threat intelligence ReAct agent."""
    return build_react_agent(
        model_name="claude-sonnet-4-6",
        tools=ALPHA4_TOOLS,
        system_prompt=ALPHA4_SYSTEM_PROMPT,
        agent_id="alpha_4_threat_intel",
    )
