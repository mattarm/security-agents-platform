"""Beta-4 DevSecOps sub-graph."""

from security_agents.core.agent_graphs.base import build_react_agent
from security_agents.core.agent_tools import BETA4_TOOLS
from security_agents.core.prompts.beta4 import BETA4_SYSTEM_PROMPT


def build_beta4_graph():
    """Build Beta-4 DevSecOps ReAct agent."""
    return build_react_agent(
        model_name="claude-sonnet-4-6",
        tools=BETA4_TOOLS,
        system_prompt=BETA4_SYSTEM_PROMPT,
        agent_id="beta_4_devsecops",
    )
