"""Delta Red Team sub-graph."""

from security_agents.core.agent_graphs.base import build_react_agent
from security_agents.core.agent_tools import DELTA_TOOLS
from security_agents.core.prompts.delta import DELTA_SYSTEM_PROMPT


def build_delta_graph():
    """Build Delta Red Team ReAct agent."""
    return build_react_agent(
        model_name="claude-sonnet-4-6",
        tools=DELTA_TOOLS,
        system_prompt=DELTA_SYSTEM_PROMPT,
        agent_id="delta_red_team",
    )
