"""System prompts for LangGraph agent sub-graphs."""

from security_agents.core.prompts.alpha4 import ALPHA4_SYSTEM_PROMPT
from security_agents.core.prompts.beta4 import BETA4_SYSTEM_PROMPT
from security_agents.core.prompts.gamma import GAMMA_SYSTEM_PROMPT
from security_agents.core.prompts.delta import DELTA_SYSTEM_PROMPT
from security_agents.core.prompts.sigma import SIGMA_SYSTEM_PROMPT
from security_agents.core.prompts.zeta import ZETA_SYSTEM_PROMPT
from security_agents.core.prompts.router import ROUTER_SYSTEM_PROMPT
from security_agents.core.prompts.synthesis import SYNTHESIS_SYSTEM_PROMPT

AGENT_PROMPTS = {
    "alpha_4_threat_intel": ALPHA4_SYSTEM_PROMPT,
    "beta_4_devsecops": BETA4_SYSTEM_PROMPT,
    "gamma_blue_team": GAMMA_SYSTEM_PROMPT,
    "delta_red_team": DELTA_SYSTEM_PROMPT,
    "sigma_metrics": SIGMA_SYSTEM_PROMPT,
    "zeta_grc": ZETA_SYSTEM_PROMPT,
}

__all__ = [
    "ALPHA4_SYSTEM_PROMPT",
    "BETA4_SYSTEM_PROMPT",
    "GAMMA_SYSTEM_PROMPT",
    "DELTA_SYSTEM_PROMPT",
    "SIGMA_SYSTEM_PROMPT",
    "ZETA_SYSTEM_PROMPT",
    "ROUTER_SYSTEM_PROMPT",
    "SYNTHESIS_SYSTEM_PROMPT",
    "AGENT_PROMPTS",
]
