"""Agent sub-graphs for LangGraph orchestration."""

from security_agents.core.agent_graphs.alpha4_graph import build_alpha4_graph
from security_agents.core.agent_graphs.beta4_graph import build_beta4_graph
from security_agents.core.agent_graphs.gamma_graph import build_gamma_graph
from security_agents.core.agent_graphs.delta_graph import build_delta_graph
from security_agents.core.agent_graphs.sigma_graph import build_sigma_graph
from security_agents.core.agent_graphs.zeta_graph import build_zeta_graph

AGENT_GRAPH_BUILDERS = {
    "alpha_4_threat_intel": build_alpha4_graph,
    "beta_4_devsecops": build_beta4_graph,
    "gamma_blue_team": build_gamma_graph,
    "delta_red_team": build_delta_graph,
    "sigma_metrics": build_sigma_graph,
    "zeta_grc": build_zeta_graph,
}

__all__ = [
    "build_alpha4_graph",
    "build_beta4_graph",
    "build_gamma_graph",
    "build_delta_graph",
    "build_sigma_graph",
    "build_zeta_graph",
    "AGENT_GRAPH_BUILDERS",
]
