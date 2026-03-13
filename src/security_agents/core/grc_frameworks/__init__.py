"""GRC Framework Knowledge Base — registry and access layer."""

from __future__ import annotations

from typing import Dict, List, Optional

from security_agents.core.grc_models import Framework


def get_framework(framework_id: str) -> Optional[Framework]:
    """Get a framework by ID."""
    return _REGISTRY.get(framework_id)


def list_frameworks() -> List[Dict[str, str]]:
    """List all available frameworks with basic metadata."""
    return [
        {"id": f.id, "name": f.name, "version": f.version, "controls": len(f.controls)}
        for f in _REGISTRY.values()
    ]


def get_all_frameworks() -> Dict[str, Framework]:
    """Get all framework objects."""
    return dict(_REGISTRY)


# Lazy-loaded registry — populated on first import of submodules
_REGISTRY: Dict[str, Framework] = {}


def _register(framework: Framework):
    _REGISTRY[framework.id] = framework


# Import submodules to trigger registration
from security_agents.core.grc_frameworks import nist_csf_2_0  # noqa: E402, F401
from security_agents.core.grc_frameworks import iso_27001_2022  # noqa: E402, F401
from security_agents.core.grc_frameworks import iso_42001_2023  # noqa: E402, F401
from security_agents.core.grc_frameworks import mitre_attack  # noqa: E402, F401
