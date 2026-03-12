"""Tests for the Enterprise Topology Skill."""

import pytest

from security_agents.skills.enterprise_topology import EnterpriseTopologySkill


@pytest.fixture
async def topology_skill():
    """Create and initialize an enterprise topology skill."""
    skill = EnterpriseTopologySkill(agent_id="beta_4_devsecops", config={})
    await skill.initialize()
    return skill


async def _seed_topology(skill):
    """Helper: seed a small topology graph for testing."""
    await skill.execute({
        "action": "map_topology",
        "systems": [
            {"system_id": "api-gw", "name": "API Gateway", "type": "gateway", "criticality": "critical"},
            {"system_id": "auth-svc", "name": "Auth Service", "type": "service", "criticality": "critical"},
            {"system_id": "user-db", "name": "User DB", "type": "database", "criticality": "high"},
            {"system_id": "cache", "name": "Redis Cache", "type": "cache", "criticality": "medium"},
            {"system_id": "worker", "name": "Background Worker", "type": "service", "criticality": "low"},
        ],
        "dependencies": [
            {"source": "api-gw", "target": "auth-svc", "type": "auth", "is_critical": True},
            {"source": "auth-svc", "target": "user-db", "type": "data", "is_critical": True},
            {"source": "auth-svc", "target": "cache", "type": "runtime"},
            {"source": "api-gw", "target": "worker", "type": "event"},
        ],
    })


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestTopologyInit:
    @pytest.mark.asyncio
    async def test_initialize(self, topology_skill):
        assert topology_skill.initialized
        assert topology_skill.SKILL_NAME == "enterprise_topology"

    @pytest.mark.asyncio
    async def test_not_initialized_returns_error(self):
        skill = EnterpriseTopologySkill(agent_id="test", config={})
        result = await skill.execute({"action": "map_topology"})
        assert not result.success
        assert "not initialized" in result.errors[0]

    def test_metadata(self):
        skill = EnterpriseTopologySkill(agent_id="beta_4_devsecops", config={})
        meta = skill.get_metadata()
        assert meta["skill_name"] == "enterprise_topology"
        assert "beta_4_devsecops" in meta["compatible_agents"]


# ---------------------------------------------------------------------------
# map_topology
# ---------------------------------------------------------------------------


class TestMapTopology:
    @pytest.mark.asyncio
    async def test_map_systems_and_deps(self, topology_skill):
        result = await topology_skill.execute({
            "action": "map_topology",
            "systems": [
                {"system_id": "svc-a", "name": "Service A", "type": "service"},
                {"system_id": "db-a", "name": "Database A", "type": "database"},
            ],
            "dependencies": [
                {"source": "svc-a", "target": "db-a", "type": "data"},
            ],
        })
        assert result.success
        assert result.data["systems_added"] == 2
        assert result.data["dependencies_added"] == 1

    @pytest.mark.asyncio
    async def test_map_empty_input_returns_error(self, topology_skill):
        result = await topology_skill.execute({
            "action": "map_topology",
            "systems": [],
            "dependencies": [],
        })
        assert not result.success
        assert "Provide at least one" in result.errors[0]

    @pytest.mark.asyncio
    async def test_map_unknown_system_type_warns(self, topology_skill):
        result = await topology_skill.execute({
            "action": "map_topology",
            "systems": [
                {"system_id": "x", "name": "X", "type": "alien_device"},
            ],
        })
        assert result.success
        assert any("unknown type" in w.lower() for w in result.warnings)

    @pytest.mark.asyncio
    async def test_map_system_without_id_warns(self, topology_skill):
        result = await topology_skill.execute({
            "action": "map_topology",
            "systems": [{"name": "No ID System"}],
        })
        assert result.success
        assert any("system_id" in w.lower() for w in result.warnings)

    @pytest.mark.asyncio
    async def test_update_existing_system(self, topology_skill):
        await topology_skill.execute({
            "action": "map_topology",
            "systems": [{"system_id": "s1", "name": "V1", "type": "service"}],
        })
        result = await topology_skill.execute({
            "action": "map_topology",
            "systems": [{"system_id": "s1", "name": "V2", "type": "service"}],
        })
        assert result.success
        assert result.data["systems_updated"] == 1
        assert result.data["systems_added"] == 0


# ---------------------------------------------------------------------------
# get_dependencies
# ---------------------------------------------------------------------------


class TestGetDependencies:
    @pytest.mark.asyncio
    async def test_get_downstream(self, topology_skill):
        await _seed_topology(topology_skill)
        result = await topology_skill.execute({
            "action": "get_dependencies",
            "system_id": "api-gw",
            "direction": "downstream",
        })
        assert result.success
        downstream_ids = [d["system_id"] for d in result.data["downstream_dependencies"]]
        assert "auth-svc" in downstream_ids

    @pytest.mark.asyncio
    async def test_get_upstream(self, topology_skill):
        await _seed_topology(topology_skill)
        result = await topology_skill.execute({
            "action": "get_dependencies",
            "system_id": "user-db",
            "direction": "upstream",
        })
        assert result.success

    @pytest.mark.asyncio
    async def test_get_deps_unknown_system(self, topology_skill):
        result = await topology_skill.execute({
            "action": "get_dependencies",
            "system_id": "nonexistent",
        })
        assert not result.success or result.data.get("dependencies") == []


# ---------------------------------------------------------------------------
# assess_blast_radius
# ---------------------------------------------------------------------------


class TestAssessBlastRadius:
    @pytest.mark.asyncio
    async def test_blast_radius_critical_system(self, topology_skill):
        await _seed_topology(topology_skill)
        result = await topology_skill.execute({
            "action": "assess_blast_radius",
            "system_id": "auth-svc",
        })
        assert result.success
        assert result.data["affected_systems_count"] >= 1
        assert "affected_systems" in result.data

    @pytest.mark.asyncio
    async def test_blast_radius_leaf_node(self, topology_skill):
        await _seed_topology(topology_skill)
        result = await topology_skill.execute({
            "action": "assess_blast_radius",
            "system_id": "worker",
        })
        assert result.success
        # Leaf node has minimal blast radius
        assert result.data["affected_systems_count"] >= 0


# ---------------------------------------------------------------------------
# find_critical_paths
# ---------------------------------------------------------------------------


class TestFindCriticalPaths:
    @pytest.mark.asyncio
    async def test_find_critical_paths(self, topology_skill):
        await _seed_topology(topology_skill)
        result = await topology_skill.execute({
            "action": "find_critical_paths",
        })
        assert result.success
        assert "paths" in result.data


# ---------------------------------------------------------------------------
# generate_report
# ---------------------------------------------------------------------------


class TestTopologyReport:
    @pytest.mark.asyncio
    async def test_generate_report(self, topology_skill):
        await _seed_topology(topology_skill)
        result = await topology_skill.execute({
            "action": "generate_report",
        })
        assert result.success
        assert "summary" in result.data
        assert result.data["summary"]["total_systems"] >= 5

    @pytest.mark.asyncio
    async def test_generate_report_empty_graph(self, topology_skill):
        result = await topology_skill.execute({
            "action": "generate_report",
        })
        assert result.success
        assert result.data["summary"]["total_systems"] == 0


# ---------------------------------------------------------------------------
# Unknown Action
# ---------------------------------------------------------------------------


class TestTopologyUnknownAction:
    @pytest.mark.asyncio
    async def test_unknown_action(self, topology_skill):
        result = await topology_skill.execute({"action": "nonexistent"})
        assert not result.success
        assert "Unknown action" in result.errors[0]
