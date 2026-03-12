"""Tests for the Threat Modeling Skill."""

import pytest

from security_agents.skills.threat_modeling import ThreatModelingSkill, StrideCategory, ComponentType


@pytest.fixture
async def threat_skill():
    """Create and initialize a threat modeling skill."""
    skill = ThreatModelingSkill(agent_id="delta_red_team", config={})
    await skill.initialize()
    return skill


async def _create_sample_model(skill, name="Test App"):
    """Helper: create a sample threat model."""
    return await skill.execute({
        "action": "create_model",
        "name": name,
        "description": "E-commerce application",
        "components": [
            {"name": "Web Frontend", "type": "web_application", "trust_level": "untrusted"},
            {"name": "API Server", "type": "api_service", "trust_level": "semi-trusted"},
            {"name": "Auth Service", "type": "auth_service", "trust_level": "trusted"},
            {"name": "User Database", "type": "database", "trust_level": "trusted"},
        ],
        "data_flows": [
            {"source": "Web Frontend", "destination": "API Server", "data_type": "user_input", "crosses_trust_boundary": True},
            {"source": "API Server", "destination": "Auth Service", "data_type": "credentials", "crosses_trust_boundary": False},
            {"source": "Auth Service", "destination": "User Database", "data_type": "user_records", "crosses_trust_boundary": False},
        ],
        "trust_boundaries": [
            {"name": "Internet Boundary", "components": ["Web Frontend"]},
            {"name": "Internal Network", "components": ["API Server", "Auth Service", "User Database"]},
        ],
    })


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestThreatModelInit:
    @pytest.mark.asyncio
    async def test_initialize(self, threat_skill):
        assert threat_skill.initialized
        assert threat_skill.SKILL_NAME == "threat_modeling"

    @pytest.mark.asyncio
    async def test_not_initialized_returns_error(self):
        skill = ThreatModelingSkill(agent_id="test", config={})
        result = await skill.execute({"action": "create_model"})
        assert not result.success
        assert "not initialized" in result.errors[0]

    def test_metadata(self):
        skill = ThreatModelingSkill(agent_id="delta_red_team", config={})
        meta = skill.get_metadata()
        assert meta["skill_name"] == "threat_modeling"
        assert "delta_red_team" in meta["compatible_agents"]


# ---------------------------------------------------------------------------
# create_model
# ---------------------------------------------------------------------------


class TestCreateModel:
    @pytest.mark.asyncio
    async def test_create_model_basic(self, threat_skill):
        result = await _create_sample_model(threat_skill)
        assert result.success
        assert result.data["model_id"].startswith("TM-")
        assert result.data["model"]["name"] == "Test App"
        assert result.data["metrics"]["total_components"] >= 4

    @pytest.mark.asyncio
    async def test_create_model_missing_name(self, threat_skill):
        result = await threat_skill.execute({
            "action": "create_model",
            "components": [{"name": "X", "type": "web_application"}],
        })
        assert not result.success
        assert "name" in result.errors[0].lower()

    @pytest.mark.asyncio
    async def test_create_model_missing_components(self, threat_skill):
        result = await threat_skill.execute({
            "action": "create_model",
            "name": "Empty Model",
            "components": [],
        })
        assert not result.success
        assert "component" in result.errors[0].lower()

    @pytest.mark.asyncio
    async def test_create_model_unknown_component_type(self, threat_skill):
        result = await threat_skill.execute({
            "action": "create_model",
            "name": "Weird Model",
            "components": [{"name": "Alien", "type": "quantum_computer"}],
        })
        assert result.success
        # Should still create but warn about unknown type
        model = threat_skill.models[result.data["model_id"]]
        comps = model.get("components", [])
        assert any("type_warning" in c for c in comps)


# ---------------------------------------------------------------------------
# analyze_stride
# ---------------------------------------------------------------------------


class TestAnalyzeSTRIDE:
    @pytest.mark.asyncio
    async def test_stride_analysis(self, threat_skill):
        create = await _create_sample_model(threat_skill)
        model_id = create.data["model_id"]

        result = await threat_skill.execute({
            "action": "analyze_stride",
            "model_id": model_id,
        })
        assert result.success
        assert "threats" in result.data
        assert len(result.data["threats"]) >= 1
        # Each threat should map to a STRIDE category
        stride_values = {c.value for c in StrideCategory}
        for t in result.data["threats"]:
            assert t["stride_category"] in stride_values

    @pytest.mark.asyncio
    async def test_stride_nonexistent_model(self, threat_skill):
        result = await threat_skill.execute({
            "action": "analyze_stride",
            "model_id": "TM-nope",
        })
        assert not result.success

    @pytest.mark.asyncio
    async def test_stride_covers_all_categories(self, threat_skill):
        create = await _create_sample_model(threat_skill)
        model_id = create.data["model_id"]

        result = await threat_skill.execute({
            "action": "analyze_stride",
            "model_id": model_id,
        })
        assert result.success
        categories_found = {t["stride_category"] for t in result.data["threats"]}
        # With a web app + api + auth + db, we should cover most STRIDE categories
        assert len(categories_found) >= 4


# ---------------------------------------------------------------------------
# analyze_pasta
# ---------------------------------------------------------------------------


class TestAnalyzePASTA:
    @pytest.mark.asyncio
    async def test_pasta_analysis(self, threat_skill):
        create = await _create_sample_model(threat_skill)
        model_id = create.data["model_id"]

        result = await threat_skill.execute({
            "action": "analyze_pasta",
            "model_id": model_id,
            "business_objectives": ["protect customer PII", "maintain uptime"],
        })
        assert result.success
        assert "stages" in result.data
        assert len(result.data["stages"]) == 7

    @pytest.mark.asyncio
    async def test_pasta_nonexistent_model(self, threat_skill):
        result = await threat_skill.execute({
            "action": "analyze_pasta",
            "model_id": "TM-nope",
        })
        assert not result.success


# ---------------------------------------------------------------------------
# identify_threats
# ---------------------------------------------------------------------------


class TestIdentifyThreats:
    @pytest.mark.asyncio
    async def test_identify_threats_for_component(self, threat_skill):
        result = await threat_skill.execute({
            "action": "identify_threats",
            "component_type": "web_application",
        })
        assert result.success
        assert result.data["total_threats"] >= 1
        for t in result.data["threats"]:
            assert "description" in t
            assert "stride_category" in t

    @pytest.mark.asyncio
    async def test_identify_threats_unknown_component(self, threat_skill):
        result = await threat_skill.execute({
            "action": "identify_threats",
            "component_type": "unknown_gadget",
        })
        assert result.success
        # Should fall back to default threats
        assert len(result.data["threats"]) >= 1


# ---------------------------------------------------------------------------
# generate_mitigations
# ---------------------------------------------------------------------------


class TestGenerateMitigations:
    @pytest.mark.asyncio
    async def test_generate_mitigations(self, threat_skill):
        # First identify threats so they exist in self.threats
        await threat_skill.execute({
            "action": "identify_threats",
            "component_type": "web_application",
        })
        result = await threat_skill.execute({
            "action": "generate_mitigations",
            "stride_category": "spoofing",
        })
        assert result.success
        assert "mitigations" in result.data
        assert result.data["total_mitigations"] >= 1


# ---------------------------------------------------------------------------
# assess_risk
# ---------------------------------------------------------------------------


class TestAssessRisk:
    @pytest.mark.asyncio
    async def test_assess_risk_model_based(self, threat_skill):
        create = await _create_sample_model(threat_skill, name="Risk Model")
        model_id = create.data["model_id"]
        await threat_skill.execute({"action": "analyze_stride", "model_id": model_id})

        result = await threat_skill.execute({
            "action": "assess_risk",
            "model_id": model_id,
        })
        assert result.success
        assert "risk_distribution" in result.data
        assert "overall_risk_percentage" in result.data

    @pytest.mark.asyncio
    async def test_assess_risk_requires_model(self, threat_skill):
        result = await threat_skill.execute({
            "action": "assess_risk",
            "threats": [{"threat": "XSS", "likelihood": 3, "impact": 3}],
        })
        # Without model_id, should fail
        assert not result.success


# ---------------------------------------------------------------------------
# generate_report
# ---------------------------------------------------------------------------


class TestThreatModelReport:
    @pytest.mark.asyncio
    async def test_generate_report(self, threat_skill):
        create = await _create_sample_model(threat_skill)
        model_id = create.data["model_id"]

        await threat_skill.execute({
            "action": "analyze_stride",
            "model_id": model_id,
        })
        result = await threat_skill.execute({
            "action": "generate_report",
            "model_id": model_id,
        })
        assert result.success
        assert "report" in result.data

    @pytest.mark.asyncio
    async def test_generate_report_nonexistent_model(self, threat_skill):
        result = await threat_skill.execute({
            "action": "generate_report",
            "model_id": "TM-nope",
        })
        assert not result.success


# ---------------------------------------------------------------------------
# Unknown Action
# ---------------------------------------------------------------------------


class TestThreatModelUnknownAction:
    @pytest.mark.asyncio
    async def test_unknown_action(self, threat_skill):
        result = await threat_skill.execute({"action": "nonexistent"})
        assert not result.success
        assert "Unknown action" in result.errors[0]
