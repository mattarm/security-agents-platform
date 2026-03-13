"""Tests for the SIEM Rule Management Skill."""

import pytest

from security_agents.skills.siem_rule_management import SIEMRuleManagementSkill, RuleStatus


@pytest.fixture
async def siem_skill():
    """Create and initialize a SIEM rule management skill."""
    skill = SIEMRuleManagementSkill(agent_id="gamma_blue_team", config={})
    await skill.initialize()
    return skill


async def _create_sample_rule(skill, name="Test Rule", techniques=None):
    """Helper to create a sample detection rule."""
    return await skill.execute({
        "action": "create_rule",
        "title": name,
        "description": "Detect suspicious PowerShell execution",
        "logsource": {"product": "windows", "service": "powershell"},
        "detection": {
            "selection": {"EventID": 4104, "ScriptBlockText|contains": "Invoke-Mimikatz"},
            "condition": "selection",
        },
        "level": "high",
        "mitre_techniques": techniques or ["T1059.001"],
        "author": "test_analyst",
    })


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestSIEMRuleInit:
    @pytest.mark.asyncio
    async def test_initialize(self, siem_skill):
        assert siem_skill.initialized
        assert siem_skill.SKILL_NAME == "siem_rule_management"

    @pytest.mark.asyncio
    async def test_not_initialized_returns_error(self):
        skill = SIEMRuleManagementSkill(agent_id="test", config={})
        result = await skill.execute({"action": "list_rules"})
        assert not result.success
        assert "not initialized" in result.errors[0]

    def test_metadata(self):
        skill = SIEMRuleManagementSkill(agent_id="gamma_blue_team", config={})
        meta = skill.get_metadata()
        assert meta["skill_name"] == "siem_rule_management"
        assert "gamma_blue_team" in meta["compatible_agents"]


# ---------------------------------------------------------------------------
# create_rule
# ---------------------------------------------------------------------------


class TestCreateRule:
    @pytest.mark.asyncio
    async def test_create_rule_basic(self, siem_skill):
        result = await _create_sample_rule(siem_skill)
        assert result.success
        assert "rule_id" in result.data
        assert result.data["rule"]["status"] == "draft"
        assert result.data["rule"]["title"] == "Test Rule"

    @pytest.mark.asyncio
    async def test_create_rule_missing_title(self, siem_skill):
        result = await siem_skill.execute({
            "action": "create_rule",
            "logsource": {"product": "windows"},
            "detection": {"selection": {"EventID": 1}, "condition": "selection"},
        })
        # Should still succeed with generated title, or fail if title required
        assert result.success or "title" in str(result.errors).lower()

    @pytest.mark.asyncio
    async def test_create_rule_with_mitre_mapping(self, siem_skill):
        result = await _create_sample_rule(siem_skill, techniques=["T1059.001", "T1003"])
        assert result.success
        assert "T1059.001" in result.data["rule"]["mitre_techniques"]


# ---------------------------------------------------------------------------
# validate_rule
# ---------------------------------------------------------------------------


class TestValidateRule:
    @pytest.mark.asyncio
    async def test_validate_valid_rule(self, siem_skill):
        create = await _create_sample_rule(siem_skill)
        rule_id = create.data["rule_id"]

        result = await siem_skill.execute({
            "action": "validate_rule",
            "rule_id": rule_id,
        })
        assert result.success
        assert result.data["validation"]["valid"] is True

    @pytest.mark.asyncio
    async def test_validate_nonexistent_rule(self, siem_skill):
        result = await siem_skill.execute({
            "action": "validate_rule",
            "rule_id": "RULE-nonexistent",
        })
        assert not result.success

    @pytest.mark.asyncio
    async def test_validate_rule_inline(self, siem_skill):
        result = await siem_skill.execute({
            "action": "validate_rule",
            "rule": {
                "title": "Inline Test Rule",
                "logsource": {"product": "windows"},
                "detection": {"selection": {"EventID": 1}, "condition": "selection"},
            },
        })
        assert result.success


# ---------------------------------------------------------------------------
# test_rule
# ---------------------------------------------------------------------------


class TestTestRule:
    @pytest.mark.asyncio
    async def test_test_rule_with_events(self, siem_skill):
        create = await _create_sample_rule(siem_skill)
        rule_id = create.data["rule_id"]

        result = await siem_skill.execute({
            "action": "test_rule",
            "rule_id": rule_id,
            "test_events": [
                {"EventID": 4104, "ScriptBlockText": "Invoke-Mimikatz -Command privilege::debug"},
                {"EventID": 4104, "ScriptBlockText": "Get-Process"},
            ],
        })
        assert result.success


# ---------------------------------------------------------------------------
# deploy_rule / disable_rule
# ---------------------------------------------------------------------------


class TestDeployDisableRule:
    @pytest.mark.asyncio
    async def test_deploy_rule(self, siem_skill):
        create = await _create_sample_rule(siem_skill)
        rule_id = create.data["rule_id"]

        # Deploy with force=True since rule is in draft status
        result = await siem_skill.execute({
            "action": "deploy_rule",
            "rule_id": rule_id,
            "force": True,
        })
        assert result.success

    @pytest.mark.asyncio
    async def test_disable_rule(self, siem_skill):
        create = await _create_sample_rule(siem_skill)
        rule_id = create.data["rule_id"]

        await siem_skill.execute({"action": "deploy_rule", "rule_id": rule_id, "force": True})

        result = await siem_skill.execute({
            "action": "disable_rule",
            "rule_id": rule_id,
            "reason": "Too many false positives",
        })
        assert result.success
        assert result.data["status"] == "disabled"

    @pytest.mark.asyncio
    async def test_deploy_nonexistent_rule(self, siem_skill):
        result = await siem_skill.execute({
            "action": "deploy_rule",
            "rule_id": "RULE-nope",
        })
        assert not result.success


# ---------------------------------------------------------------------------
# list_rules
# ---------------------------------------------------------------------------


class TestListRules:
    @pytest.mark.asyncio
    async def test_list_rules_empty(self, siem_skill):
        result = await siem_skill.execute({"action": "list_rules"})
        assert result.success
        assert result.data["total"] == 0

    @pytest.mark.asyncio
    async def test_list_rules_after_creation(self, siem_skill):
        await _create_sample_rule(siem_skill, name="Rule A")
        await _create_sample_rule(siem_skill, name="Rule B")
        result = await siem_skill.execute({"action": "list_rules"})
        assert result.success
        assert result.data["total"] >= 2


# ---------------------------------------------------------------------------
# tune_rule
# ---------------------------------------------------------------------------


class TestTuneRule:
    @pytest.mark.asyncio
    async def test_tune_rule(self, siem_skill):
        create = await _create_sample_rule(siem_skill)
        rule_id = create.data["rule_id"]

        result = await siem_skill.execute({
            "action": "tune_rule",
            "rule_id": rule_id,
            "adjustments": {
                "add_exclusions": ["ScriptBlockText|contains: 'legitimate-tool'"],
                "threshold": 5,
            },
        })
        assert result.success

    @pytest.mark.asyncio
    async def test_tune_nonexistent_rule(self, siem_skill):
        result = await siem_skill.execute({
            "action": "tune_rule",
            "rule_id": "RULE-nope",
            "adjustments": {},
        })
        assert not result.success


# ---------------------------------------------------------------------------
# get_coverage / generate_report
# ---------------------------------------------------------------------------


class TestCoverageAndReport:
    @pytest.mark.asyncio
    async def test_get_coverage(self, siem_skill):
        create = await _create_sample_rule(siem_skill, techniques=["T1059.001", "T1003"])
        rule_id = create.data["rule_id"]
        # Deploy the rule so it counts as active coverage
        await siem_skill.execute({"action": "deploy_rule", "rule_id": rule_id, "force": True})
        result = await siem_skill.execute({"action": "get_coverage"})
        assert result.success
        assert "techniques_covered" in result.data
        assert result.data["techniques_covered"] >= 1

    @pytest.mark.asyncio
    async def test_get_coverage_gaps(self, siem_skill):
        result = await siem_skill.execute({"action": "get_coverage"})
        assert result.success
        assert "gap_count" in result.data

    @pytest.mark.asyncio
    async def test_generate_report(self, siem_skill):
        await _create_sample_rule(siem_skill)
        result = await siem_skill.execute({"action": "generate_report"})
        assert result.success
        assert "report" in result.data


# ---------------------------------------------------------------------------
# Unknown Action
# ---------------------------------------------------------------------------


class TestSIEMUnknownAction:
    @pytest.mark.asyncio
    async def test_unknown_action(self, siem_skill):
        result = await siem_skill.execute({"action": "nonexistent"})
        assert not result.success
        assert "Unknown action" in result.errors[0]
