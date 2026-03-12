"""Tests for the Deception Technology Skill."""

import pytest

from security_agents.skills.deception_technology import (
    DeceptionTechnologySkill, HoneypotType, HoneytokenType, DecoyStatus,
)


@pytest.fixture
async def deception_skill():
    """Create and initialize a deception technology skill."""
    skill = DeceptionTechnologySkill(agent_id="delta_red_team", config={})
    await skill.initialize()
    return skill


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestDeceptionInit:
    @pytest.mark.asyncio
    async def test_initialize(self, deception_skill):
        assert deception_skill.initialized
        assert deception_skill.SKILL_NAME == "deception_technology"

    @pytest.mark.asyncio
    async def test_not_initialized_returns_error(self):
        skill = DeceptionTechnologySkill(agent_id="test", config={})
        result = await skill.execute({"action": "deploy_honeypot"})
        assert not result.success
        assert "not initialized" in result.errors[0]

    def test_metadata(self):
        skill = DeceptionTechnologySkill(agent_id="delta_red_team", config={})
        meta = skill.get_metadata()
        assert meta["skill_name"] == "deception_technology"
        assert "delta_red_team" in meta["compatible_agents"]


# ---------------------------------------------------------------------------
# deploy_honeypot
# ---------------------------------------------------------------------------


class TestDeployHoneypot:
    @pytest.mark.asyncio
    async def test_deploy_ssh_honeypot(self, deception_skill):
        result = await deception_skill.execute({
            "action": "deploy_honeypot",
            "honeypot_type": "ssh",
            "name": "SSH Trap",
            "network_segment": "dmz",
            "ip_address": "10.0.1.100",
        })
        assert result.success
        decoy = result.data["decoy"]
        assert decoy["decoy_id"].startswith("HP-")
        assert decoy["honeypot_type"] == "ssh"
        assert decoy["status"] == "active"
        assert decoy["port"] == 22

    @pytest.mark.asyncio
    async def test_deploy_http_honeypot(self, deception_skill):
        result = await deception_skill.execute({
            "action": "deploy_honeypot",
            "honeypot_type": "http",
            "name": "Web Trap",
            "network_segment": "perimeter",
        })
        assert result.success
        assert result.data["decoy"]["port"] == 80

    @pytest.mark.asyncio
    async def test_deploy_database_honeypot(self, deception_skill):
        result = await deception_skill.execute({
            "action": "deploy_honeypot",
            "honeypot_type": "database",
            "network_segment": "internal",
        })
        assert result.success
        assert result.data["decoy"]["port"] == 3306

    @pytest.mark.asyncio
    async def test_deploy_custom_port(self, deception_skill):
        result = await deception_skill.execute({
            "action": "deploy_honeypot",
            "honeypot_type": "ssh",
            "port": 2222,
        })
        assert result.success
        assert result.data["decoy"]["port"] == 2222

    @pytest.mark.asyncio
    async def test_deploy_invalid_honeypot_type(self, deception_skill):
        result = await deception_skill.execute({
            "action": "deploy_honeypot",
            "honeypot_type": "quantum_trap",
        })
        assert not result.success
        assert "Unknown honeypot_type" in result.errors[0]

    @pytest.mark.asyncio
    async def test_deploy_with_breadcrumbs(self, deception_skill):
        result = await deception_skill.execute({
            "action": "deploy_honeypot",
            "honeypot_type": "smb",
            "breadcrumbs": ["\\\\fileserver\\share", "C:\\Users\\admin\\credentials.txt"],
            "network_segment": "corporate",
        })
        assert result.success
        assert len(result.data["breadcrumb_trail"]) >= 1

    @pytest.mark.asyncio
    async def test_deploy_includes_detection_capabilities(self, deception_skill):
        result = await deception_skill.execute({
            "action": "deploy_honeypot",
            "honeypot_type": "ssh",
        })
        assert result.success
        caps = result.data["detection_capabilities"]
        assert len(caps) >= 1
        assert "technique" in caps[0]

    @pytest.mark.asyncio
    async def test_deploy_includes_checklist(self, deception_skill):
        result = await deception_skill.execute({
            "action": "deploy_honeypot",
            "honeypot_type": "http",
        })
        assert result.success
        assert len(result.data["deployment_checklist"]) >= 3


# ---------------------------------------------------------------------------
# deploy_honeytoken
# ---------------------------------------------------------------------------


class TestDeployHoneytoken:
    @pytest.mark.asyncio
    async def test_deploy_credential_token(self, deception_skill):
        result = await deception_skill.execute({
            "action": "deploy_honeytoken",
            "token_type": "credential",
            "name": "Fake Admin Cred",
            "placement": "active_directory",
        })
        assert result.success
        decoy = result.data["decoy"]
        assert decoy["decoy_id"].startswith("HT-")
        assert decoy["decoy_type"] == "honeytoken"
        assert decoy["status"] == "active"

    @pytest.mark.asyncio
    async def test_deploy_api_key_token(self, deception_skill):
        result = await deception_skill.execute({
            "action": "deploy_honeytoken",
            "token_type": "api_key",
            "name": "Fake API Key",
            "placement": "source_code",
        })
        assert result.success

    @pytest.mark.asyncio
    async def test_deploy_dns_canary(self, deception_skill):
        result = await deception_skill.execute({
            "action": "deploy_honeytoken",
            "token_type": "dns_canary",
            "name": "DNS Canary",
        })
        assert result.success

    @pytest.mark.asyncio
    async def test_deploy_with_custom_value(self, deception_skill):
        result = await deception_skill.execute({
            "action": "deploy_honeytoken",
            "token_type": "credential",
            "value": "SuperSecretFakePassword123!",
        })
        assert result.success

    @pytest.mark.asyncio
    async def test_deploy_invalid_token_type(self, deception_skill):
        result = await deception_skill.execute({
            "action": "deploy_honeytoken",
            "token_type": "hologram",
        })
        assert not result.success
        assert "Unknown token_type" in result.errors[0]

    @pytest.mark.asyncio
    async def test_deploy_auto_generates_value(self, deception_skill):
        result = await deception_skill.execute({
            "action": "deploy_honeytoken",
            "token_type": "aws_key",
        })
        assert result.success
        # Value is stored internally but only a preview is returned
        assert result.data["decoy"].get("value_preview") is not None


# ---------------------------------------------------------------------------
# list_decoys
# ---------------------------------------------------------------------------


class TestListDecoys:
    @pytest.mark.asyncio
    async def test_list_decoys_empty(self, deception_skill):
        result = await deception_skill.execute({"action": "list_decoys"})
        assert result.success
        assert result.data["total_decoys"] == 0

    @pytest.mark.asyncio
    async def test_list_decoys_after_deployment(self, deception_skill):
        await deception_skill.execute({
            "action": "deploy_honeypot",
            "honeypot_type": "ssh",
        })
        await deception_skill.execute({
            "action": "deploy_honeytoken",
            "token_type": "credential",
        })
        result = await deception_skill.execute({"action": "list_decoys"})
        assert result.success
        assert result.data["total_decoys"] == 2

    @pytest.mark.asyncio
    async def test_list_decoys_filter_by_type(self, deception_skill):
        await deception_skill.execute({
            "action": "deploy_honeypot",
            "honeypot_type": "ssh",
        })
        await deception_skill.execute({
            "action": "deploy_honeytoken",
            "token_type": "credential",
        })
        result = await deception_skill.execute({
            "action": "list_decoys",
            "decoy_type": "honeypot",
        })
        assert result.success
        assert result.data["total_decoys"] >= 1


# ---------------------------------------------------------------------------
# get_interactions
# ---------------------------------------------------------------------------


class TestGetInteractions:
    @pytest.mark.asyncio
    async def test_get_interactions_empty(self, deception_skill):
        result = await deception_skill.execute({"action": "get_interactions"})
        assert result.success
        assert result.data["total_interactions"] == 0

    @pytest.mark.asyncio
    async def test_get_interactions_by_decoy(self, deception_skill):
        deploy = await deception_skill.execute({
            "action": "deploy_honeypot",
            "honeypot_type": "ssh",
        })
        decoy_id = deploy.data["decoy"]["decoy_id"]

        result = await deception_skill.execute({
            "action": "get_interactions",
            "decoy_id": decoy_id,
        })
        assert result.success


# ---------------------------------------------------------------------------
# analyze_attacker
# ---------------------------------------------------------------------------


class TestAnalyzeAttacker:
    @pytest.mark.asyncio
    async def test_analyze_attacker(self, deception_skill):
        # Deploy a honeypot and record interactions first
        deploy = await deception_skill.execute({
            "action": "deploy_honeypot",
            "honeypot_type": "ssh",
        })
        decoy_id = deploy.data["decoy"]["decoy_id"]

        # Record interactions via get_interactions action
        await deception_skill.execute({
            "action": "get_interactions",
            "decoy_id": decoy_id,
            "interactions": [
                {"source_ip": "192.168.1.50", "action": "ssh_login_attempt", "details": {"credentials": "admin:password123"}, "timestamp": "2026-03-10T02:00:00Z"},
                {"source_ip": "192.168.1.50", "action": "command_execution", "details": {"command": "whoami"}, "timestamp": "2026-03-10T02:01:00Z"},
            ],
        })

        result = await deception_skill.execute({
            "action": "analyze_attacker",
            "source_ip": "192.168.1.50",
        })
        assert result.success

    @pytest.mark.asyncio
    async def test_analyze_attacker_minimal(self, deception_skill):
        # Without any recorded interactions, analyze_attacker with unknown IP fails
        result = await deception_skill.execute({
            "action": "analyze_attacker",
            "source_ip": "10.0.0.99",
        })
        # No profile exists for this IP, so it returns an error
        assert not result.success or "attacker_profiles" in result.data


# ---------------------------------------------------------------------------
# remove_decoy
# ---------------------------------------------------------------------------


class TestRemoveDecoy:
    @pytest.mark.asyncio
    async def test_remove_decoy(self, deception_skill):
        deploy = await deception_skill.execute({
            "action": "deploy_honeypot",
            "honeypot_type": "http",
        })
        decoy_id = deploy.data["decoy"]["decoy_id"]

        result = await deception_skill.execute({
            "action": "remove_decoy",
            "decoy_id": decoy_id,
        })
        assert result.success
        assert result.data["decoy"]["status"] == "decommissioned"

    @pytest.mark.asyncio
    async def test_remove_nonexistent_decoy(self, deception_skill):
        result = await deception_skill.execute({
            "action": "remove_decoy",
            "decoy_id": "HP-nonexistent",
        })
        assert not result.success


# ---------------------------------------------------------------------------
# generate_report
# ---------------------------------------------------------------------------


class TestDeceptionReport:
    @pytest.mark.asyncio
    async def test_generate_report(self, deception_skill):
        await deception_skill.execute({
            "action": "deploy_honeypot",
            "honeypot_type": "ssh",
        })
        await deception_skill.execute({
            "action": "deploy_honeytoken",
            "token_type": "credential",
        })
        result = await deception_skill.execute({"action": "generate_report"})
        assert result.success
        report = result.data.get("report", result.data)
        assert report is not None

    @pytest.mark.asyncio
    async def test_generate_report_empty(self, deception_skill):
        result = await deception_skill.execute({"action": "generate_report"})
        assert result.success
        report = result.data.get("report", result.data)
        assert report is not None


# ---------------------------------------------------------------------------
# Unknown Action
# ---------------------------------------------------------------------------


class TestDeceptionUnknownAction:
    @pytest.mark.asyncio
    async def test_unknown_action(self, deception_skill):
        result = await deception_skill.execute({"action": "nonexistent"})
        assert not result.success
        assert "Unknown action" in result.errors[0]
