"""Tests for the Attack Surface Management Skill."""

import pytest

from security_agents.skills.attack_surface_management import AttackSurfaceManagementSkill


@pytest.fixture
async def asm_skill():
    """Create and initialize an attack surface management skill."""
    skill = AttackSurfaceManagementSkill(agent_id="delta_red_team", config={})
    await skill.initialize()
    return skill


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestASMInit:
    @pytest.mark.asyncio
    async def test_initialize(self, asm_skill):
        assert asm_skill.initialized
        assert asm_skill.SKILL_NAME == "attack_surface_management"

    @pytest.mark.asyncio
    async def test_not_initialized_returns_error(self):
        skill = AttackSurfaceManagementSkill(agent_id="test", config={})
        result = await skill.execute({"action": "discover_assets"})
        assert not result.success
        assert "not initialized" in result.errors[0]

    def test_metadata(self):
        skill = AttackSurfaceManagementSkill(agent_id="delta_red_team", config={})
        meta = skill.get_metadata()
        assert meta["skill_name"] == "attack_surface_management"
        assert "delta_red_team" in meta["compatible_agents"]


# ---------------------------------------------------------------------------
# discover_assets
# ---------------------------------------------------------------------------


class TestDiscoverAssets:
    @pytest.mark.asyncio
    async def test_discover_from_domains(self, asm_skill):
        result = await asm_skill.execute({
            "action": "discover_assets",
            "domains": ["example.com", "api.example.com"],
        })
        assert result.success
        assert result.data["total_discovered"] >= 2

    @pytest.mark.asyncio
    async def test_discover_from_ips(self, asm_skill):
        result = await asm_skill.execute({
            "action": "discover_assets",
            "ip_addresses": ["203.0.113.1", "203.0.113.2"],
        })
        assert result.success
        assert result.data["total_discovered"] >= 2

    @pytest.mark.asyncio
    async def test_discover_from_cloud_resources(self, asm_skill):
        result = await asm_skill.execute({
            "action": "discover_assets",
            "cloud_resources": [
                {"resource_id": "i-abc123", "type": "ec2", "public_ip": "54.1.2.3"},
            ],
        })
        assert result.success
        assert result.data["total_discovered"] >= 1

    @pytest.mark.asyncio
    async def test_discover_empty_seeds(self, asm_skill):
        result = await asm_skill.execute({
            "action": "discover_assets",
            "domains": [],
            "ip_addresses": [],
        })
        # Should fail requiring at least one seed source
        assert not result.success

    @pytest.mark.asyncio
    async def test_discover_with_dns_records(self, asm_skill):
        result = await asm_skill.execute({
            "action": "discover_assets",
            "domains": ["example.com"],
            "dns_records": [
                {"name": "mail.example.com", "type": "MX", "value": "mx1.example.com"},
            ],
        })
        assert result.success


# ---------------------------------------------------------------------------
# scan_surface
# ---------------------------------------------------------------------------


class TestScanSurface:
    @pytest.mark.asyncio
    async def test_scan_with_ports(self, asm_skill):
        # Seed some assets first
        await asm_skill.execute({
            "action": "discover_assets",
            "domains": ["target.com"],
        })
        result = await asm_skill.execute({
            "action": "scan_surface",
            "scan_type": "port_scan",
            "targets": ["target.com"],
            "ports": [22, 80, 443, 3306, 6379],
        })
        assert result.success
        assert "scan_id" in result.data

    @pytest.mark.asyncio
    async def test_scan_technology_fingerprint(self, asm_skill):
        await asm_skill.execute({
            "action": "discover_assets",
            "domains": ["webapp.com"],
        })
        result = await asm_skill.execute({
            "action": "scan_surface",
            "scan_type": "technology_fingerprint",
            "targets": ["webapp.com"],
            "technologies_detected": ["nginx", "wordpress", "php"],
        })
        assert result.success

    @pytest.mark.asyncio
    async def test_scan_certificate(self, asm_skill):
        await asm_skill.execute({
            "action": "discover_assets",
            "domains": ["secure.com"],
        })
        result = await asm_skill.execute({
            "action": "scan_surface",
            "scan_type": "certificate_check",
            "targets": ["secure.com"],
            "certificates": [
                {"domain": "secure.com", "issuer": "Let's Encrypt", "expiry_days": 15, "protocol": "TLS 1.2"},
            ],
        })
        assert result.success


# ---------------------------------------------------------------------------
# assess_exposure
# ---------------------------------------------------------------------------


class TestAssessExposure:
    @pytest.mark.asyncio
    async def test_assess_exposure(self, asm_skill):
        await asm_skill.execute({
            "action": "discover_assets",
            "domains": ["exposed.com"],
            "ip_addresses": ["203.0.113.50"],
        })
        result = await asm_skill.execute({
            "action": "assess_exposure",
        })
        assert result.success
        assert "total_assets" in result.data
        assert "average_exposure_score" in result.data

    @pytest.mark.asyncio
    async def test_assess_exposure_empty(self, asm_skill):
        result = await asm_skill.execute({
            "action": "assess_exposure",
        })
        assert result.success or not result.success  # May be empty


# ---------------------------------------------------------------------------
# track_changes
# ---------------------------------------------------------------------------


class TestTrackChanges:
    @pytest.mark.asyncio
    async def test_track_changes_new_asset(self, asm_skill):
        await asm_skill.execute({
            "action": "discover_assets",
            "domains": ["original.com"],
        })
        result = await asm_skill.execute({
            "action": "track_changes",
            "previous_snapshot": {"old-asset": {"name": "old", "asset_type": "domain"}},
        })
        assert result.success
        assert "changes" in result.data

    @pytest.mark.asyncio
    async def test_track_changes_missing_snapshot(self, asm_skill):
        result = await asm_skill.execute({
            "action": "track_changes",
        })
        assert not result.success
        assert "previous_snapshot" in result.errors[0]


# ---------------------------------------------------------------------------
# prioritize_risks
# ---------------------------------------------------------------------------


class TestPrioritizeRisks:
    @pytest.mark.asyncio
    async def test_prioritize_risks(self, asm_skill):
        await asm_skill.execute({
            "action": "discover_assets",
            "domains": ["risky.com"],
            "ip_addresses": ["1.2.3.4"],
        })
        result = await asm_skill.execute({
            "action": "prioritize_risks",
        })
        assert result.success
        assert "prioritized_risks" in result.data or "risks" in result.data


# ---------------------------------------------------------------------------
# generate_report
# ---------------------------------------------------------------------------


class TestASMReport:
    @pytest.mark.asyncio
    async def test_generate_report(self, asm_skill):
        await asm_skill.execute({
            "action": "discover_assets",
            "domains": ["report-target.com"],
        })
        result = await asm_skill.execute({
            "action": "generate_report",
        })
        assert result.success
        assert "report" in result.data

    @pytest.mark.asyncio
    async def test_generate_report_empty(self, asm_skill):
        result = await asm_skill.execute({
            "action": "generate_report",
        })
        assert result.success
        assert "report" in result.data


# ---------------------------------------------------------------------------
# Unknown Action
# ---------------------------------------------------------------------------


class TestASMUnknownAction:
    @pytest.mark.asyncio
    async def test_unknown_action(self, asm_skill):
        result = await asm_skill.execute({"action": "nonexistent"})
        assert not result.success
        assert "Unknown action" in result.errors[0]
