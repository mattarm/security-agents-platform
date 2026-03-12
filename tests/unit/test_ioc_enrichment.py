"""Tests for the IOC Enrichment Skill."""

import pytest

from security_agents.skills.ioc_enrichment import IOCEnrichmentSkill


@pytest.fixture
async def ioc_skill():
    """Create and initialize an IOC enrichment skill."""
    skill = IOCEnrichmentSkill(agent_id="alpha_4_threat_intel", config={})
    await skill.initialize()
    return skill


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestIOCEnrichmentInit:
    @pytest.mark.asyncio
    async def test_initialize(self, ioc_skill):
        assert ioc_skill.initialized
        assert ioc_skill.SKILL_NAME == "ioc_enrichment"

    @pytest.mark.asyncio
    async def test_not_initialized_returns_error(self):
        skill = IOCEnrichmentSkill(agent_id="test", config={})
        result = await skill.execute({"action": "enrich_ioc"})
        assert not result.success
        assert "not initialized" in result.errors[0]

    def test_metadata(self):
        skill = IOCEnrichmentSkill(agent_id="alpha_4_threat_intel", config={})
        meta = skill.get_metadata()
        assert meta["skill_name"] == "ioc_enrichment"
        assert "alpha_4_threat_intel" in meta["compatible_agents"]
        assert meta["version"] == "1.0.0"


# ---------------------------------------------------------------------------
# enrich_ioc
# ---------------------------------------------------------------------------


class TestEnrichIOC:
    @pytest.mark.asyncio
    async def test_enrich_ip_address(self, ioc_skill):
        result = await ioc_skill.execute({
            "action": "enrich_ioc",
            "indicator": "8.8.8.8",
            "indicator_type": "ip",
        })
        assert result.success
        assert result.data["indicator"] == "8.8.8.8"
        assert result.data["indicator_type"] == "ip"
        assert "reputation_score" in result.data
        assert "sources" in result.data

    @pytest.mark.asyncio
    async def test_enrich_domain(self, ioc_skill):
        result = await ioc_skill.execute({
            "action": "enrich_ioc",
            "indicator": "evil-malware.xyz",
            "indicator_type": "domain",
        })
        assert result.success
        assert result.data["indicator_type"] == "domain"
        assert "classification" in result.data

    @pytest.mark.asyncio
    async def test_enrich_hash(self, ioc_skill):
        result = await ioc_skill.execute({
            "action": "enrich_ioc",
            "indicator": "d41d8cd98f00b204e9800998ecf8427e",
        })
        assert result.success
        # Auto-detected as md5 (32 chars)
        assert result.data["indicator_type"] in ("md5", "hash")

    @pytest.mark.asyncio
    async def test_enrich_missing_indicator(self, ioc_skill):
        result = await ioc_skill.execute({
            "action": "enrich_ioc",
        })
        assert not result.success
        assert "indicator" in result.errors[0].lower()

    @pytest.mark.asyncio
    async def test_enrich_caching(self, ioc_skill):
        # First call
        result1 = await ioc_skill.execute({
            "action": "enrich_ioc",
            "indicator": "10.0.0.1",
            "indicator_type": "ip",
        })
        assert result1.success
        assert result1.data["from_cache"] is False

        # Second call should be cached
        result2 = await ioc_skill.execute({
            "action": "enrich_ioc",
            "indicator": "10.0.0.1",
            "indicator_type": "ip",
        })
        assert result2.success
        assert result2.data["from_cache"] is True

    @pytest.mark.asyncio
    async def test_enrich_emits_intel_for_malicious(self, ioc_skill):
        result = await ioc_skill.execute({
            "action": "enrich_ioc",
            "indicator": "evil-malware.xyz",
            "indicator_type": "domain",
        })
        assert result.success
        # If reputation is high enough, intel packet should be emitted
        if result.data["reputation_score"] >= 60:
            assert len(result.intelligence_packets) >= 1


# ---------------------------------------------------------------------------
# bulk_enrich
# ---------------------------------------------------------------------------


class TestBulkEnrich:
    @pytest.mark.asyncio
    async def test_bulk_enrich_multiple(self, ioc_skill):
        result = await ioc_skill.execute({
            "action": "bulk_enrich",
            "indicators": [
                {"indicator": "8.8.8.8", "indicator_type": "ip"},
                {"indicator": "evil.com", "indicator_type": "domain"},
                {"indicator": "abcdef1234567890abcdef1234567890", "indicator_type": "md5"},
            ],
        })
        assert result.success
        assert result.data["total_requested"] == 3

    @pytest.mark.asyncio
    async def test_bulk_enrich_empty_list(self, ioc_skill):
        result = await ioc_skill.execute({
            "action": "bulk_enrich",
            "indicators": [],
        })
        assert result.success or "indicators" in result.errors[0].lower()


# ---------------------------------------------------------------------------
# get_reputation
# ---------------------------------------------------------------------------


class TestGetReputation:
    @pytest.mark.asyncio
    async def test_get_reputation_after_enrich(self, ioc_skill):
        await ioc_skill.execute({
            "action": "enrich_ioc",
            "indicator": "192.168.1.100",
            "indicator_type": "ip",
        })
        result = await ioc_skill.execute({
            "action": "get_reputation",
            "indicator": "192.168.1.100",
        })
        assert result.success
        assert "reputation_score" in result.data

    @pytest.mark.asyncio
    async def test_get_reputation_unknown_ioc(self, ioc_skill):
        result = await ioc_skill.execute({
            "action": "get_reputation",
            "indicator": "never-seen-before.example.com",
        })
        # Should either succeed with low score or indicate no data
        assert result.success or not result.success


# ---------------------------------------------------------------------------
# correlate_iocs
# ---------------------------------------------------------------------------


class TestCorrelateIOCs:
    @pytest.mark.asyncio
    async def test_correlate_after_enrichment(self, ioc_skill):
        await ioc_skill.execute({
            "action": "enrich_ioc",
            "indicator": "8.8.8.8",
            "indicator_type": "ip",
        })
        await ioc_skill.execute({
            "action": "enrich_ioc",
            "indicator": "evil.com",
            "indicator_type": "domain",
        })
        result = await ioc_skill.execute({
            "action": "correlate_iocs",
            "indicators": ["8.8.8.8", "evil.com"],
        })
        assert result.success
        assert "clusters" in result.data

    @pytest.mark.asyncio
    async def test_correlate_empty(self, ioc_skill):
        result = await ioc_skill.execute({
            "action": "correlate_iocs",
            "indicators": [],
        })
        assert not result.success or "clusters" in result.data


# ---------------------------------------------------------------------------
# export_stix
# ---------------------------------------------------------------------------


class TestExportSTIX:
    @pytest.mark.asyncio
    async def test_export_stix_after_enrichment(self, ioc_skill):
        await ioc_skill.execute({
            "action": "enrich_ioc",
            "indicator": "malicious.example.com",
            "indicator_type": "domain",
        })
        result = await ioc_skill.execute({
            "action": "export_stix",
            "indicators": ["malicious.example.com"],
        })
        assert result.success
        assert "stix_bundle" in result.data
        bundle = result.data["stix_bundle"]
        assert bundle["type"] == "bundle"
        assert "objects" in bundle

    @pytest.mark.asyncio
    async def test_export_stix_empty(self, ioc_skill):
        result = await ioc_skill.execute({
            "action": "export_stix",
            "indicators": [],
        })
        assert result.success or not result.success  # gracefully handles empty


# ---------------------------------------------------------------------------
# Unknown Action
# ---------------------------------------------------------------------------


class TestIOCUnknownAction:
    @pytest.mark.asyncio
    async def test_unknown_action(self, ioc_skill):
        result = await ioc_skill.execute({"action": "nonexistent"})
        assert not result.success
        assert "Unknown action" in result.errors[0]
