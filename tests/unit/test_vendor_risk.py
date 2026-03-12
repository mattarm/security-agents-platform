"""Tests for the Vendor Risk Skill."""

import pytest

from security_agents.skills.vendor_risk import VendorRiskSkill, VendorTier


@pytest.fixture
async def vendor_skill():
    """Create and initialize a vendor risk skill."""
    skill = VendorRiskSkill(agent_id="beta_4_devsecops", config={})
    await skill.initialize()
    return skill


async def _register_vendor(skill, name="Acme Corp", business_criticality="high", integration_type="api"):
    """Helper: register a sample vendor."""
    return await skill.execute({
        "action": "assess_vendor",
        "vendor_name": name,
        "data_types": ["pii", "financial"],
        "business_criticality": business_criticality,
        "integration_type": integration_type,
        "contract_end_date": "2027-01-01",
    })


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestVendorRiskInit:
    @pytest.mark.asyncio
    async def test_initialize(self, vendor_skill):
        assert vendor_skill.initialized
        assert vendor_skill.SKILL_NAME == "vendor_risk"

    @pytest.mark.asyncio
    async def test_not_initialized_returns_error(self):
        skill = VendorRiskSkill(agent_id="test", config={})
        result = await skill.execute({"action": "assess_vendor"})
        assert not result.success
        assert "not initialized" in result.errors[0]

    def test_metadata(self):
        skill = VendorRiskSkill(agent_id="beta_4_devsecops", config={})
        meta = skill.get_metadata()
        assert meta["skill_name"] == "vendor_risk"
        assert "beta_4_devsecops" in meta["compatible_agents"]


# ---------------------------------------------------------------------------
# assess_vendor
# ---------------------------------------------------------------------------


class TestAssessVendor:
    @pytest.mark.asyncio
    async def test_assess_basic(self, vendor_skill):
        result = await _register_vendor(vendor_skill)
        assert result.success
        assert "vendor" in result.data
        assert result.data["vendor"]["vendor_name"] == "Acme Corp"
        assert result.data["vendor"]["tier"] in ("critical", "high", "medium", "low")

    @pytest.mark.asyncio
    async def test_assess_critical_tier(self, vendor_skill):
        result = await _register_vendor(vendor_skill, name="Critical Vendor", business_criticality="critical")
        assert result.success
        assert result.data["vendor"]["tier"] == "critical"

    @pytest.mark.asyncio
    async def test_assess_vendor_missing_name(self, vendor_skill):
        result = await vendor_skill.execute({
            "action": "assess_vendor",
        })
        # Should succeed with generated ID or fail on missing name
        assert result.success or "vendor_name" in str(result.errors).lower()

    @pytest.mark.asyncio
    async def test_assess_multiple_vendors(self, vendor_skill):
        await _register_vendor(vendor_skill, name="Vendor A")
        await _register_vendor(vendor_skill, name="Vendor B")
        assert len(vendor_skill.vendors) >= 2


# ---------------------------------------------------------------------------
# create_questionnaire
# ---------------------------------------------------------------------------


class TestCreateQuestionnaire:
    @pytest.mark.asyncio
    async def test_create_questionnaire_security(self, vendor_skill):
        result = await vendor_skill.execute({
            "action": "create_questionnaire",
            "domains": ["security"],
        })
        assert result.success
        assert "assessment" in result.data or "questionnaire_summary" in result.data

    @pytest.mark.asyncio
    async def test_create_questionnaire_all_domains(self, vendor_skill):
        result = await vendor_skill.execute({
            "action": "create_questionnaire",
            "domains": ["security", "privacy", "compliance", "financial", "operational", "reputational"],
        })
        assert result.success

    @pytest.mark.asyncio
    async def test_create_questionnaire_for_vendor_tier(self, vendor_skill):
        create = await _register_vendor(vendor_skill, name="Tier Test", business_criticality="critical")
        vendor_id = create.data["vendor"]["vendor_id"]
        result = await vendor_skill.execute({
            "action": "create_questionnaire",
            "vendor_id": vendor_id,
            "tier": "critical",
        })
        assert result.success


# ---------------------------------------------------------------------------
# score_risk
# ---------------------------------------------------------------------------


class TestScoreRisk:
    @pytest.mark.asyncio
    async def test_score_risk_basic(self, vendor_skill):
        create = await _register_vendor(vendor_skill)
        vendor_id = create.data["vendor"]["vendor_id"]

        result = await vendor_skill.execute({
            "action": "score_risk",
            "vendor_id": vendor_id,
            "responses": {
                "SEC-001": {"answer": True, "score": 4},
                "SEC-002": {"answer": True, "score": 5},
                "SEC-003": {"answer": False, "score": 1},
            },
        })
        assert result.success

    @pytest.mark.asyncio
    async def test_score_risk_nonexistent_vendor(self, vendor_skill):
        result = await vendor_skill.execute({
            "action": "score_risk",
            "vendor_id": "V-nonexistent",
            "responses": {},
        })
        assert not result.success

    @pytest.mark.asyncio
    async def test_score_risk_all_positive(self, vendor_skill):
        create = await _register_vendor(vendor_skill, name="Good Vendor")
        vendor_id = create.data["vendor"]["vendor_id"]

        result = await vendor_skill.execute({
            "action": "score_risk",
            "vendor_id": vendor_id,
            "responses": {
                "SEC-001": {"answer": True, "score": 5},
                "SEC-002": {"answer": True, "score": 5},
                "SEC-003": {"answer": True, "score": 5},
            },
        })
        assert result.success


# ---------------------------------------------------------------------------
# track_remediation
# ---------------------------------------------------------------------------


class TestTrackRemediation:
    @pytest.mark.asyncio
    async def test_track_remediation(self, vendor_skill):
        create = await _register_vendor(vendor_skill)
        vendor_id = create.data["vendor"]["vendor_id"]

        result = await vendor_skill.execute({
            "action": "track_remediation",
            "vendor_id": vendor_id,
            "finding": "Missing encryption at rest",
            "severity": "high",
            "due_date": "2026-06-01",
            "status": "open",
        })
        assert result.success
        assert "remediation" in result.data

    @pytest.mark.asyncio
    async def test_track_remediation_update_status(self, vendor_skill):
        create = await _register_vendor(vendor_skill, name="Remediate Me")
        vendor_id = create.data["vendor"]["vendor_id"]

        first = await vendor_skill.execute({
            "action": "track_remediation",
            "vendor_id": vendor_id,
            "finding": "No MFA",
            "severity": "critical",
            "status": "open",
        })
        assert first.success

        # Update to completed
        remediation = first.data.get("remediation", {})
        assert "remediation_id" in remediation
        result = await vendor_skill.execute({
            "action": "track_remediation",
            "vendor_id": vendor_id,
            "remediation_action": "update",
            "remediation_id": remediation["remediation_id"],
            "status": "completed",
        })
        assert result.success


# ---------------------------------------------------------------------------
# list_vendors
# ---------------------------------------------------------------------------


class TestListVendors:
    @pytest.mark.asyncio
    async def test_list_vendors_empty(self, vendor_skill):
        result = await vendor_skill.execute({"action": "list_vendors"})
        assert result.success
        assert result.data["total_vendors"] == 0

    @pytest.mark.asyncio
    async def test_list_vendors_after_creation(self, vendor_skill):
        await _register_vendor(vendor_skill, name="V1")
        await _register_vendor(vendor_skill, name="V2")
        result = await vendor_skill.execute({"action": "list_vendors"})
        assert result.success
        assert result.data["total_vendors"] >= 2


# ---------------------------------------------------------------------------
# compare_vendors
# ---------------------------------------------------------------------------


class TestCompareVendors:
    @pytest.mark.asyncio
    async def test_compare_vendors(self, vendor_skill):
        v1 = await _register_vendor(vendor_skill, name="Vendor Alpha")
        v2 = await _register_vendor(vendor_skill, name="Vendor Beta")

        result = await vendor_skill.execute({
            "action": "compare_vendors",
            "vendor_ids": [v1.data["vendor"]["vendor_id"], v2.data["vendor"]["vendor_id"]],
        })
        assert result.success


# ---------------------------------------------------------------------------
# generate_report
# ---------------------------------------------------------------------------


class TestVendorReport:
    @pytest.mark.asyncio
    async def test_generate_report(self, vendor_skill):
        await _register_vendor(vendor_skill, name="Report Vendor")
        result = await vendor_skill.execute({"action": "generate_report"})
        assert result.success
        assert "report" in result.data


# ---------------------------------------------------------------------------
# Unknown Action
# ---------------------------------------------------------------------------


class TestVendorUnknownAction:
    @pytest.mark.asyncio
    async def test_unknown_action(self, vendor_skill):
        result = await vendor_skill.execute({"action": "nonexistent"})
        assert not result.success
        assert "Unknown action" in result.errors[0]
