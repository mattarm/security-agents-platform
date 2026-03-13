"""Tests for the Slack War Room Skill."""

import pytest

from security_agents.skills.slack_war_room import SlackWarRoomSkill, WAR_ROOM_TYPES


@pytest.fixture
async def war_room_skill():
    """Create and initialize a slack war room skill."""
    skill = SlackWarRoomSkill(agent_id="gamma_blue_team", config={})
    await skill.initialize()
    return skill


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestSlackWarRoomInit:
    @pytest.mark.asyncio
    async def test_initialize(self, war_room_skill):
        assert war_room_skill.initialized
        assert war_room_skill.SKILL_NAME == "slack_war_room"

    @pytest.mark.asyncio
    async def test_not_initialized_returns_error(self):
        skill = SlackWarRoomSkill(agent_id="test", config={})
        result = await skill.execute({"action": "create_war_room"})
        assert not result.success
        assert "not initialized" in result.errors[0]

    def test_metadata(self):
        skill = SlackWarRoomSkill(agent_id="gamma_blue_team", config={})
        meta = skill.get_metadata()
        assert meta["skill_name"] == "slack_war_room"
        assert "gamma_blue_team" in meta["compatible_agents"]


# ---------------------------------------------------------------------------
# create_war_room
# ---------------------------------------------------------------------------


class TestCreateWarRoom:
    @pytest.mark.asyncio
    async def test_create_basic(self, war_room_skill):
        result = await war_room_skill.execute({
            "action": "create_war_room",
            "incident_id": "INC-001",
            "title": "Ransomware Attack",
            "severity": "critical",
        })
        assert result.success
        assert result.data["room_id"].startswith("WR-")
        assert result.data["incident_id"] == "INC-001"
        assert result.data["status"] == "active"
        assert result.data["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_create_with_responders(self, war_room_skill):
        result = await war_room_skill.execute({
            "action": "create_war_room",
            "title": "Test Incident",
            "responders": ["analyst1", "analyst2"],
        })
        assert result.success
        assert "analyst1" in result.data["responders"]
        assert "analyst2" in result.data["responders"]

    @pytest.mark.asyncio
    async def test_create_critical_emits_intel_packet(self, war_room_skill):
        result = await war_room_skill.execute({
            "action": "create_war_room",
            "title": "Critical Breach",
            "severity": "critical",
        })
        assert result.success
        assert len(result.intelligence_packets) == 1
        assert result.intelligence_packets[0].source_agent == "gamma_blue_team"

    @pytest.mark.asyncio
    async def test_create_low_severity_no_intel_packet(self, war_room_skill):
        result = await war_room_skill.execute({
            "action": "create_war_room",
            "title": "Minor Issue",
            "severity": "low",
        })
        assert result.success
        assert len(result.intelligence_packets) == 0

    @pytest.mark.asyncio
    async def test_create_invalid_room_type(self, war_room_skill):
        result = await war_room_skill.execute({
            "action": "create_war_room",
            "title": "Test",
            "room_type": "invalid_type",
        })
        assert not result.success
        assert "Invalid room_type" in result.errors[0]

    @pytest.mark.asyncio
    async def test_channel_name_format(self, war_room_skill):
        result = await war_room_skill.execute({
            "action": "create_war_room",
            "incident_id": "INC-TEST-42",
            "title": "Test",
        })
        assert result.success
        assert "war-room-inc-test-42" in result.data["channel_name"]


# ---------------------------------------------------------------------------
# post_update
# ---------------------------------------------------------------------------


class TestPostUpdate:
    @pytest.mark.asyncio
    async def test_post_update(self, war_room_skill):
        create = await war_room_skill.execute({
            "action": "create_war_room",
            "title": "Incident",
        })
        room_id = create.data["room_id"]

        result = await war_room_skill.execute({
            "action": "post_update",
            "room_id": room_id,
            "message": "Containment in progress",
            "update_type": "containment",
        })
        assert result.success

    @pytest.mark.asyncio
    async def test_post_update_nonexistent_room(self, war_room_skill):
        result = await war_room_skill.execute({
            "action": "post_update",
            "room_id": "WR-nonexistent",
            "message": "Hello",
        })
        assert not result.success
        assert "not found" in result.errors[0]

    @pytest.mark.asyncio
    async def test_post_update_archived_room(self, war_room_skill):
        create = await war_room_skill.execute({
            "action": "create_war_room",
            "title": "Archive Test",
        })
        room_id = create.data["room_id"]

        await war_room_skill.execute({
            "action": "archive_room",
            "room_id": room_id,
        })
        result = await war_room_skill.execute({
            "action": "post_update",
            "room_id": room_id,
            "message": "Should fail",
        })
        assert not result.success
        assert "archived" in result.errors[0].lower()


# ---------------------------------------------------------------------------
# escalate
# ---------------------------------------------------------------------------


class TestEscalate:
    @pytest.mark.asyncio
    async def test_escalate_increments_tier(self, war_room_skill):
        create = await war_room_skill.execute({
            "action": "create_war_room",
            "title": "Escalation Test",
        })
        room_id = create.data["room_id"]

        result = await war_room_skill.execute({
            "action": "escalate",
            "room_id": room_id,
            "reason": "No response from tier 0",
        })
        assert result.success
        assert result.data["new_tier"] >= 1

    @pytest.mark.asyncio
    async def test_escalate_nonexistent_room(self, war_room_skill):
        result = await war_room_skill.execute({
            "action": "escalate",
            "room_id": "WR-nope",
        })
        assert not result.success


# ---------------------------------------------------------------------------
# add_responders
# ---------------------------------------------------------------------------


class TestAddResponders:
    @pytest.mark.asyncio
    async def test_add_responders(self, war_room_skill):
        create = await war_room_skill.execute({
            "action": "create_war_room",
            "title": "Responder Test",
        })
        room_id = create.data["room_id"]

        result = await war_room_skill.execute({
            "action": "add_responders",
            "room_id": room_id,
            "responders": ["new_analyst", "ir_lead"],
        })
        assert result.success


# ---------------------------------------------------------------------------
# archive_room
# ---------------------------------------------------------------------------


class TestArchiveRoom:
    @pytest.mark.asyncio
    async def test_archive_room(self, war_room_skill):
        create = await war_room_skill.execute({
            "action": "create_war_room",
            "title": "Archive Me",
        })
        room_id = create.data["room_id"]

        result = await war_room_skill.execute({
            "action": "archive_room",
            "room_id": room_id,
            "resolution": "False positive confirmed",
        })
        assert result.success
        assert result.data["status"] == "archived"

    @pytest.mark.asyncio
    async def test_archive_nonexistent_room(self, war_room_skill):
        result = await war_room_skill.execute({
            "action": "archive_room",
            "room_id": "WR-gone",
        })
        assert not result.success


# ---------------------------------------------------------------------------
# get_timeline
# ---------------------------------------------------------------------------


class TestGetTimeline:
    @pytest.mark.asyncio
    async def test_get_timeline(self, war_room_skill):
        create = await war_room_skill.execute({
            "action": "create_war_room",
            "title": "Timeline Test",
        })
        room_id = create.data["room_id"]

        await war_room_skill.execute({
            "action": "post_update",
            "room_id": room_id,
            "message": "Update 1",
        })

        result = await war_room_skill.execute({
            "action": "get_timeline",
            "room_id": room_id,
        })
        assert result.success
        assert len(result.data["timeline"]) >= 2  # room_created + update

    @pytest.mark.asyncio
    async def test_get_timeline_nonexistent(self, war_room_skill):
        result = await war_room_skill.execute({
            "action": "get_timeline",
            "room_id": "WR-nope",
        })
        assert not result.success


# ---------------------------------------------------------------------------
# Unknown Action
# ---------------------------------------------------------------------------


class TestWarRoomUnknownAction:
    @pytest.mark.asyncio
    async def test_unknown_action(self, war_room_skill):
        result = await war_room_skill.execute({"action": "nonexistent"})
        assert not result.success
        assert "Unknown action" in result.errors[0]
