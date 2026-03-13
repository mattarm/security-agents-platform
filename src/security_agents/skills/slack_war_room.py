#!/usr/bin/env python3
"""
Slack War Room Skill — incident war room lifecycle management via Slack.

Primary owner: Gamma (Blue Team), Sigma (Metrics)
Wraps: slack-war-rooms/bot/slack_war_room_bot.py

Capabilities:
  - Create dedicated Slack war rooms for security incidents
  - Post structured updates with severity and status tracking
  - Escalate incidents through management tiers
  - Add / remove responders to active war rooms
  - Archive resolved war rooms with audit trail
  - Retrieve full incident timelines for post-mortem analysis
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict

from security_agents.core.models import (
    SkillResult, IntelligencePacket, IntelligenceType, Priority, Severity,
)
from security_agents.skills.base_skill import BaseSecuritySkill

# ---------------------------------------------------------------------------
# War room internal enums / constants
# ---------------------------------------------------------------------------

WAR_ROOM_TYPES = {
    "incident_response", "threat_hunting", "vulnerability_response",
    "purple_team_exercise",
}

WAR_ROOM_STATUSES = [
    "active", "investigating", "resolving", "resolved", "archived",
]

ESCALATION_TIERS = [
    {"tier": 0, "label": "SOC Analyst", "response_sla_minutes": 15},
    {"tier": 1, "label": "Senior Analyst / IR Lead", "response_sla_minutes": 10},
    {"tier": 2, "label": "Security Manager", "response_sla_minutes": 5},
    {"tier": 3, "label": "CISO / Executive", "response_sla_minutes": 3},
]

class SlackWarRoomSkill(BaseSecuritySkill):
    """Slack war room lifecycle management for incident collaboration."""

    SKILL_NAME = "slack_war_room"
    DESCRIPTION = (
        "War room lifecycle management with real-time incident collaboration, "
        "escalation workflows, responder management, and timeline tracking"
    )
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS = ["gamma_blue_team", "sigma_metrics"]
    REQUIRED_INTEGRATIONS = ["slack"]

    # ---------------------------------------------------------------------
    # Lifecycle
    # ---------------------------------------------------------------------

    async def _setup(self):
        """Initialize internal state stores."""
        self.war_rooms: Dict[str, Dict[str, Any]] = {}
        self.timelines: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.escalation_state: Dict[str, Dict[str, Any]] = {}
        self.max_rooms = self.config.get("max_rooms", 500)
        self.default_channel_prefix = self.config.get("channel_prefix", "war-room")

    # ---------------------------------------------------------------------
    # Action dispatch
    # ---------------------------------------------------------------------

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        """
        Dispatch to the appropriate action.

        Supported actions:
          create_war_room  -- create a new incident war room
          post_update      -- post a structured status update
          escalate         -- escalate the incident to a higher tier
          add_responders   -- add responders to an active war room
          archive_room     -- archive a resolved war room
          get_timeline     -- retrieve the full incident timeline
        """
        action = parameters.get("action", "create_war_room")
        dispatch = {
            "create_war_room": self._create_war_room,
            "post_update": self._post_update,
            "escalate": self._escalate,
            "add_responders": self._add_responders,
            "archive_room": self._archive_room,
            "get_timeline": self._get_timeline,
        }
        handler = dispatch.get(action)
        if handler is None:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=[
                    f"Unknown action '{action}'. "
                    f"Supported: {', '.join(dispatch.keys())}"
                ],
            )
        return await handler(parameters)

    # =====================================================================
    # create_war_room
    # =====================================================================

    async def _create_war_room(self, params: Dict[str, Any]) -> SkillResult:
        """Create a new Slack war room for an incident."""
        incident_id = params.get("incident_id", f"INC-{uuid.uuid4().hex[:8]}")
        title = params.get("title", "Untitled Incident")
        description = params.get("description", "")
        severity = params.get("severity", "medium")
        room_type = params.get("room_type", "incident_response")
        created_by = params.get("created_by", self.agent_id)
        initial_responders = params.get("responders", [])

        if room_type not in WAR_ROOM_TYPES:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=[
                    f"Invalid room_type '{room_type}'. "
                    f"Valid: {', '.join(sorted(WAR_ROOM_TYPES))}"
                ],
            )

        if len(self.war_rooms) >= self.max_rooms:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=["Maximum war room capacity reached. Archive old rooms first."],
            )

        room_id = f"WR-{uuid.uuid4().hex[:8]}"
        channel_name = f"{self.default_channel_prefix}-{incident_id.lower()}"
        now = datetime.now(timezone.utc)

        room = {
            "room_id": room_id,
            "incident_id": incident_id,
            "channel_name": channel_name,
            "title": title,
            "description": description,
            "severity": severity,
            "room_type": room_type,
            "status": "active",
            "created_at": now.isoformat(),
            "created_by": created_by,
            "responders": list(initial_responders),
            "escalation_tier": 0,
            "update_count": 0,
            "last_activity": now.isoformat(),
        }

        self.war_rooms[room_id] = room
        self._record_timeline(room_id, "room_created", {
            "title": title,
            "severity": severity,
            "created_by": created_by,
            "initial_responders": initial_responders,
        })

        # Emit intelligence packet for critical / high severity
        packets: List[IntelligencePacket] = []
        if severity in ("critical", "high"):
            packets.append(
                IntelligencePacket(
                    packet_id=f"PKT-WR-{room_id}",
                    source_agent=self.agent_id,
                    target_agents=["all"],
                    intelligence_type=IntelligenceType.INCIDENT,
                    priority=Priority.CRITICAL if severity == "critical" else Priority.HIGH,
                    confidence=90.0,
                    timestamp=now,
                    data={
                        "room_id": room_id,
                        "incident_id": incident_id,
                        "title": title,
                        "severity": severity,
                        "channel": channel_name,
                    },
                    correlation_keys=[incident_id, room_id],
                )
            )

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "room_id": room_id,
                "incident_id": incident_id,
                "channel_name": channel_name,
                "status": "active",
                "severity": severity,
                "room_type": room_type,
                "responders": initial_responders,
                "created_at": now.isoformat(),
            },
            intelligence_packets=packets,
        )

    # =====================================================================
    # post_update
    # =====================================================================

    async def _post_update(self, params: Dict[str, Any]) -> SkillResult:
        """Post a structured update to an active war room."""
        room_id = params.get("room_id")
        if not room_id or room_id not in self.war_rooms:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=[f"War room '{room_id}' not found."],
            )

        room = self.war_rooms[room_id]
        if room["status"] == "archived":
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=["Cannot post to an archived war room."],
            )

        message = params.get("message", "")
        update_type = params.get("update_type", "status")  # status, finding, action, containment
        author = params.get("author", self.agent_id)
        new_status = params.get("new_status")
        attachments = params.get("attachments", [])

        now = datetime.now(timezone.utc)
        update_id = f"UPD-{uuid.uuid4().hex[:8]}"

        update_entry = {
            "update_id": update_id,
            "update_type": update_type,
            "message": message,
            "author": author,
            "attachments": attachments,
            "timestamp": now.isoformat(),
        }

        if new_status and new_status in WAR_ROOM_STATUSES:
            old_status = room["status"]
            room["status"] = new_status
            update_entry["status_change"] = {"from": old_status, "to": new_status}

        room["update_count"] += 1
        room["last_activity"] = now.isoformat()

        self._record_timeline(room_id, "update_posted", update_entry)

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "update_id": update_id,
                "room_id": room_id,
                "update_type": update_type,
                "current_status": room["status"],
                "total_updates": room["update_count"],
                "posted_at": now.isoformat(),
            },
        )

    # =====================================================================
    # escalate
    # =====================================================================

    async def _escalate(self, params: Dict[str, Any]) -> SkillResult:
        """Escalate an incident to a higher management tier."""
        room_id = params.get("room_id")
        if not room_id or room_id not in self.war_rooms:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=[f"War room '{room_id}' not found."],
            )

        room = self.war_rooms[room_id]
        if room["status"] == "archived":
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=["Cannot escalate an archived war room."],
            )

        reason = params.get("reason", "Manual escalation requested")
        escalated_by = params.get("escalated_by", self.agent_id)

        current_tier = room.get("escalation_tier", 0)
        max_tier = len(ESCALATION_TIERS) - 1

        if current_tier >= max_tier:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=[
                    f"Already at maximum escalation tier ({max_tier}: "
                    f"{ESCALATION_TIERS[max_tier]['label']})."
                ],
            )

        new_tier = current_tier + 1
        tier_info = ESCALATION_TIERS[new_tier]
        room["escalation_tier"] = new_tier

        now = datetime.now(timezone.utc)
        room["last_activity"] = now.isoformat()

        self.escalation_state[room_id] = {
            "tier": new_tier,
            "label": tier_info["label"],
            "escalated_by": escalated_by,
            "escalated_at": now.isoformat(),
            "response_sla_minutes": tier_info["response_sla_minutes"],
            "sla_deadline": (now + timedelta(minutes=tier_info["response_sla_minutes"])).isoformat(),
            "reason": reason,
        }

        self._record_timeline(room_id, "escalated", {
            "from_tier": current_tier,
            "to_tier": new_tier,
            "tier_label": tier_info["label"],
            "reason": reason,
            "escalated_by": escalated_by,
            "response_sla_minutes": tier_info["response_sla_minutes"],
        })

        # Emit intelligence for tier 2+ escalations
        packets: List[IntelligencePacket] = []
        if new_tier >= 2:
            packets.append(
                IntelligencePacket(
                    packet_id=f"PKT-ESC-{room_id}-T{new_tier}",
                    source_agent=self.agent_id,
                    target_agents=["all"],
                    intelligence_type=IntelligenceType.INCIDENT,
                    priority=Priority.CRITICAL,
                    confidence=95.0,
                    timestamp=now,
                    data={
                        "room_id": room_id,
                        "incident_id": room["incident_id"],
                        "escalation_tier": new_tier,
                        "tier_label": tier_info["label"],
                        "reason": reason,
                    },
                    correlation_keys=[room["incident_id"], room_id],
                )
            )

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "room_id": room_id,
                "previous_tier": current_tier,
                "new_tier": new_tier,
                "tier_label": tier_info["label"],
                "response_sla_minutes": tier_info["response_sla_minutes"],
                "sla_deadline": self.escalation_state[room_id]["sla_deadline"],
                "reason": reason,
            },
            intelligence_packets=packets,
        )

    # =====================================================================
    # add_responders
    # =====================================================================

    async def _add_responders(self, params: Dict[str, Any]) -> SkillResult:
        """Add responders to an active war room."""
        room_id = params.get("room_id")
        if not room_id or room_id not in self.war_rooms:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=[f"War room '{room_id}' not found."],
            )

        room = self.war_rooms[room_id]
        if room["status"] == "archived":
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=["Cannot add responders to an archived war room."],
            )

        new_responders = params.get("responders", [])
        if not new_responders:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=["'responders' list is required and must not be empty."],
            )

        existing = set(room["responders"])
        added = []
        already_present = []

        for r in new_responders:
            if r in existing:
                already_present.append(r)
            else:
                room["responders"].append(r)
                existing.add(r)
                added.append(r)

        now = datetime.now(timezone.utc)
        room["last_activity"] = now.isoformat()

        if added:
            self._record_timeline(room_id, "responders_added", {
                "added": added,
                "added_by": params.get("added_by", self.agent_id),
            })

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "room_id": room_id,
                "added": added,
                "already_present": already_present,
                "total_responders": len(room["responders"]),
                "all_responders": room["responders"],
            },
        )

    # =====================================================================
    # archive_room
    # =====================================================================

    async def _archive_room(self, params: Dict[str, Any]) -> SkillResult:
        """Archive a resolved war room."""
        room_id = params.get("room_id")
        if not room_id or room_id not in self.war_rooms:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=[f"War room '{room_id}' not found."],
            )

        room = self.war_rooms[room_id]
        if room["status"] == "archived":
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=["War room is already archived."],
            )

        resolution_summary = params.get("resolution_summary", "")
        archived_by = params.get("archived_by", self.agent_id)
        now = datetime.now(timezone.utc)

        old_status = room["status"]
        room["status"] = "archived"
        room["archived_at"] = now.isoformat()
        room["archived_by"] = archived_by
        room["resolution_summary"] = resolution_summary
        room["last_activity"] = now.isoformat()

        # Calculate duration
        created_at = datetime.fromisoformat(room["created_at"])
        duration_minutes = (now - created_at).total_seconds() / 60.0

        self._record_timeline(room_id, "room_archived", {
            "previous_status": old_status,
            "resolution_summary": resolution_summary,
            "archived_by": archived_by,
            "duration_minutes": round(duration_minutes, 1),
        })

        timeline = self.timelines.get(room_id, [])

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "room_id": room_id,
                "incident_id": room["incident_id"],
                "status": "archived",
                "duration_minutes": round(duration_minutes, 1),
                "total_updates": room["update_count"],
                "total_responders": len(room["responders"]),
                "escalation_tier_reached": room.get("escalation_tier", 0),
                "timeline_entries": len(timeline),
                "resolution_summary": resolution_summary,
                "archived_at": now.isoformat(),
            },
        )

    # =====================================================================
    # get_timeline
    # =====================================================================

    async def _get_timeline(self, params: Dict[str, Any]) -> SkillResult:
        """Retrieve the full incident timeline for a war room."""
        room_id = params.get("room_id")
        if not room_id or room_id not in self.war_rooms:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=[f"War room '{room_id}' not found."],
            )

        room = self.war_rooms[room_id]
        timeline = self.timelines.get(room_id, [])
        limit = params.get("limit", 100)
        event_filter = params.get("event_type")

        filtered = timeline
        if event_filter:
            filtered = [e for e in filtered if e.get("event_type") == event_filter]

        # Calculate metrics
        created_at = datetime.fromisoformat(room["created_at"])
        now = datetime.now(timezone.utc)
        reference = (
            datetime.fromisoformat(room["archived_at"])
            if room.get("archived_at")
            else now
        )
        duration_minutes = (reference - created_at).total_seconds() / 60.0

        # Time-to-first-update
        update_events = [
            e for e in timeline if e.get("event_type") == "update_posted"
        ]
        ttfu_minutes = None
        if update_events:
            first_update = datetime.fromisoformat(update_events[0]["timestamp"])
            ttfu_minutes = round((first_update - created_at).total_seconds() / 60.0, 1)

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "room_id": room_id,
                "incident_id": room["incident_id"],
                "status": room["status"],
                "severity": room["severity"],
                "total_events": len(timeline),
                "returned_events": min(limit, len(filtered)),
                "timeline": filtered[-limit:],
                "metrics": {
                    "duration_minutes": round(duration_minutes, 1),
                    "time_to_first_update_minutes": ttfu_minutes,
                    "total_updates": room["update_count"],
                    "escalation_tier_reached": room.get("escalation_tier", 0),
                    "responder_count": len(room["responders"]),
                },
            },
        )

    # =====================================================================
    # Internal helpers
    # =====================================================================

    def _record_timeline(
        self,
        room_id: str,
        event_type: str,
        details: Dict[str, Any],
    ) -> None:
        """Append an event to the war room timeline."""
        self.timelines[room_id].append({
            "event_id": f"EVT-{uuid.uuid4().hex[:8]}",
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details,
        })
        # Keep bounded
        if len(self.timelines[room_id]) > 2000:
            self.timelines[room_id] = self.timelines[room_id][-2000:]
