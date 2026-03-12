#!/usr/bin/env python3
"""
SOAR Integration Skill — workflow orchestration, automation chains, and playbook management.

Primary owner: Gamma (Blue Team)
Also usable by: Alpha-4, Beta-4, Delta, Sigma (all agents)

Capabilities:
  - Workflow definition and management with state machines
  - Multi-step automation chains with conditional logic
  - Integration adapter framework (TheHive, XSOAR, Tines, Slack)
  - Approval workflow management
  - Audit trail for all automated actions
  - Playbook template library
  - Trigger-based and scheduled execution
"""

import hashlib
import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Any, Optional

from security_agents.core.models import SkillResult, IntelligencePacket, IntelligenceType, Priority
from security_agents.skills.base_skill import BaseSecuritySkill

# ---------------------------------------------------------------------------
# Workflow state machine
# ---------------------------------------------------------------------------

class WorkflowState(Enum):
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

# Valid state transitions
VALID_TRANSITIONS: Dict[WorkflowState, List[WorkflowState]] = {
    WorkflowState.DRAFT: [WorkflowState.PENDING_APPROVAL, WorkflowState.APPROVED],
    WorkflowState.PENDING_APPROVAL: [WorkflowState.APPROVED, WorkflowState.CANCELLED],
    WorkflowState.APPROVED: [WorkflowState.RUNNING, WorkflowState.CANCELLED],
    WorkflowState.RUNNING: [WorkflowState.PAUSED, WorkflowState.COMPLETED, WorkflowState.FAILED],
    WorkflowState.PAUSED: [WorkflowState.RUNNING, WorkflowState.CANCELLED],
    WorkflowState.COMPLETED: [],
    WorkflowState.FAILED: [WorkflowState.DRAFT],
    WorkflowState.CANCELLED: [WorkflowState.DRAFT],
}

class StepType(Enum):
    ACTION = "action"
    CONDITION = "condition"
    APPROVAL = "approval"
    NOTIFICATION = "notification"
    WAIT = "wait"
    PARALLEL = "parallel"

# ---------------------------------------------------------------------------
# Integration adapters
# ---------------------------------------------------------------------------

INTEGRATION_ADAPTERS: Dict[str, Dict[str, Any]] = {
    "thehive": {
        "display_name": "TheHive",
        "capabilities": ["create_case", "update_case", "add_observable", "run_responder", "close_case"],
        "auth_type": "api_key",
        "default_endpoint": "http://thehive:9000/api",
    },
    "xsoar": {
        "display_name": "Cortex XSOAR",
        "capabilities": ["create_incident", "run_playbook", "get_context", "close_incident", "add_evidence"],
        "auth_type": "api_key",
        "default_endpoint": "https://xsoar.local/api",
    },
    "tines": {
        "display_name": "Tines",
        "capabilities": ["trigger_story", "send_event", "get_story_status", "list_stories"],
        "auth_type": "oauth2",
        "default_endpoint": "https://api.tines.com/api/v1",
    },
    "slack": {
        "display_name": "Slack",
        "capabilities": ["send_message", "create_channel", "add_reaction", "upload_file", "post_thread"],
        "auth_type": "bot_token",
        "default_endpoint": "https://slack.com/api",
    },
    "pagerduty": {
        "display_name": "PagerDuty",
        "capabilities": ["create_incident", "acknowledge", "resolve", "escalate"],
        "auth_type": "api_key",
        "default_endpoint": "https://api.pagerduty.com",
    },
    "jira": {
        "display_name": "Jira",
        "capabilities": ["create_issue", "update_issue", "transition_issue", "add_comment"],
        "auth_type": "api_token",
        "default_endpoint": "https://jira.local/rest/api/3",
    },
}

# ---------------------------------------------------------------------------
# Built-in playbook templates
# ---------------------------------------------------------------------------

PLAYBOOK_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "incident_response_standard": {
        "name": "Standard Incident Response",
        "description": "SOC Tier-1 incident triage, investigation, and containment workflow",
        "category": "incident_response",
        "steps": [
            {"id": "s1", "type": "action", "action": "enrich_iocs", "description": "Enrich all IOCs from the alert"},
            {"id": "s2", "type": "condition", "field": "severity", "operator": "gte", "value": "high",
             "true_step": "s3", "false_step": "s4"},
            {"id": "s3", "type": "notification", "channel": "slack", "target": "#soc-critical",
             "message_template": "Critical alert: {alert_title}"},
            {"id": "s4", "type": "action", "action": "create_case", "integration": "thehive"},
            {"id": "s5", "type": "action", "action": "assign_analyst", "auto_assign": True},
            {"id": "s6", "type": "approval", "approver_role": "soc_lead", "timeout_minutes": 30,
             "auto_approve_if": "severity == critical"},
            {"id": "s7", "type": "action", "action": "execute_containment"},
            {"id": "s8", "type": "notification", "channel": "slack", "target": "#soc-updates",
             "message_template": "Containment executed for {case_id}"},
        ],
        "required_integrations": ["thehive", "slack"],
        "estimated_duration_minutes": 45,
    },
    "phishing_response": {
        "name": "Phishing Email Response",
        "description": "Automated phishing triage, mailbox sweep, and user notification",
        "category": "phishing",
        "steps": [
            {"id": "s1", "type": "action", "action": "analyze_email", "skill": "phishing_analysis"},
            {"id": "s2", "type": "condition", "field": "risk_score", "operator": "gte", "value": 70,
             "true_step": "s3", "false_step": "s5"},
            {"id": "s3", "type": "action", "action": "quarantine_email"},
            {"id": "s4", "type": "parallel", "steps": [
                {"action": "block_sender_domain"},
                {"action": "sweep_mailboxes"},
                {"action": "notify_recipients"},
            ]},
            {"id": "s5", "type": "action", "action": "create_case", "integration": "thehive"},
            {"id": "s6", "type": "notification", "channel": "slack", "target": "#phishing-alerts"},
        ],
        "required_integrations": ["thehive", "slack"],
        "estimated_duration_minutes": 15,
    },
    "vulnerability_remediation": {
        "name": "Vulnerability Remediation Tracking",
        "description": "Track critical vulnerability from discovery through patch verification",
        "category": "vulnerability_management",
        "steps": [
            {"id": "s1", "type": "action", "action": "create_vuln_ticket", "integration": "jira"},
            {"id": "s2", "type": "condition", "field": "cvss_score", "operator": "gte", "value": 9.0,
             "true_step": "s3", "false_step": "s4"},
            {"id": "s3", "type": "notification", "channel": "pagerduty", "severity": "critical"},
            {"id": "s4", "type": "wait", "wait_for": "patch_available", "timeout_hours": 72},
            {"id": "s5", "type": "approval", "approver_role": "change_manager", "timeout_minutes": 120},
            {"id": "s6", "type": "action", "action": "deploy_patch"},
            {"id": "s7", "type": "action", "action": "verify_remediation"},
        ],
        "required_integrations": ["jira", "pagerduty"],
        "estimated_duration_minutes": 4320,
    },
    "threat_hunt": {
        "name": "Proactive Threat Hunt",
        "description": "Structured threat hunting workflow based on hypothesis",
        "category": "threat_hunting",
        "steps": [
            {"id": "s1", "type": "action", "action": "define_hypothesis"},
            {"id": "s2", "type": "action", "action": "collect_telemetry"},
            {"id": "s3", "type": "action", "action": "analyze_data"},
            {"id": "s4", "type": "condition", "field": "findings_count", "operator": "gt", "value": 0,
             "true_step": "s5", "false_step": "s7"},
            {"id": "s5", "type": "action", "action": "create_detections"},
            {"id": "s6", "type": "notification", "channel": "slack", "target": "#threat-intel"},
            {"id": "s7", "type": "action", "action": "document_results"},
        ],
        "required_integrations": ["slack"],
        "estimated_duration_minutes": 480,
    },
}

class SOARIntegrationSkill(BaseSecuritySkill):
    """Orchestrate security workflows, playbooks, and cross-tool automation."""

    SKILL_NAME = "soar_integration"
    DESCRIPTION = (
        "Security orchestration, automation, and response — workflow management, "
        "playbook execution, integration adapters, and approval workflows"
    )
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS = [
        "gamma_blue_team", "alpha_4_threat_intel", "beta_4_devsecops",
        "delta_red_team", "sigma_metrics",
    ]
    REQUIRED_INTEGRATIONS = []  # Adapters loaded dynamically

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def _setup(self):
        """Initialize workflow engine state."""
        self.workflows: Dict[str, Dict[str, Any]] = {}
        self.integrations: Dict[str, Dict[str, Any]] = {}
        self.audit_log: List[Dict[str, Any]] = []
        self.approvals: Dict[str, Dict[str, Any]] = {}

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        """
        Dispatch to the appropriate SOAR action.

        Supported actions:
          create_workflow   — define a new automation workflow
          execute_workflow   — run a workflow
          list_workflows     — list defined workflows
          add_integration    — register an integration adapter
          trigger_action     — fire a single action via an integration
          get_audit_trail    — retrieve the audit log
          create_approval    — request human approval for a step
          resolve_approval   — approve or deny a pending approval
        """
        action = parameters.get("action", "list_workflows")

        dispatch = {
            "create_workflow": self._create_workflow,
            "execute_workflow": self._execute_workflow,
            "list_workflows": self._list_workflows,
            "add_integration": self._add_integration,
            "trigger_action": self._trigger_action,
            "get_audit_trail": self._get_audit_trail,
            "create_approval": self._create_approval,
            "resolve_approval": self._resolve_approval,
        }

        handler = dispatch.get(action)
        if handler is None:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=[
                    f"Unknown action '{action}'. Supported: {', '.join(dispatch.keys())}"
                ],
            )

        return await handler(parameters)

    # ==================================================================
    # Workflow Management
    # ==================================================================

    async def _create_workflow(self, params: Dict[str, Any]) -> SkillResult:
        """Define a new automation workflow, optionally from a template."""
        template_id = params.get("template")
        name = params.get("name", "")
        steps = params.get("steps", [])
        trigger = params.get("trigger")  # e.g. {"type": "alert", "source": "crowdstrike"}
        requires_approval = params.get("requires_approval", False)

        # Load from template if specified
        if template_id:
            template = PLAYBOOK_TEMPLATES.get(template_id)
            if not template:
                return SkillResult(
                    success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                    errors=[f"Unknown template '{template_id}'. Available: {', '.join(PLAYBOOK_TEMPLATES.keys())}"],
                )
            name = name or template["name"]
            steps = steps or template["steps"]

        if not name:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'name' parameter required"],
            )

        workflow_id = f"WF-{uuid.uuid4().hex[:8]}"
        workflow = {
            "workflow_id": workflow_id,
            "name": name,
            "state": WorkflowState.DRAFT.value,
            "steps": steps,
            "trigger": trigger,
            "requires_approval": requires_approval,
            "created_by": self.agent_id,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "execution_history": [],
            "template_id": template_id,
        }
        self.workflows[workflow_id] = workflow

        self._audit("create_workflow", {"workflow_id": workflow_id, "name": name})

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "workflow_id": workflow_id,
                "name": name,
                "state": WorkflowState.DRAFT.value,
                "step_count": len(steps),
                "template_used": template_id,
            },
        )

    async def _execute_workflow(self, params: Dict[str, Any]) -> SkillResult:
        """Execute a workflow through its step chain."""
        workflow_id = params.get("workflow_id", "")
        context = params.get("context", {})

        workflow = self.workflows.get(workflow_id)
        if not workflow:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Workflow '{workflow_id}' not found"],
            )

        current_state = WorkflowState(workflow["state"])

        # Check if approval is needed before running
        if workflow["requires_approval"] and current_state == WorkflowState.DRAFT:
            workflow["state"] = WorkflowState.PENDING_APPROVAL.value
            self._audit("workflow_pending_approval", {"workflow_id": workflow_id})
            return SkillResult(
                success=True,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                data={
                    "workflow_id": workflow_id,
                    "state": WorkflowState.PENDING_APPROVAL.value,
                    "message": "Workflow requires approval before execution",
                },
                warnings=["Approval required — use create_approval to request"],
            )

        # Validate state transition
        if current_state not in (WorkflowState.DRAFT, WorkflowState.APPROVED, WorkflowState.PAUSED):
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Cannot execute workflow in state '{current_state.value}'"],
            )

        # Transition to running
        workflow["state"] = WorkflowState.RUNNING.value
        workflow["updated_at"] = datetime.now().isoformat()

        # Walk the steps
        steps = workflow["steps"]
        executed_steps = []
        packets: List[IntelligencePacket] = []

        for step in steps:
            step_result = self._simulate_step(step, context)
            executed_steps.append(step_result)

            if step_result.get("status") == "failed":
                workflow["state"] = WorkflowState.FAILED.value
                self._audit("workflow_failed", {
                    "workflow_id": workflow_id,
                    "failed_step": step.get("id"),
                    "error": step_result.get("error"),
                })
                return SkillResult(
                    success=False,
                    skill_name=self.SKILL_NAME,
                    agent_id=self.agent_id,
                    data={"workflow_id": workflow_id, "executed_steps": executed_steps},
                    errors=[f"Step {step.get('id')} failed: {step_result.get('error')}"],
                )

            # Handle conditional branching
            if step.get("type") == "condition":
                next_step_id = step_result.get("next_step")
                if next_step_id:
                    context["_branch"] = next_step_id

        # Mark complete
        workflow["state"] = WorkflowState.COMPLETED.value
        workflow["updated_at"] = datetime.now().isoformat()
        execution_record = {
            "run_id": f"RUN-{uuid.uuid4().hex[:8]}",
            "started_at": datetime.now().isoformat(),
            "completed_at": datetime.now().isoformat(),
            "steps_executed": len(executed_steps),
            "context_keys": list(context.keys()),
        }
        workflow["execution_history"].append(execution_record)

        self._audit("workflow_completed", {
            "workflow_id": workflow_id,
            "run_id": execution_record["run_id"],
            "steps_executed": len(executed_steps),
        })

        # Emit intelligence packet for completed workflows
        packets.append(IntelligencePacket(
            packet_id=f"PKT-SOAR-{execution_record['run_id']}",
            source_agent=self.agent_id,
            target_agents=["all"],
            intelligence_type=IntelligenceType.INCIDENT,
            priority=Priority.MEDIUM,
            confidence=90.0,
            timestamp=datetime.now(),
            data={
                "workflow_id": workflow_id,
                "workflow_name": workflow["name"],
                "run_id": execution_record["run_id"],
                "steps_executed": len(executed_steps),
            },
            correlation_keys=[workflow_id],
        ))

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "workflow_id": workflow_id,
                "state": WorkflowState.COMPLETED.value,
                "run_id": execution_record["run_id"],
                "steps_executed": len(executed_steps),
                "step_results": executed_steps,
            },
            intelligence_packets=packets,
        )

    async def _list_workflows(self, params: Dict[str, Any]) -> SkillResult:
        """List workflows, optionally filtered by state or template availability."""
        state_filter = params.get("state")
        include_templates = params.get("include_templates", False)

        workflows = []
        for wf in self.workflows.values():
            if state_filter and wf["state"] != state_filter:
                continue
            workflows.append({
                "workflow_id": wf["workflow_id"],
                "name": wf["name"],
                "state": wf["state"],
                "step_count": len(wf["steps"]),
                "created_at": wf["created_at"],
                "executions": len(wf["execution_history"]),
            })

        result_data: Dict[str, Any] = {"workflows": workflows, "total": len(workflows)}

        if include_templates:
            result_data["templates"] = {
                tid: {"name": t["name"], "category": t["category"], "description": t["description"]}
                for tid, t in PLAYBOOK_TEMPLATES.items()
            }

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data=result_data,
        )

    # ==================================================================
    # Integration Management
    # ==================================================================

    async def _add_integration(self, params: Dict[str, Any]) -> SkillResult:
        """Register or update an integration adapter."""
        integration_id = params.get("integration_id", "")
        endpoint = params.get("endpoint", "")
        credentials_ref = params.get("credentials_ref", "")  # vault reference, never raw secrets

        adapter = INTEGRATION_ADAPTERS.get(integration_id)
        if not adapter:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[
                    f"Unknown integration '{integration_id}'. "
                    f"Supported: {', '.join(INTEGRATION_ADAPTERS.keys())}"
                ],
            )

        self.integrations[integration_id] = {
            "integration_id": integration_id,
            "display_name": adapter["display_name"],
            "endpoint": endpoint or adapter["default_endpoint"],
            "auth_type": adapter["auth_type"],
            "credentials_ref": credentials_ref,
            "capabilities": adapter["capabilities"],
            "status": "connected",
            "registered_at": datetime.now().isoformat(),
        }

        self._audit("add_integration", {
            "integration_id": integration_id,
            "endpoint": endpoint or adapter["default_endpoint"],
        })

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "integration_id": integration_id,
                "display_name": adapter["display_name"],
                "capabilities": adapter["capabilities"],
                "status": "connected",
            },
        )

    async def _trigger_action(self, params: Dict[str, Any]) -> SkillResult:
        """Fire a single action through a registered integration."""
        integration_id = params.get("integration_id", "")
        action_name = params.get("action_name", "")
        action_params = params.get("action_params", {})

        integration = self.integrations.get(integration_id)
        if not integration:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Integration '{integration_id}' not registered. Use add_integration first."],
            )

        if action_name not in integration["capabilities"]:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[
                    f"Action '{action_name}' not supported by {integration_id}. "
                    f"Available: {', '.join(integration['capabilities'])}"
                ],
            )

        # Simulate the external call
        action_id = f"ACT-{uuid.uuid4().hex[:8]}"
        result_data = {
            "action_id": action_id,
            "integration": integration_id,
            "action": action_name,
            "status": "executed",
            "timestamp": datetime.now().isoformat(),
            "response": {"simulated": True, "message": f"{action_name} executed via {integration_id}"},
        }

        self._audit("trigger_action", {
            "action_id": action_id,
            "integration_id": integration_id,
            "action_name": action_name,
        })

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data=result_data,
        )

    # ==================================================================
    # Approval Management
    # ==================================================================

    async def _create_approval(self, params: Dict[str, Any]) -> SkillResult:
        """Request human approval for a workflow or action."""
        workflow_id = params.get("workflow_id", "")
        approver_role = params.get("approver_role", "soc_lead")
        reason = params.get("reason", "")
        timeout_minutes = params.get("timeout_minutes", 60)

        approval_id = f"APR-{uuid.uuid4().hex[:8]}"
        expiry = datetime.now() + timedelta(minutes=timeout_minutes)

        self.approvals[approval_id] = {
            "approval_id": approval_id,
            "workflow_id": workflow_id,
            "approver_role": approver_role,
            "reason": reason,
            "status": "pending",
            "requested_by": self.agent_id,
            "requested_at": datetime.now().isoformat(),
            "expires_at": expiry.isoformat(),
            "resolved_by": None,
            "resolved_at": None,
            "decision": None,
        }

        self._audit("create_approval", {
            "approval_id": approval_id,
            "workflow_id": workflow_id,
            "approver_role": approver_role,
        })

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "approval_id": approval_id,
                "workflow_id": workflow_id,
                "status": "pending",
                "approver_role": approver_role,
                "expires_at": expiry.isoformat(),
            },
        )

    async def _resolve_approval(self, params: Dict[str, Any]) -> SkillResult:
        """Approve or deny a pending approval request."""
        approval_id = params.get("approval_id", "")
        decision = params.get("decision", "")  # "approved" or "denied"
        resolved_by = params.get("resolved_by", "unknown")
        comment = params.get("comment", "")

        approval = self.approvals.get(approval_id)
        if not approval:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Approval '{approval_id}' not found"],
            )

        if approval["status"] != "pending":
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Approval already resolved with decision: {approval['decision']}"],
            )

        if decision not in ("approved", "denied"):
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'decision' must be 'approved' or 'denied'"],
            )

        # Check expiry
        expiry = datetime.fromisoformat(approval["expires_at"])
        if datetime.now() > expiry:
            approval["status"] = "expired"
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["Approval request has expired"],
            )

        approval["status"] = decision
        approval["decision"] = decision
        approval["resolved_by"] = resolved_by
        approval["resolved_at"] = datetime.now().isoformat()
        approval["comment"] = comment

        # If approved, transition the linked workflow
        if decision == "approved" and approval["workflow_id"]:
            wf = self.workflows.get(approval["workflow_id"])
            if wf and wf["state"] == WorkflowState.PENDING_APPROVAL.value:
                wf["state"] = WorkflowState.APPROVED.value
                wf["updated_at"] = datetime.now().isoformat()

        self._audit("resolve_approval", {
            "approval_id": approval_id,
            "decision": decision,
            "resolved_by": resolved_by,
        })

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "approval_id": approval_id,
                "decision": decision,
                "resolved_by": resolved_by,
                "workflow_id": approval["workflow_id"],
            },
        )

    # ==================================================================
    # Audit Trail
    # ==================================================================

    async def _get_audit_trail(self, params: Dict[str, Any]) -> SkillResult:
        """Retrieve the audit trail, optionally filtered."""
        workflow_id = params.get("workflow_id")
        event_type = params.get("event_type")
        limit = params.get("limit", 100)

        entries = self.audit_log
        if workflow_id:
            entries = [e for e in entries if e.get("details", {}).get("workflow_id") == workflow_id]
        if event_type:
            entries = [e for e in entries if e["event"] == event_type]

        entries = entries[-limit:]

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={"entries": entries, "total": len(entries)},
        )

    # ==================================================================
    # Internal Helpers
    # ==================================================================

    def _audit(self, event: str, details: Dict[str, Any]):
        """Append an entry to the immutable audit log."""
        entry = {
            "event_id": f"AUD-{uuid.uuid4().hex[:8]}",
            "event": event,
            "agent_id": self.agent_id,
            "timestamp": datetime.now().isoformat(),
            "details": details,
            "checksum": hashlib.sha256(
                f"{event}:{self.agent_id}:{datetime.now().isoformat()}".encode()
            ).hexdigest()[:16],
        }
        self.audit_log.append(entry)
        self.logger.debug(f"Audit: {event} — {details}")

    def _simulate_step(self, step: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate execution of a single workflow step."""
        step_type = step.get("type", "action")
        step_id = step.get("id", "unknown")

        result: Dict[str, Any] = {
            "step_id": step_id,
            "type": step_type,
            "status": "completed",
            "timestamp": datetime.now().isoformat(),
        }

        if step_type == "condition":
            field = step.get("field", "")
            operator = step.get("operator", "eq")
            value = step.get("value")
            actual = context.get(field)

            condition_met = self._evaluate_condition(actual, operator, value)
            result["condition_met"] = condition_met
            result["next_step"] = step.get("true_step") if condition_met else step.get("false_step")

        elif step_type == "approval":
            # In simulation, auto-approve
            result["auto_approved"] = True

        elif step_type == "notification":
            result["channel"] = step.get("channel", "")
            result["target"] = step.get("target", "")

        elif step_type == "wait":
            result["wait_for"] = step.get("wait_for", "")
            result["timeout_hours"] = step.get("timeout_hours", 24)

        elif step_type == "parallel":
            sub_steps = step.get("steps", [])
            result["parallel_count"] = len(sub_steps)
            result["parallel_results"] = [
                {"action": s.get("action", ""), "status": "completed"} for s in sub_steps
            ]

        return result

    @staticmethod
    def _evaluate_condition(actual: Any, operator: str, expected: Any) -> bool:
        """Evaluate a condition expression."""
        if actual is None:
            return False
        try:
            if operator in ("eq", "=="):
                return actual == expected
            elif operator in ("neq", "!="):
                return actual != expected
            elif operator in ("gt", ">"):
                return float(actual) > float(expected)
            elif operator in ("gte", ">="):
                return float(actual) >= float(expected)
            elif operator in ("lt", "<"):
                return float(actual) < float(expected)
            elif operator in ("lte", "<="):
                return float(actual) <= float(expected)
            elif operator == "in":
                return actual in expected
            elif operator == "contains":
                return expected in actual
        except (ValueError, TypeError):
            return False
        return False
