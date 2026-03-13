"""
Autonomy Controller - Graduated autonomy framework for AI decision-making
Implements 4-tier autonomy system with human oversight and approval gates
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class AutonomyTier(Enum):
    """Graduated autonomy tiers with increasing human oversight"""
    AUTONOMOUS = 0      # Auto-close false positives (>95% confidence)
    ASSISTED = 1        # Enrich and create tickets (>80% confidence)
    SUPERVISED = 2      # Recommend containment (>60% confidence)
    COLLABORATIVE = 3   # Human-led assistance (any confidence)

@dataclass
class AutonomyAction:
    """Action to be executed based on autonomy tier"""
    tier: AutonomyTier
    action_type: str
    action_data: Dict[str, Any]
    requires_approval: bool
    approval_timeout_minutes: int
    escalation_tier: Optional[AutonomyTier]

class AutonomyController:
    """
    Graduated autonomy controller for AI security decisions
    
    Tier 0 - Autonomous:
    - Auto-close false positives with >95% confidence
    - Immediate action with post-audit logging
    - No human approval required
    
    Tier 1 - Assisted:
    - Enrich alerts and create tickets with >80% confidence  
    - Async human validation with override capability
    - Automatic execution with human review queue
    
    Tier 2 - Supervised:
    - Recommend containment actions with >60% confidence
    - Explicit Slack approval required
    - Interactive approval with rationale
    
    Tier 3 - Collaborative:
    - Human-led assistance for any confidence level
    - AI as copilot, human drives decisions
    - Conversational Slack interface
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize autonomy controller"""
        self.config = config
        
        # Confidence thresholds for each tier
        self.confidence_thresholds = {
            AutonomyTier.AUTONOMOUS: 0.95,
            AutonomyTier.ASSISTED: 0.80,
            AutonomyTier.SUPERVISED: 0.60,
            AutonomyTier.COLLABORATIVE: 0.00
        }
        
        # Approval timeout configurations
        self.approval_timeouts = {
            AutonomyTier.SUPERVISED: 30,   # 30 minutes for containment decisions
            AutonomyTier.COLLABORATIVE: 120  # 2 hours for complex analysis
        }
        
        # Action handlers for each tier
        self.action_handlers = {
            AutonomyTier.AUTONOMOUS: self._execute_autonomous_action,
            AutonomyTier.ASSISTED: self._execute_assisted_action,
            AutonomyTier.SUPERVISED: self._execute_supervised_action,
            AutonomyTier.COLLABORATIVE: self._execute_collaborative_action
        }
        
        # Pending approval requests
        self.pending_approvals = {}
        
        # Integration configurations
        self.slack_webhook = config.get('slack_webhook')
        self.jira_config = config.get('jira_config', {})
        self.approval_groups = config.get('approval_groups', {
            'tier2': ['soc-analysts', 'security-leads'],
            'tier3': ['soc-analysts', 'security-leads', 'incident-response']
        })
        
        # Performance tracking
        self.metrics = {
            'actions_by_tier': {tier: 0 for tier in AutonomyTier},
            'approval_response_times': [],
            'escalations': 0,
            'false_positive_rate': 0.0
        }
    
    async def execute_action(self, alert, analysis_result):
        """
        Execute appropriate action based on autonomy tier determination
        
        Args:
            alert: SecurityAlert object
            analysis_result: AnalysisResult from AI analysis
        """
        
        # Determine autonomy tier based on confidence and context
        tier = self._determine_autonomy_tier(alert, analysis_result)
        
        # Create autonomy action
        action = self._create_autonomy_action(alert, analysis_result, tier)
        
        # Execute action based on tier
        handler = self.action_handlers[tier]
        result = await handler(action, alert, analysis_result)
        
        # Update metrics
        self.metrics['actions_by_tier'][tier] += 1
        
        # Log action execution
        logger.info(f"Executed {tier.name} action for alert {alert.id}: {action.action_type}")
        
        return result
    
    def _determine_autonomy_tier(self, alert, analysis_result) -> AutonomyTier:
        """
        Determine appropriate autonomy tier based on:
        1. Confidence score
        2. Alert severity and category
        3. Business impact assessment
        4. Historical performance
        """
        
        confidence = analysis_result.confidence_score
        category = analysis_result.category.value
        severity = alert.severity.value
        
        # Apply confidence-based tier selection
        base_tier = AutonomyTier.COLLABORATIVE  # Default to most conservative
        
        for tier, threshold in sorted(self.confidence_thresholds.items(), 
                                    key=lambda x: x[1], reverse=True):
            if confidence >= threshold:
                base_tier = tier
                break
        
        # Apply business rules for tier escalation
        adjusted_tier = self._apply_tier_escalation_rules(
            base_tier, alert, analysis_result
        )
        
        return adjusted_tier
    
    def _apply_tier_escalation_rules(self, base_tier: AutonomyTier, 
                                   alert, analysis_result) -> AutonomyTier:
        """Apply business rules that may escalate to higher oversight tier"""
        
        severity = alert.severity.value
        category = analysis_result.category.value
        
        # Rule 1: Critical alerts never fully autonomous (escalate from Tier 0)
        if severity == 'critical' and base_tier == AutonomyTier.AUTONOMOUS:
            return AutonomyTier.ASSISTED
        
        # Rule 2: Containment actions require supervision (escalate to Tier 2)
        if category == 'containment_required' and base_tier.value < AutonomyTier.SUPERVISED.value:
            return AutonomyTier.SUPERVISED
        
        # Rule 3: Novel threats require collaboration (escalate to Tier 3)
        if category == 'novel_threat':
            return AutonomyTier.COLLABORATIVE
        
        # Rule 4: High-value assets require elevated oversight
        if self._is_high_value_asset(alert):
            escalated_tier_value = min(base_tier.value + 1, AutonomyTier.COLLABORATIVE.value)
            return AutonomyTier(escalated_tier_value)
        
        return base_tier
    
    def _is_high_value_asset(self, alert) -> bool:
        """Check if alert involves high-value assets"""
        
        high_value_keywords = [
            'domain_controller', 'database', 'financial_system', 
            'customer_data', 'payment_processor'
        ]
        
        alert_text = f"{alert.source} {alert.title} {alert.description}".lower()
        return any(keyword in alert_text for keyword in high_value_keywords)
    
    def _create_autonomy_action(self, alert, analysis_result, tier: AutonomyTier) -> AutonomyAction:
        """Create appropriate action based on tier and analysis"""
        
        category = analysis_result.category.value
        confidence = analysis_result.confidence_score
        
        if tier == AutonomyTier.AUTONOMOUS:
            if category == 'false_positive':
                action = AutonomyAction(
                    tier=tier,
                    action_type='close_alert',
                    action_data={
                        'reason': 'AI_DETERMINED_FALSE_POSITIVE',
                        'confidence': confidence,
                        'auto_closed': True
                    },
                    requires_approval=False,
                    approval_timeout_minutes=0,
                    escalation_tier=None
                )
            else:
                # Fallback: should not reach here with current logic
                action = self._create_assisted_action(alert, analysis_result)
        
        elif tier == AutonomyTier.ASSISTED:
            action = self._create_assisted_action(alert, analysis_result)
            
        elif tier == AutonomyTier.SUPERVISED:
            action = self._create_supervised_action(alert, analysis_result)
            
        else:  # COLLABORATIVE
            action = self._create_collaborative_action(alert, analysis_result)
        
        return action
    
    def _create_assisted_action(self, alert, analysis_result) -> AutonomyAction:
        """Create assisted tier action (auto-execute with human review)"""
        
        category = analysis_result.category.value
        
        if category == 'false_positive':
            action_type = 'close_with_review'
            action_data = {
                'action': 'close_alert',
                'create_review_item': True,
                'review_queue': 'false_positive_review'
            }
        else:
            action_type = 'enrich_and_ticket'
            action_data = {
                'action': 'create_jira_ticket',
                'enrichment': {
                    'ai_analysis': analysis_result.reasoning_chain,
                    'confidence_score': analysis_result.confidence_score,
                    'recommended_action': analysis_result.recommended_action
                },
                'ticket_priority': self._map_severity_to_priority(alert.severity.value),
                'auto_assign': True
            }
        
        return AutonomyAction(
            tier=AutonomyTier.ASSISTED,
            action_type=action_type,
            action_data=action_data,
            requires_approval=False,  # Auto-execute but with review
            approval_timeout_minutes=0,
            escalation_tier=AutonomyTier.SUPERVISED
        )
    
    def _create_supervised_action(self, alert, analysis_result) -> AutonomyAction:
        """Create supervised tier action (requires explicit approval)"""
        
        return AutonomyAction(
            tier=AutonomyTier.SUPERVISED,
            action_type='request_containment_approval',
            action_data={
                'recommended_actions': analysis_result.recommended_action,
                'ai_reasoning': analysis_result.reasoning_chain,
                'confidence_score': analysis_result.confidence_score,
                'impact_assessment': self._assess_business_impact(alert),
                'approval_options': [
                    'approve_recommended_action',
                    'modify_and_approve',
                    'escalate_to_ir_team',
                    'reject_and_investigate'
                ]
            },
            requires_approval=True,
            approval_timeout_minutes=self.approval_timeouts[AutonomyTier.SUPERVISED],
            escalation_tier=AutonomyTier.COLLABORATIVE
        )
    
    def _create_collaborative_action(self, alert, analysis_result) -> AutonomyAction:
        """Create collaborative tier action (human-led with AI assistance)"""
        
        return AutonomyAction(
            tier=AutonomyTier.COLLABORATIVE,
            action_type='initiate_collaboration',
            action_data={
                'ai_insights': {
                    'analysis': analysis_result.reasoning_chain,
                    'confidence': analysis_result.confidence_score,
                    'suggested_investigation_steps': self._generate_investigation_steps(alert, analysis_result)
                },
                'collaboration_mode': 'interactive_analysis',
                'expert_consultation': self._recommend_experts(alert),
                'escalation_path': self._define_escalation_path(alert)
            },
            requires_approval=False,  # Human drives the process
            approval_timeout_minutes=self.approval_timeouts[AutonomyTier.COLLABORATIVE],
            escalation_tier=None  # Highest tier
        )
    
    async def _execute_autonomous_action(self, action: AutonomyAction, alert, analysis_result):
        """Execute fully autonomous action (Tier 0)"""
        
        if action.action_type == 'close_alert':
            # Automatically close false positive
            result = await self._close_alert_automatically(alert, action.action_data)
            
            # Send notification for audit trail
            await self._send_post_action_notification(
                alert, action, result, 'POST_AUTONOMOUS_ACTION'
            )
            
            return result
        
        raise ValueError(f"Unsupported autonomous action: {action.action_type}")
    
    async def _execute_assisted_action(self, action: AutonomyAction, alert, analysis_result):
        """Execute assisted action with async human review (Tier 1)"""
        
        if action.action_type == 'close_with_review':
            # Auto-close but add to review queue
            result = await self._close_alert_automatically(alert, action.action_data)
            await self._add_to_review_queue(alert, analysis_result, 'false_positive_review')
            
        elif action.action_type == 'enrich_and_ticket':
            # Auto-create enriched ticket
            result = await self._create_enriched_ticket(alert, analysis_result, action.action_data)
            
        else:
            raise ValueError(f"Unsupported assisted action: {action.action_type}")
        
        # Send notification with review capability
        await self._send_assisted_action_notification(alert, action, result)
        
        return result
    
    async def _execute_supervised_action(self, action: AutonomyAction, alert, analysis_result):
        """Execute supervised action requiring explicit approval (Tier 2)"""
        
        if action.action_type == 'request_containment_approval':
            # Send Slack approval request
            approval_id = await self._send_slack_approval_request(
                alert, analysis_result, action.action_data
            )
            
            # Store pending approval
            self.pending_approvals[approval_id] = {
                'action': action,
                'alert': alert,
                'analysis_result': analysis_result,
                'created_at': datetime.now(timezone.utc),
                'status': 'pending'
            }
            
            # Schedule timeout escalation
            asyncio.create_task(
                self._handle_approval_timeout(approval_id, action.approval_timeout_minutes)
            )
            
            return {'status': 'pending_approval', 'approval_id': approval_id}
        
        raise ValueError(f"Unsupported supervised action: {action.action_type}")
    
    async def _execute_collaborative_action(self, action: AutonomyAction, alert, analysis_result):
        """Execute collaborative action with human-AI partnership (Tier 3)"""
        
        if action.action_type == 'initiate_collaboration':
            # Start interactive Slack thread for collaboration
            collaboration_id = await self._initiate_slack_collaboration(
                alert, analysis_result, action.action_data
            )
            
            # Provide AI insights and assistance
            await self._provide_ai_assistance(collaboration_id, alert, analysis_result)
            
            return {'status': 'collaboration_initiated', 'collaboration_id': collaboration_id}
        
        raise ValueError(f"Unsupported collaborative action: {action.action_type}")
    
    async def _close_alert_automatically(self, alert, action_data: Dict[str, Any]) -> Dict[str, Any]:
        """Automatically close an alert (Tier 0/1)"""
        
        # Simulate SIEM integration for alert closure
        closure_data = {
            'alert_id': alert.id,
            'closure_reason': action_data.get('reason', 'AI_ANALYSIS'),
            'closure_timestamp': datetime.now(timezone.utc).isoformat(),
            'confidence_score': action_data.get('confidence'),
            'auto_closed': action_data.get('auto_closed', False)
        }
        
        logger.info(f"Auto-closed alert {alert.id}: {action_data.get('reason')}")
        return closure_data
    
    async def _create_enriched_ticket(self, alert, analysis_result, action_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create enriched JIRA ticket with AI analysis (Tier 1)"""
        
        # Simulate JIRA integration
        ticket_data = {
            'project': self.jira_config.get('project', 'SOC'),
            'issue_type': 'Security Alert',
            'summary': f"[AI-Enriched] {alert.title}",
            'description': self._build_enriched_description(alert, analysis_result),
            'priority': action_data.get('ticket_priority', 'Medium'),
            'labels': ['ai-enriched', f'confidence-{int(analysis_result.confidence_score * 100)}'],
            'custom_fields': {
                'ai_confidence': analysis_result.confidence_score,
                'ai_category': analysis_result.category.value,
                'original_alert_id': alert.id
            }
        }
        
        # Simulate ticket creation
        ticket_id = f"SOC-{hash(alert.id) % 10000:04d}"
        
        logger.info(f"Created enriched ticket {ticket_id} for alert {alert.id}")
        
        return {
            'ticket_id': ticket_id,
            'ticket_data': ticket_data,
            'created_at': datetime.now(timezone.utc).isoformat()
        }
    
    def _build_enriched_description(self, alert, analysis_result) -> str:
        """Build enriched ticket description with AI analysis"""
        
        reasoning_text = '\n'.join(f"• {step}" for step in analysis_result.reasoning_chain)
        
        return f"""
## Original Alert Details
- **Alert ID**: {alert.id}
- **Severity**: {alert.severity.value}
- **Source**: {alert.source}
- **Description**: {alert.description}

## AI Analysis Summary
- **Category**: {analysis_result.category.value}
- **Confidence**: {analysis_result.confidence_score:.1%}
- **Model Used**: {analysis_result.model_used}

## AI Reasoning Chain
{reasoning_text}

## Recommended Action
{analysis_result.recommended_action}

---
*This ticket was automatically enriched by SecOps AI Platform*
        """.strip()
    
    async def _add_to_review_queue(self, alert, analysis_result, queue_name: str):
        """Add action to human review queue"""
        
        review_item = {
            'alert_id': alert.id,
            'queue': queue_name,
            'ai_decision': analysis_result.category.value,
            'confidence': analysis_result.confidence_score,
            'reasoning': analysis_result.reasoning_chain,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'status': 'pending_review'
        }
        
        # Simulate review queue storage
        logger.info(f"Added alert {alert.id} to review queue: {queue_name}")
        
    async def _send_slack_approval_request(self, alert, analysis_result, action_data: Dict[str, Any]) -> str:
        """Send Slack approval request for supervised actions (Tier 2)"""
        
        approval_id = f"approval_{hash(alert.id)}_{int(datetime.now(timezone.utc).timestamp())}"
        
        # Build Slack message with interactive buttons
        slack_message = {
            'text': f"🔍 Security Alert Approval Required - {alert.title}",
            'blocks': [
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': f"*Alert*: {alert.title}\n*Severity*: {alert.severity.value}\n*Confidence*: {analysis_result.confidence_score:.1%}"
                    }
                },
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': f"*AI Recommendation*: {action_data['recommended_actions']}"
                    }
                },
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': '*AI Reasoning*:\n' + '\n'.join(f"• {step}" for step in analysis_result.reasoning_chain[:3])
                    }
                },
                {
                    'type': 'actions',
                    'elements': [
                        {
                            'type': 'button',
                            'text': {'type': 'plain_text', 'text': '✅ Approve'},
                            'style': 'primary',
                            'value': f"{approval_id}:approve"
                        },
                        {
                            'type': 'button', 
                            'text': {'type': 'plain_text', 'text': '✏️ Modify'},
                            'value': f"{approval_id}:modify"
                        },
                        {
                            'type': 'button',
                            'text': {'type': 'plain_text', 'text': '🚨 Escalate'},
                            'style': 'danger',
                            'value': f"{approval_id}:escalate"
                        },
                        {
                            'type': 'button',
                            'text': {'type': 'plain_text', 'text': '❌ Reject'},
                            'value': f"{approval_id}:reject"
                        }
                    ]
                }
            ]
        }
        
        # Simulate Slack webhook call
        logger.info(f"Sent Slack approval request {approval_id} for alert {alert.id}")
        
        return approval_id
    
    async def _initiate_slack_collaboration(self, alert, analysis_result, action_data: Dict[str, Any]) -> str:
        """Initiate collaborative Slack thread (Tier 3)"""
        
        collaboration_id = f"collab_{hash(alert.id)}_{int(datetime.now(timezone.utc).timestamp())}"
        
        # Start Slack thread with AI insights
        slack_message = {
            'text': f"🤖 AI Collaboration: {alert.title}",
            'blocks': [
                {
                    'type': 'section', 
                    'text': {
                        'type': 'mrkdwn',
                        'text': f"*Complex Alert Requires Human-AI Collaboration*\n\n*Alert*: {alert.title}\n*Severity*: {alert.severity.value}"
                    }
                },
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn', 
                        'text': f"*AI Confidence*: {analysis_result.confidence_score:.1%} (requires human expertise)"
                    }
                },
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': '*Recommended Experts*: ' + ', '.join(action_data['expert_consultation'])
                    }
                }
            ]
        }
        
        logger.info(f"Initiated collaboration {collaboration_id} for alert {alert.id}")
        
        return collaboration_id
    
    async def _provide_ai_assistance(self, collaboration_id: str, alert, analysis_result):
        """Provide ongoing AI assistance in collaborative mode"""
        
        # Send follow-up message with detailed AI insights
        assistance_message = {
            'text': '🧠 AI Insights & Assistance',
            'thread_ts': collaboration_id,  # Reply in thread
            'blocks': [
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': '*AI Analysis*:\n' + '\n'.join(f"• {step}" for step in analysis_result.reasoning_chain)
                    }
                },
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': f"*Suggested Next Steps*:\n{self._format_investigation_steps(alert, analysis_result)}"
                    }
                }
            ]
        }
        
        logger.info(f"Provided AI assistance for collaboration {collaboration_id}")
    
    def _format_investigation_steps(self, alert, analysis_result) -> str:
        """Format investigation steps for collaborative mode"""
        
        steps = self._generate_investigation_steps(alert, analysis_result)
        return '\n'.join(f"{i+1}. {step}" for i, step in enumerate(steps))
    
    def _generate_investigation_steps(self, alert, analysis_result) -> List[str]:
        """Generate suggested investigation steps"""
        
        base_steps = [
            "Review alert evidence and logs",
            "Check for similar recent alerts", 
            "Validate with threat intelligence",
            "Assess business impact"
        ]
        
        # Add category-specific steps
        category = analysis_result.category.value
        
        if category == 'containment_required':
            base_steps.extend([
                "Isolate affected systems if confirmed",
                "Preserve forensic evidence",
                "Notify incident response team"
            ])
        elif category == 'novel_threat':
            base_steps.extend([
                "Create new detection rules",
                "Update threat intelligence feeds", 
                "Document new attack pattern"
            ])
        
        return base_steps
    
    def _recommend_experts(self, alert) -> List[str]:
        """Recommend experts for collaborative analysis"""
        
        experts = ['soc-analysts']
        
        # Add specialized experts based on alert characteristics
        if 'network' in alert.source.lower():
            experts.append('network-security')
        if 'endpoint' in alert.source.lower():
            experts.append('endpoint-security')
        if alert.severity.value in ['critical', 'high']:
            experts.append('incident-response')
        
        return experts
    
    def _define_escalation_path(self, alert) -> List[str]:
        """Define escalation path for collaborative mode"""
        
        path = ['soc-analysts', 'security-leads']
        
        if alert.severity.value == 'critical':
            path.extend(['incident-response', 'security-manager'])
        
        return path
    
    def _assess_business_impact(self, alert) -> Dict[str, Any]:
        """Assess potential business impact of alert"""
        
        # Simplified impact assessment
        impact_factors = {
            'asset_criticality': self._assess_asset_criticality(alert),
            'data_sensitivity': self._assess_data_sensitivity(alert),
            'operational_impact': self._assess_operational_impact(alert),
            'financial_risk': self._assess_financial_risk(alert)
        }
        
        # Calculate overall impact score
        impact_score = sum(impact_factors.values()) / len(impact_factors)
        
        return {
            'overall_score': impact_score,
            'factors': impact_factors,
            'impact_level': self._map_impact_score_to_level(impact_score),
            'estimated_cost_if_real': self._estimate_incident_cost(alert, impact_score)
        }
    
    def _assess_asset_criticality(self, alert) -> float:
        """Assess criticality of affected asset"""
        
        critical_keywords = ['domain_controller', 'database', 'financial']
        high_keywords = ['server', 'application', 'network']
        
        alert_text = f"{alert.source} {alert.title}".lower()
        
        if any(keyword in alert_text for keyword in critical_keywords):
            return 1.0
        elif any(keyword in alert_text for keyword in high_keywords):
            return 0.7
        else:
            return 0.3
    
    def _assess_data_sensitivity(self, alert) -> float:
        """Assess sensitivity of potentially affected data"""
        
        sensitive_keywords = ['customer', 'payment', 'personal', 'confidential']
        alert_text = f"{alert.description} {alert.source}".lower()
        
        if any(keyword in alert_text for keyword in sensitive_keywords):
            return 0.9
        else:
            return 0.4
    
    def _assess_operational_impact(self, alert) -> float:
        """Assess potential operational disruption"""
        
        severity_impact = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.5,
            'low': 0.2
        }
        
        return severity_impact.get(alert.severity.value, 0.5)
    
    def _assess_financial_risk(self, alert) -> float:
        """Assess potential financial impact"""
        
        # Simplified financial risk based on asset type and severity
        base_risk = self._assess_asset_criticality(alert)
        severity_multiplier = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.5,
            'low': 0.2
        }
        
        return base_risk * severity_multiplier.get(alert.severity.value, 0.5)
    
    def _map_impact_score_to_level(self, score: float) -> str:
        """Map numerical impact score to level"""
        
        if score >= 0.8:
            return 'critical'
        elif score >= 0.6:
            return 'high'
        elif score >= 0.4:
            return 'medium'
        else:
            return 'low'
    
    def _estimate_incident_cost(self, alert, impact_score: float) -> str:
        """Estimate potential incident cost"""
        
        base_costs = {
            'critical': '$100K - $1M+',
            'high': '$50K - $500K',
            'medium': '$10K - $100K',
            'low': '$1K - $25K'
        }
        
        impact_level = self._map_impact_score_to_level(impact_score)
        return base_costs.get(impact_level, '$1K - $25K')
    
    def _map_severity_to_priority(self, severity: str) -> str:
        """Map alert severity to ticket priority"""
        
        mapping = {
            'critical': 'Critical',
            'high': 'High',
            'medium': 'Medium', 
            'low': 'Low'
        }
        
        return mapping.get(severity, 'Medium')
    
    async def handle_approval_response(self, approval_id: str, response: str, user_id: str) -> Dict[str, Any]:
        """Handle human approval response for supervised actions"""
        
        if approval_id not in self.pending_approvals:
            return {'error': 'Approval request not found'}
        
        approval_data = self.pending_approvals[approval_id]
        approval_data['status'] = 'responded'
        approval_data['response'] = response
        approval_data['responder'] = user_id
        approval_data['responded_at'] = datetime.now(timezone.utc)
        
        # Calculate response time
        response_time = (approval_data['responded_at'] - approval_data['created_at']).total_seconds()
        self.metrics['approval_response_times'].append(response_time)
        
        # Execute approved action or escalate
        result = await self._process_approval_response(approval_data, response)
        
        # Clean up
        del self.pending_approvals[approval_id]
        
        return result
    
    async def _process_approval_response(self, approval_data: Dict[str, Any], response: str) -> Dict[str, Any]:
        """Process the approval response and take appropriate action"""
        
        action = approval_data['action']
        alert = approval_data['alert']
        analysis_result = approval_data['analysis_result']
        
        if response == 'approve':
            # Execute the recommended action
            if action.action_data['recommended_actions']:
                result = await self._execute_approved_containment(alert, action.action_data)
                return {'status': 'executed', 'action': 'containment', 'result': result}
        
        elif response == 'modify':
            # Request modification (would open modal in real implementation)
            return {'status': 'modification_requested', 'requires_input': True}
        
        elif response == 'escalate':
            # Escalate to higher tier
            if action.escalation_tier:
                escalated_action = AutonomyAction(
                    tier=action.escalation_tier,
                    action_type='escalated_collaboration',
                    action_data={**action.action_data, 'escalated_from': action.tier.name},
                    requires_approval=False,
                    approval_timeout_minutes=action.approval_timeout_minutes,
                    escalation_tier=None
                )
                
                self.metrics['escalations'] += 1
                return await self._execute_collaborative_action(escalated_action, alert, analysis_result)
        
        elif response == 'reject':
            # Reject and require manual investigation
            return await self._handle_rejection(alert, analysis_result, approval_data['responder'])
        
        return {'status': 'unknown_response', 'response': response}
    
    async def _execute_approved_containment(self, alert, action_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute approved containment actions"""
        
        containment_actions = action_data['recommended_actions']
        
        # Simulate containment execution
        result = {
            'containment_executed': True,
            'actions_taken': containment_actions,
            'execution_time': datetime.now(timezone.utc).isoformat(),
            'alert_id': alert.id
        }
        
        logger.info(f"Executed approved containment for alert {alert.id}: {containment_actions}")
        
        return result
    
    async def _handle_rejection(self, alert, analysis_result, rejector_user: str) -> Dict[str, Any]:
        """Handle rejection of AI recommendation"""
        
        # Create manual investigation task
        investigation_task = {
            'alert_id': alert.id,
            'ai_recommendation': analysis_result.recommended_action,
            'ai_confidence': analysis_result.confidence_score,
            'rejected_by': rejector_user,
            'rejection_time': datetime.now(timezone.utc).isoformat(),
            'status': 'requires_manual_investigation',
            'assigned_to': 'soc-analysts'
        }
        
        logger.info(f"AI recommendation rejected for alert {alert.id} by {rejector_user}")
        
        return {'status': 'rejected', 'investigation_task': investigation_task}
    
    async def _handle_approval_timeout(self, approval_id: str, timeout_minutes: int):
        """Handle approval timeout and escalate"""
        
        await asyncio.sleep(timeout_minutes * 60)  # Convert to seconds
        
        if approval_id in self.pending_approvals:
            approval_data = self.pending_approvals[approval_id]
            
            if approval_data['status'] == 'pending':  # Not yet responded
                # Escalate due to timeout
                approval_data['status'] = 'timed_out'
                
                action = approval_data['action']
                if action.escalation_tier:
                    # Auto-escalate to higher tier
                    await self._execute_collaborative_action(
                        AutonomyAction(
                            tier=action.escalation_tier,
                            action_type='timeout_escalation',
                            action_data={**action.action_data, 'escalated_reason': 'approval_timeout'},
                            requires_approval=False,
                            approval_timeout_minutes=action.approval_timeout_minutes,
                            escalation_tier=None
                        ),
                        approval_data['alert'],
                        approval_data['analysis_result']
                    )
                
                logger.warning(f"Approval {approval_id} timed out after {timeout_minutes} minutes")
                
                # Clean up
                del self.pending_approvals[approval_id]
    
    async def _send_post_action_notification(self, alert, action: AutonomyAction, result: Dict[str, Any], notification_type: str):
        """Send notification after autonomous action"""
        
        message = f"🤖 Autonomous Action Taken\n\nAlert: {alert.title}\nAction: {action.action_type}\nConfidence: {result.get('confidence', 'N/A')}"
        
        logger.info(f"Post-action notification: {notification_type} for alert {alert.id}")
        
    async def _send_assisted_action_notification(self, alert, action: AutonomyAction, result: Dict[str, Any]):
        """Send notification for assisted action with review capability"""
        
        message = f"🔄 Assisted Action Executed\n\nAlert: {alert.title}\nAction: {action.action_type}\nReview: Available in queue"
        
        logger.info(f"Assisted action notification for alert {alert.id}")
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get autonomy controller performance metrics"""
        
        total_actions = sum(self.metrics['actions_by_tier'].values())
        
        tier_percentages = {}
        for tier, count in self.metrics['actions_by_tier'].items():
            tier_percentages[tier.name.lower()] = (count / total_actions * 100) if total_actions > 0 else 0
        
        avg_response_time = (
            sum(self.metrics['approval_response_times']) / len(self.metrics['approval_response_times'])
            if self.metrics['approval_response_times'] else 0
        )
        
        return {
            'total_actions': total_actions,
            'tier_distribution_percent': tier_percentages,
            'pending_approvals': len(self.pending_approvals),
            'total_escalations': self.metrics['escalations'],
            'avg_approval_response_time_seconds': avg_response_time,
            'false_positive_rate': self.metrics['false_positive_rate']
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Health check for autonomy controller"""
        
        return {
            'status': 'healthy',
            'configuration': {
                'confidence_thresholds': {tier.name: threshold for tier, threshold in self.confidence_thresholds.items()},
                'approval_timeouts': self.approval_timeouts
            },
            'pending_approvals': len(self.pending_approvals),
            'metrics': await self.get_metrics()
        }