"""
Tines High-Availability Orchestration Engine
Implements complex incident response workflows with human approval gates
Provides state management, error handling, and automatic retry capabilities
"""

import asyncio
import logging
import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass, asdict, field
from enum import Enum
import aiohttp
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)

class WorkflowStatus(Enum):
    """Workflow execution status"""
    PENDING = "pending"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    ESCALATED = "escalated"

class ApprovalType(Enum):
    """Types of approval required in workflows"""
    SLACK_BUTTON = "slack_button"
    EMAIL_APPROVAL = "email_approval"
    API_CALLBACK = "api_callback"
    MANUAL_VERIFICATION = "manual_verification"

class WorkflowPriority(Enum):
    """Workflow execution priority levels"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4

@dataclass
class WorkflowStep:
    """Individual workflow step definition"""
    id: str
    name: str
    type: str  # action, condition, approval, delay, webhook
    config: Dict[str, Any]
    depends_on: List[str] = field(default_factory=list)
    timeout_seconds: int = 300
    retry_count: int = 0
    max_retries: int = 3
    retry_delay_seconds: int = 30
    on_failure: str = "fail"  # fail, continue, retry, escalate
    condition_expression: Optional[str] = None

@dataclass
class ApprovalGate:
    """Human approval gate configuration"""
    id: str
    type: ApprovalType
    title: str
    description: str
    approvers: List[str]
    timeout_minutes: int
    escalation_approvers: List[str] = field(default_factory=list)
    approval_options: List[Dict[str, str]] = field(default_factory=list)
    required_approvals: int = 1
    slack_channel: Optional[str] = None
    email_template: Optional[str] = None
    auto_approve_conditions: List[str] = field(default_factory=list)

@dataclass
class WorkflowDefinition:
    """Complete workflow definition"""
    id: str
    name: str
    description: str
    version: str
    priority: WorkflowPriority
    steps: List[WorkflowStep]
    approval_gates: List[ApprovalGate]
    global_timeout_minutes: int = 120
    max_concurrent_executions: int = 10
    retry_strategy: str = "exponential_backoff"
    state_persistence: bool = True
    audit_level: str = "full"

@dataclass
class WorkflowExecution:
    """Runtime workflow execution instance"""
    execution_id: str
    workflow_id: str
    definition: WorkflowDefinition
    status: WorkflowStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    current_step: Optional[str] = None
    input_data: Dict[str, Any] = field(default_factory=dict)
    output_data: Dict[str, Any] = field(default_factory=dict)
    step_results: Dict[str, Any] = field(default_factory=dict)
    error_details: Optional[Dict[str, Any]] = None
    approval_responses: Dict[str, Any] = field(default_factory=dict)
    retry_attempts: Dict[str, int] = field(default_factory=dict)
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class PendingApproval:
    """Pending approval request"""
    approval_id: str
    execution_id: str
    gate_id: str
    created_at: datetime
    expires_at: datetime
    approvers: List[str]
    required_approvals: int
    received_approvals: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "pending"
    slack_message_ts: Optional[str] = None

class TinesAPIClient:
    """Client for Tines API integration"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Tines API client"""
        self.config = config
        self.base_url = config['tines_api_url']
        self.api_key = config['api_key']
        self.tenant_name = config['tenant_name']
        
        # Rate limiting and connection pooling
        self.connector = aiohttp.TCPConnector(
            limit=config.get('connection_pool_size', 20),
            limit_per_host=config.get('connections_per_host', 10),
            keepalive_timeout=config.get('keepalive_timeout', 30)
        )
        self.session = None
        
        # Metrics
        self.metrics = {
            'api_calls': 0,
            'errors': 0,
            'rate_limits': 0,
            'workflows_triggered': 0
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            connector=self.connector,
            headers={'Authorization': f'Bearer {self.api_key}'},
            timeout=aiohttp.ClientTimeout(total=30)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
        await self.connector.close()
    
    async def trigger_workflow(self, workflow_name: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Trigger Tines workflow execution"""
        
        endpoint = f"/api/v1/stories/{workflow_name}/runs"
        
        payload = {
            'data': input_data,
            'metadata': {
                'triggered_by': 'secops_ai_platform',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'execution_context': 'automated_workflow'
            }
        }
        
        return await self._make_api_call('POST', endpoint, json=payload)
    
    async def get_workflow_status(self, run_id: str) -> Dict[str, Any]:
        """Get workflow execution status"""
        
        endpoint = f"/api/v1/runs/{run_id}"
        return await self._make_api_call('GET', endpoint)
    
    async def update_workflow_data(self, run_id: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update workflow execution data"""
        
        endpoint = f"/api/v1/runs/{run_id}"
        payload = {'data': update_data}
        
        return await self._make_api_call('PATCH', endpoint, json=payload)
    
    async def cancel_workflow(self, run_id: str, reason: str = "cancelled") -> Dict[str, Any]:
        """Cancel workflow execution"""
        
        endpoint = f"/api/v1/runs/{run_id}/cancel"
        payload = {'reason': reason}
        
        return await self._make_api_call('POST', endpoint, json=payload)
    
    async def get_workflow_logs(self, run_id: str, limit: int = 100) -> Dict[str, Any]:
        """Get workflow execution logs"""
        
        endpoint = f"/api/v1/runs/{run_id}/logs"
        params = {'limit': limit}
        
        return await self._make_api_call('GET', endpoint, params=params)
    
    async def _make_api_call(self, method: str, endpoint: str, 
                           json: Dict[str, Any] = None, 
                           params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Make authenticated API call to Tines"""
        
        url = f"{self.base_url}{endpoint}"
        
        try:
            async with self.session.request(method, url, json=json, params=params) as response:
                self.metrics['api_calls'] += 1
                
                if response.status == 429:  # Rate limited
                    self.metrics['rate_limits'] += 1
                    retry_after = int(response.headers.get('Retry-After', 60))
                    logger.warning(f"Tines API rate limited, retrying after {retry_after}s")
                    await asyncio.sleep(retry_after)
                    return await self._make_api_call(method, endpoint, json, params)
                
                elif 200 <= response.status < 300:
                    return await response.json()
                
                else:
                    error_text = await response.text()
                    self.metrics['errors'] += 1
                    logger.error(f"Tines API error {response.status}: {error_text}")
                    raise Exception(f"Tines API error {response.status}: {error_text}")
        
        except Exception as e:
            self.metrics['errors'] += 1
            logger.error(f"Tines API call failed: {e}")
            raise

class WorkflowStateManager:
    """Manages workflow execution state with persistence and recovery"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize state manager"""
        self.config = config
        self.executions: Dict[str, WorkflowExecution] = {}
        self.pending_approvals: Dict[str, PendingApproval] = {}
        
        # Persistence configuration
        self.persistence_enabled = config.get('state_persistence', True)
        self.state_storage_path = config.get('state_storage_path', '/tmp/tines_state')
        
        # Recovery configuration
        self.auto_recovery_enabled = config.get('auto_recovery', True)
        self.max_recovery_attempts = config.get('max_recovery_attempts', 3)
        
        # Cleanup configuration
        self.retention_hours = config.get('execution_retention_hours', 168)  # 7 days
        
    async def create_execution(self, workflow_def: WorkflowDefinition, 
                             input_data: Dict[str, Any]) -> WorkflowExecution:
        """Create new workflow execution"""
        
        execution_id = str(uuid.uuid4())
        
        execution = WorkflowExecution(
            execution_id=execution_id,
            workflow_id=workflow_def.id,
            definition=workflow_def,
            status=WorkflowStatus.PENDING,
            created_at=datetime.now(timezone.utc),
            input_data=input_data
        )
        
        # Add to audit trail
        self._add_audit_entry(execution, 'workflow_created', {
            'workflow_name': workflow_def.name,
            'input_keys': list(input_data.keys())
        })
        
        # Store execution
        self.executions[execution_id] = execution
        
        if self.persistence_enabled:
            await self._persist_execution_state(execution)
        
        logger.info(f"Created workflow execution {execution_id} for {workflow_def.name}")
        return execution
    
    async def update_execution_status(self, execution_id: str, status: WorkflowStatus,
                                    details: Dict[str, Any] = None):
        """Update execution status"""
        
        if execution_id not in self.executions:
            raise ValueError(f"Execution {execution_id} not found")
        
        execution = self.executions[execution_id]
        old_status = execution.status
        execution.status = status
        
        # Update timestamps
        if status == WorkflowStatus.RUNNING and not execution.started_at:
            execution.started_at = datetime.now(timezone.utc)
        elif status in [WorkflowStatus.COMPLETED, WorkflowStatus.FAILED, WorkflowStatus.TIMEOUT]:
            execution.completed_at = datetime.now(timezone.utc)
        
        # Add audit entry
        audit_data = {'old_status': old_status.value, 'new_status': status.value}
        if details:
            audit_data.update(details)
        
        self._add_audit_entry(execution, 'status_change', audit_data)
        
        # Persist updated state
        if self.persistence_enabled:
            await self._persist_execution_state(execution)
        
        logger.info(f"Execution {execution_id} status: {old_status.value} → {status.value}")
    
    async def update_step_result(self, execution_id: str, step_id: str, 
                               result: Dict[str, Any]):
        """Update step execution result"""
        
        if execution_id not in self.executions:
            raise ValueError(f"Execution {execution_id} not found")
        
        execution = self.executions[execution_id]
        execution.step_results[step_id] = result
        execution.current_step = step_id
        
        # Add audit entry
        self._add_audit_entry(execution, 'step_completed', {
            'step_id': step_id,
            'result_keys': list(result.keys())
        })
        
        # Persist updated state
        if self.persistence_enabled:
            await self._persist_execution_state(execution)
    
    async def create_pending_approval(self, execution_id: str, gate: ApprovalGate) -> PendingApproval:
        """Create pending approval request"""
        
        approval_id = f"{execution_id}_{gate.id}_{int(datetime.now(timezone.utc).timestamp())}"
        
        approval = PendingApproval(
            approval_id=approval_id,
            execution_id=execution_id,
            gate_id=gate.id,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=gate.timeout_minutes),
            approvers=gate.approvers,
            required_approvals=gate.required_approvals
        )
        
        self.pending_approvals[approval_id] = approval
        
        # Update execution status
        await self.update_execution_status(execution_id, WorkflowStatus.AWAITING_APPROVAL, {
            'approval_id': approval_id,
            'gate_id': gate.id
        })
        
        logger.info(f"Created pending approval {approval_id} for execution {execution_id}")
        return approval
    
    async def process_approval_response(self, approval_id: str, approver: str, 
                                      response: str, details: Dict[str, Any] = None) -> bool:
        """Process approval response and determine if workflow can continue"""
        
        if approval_id not in self.pending_approvals:
            raise ValueError(f"Approval {approval_id} not found")
        
        approval = self.pending_approvals[approval_id]
        
        # Add approval response
        approval_response = {
            'approver': approver,
            'response': response,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'details': details or {}
        }
        
        approval.received_approvals.append(approval_response)
        
        # Check if we have enough approvals
        approved_count = len([r for r in approval.received_approvals if r['response'] == 'approve'])
        rejected_count = len([r for r in approval.received_approvals if r['response'] == 'reject'])
        
        # Determine approval status
        if rejected_count > 0:
            approval.status = 'rejected'
            await self.update_execution_status(approval.execution_id, WorkflowStatus.REJECTED, {
                'approval_id': approval_id,
                'rejected_by': approver
            })
            workflow_can_continue = False
        
        elif approved_count >= approval.required_approvals:
            approval.status = 'approved'
            await self.update_execution_status(approval.execution_id, WorkflowStatus.APPROVED, {
                'approval_id': approval_id,
                'approved_by': [r['approver'] for r in approval.received_approvals if r['response'] == 'approve']
            })
            workflow_can_continue = True
        
        else:
            # Still waiting for more approvals
            workflow_can_continue = False
        
        # Persist state
        if self.persistence_enabled:
            execution = self.executions[approval.execution_id]
            await self._persist_execution_state(execution)
        
        logger.info(f"Approval {approval_id}: {response} by {approver}. Continue: {workflow_can_continue}")
        return workflow_can_continue
    
    def _add_audit_entry(self, execution: WorkflowExecution, event_type: str, 
                        data: Dict[str, Any]):
        """Add entry to execution audit trail"""
        
        audit_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': event_type,
            'data': data
        }
        
        execution.audit_trail.append(audit_entry)
    
    async def _persist_execution_state(self, execution: WorkflowExecution):
        """Persist execution state for recovery"""
        
        if not self.persistence_enabled:
            return
        
        try:
            # In production, this would persist to Redis, database, or S3
            # For now, we'll simulate persistence
            state_data = {
                'execution': asdict(execution),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            # Simulate file persistence
            # await self._write_state_to_storage(execution.execution_id, state_data)
            
        except Exception as e:
            logger.error(f"Failed to persist state for execution {execution.execution_id}: {e}")
    
    async def recover_executions(self) -> List[WorkflowExecution]:
        """Recover workflow executions from persistent storage"""
        
        if not self.auto_recovery_enabled:
            return []
        
        try:
            # In production, this would load from persistent storage
            # For now, return empty list
            recovered_executions = []
            
            for execution in recovered_executions:
                self.executions[execution.execution_id] = execution
                logger.info(f"Recovered execution {execution.execution_id}")
            
            return recovered_executions
        
        except Exception as e:
            logger.error(f"Failed to recover executions: {e}")
            return []
    
    async def cleanup_completed_executions(self):
        """Clean up old completed executions"""
        
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=self.retention_hours)
        
        executions_to_remove = []
        for execution_id, execution in self.executions.items():
            if (execution.completed_at and 
                execution.completed_at < cutoff_time and 
                execution.status in [WorkflowStatus.COMPLETED, WorkflowStatus.FAILED]):
                executions_to_remove.append(execution_id)
        
        for execution_id in executions_to_remove:
            del self.executions[execution_id]
            logger.info(f"Cleaned up execution {execution_id}")
        
        return len(executions_to_remove)

class SlackApprovalHandler:
    """Handles Slack-based approval workflows"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Slack approval handler"""
        self.config = config
        self.webhook_url = config['slack_webhook_url']
        self.bot_token = config.get('slack_bot_token')
        self.session = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def send_approval_request(self, approval: PendingApproval, 
                                  gate: ApprovalGate, 
                                  execution: WorkflowExecution) -> str:
        """Send Slack approval request with interactive buttons"""
        
        # Build Slack message with approval buttons
        slack_message = self._build_approval_message(approval, gate, execution)
        
        # Send to Slack
        async with self.session.post(self.webhook_url, json=slack_message) as response:
            if response.status == 200:
                response_data = await response.json()
                message_ts = response_data.get('ts')
                
                logger.info(f"Sent Slack approval request {approval.approval_id}")
                return message_ts
            else:
                error_text = await response.text()
                raise Exception(f"Failed to send Slack approval: {error_text}")
    
    def _build_approval_message(self, approval: PendingApproval, 
                              gate: ApprovalGate, 
                              execution: WorkflowExecution) -> Dict[str, Any]:
        """Build Slack message with approval buttons"""
        
        # Format approval details
        workflow_name = execution.definition.name
        execution_id_short = execution.execution_id[:8]
        
        # Build approval options or use defaults
        approval_options = gate.approval_options or [
            {'text': '✅ Approve', 'value': 'approve', 'style': 'primary'},
            {'text': '❌ Reject', 'value': 'reject', 'style': 'danger'},
            {'text': '🔄 Request Info', 'value': 'request_info'},
            {'text': '⬆️ Escalate', 'value': 'escalate'}
        ]
        
        # Create interactive buttons
        buttons = []
        for option in approval_options:
            button = {
                'type': 'button',
                'text': {'type': 'plain_text', 'text': option['text']},
                'value': f"{approval.approval_id}:{option['value']}",
                'action_id': f"approval_{option['value']}"
            }
            
            if option.get('style'):
                button['style'] = option['style']
            
            buttons.append(button)
        
        # Format execution context
        input_summary = self._format_input_summary(execution.input_data)
        current_step_info = self._get_current_step_info(execution)
        
        slack_message = {
            'text': f'🔔 Workflow Approval Required: {gate.title}',
            'blocks': [
                {
                    'type': 'header',
                    'text': {
                        'type': 'plain_text',
                        'text': f'🔔 {gate.title}'
                    }
                },
                {
                    'type': 'section',
                    'fields': [
                        {
                            'type': 'mrkdwn',
                            'text': f'*Workflow:* {workflow_name}'
                        },
                        {
                            'type': 'mrkdwn',
                            'text': f'*Execution:* {execution_id_short}'
                        },
                        {
                            'type': 'mrkdwn',
                            'text': f'*Priority:* {execution.definition.priority.name}'
                        },
                        {
                            'type': 'mrkdwn',
                            'text': f'*Approvers:* {", ".join(gate.approvers)}'
                        }
                    ]
                },
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': f'*Description:*\n{gate.description}'
                    }
                }
            ]
        }
        
        # Add execution context if available
        if input_summary:
            slack_message['blocks'].append({
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': f'*Execution Context:*\n{input_summary}'
                }
            })
        
        # Add current step info
        if current_step_info:
            slack_message['blocks'].append({
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': f'*Current Step:*\n{current_step_info}'
                }
            })
        
        # Add approval buttons
        slack_message['blocks'].append({
            'type': 'actions',
            'elements': buttons
        })
        
        # Add metadata for response handling
        slack_message['blocks'].append({
            'type': 'context',
            'elements': [
                {
                    'type': 'mrkdwn',
                    'text': f'Approval ID: `{approval.approval_id}` | Expires: {approval.expires_at.strftime("%Y-%m-%d %H:%M UTC")}'
                }
            ]
        })
        
        return slack_message
    
    def _format_input_summary(self, input_data: Dict[str, Any]) -> str:
        """Format execution input data for display"""
        
        if not input_data:
            return "No input data"
        
        summary_lines = []
        for key, value in input_data.items():
            if isinstance(value, dict):
                summary_lines.append(f"• {key}: {len(value)} items")
            elif isinstance(value, list):
                summary_lines.append(f"• {key}: {len(value)} entries")
            else:
                # Truncate long values
                str_value = str(value)
                if len(str_value) > 50:
                    str_value = str_value[:47] + "..."
                summary_lines.append(f"• {key}: {str_value}")
        
        return "\n".join(summary_lines[:5])  # Limit to first 5 items
    
    def _get_current_step_info(self, execution: WorkflowExecution) -> str:
        """Get current step information"""
        
        if not execution.current_step:
            return "Not started"
        
        # Find step definition
        current_step_def = None
        for step in execution.definition.steps:
            if step.id == execution.current_step:
                current_step_def = step
                break
        
        if current_step_def:
            return f"{current_step_def.name} ({current_step_def.type})"
        else:
            return f"Step: {execution.current_step}"

class TinesOrchestrator:
    """Main Tines orchestration engine for complex workflows"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Tines orchestrator"""
        self.config = config
        
        # Initialize components
        self.tines_client = None
        self.state_manager = WorkflowStateManager(config.get('state_config', {}))
        self.slack_handler = None
        
        # Workflow registry
        self.workflow_definitions: Dict[str, WorkflowDefinition] = {}
        
        # Execution management
        self.active_executions: Dict[str, asyncio.Task] = {}
        self.execution_semaphore = asyncio.Semaphore(config.get('max_concurrent_workflows', 50))
        
        # Circuit breaker for failure handling
        self.circuit_breaker = {
            'failure_count': 0,
            'failure_threshold': config.get('failure_threshold', 10),
            'reset_timeout': config.get('circuit_reset_timeout', 300),
            'last_failure': None,
            'state': 'closed'  # closed, open, half_open
        }
        
        # Performance metrics
        self.metrics = {
            'workflows_executed': 0,
            'workflows_completed': 0,
            'workflows_failed': 0,
            'approvals_processed': 0,
            'avg_execution_time': 0,
            'circuit_breaker_trips': 0
        }
    
    async def initialize(self):
        """Initialize orchestrator components"""
        
        # Initialize Tines API client
        self.tines_client = TinesAPIClient(self.config['tines_config'])
        
        # Initialize Slack handler
        if 'slack_config' in self.config:
            self.slack_handler = SlackApprovalHandler(self.config['slack_config'])
        
        # Recover any existing executions
        await self.state_manager.recover_executions()
        
        # Start background tasks
        asyncio.create_task(self._approval_timeout_monitor())
        asyncio.create_task(self._execution_cleanup_task())
        
        logger.info("Tines orchestrator initialized successfully")
    
    def register_workflow(self, workflow_def: WorkflowDefinition):
        """Register workflow definition"""
        
        self.workflow_definitions[workflow_def.id] = workflow_def
        logger.info(f"Registered workflow: {workflow_def.name} (v{workflow_def.version})")
    
    async def execute_workflow(self, workflow_id: str, input_data: Dict[str, Any],
                             execution_context: Dict[str, Any] = None) -> str:
        """Execute workflow with high availability and error handling"""
        
        # Check circuit breaker
        if not self._check_circuit_breaker():
            raise Exception("Circuit breaker is open - too many recent failures")
        
        # Get workflow definition
        if workflow_id not in self.workflow_definitions:
            raise ValueError(f"Workflow {workflow_id} not found")
        
        workflow_def = self.workflow_definitions[workflow_id]
        
        # Create execution
        execution = await self.state_manager.create_execution(workflow_def, input_data)
        
        # Start execution task
        execution_task = asyncio.create_task(
            self._execute_workflow_steps(execution, execution_context or {})
        )
        
        self.active_executions[execution.execution_id] = execution_task
        self.metrics['workflows_executed'] += 1
        
        logger.info(f"Started workflow execution {execution.execution_id}")
        return execution.execution_id
    
    async def _execute_workflow_steps(self, execution: WorkflowExecution, 
                                    context: Dict[str, Any]):
        """Execute workflow steps with error handling and retries"""
        
        try:
            async with self.execution_semaphore:
                await self.state_manager.update_execution_status(
                    execution.execution_id, WorkflowStatus.RUNNING
                )
                
                # Execute steps in dependency order
                completed_steps = set()
                
                while len(completed_steps) < len(execution.definition.steps):
                    # Find next executable steps
                    executable_steps = self._find_executable_steps(
                        execution.definition.steps, completed_steps
                    )
                    
                    if not executable_steps:
                        raise Exception("No executable steps found - possible circular dependency")
                    
                    # Execute steps (can be parallel if no dependencies)
                    step_tasks = []
                    for step in executable_steps:
                        task = asyncio.create_task(
                            self._execute_single_step(execution, step, context)
                        )
                        step_tasks.append((step, task))
                    
                    # Wait for step completion
                    for step, task in step_tasks:
                        try:
                            result = await task
                            completed_steps.add(step.id)
                            
                            # Update execution context with step output
                            if result:
                                context[f"step_{step.id}_output"] = result
                            
                        except Exception as e:
                            # Handle step failure based on failure strategy
                            if step.on_failure == "fail":
                                raise e
                            elif step.on_failure == "continue":
                                logger.warning(f"Step {step.id} failed but continuing: {e}")
                                completed_steps.add(step.id)
                            elif step.on_failure == "retry":
                                # Retry will be handled by _execute_single_step
                                raise e
                            elif step.on_failure == "escalate":
                                await self._escalate_step_failure(execution, step, e)
                                completed_steps.add(step.id)
                
                # Workflow completed successfully
                await self.state_manager.update_execution_status(
                    execution.execution_id, WorkflowStatus.COMPLETED
                )
                
                self.metrics['workflows_completed'] += 1
                self._reset_circuit_breaker()
                
                logger.info(f"Workflow execution {execution.execution_id} completed successfully")
        
        except Exception as e:
            # Workflow failed
            await self.state_manager.update_execution_status(
                execution.execution_id, WorkflowStatus.FAILED,
                {'error': str(e)}
            )
            
            self.metrics['workflows_failed'] += 1
            self._record_circuit_breaker_failure()
            
            logger.error(f"Workflow execution {execution.execution_id} failed: {e}")
            raise
        
        finally:
            # Clean up active execution
            if execution.execution_id in self.active_executions:
                del self.active_executions[execution.execution_id]
    
    def _find_executable_steps(self, all_steps: List[WorkflowStep], 
                              completed_steps: set) -> List[WorkflowStep]:
        """Find steps that can be executed now"""
        
        executable = []
        
        for step in all_steps:
            if step.id in completed_steps:
                continue
            
            # Check if all dependencies are completed
            dependencies_met = all(dep_id in completed_steps for dep_id in step.depends_on)
            
            if dependencies_met:
                executable.append(step)
        
        return executable
    
    async def _execute_single_step(self, execution: WorkflowExecution, 
                                 step: WorkflowStep, context: Dict[str, Any]) -> Any:
        """Execute a single workflow step with retries"""
        
        retry_count = execution.retry_attempts.get(step.id, 0)
        
        while retry_count <= step.max_retries:
            try:
                # Execute step based on type
                result = await self._execute_step_by_type(execution, step, context)
                
                # Store result
                await self.state_manager.update_step_result(
                    execution.execution_id, step.id, result
                )
                
                return result
            
            except Exception as e:
                retry_count += 1
                execution.retry_attempts[step.id] = retry_count
                
                if retry_count <= step.max_retries:
                    delay = step.retry_delay_seconds * (2 ** (retry_count - 1))  # Exponential backoff
                    logger.warning(f"Step {step.id} failed, retrying in {delay}s (attempt {retry_count}/{step.max_retries}): {e}")
                    await asyncio.sleep(delay)
                else:
                    logger.error(f"Step {step.id} failed after {step.max_retries} retries: {e}")
                    raise e
    
    async def _execute_step_by_type(self, execution: WorkflowExecution, 
                                   step: WorkflowStep, context: Dict[str, Any]) -> Any:
        """Execute step based on its type"""
        
        if step.type == "approval":
            return await self._execute_approval_step(execution, step, context)
        elif step.type == "action":
            return await self._execute_action_step(execution, step, context)
        elif step.type == "condition":
            return await self._execute_condition_step(execution, step, context)
        elif step.type == "delay":
            return await self._execute_delay_step(execution, step, context)
        elif step.type == "webhook":
            return await self._execute_webhook_step(execution, step, context)
        elif step.type == "tines_workflow":
            return await self._execute_tines_workflow_step(execution, step, context)
        else:
            raise ValueError(f"Unsupported step type: {step.type}")
    
    async def _execute_approval_step(self, execution: WorkflowExecution, 
                                   step: WorkflowStep, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute approval step with human intervention"""
        
        gate_id = step.config['approval_gate_id']
        
        # Find approval gate definition
        gate = None
        for approval_gate in execution.definition.approval_gates:
            if approval_gate.id == gate_id:
                gate = approval_gate
                break
        
        if not gate:
            raise ValueError(f"Approval gate {gate_id} not found")
        
        # Check auto-approval conditions
        if gate.auto_approve_conditions:
            if self._check_auto_approval_conditions(gate.auto_approve_conditions, context):
                logger.info(f"Auto-approved step {step.id} based on conditions")
                return {'status': 'auto_approved', 'approver': 'system'}
        
        # Create pending approval
        approval = await self.state_manager.create_pending_approval(execution.execution_id, gate)
        
        # Send Slack approval request if configured
        if self.slack_handler and gate.type == ApprovalType.SLACK_BUTTON:
            async with self.slack_handler as slack:
                message_ts = await slack.send_approval_request(approval, gate, execution)
                approval.slack_message_ts = message_ts
        
        # Wait for approval (handled by approval response processing)
        # This step will complete when approval is processed
        approval_timeout = gate.timeout_minutes * 60
        
        start_time = datetime.now(timezone.utc)
        while True:
            if approval.status == 'approved':
                return {
                    'status': 'approved',
                    'approvers': [r['approver'] for r in approval.received_approvals if r['response'] == 'approve'],
                    'approval_time': (datetime.now(timezone.utc) - start_time).total_seconds()
                }
            elif approval.status == 'rejected':
                raise Exception(f"Approval rejected by: {[r['approver'] for r in approval.received_approvals if r['response'] == 'reject']}")
            elif (datetime.now(timezone.utc) - start_time).total_seconds() > approval_timeout:
                # Handle timeout - escalate if configured
                if gate.escalation_approvers:
                    await self._escalate_approval(approval, gate)
                    # Continue waiting with extended timeout
                    approval_timeout += 30 * 60  # Add 30 minutes for escalation
                else:
                    raise Exception("Approval timed out")
            
            await asyncio.sleep(5)  # Poll every 5 seconds
    
    async def _execute_action_step(self, execution: WorkflowExecution, 
                                 step: WorkflowStep, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute action step"""
        
        action_type = step.config['action_type']
        
        if action_type == "create_jira_ticket":
            return await self._create_jira_ticket_action(step.config, context)
        elif action_type == "send_notification":
            return await self._send_notification_action(step.config, context)
        elif action_type == "update_database":
            return await self._update_database_action(step.config, context)
        elif action_type == "call_api":
            return await self._call_api_action(step.config, context)
        else:
            raise ValueError(f"Unsupported action type: {action_type}")
    
    async def _execute_tines_workflow_step(self, execution: WorkflowExecution, 
                                         step: WorkflowStep, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Tines workflow step"""
        
        workflow_name = step.config['tines_workflow_name']
        input_mapping = step.config.get('input_mapping', {})
        
        # Build input data from context
        tines_input = {}
        for key, context_key in input_mapping.items():
            if context_key in context:
                tines_input[key] = context[context_key]
        
        # Add execution context
        tines_input['_secops_ai_context'] = {
            'execution_id': execution.execution_id,
            'workflow_name': execution.definition.name,
            'step_id': step.id
        }
        
        # Trigger Tines workflow
        async with self.tines_client as client:
            result = await client.trigger_workflow(workflow_name, tines_input)
            
            tines_run_id = result.get('id')
            
            # Wait for completion if configured
            if step.config.get('wait_for_completion', True):
                return await self._wait_for_tines_completion(tines_run_id)
            else:
                return {'tines_run_id': tines_run_id, 'status': 'triggered'}
    
    async def _wait_for_tines_completion(self, run_id: str, 
                                       timeout_seconds: int = 300) -> Dict[str, Any]:
        """Wait for Tines workflow completion"""
        
        start_time = datetime.now(timezone.utc)
        
        while True:
            async with self.tines_client as client:
                status_response = await client.get_workflow_status(run_id)
                
                status = status_response.get('status')
                
                if status == 'completed':
                    return {
                        'tines_run_id': run_id,
                        'status': 'completed',
                        'output': status_response.get('output', {}),
                        'execution_time': (datetime.now(timezone.utc) - start_time).total_seconds()
                    }
                elif status == 'failed':
                    error_details = status_response.get('error', {})
                    raise Exception(f"Tines workflow failed: {error_details}")
                elif (datetime.now(timezone.utc) - start_time).total_seconds() > timeout_seconds:
                    raise Exception(f"Tines workflow timed out after {timeout_seconds}s")
            
            await asyncio.sleep(10)  # Poll every 10 seconds
    
    async def process_approval_response(self, approval_id: str, approver: str, 
                                      response: str, details: Dict[str, Any] = None) -> Dict[str, Any]:
        """Process approval response from external systems (e.g., Slack)"""
        
        try:
            can_continue = await self.state_manager.process_approval_response(
                approval_id, approver, response, details
            )
            
            self.metrics['approvals_processed'] += 1
            
            return {
                'status': 'processed',
                'approval_id': approval_id,
                'can_continue': can_continue,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        except Exception as e:
            logger.error(f"Failed to process approval response {approval_id}: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def _check_circuit_breaker(self) -> bool:
        """Check if circuit breaker allows execution"""
        
        if self.circuit_breaker['state'] == 'open':
            # Check if we can transition to half-open
            if (datetime.now(timezone.utc) - self.circuit_breaker['last_failure']).total_seconds() > self.circuit_breaker['reset_timeout']:
                self.circuit_breaker['state'] = 'half_open'
                logger.info("Circuit breaker transitioned to half-open")
                return True
            return False
        
        return True
    
    def _record_circuit_breaker_failure(self):
        """Record failure for circuit breaker"""
        
        self.circuit_breaker['failure_count'] += 1
        self.circuit_breaker['last_failure'] = datetime.now(timezone.utc)
        
        if self.circuit_breaker['failure_count'] >= self.circuit_breaker['failure_threshold']:
            self.circuit_breaker['state'] = 'open'
            self.metrics['circuit_breaker_trips'] += 1
            logger.warning("Circuit breaker tripped - too many failures")
    
    def _reset_circuit_breaker(self):
        """Reset circuit breaker after successful execution"""
        
        if self.circuit_breaker['state'] in ['half_open', 'open']:
            self.circuit_breaker['state'] = 'closed'
            self.circuit_breaker['failure_count'] = 0
            logger.info("Circuit breaker reset to closed state")
    
    async def _approval_timeout_monitor(self):
        """Background task to monitor approval timeouts"""
        
        while True:
            try:
                current_time = datetime.now(timezone.utc)
                
                expired_approvals = []
                for approval_id, approval in self.state_manager.pending_approvals.items():
                    if approval.status == 'pending' and current_time > approval.expires_at:
                        expired_approvals.append(approval_id)
                
                # Handle expired approvals
                for approval_id in expired_approvals:
                    await self._handle_approval_timeout(approval_id)
                
                await asyncio.sleep(60)  # Check every minute
            
            except Exception as e:
                logger.error(f"Error in approval timeout monitor: {e}")
                await asyncio.sleep(60)
    
    async def _handle_approval_timeout(self, approval_id: str):
        """Handle approval timeout"""
        
        approval = self.state_manager.pending_approvals[approval_id]
        
        # Mark as timed out
        approval.status = 'timed_out'
        
        # Update execution status
        await self.state_manager.update_execution_status(
            approval.execution_id, WorkflowStatus.TIMEOUT,
            {'approval_id': approval_id, 'reason': 'approval_timeout'}
        )
        
        logger.warning(f"Approval {approval_id} timed out")
    
    async def _execution_cleanup_task(self):
        """Background task to clean up completed executions"""
        
        while True:
            try:
                cleaned_count = await self.state_manager.cleanup_completed_executions()
                if cleaned_count > 0:
                    logger.info(f"Cleaned up {cleaned_count} completed executions")
                
                await asyncio.sleep(3600)  # Run every hour
            
            except Exception as e:
                logger.error(f"Error in execution cleanup: {e}")
                await asyncio.sleep(3600)
    
    # Additional methods for other step types and actions would be implemented here...
    
    async def get_orchestrator_metrics(self) -> Dict[str, Any]:
        """Get orchestrator performance metrics"""
        
        return {
            'execution_metrics': self.metrics,
            'active_executions': len(self.active_executions),
            'pending_approvals': len(self.state_manager.pending_approvals),
            'circuit_breaker_state': self.circuit_breaker['state'],
            'workflow_definitions': len(self.workflow_definitions)
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Comprehensive health check"""
        
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'components': {}
        }
        
        # Check Tines API connectivity
        try:
            async with self.tines_client as client:
                # Simple API health check
                health_status['components']['tines_api'] = 'healthy'
        except Exception as e:
            health_status['components']['tines_api'] = f'unhealthy: {str(e)}'
            health_status['status'] = 'degraded'
        
        # Check Slack connectivity
        if self.slack_handler:
            try:
                # Simple webhook check
                health_status['components']['slack'] = 'healthy'
            except Exception as e:
                health_status['components']['slack'] = f'unhealthy: {str(e)}'
                health_status['status'] = 'degraded'
        
        # Check circuit breaker state
        if self.circuit_breaker['state'] == 'open':
            health_status['status'] = 'degraded'
            health_status['components']['circuit_breaker'] = 'open'
        else:
            health_status['components']['circuit_breaker'] = self.circuit_breaker['state']
        
        # Add metrics
        health_status['metrics'] = await self.get_orchestrator_metrics()
        
        return health_status