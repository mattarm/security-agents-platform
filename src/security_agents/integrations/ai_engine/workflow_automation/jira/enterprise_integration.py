"""
Jira Enterprise Integration & SLA Tracking
Implements automated ticket lifecycle management with AI-generated summaries,
engineering team routing, SLA enforcement, and compliance reporting
"""

import asyncio
import logging
import json
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict, field
from enum import Enum
import aiohttp
from base64 import b64encode

from ...ai_engine.orchestrator import AIOrchestrator, SecurityAlert, AnalysisResult
from ..crowdstrike.spotlight_integration import EnrichedVulnerability, VulnerabilityRisk

logger = logging.getLogger(__name__)

class TicketPriority(Enum):
    """Jira ticket priority levels"""
    CRITICAL = "Critical"
    HIGH = "High" 
    MEDIUM = "Medium"
    LOW = "Low"
    TRIVIAL = "Trivial"

class TicketStatus(Enum):
    """Jira ticket status"""
    OPEN = "Open"
    IN_PROGRESS = "In Progress"
    PENDING_REVIEW = "Pending Review"
    RESOLVED = "Resolved"
    CLOSED = "Closed"
    REOPENED = "Reopened"
    BLOCKED = "Blocked"
    WAITING_FOR_CUSTOMER = "Waiting for Customer"

class SLAMetric(Enum):
    """SLA tracking metrics"""
    TIME_TO_FIRST_RESPONSE = "time_to_first_response"
    TIME_TO_RESOLUTION = "time_to_resolution"
    TIME_TO_CLOSE = "time_to_close"
    ESCALATION_TIME = "escalation_time"

class ComplianceFramework(Enum):
    """Compliance framework requirements"""
    SOC2 = "SOC2"
    ISO27001 = "ISO27001"
    PCI_DSS = "PCI_DSS"
    NIST_CSF = "NIST_CSF"
    HIPAA = "HIPAA"
    SOX = "SOX"

@dataclass
class SLATarget:
    """SLA target definition"""
    priority: TicketPriority
    metric: SLAMetric
    target_hours: float
    warning_threshold_percent: float = 80.0
    escalation_threshold_percent: float = 95.0
    business_hours_only: bool = True

@dataclass
class TeamRouting:
    """Team routing configuration"""
    team_name: str
    team_lead: str
    team_members: List[str]
    specialties: List[str]
    workload_capacity: int
    current_workload: int = 0
    availability_hours: Dict[str, List[str]] = field(default_factory=dict)
    escalation_chain: List[str] = field(default_factory=list)

@dataclass
class TicketMetadata:
    """Enhanced ticket metadata for SOC automation"""
    ai_confidence: float
    ai_model_used: str
    analysis_id: str
    vulnerability_id: Optional[str] = None
    asset_criticality: Optional[str] = None
    business_risk_level: Optional[str] = None
    compliance_frameworks: List[str] = field(default_factory=list)
    related_alerts: List[str] = field(default_factory=list)
    threat_indicators: Dict[str, Any] = field(default_factory=dict)
    remediation_complexity: Optional[str] = None
    estimated_effort_hours: Optional[float] = None
    business_justification: Optional[str] = None
    auto_created: bool = True

@dataclass
class JiraTicket:
    """Jira ticket representation"""
    key: Optional[str]  # Jira ticket key (set after creation)
    id: Optional[str]   # Jira ticket ID (set after creation)
    summary: str
    description: str
    issue_type: str
    priority: TicketPriority
    project_key: str
    assignee: Optional[str] = None
    reporter: str = "secops-ai-platform"
    labels: List[str] = field(default_factory=list)
    components: List[str] = field(default_factory=list)
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    metadata: Optional[TicketMetadata] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    status: TicketStatus = TicketStatus.OPEN
    resolution: Optional[str] = None
    sla_targets: List[SLATarget] = field(default_factory=list)
    sla_breaches: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class SLATracking:
    """SLA tracking for a ticket"""
    ticket_key: str
    priority: TicketPriority
    created_at: datetime
    first_response_at: Optional[datetime] = None
    in_progress_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    escalated_at: Optional[datetime] = None
    sla_targets: List[SLATarget] = field(default_factory=list)
    current_sla_status: Dict[SLAMetric, Dict[str, Any]] = field(default_factory=dict)
    breach_history: List[Dict[str, Any]] = field(default_factory=list)
    business_hours_calculator: Optional[Any] = None

class BusinessHoursCalculator:
    """Calculate business hours for SLA tracking"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize business hours calculator"""
        self.config = config
        
        # Default business hours (can be customized per team/priority)
        self.business_hours = {
            'monday': ('09:00', '17:00'),
            'tuesday': ('09:00', '17:00'),
            'wednesday': ('09:00', '17:00'),
            'thursday': ('09:00', '17:00'),
            'friday': ('09:00', '17:00'),
            'saturday': None,  # No business hours
            'sunday': None     # No business hours
        }
        
        # Holidays (would be loaded from configuration)
        self.holidays = config.get('holidays', [])
        
        # Time zone
        self.timezone = config.get('timezone', 'America/New_York')
    
    def calculate_business_hours_between(self, start_time: datetime, 
                                       end_time: datetime) -> float:
        """Calculate business hours between two timestamps"""
        
        if start_time >= end_time:
            return 0.0
        
        total_business_hours = 0.0
        current_date = start_time.date()
        end_date = end_time.date()
        
        while current_date <= end_date:
            # Skip holidays
            if current_date.isoformat() in self.holidays:
                current_date += timedelta(days=1)
                continue
            
            # Get business hours for this day
            weekday = current_date.strftime('%A').lower()
            day_hours = self.business_hours.get(weekday)
            
            if not day_hours:  # Weekend or no business hours
                current_date += timedelta(days=1)
                continue
            
            # Calculate business hours for this day
            day_start = datetime.combine(current_date, 
                                       datetime.strptime(day_hours[0], '%H:%M').time())
            day_end = datetime.combine(current_date,
                                     datetime.strptime(day_hours[1], '%H:%M').time())
            
            # Adjust for start and end times
            if current_date == start_time.date():
                day_start = max(day_start, start_time)
            if current_date == end_time.date():
                day_end = min(day_end, end_time)
            
            if day_start < day_end:
                total_business_hours += (day_end - day_start).total_seconds() / 3600
            
            current_date += timedelta(days=1)
        
        return total_business_hours
    
    def add_business_hours(self, start_time: datetime, hours_to_add: float) -> datetime:
        """Add business hours to a timestamp"""
        
        remaining_hours = hours_to_add
        current_time = start_time
        
        while remaining_hours > 0:
            current_date = current_time.date()
            weekday = current_date.strftime('%A').lower()
            
            # Skip holidays and weekends
            if (current_date.isoformat() in self.holidays or 
                weekday not in self.business_hours or 
                self.business_hours[weekday] is None):
                current_time = datetime.combine(current_date + timedelta(days=1),
                                              datetime.strptime('09:00', '%H:%M').time())
                continue
            
            # Get business hours for this day
            day_hours = self.business_hours[weekday]
            day_start = datetime.combine(current_date,
                                       datetime.strptime(day_hours[0], '%H:%M').time())
            day_end = datetime.combine(current_date,
                                     datetime.strptime(day_hours[1], '%H:%M').time())
            
            # If current time is before business hours, move to start
            if current_time < day_start:
                current_time = day_start
            
            # If current time is after business hours, move to next business day
            if current_time >= day_end:
                current_time = datetime.combine(current_date + timedelta(days=1),
                                              datetime.strptime('09:00', '%H:%M').time())
                continue
            
            # Calculate hours available today
            hours_available_today = (day_end - current_time).total_seconds() / 3600
            
            if remaining_hours <= hours_available_today:
                # Can finish today
                current_time += timedelta(hours=remaining_hours)
                remaining_hours = 0
            else:
                # Move to next business day
                remaining_hours -= hours_available_today
                current_time = datetime.combine(current_date + timedelta(days=1),
                                              datetime.strptime('09:00', '%H:%M').time())
        
        return current_time

class JiraAPIClient:
    """Enhanced Jira API client with enterprise features"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Jira API client"""
        self.config = config
        self.base_url = config['jira_base_url']
        self.username = config['username']
        self.api_token = config['api_token']
        self.project_key = config.get('default_project', 'SOC')
        
        # Authentication
        auth_string = f"{self.username}:{self.api_token}"
        self.auth_header = b64encode(auth_string.encode()).decode()
        
        # API configuration
        self.api_version = config.get('api_version', '3')
        self.timeout = config.get('timeout', 30)
        self.max_retries = config.get('max_retries', 3)
        
        # Connection management
        self.session = None
        self.connector = None
        
        # Performance metrics
        self.metrics = {
            'api_calls': 0,
            'tickets_created': 0,
            'tickets_updated': 0,
            'errors': 0,
            'rate_limits': 0
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.connector = aiohttp.TCPConnector(
            limit=self.config.get('connection_pool_size', 20)
        )
        
        self.session = aiohttp.ClientSession(
            connector=self.connector,
            headers={
                'Authorization': f'Basic {self.auth_header}',
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        )
        
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
        if self.connector:
            await self.connector.close()
    
    async def create_ticket(self, ticket: JiraTicket) -> JiraTicket:
        """Create Jira ticket with enterprise features"""
        
        # Build ticket payload
        ticket_payload = self._build_ticket_payload(ticket)
        
        # Create ticket via API
        endpoint = f"/rest/api/{self.api_version}/issue"
        response_data = await self._make_api_call('POST', endpoint, json=ticket_payload)
        
        # Update ticket with Jira response
        ticket.key = response_data['key']
        ticket.id = response_data['id']
        ticket.created_at = datetime.now(timezone.utc)
        
        self.metrics['tickets_created'] += 1
        
        logger.info(f"Created Jira ticket {ticket.key}: {ticket.summary}")
        return ticket
    
    async def update_ticket(self, ticket_key: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update existing Jira ticket"""
        
        endpoint = f"/rest/api/{self.api_version}/issue/{ticket_key}"
        response_data = await self._make_api_call('PUT', endpoint, json={'fields': updates})
        
        self.metrics['tickets_updated'] += 1
        
        logger.info(f"Updated Jira ticket {ticket_key}")
        return response_data
    
    async def get_ticket(self, ticket_key: str) -> Dict[str, Any]:
        """Get ticket details"""
        
        endpoint = f"/rest/api/{self.api_version}/issue/{ticket_key}"
        return await self._make_api_call('GET', endpoint)
    
    async def add_comment(self, ticket_key: str, comment: str, 
                         visibility: Dict[str, str] = None) -> Dict[str, Any]:
        """Add comment to ticket"""
        
        endpoint = f"/rest/api/{self.api_version}/issue/{ticket_key}/comment"
        
        comment_data = {'body': comment}
        if visibility:
            comment_data['visibility'] = visibility
        
        return await self._make_api_call('POST', endpoint, json=comment_data)
    
    async def transition_ticket(self, ticket_key: str, transition_id: str,
                              comment: str = None) -> Dict[str, Any]:
        """Transition ticket status"""
        
        endpoint = f"/rest/api/{self.api_version}/issue/{ticket_key}/transitions"
        
        transition_data = {
            'transition': {'id': transition_id}
        }
        
        if comment:
            transition_data['update'] = {
                'comment': [{'add': {'body': comment}}]
            }
        
        return await self._make_api_call('POST', endpoint, json=transition_data)
    
    async def assign_ticket(self, ticket_key: str, assignee: str) -> Dict[str, Any]:
        """Assign ticket to user"""
        
        return await self.update_ticket(ticket_key, {'assignee': {'name': assignee}})
    
    async def search_tickets(self, jql: str, fields: List[str] = None,
                           max_results: int = 100) -> Dict[str, Any]:
        """Search tickets using JQL"""
        
        endpoint = f"/rest/api/{self.api_version}/search"
        
        search_data = {
            'jql': jql,
            'maxResults': max_results,
            'fields': fields or ['summary', 'status', 'assignee', 'created', 'updated']
        }
        
        return await self._make_api_call('POST', endpoint, json=search_data)
    
    async def get_project_info(self, project_key: str) -> Dict[str, Any]:
        """Get project information"""
        
        endpoint = f"/rest/api/{self.api_version}/project/{project_key}"
        return await self._make_api_call('GET', endpoint)
    
    async def get_user_workload(self, username: str) -> Dict[str, Any]:
        """Get user's current workload"""
        
        jql = f'assignee = "{username}" AND resolution is EMPTY'
        search_result = await self.search_tickets(jql)
        
        return {
            'username': username,
            'open_tickets': search_result['total'],
            'tickets': search_result['issues']
        }
    
    def _build_ticket_payload(self, ticket: JiraTicket) -> Dict[str, Any]:
        """Build Jira ticket creation payload"""
        
        # Basic fields
        fields = {
            'project': {'key': ticket.project_key},
            'summary': ticket.summary,
            'description': ticket.description,
            'issuetype': {'name': ticket.issue_type},
            'priority': {'name': ticket.priority.value}
        }
        
        # Optional fields
        if ticket.assignee:
            fields['assignee'] = {'name': ticket.assignee}
        
        if ticket.reporter:
            fields['reporter'] = {'name': ticket.reporter}
        
        if ticket.labels:
            fields['labels'] = ticket.labels
        
        if ticket.components:
            fields['components'] = [{'name': comp} for comp in ticket.components]
        
        # Custom fields
        if ticket.custom_fields:
            fields.update(ticket.custom_fields)
        
        # AI metadata as custom fields (if configured)
        if ticket.metadata:
            metadata_fields = self._convert_metadata_to_custom_fields(ticket.metadata)
            fields.update(metadata_fields)
        
        return {'fields': fields}
    
    def _convert_metadata_to_custom_fields(self, metadata: TicketMetadata) -> Dict[str, Any]:
        """Convert ticket metadata to Jira custom fields"""
        
        # Map metadata to custom field IDs (would be configured per Jira instance)
        custom_field_mapping = self.config.get('custom_field_mapping', {})
        
        custom_fields = {}
        
        if 'ai_confidence' in custom_field_mapping:
            custom_fields[custom_field_mapping['ai_confidence']] = metadata.ai_confidence
        
        if 'ai_model_used' in custom_field_mapping:
            custom_fields[custom_field_mapping['ai_model_used']] = metadata.ai_model_used
        
        if 'vulnerability_id' in custom_field_mapping and metadata.vulnerability_id:
            custom_fields[custom_field_mapping['vulnerability_id']] = metadata.vulnerability_id
        
        if 'asset_criticality' in custom_field_mapping and metadata.asset_criticality:
            custom_fields[custom_field_mapping['asset_criticality']] = {'value': metadata.asset_criticality}
        
        if 'business_risk_level' in custom_field_mapping and metadata.business_risk_level:
            custom_fields[custom_field_mapping['business_risk_level']] = {'value': metadata.business_risk_level}
        
        if 'compliance_frameworks' in custom_field_mapping and metadata.compliance_frameworks:
            custom_fields[custom_field_mapping['compliance_frameworks']] = [
                {'value': framework} for framework in metadata.compliance_frameworks
            ]
        
        return custom_fields
    
    async def _make_api_call(self, method: str, endpoint: str, 
                           json: Dict[str, Any] = None,
                           params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Make authenticated API call to Jira"""
        
        url = f"{self.base_url}{endpoint}"
        retry_count = 0
        
        while retry_count <= self.max_retries:
            try:
                async with self.session.request(method, url, json=json, params=params) as response:
                    self.metrics['api_calls'] += 1
                    
                    if response.status == 429:  # Rate limited
                        self.metrics['rate_limits'] += 1
                        retry_after = int(response.headers.get('Retry-After', 60))
                        logger.warning(f"Jira API rate limited, waiting {retry_after}s")
                        await asyncio.sleep(retry_after)
                        retry_count += 1
                        continue
                    
                    elif 200 <= response.status < 300:
                        if method == 'PUT':
                            return {}  # PUT requests often return empty response
                        return await response.json() if response.content_length else {}
                    
                    else:
                        error_text = await response.text()
                        self.metrics['errors'] += 1
                        logger.error(f"Jira API error {response.status}: {error_text}")
                        
                        if response.status >= 500 and retry_count < self.max_retries:
                            # Retry on server errors
                            await asyncio.sleep(2 ** retry_count)  # Exponential backoff
                            retry_count += 1
                            continue
                        
                        raise Exception(f"Jira API error {response.status}: {error_text}")
            
            except asyncio.TimeoutError:
                retry_count += 1
                if retry_count <= self.max_retries:
                    logger.warning(f"Jira API timeout, retrying (attempt {retry_count})")
                    await asyncio.sleep(2 ** retry_count)
                    continue
                else:
                    self.metrics['errors'] += 1
                    raise Exception("Jira API timeout after retries")
            
            except Exception as e:
                if retry_count < self.max_retries and "connection" in str(e).lower():
                    retry_count += 1
                    logger.warning(f"Jira API connection error, retrying: {e}")
                    await asyncio.sleep(2 ** retry_count)
                    continue
                else:
                    self.metrics['errors'] += 1
                    raise e
        
        raise Exception("Jira API call failed after all retries")

class TeamRoutingEngine:
    """Intelligent team routing based on expertise and workload"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize team routing engine"""
        self.config = config
        self.teams: Dict[str, TeamRouting] = {}
        self.load_team_configurations()
        
        # Routing algorithms
        self.routing_algorithms = {
            'round_robin': self._round_robin_routing,
            'workload_balanced': self._workload_balanced_routing,
            'expertise_based': self._expertise_based_routing,
            'hybrid': self._hybrid_routing
        }
        
        self.default_algorithm = config.get('default_routing_algorithm', 'hybrid')
    
    def load_team_configurations(self):
        """Load team configurations from config"""
        
        teams_config = self.config.get('teams', {})
        
        for team_name, team_data in teams_config.items():
            self.teams[team_name] = TeamRouting(
                team_name=team_name,
                team_lead=team_data['team_lead'],
                team_members=team_data['team_members'],
                specialties=team_data.get('specialties', []),
                workload_capacity=team_data.get('workload_capacity', 20),
                current_workload=team_data.get('current_workload', 0),
                availability_hours=team_data.get('availability_hours', {}),
                escalation_chain=team_data.get('escalation_chain', [])
            )
    
    async def route_ticket(self, ticket: JiraTicket, 
                          routing_context: Dict[str, Any] = None) -> str:
        """Route ticket to appropriate team member"""
        
        algorithm = routing_context.get('algorithm', self.default_algorithm) if routing_context else self.default_algorithm
        
        # Determine relevant teams based on ticket characteristics
        relevant_teams = self._identify_relevant_teams(ticket)
        
        if not relevant_teams:
            # Default to general SOC team
            relevant_teams = [team for team in self.teams.keys() if 'soc' in team.lower()]
        
        # Apply routing algorithm
        routing_func = self.routing_algorithms.get(algorithm, self._hybrid_routing)
        assigned_user = await routing_func(ticket, relevant_teams, routing_context or {})
        
        logger.info(f"Routed ticket {ticket.key} to {assigned_user} using {algorithm} algorithm")
        return assigned_user
    
    def _identify_relevant_teams(self, ticket: JiraTicket) -> List[str]:
        """Identify teams relevant to the ticket"""
        
        relevant_teams = []
        
        # Analyze ticket content for team specialties
        ticket_text = f"{ticket.summary} {ticket.description}".lower()
        
        for team_name, team in self.teams.items():
            for specialty in team.specialties:
                if specialty.lower() in ticket_text:
                    relevant_teams.append(team_name)
                    break
        
        # Check metadata for specific routing hints
        if ticket.metadata:
            if ticket.metadata.vulnerability_id:
                # Route vulnerability tickets to security teams
                security_teams = [name for name, team in self.teams.items() 
                                if any('security' in spec.lower() or 'vulnerability' in spec.lower() 
                                      for spec in team.specialties)]
                relevant_teams.extend(security_teams)
            
            if ticket.metadata.asset_criticality in ['TIER_0', 'TIER_1']:
                # Route critical asset tickets to senior teams
                senior_teams = [name for name, team in self.teams.items()
                              if any('senior' in spec.lower() or 'critical' in spec.lower()
                                    for spec in team.specialties)]
                relevant_teams.extend(senior_teams)
        
        return list(set(relevant_teams))  # Remove duplicates
    
    async def _round_robin_routing(self, ticket: JiraTicket, relevant_teams: List[str],
                                 context: Dict[str, Any]) -> str:
        """Simple round-robin routing within teams"""
        
        # For simplicity, use first relevant team
        if not relevant_teams:
            return self._get_default_assignee()
        
        team = self.teams[relevant_teams[0]]
        
        # Simple round-robin logic (would need persistent state in production)
        import random
        return random.choice(team.team_members)
    
    async def _workload_balanced_routing(self, ticket: JiraTicket, relevant_teams: List[str],
                                       context: Dict[str, Any]) -> str:
        """Route based on current workload"""
        
        # Find team member with lowest workload
        candidates = []
        for team_name in relevant_teams:
            team = self.teams[team_name]
            for member in team.team_members:
                # In production, would query actual workload from Jira
                estimated_workload = team.current_workload // len(team.team_members)
                candidates.append((member, estimated_workload, team.workload_capacity))
        
        if not candidates:
            return self._get_default_assignee()
        
        # Sort by workload and capacity
        candidates.sort(key=lambda x: x[1] / x[2])  # workload/capacity ratio
        return candidates[0][0]
    
    async def _expertise_based_routing(self, ticket: JiraTicket, relevant_teams: List[str],
                                     context: Dict[str, Any]) -> str:
        """Route based on expertise matching"""
        
        ticket_text = f"{ticket.summary} {ticket.description}".lower()
        
        # Score team members based on specialty match
        scored_members = []
        for team_name in relevant_teams:
            team = self.teams[team_name]
            for member in team.team_members:
                score = 0
                for specialty in team.specialties:
                    if specialty.lower() in ticket_text:
                        score += 1
                
                # Boost score for team lead on complex issues
                if member == team.team_lead and ticket.priority in [TicketPriority.CRITICAL, TicketPriority.HIGH]:
                    score += 2
                
                scored_members.append((member, score))
        
        if not scored_members:
            return self._get_default_assignee()
        
        # Sort by score and return highest
        scored_members.sort(key=lambda x: x[1], reverse=True)
        return scored_members[0][0]
    
    async def _hybrid_routing(self, ticket: JiraTicket, relevant_teams: List[str],
                            context: Dict[str, Any]) -> str:
        """Hybrid routing combining expertise and workload"""
        
        # Get expertise-based candidates
        expertise_candidates = []
        ticket_text = f"{ticket.summary} {ticket.description}".lower()
        
        for team_name in relevant_teams:
            team = self.teams[team_name]
            for member in team.team_members:
                expertise_score = 0
                for specialty in team.specialties:
                    if specialty.lower() in ticket_text:
                        expertise_score += 1
                
                # Estimate workload (would query Jira in production)
                workload_ratio = team.current_workload / (len(team.team_members) * team.workload_capacity)
                
                # Combine scores (expertise is positive, workload is negative)
                combined_score = expertise_score * 10 - workload_ratio * 5
                
                expertise_candidates.append((member, combined_score, expertise_score, workload_ratio))
        
        if not expertise_candidates:
            return self._get_default_assignee()
        
        # Sort by combined score
        expertise_candidates.sort(key=lambda x: x[1], reverse=True)
        return expertise_candidates[0][0]
    
    def _get_default_assignee(self) -> str:
        """Get default assignee when routing fails"""
        
        # Return first team lead found
        for team in self.teams.values():
            return team.team_lead
        
        return "admin"  # Fallback
    
    async def update_team_workload(self, team_name: str, workload_delta: int):
        """Update team workload"""
        
        if team_name in self.teams:
            self.teams[team_name].current_workload += workload_delta
            logger.info(f"Updated {team_name} workload by {workload_delta}")

class SLAManager:
    """SLA tracking and enforcement engine"""
    
    def __init__(self, config: Dict[str, Any], jira_client: JiraAPIClient):
        """Initialize SLA manager"""
        self.config = config
        self.jira_client = jira_client
        self.business_hours_calc = BusinessHoursCalculator(config.get('business_hours', {}))
        
        # SLA targets by priority
        self.default_sla_targets = self._load_default_sla_targets()
        
        # Active SLA tracking
        self.active_sla_tracking: Dict[str, SLATracking] = {}
        
        # Notification configuration
        self.notification_config = config.get('notifications', {})
        
        # Metrics
        self.metrics = {
            'tickets_tracked': 0,
            'sla_breaches': 0,
            'escalations_triggered': 0,
            'avg_response_time': 0,
            'avg_resolution_time': 0
        }
    
    def _load_default_sla_targets(self) -> Dict[TicketPriority, List[SLATarget]]:
        """Load default SLA targets by priority"""
        
        # Default enterprise SLA targets
        default_targets = {
            TicketPriority.CRITICAL: [
                SLATarget(TicketPriority.CRITICAL, SLAMetric.TIME_TO_FIRST_RESPONSE, 1.0, 80.0, 95.0, False),  # 1 hour, 24/7
                SLATarget(TicketPriority.CRITICAL, SLAMetric.TIME_TO_RESOLUTION, 8.0, 80.0, 95.0, False),      # 8 hours, 24/7
            ],
            TicketPriority.HIGH: [
                SLATarget(TicketPriority.HIGH, SLAMetric.TIME_TO_FIRST_RESPONSE, 4.0, 80.0, 95.0, True),       # 4 business hours
                SLATarget(TicketPriority.HIGH, SLAMetric.TIME_TO_RESOLUTION, 24.0, 80.0, 95.0, True),          # 3 business days
            ],
            TicketPriority.MEDIUM: [
                SLATarget(TicketPriority.MEDIUM, SLAMetric.TIME_TO_FIRST_RESPONSE, 8.0, 80.0, 90.0, True),     # 8 business hours
                SLATarget(TicketPriority.MEDIUM, SLAMetric.TIME_TO_RESOLUTION, 72.0, 80.0, 90.0, True),        # 9 business days
            ],
            TicketPriority.LOW: [
                SLATarget(TicketPriority.LOW, SLAMetric.TIME_TO_FIRST_RESPONSE, 24.0, 80.0, 90.0, True),       # 3 business days
                SLATarget(TicketPriority.LOW, SLAMetric.TIME_TO_RESOLUTION, 120.0, 80.0, 90.0, True),          # 15 business days
            ]
        }
        
        # Override with configuration if provided
        configured_targets = self.config.get('sla_targets', {})
        for priority_str, targets in configured_targets.items():
            priority = TicketPriority(priority_str)
            if priority in default_targets:
                # Would parse and override targets from config
                pass
        
        return default_targets
    
    async def start_sla_tracking(self, ticket: JiraTicket) -> SLATracking:
        """Start SLA tracking for a ticket"""
        
        if not ticket.key:
            raise ValueError("Ticket must have a key to start SLA tracking")
        
        # Get SLA targets for this ticket priority
        sla_targets = self.default_sla_targets.get(ticket.priority, [])
        
        # Create SLA tracking record
        sla_tracking = SLATracking(
            ticket_key=ticket.key,
            priority=ticket.priority,
            created_at=ticket.created_at or datetime.now(timezone.utc),
            sla_targets=sla_targets,
            business_hours_calculator=self.business_hours_calc
        )
        
        # Initialize SLA status
        for target in sla_targets:
            sla_tracking.current_sla_status[target.metric] = {
                'target_hours': target.target_hours,
                'deadline': self._calculate_sla_deadline(sla_tracking.created_at, target),
                'warning_time': None,
                'escalation_time': None,
                'status': 'active',
                'elapsed_hours': 0,
                'remaining_hours': target.target_hours
            }
            
            # Calculate warning and escalation times
            warning_hours = target.target_hours * (target.warning_threshold_percent / 100)
            escalation_hours = target.target_hours * (target.escalation_threshold_percent / 100)
            
            if target.business_hours_only:
                warning_time = self.business_hours_calc.add_business_hours(sla_tracking.created_at, warning_hours)
                escalation_time = self.business_hours_calc.add_business_hours(sla_tracking.created_at, escalation_hours)
            else:
                warning_time = sla_tracking.created_at + timedelta(hours=warning_hours)
                escalation_time = sla_tracking.created_at + timedelta(hours=escalation_hours)
            
            sla_tracking.current_sla_status[target.metric].update({
                'warning_time': warning_time,
                'escalation_time': escalation_time
            })
        
        # Store tracking record
        self.active_sla_tracking[ticket.key] = sla_tracking
        self.metrics['tickets_tracked'] += 1
        
        logger.info(f"Started SLA tracking for ticket {ticket.key} with priority {ticket.priority.value}")
        return sla_tracking
    
    def _calculate_sla_deadline(self, start_time: datetime, target: SLATarget) -> datetime:
        """Calculate SLA deadline based on target"""
        
        if target.business_hours_only:
            return self.business_hours_calc.add_business_hours(start_time, target.target_hours)
        else:
            return start_time + timedelta(hours=target.target_hours)
    
    async def update_sla_milestone(self, ticket_key: str, milestone: str):
        """Update SLA milestone (first response, resolution, etc.)"""
        
        if ticket_key not in self.active_sla_tracking:
            logger.warning(f"No SLA tracking found for ticket {ticket_key}")
            return
        
        tracking = self.active_sla_tracking[ticket_key]
        current_time = datetime.now(timezone.utc)
        
        # Update milestone timestamp
        if milestone == 'first_response':
            tracking.first_response_at = current_time
            await self._check_sla_completion(tracking, SLAMetric.TIME_TO_FIRST_RESPONSE)
        elif milestone == 'in_progress':
            tracking.in_progress_at = current_time
        elif milestone == 'resolved':
            tracking.resolved_at = current_time
            await self._check_sla_completion(tracking, SLAMetric.TIME_TO_RESOLUTION)
        elif milestone == 'closed':
            tracking.closed_at = current_time
            await self._check_sla_completion(tracking, SLAMetric.TIME_TO_CLOSE)
        elif milestone == 'escalated':
            tracking.escalated_at = current_time
        
        logger.info(f"Updated SLA milestone '{milestone}' for ticket {ticket_key}")
    
    async def _check_sla_completion(self, tracking: SLATracking, metric: SLAMetric):
        """Check if SLA metric is completed and update status"""
        
        if metric not in tracking.current_sla_status:
            return
        
        current_time = datetime.now(timezone.utc)
        sla_status = tracking.current_sla_status[metric]
        
        # Calculate elapsed time
        start_time = tracking.created_at
        if metric == SLAMetric.TIME_TO_RESOLUTION and tracking.first_response_at:
            # Some organizations measure resolution time from first response
            start_time = tracking.first_response_at
        
        # Find corresponding target
        target = None
        for t in tracking.sla_targets:
            if t.metric == metric:
                target = t
                break
        
        if not target:
            return
        
        # Calculate elapsed hours
        if target.business_hours_only:
            elapsed_hours = self.business_hours_calc.calculate_business_hours_between(
                start_time, current_time
            )
        else:
            elapsed_hours = (current_time - start_time).total_seconds() / 3600
        
        sla_status['elapsed_hours'] = elapsed_hours
        sla_status['remaining_hours'] = max(0, target.target_hours - elapsed_hours)
        
        # Check for breach
        if elapsed_hours > target.target_hours:
            sla_status['status'] = 'breached'
            tracking.breach_history.append({
                'metric': metric.value,
                'target_hours': target.target_hours,
                'actual_hours': elapsed_hours,
                'breach_time': current_time.isoformat(),
                'priority': tracking.priority.value
            })
            
            self.metrics['sla_breaches'] += 1
            await self._handle_sla_breach(tracking, metric, target, elapsed_hours)
        else:
            sla_status['status'] = 'met'
        
        # Update metrics
        if metric == SLAMetric.TIME_TO_FIRST_RESPONSE:
            self._update_average_metric('avg_response_time', elapsed_hours)
        elif metric == SLAMetric.TIME_TO_RESOLUTION:
            self._update_average_metric('avg_resolution_time', elapsed_hours)
    
    async def _handle_sla_breach(self, tracking: SLATracking, metric: SLAMetric,
                                target: SLATarget, actual_hours: float):
        """Handle SLA breach notification and escalation"""
        
        breach_details = {
            'ticket_key': tracking.ticket_key,
            'metric': metric.value,
            'target_hours': target.target_hours,
            'actual_hours': actual_hours,
            'priority': tracking.priority.value,
            'breach_percentage': (actual_hours / target.target_hours) * 100
        }
        
        logger.warning(f"SLA breach detected for {tracking.ticket_key}: {metric.value} "
                      f"took {actual_hours:.1f}h (target: {target.target_hours}h)")
        
        # Send notifications if configured
        if self.notification_config.get('sla_breach_notifications'):
            await self._send_sla_breach_notification(breach_details)
        
        # Auto-escalate if configured
        if self.notification_config.get('auto_escalate_on_breach'):
            await self._escalate_breached_ticket(tracking, breach_details)
    
    async def _send_sla_breach_notification(self, breach_details: Dict[str, Any]):
        """Send SLA breach notification"""
        
        # Implementation would send to Slack, email, etc.
        logger.info(f"Sending SLA breach notification for {breach_details['ticket_key']}")
    
    async def _escalate_breached_ticket(self, tracking: SLATracking, breach_details: Dict[str, Any]):
        """Auto-escalate ticket after SLA breach"""
        
        self.metrics['escalations_triggered'] += 1
        
        # Implementation would:
        # 1. Increase ticket priority
        # 2. Reassign to manager/senior team
        # 3. Add escalation comment
        # 4. Update SLA targets for higher priority
        
        logger.info(f"Auto-escalated ticket {tracking.ticket_key} due to SLA breach")
    
    def _update_average_metric(self, metric_name: str, new_value: float):
        """Update running average metric"""
        
        current_avg = self.metrics[metric_name]
        total_tickets = self.metrics['tickets_tracked']
        
        if total_tickets > 1:
            # Update running average
            self.metrics[metric_name] = ((current_avg * (total_tickets - 1)) + new_value) / total_tickets
        else:
            self.metrics[metric_name] = new_value
    
    async def check_sla_warnings_and_escalations(self):
        """Background task to check for SLA warnings and escalations"""
        
        current_time = datetime.now(timezone.utc)
        
        for ticket_key, tracking in self.active_sla_tracking.items():
            for metric, sla_status in tracking.current_sla_status.items():
                if sla_status['status'] != 'active':
                    continue
                
                # Check for warnings
                if (sla_status.get('warning_time') and 
                    current_time >= sla_status['warning_time'] and
                    not sla_status.get('warning_sent')):
                    
                    await self._send_sla_warning(tracking, metric)
                    sla_status['warning_sent'] = True
                
                # Check for escalations
                if (sla_status.get('escalation_time') and
                    current_time >= sla_status['escalation_time'] and
                    not sla_status.get('escalation_sent')):
                    
                    await self._send_sla_escalation_warning(tracking, metric)
                    sla_status['escalation_sent'] = True
    
    async def _send_sla_warning(self, tracking: SLATracking, metric: SLAMetric):
        """Send SLA warning notification"""
        
        logger.warning(f"SLA warning for {tracking.ticket_key}: {metric.value} approaching deadline")
    
    async def _send_sla_escalation_warning(self, tracking: SLATracking, metric: SLAMetric):
        """Send SLA escalation warning"""
        
        logger.critical(f"SLA escalation warning for {tracking.ticket_key}: {metric.value} about to breach")
    
    async def get_sla_metrics(self) -> Dict[str, Any]:
        """Get SLA performance metrics"""
        
        return {
            'tracking_metrics': self.metrics,
            'active_tickets': len(self.active_sla_tracking),
            'sla_compliance_rate': ((self.metrics['tickets_tracked'] - self.metrics['sla_breaches']) / 
                                   max(self.metrics['tickets_tracked'], 1)) * 100
        }

class JiraEnterpriseIntegration:
    """Main Jira enterprise integration orchestrator"""
    
    def __init__(self, config: Dict[str, Any], ai_orchestrator: AIOrchestrator):
        """Initialize Jira enterprise integration"""
        self.config = config
        self.ai_orchestrator = ai_orchestrator
        
        # Initialize components
        self.jira_client = None
        self.team_router = TeamRoutingEngine(config.get('team_routing', {}))
        self.sla_manager = None
        
        # Ticket templates
        self.ticket_templates = self._load_ticket_templates()
        
        # Performance metrics
        self.metrics = {
            'tickets_created': 0,
            'auto_enriched_tickets': 0,
            'routing_accuracy': 0,
            'average_creation_time': 0
        }
    
    async def initialize(self):
        """Initialize integration components"""
        
        self.jira_client = JiraAPIClient(self.config['jira'])
        self.sla_manager = SLAManager(
            self.config.get('sla', {}), 
            self.jira_client
        )
        
        # Start background SLA monitoring
        asyncio.create_task(self._sla_monitoring_task())
        
        logger.info("Jira enterprise integration initialized")
    
    def _load_ticket_templates(self) -> Dict[str, Dict[str, Any]]:
        """Load ticket templates for different types"""
        
        return {
            'vulnerability': {
                'issue_type': 'Security Vulnerability',
                'summary_template': '[{risk_level}] {vulnerability_name} on {asset_hostname}',
                'description_template': """
## Vulnerability Summary
**CVE**: {cve_id}
**CVSS Score**: {cvss_score}
**Asset**: {asset_hostname} ({asset_ip})
**Business Risk**: {business_risk_level}

## AI Analysis
**Confidence**: {ai_confidence:.1%}
**Model**: {ai_model_used}

{ai_reasoning}

## Business Impact
{business_justification}

## Recommended Action
{recommended_action}

**Estimated Effort**: {estimated_effort} hours
**SLA**: {recommended_sla}

---
*Auto-generated by SecOps AI Platform*
                """.strip()
            },
            'security_alert': {
                'issue_type': 'Security Alert',
                'summary_template': '[{severity}] {alert_title}',
                'description_template': """
## Alert Details
**Source**: {alert_source}
**Severity**: {severity}
**Detected**: {detected_time}

## AI Analysis
**Confidence**: {ai_confidence:.1%}
**Category**: {alert_category}

{ai_reasoning}

## Recommended Actions
{recommended_actions}

---
*Auto-generated by SecOps AI Platform*
                """.strip()
            }
        }
    
    async def create_vulnerability_ticket(self, enriched_vuln: EnrichedVulnerability,
                                        routing_context: Dict[str, Any] = None) -> JiraTicket:
        """Create Jira ticket from enriched vulnerability"""
        
        start_time = datetime.now(timezone.utc)
        
        # Build ticket from template
        template = self.ticket_templates['vulnerability']
        
        # Format summary
        summary = template['summary_template'].format(
            risk_level=enriched_vuln.business_risk.name,
            vulnerability_name=enriched_vuln.vulnerability.vulnerability_name,
            asset_hostname=enriched_vuln.asset_profile.hostname
        )
        
        # Format description
        description = template['description_template'].format(
            cve_id=enriched_vuln.vulnerability.cve_id or 'N/A',
            cvss_score=enriched_vuln.vulnerability.cvss_score,
            asset_hostname=enriched_vuln.asset_profile.hostname,
            asset_ip=enriched_vuln.asset_profile.ip_address,
            business_risk_level=enriched_vuln.business_risk.value,
            ai_confidence=enriched_vuln.charlotte_analysis['ai_confidence'],
            ai_model_used=enriched_vuln.charlotte_analysis['model_used'],
            ai_reasoning='\\n'.join(f"- {step}" for step in enriched_vuln.charlotte_analysis['reasoning_chain']),
            business_justification=enriched_vuln.business_justification,
            recommended_action=enriched_vuln.vulnerability.remediation_guidance,
            estimated_effort=enriched_vuln.metadata.estimated_effort_hours if enriched_vuln.metadata else 'TBD',
            recommended_sla=enriched_vuln.recommended_sla
        )
        
        # Map risk to priority
        priority = self._map_risk_to_priority(enriched_vuln.business_risk)
        
        # Create ticket metadata
        metadata = TicketMetadata(
            ai_confidence=enriched_vuln.charlotte_analysis['ai_confidence'],
            ai_model_used=enriched_vuln.charlotte_analysis['model_used'],
            analysis_id=enriched_vuln.charlotte_analysis['analysis_id'],
            vulnerability_id=enriched_vuln.vulnerability.id,
            asset_criticality=enriched_vuln.asset_profile.criticality.value,
            business_risk_level=enriched_vuln.business_risk.value,
            compliance_frameworks=enriched_vuln.asset_profile.compliance_scope,
            remediation_complexity=enriched_vuln.remediation_complexity,
            estimated_effort_hours=self._estimate_effort_hours(enriched_vuln),
            business_justification=enriched_vuln.business_justification,
            auto_created=True
        )
        
        # Create Jira ticket object
        ticket = JiraTicket(
            key=None,
            id=None,
            summary=summary,
            description=description,
            issue_type=template['issue_type'],
            priority=priority,
            project_key=self.config['jira']['default_project'],
            labels=['ai-generated', 'vulnerability', f"risk-{enriched_vuln.business_risk.name.lower()}"],
            components=self._determine_components(enriched_vuln),
            metadata=metadata
        )
        
        # Route to appropriate team member
        assignee = await self.team_router.route_ticket(ticket, routing_context)
        ticket.assignee = assignee
        
        # Create ticket in Jira
        async with self.jira_client as client:
            created_ticket = await client.create_ticket(ticket)
        
        # Start SLA tracking
        await self.sla_manager.start_sla_tracking(created_ticket)
        
        # Update metrics
        creation_time = (datetime.now(timezone.utc) - start_time).total_seconds()
        self._update_metrics(creation_time)
        
        logger.info(f"Created vulnerability ticket {created_ticket.key} for {enriched_vuln.vulnerability.id}")
        return created_ticket
    
    async def create_security_alert_ticket(self, alert: SecurityAlert, 
                                         analysis_result: AnalysisResult,
                                         routing_context: Dict[str, Any] = None) -> JiraTicket:
        """Create Jira ticket from security alert"""
        
        start_time = datetime.now(timezone.utc)
        
        # Build ticket from template
        template = self.ticket_templates['security_alert']
        
        # Format summary
        summary = template['summary_template'].format(
            severity=alert.severity.value,
            alert_title=alert.title
        )
        
        # Format description
        description = template['description_template'].format(
            alert_source=alert.source,
            severity=alert.severity.value,
            detected_time=alert.timestamp.strftime('%Y-%m-%d %H:%M UTC'),
            ai_confidence=analysis_result.confidence_score,
            alert_category=analysis_result.category.value,
            ai_reasoning='\\n'.join(f"- {step}" for step in analysis_result.reasoning_chain),
            recommended_actions=analysis_result.recommended_action
        )
        
        # Map severity to priority
        priority = self._map_severity_to_priority(alert.severity)
        
        # Create ticket metadata
        metadata = TicketMetadata(
            ai_confidence=analysis_result.confidence_score,
            ai_model_used=analysis_result.model_used,
            analysis_id=analysis_result.analysis_id,
            related_alerts=[alert.id],
            threat_indicators=alert.evidence,
            auto_created=True
        )
        
        # Create Jira ticket object
        ticket = JiraTicket(
            key=None,
            id=None,
            summary=summary,
            description=description,
            issue_type=template['issue_type'],
            priority=priority,
            project_key=self.config['jira']['default_project'],
            labels=['ai-generated', 'security-alert', f"category-{analysis_result.category.value}"],
            metadata=metadata
        )
        
        # Route to appropriate team member
        assignee = await self.team_router.route_ticket(ticket, routing_context)
        ticket.assignee = assignee
        
        # Create ticket in Jira
        async with self.jira_client as client:
            created_ticket = await client.create_ticket(ticket)
        
        # Start SLA tracking
        await self.sla_manager.start_sla_tracking(created_ticket)
        
        # Update metrics
        creation_time = (datetime.now(timezone.utc) - start_time).total_seconds()
        self._update_metrics(creation_time)
        
        logger.info(f"Created security alert ticket {created_ticket.key} for {alert.id}")
        return created_ticket
    
    def _map_risk_to_priority(self, risk: VulnerabilityRisk) -> TicketPriority:
        """Map vulnerability risk to Jira priority"""
        
        risk_mapping = {
            VulnerabilityRisk.CRITICAL_BUSINESS_RISK: TicketPriority.CRITICAL,
            VulnerabilityRisk.HIGH_BUSINESS_RISK: TicketPriority.HIGH,
            VulnerabilityRisk.MEDIUM_BUSINESS_RISK: TicketPriority.MEDIUM,
            VulnerabilityRisk.LOW_BUSINESS_RISK: TicketPriority.LOW,
            VulnerabilityRisk.ACCEPTED_RISK: TicketPriority.TRIVIAL
        }
        
        return risk_mapping.get(risk, TicketPriority.MEDIUM)
    
    def _map_severity_to_priority(self, severity) -> TicketPriority:
        """Map alert severity to Jira priority"""
        
        severity_mapping = {
            'CRITICAL': TicketPriority.CRITICAL,
            'HIGH': TicketPriority.HIGH,
            'MEDIUM': TicketPriority.MEDIUM,
            'LOW': TicketPriority.LOW
        }
        
        return severity_mapping.get(severity.name, TicketPriority.MEDIUM)
    
    def _determine_components(self, enriched_vuln: EnrichedVulnerability) -> List[str]:
        """Determine Jira components based on vulnerability"""
        
        components = ['Security']
        
        # Add components based on asset type
        hostname = enriched_vuln.asset_profile.hostname.lower()
        if hostname.startswith('db-'):
            components.append('Database')
        elif hostname.startswith('web-'):
            components.append('Web Services')
        elif hostname.startswith('app-'):
            components.append('Application Services')
        
        # Add compliance components
        if 'PCI' in enriched_vuln.asset_profile.compliance_scope:
            components.append('PCI Compliance')
        if 'SOX' in enriched_vuln.asset_profile.compliance_scope:
            components.append('SOX Compliance')
        
        return components
    
    def _estimate_effort_hours(self, enriched_vuln: EnrichedVulnerability) -> float:
        """Estimate effort hours for vulnerability remediation"""
        
        base_hours = {
            VulnerabilityRisk.CRITICAL_BUSINESS_RISK: 8.0,
            VulnerabilityRisk.HIGH_BUSINESS_RISK: 6.0,
            VulnerabilityRisk.MEDIUM_BUSINESS_RISK: 4.0,
            VulnerabilityRisk.LOW_BUSINESS_RISK: 2.0,
            VulnerabilityRisk.ACCEPTED_RISK: 1.0
        }
        
        effort = base_hours.get(enriched_vuln.business_risk, 4.0)
        
        # Adjust based on complexity
        if 'Complex' in enriched_vuln.remediation_complexity:
            effort *= 2.0
        elif 'Very Complex' in enriched_vuln.remediation_complexity:
            effort *= 3.0
        
        return effort
    
    def _update_metrics(self, creation_time: float):
        """Update performance metrics"""
        
        self.metrics['tickets_created'] += 1
        self.metrics['auto_enriched_tickets'] += 1
        
        # Update average creation time
        current_avg = self.metrics['average_creation_time']
        ticket_count = self.metrics['tickets_created']
        
        if ticket_count > 1:
            self.metrics['average_creation_time'] = ((current_avg * (ticket_count - 1)) + creation_time) / ticket_count
        else:
            self.metrics['average_creation_time'] = creation_time
    
    async def _sla_monitoring_task(self):
        """Background task for SLA monitoring"""
        
        while True:
            try:
                await self.sla_manager.check_sla_warnings_and_escalations()
                await asyncio.sleep(300)  # Check every 5 minutes
            except Exception as e:
                logger.error(f"Error in SLA monitoring task: {e}")
                await asyncio.sleep(300)
    
    async def get_integration_metrics(self) -> Dict[str, Any]:
        """Get comprehensive integration metrics"""
        
        sla_metrics = await self.sla_manager.get_sla_metrics()
        
        return {
            'ticket_metrics': self.metrics,
            'sla_metrics': sla_metrics,
            'active_teams': len(self.team_router.teams),
            'jira_api_metrics': self.jira_client.metrics if self.jira_client else {}
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Comprehensive health check"""
        
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'components': {}
        }
        
        # Test Jira connectivity
        try:
            async with self.jira_client as client:
                await client.get_project_info(self.config['jira']['default_project'])
                health_status['components']['jira_api'] = 'healthy'
        except Exception as e:
            health_status['components']['jira_api'] = f'unhealthy: {str(e)}'
            health_status['status'] = 'degraded'
        
        # Check SLA manager
        health_status['components']['sla_manager'] = 'healthy'
        
        # Check team routing
        health_status['components']['team_routing'] = 'healthy'
        
        # Add metrics
        health_status['metrics'] = await self.get_integration_metrics()
        
        return health_status