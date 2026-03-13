"""
CrowdStrike Spotlight + Charlotte AI Integration
Implements vulnerability management workflow with intelligent analysis
Transforms 5K-20K raw findings → 50-300 actionable tickets
"""

import asyncio
import logging
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import json
import aiohttp

from ...ai_engine.orchestrator import AIOrchestrator, SecurityAlert, AlertSeverity, AnalysisResult

logger = logging.getLogger(__name__)

class VulnerabilityRisk(Enum):
    """Business risk levels for vulnerability assessment"""
    CRITICAL_BUSINESS_RISK = "critical_business_risk"
    HIGH_BUSINESS_RISK = "high_business_risk" 
    MEDIUM_BUSINESS_RISK = "medium_business_risk"
    LOW_BUSINESS_RISK = "low_business_risk"
    ACCEPTED_RISK = "accepted_risk"

class AssetCriticality(Enum):
    """Asset criticality classifications"""
    TIER_0 = "tier_0"  # Crown jewels
    TIER_1 = "tier_1"  # Critical business systems
    TIER_2 = "tier_2"  # Important systems
    TIER_3 = "tier_3"  # Standard systems

@dataclass
class SpotlightVulnerability:
    """CrowdStrike Spotlight vulnerability finding"""
    id: str
    cve_id: Optional[str]
    severity: str  # Critical, High, Medium, Low
    cvss_score: float
    asset_id: str
    asset_hostname: str
    asset_ip: str
    vulnerability_name: str
    description: str
    exploitability: str
    patch_available: bool
    first_seen: datetime
    last_seen: datetime
    exposure_score: float
    business_criticality: int
    remediation_guidance: str
    raw_data: Dict[str, Any]

@dataclass
class AssetProfile:
    """Asset criticality and business context"""
    asset_id: str
    hostname: str
    ip_address: str
    criticality: AssetCriticality
    business_function: str
    data_classification: str
    compliance_scope: List[str]
    last_updated: datetime

@dataclass
class EnrichedVulnerability:
    """Vulnerability enriched with Charlotte AI analysis"""
    vulnerability: SpotlightVulnerability
    asset_profile: AssetProfile
    charlotte_analysis: Dict[str, Any]
    business_risk: VulnerabilityRisk
    priority_score: float
    recommended_sla: str
    remediation_complexity: str
    business_justification: str

class CrowdStrikeSpotlightClient:
    """Client for CrowdStrike Spotlight vulnerability management API"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize CrowdStrike Spotlight client"""
        self.config = config
        self.base_url = config['spotlight_api_url']
        self.client_id = config['client_id']
        self.client_secret = config['client_secret']
        self.access_token = None
        self.token_expiry = None
        
        # Rate limiting
        self.rate_limit = asyncio.Semaphore(config.get('rate_limit', 10))
        self.session = None
        
        # Performance metrics
        self.metrics = {
            'vulnerabilities_fetched': 0,
            'api_calls': 0,
            'rate_limit_hits': 0,
            'errors': 0
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        await self._authenticate()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def _authenticate(self):
        """Authenticate with CrowdStrike OAuth"""
        
        auth_data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'client_credentials'
        }
        
        async with self.session.post(
            f"{self.base_url}/oauth2/token",
            data=auth_data
        ) as response:
            if response.status == 200:
                token_data = await response.json()
                self.access_token = token_data['access_token']
                self.token_expiry = datetime.now(timezone.utc) + timedelta(
                    seconds=token_data['expires_in']
                )
                logger.info("CrowdStrike authentication successful")
            else:
                error_text = await response.text()
                raise Exception(f"CrowdStrike authentication failed: {error_text}")
    
    async def _ensure_authenticated(self):
        """Ensure valid authentication token"""
        
        if not self.access_token or datetime.now(timezone.utc) >= self.token_expiry:
            await self._authenticate()
    
    async def _make_api_call(self, endpoint: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Make authenticated API call with rate limiting"""
        
        async with self.rate_limit:
            await self._ensure_authenticated()
            
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }
            
            try:
                async with self.session.get(
                    f"{self.base_url}{endpoint}",
                    headers=headers,
                    params=params
                ) as response:
                    
                    self.metrics['api_calls'] += 1
                    
                    if response.status == 429:  # Rate limited
                        self.metrics['rate_limit_hits'] += 1
                        retry_after = int(response.headers.get('Retry-After', 60))
                        logger.warning(f"Rate limited, retrying after {retry_after}s")
                        await asyncio.sleep(retry_after)
                        return await self._make_api_call(endpoint, params)
                    
                    elif response.status == 200:
                        return await response.json()
                    
                    else:
                        error_text = await response.text()
                        logger.error(f"API call failed: {response.status} - {error_text}")
                        self.metrics['errors'] += 1
                        raise Exception(f"API error {response.status}: {error_text}")
            
            except Exception as e:
                self.metrics['errors'] += 1
                raise e
    
    async def fetch_vulnerabilities(self, filters: Dict[str, Any] = None) -> List[SpotlightVulnerability]:
        """Fetch vulnerabilities from Spotlight with optional filters"""
        
        # Default filters for active, patchable vulnerabilities
        default_filters = {
            'status': 'open',
            'patch_available': True,
            'limit': 5000
        }
        
        if filters:
            default_filters.update(filters)
        
        vulnerabilities = []
        offset = 0
        page_size = default_filters.get('limit', 1000)
        
        while True:
            params = {
                **default_filters,
                'offset': offset,
                'limit': min(page_size, 1000)  # API limit
            }
            
            response = await self._make_api_call('/spotlight/entities/vulnerabilities/v1', params)
            
            vuln_data = response.get('resources', [])
            if not vuln_data:
                break
            
            # Convert to SpotlightVulnerability objects
            for vuln in vuln_data:
                vulnerability = SpotlightVulnerability(
                    id=vuln['id'],
                    cve_id=vuln.get('cve', {}).get('id'),
                    severity=vuln.get('severity', 'unknown'),
                    cvss_score=float(vuln.get('cvss', {}).get('base_score', 0)),
                    asset_id=vuln['aid'],
                    asset_hostname=vuln.get('host_info', {}).get('hostname', ''),
                    asset_ip=vuln.get('host_info', {}).get('local_ip', ''),
                    vulnerability_name=vuln.get('cve', {}).get('description', vuln['id']),
                    description=vuln.get('description', ''),
                    exploitability=vuln.get('exploitability', 'unknown'),
                    patch_available=vuln.get('remediation', {}).get('patch_available', False),
                    first_seen=datetime.fromisoformat(vuln['first_seen'].replace('Z', '+00:00')),
                    last_seen=datetime.fromisoformat(vuln['last_seen'].replace('Z', '+00:00')),
                    exposure_score=float(vuln.get('exposure_score', 0)),
                    business_criticality=int(vuln.get('host_info', {}).get('criticality', 1)),
                    remediation_guidance=vuln.get('remediation', {}).get('guidance', ''),
                    raw_data=vuln
                )
                
                vulnerabilities.append(vulnerability)
            
            self.metrics['vulnerabilities_fetched'] += len(vuln_data)
            
            # Check if we have more pages
            if len(vuln_data) < params['limit']:
                break
            
            offset += len(vuln_data)
        
        logger.info(f"Fetched {len(vulnerabilities)} vulnerabilities from Spotlight")
        return vulnerabilities
    
    async def get_asset_details(self, asset_id: str) -> Dict[str, Any]:
        """Get detailed asset information"""
        
        return await self._make_api_call(f'/devices/entities/devices/v1', {'ids': asset_id})
    
    async def fetch_threat_intelligence(self, cve_id: str) -> Dict[str, Any]:
        """Fetch threat intelligence for CVE"""
        
        if not cve_id:
            return {}
        
        return await self._make_api_call(f'/intel/entities/vulnerabilities/v1', {'cve_id': cve_id})

class CharlotteAIAnalyzer:
    """Charlotte AI vulnerability analysis engine"""
    
    def __init__(self, config: Dict[str, Any], ai_orchestrator: AIOrchestrator):
        """Initialize Charlotte AI analyzer"""
        self.config = config
        self.ai_orchestrator = ai_orchestrator
        
        # Business risk weighting factors
        self.risk_weights = {
            'cvss_score': 0.25,
            'asset_criticality': 0.30,
            'exploitability': 0.20,
            'exposure_time': 0.15,
            'patch_availability': 0.10
        }
        
        # SLA mappings based on risk
        self.sla_mappings = {
            VulnerabilityRisk.CRITICAL_BUSINESS_RISK: "4 hours",
            VulnerabilityRisk.HIGH_BUSINESS_RISK: "24 hours",
            VulnerabilityRisk.MEDIUM_BUSINESS_RISK: "7 days",
            VulnerabilityRisk.LOW_BUSINESS_RISK: "30 days",
            VulnerabilityRisk.ACCEPTED_RISK: "No SLA"
        }
    
    async def analyze_vulnerability(self, vulnerability: SpotlightVulnerability, 
                                 asset_profile: AssetProfile) -> EnrichedVulnerability:
        """Analyze vulnerability with Charlotte AI for business risk assessment"""
        
        # Create security alert for AI analysis
        alert = SecurityAlert(
            id=f"vuln_{vulnerability.id}",
            timestamp=datetime.now(timezone.utc),
            severity=self._map_severity(vulnerability.severity),
            source="CrowdStrike_Spotlight",
            title=f"Vulnerability: {vulnerability.vulnerability_name}",
            description=self._build_vulnerability_description(vulnerability, asset_profile),
            evidence=self._extract_evidence(vulnerability),
            metadata=self._build_metadata(vulnerability, asset_profile)
        )
        
        # Get AI analysis
        analysis_result = await self.ai_orchestrator.process_security_alert(alert)
        
        # Calculate business risk
        business_risk = self._calculate_business_risk(vulnerability, asset_profile, analysis_result)
        
        # Calculate priority score
        priority_score = self._calculate_priority_score(vulnerability, asset_profile, business_risk)
        
        # Generate business justification
        business_justification = self._generate_business_justification(
            vulnerability, asset_profile, business_risk, analysis_result
        )
        
        # Assess remediation complexity
        remediation_complexity = self._assess_remediation_complexity(vulnerability, asset_profile)
        
        return EnrichedVulnerability(
            vulnerability=vulnerability,
            asset_profile=asset_profile,
            charlotte_analysis={
                'ai_confidence': analysis_result.confidence_score,
                'reasoning_chain': analysis_result.reasoning_chain,
                'model_used': analysis_result.model_used,
                'analysis_id': analysis_result.analysis_id
            },
            business_risk=business_risk,
            priority_score=priority_score,
            recommended_sla=self.sla_mappings[business_risk],
            remediation_complexity=remediation_complexity,
            business_justification=business_justification
        )
    
    def _map_severity(self, severity: str) -> AlertSeverity:
        """Map Spotlight severity to AlertSeverity"""
        mapping = {
            'Critical': AlertSeverity.CRITICAL,
            'High': AlertSeverity.HIGH,
            'Medium': AlertSeverity.MEDIUM,
            'Low': AlertSeverity.LOW
        }
        return mapping.get(severity, AlertSeverity.MEDIUM)
    
    def _build_vulnerability_description(self, vuln: SpotlightVulnerability, 
                                       asset: AssetProfile) -> str:
        """Build comprehensive vulnerability description for AI analysis"""
        
        return f"""
VULNERABILITY ASSESSMENT REQUEST

Asset Information:
- Hostname: {asset.hostname}
- IP Address: {asset.ip_address}  
- Business Criticality: {asset.criticality.value}
- Business Function: {asset.business_function}
- Data Classification: {asset.data_classification}
- Compliance Scope: {', '.join(asset.compliance_scope)}

Vulnerability Details:
- CVE: {vuln.cve_id or 'N/A'}
- CVSS Score: {vuln.cvss_score}
- Severity: {vuln.severity}
- Vulnerability: {vuln.vulnerability_name}
- Description: {vuln.description}
- Exploitability: {vuln.exploitability}
- Patch Available: {vuln.patch_available}
- Exposure Time: {(datetime.now(timezone.utc) - vuln.first_seen).days} days
- Remediation Guidance: {vuln.remediation_guidance}

REQUEST: Analyze the business risk of this vulnerability considering:
1. Asset criticality and business function
2. Vulnerability severity and exploitability
3. Potential business impact if exploited
4. Remediation complexity and downtime requirements
5. Compliance implications

Provide risk classification, priority recommendation, and business justification.
        """.strip()
    
    def _extract_evidence(self, vuln: SpotlightVulnerability) -> Dict[str, Any]:
        """Extract evidence for AI analysis"""
        
        return {
            'cvss_score': vuln.cvss_score,
            'severity': vuln.severity,
            'exploitability': vuln.exploitability,
            'patch_available': vuln.patch_available,
            'exposure_days': (datetime.now(timezone.utc) - vuln.first_seen).days,
            'exposure_score': vuln.exposure_score,
            'business_criticality': vuln.business_criticality
        }
    
    def _build_metadata(self, vuln: SpotlightVulnerability, asset: AssetProfile) -> Dict[str, Any]:
        """Build metadata for vulnerability analysis"""
        
        return {
            'asset_id': asset.asset_id,
            'asset_criticality': asset.criticality.value,
            'business_function': asset.business_function,
            'data_classification': asset.data_classification,
            'compliance_scope': asset.compliance_scope,
            'vulnerability_id': vuln.id,
            'cve_id': vuln.cve_id,
            'first_seen': vuln.first_seen.isoformat(),
            'last_seen': vuln.last_seen.isoformat()
        }
    
    def _calculate_business_risk(self, vuln: SpotlightVulnerability, 
                               asset: AssetProfile, analysis: AnalysisResult) -> VulnerabilityRisk:
        """Calculate business risk classification"""
        
        # Factor calculations
        cvss_factor = min(vuln.cvss_score / 10.0, 1.0)
        
        asset_factor = {
            AssetCriticality.TIER_0: 1.0,
            AssetCriticality.TIER_1: 0.8,
            AssetCriticality.TIER_2: 0.6,
            AssetCriticality.TIER_3: 0.3
        }.get(asset.criticality, 0.5)
        
        exploit_factor = {
            'high': 1.0,
            'functional': 0.8,
            'poc': 0.6,
            'unproven': 0.3
        }.get(vuln.exploitability.lower(), 0.5)
        
        exposure_factor = min((datetime.now(timezone.utc) - vuln.first_seen).days / 365, 1.0)
        
        patch_factor = 0.2 if vuln.patch_available else 1.0
        
        # Calculate weighted risk score
        risk_score = (
            cvss_factor * self.risk_weights['cvss_score'] +
            asset_factor * self.risk_weights['asset_criticality'] +
            exploit_factor * self.risk_weights['exploitability'] +
            exposure_factor * self.risk_weights['exposure_time'] +
            patch_factor * self.risk_weights['patch_availability']
        )
        
        # Apply AI confidence adjustment
        ai_confidence_adjustment = analysis.confidence_score * 0.1
        adjusted_risk_score = risk_score + ai_confidence_adjustment
        
        # Map to risk classification
        if adjusted_risk_score >= 0.85:
            return VulnerabilityRisk.CRITICAL_BUSINESS_RISK
        elif adjusted_risk_score >= 0.70:
            return VulnerabilityRisk.HIGH_BUSINESS_RISK
        elif adjusted_risk_score >= 0.50:
            return VulnerabilityRisk.MEDIUM_BUSINESS_RISK
        elif adjusted_risk_score >= 0.30:
            return VulnerabilityRisk.LOW_BUSINESS_RISK
        else:
            return VulnerabilityRisk.ACCEPTED_RISK
    
    def _calculate_priority_score(self, vuln: SpotlightVulnerability, 
                                asset: AssetProfile, risk: VulnerabilityRisk) -> float:
        """Calculate numerical priority score for sorting/routing"""
        
        base_scores = {
            VulnerabilityRisk.CRITICAL_BUSINESS_RISK: 95.0,
            VulnerabilityRisk.HIGH_BUSINESS_RISK: 80.0,
            VulnerabilityRisk.MEDIUM_BUSINESS_RISK: 60.0,
            VulnerabilityRisk.LOW_BUSINESS_RISK: 35.0,
            VulnerabilityRisk.ACCEPTED_RISK: 10.0
        }
        
        base_score = base_scores[risk]
        
        # Adjustments
        if vuln.cvss_score >= 9.0:
            base_score += 5
        if vuln.exploitability.lower() in ['high', 'functional']:
            base_score += 3
        if vuln.patch_available:
            base_score += 2
        if asset.criticality in [AssetCriticality.TIER_0, AssetCriticality.TIER_1]:
            base_score += 3
        
        return min(base_score, 100.0)
    
    def _generate_business_justification(self, vuln: SpotlightVulnerability, 
                                       asset: AssetProfile, risk: VulnerabilityRisk,
                                       analysis: AnalysisResult) -> str:
        """Generate business justification for risk classification"""
        
        justification_parts = []
        
        # Risk classification rationale
        risk_rationale = {
            VulnerabilityRisk.CRITICAL_BUSINESS_RISK: "Poses immediate and severe business risk",
            VulnerabilityRisk.HIGH_BUSINESS_RISK: "Significant business impact potential",
            VulnerabilityRisk.MEDIUM_BUSINESS_RISK: "Moderate business risk requiring attention",
            VulnerabilityRisk.LOW_BUSINESS_RISK: "Limited business impact, scheduled remediation",
            VulnerabilityRisk.ACCEPTED_RISK: "Minimal impact, accepted business risk"
        }
        
        justification_parts.append(risk_rationale[risk])
        
        # Asset criticality impact
        if asset.criticality == AssetCriticality.TIER_0:
            justification_parts.append("Affects crown jewel business asset")
        elif asset.criticality == AssetCriticality.TIER_1:
            justification_parts.append("Impacts critical business system")
        
        # CVSS severity
        if vuln.cvss_score >= 9.0:
            justification_parts.append("Critical CVSS score requires immediate attention")
        elif vuln.cvss_score >= 7.0:
            justification_parts.append("High CVSS score indicates significant vulnerability")
        
        # Exploitability
        if vuln.exploitability.lower() in ['high', 'functional']:
            justification_parts.append("Active exploitation possible")
        
        # Patch availability
        if vuln.patch_available:
            justification_parts.append("Patch available for remediation")
        else:
            justification_parts.append("No patch available, requires alternative mitigation")
        
        # Compliance considerations
        if 'PCI' in asset.compliance_scope:
            justification_parts.append("PCI compliance requirements apply")
        if 'SOX' in asset.compliance_scope:
            justification_parts.append("SOX compliance impact")
        
        return ". ".join(justification_parts) + "."
    
    def _assess_remediation_complexity(self, vuln: SpotlightVulnerability, 
                                     asset: AssetProfile) -> str:
        """Assess remediation complexity and downtime requirements"""
        
        if asset.criticality == AssetCriticality.TIER_0:
            if vuln.patch_available:
                return "Complex - Crown jewel asset requires change management and minimal downtime"
            else:
                return "Very Complex - No patch available, requires vendor coordination and alternative controls"
        
        elif asset.criticality == AssetCriticality.TIER_1:
            if vuln.patch_available:
                return "Moderate - Standard change process with scheduled maintenance window"
            else:
                return "Complex - Alternative mitigation strategies required"
        
        else:
            if vuln.patch_available:
                return "Simple - Standard patch deployment during maintenance window"
            else:
                return "Moderate - Workaround configuration or additional controls"

class AssetInventoryManager:
    """Manages asset inventory and criticality classifications"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize asset inventory manager"""
        self.config = config
        self.asset_cache = {}
        self.cache_ttl = config.get('asset_cache_ttl', 3600)  # 1 hour
        
        # Default criticality mappings based on naming conventions
        self.criticality_patterns = {
            'dc-': AssetCriticality.TIER_0,  # Domain controllers
            'db-': AssetCriticality.TIER_0,  # Databases
            'web-prod': AssetCriticality.TIER_1,  # Production web servers
            'app-prod': AssetCriticality.TIER_1,  # Production app servers
            'web-staging': AssetCriticality.TIER_2,  # Staging systems
            'dev-': AssetCriticality.TIER_3,  # Development systems
        }
    
    async def get_asset_profile(self, asset_id: str, hostname: str, ip_address: str) -> AssetProfile:
        """Get or create asset profile with business context"""
        
        # Check cache first
        cache_key = f"{asset_id}_{hostname}"
        cached_asset = self.asset_cache.get(cache_key)
        
        if cached_asset and self._is_cache_valid(cached_asset['timestamp']):
            return cached_asset['asset']
        
        # Determine criticality from hostname patterns
        criticality = self._determine_criticality(hostname)
        
        # Determine business function from naming/IP patterns
        business_function = self._determine_business_function(hostname, ip_address)
        
        # Determine data classification
        data_classification = self._determine_data_classification(hostname, criticality)
        
        # Determine compliance scope
        compliance_scope = self._determine_compliance_scope(hostname, criticality, business_function)
        
        asset_profile = AssetProfile(
            asset_id=asset_id,
            hostname=hostname,
            ip_address=ip_address,
            criticality=criticality,
            business_function=business_function,
            data_classification=data_classification,
            compliance_scope=compliance_scope,
            last_updated=datetime.now(timezone.utc)
        )
        
        # Cache the result
        self.asset_cache[cache_key] = {
            'asset': asset_profile,
            'timestamp': datetime.now(timezone.utc)
        }
        
        return asset_profile
    
    def _is_cache_valid(self, timestamp: datetime) -> bool:
        """Check if cached asset data is still valid"""
        return (datetime.now(timezone.utc) - timestamp).total_seconds() < self.cache_ttl
    
    def _determine_criticality(self, hostname: str) -> AssetCriticality:
        """Determine asset criticality from hostname patterns"""
        
        hostname_lower = hostname.lower()
        
        for pattern, criticality in self.criticality_patterns.items():
            if hostname_lower.startswith(pattern):
                return criticality
        
        # Default to TIER_2 if no pattern matches
        return AssetCriticality.TIER_2
    
    def _determine_business_function(self, hostname: str, ip_address: str) -> str:
        """Determine business function from system characteristics"""
        
        hostname_lower = hostname.lower()
        
        # Function mapping based on naming conventions
        function_patterns = {
            'dc-': 'Active Directory',
            'db-': 'Database Services',
            'web-': 'Web Services',
            'app-': 'Application Services',
            'mail-': 'Email Services',
            'file-': 'File Services',
            'backup-': 'Backup Services',
            'fw-': 'Network Security',
            'proxy-': 'Network Proxy',
            'dns-': 'DNS Services'
        }
        
        for pattern, function in function_patterns.items():
            if hostname_lower.startswith(pattern):
                return function
        
        # IP-based classification for network ranges
        if ip_address.startswith('10.1.'):
            return 'Production Services'
        elif ip_address.startswith('10.2.'):
            return 'Development Services'
        elif ip_address.startswith('10.3.'):
            return 'Testing Services'
        
        return 'General IT Services'
    
    def _determine_data_classification(self, hostname: str, criticality: AssetCriticality) -> str:
        """Determine data classification based on asset characteristics"""
        
        hostname_lower = hostname.lower()
        
        # High sensitivity indicators
        if any(indicator in hostname_lower for indicator in ['financial', 'payment', 'customer', 'hr']):
            return 'Confidential'
        
        # Database systems often contain sensitive data
        if hostname_lower.startswith('db-') or 'database' in hostname_lower:
            return 'Confidential'
        
        # Criticality-based classification
        if criticality == AssetCriticality.TIER_0:
            return 'Confidential'
        elif criticality == AssetCriticality.TIER_1:
            return 'Internal'
        else:
            return 'Internal'
    
    def _determine_compliance_scope(self, hostname: str, criticality: AssetCriticality, 
                                  business_function: str) -> List[str]:
        """Determine applicable compliance frameworks"""
        
        compliance_scope = []
        hostname_lower = hostname.lower()
        
        # SOX compliance for financial systems
        if any(indicator in hostname_lower for indicator in ['financial', 'accounting', 'erp']):
            compliance_scope.append('SOX')
        
        # PCI DSS for payment systems
        if any(indicator in hostname_lower for indicator in ['payment', 'pos', 'card']):
            compliance_scope.append('PCI')
        
        # HIPAA for healthcare (if applicable)
        if any(indicator in hostname_lower for indicator in ['health', 'medical', 'patient']):
            compliance_scope.append('HIPAA')
        
        # ISO 27001 for all Tier 0 and Tier 1 assets
        if criticality in [AssetCriticality.TIER_0, AssetCriticality.TIER_1]:
            compliance_scope.append('ISO27001')
        
        # SOC 2 for customer-facing services
        if business_function in ['Web Services', 'Application Services', 'Database Services']:
            compliance_scope.append('SOC2')
        
        return compliance_scope or ['General']

class SpotlightWorkflowOrchestrator:
    """Main orchestrator for CrowdStrike Spotlight vulnerability workflow"""
    
    def __init__(self, config: Dict[str, Any], ai_orchestrator: AIOrchestrator):
        """Initialize Spotlight workflow orchestrator"""
        self.config = config
        self.ai_orchestrator = ai_orchestrator
        
        # Initialize components
        self.charlotte_analyzer = CharlotteAIAnalyzer(config.get('charlotte_config', {}), ai_orchestrator)
        self.asset_manager = AssetInventoryManager(config.get('asset_config', {}))
        
        # Workflow metrics
        self.metrics = {
            'vulnerabilities_processed': 0,
            'tickets_created': 0,
            'processing_time_avg': 0,
            'risk_distribution': {risk.name: 0 for risk in VulnerabilityRisk}
        }
        
        # Thresholds for ticket creation
        self.ticket_thresholds = {
            'minimum_cvss': config.get('minimum_cvss_for_ticket', 4.0),
            'minimum_risk_level': VulnerabilityRisk.MEDIUM_BUSINESS_RISK,
            'exclude_accepted_risks': config.get('exclude_accepted_risks', True)
        }
    
    async def process_vulnerability_scan(self, scan_filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Process complete vulnerability scan with AI analysis"""
        
        workflow_start = datetime.now(timezone.utc)
        logger.info("Starting Spotlight vulnerability workflow")
        
        try:
            # Step 1: Fetch vulnerabilities from CrowdStrike Spotlight
            async with CrowdStrikeSpotlightClient(self.config['crowdstrike']) as spotlight_client:
                vulnerabilities = await spotlight_client.fetch_vulnerabilities(scan_filters)
            
            logger.info(f"Fetched {len(vulnerabilities)} vulnerabilities from Spotlight")
            
            # Step 2: Process vulnerabilities with Charlotte AI analysis
            enriched_vulnerabilities = []
            processing_tasks = []
            
            # Process in batches to manage resource usage
            batch_size = self.config.get('processing_batch_size', 50)
            for i in range(0, len(vulnerabilities), batch_size):
                batch = vulnerabilities[i:i + batch_size]
                batch_tasks = [
                    self._process_single_vulnerability(vuln) 
                    for vuln in batch
                ]
                
                batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                
                for result in batch_results:
                    if isinstance(result, Exception):
                        logger.error(f"Error processing vulnerability: {result}")
                    else:
                        enriched_vulnerabilities.append(result)
            
            logger.info(f"Processed {len(enriched_vulnerabilities)} vulnerabilities with AI analysis")
            
            # Step 3: Filter and prioritize for ticket creation
            actionable_vulnerabilities = self._filter_actionable_vulnerabilities(enriched_vulnerabilities)
            
            # Step 4: Sort by priority score
            actionable_vulnerabilities.sort(key=lambda v: v.priority_score, reverse=True)
            
            # Step 5: Generate summary report
            workflow_duration = (datetime.now(timezone.utc) - workflow_start).total_seconds()
            
            summary = self._generate_workflow_summary(
                total_vulnerabilities=len(vulnerabilities),
                enriched_vulnerabilities=enriched_vulnerabilities,
                actionable_vulnerabilities=actionable_vulnerabilities,
                processing_time=workflow_duration
            )
            
            # Update metrics
            self.metrics['vulnerabilities_processed'] = len(vulnerabilities)
            
            return {
                'status': 'completed',
                'summary': summary,
                'actionable_vulnerabilities': [asdict(v) for v in actionable_vulnerabilities],
                'processing_time_seconds': workflow_duration,
                'workflow_id': hashlib.sha256(f"{workflow_start.isoformat()}_{len(vulnerabilities)}".encode()).hexdigest()[:12]
            }
        
        except Exception as e:
            logger.error(f"Workflow processing failed: {e}")
            return {
                'status': 'failed',
                'error': str(e),
                'processing_time_seconds': (datetime.now(timezone.utc) - workflow_start).total_seconds()
            }
    
    async def _process_single_vulnerability(self, vulnerability: SpotlightVulnerability) -> EnrichedVulnerability:
        """Process a single vulnerability with AI analysis"""
        
        # Get asset profile
        asset_profile = await self.asset_manager.get_asset_profile(
            vulnerability.asset_id,
            vulnerability.asset_hostname, 
            vulnerability.asset_ip
        )
        
        # Analyze with Charlotte AI
        enriched_vulnerability = await self.charlotte_analyzer.analyze_vulnerability(
            vulnerability, asset_profile
        )
        
        # Update risk distribution metrics
        risk_name = enriched_vulnerability.business_risk.name
        self.metrics['risk_distribution'][risk_name] += 1
        
        return enriched_vulnerability
    
    def _filter_actionable_vulnerabilities(self, enriched_vulnerabilities: List[EnrichedVulnerability]) -> List[EnrichedVulnerability]:
        """Filter vulnerabilities that should generate tickets"""
        
        actionable = []
        
        for vuln in enriched_vulnerabilities:
            # Apply filtering criteria
            meets_cvss_threshold = vuln.vulnerability.cvss_score >= self.ticket_thresholds['minimum_cvss']
            meets_risk_threshold = self._meets_risk_threshold(vuln.business_risk)
            not_accepted_risk = not (self.ticket_thresholds['exclude_accepted_risks'] and 
                                   vuln.business_risk == VulnerabilityRisk.ACCEPTED_RISK)
            
            if meets_cvss_threshold and meets_risk_threshold and not_accepted_risk:
                actionable.append(vuln)
        
        return actionable
    
    def _meets_risk_threshold(self, risk: VulnerabilityRisk) -> bool:
        """Check if vulnerability meets minimum risk threshold"""
        
        risk_levels = {
            VulnerabilityRisk.CRITICAL_BUSINESS_RISK: 5,
            VulnerabilityRisk.HIGH_BUSINESS_RISK: 4,
            VulnerabilityRisk.MEDIUM_BUSINESS_RISK: 3,
            VulnerabilityRisk.LOW_BUSINESS_RISK: 2,
            VulnerabilityRisk.ACCEPTED_RISK: 1
        }
        
        threshold_level = risk_levels[self.ticket_thresholds['minimum_risk_level']]
        current_level = risk_levels[risk]
        
        return current_level >= threshold_level
    
    def _generate_workflow_summary(self, total_vulnerabilities: int, 
                                 enriched_vulnerabilities: List[EnrichedVulnerability],
                                 actionable_vulnerabilities: List[EnrichedVulnerability],
                                 processing_time: float) -> Dict[str, Any]:
        """Generate comprehensive workflow summary"""
        
        # Risk distribution
        risk_counts = {}
        for vuln in enriched_vulnerabilities:
            risk_name = vuln.business_risk.name
            risk_counts[risk_name] = risk_counts.get(risk_name, 0) + 1
        
        # Asset criticality distribution
        asset_criticality_counts = {}
        for vuln in enriched_vulnerabilities:
            criticality = vuln.asset_profile.criticality.name
            asset_criticality_counts[criticality] = asset_criticality_counts.get(criticality, 0) + 1
        
        # CVSS distribution
        cvss_distribution = {
            'critical_9_10': len([v for v in enriched_vulnerabilities if v.vulnerability.cvss_score >= 9.0]),
            'high_7_8_9': len([v for v in enriched_vulnerabilities if 7.0 <= v.vulnerability.cvss_score < 9.0]),
            'medium_4_6_9': len([v for v in enriched_vulnerabilities if 4.0 <= v.vulnerability.cvss_score < 7.0]),
            'low_0_3_9': len([v for v in enriched_vulnerabilities if v.vulnerability.cvss_score < 4.0])
        }
        
        # Processing efficiency metrics
        reduction_rate = (total_vulnerabilities - len(actionable_vulnerabilities)) / total_vulnerabilities * 100
        avg_confidence = sum(v.charlotte_analysis['ai_confidence'] for v in enriched_vulnerabilities) / len(enriched_vulnerabilities)
        
        return {
            'total_vulnerabilities_scanned': total_vulnerabilities,
            'vulnerabilities_analyzed': len(enriched_vulnerabilities),
            'actionable_tickets': len(actionable_vulnerabilities),
            'reduction_rate_percent': round(reduction_rate, 1),
            'processing_time_seconds': round(processing_time, 2),
            'avg_processing_time_per_vuln': round(processing_time / total_vulnerabilities, 3),
            'avg_ai_confidence': round(avg_confidence, 3),
            'risk_distribution': risk_counts,
            'asset_criticality_distribution': asset_criticality_counts,
            'cvss_distribution': cvss_distribution,
            'top_priority_vulnerabilities': [
                {
                    'vulnerability_id': v.vulnerability.id,
                    'cve_id': v.vulnerability.cve_id,
                    'asset_hostname': v.asset_profile.hostname,
                    'business_risk': v.business_risk.name,
                    'priority_score': v.priority_score,
                    'recommended_sla': v.recommended_sla
                }
                for v in sorted(actionable_vulnerabilities, key=lambda x: x.priority_score, reverse=True)[:10]
            ]
        }

    async def get_workflow_metrics(self) -> Dict[str, Any]:
        """Get current workflow performance metrics"""
        
        return {
            'processing_metrics': self.metrics,
            'configuration': {
                'ticket_thresholds': {
                    'minimum_cvss': self.ticket_thresholds['minimum_cvss'],
                    'minimum_risk_level': self.ticket_thresholds['minimum_risk_level'].name,
                    'exclude_accepted_risks': self.ticket_thresholds['exclude_accepted_risks']
                }
            }
        }