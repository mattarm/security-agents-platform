"""
CrowdStrike Falcon Integration

Log forwarding for CrowdStrike Falcon platform using LogScale
(formerly Humio) APIs and data formats.
"""

import json
import gzip
import time
import hmac
import hashlib
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import io
import uuid
import base64

import requests
import structlog

from .universal_formatter import UniversalFormatter, SchemaDefinition, EventMapping
from ..okta_security.exceptions import SIEMIntegrationError

logger = structlog.get_logger()


@dataclass
class CrowdStrikeConfig:
    """CrowdStrike Falcon LogScale configuration"""
    # LogScale/Humio endpoint
    logscale_url: str
    repository: str = "okta-logs"
    
    # Authentication
    ingest_token: Optional[str] = None
    api_token: Optional[str] = None
    
    # Data source configuration
    datasource: str = "okta-identity-security"
    parser: str = "json"
    
    # Delivery settings
    batch_size: int = 1000
    batch_timeout: int = 60  # 1 minute for LogScale
    compression: bool = True
    
    # Retry settings
    max_retries: int = 3
    retry_delay: int = 2
    
    # LogScale specific
    use_structured_data: bool = True
    timezone: str = "UTC"


class CrowdStrikeForwarder:
    """
    CrowdStrike Falcon LogScale forwarder for Okta identity events.
    
    Features:
    - LogScale HTTP ingest API
    - Structured data formatting
    - Batch processing with compression
    - CrowdStrike-specific field mapping
    - Event correlation and enrichment
    - Automatic parser assignment
    """
    
    def __init__(self, config: CrowdStrikeConfig):
        self.config = config
        self.formatter = UniversalFormatter()
        
        # Batch management
        self.pending_events = []
        self.last_batch_time = datetime.utcnow()
        
        # HTTP session with auth
        self.session = requests.Session()
        self._configure_authentication()
        
        # Threading for async delivery
        self.executor = ThreadPoolExecutor(max_workers=3)
        
        # Statistics
        self.stats = {
            'events_forwarded': 0,
            'events_failed': 0,
            'batches_sent': 0,
            'bytes_sent': 0,
            'last_delivery': None,
            'delivery_errors': []
        }
        
        # Load CrowdStrike schema
        self._load_crowdstrike_schema()
        
        logger.info("CrowdStrike forwarder initialized",
                   logscale_url=config.logscale_url,
                   repository=config.repository)
    
    def _configure_authentication(self):
        """Configure authentication headers"""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'okta-security-integration/1.0'
        }
        
        if self.config.ingest_token:
            headers['Authorization'] = f'Bearer {self.config.ingest_token}'
        
        self.session.headers.update(headers)
    
    def _load_crowdstrike_schema(self):
        """Load CrowdStrike Falcon LogScale optimized schema"""
        crowdstrike_schema = SchemaDefinition(
            name="crowdstrike_falcon",
            version="1.0", 
            format_type="json",
            field_mappings=[
                # Core CrowdStrike fields
                EventMapping("uuid", "@id", required=True),
                EventMapping("published", "@timestamp", "datetime", required=True),
                EventMapping("eventType", "@type", required=True),
                
                # Identity and authentication
                EventMapping("actor.id", "user.id"),
                EventMapping("actor.displayName", "user.name"),
                EventMapping("actor.alternateId", "user.email"),
                EventMapping("actor.type", "user.type"),
                
                # Network and location
                EventMapping("client.ipAddress", "source.ip", "ip"),
                EventMapping("client.userAgent.rawUserAgent", "user_agent.original"),
                EventMapping("client.geographicalContext.country", "source.geo.country_iso_code"),
                EventMapping("client.geographicalContext.state", "source.geo.region_name"),
                EventMapping("client.geographicalContext.city", "source.geo.city_name"),
                EventMapping("client.geographicalContext.postalCode", "source.geo.postal_code"),
                
                # Authentication details
                EventMapping("authenticationContext.authenticationProvider", "okta.auth.provider"),
                EventMapping("authenticationContext.authenticationStep", "okta.auth.step", "int"),
                EventMapping("authenticationContext.credentialProvider", "okta.auth.credential_provider"),
                EventMapping("authenticationContext.credentialType", "okta.auth.credential_type"),
                EventMapping("authenticationContext.issuer", "okta.auth.issuer"),
                
                # Event outcome and details
                EventMapping("outcome.result", "event.outcome"),
                EventMapping("outcome.reason", "event.reason"),
                EventMapping("severity", "event.severity"),
                EventMapping("displayMessage", "message"),
                EventMapping("legacyEventType", "okta.legacy_event_type"),
                
                # Target information
                EventMapping("target.0.id", "target.id"),
                EventMapping("target.0.type", "target.type"),
                EventMapping("target.0.displayName", "target.name"),
                EventMapping("target.0.alternateId", "target.alternate_id"),
                
                # Security context
                EventMapping("securityContext.asNumber", "source.as.number", "int"),
                EventMapping("securityContext.asOrg", "source.as.organization.name"),
                EventMapping("securityContext.isp", "source.provider"),
                EventMapping("securityContext.isProxy", "source.is_proxy", "bool"),
                
                # Request context
                EventMapping("debugContext.debugData.requestId", "okta.request.id"),
                EventMapping("debugContext.debugData.requestUri", "okta.request.uri"),
                EventMapping("debugContext.debugData.threatSuspected", "okta.threat_suspected", "bool"),
                EventMapping("debugContext.debugData.url", "url.original"),
                
                # Transaction details
                EventMapping("transaction.id", "okta.transaction.id"),
                EventMapping("transaction.type", "okta.transaction.type"),
                EventMapping("transaction.detail", "okta.transaction.detail"),
                
                # Application context
                EventMapping("target.0.displayName", "service.name", transform_function="extract_service_name"),
                
                # Additional Okta-specific fields
                EventMapping("version", "okta.version"),
                EventMapping("published", "okta.published", "datetime")
            ],
            required_fields=["@id", "@timestamp", "@type"],
            metadata={
                'service.type': 'okta',
                'service.name': 'okta-identity',
                'service.version': '1.0',
                'data_stream.type': 'logs',
                'data_stream.dataset': 'okta.system',
                'data_stream.namespace': 'default'
            }
        )
        
        self.formatter.add_schema(crowdstrike_schema)
    
    def forward_event(self, event: Dict, immediate: bool = False) -> bool:
        """
        Forward single event to CrowdStrike Falcon
        
        Args:
            event: Raw Okta event
            immediate: Send immediately without batching
            
        Returns:
            Success status
        """
        
        try:
            # Format event for CrowdStrike
            formatted_event = self.formatter.format_event(event, "crowdstrike_falcon")
            
            # Add CrowdStrike-specific metadata
            formatted_event.update({
                '@ingest_timestamp': datetime.utcnow().isoformat(),
                'labels': {
                    'service': 'okta',
                    'environment': 'production',
                    'data_source': self.config.datasource
                },
                'tags': ['okta', 'identity', 'authentication'],
                'falcon': {
                    'parser': self.config.parser,
                    'repository': self.config.repository
                }
            })
            
            # Add event correlation ID for tracking
            formatted_event['correlation_id'] = self._generate_correlation_id(event)
            
            if immediate:
                return self._send_events_immediate([formatted_event])
            else:
                # Add to batch
                self.pending_events.append(formatted_event)
                
                # Check if batch should be sent
                if self._should_send_batch():
                    self._send_batch_async()
                
                return True
                
        except Exception as e:
            logger.error("Event forwarding failed",
                        event_id=event.get('uuid'),
                        error=str(e))
            self.stats['events_failed'] += 1
            return False
    
    def forward_events_batch(self, events: List[Dict], immediate: bool = True) -> Dict:
        """
        Forward multiple events to CrowdStrike Falcon
        
        Args:
            events: List of raw Okta events
            immediate: Send immediately
            
        Returns:
            Result summary
        """
        
        formatted_events = []
        failed_count = 0
        
        for event in events:
            try:
                formatted_event = self.formatter.format_event(event, "crowdstrike_falcon")
                
                # Add CrowdStrike metadata
                formatted_event.update({
                    '@ingest_timestamp': datetime.utcnow().isoformat(),
                    'labels': {
                        'service': 'okta',
                        'environment': 'production',
                        'data_source': self.config.datasource
                    },
                    'tags': ['okta', 'identity', 'authentication'],
                    'falcon': {
                        'parser': self.config.parser,
                        'repository': self.config.repository
                    },
                    'correlation_id': self._generate_correlation_id(event)
                })
                
                formatted_events.append(formatted_event)
                
            except Exception as e:
                logger.warning("Event formatting failed",
                              event_id=event.get('uuid'),
                              error=str(e))
                failed_count += 1
                continue
        
        if not formatted_events:
            return {
                'success': False,
                'formatted_count': 0,
                'failed_count': failed_count,
                'sent_count': 0
            }
        
        # Send events
        if immediate:
            success = self._send_events_immediate(formatted_events)
            sent_count = len(formatted_events) if success else 0
        else:
            # Add to pending batch
            self.pending_events.extend(formatted_events)
            sent_count = len(formatted_events)
            success = True
        
        return {
            'success': success,
            'formatted_count': len(formatted_events),
            'failed_count': failed_count,
            'sent_count': sent_count
        }
    
    def flush_pending_events(self) -> bool:
        """Force send any pending events"""
        if not self.pending_events:
            return True
        
        return self._send_batch_sync()
    
    def _should_send_batch(self) -> bool:
        """Check if batch should be sent"""
        if len(self.pending_events) >= self.config.batch_size:
            return True
        
        if self.pending_events and \
           (datetime.utcnow() - self.last_batch_time).total_seconds() >= self.config.batch_timeout:
            return True
        
        return False
    
    def _send_batch_async(self):
        """Send batch asynchronously"""
        if not self.pending_events:
            return
        
        events_to_send = self.pending_events.copy()
        self.pending_events.clear()
        self.last_batch_time = datetime.utcnow()
        
        # Submit to thread pool
        self.executor.submit(self._send_events_with_retry, events_to_send)
    
    def _send_batch_sync(self) -> bool:
        """Send batch synchronously"""
        if not self.pending_events:
            return True
        
        events_to_send = self.pending_events.copy()
        self.pending_events.clear()
        self.last_batch_time = datetime.utcnow()
        
        return self._send_events_with_retry(events_to_send)
    
    def _send_events_immediate(self, events: List[Dict]) -> bool:
        """Send events immediately"""
        return self._send_events_with_retry(events)
    
    def _send_events_with_retry(self, events: List[Dict]) -> bool:
        """Send events with retry logic"""
        last_error = None
        
        for attempt in range(self.config.max_retries + 1):
            try:
                success = self._send_via_logscale_ingest(events)
                
                if success:
                    self.stats['events_forwarded'] += len(events)
                    self.stats['batches_sent'] += 1
                    self.stats['last_delivery'] = datetime.utcnow().isoformat()
                    return True
                    
            except Exception as e:
                last_error = str(e)
                logger.warning("Delivery attempt failed",
                              attempt=attempt + 1,
                              events_count=len(events),
                              error=str(e))
                
                if attempt < self.config.max_retries:
                    # Exponential backoff
                    delay = self.config.retry_delay * (2 ** attempt)
                    time.sleep(min(delay, 60))  # Max 1 minute
                    continue
        
        # All retries failed
        self.stats['events_failed'] += len(events)
        self.stats['delivery_errors'].append({
            'timestamp': datetime.utcnow().isoformat(),
            'events_count': len(events),
            'error': last_error
        })
        
        # Keep only last 10 errors
        self.stats['delivery_errors'] = self.stats['delivery_errors'][-10:]
        
        logger.error("Event delivery failed after all retries",
                    events_count=len(events),
                    error=last_error)
        return False
    
    def _send_via_logscale_ingest(self, events: List[Dict]) -> bool:
        """Send events via LogScale ingest API"""
        try:
            # Prepare LogScale ingest payload
            ingest_events = []
            
            for event in events:
                # LogScale expects specific format
                logscale_event = {
                    'timestamp': event.get('@timestamp'),
                    'timezone': self.config.timezone,
                    'attributes': event,
                    'rawstring': json.dumps(event, separators=(',', ':'))
                }
                
                # Add tags for better organization
                logscale_event['attributes']['#repo'] = self.config.repository
                logscale_event['attributes']['#type'] = self.config.parser
                logscale_event['attributes']['#datasource'] = self.config.datasource
                
                ingest_events.append(logscale_event)
            
            # Create batch payload
            payload = {
                'tags': {
                    'repo': self.config.repository,
                    'type': self.config.parser,
                    'source': self.config.datasource
                },
                'events': ingest_events
            }
            
            # Prepare request
            ingest_url = f"{self.config.logscale_url}/api/v1/ingest/hec"
            
            if self.config.compression:
                # Compress payload
                json_data = json.dumps(payload, separators=(',', ':'))
                
                buffer = io.BytesIO()
                with gzip.GzipFile(fileobj=buffer, mode='wb') as gz:
                    gz.write(json_data.encode('utf-8'))
                
                data = buffer.getvalue()
                headers = {
                    'Content-Type': 'application/json',
                    'Content-Encoding': 'gzip'
                }
            else:
                data = json.dumps(payload, separators=(',', ':'))
                headers = {'Content-Type': 'application/json'}
            
            # Add repository-specific headers if needed
            headers.update({
                'X-Humio-Repository': self.config.repository,
                'X-Humio-Parser': self.config.parser
            })
            
            # Send request
            response = self.session.post(
                ingest_url,
                data=data,
                headers=headers,
                timeout=60
            )
            
            response.raise_for_status()
            
            # Track bytes sent
            self.stats['bytes_sent'] += len(data) if isinstance(data, bytes) else len(data.encode())
            
            logger.info("Events sent to LogScale",
                       events_count=len(events),
                       status_code=response.status_code,
                       compressed=self.config.compression,
                       repository=self.config.repository)
            
            return True
            
        except requests.exceptions.RequestException as e:
            logger.error("LogScale ingest failed", error=str(e))
            return False
    
    def _generate_correlation_id(self, event: Dict) -> str:
        """Generate correlation ID for event tracking"""
        # Use actor ID + timestamp + event type for correlation
        components = [
            event.get('actor', {}).get('id', 'unknown'),
            event.get('published', ''),
            event.get('eventType', '')
        ]
        
        correlation_str = '|'.join(str(c) for c in components)
        return hashlib.md5(correlation_str.encode()).hexdigest()[:12]
    
    def create_parser(self, parser_name: str = None) -> Dict:
        """Create custom LogScale parser for Okta events"""
        parser_name = parser_name or "okta-identity-security"
        
        # LogScale parser script for Okta events
        parser_script = """
        // Okta Identity Security Events Parser
        case {
            @type = /user\.authentication\./ | putField("category", "authentication");
            @type = /user\.session\./ | putField("category", "session");
            @type = /group\./ | putField("category", "group_management");
            @type = /application\./ | putField("category", "application");
            @type = /policy\./ | putField("category", "policy");
            * | putField("category", "other")
        }
        
        // Extract risk indicators
        case {
            event.outcome = "FAILURE" | putField("risk_score", 5);
            source.is_proxy = true | putField("risk_score", 3);
            okta.threat_suspected = true | putField("risk_score", 8);
            * | putField("risk_score", 1)
        }
        
        // Geo-location enrichment
        case {
            source.geo.country_iso_code != "US" | putField("geo_risk", "medium");
            source.geo.country_iso_code in ["CN", "RU", "KP"] | putField("geo_risk", "high");
            * | putField("geo_risk", "low")
        }
        
        // Authentication method classification
        case {
            okta.auth.provider = "OKTA" | putField("auth_method", "native");
            okta.auth.provider in ["ACTIVE_DIRECTORY", "LDAP"] | putField("auth_method", "directory");
            okta.auth.provider = "SOCIAL" | putField("auth_method", "social");
            * | putField("auth_method", "other")
        }
        """
        
        try:
            # Create parser via API
            parser_url = f"{self.config.logscale_url}/api/v1/repositories/{self.config.repository}/parsers"
            
            parser_data = {
                'name': parser_name,
                'script': parser_script,
                'tagFields': ['category', 'auth_method', 'geo_risk'],
                'timeFormat': 'iso'
            }
            
            response = self.session.post(
                parser_url,
                json=parser_data,
                timeout=30
            )
            
            if response.status_code == 201:
                logger.info("LogScale parser created", parser_name=parser_name)
                return {'success': True, 'parser_name': parser_name}
            else:
                logger.warning("Parser creation failed", 
                             status_code=response.status_code,
                             response=response.text)
                return {'success': False, 'error': response.text}
                
        except Exception as e:
            logger.error("Parser creation error", error=str(e))
            return {'success': False, 'error': str(e)}
    
    def create_search_alert(self, alert_name: str, query: str, description: str = None) -> Dict:
        """Create LogScale search alert for Okta events"""
        try:
            alert_url = f"{self.config.logscale_url}/api/v1/repositories/{self.config.repository}/alerts"
            
            alert_data = {
                'name': alert_name,
                'description': description or f"Alert for {alert_name}",
                'query': query,
                'start': '24h',
                'throttleTimeMillis': 300000,  # 5 minutes
                'enabled': True,
                'actions': [
                    {
                        'type': 'email',
                        'recipients': ['security-team@company.com']
                    }
                ]
            }
            
            response = self.session.post(
                alert_url,
                json=alert_data,
                timeout=30
            )
            
            if response.status_code == 201:
                logger.info("LogScale alert created", alert_name=alert_name)
                return {'success': True, 'alert_name': alert_name}
            else:
                return {'success': False, 'error': response.text}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def test_connectivity(self) -> Dict:
        """Test connectivity to CrowdStrike LogScale"""
        results = {
            'timestamp': datetime.utcnow().isoformat(),
            'logscale_connectivity': False,
            'repository_access': False,
            'ingest_test': False,
            'overall_status': False
        }
        
        try:
            # Test basic connectivity
            health_url = f"{self.config.logscale_url}/api/v1/status"
            response = self.session.get(health_url, timeout=10)
            response.raise_for_status()
            results['logscale_connectivity'] = True
            
            # Test repository access
            repo_url = f"{self.config.logscale_url}/api/v1/repositories/{self.config.repository}"
            response = self.session.get(repo_url, timeout=10)
            if response.status_code == 200:
                results['repository_access'] = True
            
            # Test ingest with minimal event
            test_event = {
                '@id': f'test-{uuid.uuid4().hex}',
                '@timestamp': datetime.utcnow().isoformat(),
                '@type': 'connectivity_test',
                'message': 'Connectivity test from Okta security integration',
                'test': True
            }
            
            success = self._send_via_logscale_ingest([test_event])
            results['ingest_test'] = success
            
        except Exception as e:
            results['error'] = str(e)
        
        # Overall status
        results['overall_status'] = all([
            results['logscale_connectivity'],
            results['repository_access'],
            results['ingest_test']
        ])
        
        return results
    
    def get_statistics(self) -> Dict:
        """Get forwarding statistics"""
        return {
            **self.stats,
            'pending_events': len(self.pending_events),
            'last_batch_time': self.last_batch_time.isoformat(),
            'config': {
                'repository': self.config.repository,
                'datasource': self.config.datasource,
                'batch_size': self.config.batch_size,
                'batch_timeout': self.config.batch_timeout,
                'compression': self.config.compression
            }
        }
    
    def shutdown(self):
        """Graceful shutdown"""
        logger.info("Shutting down CrowdStrike forwarder")
        
        # Flush pending events
        if self.pending_events:
            self.flush_pending_events()
        
        # Shutdown thread pool
        self.executor.shutdown(wait=True)
        
        logger.info("CrowdStrike forwarder shutdown complete")