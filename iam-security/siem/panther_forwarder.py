"""
Panther SIEM Integration

Optimized log forwarding and formatting for Panther SIEM platform
with support for HTTP and S3 delivery methods.
"""

import json
import gzip
import time
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import io
import uuid

import requests
import boto3
from botocore.exceptions import ClientError
import structlog

from .universal_formatter import UniversalFormatter, SchemaDefinition, EventMapping
from ..okta_security.exceptions import SIEMIntegrationError

logger = structlog.get_logger()


@dataclass
class PantherConfig:
    """Panther SIEM configuration"""
    # HTTP delivery
    http_endpoint: Optional[str] = None
    http_headers: Dict[str, str] = None
    
    # S3 delivery
    s3_bucket: Optional[str] = None
    s3_prefix: str = "okta-logs"
    s3_region: str = "us-east-1"
    
    # Authentication
    auth_token: Optional[str] = None
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    
    # Delivery settings
    delivery_method: str = "http"  # http, s3, both
    batch_size: int = 1000
    batch_timeout: int = 300  # 5 minutes
    compression: bool = True
    
    # Retry settings
    max_retries: int = 3
    retry_delay: int = 5


class PantherForwarder:
    """
    Panther SIEM log forwarder with optimized delivery and formatting.
    
    Features:
    - HTTP endpoint delivery
    - S3 batch upload
    - Automatic batching and compression
    - Retry logic with exponential backoff
    - Schema validation
    - Delivery metrics and monitoring
    """
    
    def __init__(self, config: PantherConfig):
        self.config = config
        self.formatter = UniversalFormatter()
        
        # Batch management
        self.pending_events = []
        self.last_batch_time = datetime.utcnow()
        
        # AWS S3 client
        self.s3_client = None
        if config.delivery_method in ['s3', 'both']:
            self._init_s3_client()
        
        # HTTP session
        self.session = requests.Session()
        if config.http_headers:
            self.session.headers.update(config.http_headers)
        
        # Threading for async delivery
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        # Statistics
        self.stats = {
            'events_forwarded': 0,
            'events_failed': 0,
            'batches_sent': 0,
            'last_delivery': None,
            'delivery_errors': []
        }
        
        # Load Panther-optimized schema
        self._load_panther_schema()
        
        logger.info("Panther forwarder initialized", 
                   delivery_method=config.delivery_method,
                   batch_size=config.batch_size)
    
    def _init_s3_client(self):
        """Initialize S3 client for batch uploads"""
        try:
            if self.config.aws_access_key_id and self.config.aws_secret_access_key:
                self.s3_client = boto3.client(
                    's3',
                    aws_access_key_id=self.config.aws_access_key_id,
                    aws_secret_access_key=self.config.aws_secret_access_key,
                    region_name=self.config.s3_region
                )
            else:
                # Use default credential chain
                self.s3_client = boto3.client('s3', region_name=self.config.s3_region)
            
            # Test connection
            self.s3_client.head_bucket(Bucket=self.config.s3_bucket)
            logger.info("S3 client initialized successfully", bucket=self.config.s3_bucket)
            
        except Exception as e:
            logger.error("Failed to initialize S3 client", error=str(e))
            raise SIEMIntegrationError(f"S3 initialization failed: {e}")
    
    def _load_panther_schema(self):
        """Load Panther-optimized schema"""
        panther_schema = SchemaDefinition(
            name="panther_okta",
            version="1.0",
            format_type="json",
            field_mappings=[
                # Core fields
                EventMapping("uuid", "p_event_id", required=True),
                EventMapping("published", "p_event_time", "datetime", required=True),
                EventMapping("eventType", "p_log_type", required=True),
                
                # Panther-specific enrichment
                EventMapping("severity", "p_severity"),
                EventMapping("outcome.result", "p_outcome"),
                
                # Identity fields
                EventMapping("actor.id", "okta_actor_id"),
                EventMapping("actor.displayName", "okta_actor_name"),
                EventMapping("actor.type", "okta_actor_type"),
                
                # Network fields
                EventMapping("client.ipAddress", "p_source_ip", "ip"),
                EventMapping("client.userAgent.rawUserAgent", "http_user_agent"),
                EventMapping("client.geographicalContext.country", "p_source_country"),
                EventMapping("client.geographicalContext.state", "p_source_state"),
                EventMapping("client.geographicalContext.city", "p_source_city"),
                
                # Authentication fields
                EventMapping("authenticationContext.authenticationProvider", "okta_auth_provider"),
                EventMapping("authenticationContext.authenticationStep", "okta_auth_step", "int"),
                EventMapping("authenticationContext.credentialProvider", "okta_credential_provider"),
                EventMapping("authenticationContext.credentialType", "okta_credential_type"),
                
                # Application fields
                EventMapping("target.0.id", "okta_target_id"),
                EventMapping("target.0.type", "okta_target_type"),
                EventMapping("target.0.displayName", "okta_target_name"),
                EventMapping("target.0.alternateId", "okta_target_alt_id"),
                
                # Security context
                EventMapping("securityContext.asNumber", "asn", "int"),
                EventMapping("securityContext.asOrg", "as_org"),
                EventMapping("securityContext.isProxy", "is_proxy", "bool"),
                EventMapping("securityContext.isp", "isp"),
                
                # Request context
                EventMapping("debugContext.debugData.requestId", "okta_request_id"),
                EventMapping("debugContext.debugData.requestUri", "okta_request_uri"),
                EventMapping("debugContext.debugData.threatSuspected", "threat_suspected", "bool"),
                
                # Transaction info
                EventMapping("transaction.id", "okta_transaction_id"),
                EventMapping("transaction.type", "okta_transaction_type"),
                
                # Message
                EventMapping("displayMessage", "p_description"),
                EventMapping("legacyEventType", "okta_legacy_event_type")
            ],
            required_fields=["p_event_id", "p_event_time", "p_log_type"],
            metadata={
                'p_source_label': 'okta-identity-security',
                'p_schema_version': '1.0',
                'p_log_source': 'okta'
            }
        )
        
        self.formatter.add_schema(panther_schema)
    
    def forward_event(self, event: Dict, immediate: bool = False) -> bool:
        """
        Forward single event to Panther
        
        Args:
            event: Raw Okta event
            immediate: Send immediately without batching
            
        Returns:
            Success status
        """
        
        try:
            # Format event for Panther
            formatted_event = self.formatter.format_event(event, "panther_okta")
            
            # Add Panther-specific metadata
            formatted_event.update({
                'p_parse_time': datetime.utcnow().isoformat(),
                'p_ingestion_time': datetime.utcnow().isoformat(),
                'p_source_id': f"okta-{event.get('uuid', 'unknown')}",
                'p_source_label': 'okta-identity-security'
            })
            
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
        Forward multiple events to Panther
        
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
                formatted_event = self.formatter.format_event(event, "panther_okta")
                
                # Add Panther metadata
                formatted_event.update({
                    'p_parse_time': datetime.utcnow().isoformat(),
                    'p_ingestion_time': datetime.utcnow().isoformat(),
                    'p_source_id': f"okta-{event.get('uuid', 'unknown')}",
                    'p_source_label': 'okta-identity-security'
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
        """Check if batch should be sent based on size and time"""
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
                # Choose delivery method
                if self.config.delivery_method == "http":
                    success = self._send_via_http(events)
                elif self.config.delivery_method == "s3":
                    success = self._send_via_s3(events)
                elif self.config.delivery_method == "both":
                    http_success = self._send_via_http(events)
                    s3_success = self._send_via_s3(events)
                    success = http_success or s3_success  # Success if either works
                else:
                    raise SIEMIntegrationError(f"Unknown delivery method: {self.config.delivery_method}")
                
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
                    time.sleep(min(delay, 300))  # Max 5 minutes
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
    
    def _send_via_http(self, events: List[Dict]) -> bool:
        """Send events via HTTP endpoint"""
        if not self.config.http_endpoint:
            raise SIEMIntegrationError("HTTP endpoint not configured")
        
        try:
            # Prepare payload
            if self.config.compression:
                # Compress JSON payload
                json_data = '\\n'.join(json.dumps(event, separators=(',', ':')) for event in events)
                
                # Gzip compression
                buffer = io.BytesIO()
                with gzip.GzipFile(fileobj=buffer, mode='wb') as gz:
                    gz.write(json_data.encode('utf-8'))
                
                payload = buffer.getvalue()
                headers = {
                    'Content-Type': 'application/json',
                    'Content-Encoding': 'gzip'
                }
            else:
                payload = '\\n'.join(json.dumps(event, separators=(',', ':')) for event in events)
                headers = {'Content-Type': 'application/json'}
            
            # Add authentication header
            if self.config.auth_token:
                headers['Authorization'] = f'Bearer {self.config.auth_token}'
            
            # Send request
            response = self.session.post(
                self.config.http_endpoint,
                data=payload,
                headers=headers,
                timeout=60
            )
            
            response.raise_for_status()
            
            logger.info("Events sent via HTTP", 
                       events_count=len(events),
                       status_code=response.status_code,
                       compressed=self.config.compression)
            
            return True
            
        except requests.exceptions.RequestException as e:
            logger.error("HTTP delivery failed", error=str(e))
            return False
    
    def _send_via_s3(self, events: List[Dict]) -> bool:
        """Send events via S3 upload"""
        if not self.s3_client or not self.config.s3_bucket:
            raise SIEMIntegrationError("S3 not configured")
        
        try:
            # Create S3 key with timestamp
            timestamp = datetime.utcnow()
            s3_key = f"{self.config.s3_prefix}/year={timestamp.year}/month={timestamp.month:02d}/day={timestamp.day:02d}/{timestamp.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}.json"
            
            if self.config.compression:
                s3_key += ".gz"
            
            # Prepare data
            json_data = '\\n'.join(json.dumps(event, separators=(',', ':')) for event in events)
            
            if self.config.compression:
                # Compress data
                buffer = io.BytesIO()
                with gzip.GzipFile(fileobj=buffer, mode='wb') as gz:
                    gz.write(json_data.encode('utf-8'))
                data_to_upload = buffer.getvalue()
                content_type = 'application/json'
                content_encoding = 'gzip'
            else:
                data_to_upload = json_data.encode('utf-8')
                content_type = 'application/json'
                content_encoding = None
            
            # Upload to S3
            extra_args = {
                'ContentType': content_type,
                'Metadata': {
                    'events_count': str(len(events)),
                    'upload_time': timestamp.isoformat(),
                    'source': 'okta-security-integration'
                }
            }
            
            if content_encoding:
                extra_args['ContentEncoding'] = content_encoding
            
            self.s3_client.put_object(
                Bucket=self.config.s3_bucket,
                Key=s3_key,
                Body=data_to_upload,
                **extra_args
            )
            
            logger.info("Events uploaded to S3",
                       events_count=len(events),
                       s3_key=s3_key,
                       compressed=self.config.compression)
            
            return True
            
        except ClientError as e:
            logger.error("S3 upload failed", error=str(e))
            return False
    
    def test_connectivity(self) -> Dict:
        """Test connectivity to Panther endpoints"""
        results = {
            'timestamp': datetime.utcnow().isoformat(),
            'http_connectivity': False,
            's3_connectivity': False,
            'overall_status': False
        }
        
        # Test HTTP endpoint
        if self.config.delivery_method in ['http', 'both'] and self.config.http_endpoint:
            try:
                # Send test event
                test_event = {
                    'p_event_id': f'test-{uuid.uuid4().hex}',
                    'p_event_time': datetime.utcnow().isoformat(),
                    'p_log_type': 'connectivity_test',
                    'p_source_label': 'okta-identity-security',
                    'test_message': 'Connectivity test from Okta security integration'
                }
                
                success = self._send_via_http([test_event])
                results['http_connectivity'] = success
                
            except Exception as e:
                results['http_error'] = str(e)
        
        # Test S3 connectivity
        if self.config.delivery_method in ['s3', 'both'] and self.s3_client:
            try:
                # Test S3 bucket access
                self.s3_client.head_bucket(Bucket=self.config.s3_bucket)
                results['s3_connectivity'] = True
                
            except Exception as e:
                results['s3_error'] = str(e)
        
        # Overall status
        if self.config.delivery_method == "http":
            results['overall_status'] = results['http_connectivity']
        elif self.config.delivery_method == "s3":
            results['overall_status'] = results['s3_connectivity']
        else:  # both
            results['overall_status'] = results['http_connectivity'] or results['s3_connectivity']
        
        return results
    
    def get_statistics(self) -> Dict:
        """Get forwarding statistics"""
        return {
            **self.stats,
            'pending_events': len(self.pending_events),
            'last_batch_time': self.last_batch_time.isoformat(),
            'config': {
                'delivery_method': self.config.delivery_method,
                'batch_size': self.config.batch_size,
                'batch_timeout': self.config.batch_timeout,
                'compression': self.config.compression
            }
        }
    
    def shutdown(self):
        """Graceful shutdown - flush pending events"""
        logger.info("Shutting down Panther forwarder, flushing pending events")
        
        # Flush any pending events
        if self.pending_events:
            self.flush_pending_events()
        
        # Shutdown thread pool
        self.executor.shutdown(wait=True)
        
        logger.info("Panther forwarder shutdown complete")