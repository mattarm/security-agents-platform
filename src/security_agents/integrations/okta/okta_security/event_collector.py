"""
Event Collector for Okta Security Integration

Real-time collection, preprocessing, and streaming of Okta system logs
with deduplication, enrichment, and buffering capabilities.
"""

import time
import asyncio
import threading
from typing import Dict, List, Callable, Optional, Set
from datetime import datetime, timedelta
from collections import deque
from dataclasses import dataclass, field
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor

import redis
import structlog

from .api_client import OktaSecurityClient
from .exceptions import OktaSecurityError

logger = structlog.get_logger()


@dataclass
class EventBuffer:
    """Buffer for managing event batching and deduplication"""
    events: deque = field(default_factory=deque)
    seen_hashes: Set[str] = field(default_factory=set)
    max_size: int = 10000
    max_age_seconds: int = 3600  # 1 hour
    
    def add_event(self, event: Dict) -> bool:
        """Add event to buffer, return True if new"""
        event_hash = self._hash_event(event)
        
        if event_hash in self.seen_hashes:
            return False  # Duplicate
        
        self.events.append({
            'hash': event_hash,
            'timestamp': datetime.utcnow(),
            'event': event
        })
        
        self.seen_hashes.add(event_hash)
        
        # Clean old events
        self._cleanup()
        
        return True
    
    def _hash_event(self, event: Dict) -> str:
        """Create hash for event deduplication"""
        # Use key fields for hashing
        key_fields = {
            'uuid': event.get('uuid'),
            'published': event.get('published'),
            'eventType': event.get('eventType'),
            'actor': event.get('actor', {}).get('id'),
            'target': [t.get('id') for t in event.get('target', [])]
        }
        
        content = json.dumps(key_fields, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _cleanup(self):
        """Remove old events and maintain buffer size"""
        cutoff_time = datetime.utcnow() - timedelta(seconds=self.max_age_seconds)
        
        # Remove old events
        while self.events and self.events[0]['timestamp'] < cutoff_time:
            old_event = self.events.popleft()
            self.seen_hashes.discard(old_event['hash'])
        
        # Maintain max size
        while len(self.events) > self.max_size:
            old_event = self.events.popleft()
            self.seen_hashes.discard(old_event['hash'])
    
    def get_events(self, max_count: int = None) -> List[Dict]:
        """Get events from buffer"""
        events = [item['event'] for item in list(self.events)]
        
        if max_count:
            events = events[-max_count:]
        
        return events


class EventEnricher:
    """Enrich events with additional context and metadata"""
    
    def __init__(self, okta_client: OktaSecurityClient):
        self.okta_client = okta_client
        self.user_cache = {}
        self.group_cache = {}
        self.app_cache = {}
    
    def enrich_event(self, event: Dict) -> Dict:
        """Enrich event with additional context"""
        enriched = event.copy()
        
        try:
            # Add enrichment timestamp
            enriched['enrichment'] = {
                'timestamp': datetime.utcnow().isoformat(),
                'version': '1.0'
            }
            
            # Enrich actor information
            if 'actor' in event and event['actor'].get('id'):
                actor_id = event['actor']['id']
                actor_info = self._get_user_info(actor_id)
                if actor_info:
                    enriched['actor']['enriched'] = actor_info
            
            # Enrich target information
            if 'target' in event:
                enriched_targets = []
                for target in event['target']:
                    enriched_target = target.copy()
                    
                    if target.get('type') == 'User' and target.get('id'):
                        user_info = self._get_user_info(target['id'])
                        if user_info:
                            enriched_target['enriched'] = user_info
                    
                    elif target.get('type') == 'Group' and target.get('id'):
                        group_info = self._get_group_info(target['id'])
                        if group_info:
                            enriched_target['enriched'] = group_info
                    
                    enriched_targets.append(enriched_target)
                
                enriched['target'] = enriched_targets
            
            # Add geolocation enrichment
            if 'client' in event and 'geographicalContext' in event['client']:
                geo_context = event['client']['geographicalContext']
                enriched['client']['enriched_geo'] = {
                    'country_risk': self._assess_country_risk(geo_context.get('country')),
                    'known_location': self._is_known_location(
                        event.get('actor', {}).get('id'),
                        geo_context
                    )
                }
            
            # Add risk scoring
            enriched['risk_score'] = self._calculate_risk_score(event)
            
        except Exception as e:
            logger.warning("Event enrichment failed", 
                         event_id=event.get('uuid'), 
                         error=str(e))
            
            # Add enrichment error but don't fail
            enriched['enrichment'] = {
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
        
        return enriched
    
    def _get_user_info(self, user_id: str) -> Optional[Dict]:
        """Get cached user information"""
        if user_id in self.user_cache:
            return self.user_cache[user_id]
        
        try:
            user_info = self.okta_client.get_user(user_id)
            
            # Extract relevant fields
            enriched_info = {
                'profile': user_info.get('profile', {}),
                'status': user_info.get('status'),
                'created': user_info.get('created'),
                'lastLogin': user_info.get('lastLogin'),
                'passwordChanged': user_info.get('passwordChanged')
            }
            
            # Cache for 5 minutes
            self.user_cache[user_id] = enriched_info
            
            return enriched_info
            
        except Exception as e:
            logger.warning("Failed to enrich user info", user_id=user_id, error=str(e))
            return None
    
    def _get_group_info(self, group_id: str) -> Optional[Dict]:
        """Get cached group information"""
        if group_id in self.group_cache:
            return self.group_cache[group_id]
        
        try:
            response = self.okta_client._make_request('GET', f'/groups/{group_id}')
            group_info = response.json()
            
            enriched_info = {
                'profile': group_info.get('profile', {}),
                'type': group_info.get('type'),
                'created': group_info.get('created')
            }
            
            self.group_cache[group_id] = enriched_info
            return enriched_info
            
        except Exception as e:
            logger.warning("Failed to enrich group info", group_id=group_id, error=str(e))
            return None
    
    def _assess_country_risk(self, country: str) -> str:
        """Assess risk level based on country"""
        high_risk_countries = {
            'CN', 'RU', 'IR', 'KP', 'BY'  # Example high-risk countries
        }
        
        medium_risk_countries = {
            'PK', 'IN', 'BD', 'VN', 'TH'  # Example medium-risk countries
        }
        
        if country in high_risk_countries:
            return 'HIGH'
        elif country in medium_risk_countries:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _is_known_location(self, user_id: str, geo_context: Dict) -> bool:
        """Check if location is known for user (simplified)"""
        # In production, this would check against historical location data
        # For now, return True for US/CA/GB, False for others
        safe_countries = {'US', 'CA', 'GB', 'AU', 'DE', 'FR'}
        return geo_context.get('country') in safe_countries
    
    def _calculate_risk_score(self, event: Dict) -> int:
        """Calculate risk score (0-100) for event"""
        score = 0
        
        event_type = event.get('eventType', '')
        
        # High-risk event types
        high_risk_events = {
            'user.authentication.auth_via_mfa',
            'user.account.lock',
            'user.session.start',
            'application.user_membership.add',
            'group.user_membership.add'
        }
        
        if event_type in high_risk_events:
            score += 30
        
        # Check for suspicious patterns
        if 'client' in event:
            client = event['client']
            
            # Unknown user agent
            if 'userAgent' in client and 'unknown' in client['userAgent'].lower():
                score += 20
            
            # Geographic risk
            if 'geographicalContext' in client:
                geo = client['geographicalContext']
                risk_level = self._assess_country_risk(geo.get('country'))
                if risk_level == 'HIGH':
                    score += 40
                elif risk_level == 'MEDIUM':
                    score += 20
        
        # Multiple failed attempts
        if event_type.startswith('user.authentication.auth_via') and 'FAILURE' in event.get('outcome', {}).get('result', ''):
            score += 25
        
        return min(score, 100)


class EventCollector:
    """
    Real-time Okta event collection with streaming, buffering, 
    and enrichment capabilities.
    """
    
    def __init__(
        self, 
        okta_client: OktaSecurityClient,
        redis_url: str = "redis://localhost:6379",
        buffer_size: int = 10000,
        poll_interval: int = 30,
        enable_enrichment: bool = True
    ):
        self.okta_client = okta_client
        self.redis_url = redis_url
        self.poll_interval = poll_interval
        self.enable_enrichment = enable_enrichment
        
        # Event processing
        self.buffer = EventBuffer(max_size=buffer_size)
        self.enricher = EventEnricher(okta_client) if enable_enrichment else None
        
        # Redis for state management
        try:
            self.redis_client = redis.from_url(redis_url, decode_responses=True)
            self.redis_client.ping()
            logger.info("Redis connection established")
        except Exception as e:
            logger.warning("Redis not available, using memory state", error=str(e))
            self.redis_client = None
        
        # Streaming state
        self.is_running = False
        self.last_poll_time = None
        self.event_handlers: List[Callable] = []
        
        # Threading
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        logger.info("Event collector initialized", 
                   poll_interval=poll_interval,
                   enrichment_enabled=enable_enrichment)
    
    def add_handler(self, handler: Callable[[Dict], None]):
        """Add event handler callback"""
        self.event_handlers.append(handler)
        logger.info("Event handler added", handler=handler.__name__)
    
    def _get_last_poll_time(self) -> Optional[datetime]:
        """Get last poll timestamp from state"""
        if self.redis_client:
            try:
                timestamp_str = self.redis_client.get("okta_collector:last_poll")
                if timestamp_str:
                    return datetime.fromisoformat(timestamp_str)
            except Exception as e:
                logger.warning("Failed to get last poll time from Redis", error=str(e))
        
        return self.last_poll_time
    
    def _set_last_poll_time(self, timestamp: datetime):
        """Save last poll timestamp to state"""
        self.last_poll_time = timestamp
        
        if self.redis_client:
            try:
                self.redis_client.set(
                    "okta_collector:last_poll", 
                    timestamp.isoformat(),
                    ex=86400  # 24 hour expiry
                )
            except Exception as e:
                logger.warning("Failed to save last poll time to Redis", error=str(e))
    
    def _process_events(self, events: List[Dict]):
        """Process batch of events"""
        processed_count = 0
        
        for event in events:
            try:
                # Check for duplicates
                if not self.buffer.add_event(event):
                    continue  # Skip duplicate
                
                # Enrich event
                if self.enricher:
                    event = self.enricher.enrich_event(event)
                
                # Call handlers
                for handler in self.event_handlers:
                    try:
                        handler(event)
                    except Exception as e:
                        logger.error("Event handler failed", 
                                   handler=handler.__name__, 
                                   error=str(e))
                
                processed_count += 1
                
            except Exception as e:
                logger.error("Event processing failed", 
                           event_id=event.get('uuid'), 
                           error=str(e))
        
        if processed_count > 0:
            logger.info("Events processed", count=processed_count)
    
    def _poll_events(self):
        """Poll for new events from Okta"""
        try:
            since = self._get_last_poll_time()
            if not since:
                # First run - start from 1 hour ago
                since = datetime.utcnow() - timedelta(hours=1)
            
            # Fetch events
            events = self.okta_client.get_system_logs(
                since=since,
                limit=1000
            )
            
            if events:
                logger.debug("Fetched events from Okta", count=len(events))
                
                # Process events in background
                self.executor.submit(self._process_events, events)
                
                # Update last poll time
                latest_time = max(
                    datetime.fromisoformat(event['published'].replace('Z', '+00:00'))
                    for event in events
                )
                self._set_last_poll_time(latest_time)
            
        except Exception as e:
            logger.error("Event polling failed", error=str(e))
    
    def start_streaming(self):
        """Start real-time event streaming"""
        if self.is_running:
            logger.warning("Event collector is already running")
            return
        
        self.is_running = True
        logger.info("Starting event streaming", interval=self.poll_interval)
        
        # Run in background thread
        def stream_worker():
            while self.is_running:
                try:
                    self._poll_events()
                    time.sleep(self.poll_interval)
                except Exception as e:
                    logger.error("Streaming error", error=str(e))
                    time.sleep(60)  # Extended wait on error
        
        stream_thread = threading.Thread(target=stream_worker, daemon=True)
        stream_thread.start()
        
        logger.info("Event streaming started")
    
    def stop_streaming(self):
        """Stop event streaming"""
        if not self.is_running:
            return
        
        self.is_running = False
        logger.info("Event streaming stopped")
    
    def get_buffered_events(self, max_count: int = None) -> List[Dict]:
        """Get events from buffer"""
        return self.buffer.get_events(max_count)
    
    def get_streaming_stats(self) -> Dict:
        """Get streaming statistics"""
        return {
            'is_running': self.is_running,
            'buffer_size': len(self.buffer.events),
            'last_poll_time': self.last_poll_time.isoformat() if self.last_poll_time else None,
            'handler_count': len(self.event_handlers),
            'enrichment_enabled': bool(self.enricher)
        }
    
    def health_check(self) -> Dict:
        """Perform health check"""
        health = {
            'timestamp': datetime.utcnow().isoformat(),
            'streaming_active': self.is_running,
            'okta_connectivity': False,
            'redis_connectivity': False,
            'buffer_health': True
        }
        
        # Test Okta connectivity
        try:
            health_check = self.okta_client.health_check()
            health['okta_connectivity'] = health_check['okta_connectivity']
        except Exception:
            pass
        
        # Test Redis connectivity
        if self.redis_client:
            try:
                self.redis_client.ping()
                health['redis_connectivity'] = True
            except Exception:
                pass
        
        # Check buffer health
        if len(self.buffer.events) >= self.buffer.max_size * 0.9:
            health['buffer_health'] = False
            health['buffer_warning'] = 'Buffer nearly full'
        
        return health