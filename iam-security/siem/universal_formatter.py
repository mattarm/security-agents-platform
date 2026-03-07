"""
Universal Event Formatter for SIEM Integration

SIEM-agnostic event formatting with support for multiple output formats
including CEF, LEEF, JSON, and custom schemas.
"""

import json
import hashlib
import re
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from dataclasses import dataclass, field
from urllib.parse import quote
import ipaddress

import structlog

logger = structlog.get_logger()


@dataclass
class EventMapping:
    """Mapping configuration for event fields"""
    source_field: str
    target_field: str
    data_type: str = 'string'  # string, int, float, datetime, ip, email
    required: bool = False
    default_value: Any = None
    transform_function: Optional[str] = None


@dataclass
class SchemaDefinition:
    """Schema definition for event format"""
    name: str
    version: str
    format_type: str  # json, cef, leef, xml
    field_mappings: List[EventMapping] = field(default_factory=list)
    required_fields: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class UniversalFormatter:
    """
    Universal event formatter supporting multiple SIEM platforms and formats.
    
    Features:
    - Multiple output formats (JSON, CEF, LEEF, XML)
    - Field mapping and transformation
    - Data type validation and conversion
    - Schema validation
    - Event enrichment and normalization
    """
    
    def __init__(self):
        self.schemas: Dict[str, SchemaDefinition] = {}
        self.field_transforms = {
            'normalize_ip': self._normalize_ip_address,
            'extract_domain': self._extract_domain,
            'hash_pii': self._hash_pii,
            'normalize_timestamp': self._normalize_timestamp,
            'extract_user_agent': self._extract_user_agent_info,
            'severity_mapping': self._map_severity,
            'outcome_mapping': self._map_outcome
        }
        
        # Load default schemas
        self._load_default_schemas()
        
        logger.info("Universal formatter initialized", schemas=len(self.schemas))
    
    def _load_default_schemas(self):
        """Load default schema definitions for common SIEM platforms"""
        
        # JSON Schema for structured logging
        self.schemas['json_structured'] = SchemaDefinition(
            name="json_structured",
            version="1.0",
            format_type="json",
            field_mappings=[
                EventMapping("uuid", "event_id", required=True),
                EventMapping("published", "timestamp", "datetime", required=True),
                EventMapping("eventType", "event_type", required=True),
                EventMapping("displayMessage", "message"),
                EventMapping("severity", "severity"),
                EventMapping("outcome.result", "outcome"),
                EventMapping("actor.id", "actor_user_id"),
                EventMapping("actor.displayName", "actor_user_name"),
                EventMapping("actor.type", "actor_type"),
                EventMapping("client.ipAddress", "source_ip", "ip"),
                EventMapping("client.userAgent.rawUserAgent", "user_agent"),
                EventMapping("client.geographicalContext.country", "source_country"),
                EventMapping("client.geographicalContext.city", "source_city"),
                EventMapping("debugContext.debugData.requestId", "request_id"),
                EventMapping("authenticationContext.authenticationProvider", "auth_provider"),
                EventMapping("securityContext.asNumber", "asn", "int"),
                EventMapping("securityContext.asOrg", "as_org"),
                EventMapping("securityContext.isProxy", "is_proxy", "bool")
            ],
            required_fields=["event_id", "timestamp", "event_type"]
        )
        
        # CEF Format for traditional SIEMs
        self.schemas['cef'] = SchemaDefinition(
            name="cef",
            version="1.0",
            format_type="cef",
            field_mappings=[
                EventMapping("eventType", "name", required=True),
                EventMapping("severity", "severity", transform_function="severity_mapping"),
                EventMapping("uuid", "externalId"),
                EventMapping("published", "rt", "datetime"),
                EventMapping("client.ipAddress", "src", "ip"),
                EventMapping("actor.displayName", "suser"),
                EventMapping("outcome.result", "outcome", transform_function="outcome_mapping"),
                EventMapping("displayMessage", "msg"),
                EventMapping("client.userAgent.rawUserAgent", "requestClientApplication"),
                EventMapping("client.geographicalContext.country", "cs1"),
                EventMapping("authenticationContext.authenticationProvider", "cs2")
            ],
            metadata={
                'vendor': 'Okta',
                'product': 'Identity Management',
                'version': '1.0'
            }
        )
        
        # LEEF Format for IBM QRadar
        self.schemas['leef'] = SchemaDefinition(
            name="leef",
            version="2.0", 
            format_type="leef",
            field_mappings=[
                EventMapping("eventType", "cat", required=True),
                EventMapping("published", "devTime", "datetime"),
                EventMapping("uuid", "identSrc"),
                EventMapping("severity", "sev", transform_function="severity_mapping"),
                EventMapping("client.ipAddress", "srcIP", "ip"),
                EventMapping("actor.displayName", "usrName"),
                EventMapping("outcome.result", "result"),
                EventMapping("displayMessage", "msg"),
                EventMapping("client.geographicalContext.country", "srcGeoCountry"),
                EventMapping("authenticationContext.authenticationProvider", "authMethod")
            ],
            metadata={
                'vendor': 'Okta',
                'product': 'Okta_Identity',
                'version': '1.0',
                'eventId': 'OktaEvent'
            }
        )
        
        # Splunk-optimized JSON
        self.schemas['splunk_json'] = SchemaDefinition(
            name="splunk_json",
            version="1.0",
            format_type="json",
            field_mappings=[
                EventMapping("published", "_time", "datetime", required=True),
                EventMapping("eventType", "event_type", required=True),
                EventMapping("uuid", "event_id"),
                EventMapping("severity", "severity"),
                EventMapping("displayMessage", "message"),
                EventMapping("outcome.result", "action"),
                EventMapping("actor.id", "user_id"),
                EventMapping("actor.displayName", "user_name"),
                EventMapping("client.ipAddress", "src_ip", "ip"),
                EventMapping("client.userAgent.rawUserAgent", "http_user_agent"),
                EventMapping("client.geographicalContext.country", "src_country"),
                EventMapping("authenticationContext.authenticationProvider", "auth_method"),
                EventMapping("securityContext.isProxy", "is_proxy", "bool")
            ],
            metadata={
                'sourcetype': 'okta:identity:security',
                'index': 'security'
            }
        )
    
    def add_schema(self, schema: SchemaDefinition):
        """Add custom schema definition"""
        self.schemas[schema.name] = schema
        logger.info("Schema added", schema=schema.name, format=schema.format_type)
    
    def format_event(
        self, 
        event: Dict, 
        schema_name: str,
        include_raw: bool = False,
        enrich: bool = True
    ) -> Union[str, Dict]:
        """
        Format event according to specified schema
        
        Args:
            event: Raw Okta event
            schema_name: Schema to use for formatting
            include_raw: Include raw event in output
            enrich: Apply enrichment transformations
            
        Returns:
            Formatted event as string or dict
        """
        
        if schema_name not in self.schemas:
            raise ValueError(f"Unknown schema: {schema_name}")
        
        schema = self.schemas[schema_name]
        
        try:
            # Apply enrichment
            if enrich:
                event = self._enrich_event(event)
            
            # Map fields according to schema
            mapped_event = self._map_event_fields(event, schema)
            
            # Validate required fields
            self._validate_required_fields(mapped_event, schema)
            
            # Format according to output type
            if schema.format_type == 'json':
                formatted = self._format_json(mapped_event, schema, include_raw, event)
            elif schema.format_type == 'cef':
                formatted = self._format_cef(mapped_event, schema)
            elif schema.format_type == 'leef':
                formatted = self._format_leef(mapped_event, schema)
            elif schema.format_type == 'xml':
                formatted = self._format_xml(mapped_event, schema)
            else:
                raise ValueError(f"Unsupported format type: {schema.format_type}")
            
            return formatted
            
        except Exception as e:
            logger.error("Event formatting failed", 
                        schema=schema_name, 
                        event_id=event.get('uuid'),
                        error=str(e))
            raise
    
    def format_events_batch(
        self,
        events: List[Dict],
        schema_name: str,
        batch_format: str = 'newline_delimited',
        **kwargs
    ) -> str:
        """
        Format multiple events in batch
        
        Args:
            events: List of Okta events
            schema_name: Schema to use
            batch_format: How to combine events (newline_delimited, json_array, etc.)
            
        Returns:
            Formatted batch as string
        """
        
        formatted_events = []
        
        for event in events:
            try:
                formatted = self.format_event(event, schema_name, **kwargs)
                formatted_events.append(formatted)
            except Exception as e:
                logger.warning("Skipping event due to formatting error", 
                              event_id=event.get('uuid'),
                              error=str(e))
                continue
        
        # Combine according to batch format
        if batch_format == 'newline_delimited':
            return '\\n'.join(
                json.dumps(event) if isinstance(event, dict) else event
                for event in formatted_events
            )
        elif batch_format == 'json_array':
            return json.dumps(formatted_events)
        elif batch_format == 'space_delimited':
            return ' '.join(
                json.dumps(event) if isinstance(event, dict) else event
                for event in formatted_events
            )
        else:
            raise ValueError(f"Unsupported batch format: {batch_format}")
    
    def _enrich_event(self, event: Dict) -> Dict:
        """Apply enrichment to event"""
        enriched = event.copy()
        
        # Add processing metadata
        enriched['_processing'] = {
            'ingestion_time': datetime.utcnow().isoformat(),
            'processor': 'universal_formatter',
            'version': '1.0'
        }
        
        # Normalize common fields
        if 'published' in enriched:
            enriched['_normalized_timestamp'] = self._normalize_timestamp(enriched['published'])
        
        # Extract and normalize IP address
        client = enriched.get('client', {})
        if client.get('ipAddress'):
            enriched['_normalized_ip'] = self._normalize_ip_address(client['ipAddress'])
            enriched['_ip_info'] = self._analyze_ip_address(client['ipAddress'])
        
        # Analyze user agent
        user_agent = client.get('userAgent', {}).get('rawUserAgent')
        if user_agent:
            enriched['_user_agent_info'] = self._extract_user_agent_info(user_agent)
        
        # Add event hash for deduplication
        enriched['_event_hash'] = self._generate_event_hash(enriched)
        
        return enriched
    
    def _map_event_fields(self, event: Dict, schema: SchemaDefinition) -> Dict:
        """Map event fields according to schema"""
        mapped = {}
        
        for mapping in schema.field_mappings:
            try:
                # Extract source value
                source_value = self._extract_nested_value(event, mapping.source_field)
                
                # Apply default if value is None
                if source_value is None:
                    if mapping.default_value is not None:
                        source_value = mapping.default_value
                    elif mapping.required:
                        logger.warning("Missing required field", 
                                     field=mapping.source_field,
                                     event_id=event.get('uuid'))
                        continue
                    else:
                        continue
                
                # Apply transformations
                if mapping.transform_function and mapping.transform_function in self.field_transforms:
                    transform_func = self.field_transforms[mapping.transform_function]
                    source_value = transform_func(source_value)
                
                # Convert data type
                converted_value = self._convert_data_type(source_value, mapping.data_type)
                
                # Set target field
                mapped[mapping.target_field] = converted_value
                
            except Exception as e:
                logger.warning("Field mapping failed",
                             source_field=mapping.source_field,
                             target_field=mapping.target_field,
                             error=str(e))
                continue
        
        return mapped
    
    def _validate_required_fields(self, mapped_event: Dict, schema: SchemaDefinition):
        """Validate that all required fields are present"""
        missing_fields = []
        
        for required_field in schema.required_fields:
            if required_field not in mapped_event or mapped_event[required_field] is None:
                missing_fields.append(required_field)
        
        if missing_fields:
            raise ValueError(f"Missing required fields: {missing_fields}")
    
    def _format_json(self, mapped_event: Dict, schema: SchemaDefinition, include_raw: bool, raw_event: Dict) -> Dict:
        """Format as JSON"""
        output = mapped_event.copy()
        
        # Add metadata
        if schema.metadata:
            output.update(schema.metadata)
        
        # Include raw event if requested
        if include_raw:
            output['_raw_event'] = raw_event
        
        return output
    
    def _format_cef(self, mapped_event: Dict, schema: SchemaDefinition) -> str:
        """Format as CEF (Common Event Format)"""
        metadata = schema.metadata
        
        # CEF Header
        header_parts = [
            'CEF:0',  # Version
            metadata.get('vendor', 'Unknown'),
            metadata.get('product', 'Unknown'), 
            metadata.get('version', '1.0'),
            mapped_event.get('externalId', 'unknown'),
            mapped_event.get('name', 'Unknown Event'),
            str(mapped_event.get('severity', 5))
        ]
        
        header = '|'.join(self._escape_cef_value(part) for part in header_parts)
        
        # CEF Extensions
        extensions = []
        for key, value in mapped_event.items():
            if key not in ['externalId', 'name', 'severity'] and value is not None:
                extensions.append(f"{key}={self._escape_cef_value(str(value))}")
        
        extension_str = ' '.join(extensions)
        
        return f"{header} {extension_str}"
    
    def _format_leef(self, mapped_event: Dict, schema: SchemaDefinition) -> str:
        """Format as LEEF (Log Event Extended Format)"""
        metadata = schema.metadata
        
        # LEEF Header
        header_parts = [
            f"LEEF:{schema.version}",
            metadata.get('vendor', 'Unknown'),
            metadata.get('product', 'Unknown'),
            metadata.get('version', '1.0'),
            metadata.get('eventId', 'Event'),
            '|'  # Delimiter
        ]
        
        header = '|'.join(header_parts[:-1]) + header_parts[-1]
        
        # LEEF Fields
        fields = []
        for key, value in mapped_event.items():
            if value is not None:
                fields.append(f"{key}={self._escape_leef_value(str(value))}")
        
        fields_str = '\\t'.join(fields)
        
        return f"{header}{fields_str}"
    
    def _format_xml(self, mapped_event: Dict, schema: SchemaDefinition) -> str:
        """Format as XML"""
        root_element = schema.metadata.get('root_element', 'event')
        
        xml_parts = [f'<{root_element}>']
        
        for key, value in mapped_event.items():
            if value is not None:
                escaped_value = self._escape_xml_value(str(value))
                xml_parts.append(f'  <{key}>{escaped_value}</{key}>')
        
        xml_parts.append(f'</{root_element}>')
        
        return '\\n'.join(xml_parts)
    
    def _extract_nested_value(self, data: Dict, field_path: str) -> Any:
        """Extract value from nested dictionary using dot notation"""
        try:
            value = data
            for part in field_path.split('.'):
                if isinstance(value, dict):
                    value = value.get(part)
                elif isinstance(value, list) and part.isdigit():
                    idx = int(part)
                    value = value[idx] if 0 <= idx < len(value) else None
                else:
                    return None
            return value
        except (KeyError, IndexError, TypeError):
            return None
    
    def _convert_data_type(self, value: Any, data_type: str) -> Any:
        """Convert value to specified data type"""
        if value is None:
            return None
        
        try:
            if data_type == 'string':
                return str(value)
            elif data_type == 'int':
                return int(float(value))  # Handle string numbers
            elif data_type == 'float':
                return float(value)
            elif data_type == 'bool':
                if isinstance(value, bool):
                    return value
                if isinstance(value, str):
                    return value.lower() in ['true', '1', 'yes', 'on']
                return bool(value)
            elif data_type == 'datetime':
                if isinstance(value, str):
                    # Parse ISO format datetime
                    return datetime.fromisoformat(value.replace('Z', '+00:00'))
                return value
            elif data_type == 'ip':
                return self._normalize_ip_address(str(value))
            elif data_type == 'email':
                return str(value).lower().strip()
            else:
                return value
        except Exception:
            # Return original value if conversion fails
            return value
    
    def _normalize_ip_address(self, ip_str: str) -> str:
        """Normalize IP address format"""
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            return str(ip)
        except ValueError:
            return ip_str
    
    def _analyze_ip_address(self, ip_str: str) -> Dict:
        """Analyze IP address properties"""
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            return {
                'version': ip.version,
                'is_private': ip.is_private,
                'is_multicast': ip.is_multicast,
                'is_reserved': ip.is_reserved,
                'is_loopback': ip.is_loopback
            }
        except ValueError:
            return {'version': 'unknown'}
    
    def _extract_domain(self, email_or_url: str) -> str:
        """Extract domain from email or URL"""
        if '@' in email_or_url:
            return email_or_url.split('@')[-1]
        elif '//' in email_or_url:
            return email_or_url.split('//')[1].split('/')[0]
        return email_or_url
    
    def _hash_pii(self, value: str) -> str:
        """Hash personally identifiable information"""
        return hashlib.sha256(str(value).encode()).hexdigest()[:16]
    
    def _normalize_timestamp(self, timestamp_str: str) -> str:
        """Normalize timestamp to ISO format"""
        try:
            # Parse Okta timestamp format
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return dt.isoformat()
        except ValueError:
            return timestamp_str
    
    def _extract_user_agent_info(self, user_agent: str) -> Dict:
        """Extract information from user agent string"""
        if not user_agent:
            return {}
        
        info = {'raw': user_agent}
        
        # Basic browser detection
        browsers = {
            'Chrome': r'Chrome/([\\d.]+)',
            'Firefox': r'Firefox/([\\d.]+)',
            'Safari': r'Safari/([\\d.]+)',
            'Edge': r'Edge/([\\d.]+)',
            'Opera': r'Opera/([\\d.]+)'
        }
        
        for browser, pattern in browsers.items():
            match = re.search(pattern, user_agent)
            if match:
                info['browser'] = browser
                info['browser_version'] = match.group(1)
                break
        
        # Operating system detection
        if 'Windows' in user_agent:
            info['os'] = 'Windows'
        elif 'Mac OS' in user_agent:
            info['os'] = 'macOS'
        elif 'Linux' in user_agent:
            info['os'] = 'Linux'
        elif 'Android' in user_agent:
            info['os'] = 'Android'
        elif 'iOS' in user_agent:
            info['os'] = 'iOS'
        
        # Device type detection
        if 'Mobile' in user_agent or 'Android' in user_agent:
            info['device_type'] = 'mobile'
        elif 'Tablet' in user_agent or 'iPad' in user_agent:
            info['device_type'] = 'tablet'
        else:
            info['device_type'] = 'desktop'
        
        return info
    
    def _map_severity(self, severity: str) -> int:
        """Map Okta severity to numeric value"""
        severity_map = {
            'DEBUG': 1,
            'INFO': 2,
            'WARN': 5,
            'ERROR': 8,
            'FATAL': 10
        }
        return severity_map.get(str(severity).upper(), 5)
    
    def _map_outcome(self, outcome: str) -> str:
        """Map Okta outcome to standardized value"""
        outcome_map = {
            'SUCCESS': 'success',
            'FAILURE': 'failure',
            'SKIPPED': 'skipped',
            'ALLOW': 'allowed',
            'DENY': 'denied',
            'CHALLENGE': 'challenged'
        }
        return outcome_map.get(str(outcome).upper(), outcome.lower() if outcome else 'unknown')
    
    def _generate_event_hash(self, event: Dict) -> str:
        """Generate hash for event deduplication"""
        # Use key fields for hash generation
        key_fields = {
            'uuid': event.get('uuid'),
            'published': event.get('published'),
            'eventType': event.get('eventType'),
            'actor_id': event.get('actor', {}).get('id') if event.get('actor') else None
        }
        
        content = json.dumps(key_fields, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _escape_cef_value(self, value: str) -> str:
        """Escape value for CEF format"""
        if not value:
            return ''
        
        # Escape special characters
        value = value.replace('\\\\', '\\\\\\\\')  # Escape backslashes
        value = value.replace('|', '\\\\|')        # Escape pipes
        value = value.replace('=', '\\\\=')        # Escape equals
        value = value.replace('\\n', '\\\\n')     # Escape newlines
        value = value.replace('\\r', '\\\\r')     # Escape carriage returns
        
        return value
    
    def _escape_leef_value(self, value: str) -> str:
        """Escape value for LEEF format"""
        if not value:
            return ''
        
        # Escape special characters
        value = value.replace('\\\\', '\\\\\\\\')  # Escape backslashes
        value = value.replace('|', '\\\\|')        # Escape pipes
        value = value.replace('=', '\\\\=')        # Escape equals
        value = value.replace('\\t', '\\\\t')     # Escape tabs
        value = value.replace('\\n', '\\\\n')     # Escape newlines
        value = value.replace('\\r', '\\\\r')     # Escape carriage returns
        
        return value
    
    def _escape_xml_value(self, value: str) -> str:
        """Escape value for XML format"""
        if not value:
            return ''
        
        # Escape XML special characters
        value = value.replace('&', '&amp;')
        value = value.replace('<', '&lt;')
        value = value.replace('>', '&gt;')
        value = value.replace('"', '&quot;')
        value = value.replace("'", '&#39;')
        
        return value
    
    def get_schema_info(self, schema_name: str = None) -> Dict:
        """Get schema information"""
        if schema_name:
            if schema_name not in self.schemas:
                return {}
            
            schema = self.schemas[schema_name]
            return {
                'name': schema.name,
                'version': schema.version,
                'format_type': schema.format_type,
                'field_count': len(schema.field_mappings),
                'required_fields': schema.required_fields,
                'metadata': schema.metadata
            }
        else:
            return {
                'available_schemas': list(self.schemas.keys()),
                'total_schemas': len(self.schemas),
                'supported_formats': list(set(s.format_type for s in self.schemas.values()))
            }
    
    def validate_event(self, event: Dict, schema_name: str) -> Dict:
        """Validate event against schema without formatting"""
        if schema_name not in self.schemas:
            return {'valid': False, 'error': f'Unknown schema: {schema_name}'}
        
        try:
            schema = self.schemas[schema_name]
            mapped_event = self._map_event_fields(event, schema)
            self._validate_required_fields(mapped_event, schema)
            
            return {
                'valid': True,
                'mapped_fields': len(mapped_event),
                'missing_optional': len(schema.field_mappings) - len(mapped_event)
            }
            
        except Exception as e:
            return {'valid': False, 'error': str(e)}