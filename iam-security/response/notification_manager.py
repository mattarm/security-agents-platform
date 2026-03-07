"""
Notification Manager for Security Incidents

Multi-channel notification system for security alerts, action updates,
and incident response coordination.
"""

import json
import smtplib
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import requests
from collections import defaultdict

import structlog

from ..analytics.threat_detector import ThreatAlert
from .action_executor import ResponseAction

logger = structlog.get_logger()


@dataclass
class NotificationChannel:
    """Notification channel configuration"""
    name: str
    type: str  # email, slack, teams, webhook, sms
    enabled: bool = True
    config: Dict = None
    severity_filter: List[str] = None  # None = all severities


@dataclass
class NotificationTemplate:
    """Notification message template"""
    name: str
    channel_type: str
    subject_template: str
    body_template: str
    format_type: str = "text"  # text, html, markdown


class NotificationManager:
    """
    Multi-channel notification management for security incidents.
    
    Supports:
    - Email notifications (SMTP)
    - Slack integration
    - Microsoft Teams webhooks
    - Custom webhooks
    - SMS notifications (via webhook)
    - Template-based messaging
    - Severity-based routing
    - Rate limiting and deduplication
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.channels: Dict[str, NotificationChannel] = {}
        self.templates: Dict[str, NotificationTemplate] = {}
        
        # Notification state
        self.sent_notifications = {}
        self.rate_limits = defaultdict(list)  # channel -> list of timestamps
        self.deduplication_cache = {}
        
        # Load configuration
        self._load_channels()
        self._load_templates()
        
        logger.info("Notification manager initialized", 
                   channels=len(self.channels),
                   templates=len(self.templates))
    
    def _load_channels(self):
        """Load notification channels from configuration"""
        channels_config = self.config.get('channels', {})
        
        # Email channel
        if 'email' in channels_config:
            email_config = channels_config['email']
            self.channels['email'] = NotificationChannel(
                name="email",
                type="email",
                enabled=email_config.get('enabled', True),
                config=email_config,
                severity_filter=email_config.get('severity_filter')
            )
        
        # Slack channel
        if 'slack' in channels_config:
            slack_config = channels_config['slack']
            self.channels['slack'] = NotificationChannel(
                name="slack",
                type="slack",
                enabled=slack_config.get('enabled', True),
                config=slack_config,
                severity_filter=slack_config.get('severity_filter')
            )
        
        # Microsoft Teams channel
        if 'teams' in channels_config:
            teams_config = channels_config['teams']
            self.channels['teams'] = NotificationChannel(
                name="teams",
                type="teams",
                enabled=teams_config.get('enabled', True),
                config=teams_config,
                severity_filter=teams_config.get('severity_filter')
            )
        
        # Custom webhooks
        webhooks_config = channels_config.get('webhooks', {})
        for webhook_name, webhook_config in webhooks_config.items():
            self.channels[webhook_name] = NotificationChannel(
                name=webhook_name,
                type="webhook",
                enabled=webhook_config.get('enabled', True),
                config=webhook_config,
                severity_filter=webhook_config.get('severity_filter')
            )
    
    def _load_templates(self):
        """Load notification templates"""
        
        # Email templates
        self.templates['threat_alert_email'] = NotificationTemplate(
            name="threat_alert_email",
            channel_type="email",
            subject_template="🚨 Security Alert: {alert_type} - {severity}",
            body_template="""
Security Alert Detected

Alert ID: {alert_id}
Threat Type: {alert_type}
Severity: {severity}
Confidence: {confidence}%

Description:
{description}

Affected Users:
{affected_users}

Indicators:
{indicators}

Timestamp: {timestamp}

Recommended Actions:
{recommended_actions}

Please investigate immediately and take appropriate action.

This is an automated security notification.
            """,
            format_type="text"
        )
        
        self.templates['action_completed_email'] = NotificationTemplate(
            name="action_completed_email",
            channel_type="email",
            subject_template="✅ Security Action Completed: {action_type}",
            body_template="""
Security Response Action Completed

Action ID: {action_id}
Action Type: {action_type}
Description: {description}
Status: {status}

Target Entities:
{target_entities}

Execution Details:
- Executed At: {executed_at}
- Executed By: {executed_by}
- Duration: {duration}

Result:
{result}

This action was triggered by: {trigger_source}

This is an automated security notification.
            """,
            format_type="text"
        )
        
        # Slack templates
        self.templates['threat_alert_slack'] = NotificationTemplate(
            name="threat_alert_slack",
            channel_type="slack",
            subject_template="",  # Slack uses blocks, not subjects
            body_template="""{
    "text": "Security Alert: {alert_type}",
    "blocks": [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🚨 Security Alert: {alert_type}"
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*Alert ID:*\\n{alert_id}"
                },
                {
                    "type": "mrkdwn",
                    "text": "*Severity:*\\n{severity}"
                },
                {
                    "type": "mrkdwn",
                    "text": "*Confidence:*\\n{confidence}%"
                },
                {
                    "type": "mrkdwn",
                    "text": "*Affected Users:*\\n{affected_users}"
                }
            ]
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Description:*\\n{description}"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Indicators:*\\n{indicators}"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Recommended Actions:*\\n{recommended_actions}"
            }
        }
    ]
}""",
            format_type="json"
        )
        
        # Teams templates
        self.templates['threat_alert_teams'] = NotificationTemplate(
            name="threat_alert_teams",
            channel_type="teams",
            subject_template="Security Alert",
            body_template="""{
    "@type": "MessageCard",
    "@context": "https://schema.org/extensions",
    "summary": "Security Alert: {alert_type}",
    "themeColor": "{color}",
    "sections": [
        {
            "activityTitle": "🚨 Security Alert Detected",
            "activitySubtitle": "{alert_type} - {severity}",
            "facts": [
                {
                    "name": "Alert ID",
                    "value": "{alert_id}"
                },
                {
                    "name": "Threat Type",
                    "value": "{alert_type}"
                },
                {
                    "name": "Severity",
                    "value": "{severity}"
                },
                {
                    "name": "Confidence",
                    "value": "{confidence}%"
                },
                {
                    "name": "Affected Users",
                    "value": "{affected_users}"
                },
                {
                    "name": "Timestamp",
                    "value": "{timestamp}"
                }
            ],
            "text": "{description}"
        }
    ]
}""",
            format_type="json"
        )
    
    def send_threat_alert(
        self, 
        alert: ThreatAlert, 
        channels: List[str] = None,
        override_recipients: Dict[str, List[str]] = None
    ) -> Dict[str, bool]:
        """
        Send threat alert notification
        
        Args:
            alert: ThreatAlert object
            channels: List of channel names to send to (None = all enabled)
            override_recipients: Override recipients for specific channels
            
        Returns:
            Dict mapping channel names to success status
        """
        
        # Check for duplicate alerts
        alert_key = f"alert_{alert.alert_id}"
        if self._is_duplicate_notification(alert_key):
            logger.info("Skipping duplicate alert notification", alert_id=alert.alert_id)
            return {}
        
        # Prepare template variables
        template_vars = {
            'alert_id': alert.alert_id,
            'alert_type': alert.threat_type,
            'severity': alert.severity,
            'confidence': int(alert.confidence * 100),
            'description': alert.description,
            'affected_users': ', '.join(alert.affected_users) or 'None',
            'indicators': '\\n'.join(f"• {indicator}" for indicator in alert.indicators),
            'recommended_actions': '\\n'.join(f"• {action}" for action in alert.recommended_actions),
            'timestamp': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'color': self._get_severity_color(alert.severity)
        }
        
        # Determine target channels
        target_channels = channels or [name for name, ch in self.channels.items() 
                                     if ch.enabled and self._severity_matches(ch, alert.severity)]
        
        results = {}
        
        for channel_name in target_channels:
            if channel_name not in self.channels:
                logger.warning("Unknown notification channel", channel=channel_name)
                continue
            
            channel = self.channels[channel_name]
            
            # Check rate limits
            if self._is_rate_limited(channel_name):
                logger.warning("Rate limit exceeded for channel", channel=channel_name)
                results[channel_name] = False
                continue
            
            try:
                # Get template for channel type
                template_name = f"threat_alert_{channel.type}"
                if template_name not in self.templates:
                    logger.warning("No template for channel type", 
                                 channel=channel_name, 
                                 type=channel.type)
                    continue
                
                template = self.templates[template_name]
                
                # Send notification
                success = self._send_notification(
                    channel=channel,
                    template=template,
                    template_vars=template_vars,
                    recipients=override_recipients.get(channel_name) if override_recipients else None
                )
                
                results[channel_name] = success
                
                if success:
                    self._update_rate_limit(channel_name)
                    self._mark_notification_sent(alert_key)
                
            except Exception as e:
                logger.error("Failed to send alert notification", 
                           channel=channel_name, 
                           alert_id=alert.alert_id,
                           error=str(e))
                results[channel_name] = False
        
        return results
    
    def send_action_notification(
        self, 
        action: ResponseAction, 
        event_type: str,  # completed, failed, approved, etc.
        channels: List[str] = None
    ) -> Dict[str, bool]:
        """
        Send action status notification
        
        Args:
            action: ResponseAction object
            event_type: Type of event (completed, failed, approved, etc.)
            channels: List of channel names
            
        Returns:
            Dict mapping channel names to success status
        """
        
        # Prepare template variables
        template_vars = {
            'action_id': action.action_id,
            'action_type': action.action_type,
            'description': action.description,
            'status': action.status.value,
            'target_entities': self._format_target_entities(action.target_entities),
            'executed_at': action.executed_at.strftime('%Y-%m-%d %H:%M:%S UTC') if action.executed_at else 'N/A',
            'executed_by': action.approved_by or 'system',
            'duration': self._calculate_duration(action),
            'result': json.dumps(action.execution_result, indent=2) if action.execution_result else 'N/A',
            'trigger_source': action.triggered_by_alert or action.triggered_by_rule or 'Manual',
            'error_message': action.error_message or 'None'
        }
        
        # Determine target channels (only email for action notifications by default)
        target_channels = channels or ['email']
        
        results = {}
        
        for channel_name in target_channels:
            if channel_name not in self.channels:
                continue
            
            channel = self.channels[channel_name]
            
            # Check rate limits
            if self._is_rate_limited(channel_name):
                continue
            
            try:
                # Get template
                template_name = f"action_{event_type}_{channel.type}"
                if template_name not in self.templates:
                    # Fallback to generic action template
                    template_name = f"action_completed_{channel.type}"
                
                if template_name not in self.templates:
                    continue
                
                template = self.templates[template_name]
                
                # Send notification
                success = self._send_notification(
                    channel=channel,
                    template=template,
                    template_vars=template_vars
                )
                
                results[channel_name] = success
                
                if success:
                    self._update_rate_limit(channel_name)
                
            except Exception as e:
                logger.error("Failed to send action notification",
                           channel=channel_name,
                           action_id=action.action_id,
                           error=str(e))
                results[channel_name] = False
        
        return results
    
    def send_notification(
        self, 
        recipient: str, 
        message: str, 
        severity: str = 'INFO',
        alert_id: str = None
    ) -> Dict[str, Any]:
        """
        Send general notification
        
        Args:
            recipient: Recipient (email, channel, etc.)
            message: Message content
            severity: Message severity
            alert_id: Optional alert ID for context
            
        Returns:
            Dict with notification result
        """
        
        try:
            # Determine channel based on recipient format
            if '@' in recipient:
                # Email address
                success = self._send_email_direct(
                    to_address=recipient,
                    subject=f"Security Notification - {severity}",
                    body=message
                )
                return {'status': 'success' if success else 'failed', 'recipient': recipient}
            
            else:
                # Try to find matching channel
                if recipient in self.channels:
                    channel = self.channels[recipient]
                    template = NotificationTemplate(
                        name="direct_message",
                        channel_type=channel.type,
                        subject_template=f"Security Notification - {severity}",
                        body_template=message,
                        format_type="text"
                    )
                    
                    success = self._send_notification(
                        channel=channel,
                        template=template,
                        template_vars={}
                    )
                    
                    return {'status': 'success' if success else 'failed', 'channel': recipient}
                
                else:
                    return {'status': 'failed', 'error': 'Unknown recipient type'}
                    
        except Exception as e:
            logger.error("Failed to send general notification", 
                        recipient=recipient, 
                        error=str(e))
            return {'status': 'failed', 'error': str(e)}
    
    def _send_notification(
        self,
        channel: NotificationChannel,
        template: NotificationTemplate,
        template_vars: Dict,
        recipients: List[str] = None
    ) -> bool:
        """Send notification via specific channel"""
        
        try:
            # Format message from template
            subject = template.subject_template.format(**template_vars)
            body = template.body_template.format(**template_vars)
            
            if channel.type == 'email':
                return self._send_email(channel, subject, body, recipients)
            elif channel.type == 'slack':
                return self._send_slack(channel, json.loads(body))
            elif channel.type == 'teams':
                return self._send_teams(channel, json.loads(body))
            elif channel.type == 'webhook':
                return self._send_webhook(channel, subject, body, template_vars)
            else:
                logger.warning("Unsupported channel type", type=channel.type)
                return False
                
        except Exception as e:
            logger.error("Notification sending failed", 
                        channel=channel.name, 
                        error=str(e))
            return False
    
    def _send_email(
        self, 
        channel: NotificationChannel, 
        subject: str, 
        body: str,
        recipients: List[str] = None
    ) -> bool:
        """Send email notification"""
        try:
            config = channel.config
            
            # SMTP configuration
            smtp_server = config.get('smtp_server', 'localhost')
            smtp_port = config.get('smtp_port', 587)
            username = config.get('username')
            password = config.get('password')
            use_tls = config.get('use_tls', True)
            from_address = config.get('from_address', 'security@company.com')
            
            # Recipients
            to_addresses = recipients or config.get('to_addresses', [])
            if isinstance(to_addresses, str):
                to_addresses = [to_addresses]
            
            if not to_addresses:
                logger.warning("No email recipients configured")
                return False
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = from_address
            msg['To'] = ', '.join(to_addresses)
            msg['Subject'] = subject
            
            # Add body
            msg.attach(MIMEText(body, 'plain'))
            
            # Connect and send
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                if use_tls:
                    server.starttls()
                
                if username and password:
                    server.login(username, password)
                
                text = msg.as_string()
                server.sendmail(from_address, to_addresses, text)
            
            logger.info("Email notification sent", 
                       recipients=to_addresses, 
                       subject=subject)
            return True
            
        except Exception as e:
            logger.error("Email sending failed", error=str(e))
            return False
    
    def _send_email_direct(self, to_address: str, subject: str, body: str) -> bool:
        """Send email directly (using default email channel)"""
        email_channel = self.channels.get('email')
        if not email_channel:
            logger.warning("No email channel configured for direct sending")
            return False
        
        return self._send_email(email_channel, subject, body, [to_address])
    
    def _send_slack(self, channel: NotificationChannel, payload: Dict) -> bool:
        """Send Slack notification"""
        try:
            config = channel.config
            webhook_url = config.get('webhook_url')
            
            if not webhook_url:
                logger.warning("No Slack webhook URL configured")
                return False
            
            # Send webhook
            response = requests.post(webhook_url, json=payload, timeout=30)
            response.raise_for_status()
            
            logger.info("Slack notification sent", channel=channel.name)
            return True
            
        except Exception as e:
            logger.error("Slack notification failed", error=str(e))
            return False
    
    def _send_teams(self, channel: NotificationChannel, payload: Dict) -> bool:
        """Send Microsoft Teams notification"""
        try:
            config = channel.config
            webhook_url = config.get('webhook_url')
            
            if not webhook_url:
                logger.warning("No Teams webhook URL configured")
                return False
            
            # Send webhook
            response = requests.post(webhook_url, json=payload, timeout=30)
            response.raise_for_status()
            
            logger.info("Teams notification sent", channel=channel.name)
            return True
            
        except Exception as e:
            logger.error("Teams notification failed", error=str(e))
            return False
    
    def _send_webhook(
        self, 
        channel: NotificationChannel, 
        subject: str, 
        body: str,
        template_vars: Dict
    ) -> bool:
        """Send custom webhook notification"""
        try:
            config = channel.config
            webhook_url = config.get('webhook_url')
            
            if not webhook_url:
                logger.warning("No webhook URL configured", channel=channel.name)
                return False
            
            # Build webhook payload
            payload = {
                'subject': subject,
                'body': body,
                'timestamp': datetime.utcnow().isoformat(),
                'source': 'okta_security',
                'channel': channel.name,
                **template_vars
            }
            
            # Add custom payload fields
            if 'payload_template' in config:
                custom_payload = config['payload_template']
                for key, value_template in custom_payload.items():
                    payload[key] = value_template.format(**template_vars)
            
            # Send webhook
            headers = {'Content-Type': 'application/json'}
            if 'headers' in config:
                headers.update(config['headers'])
            
            response = requests.post(
                webhook_url, 
                json=payload, 
                headers=headers,
                timeout=config.get('timeout', 30)
            )
            response.raise_for_status()
            
            logger.info("Webhook notification sent", 
                       channel=channel.name, 
                       url=webhook_url)
            return True
            
        except Exception as e:
            logger.error("Webhook notification failed", 
                        channel=channel.name, 
                        error=str(e))
            return False
    
    def _severity_matches(self, channel: NotificationChannel, severity: str) -> bool:
        """Check if severity matches channel filter"""
        if not channel.severity_filter:
            return True
        
        return severity in channel.severity_filter
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color code for severity"""
        color_map = {
            'LOW': '28a745',      # Green
            'MEDIUM': 'ffc107',   # Yellow  
            'HIGH': 'fd7e14',     # Orange
            'CRITICAL': 'dc3545'  # Red
        }
        return color_map.get(severity, '6c757d')  # Gray default
    
    def _format_target_entities(self, target_entities: Dict[str, List[str]]) -> str:
        """Format target entities for display"""
        if not target_entities:
            return "None"
        
        formatted = []
        for entity_type, entities in target_entities.items():
            if entities:
                formatted.append(f"{entity_type}: {', '.join(entities)}")
        
        return '\\n'.join(formatted) if formatted else "None"
    
    def _calculate_duration(self, action: ResponseAction) -> str:
        """Calculate action duration"""
        if not action.executed_at or not action.completed_at:
            return "N/A"
        
        duration = action.completed_at - action.executed_at
        return f"{duration.total_seconds():.1f} seconds"
    
    def _is_duplicate_notification(self, notification_key: str, window: int = 300) -> bool:
        """Check if notification is duplicate within time window"""
        now = datetime.utcnow()
        
        if notification_key in self.deduplication_cache:
            last_sent = self.deduplication_cache[notification_key]
            if (now - last_sent).total_seconds() < window:
                return True
        
        return False
    
    def _mark_notification_sent(self, notification_key: str):
        """Mark notification as sent for deduplication"""
        self.deduplication_cache[notification_key] = datetime.utcnow()
        
        # Clean old entries
        cutoff = datetime.utcnow() - timedelta(seconds=3600)  # 1 hour
        keys_to_remove = [
            key for key, timestamp in self.deduplication_cache.items()
            if timestamp < cutoff
        ]
        for key in keys_to_remove:
            del self.deduplication_cache[key]
    
    def _is_rate_limited(self, channel_name: str, limit: int = 10, window: int = 300) -> bool:
        """Check if channel is rate limited"""
        now = datetime.utcnow()
        
        # Clean old timestamps
        cutoff = now - timedelta(seconds=window)
        self.rate_limits[channel_name] = [
            ts for ts in self.rate_limits[channel_name] if ts > cutoff
        ]
        
        # Check limit
        return len(self.rate_limits[channel_name]) >= limit
    
    def _update_rate_limit(self, channel_name: str):
        """Update rate limit tracking"""
        self.rate_limits[channel_name].append(datetime.utcnow())
    
    def get_notification_statistics(self) -> Dict:
        """Get notification statistics"""
        total_sent = sum(len(timestamps) for timestamps in self.rate_limits.values())
        
        channel_stats = {}
        for channel_name, timestamps in self.rate_limits.items():
            recent_count = len([ts for ts in timestamps 
                              if (datetime.utcnow() - ts).total_seconds() < 3600])
            channel_stats[channel_name] = {
                'total_sent': len(timestamps),
                'recent_hour': recent_count,
                'enabled': self.channels.get(channel_name, {}).enabled
            }
        
        return {
            'total_notifications_sent': total_sent,
            'active_channels': len([ch for ch in self.channels.values() if ch.enabled]),
            'channel_statistics': channel_stats,
            'deduplication_cache_size': len(self.deduplication_cache)
        }