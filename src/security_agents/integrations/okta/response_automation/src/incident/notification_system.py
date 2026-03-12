"""
Notification System

Handles notifications for identity threat responses including:
- SOC analyst notifications
- Executive alerts for critical threats
- End-user notifications
- Approval request workflows
"""

import asyncio
import aiohttp
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import json
import ssl

from ..core.response_engine import ThreatEvent, ThreatLevel, ResponseAction


@dataclass
class NotificationChannel:
    """Represents a notification channel configuration"""
    channel_type: str  # email, slack, teams, webhook
    config: Dict[str, Any]
    enabled: bool = True


class NotificationSystem:
    """
    Centralized notification system for identity threat responses
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize notification system"""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize notification channels
        self.soc_channels = self._init_channels(config.get('soc', {}))
        self.executive_channels = self._init_channels(config.get('executive', {}))
        self.end_user_config = config.get('end_user', {})
        
        # Email configuration for end-user notifications
        self.smtp_config = self.end_user_config.get('email', {})
        
        # Notification thresholds
        self.executive_threshold = config.get('executive', {}).get('threshold', 'CRITICAL')
        
        # Template configurations
        self.templates = {
            'threat_notification': self._get_threat_notification_template(),
            'approval_request': self._get_approval_request_template(),
            'action_completed': self._get_action_completed_template(),
            'user_security_action': self._get_user_security_action_template()
        }
        
        self.session: Optional[aiohttp.ClientSession] = None
        self.logger.info("Initialized notification system")

    def _init_channels(self, channel_configs: Dict[str, Any]) -> List[NotificationChannel]:
        """Initialize notification channels from configuration"""
        channels = []
        
        # Email channel
        if 'email' in channel_configs:
            email_config = channel_configs['email']
            if email_config.get('to_addresses'):
                channels.append(NotificationChannel(
                    channel_type='email',
                    config=email_config,
                    enabled=True
                ))
        
        # Slack channel
        if 'slack' in channel_configs:
            slack_config = channel_configs['slack']
            if slack_config.get('webhook_url'):
                channels.append(NotificationChannel(
                    channel_type='slack',
                    config=slack_config,
                    enabled=True
                ))
        
        # Microsoft Teams channel
        if 'teams' in channel_configs:
            teams_config = channel_configs['teams']
            if teams_config.get('webhook_url'):
                channels.append(NotificationChannel(
                    channel_type='teams',
                    config=teams_config,
                    enabled=True
                ))
        
        # Generic webhook
        if 'webhook' in channel_configs:
            webhook_config = channel_configs['webhook']
            if webhook_config.get('url'):
                channels.append(NotificationChannel(
                    channel_type='webhook',
                    config=webhook_config,
                    enabled=True
                ))
        
        return channels

    async def __aenter__(self):
        """Async context manager entry"""
        await self._ensure_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()

    async def _ensure_session(self):
        """Ensure HTTP session is created"""
        if self.session is None:
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(timeout=timeout)

    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
            self.session = None

    async def send_threat_notification(self, threat_event: ThreatEvent, response_actions: List[ResponseAction]) -> bool:
        """Send notification about a threat event and response actions"""
        self.logger.info(f"Sending threat notification for event {threat_event.id}")
        
        try:
            # Prepare notification data
            notification_data = {
                'type': 'threat_detected',
                'threat_event': {
                    'id': threat_event.id,
                    'type': threat_event.threat_type,
                    'level': threat_event.level.value,
                    'user_email': threat_event.user_email,
                    'user_id': threat_event.user_id,
                    'timestamp': threat_event.timestamp.isoformat(),
                    'source': threat_event.source,
                    'ip_address': threat_event.ip_address,
                    'indicators': threat_event.indicators
                },
                'response_actions': [
                    {
                        'action_type': action.action_type,
                        'status': action.status.value,
                        'executed_at': action.executed_at.isoformat() if action.executed_at else None,
                        'requires_approval': action.requires_approval
                    }
                    for action in response_actions
                ],
                'timestamp': datetime.now().isoformat()
            }
            
            # Send to SOC channels
            soc_success = await self._send_to_channels(
                self.soc_channels,
                'threat_notification',
                notification_data
            )
            
            # Send to executive channels if threshold met
            executive_success = True
            if self._meets_executive_threshold(threat_event.level):
                executive_success = await self._send_to_channels(
                    self.executive_channels,
                    'threat_notification',
                    notification_data
                )
            
            return soc_success and executive_success
            
        except Exception as e:
            self.logger.error(f"Error sending threat notification: {e}")
            return False

    async def send_approval_request(self, action: ResponseAction) -> bool:
        """Send approval request for a response action"""
        self.logger.info(f"Sending approval request for action {action.id}")
        
        try:
            approval_data = {
                'type': 'approval_request',
                'action': {
                    'id': action.id,
                    'type': action.action_type,
                    'threat_event_id': action.threat_event_id,
                    'parameters': action.parameters,
                    'created_at': action.created_at.isoformat()
                },
                'approval_url': f"/approve/{action.id}",  # Would be implemented in web interface
                'timestamp': datetime.now().isoformat()
            }
            
            # Send to SOC channels only (executives don't need to approve individual actions)
            return await self._send_to_channels(
                self.soc_channels,
                'approval_request',
                approval_data
            )
            
        except Exception as e:
            self.logger.error(f"Error sending approval request: {e}")
            return False

    async def send_action_completion_notification(self, action: ResponseAction) -> bool:
        """Send notification when an action completes"""
        self.logger.info(f"Sending action completion notification for {action.id}")
        
        try:
            completion_data = {
                'type': 'action_completed',
                'action': {
                    'id': action.id,
                    'type': action.action_type,
                    'threat_event_id': action.threat_event_id,
                    'status': action.status.value,
                    'executed_at': action.executed_at.isoformat() if action.executed_at else None,
                    'completed_at': action.completed_at.isoformat() if action.completed_at else None,
                    'result': action.result,
                    'error': action.error
                },
                'timestamp': datetime.now().isoformat()
            }
            
            # Send to SOC channels
            return await self._send_to_channels(
                self.soc_channels,
                'action_completed',
                completion_data
            )
            
        except Exception as e:
            self.logger.error(f"Error sending action completion notification: {e}")
            return False

    async def send_user_notification(self, user_email: str, action_type: str, details: Dict[str, Any]) -> bool:
        """Send notification to end user about security action"""
        if not self.smtp_config or not user_email:
            return False
        
        self.logger.info(f"Sending user notification to {user_email}")
        
        try:
            # Prepare user notification data
            user_data = {
                'type': 'user_security_action',
                'user_email': user_email,
                'action_type': action_type,
                'details': details,
                'timestamp': datetime.now().isoformat()
            }
            
            # Send email to user
            return await self._send_user_email(user_email, user_data)
            
        except Exception as e:
            self.logger.error(f"Error sending user notification: {e}")
            return False

    async def _send_to_channels(
        self,
        channels: List[NotificationChannel],
        template_name: str,
        data: Dict[str, Any]
    ) -> bool:
        """Send notification to multiple channels"""
        
        if not channels:
            return True  # No channels configured, consider success
        
        results = []
        
        for channel in channels:
            if not channel.enabled:
                continue
                
            try:
                if channel.channel_type == 'email':
                    result = await self._send_email_notification(channel, template_name, data)
                elif channel.channel_type == 'slack':
                    result = await self._send_slack_notification(channel, template_name, data)
                elif channel.channel_type == 'teams':
                    result = await self._send_teams_notification(channel, template_name, data)
                elif channel.channel_type == 'webhook':
                    result = await self._send_webhook_notification(channel, template_name, data)
                else:
                    self.logger.warning(f"Unknown channel type: {channel.channel_type}")
                    result = False
                
                results.append(result)
                
            except Exception as e:
                self.logger.error(f"Error sending to {channel.channel_type} channel: {e}")
                results.append(False)
        
        # Return True if at least one channel succeeded
        return any(results) if results else False

    async def _send_email_notification(
        self,
        channel: NotificationChannel,
        template_name: str,
        data: Dict[str, Any]
    ) -> bool:
        """Send email notification"""
        
        try:
            config = channel.config
            smtp_server = config.get('smtp_server', 'localhost')
            smtp_port = config.get('smtp_port', 587)
            username = config.get('username')
            password = config.get('password')
            from_address = config.get('from_address')
            to_addresses = config.get('to_addresses', [])
            
            if not from_address or not to_addresses:
                return False
            
            # Generate email content
            subject, body = self._generate_email_content(template_name, data)
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = from_address
            msg['To'] = ', '.join(to_addresses)
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            context = ssl.create_default_context()
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls(context=context)
                if username and password:
                    server.login(username, password)
                
                server.send_message(msg)
            
            self.logger.debug(f"Email notification sent to {', '.join(to_addresses)}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending email notification: {e}")
            return False

    async def _send_slack_notification(
        self,
        channel: NotificationChannel,
        template_name: str,
        data: Dict[str, Any]
    ) -> bool:
        """Send Slack notification"""
        
        try:
            await self._ensure_session()
            
            webhook_url = channel.config['webhook_url']
            slack_payload = self._generate_slack_payload(template_name, data, channel.config)
            
            async with self.session.post(webhook_url, json=slack_payload) as response:
                if response.status == 200:
                    self.logger.debug("Slack notification sent successfully")
                    return True
                else:
                    self.logger.error(f"Slack notification failed: {response.status}")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Error sending Slack notification: {e}")
            return False

    async def _send_teams_notification(
        self,
        channel: NotificationChannel,
        template_name: str,
        data: Dict[str, Any]
    ) -> bool:
        """Send Microsoft Teams notification"""
        
        try:
            await self._ensure_session()
            
            webhook_url = channel.config['webhook_url']
            teams_payload = self._generate_teams_payload(template_name, data)
            
            async with self.session.post(webhook_url, json=teams_payload) as response:
                if response.status == 200:
                    self.logger.debug("Teams notification sent successfully")
                    return True
                else:
                    self.logger.error(f"Teams notification failed: {response.status}")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Error sending Teams notification: {e}")
            return False

    async def _send_webhook_notification(
        self,
        channel: NotificationChannel,
        template_name: str,
        data: Dict[str, Any]
    ) -> bool:
        """Send generic webhook notification"""
        
        try:
            await self._ensure_session()
            
            webhook_url = channel.config['url']
            headers = channel.config.get('headers', {})
            
            payload = {
                'template': template_name,
                'data': data,
                'timestamp': datetime.now().isoformat()
            }
            
            async with self.session.post(webhook_url, json=payload, headers=headers) as response:
                if response.status < 400:
                    self.logger.debug("Webhook notification sent successfully")
                    return True
                else:
                    self.logger.error(f"Webhook notification failed: {response.status}")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Error sending webhook notification: {e}")
            return False

    async def _send_user_email(self, user_email: str, data: Dict[str, Any]) -> bool:
        """Send email to end user"""
        
        try:
            smtp_server = self.smtp_config.get('smtp_server', 'localhost')
            smtp_port = self.smtp_config.get('smtp_port', 587)
            username = self.smtp_config.get('username')
            password = self.smtp_config.get('password')
            from_address = self.smtp_config.get('from_address')
            
            if not from_address:
                return False
            
            # Generate user email content
            subject, body = self._generate_user_email_content(data)
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = from_address
            msg['To'] = user_email
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            context = ssl.create_default_context()
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls(context=context)
                if username and password:
                    server.login(username, password)
                
                server.send_message(msg)
            
            self.logger.debug(f"User email sent to {user_email}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending user email: {e}")
            return False

    def _meets_executive_threshold(self, threat_level: ThreatLevel) -> bool:
        """Check if threat level meets executive notification threshold"""
        threshold_map = {
            'LOW': ThreatLevel.LOW,
            'MEDIUM': ThreatLevel.MEDIUM,
            'HIGH': ThreatLevel.HIGH,
            'CRITICAL': ThreatLevel.CRITICAL
        }
        
        threshold = threshold_map.get(self.executive_threshold, ThreatLevel.CRITICAL)
        
        # Convert to numeric for comparison
        level_values = {
            ThreatLevel.LOW: 1,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.HIGH: 3,
            ThreatLevel.CRITICAL: 4
        }
        
        return level_values.get(threat_level, 0) >= level_values.get(threshold, 4)

    def _generate_email_content(self, template_name: str, data: Dict[str, Any]) -> tuple[str, str]:
        """Generate email subject and body"""
        
        if template_name == 'threat_notification':
            return self._generate_threat_email(data)
        elif template_name == 'approval_request':
            return self._generate_approval_email(data)
        elif template_name == 'action_completed':
            return self._generate_completion_email(data)
        else:
            return "Identity Security Alert", "Security event notification"

    def _generate_threat_email(self, data: Dict[str, Any]) -> tuple[str, str]:
        """Generate threat notification email"""
        threat = data['threat_event']
        actions = data['response_actions']
        
        subject = f"🚨 Identity Threat Detected: {threat['type']} - {threat['user_email']}"
        
        body = f"""
        <html>
        <body>
            <h2>Identity Threat Detected</h2>
            
            <h3>Threat Summary</h3>
            <ul>
                <li><strong>Type:</strong> {threat['type']}</li>
                <li><strong>Level:</strong> {threat['level']}</li>
                <li><strong>User:</strong> {threat['user_email']} ({threat['user_id']})</li>
                <li><strong>Source:</strong> {threat['source']}</li>
                <li><strong>Time:</strong> {threat['timestamp']}</li>
                {f"<li><strong>IP Address:</strong> {threat['ip_address']}</li>" if threat['ip_address'] else ""}
            </ul>
            
            <h3>Automated Response Actions</h3>
            <ul>
        """
        
        for action in actions:
            status_emoji = "✅" if action['status'] == 'COMPLETED' else "⏳" if action['status'] == 'IN_PROGRESS' else "❌"
            body += f"<li>{status_emoji} {action['action_type'].replace('_', ' ').title()} - {action['status']}</li>"
        
        body += """
            </ul>
            
            <p><strong>This is an automated notification from the Identity Threat Response System.</strong></p>
        </body>
        </html>
        """
        
        return subject, body

    def _generate_approval_email(self, data: Dict[str, Any]) -> tuple[str, str]:
        """Generate approval request email"""
        action = data['action']
        
        subject = f"🔐 Action Approval Required: {action['type']}"
        
        body = f"""
        <html>
        <body>
            <h2>Action Approval Required</h2>
            
            <p>The following response action requires your approval:</p>
            
            <ul>
                <li><strong>Action:</strong> {action['type'].replace('_', ' ').title()}</li>
                <li><strong>Threat Event:</strong> {action['threat_event_id']}</li>
                <li><strong>Requested:</strong> {action['created_at']}</li>
            </ul>
            
            <h3>Action Parameters</h3>
            <pre>{json.dumps(action['parameters'], indent=2)}</pre>
            
            <p><a href="{data.get('approval_url', '#')}">Click here to approve or deny this action</a></p>
        </body>
        </html>
        """
        
        return subject, body

    def _generate_completion_email(self, data: Dict[str, Any]) -> tuple[str, str]:
        """Generate action completion email"""
        action = data['action']
        status_emoji = "✅" if action['status'] == 'COMPLETED' else "❌"
        
        subject = f"{status_emoji} Action {action['status']}: {action['type']}"
        
        body = f"""
        <html>
        <body>
            <h2>Response Action {action['status']}</h2>
            
            <ul>
                <li><strong>Action:</strong> {action['type'].replace('_', ' ').title()}</li>
                <li><strong>Status:</strong> {action['status']}</li>
                <li><strong>Completed:</strong> {action['completed_at']}</li>
            </ul>
            
            {f"<h3>Error</h3><pre>{action['error']}</pre>" if action['error'] else ""}
            {f"<h3>Result</h3><pre>{json.dumps(action['result'], indent=2)}</pre>" if action['result'] else ""}
        </body>
        </html>
        """
        
        return subject, body

    def _generate_user_email_content(self, data: Dict[str, Any]) -> tuple[str, str]:
        """Generate user notification email content"""
        action_type = data['action_type']
        details = data['details']
        
        subject = "Security Action Taken on Your Account"
        
        body = f"""
        <html>
        <body>
            <h2>Security Action Notification</h2>
            
            <p>Hello,</p>
            
            <p>Our security systems have detected suspicious activity on your account and have taken 
            the following protective action:</p>
            
            <h3>Action Taken</h3>
            <p><strong>{action_type.replace('_', ' ').title()}</strong></p>
            
            <h3>What This Means</h3>
            <p>This action was taken to protect your account from potential unauthorized access.</p>
            
            <h3>What You Should Do</h3>
            <ul>
                <li>If you were trying to access your account, please try again</li>
                <li>If you did not initiate this activity, please contact IT Security immediately</li>
                <li>Review your recent account activity</li>
                <li>Ensure your password is strong and unique</li>
            </ul>
            
            <p>If you have any questions or concerns, please contact our IT Security team.</p>
            
            <p>Thank you,<br>IT Security Team</p>
        </body>
        </html>
        """
        
        return subject, body

    def _generate_slack_payload(self, template_name: str, data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate Slack message payload"""
        
        if template_name == 'threat_notification':
            return self._generate_slack_threat_message(data, config)
        elif template_name == 'approval_request':
            return self._generate_slack_approval_message(data, config)
        elif template_name == 'action_completed':
            return self._generate_slack_completion_message(data, config)
        
        return {'text': 'Identity security notification'}

    def _generate_slack_threat_message(self, data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate Slack threat notification"""
        threat = data['threat_event']
        actions = data['response_actions']
        
        level_colors = {
            'LOW': '#36a64f',
            'MEDIUM': '#ffaa00', 
            'HIGH': '#ff6600',
            'CRITICAL': '#cc0000'
        }
        
        color = level_colors.get(threat['level'], '#cccccc')
        
        action_text = '\n'.join([
            f"• {action['action_type'].replace('_', ' ').title()} - {action['status']}"
            for action in actions
        ])
        
        payload = {
            'channel': config.get('channel', '#security'),
            'attachments': [
                {
                    'color': color,
                    'title': f"🚨 Identity Threat Detected: {threat['type']}",
                    'fields': [
                        {
                            'title': 'User',
                            'value': f"{threat['user_email']} ({threat['user_id']})",
                            'short': True
                        },
                        {
                            'title': 'Threat Level',
                            'value': threat['level'],
                            'short': True
                        },
                        {
                            'title': 'Source',
                            'value': threat['source'],
                            'short': True
                        },
                        {
                            'title': 'IP Address',
                            'value': threat['ip_address'] or 'Unknown',
                            'short': True
                        },
                        {
                            'title': 'Automated Actions',
                            'value': action_text or 'None',
                            'short': False
                        }
                    ],
                    'footer': 'Identity Threat Response System',
                    'ts': int(datetime.now().timestamp())
                }
            ]
        }
        
        return payload

    def _generate_slack_approval_message(self, data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate Slack approval request"""
        action = data['action']
        
        payload = {
            'channel': config.get('channel', '#security'),
            'text': f"🔐 Approval required for: {action['type'].replace('_', ' ').title()}",
            'attachments': [
                {
                    'color': '#ffaa00',
                    'title': 'Response Action Approval Required',
                    'fields': [
                        {
                            'title': 'Action',
                            'value': action['type'].replace('_', ' ').title(),
                            'short': True
                        },
                        {
                            'title': 'Threat Event',
                            'value': action['threat_event_id'],
                            'short': True
                        }
                    ],
                    'footer': 'Identity Threat Response System'
                }
            ]
        }
        
        return payload

    def _generate_slack_completion_message(self, data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate Slack completion notification"""
        action = data['action']
        
        status_emoji = "✅" if action['status'] == 'COMPLETED' else "❌"
        color = '#36a64f' if action['status'] == 'COMPLETED' else '#cc0000'
        
        payload = {
            'channel': config.get('channel', '#security'),
            'text': f"{status_emoji} Action {action['status'].lower()}: {action['type'].replace('_', ' ').title()}",
            'attachments': [
                {
                    'color': color,
                    'title': f"Response Action {action['status']}",
                    'fields': [
                        {
                            'title': 'Action',
                            'value': action['type'].replace('_', ' ').title(),
                            'short': True
                        },
                        {
                            'title': 'Status',
                            'value': action['status'],
                            'short': True
                        }
                    ],
                    'footer': 'Identity Threat Response System'
                }
            ]
        }
        
        return payload

    def _generate_teams_payload(self, template_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate Microsoft Teams message payload"""
        
        # Basic Teams adaptive card format
        if template_name == 'threat_notification':
            threat = data['threat_event']
            return {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": f"Identity threat detected: {threat['type']}",
                "themeColor": "FF6600",
                "sections": [
                    {
                        "activityTitle": f"🚨 Identity Threat: {threat['type']}",
                        "facts": [
                            {"name": "User", "value": threat['user_email']},
                            {"name": "Threat Level", "value": threat['level']},
                            {"name": "Source", "value": threat['source']},
                            {"name": "Time", "value": threat['timestamp']}
                        ]
                    }
                ]
            }
        
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": "Identity security notification",
            "text": "Identity security notification from automated response system"
        }

    def _get_threat_notification_template(self) -> Dict[str, str]:
        """Get threat notification template"""
        return {
            'name': 'threat_notification',
            'description': 'Notification sent when a threat is detected and automated response is triggered'
        }

    def _get_approval_request_template(self) -> Dict[str, str]:
        """Get approval request template"""
        return {
            'name': 'approval_request',
            'description': 'Request for approval of a response action'
        }

    def _get_action_completed_template(self) -> Dict[str, str]:
        """Get action completion template"""
        return {
            'name': 'action_completed',
            'description': 'Notification sent when a response action completes'
        }

    def _get_user_security_action_template(self) -> Dict[str, str]:
        """Get user security action template"""
        return {
            'name': 'user_security_action',
            'description': 'Notification sent to end users about security actions taken on their account'
        }