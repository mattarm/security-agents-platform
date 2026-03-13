#!/usr/bin/env python3
"""
Configuration management for Slack War Room Bot
"""

import os
from dataclasses import dataclass
from typing import Dict, List, Optional

@dataclass
class SlackConfig:
    """Slack application configuration"""
    bot_token: str
    app_token: str
    signing_secret: str
    client_id: Optional[str] = None
    client_secret: Optional[str] = None

@dataclass
class DatabaseConfig:
    """Database configuration"""
    type: str = "sqlite"  # sqlite, postgresql, mysql
    path: Optional[str] = "war_rooms.db"  # For SQLite
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    database: Optional[str] = None

@dataclass
class SecurityAgentsConfig:
    """SecurityAgents integration configuration"""
    alpha_4_enabled: bool = True
    gamma_enabled: bool = True
    beta_4_enabled: bool = True
    delta_enabled: bool = True
    
    # CrowdStrike MCP configuration
    crowdstrike_client_id: Optional[str] = None
    crowdstrike_client_secret: Optional[str] = None
    crowdstrike_base_url: str = "https://api.crowdstrike.com"
    
    # Agent timeouts
    command_timeout: int = 300  # seconds
    long_running_timeout: int = 3600  # seconds for exercises

@dataclass
class WarRoomConfig:
    """War room configuration"""
    auto_create_channels: bool = True
    default_severity: str = "medium"
    max_war_rooms_per_user: int = 10
    evidence_retention_days: int = 365
    auto_archive_after_days: int = 30
    
    # Notification settings
    notify_on_creation: bool = True
    notify_on_escalation: bool = True
    escalation_channels: List[str] = None
    
    def __post_init__(self):
        if self.escalation_channels is None:
            self.escalation_channels = []

@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: Optional[str] = "war_room_bot.log"
    max_file_size: int = 10485760  # 10MB
    backup_count: int = 5

class WarRoomBotConfig:
    """Main configuration class"""
    
    def __init__(self):
        self.slack = SlackConfig(
            bot_token=os.environ.get("SLACK_BOT_TOKEN", ""),
            app_token=os.environ.get("SLACK_APP_TOKEN", ""),
            signing_secret=os.environ.get("SLACK_SIGNING_SECRET", ""),
            client_id=os.environ.get("SLACK_CLIENT_ID"),
            client_secret=os.environ.get("SLACK_CLIENT_SECRET")
        )
        
        self.database = DatabaseConfig(
            type=os.environ.get("DB_TYPE", "sqlite"),
            path=os.environ.get("DB_PATH", "war_rooms.db"),
            host=os.environ.get("DB_HOST"),
            port=int(os.environ.get("DB_PORT", "5432")) if os.environ.get("DB_PORT") else None,
            username=os.environ.get("DB_USERNAME"),
            password=os.environ.get("DB_PASSWORD"),
            database=os.environ.get("DB_DATABASE")
        )
        
        self.security_agents = SecurityAgentsConfig(
            alpha_4_enabled=os.environ.get("ALPHA_4_ENABLED", "true").lower() == "true",
            gamma_enabled=os.environ.get("GAMMA_ENABLED", "true").lower() == "true",
            beta_4_enabled=os.environ.get("BETA_4_ENABLED", "true").lower() == "true",
            delta_enabled=os.environ.get("DELTA_ENABLED", "true").lower() == "true",
            crowdstrike_client_id=os.environ.get("CROWDSTRIKE_CLIENT_ID"),
            crowdstrike_client_secret=os.environ.get("CROWDSTRIKE_CLIENT_SECRET"),
            command_timeout=int(os.environ.get("COMMAND_TIMEOUT", "300")),
            long_running_timeout=int(os.environ.get("LONG_RUNNING_TIMEOUT", "3600"))
        )
        
        self.war_room = WarRoomConfig(
            auto_create_channels=os.environ.get("AUTO_CREATE_CHANNELS", "true").lower() == "true",
            default_severity=os.environ.get("DEFAULT_SEVERITY", "medium"),
            max_war_rooms_per_user=int(os.environ.get("MAX_WAR_ROOMS_PER_USER", "10")),
            evidence_retention_days=int(os.environ.get("EVIDENCE_RETENTION_DAYS", "365")),
            auto_archive_after_days=int(os.environ.get("AUTO_ARCHIVE_DAYS", "30")),
            notify_on_creation=os.environ.get("NOTIFY_ON_CREATION", "true").lower() == "true",
            notify_on_escalation=os.environ.get("NOTIFY_ON_ESCALATION", "true").lower() == "true",
            escalation_channels=os.environ.get("ESCALATION_CHANNELS", "").split(",") if os.environ.get("ESCALATION_CHANNELS") else []
        )
        
        self.logging = LoggingConfig(
            level=os.environ.get("LOG_LEVEL", "INFO"),
            file_path=os.environ.get("LOG_FILE_PATH", "war_room_bot.log"),
            max_file_size=int(os.environ.get("LOG_MAX_FILE_SIZE", "10485760")),
            backup_count=int(os.environ.get("LOG_BACKUP_COUNT", "5"))
        )
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of errors"""
        errors = []
        
        # Slack configuration validation
        if not self.slack.bot_token:
            errors.append("SLACK_BOT_TOKEN is required")
        if not self.slack.app_token:
            errors.append("SLACK_APP_TOKEN is required")
        if not self.slack.signing_secret:
            errors.append("SLACK_SIGNING_SECRET is required")
        
        # Database configuration validation
        if self.database.type not in ["sqlite", "postgresql", "mysql"]:
            errors.append("DB_TYPE must be one of: sqlite, postgresql, mysql")
        
        if self.database.type == "sqlite" and not self.database.path:
            errors.append("DB_PATH is required for SQLite database")
        
        if self.database.type in ["postgresql", "mysql"]:
            if not self.database.host:
                errors.append("DB_HOST is required for PostgreSQL/MySQL")
            if not self.database.username:
                errors.append("DB_USERNAME is required for PostgreSQL/MySQL")
            if not self.database.password:
                errors.append("DB_PASSWORD is required for PostgreSQL/MySQL")
            if not self.database.database:
                errors.append("DB_DATABASE is required for PostgreSQL/MySQL")
        
        # SecurityAgents configuration validation
        if (self.security_agents.alpha_4_enabled or 
            self.security_agents.gamma_enabled or
            self.security_agents.beta_4_enabled or
            self.security_agents.delta_enabled):
            
            if not self.security_agents.crowdstrike_client_id:
                errors.append("CROWDSTRIKE_CLIENT_ID is required when SecurityAgents are enabled")
            if not self.security_agents.crowdstrike_client_secret:
                errors.append("CROWDSTRIKE_CLIENT_SECRET is required when SecurityAgents are enabled")
        
        return errors
    
    def to_dict(self) -> Dict:
        """Convert configuration to dictionary"""
        return {
            "slack": {
                "bot_token": "***" if self.slack.bot_token else None,
                "app_token": "***" if self.slack.app_token else None,
                "signing_secret": "***" if self.slack.signing_secret else None,
                "client_id": self.slack.client_id
            },
            "database": {
                "type": self.database.type,
                "path": self.database.path,
                "host": self.database.host,
                "port": self.database.port,
                "username": self.database.username,
                "password": "***" if self.database.password else None,
                "database": self.database.database
            },
            "security_agents": {
                "alpha_4_enabled": self.security_agents.alpha_4_enabled,
                "gamma_enabled": self.security_agents.gamma_enabled,
                "beta_4_enabled": self.security_agents.beta_4_enabled,
                "delta_enabled": self.security_agents.delta_enabled,
                "crowdstrike_client_id": "***" if self.security_agents.crowdstrike_client_id else None,
                "command_timeout": self.security_agents.command_timeout,
                "long_running_timeout": self.security_agents.long_running_timeout
            },
            "war_room": {
                "auto_create_channels": self.war_room.auto_create_channels,
                "default_severity": self.war_room.default_severity,
                "max_war_rooms_per_user": self.war_room.max_war_rooms_per_user,
                "evidence_retention_days": self.war_room.evidence_retention_days,
                "auto_archive_after_days": self.war_room.auto_archive_after_days,
                "escalation_channels": self.war_room.escalation_channels
            },
            "logging": {
                "level": self.logging.level,
                "file_path": self.logging.file_path,
                "max_file_size": self.logging.max_file_size,
                "backup_count": self.logging.backup_count
            }
        }

# Global configuration instance
config = WarRoomBotConfig()