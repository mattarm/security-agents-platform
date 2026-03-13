#!/usr/bin/env python3
"""
Configuration Management - Environment-aware configuration for SecurityAgents Platform
Supports development, staging, and production environments
"""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import logging

class Environment(Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"

@dataclass
class DatabaseConfig:
    """Database configuration"""
    host: str
    port: int
    database: str
    username: str
    password: str
    ssl_mode: str = "prefer"
    pool_size: int = 5
    max_overflow: int = 10

@dataclass
class RedisConfig:
    """Redis configuration"""
    host: str
    port: int
    password: Optional[str] = None
    db: int = 0
    ssl: bool = False

@dataclass
class APIConfig:
    """API server configuration"""
    host: str = "0.0.0.0"
    port: int = 8080
    workers: int = 1
    reload: bool = False
    cors_origins: list = None
    rate_limit_per_minute: int = 100
    request_timeout: int = 300

@dataclass
class AgentConfig:
    """Agent configuration"""
    enabled: bool
    max_concurrent_tasks: int
    timeout: int
    capabilities: list
    config: Dict[str, Any] = None

@dataclass
class SecurityConfig:
    """Security configuration"""
    api_keys: Dict[str, Dict[str, Any]]
    jwt_secret: str
    encryption_key: str
    session_timeout: int = 3600
    rate_limiting: bool = True
    cors_enabled: bool = True

@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file: Optional[str] = None
    max_bytes: int = 10485760  # 10MB
    backup_count: int = 5
    json_format: bool = False

@dataclass
class MonitoringConfig:
    """Monitoring configuration"""
    metrics_enabled: bool = True
    prometheus_enabled: bool = False
    prometheus_port: int = 9090
    health_check_interval: int = 30
    alert_webhooks: list = None

@dataclass
class ExternalServicesConfig:
    """External services configuration"""
    virustotal_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None
    github_token: Optional[str] = None
    aws_access_key: Optional[str] = None
    aws_secret_key: Optional[str] = None
    aws_region: str = "us-east-1"

class ConfigManager:
    """Centralized configuration management"""
    
    def __init__(self, environment: Environment = None, config_file: str = None):
        self.environment = environment or self.detect_environment()
        self.config_file = config_file
        self.config = self.load_configuration()
        
        print(f"🔧 Configuration loaded for environment: {self.environment.value}")

    def detect_environment(self) -> Environment:
        """Auto-detect environment from environment variables"""
        env_name = os.getenv('ENVIRONMENT', os.getenv('ENV', 'development')).lower()
        
        if env_name in ['prod', 'production']:
            return Environment.PRODUCTION
        elif env_name in ['stage', 'staging']:
            return Environment.STAGING
        else:
            return Environment.DEVELOPMENT

    def load_configuration(self) -> Dict[str, Any]:
        """Load configuration from multiple sources"""
        
        # Start with default configuration
        config = self.get_default_config()
        
        # Override with environment-specific config
        env_config = self.get_environment_config()
        config.update(env_config)
        
        # Override with file-based config if specified
        if self.config_file:
            file_config = self.load_config_file(self.config_file)
            config.update(file_config)
        
        # Override with environment variables
        env_vars = self.load_environment_variables()
        config.update(env_vars)
        
        # Validate configuration
        self.validate_configuration(config)
        
        return config

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'environment': self.environment.value,
            'database': {
                'host': 'localhost',
                'port': 5432,
                'database': 'security_agents',
                'username': 'postgres',
                'password': 'password',
                'ssl_mode': 'prefer',
                'pool_size': 5,
                'max_overflow': 10
            },
            'redis': {
                'host': 'localhost',
                'port': 6379,
                'password': None,
                'db': 0,
                'ssl': False
            },
            'api': {
                'host': '0.0.0.0',
                'port': 8080,
                'workers': 1,
                'reload': False,
                'cors_origins': ['*'],
                'rate_limit_per_minute': 100,
                'request_timeout': 300
            },
            'agents': {
                'alpha_4_threat_intel': {
                    'enabled': True,
                    'max_concurrent_tasks': 3,
                    'timeout': 300,
                    'capabilities': ['threat_campaigns', 'actor_profiling', 'ioc_enrichment'],
                    'config': {
                        'osint_sources': ['virustotal', 'shodan', 'urlvoid'],
                        'attribution_threshold': 70.0,
                        'campaign_clustering': True
                    }
                },
                'beta_4_devsecops': {
                    'enabled': True,
                    'max_concurrent_tasks': 5,
                    'timeout': 600,
                    'capabilities': ['sast_analysis', 'container_security', 'iac_security', 'supply_chain'],
                    'config': {
                        'languages': ['python', 'javascript', 'typescript', 'java', 'go'],
                        'container_scanners': ['docker', 'kubernetes'],
                        'iac_tools': ['terraform', 'cloudformation'],
                        'sca_enabled': True
                    }
                }
            },
            'security': {
                'api_keys': {
                    'demo-key-123': {
                        'name': 'Demo Client',
                        'permissions': ['read', 'write'],
                        'rate_limit': 100
                    }
                },
                'jwt_secret': 'change-this-in-production',
                'encryption_key': 'change-this-32-char-key-in-prod',
                'session_timeout': 3600,
                'rate_limiting': True,
                'cors_enabled': True
            },
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'file': None,
                'max_bytes': 10485760,
                'backup_count': 5,
                'json_format': False
            },
            'monitoring': {
                'metrics_enabled': True,
                'prometheus_enabled': False,
                'prometheus_port': 9090,
                'health_check_interval': 30,
                'alert_webhooks': []
            },
            'external_services': {
                'virustotal_api_key': None,
                'shodan_api_key': None,
                'github_token': None,
                'aws_access_key': None,
                'aws_secret_key': None,
                'aws_region': 'us-east-1'
            }
        }

    def get_environment_config(self) -> Dict[str, Any]:
        """Get environment-specific configuration"""
        
        if self.environment == Environment.PRODUCTION:
            return {
                'api': {
                    'workers': 4,
                    'reload': False,
                    'cors_origins': ['https://yourdomain.com'],
                    'rate_limit_per_minute': 1000
                },
                'database': {
                    'ssl_mode': 'require',
                    'pool_size': 20,
                    'max_overflow': 30
                },
                'logging': {
                    'level': 'WARNING',
                    'file': '/var/log/security-agents/app.log',
                    'json_format': True
                },
                'monitoring': {
                    'prometheus_enabled': True,
                    'health_check_interval': 10
                },
                'security': {
                    'rate_limiting': True,
                    'cors_enabled': False
                }
            }
        
        elif self.environment == Environment.STAGING:
            return {
                'api': {
                    'workers': 2,
                    'reload': False,
                    'cors_origins': ['https://staging.yourdomain.com'],
                    'rate_limit_per_minute': 500
                },
                'database': {
                    'ssl_mode': 'require',
                    'pool_size': 10
                },
                'logging': {
                    'level': 'INFO',
                    'file': '/var/log/security-agents/staging.log'
                },
                'monitoring': {
                    'prometheus_enabled': True
                }
            }
        
        else:  # DEVELOPMENT
            return {
                'api': {
                    'workers': 1,
                    'reload': True,
                    'rate_limit_per_minute': 1000
                },
                'logging': {
                    'level': 'DEBUG'
                },
                'security': {
                    'rate_limiting': False
                }
            }

    def load_config_file(self, file_path: str) -> Dict[str, Any]:
        """Load configuration from file (JSON or YAML)"""
        
        config_path = Path(file_path)
        if not config_path.exists():
            print(f"⚠️ Config file not found: {file_path}")
            return {}
        
        try:
            with open(config_path, 'r') as f:
                if config_path.suffix.lower() in ['.yml', '.yaml']:
                    return yaml.safe_load(f) or {}
                else:
                    return json.load(f)
        except Exception as e:
            print(f"❌ Failed to load config file {file_path}: {e}")
            return {}

    def load_environment_variables(self) -> Dict[str, Any]:
        """Load configuration from environment variables"""
        
        env_config = {}
        
        # Database configuration
        if os.getenv('DB_HOST'):
            env_config.setdefault('database', {})['host'] = os.getenv('DB_HOST')
        if os.getenv('DB_PORT'):
            env_config.setdefault('database', {})['port'] = int(os.getenv('DB_PORT'))
        if os.getenv('DB_NAME'):
            env_config.setdefault('database', {})['database'] = os.getenv('DB_NAME')
        if os.getenv('DB_USER'):
            env_config.setdefault('database', {})['username'] = os.getenv('DB_USER')
        if os.getenv('DB_PASSWORD'):
            env_config.setdefault('database', {})['password'] = os.getenv('DB_PASSWORD')
        
        # Redis configuration
        if os.getenv('REDIS_HOST'):
            env_config.setdefault('redis', {})['host'] = os.getenv('REDIS_HOST')
        if os.getenv('REDIS_PORT'):
            env_config.setdefault('redis', {})['port'] = int(os.getenv('REDIS_PORT'))
        if os.getenv('REDIS_PASSWORD'):
            env_config.setdefault('redis', {})['password'] = os.getenv('REDIS_PASSWORD')
        
        # API configuration
        if os.getenv('API_HOST'):
            env_config.setdefault('api', {})['host'] = os.getenv('API_HOST')
        if os.getenv('API_PORT'):
            env_config.setdefault('api', {})['port'] = int(os.getenv('API_PORT'))
        if os.getenv('API_WORKERS'):
            env_config.setdefault('api', {})['workers'] = int(os.getenv('API_WORKERS'))
        
        # Security configuration
        if os.getenv('JWT_SECRET'):
            env_config.setdefault('security', {})['jwt_secret'] = os.getenv('JWT_SECRET')
        if os.getenv('ENCRYPTION_KEY'):
            env_config.setdefault('security', {})['encryption_key'] = os.getenv('ENCRYPTION_KEY')
        
        # External services
        if os.getenv('VIRUSTOTAL_API_KEY'):
            env_config.setdefault('external_services', {})['virustotal_api_key'] = os.getenv('VIRUSTOTAL_API_KEY')
        if os.getenv('SHODAN_API_KEY'):
            env_config.setdefault('external_services', {})['shodan_api_key'] = os.getenv('SHODAN_API_KEY')
        if os.getenv('GITHUB_TOKEN'):
            env_config.setdefault('external_services', {})['github_token'] = os.getenv('GITHUB_TOKEN')
        if os.getenv('AWS_ACCESS_KEY_ID'):
            env_config.setdefault('external_services', {})['aws_access_key'] = os.getenv('AWS_ACCESS_KEY_ID')
        if os.getenv('AWS_SECRET_ACCESS_KEY'):
            env_config.setdefault('external_services', {})['aws_secret_key'] = os.getenv('AWS_SECRET_ACCESS_KEY')
        if os.getenv('AWS_DEFAULT_REGION'):
            env_config.setdefault('external_services', {})['aws_region'] = os.getenv('AWS_DEFAULT_REGION')
        
        # Logging configuration
        if os.getenv('LOG_LEVEL'):
            env_config.setdefault('logging', {})['level'] = os.getenv('LOG_LEVEL')
        if os.getenv('LOG_FILE'):
            env_config.setdefault('logging', {})['file'] = os.getenv('LOG_FILE')
        
        return env_config

    def validate_configuration(self, config: Dict[str, Any]):
        """Validate configuration for required fields and consistency"""
        
        errors = []
        
        # Validate critical security settings in production
        if self.environment == Environment.PRODUCTION:
            security = config.get('security', {})
            
            if security.get('jwt_secret') == 'change-this-in-production':
                errors.append("JWT secret must be changed in production")
            
            if security.get('encryption_key') == 'change-this-32-char-key-in-prod':
                errors.append("Encryption key must be changed in production")
            
            if not security.get('rate_limiting', True):
                errors.append("Rate limiting should be enabled in production")
        
        # Validate API keys for external services
        external = config.get('external_services', {})
        agents = config.get('agents', {})
        
        if agents.get('alpha_4_threat_intel', {}).get('enabled'):
            if not external.get('virustotal_api_key') and not external.get('shodan_api_key'):
                errors.append("At least one threat intelligence API key required for Alpha-4 agent")
        
        # Validate database configuration
        db_config = config.get('database', {})
        required_db_fields = ['host', 'port', 'database', 'username', 'password']
        missing_db_fields = [field for field in required_db_fields if not db_config.get(field)]
        
        if missing_db_fields and self.environment == Environment.PRODUCTION:
            errors.append(f"Missing required database fields: {missing_db_fields}")
        
        if errors:
            error_msg = "Configuration validation failed:\n" + "\n".join(f"- {error}" for error in errors)
            if self.environment == Environment.PRODUCTION:
                raise ValueError(error_msg)
            else:
                print(f"⚠️ Configuration warnings:\n{error_msg}")

    def get_database_config(self) -> DatabaseConfig:
        """Get typed database configuration"""
        db_config = self.config.get('database', {})
        return DatabaseConfig(**db_config)

    def get_redis_config(self) -> RedisConfig:
        """Get typed Redis configuration"""
        redis_config = self.config.get('redis', {})
        return RedisConfig(**redis_config)

    def get_api_config(self) -> APIConfig:
        """Get typed API configuration"""
        api_config = self.config.get('api', {})
        return APIConfig(**api_config)

    def get_agent_config(self, agent_id: str) -> Optional[AgentConfig]:
        """Get typed agent configuration"""
        agents_config = self.config.get('agents', {})
        agent_config = agents_config.get(agent_id)
        
        if agent_config:
            return AgentConfig(**agent_config)
        return None

    def get_security_config(self) -> SecurityConfig:
        """Get typed security configuration"""
        security_config = self.config.get('security', {})
        return SecurityConfig(**security_config)

    def get_logging_config(self) -> LoggingConfig:
        """Get typed logging configuration"""
        logging_config = self.config.get('logging', {})
        return LoggingConfig(**logging_config)

    def get_monitoring_config(self) -> MonitoringConfig:
        """Get typed monitoring configuration"""
        monitoring_config = self.config.get('monitoring', {})
        return MonitoringConfig(**monitoring_config)

    def get_external_services_config(self) -> ExternalServicesConfig:
        """Get typed external services configuration"""
        external_config = self.config.get('external_services', {})
        return ExternalServicesConfig(**external_config)

    def get(self, key: str, default=None):
        """Get configuration value by key (supports dot notation)"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value

    def export_config(self, file_path: str, format: str = 'yaml', exclude_secrets: bool = True):
        """Export current configuration to file"""
        
        config_to_export = self.config.copy()
        
        if exclude_secrets:
            # Remove sensitive information
            if 'security' in config_to_export:
                security = config_to_export['security']
                if 'api_keys' in security:
                    security['api_keys'] = '*** REDACTED ***'
                if 'jwt_secret' in security:
                    security['jwt_secret'] = '*** REDACTED ***'
                if 'encryption_key' in security:
                    security['encryption_key'] = '*** REDACTED ***'
            
            if 'database' in config_to_export:
                config_to_export['database']['password'] = '*** REDACTED ***'
            
            if 'external_services' in config_to_export:
                external = config_to_export['external_services']
                for key in external:
                    if 'key' in key.lower() or 'secret' in key.lower() or 'token' in key.lower():
                        if external[key]:
                            external[key] = '*** REDACTED ***'
        
        try:
            with open(file_path, 'w') as f:
                if format.lower() == 'yaml':
                    yaml.dump(config_to_export, f, default_flow_style=False, indent=2)
                else:
                    json.dump(config_to_export, f, indent=2, default=str)
            
            print(f"✅ Configuration exported to {file_path}")
            
        except Exception as e:
            print(f"❌ Failed to export configuration: {e}")

    def setup_logging(self):
        """Setup logging based on configuration"""
        
        log_config = self.get_logging_config()
        
        # Configure basic logging
        log_handlers = [logging.StreamHandler()]
        
        if log_config.file:
            # Ensure log directory exists
            log_path = Path(log_config.file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            if log_config.max_bytes > 0:
                from logging.handlers import RotatingFileHandler
                file_handler = RotatingFileHandler(
                    log_config.file,
                    maxBytes=log_config.max_bytes,
                    backupCount=log_config.backup_count
                )
            else:
                file_handler = logging.FileHandler(log_config.file)
            
            log_handlers.append(file_handler)
        
        # Configure format
        if log_config.json_format:
            # JSON formatter for structured logging
            import json
            class JSONFormatter(logging.Formatter):
                def format(self, record):
                    log_data = {
                        'timestamp': self.formatTime(record),
                        'level': record.levelname,
                        'logger': record.name,
                        'message': record.getMessage(),
                        'module': record.module,
                        'function': record.funcName,
                        'line': record.lineno
                    }
                    if record.exc_info:
                        log_data['exception'] = self.formatException(record.exc_info)
                    return json.dumps(log_data)
            
            formatter = JSONFormatter()
        else:
            formatter = logging.Formatter(log_config.format)
        
        for handler in log_handlers:
            handler.setFormatter(formatter)
        
        # Configure root logger
        logging.basicConfig(
            level=getattr(logging, log_config.level.upper()),
            handlers=log_handlers,
            force=True
        )

# Global configuration manager instance
config_manager = None

def get_config_manager() -> ConfigManager:
    """Get global configuration manager instance"""
    global config_manager
    
    if config_manager is None:
        config_manager = ConfigManager()
    
    return config_manager

def init_config(environment: Environment = None, config_file: str = None) -> ConfigManager:
    """Initialize global configuration manager"""
    global config_manager
    
    config_manager = ConfigManager(environment=environment, config_file=config_file)
    config_manager.setup_logging()
    
    return config_manager

# Example usage and testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="SecurityAgents Configuration Manager")
    parser.add_argument("--environment", choices=['development', 'staging', 'production'], 
                       help="Environment name")
    parser.add_argument("--config-file", help="Configuration file path")
    parser.add_argument("--export", help="Export configuration to file")
    parser.add_argument("--format", choices=['json', 'yaml'], default='yaml', help="Export format")
    parser.add_argument("--validate", action="store_true", help="Validate configuration only")
    
    args = parser.parse_args()
    
    # Initialize configuration
    env = Environment(args.environment) if args.environment else None
    config_mgr = init_config(environment=env, config_file=args.config_file)
    
    if args.validate:
        print("✅ Configuration validation passed")
    
    if args.export:
        config_mgr.export_config(args.export, format=args.format)
    
    if not args.export and not args.validate:
        # Display configuration summary
        print(f"\n📊 Configuration Summary:")
        print(f"Environment: {config_mgr.environment.value}")
        print(f"API: {config_mgr.get('api.host')}:{config_mgr.get('api.port')}")
        print(f"Database: {config_mgr.get('database.host')}:{config_mgr.get('database.port')}")
        print(f"Agents enabled: {[k for k, v in config_mgr.get('agents', {}).items() if v.get('enabled')]}")
        print(f"Log level: {config_mgr.get('logging.level')}")
        print(f"External services configured: {len([k for k, v in config_mgr.get('external_services', {}).items() if v])}")