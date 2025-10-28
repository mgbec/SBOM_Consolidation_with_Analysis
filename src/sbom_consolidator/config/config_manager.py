"""
Configuration management system for the SBOM consolidator.
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass, field
import logging
from string import Template

logger = logging.getLogger(__name__)


@dataclass
class GitHubConfig:
    """GitHub API configuration."""
    access_token: Optional[str] = None
    api_base_url: str = "https://api.github.com"
    timeout: int = 30
    max_retries: int = 3


@dataclass
class OutputConfig:
    """Output configuration for SBOMs."""
    format: list = field(default_factory=lambda: ["spdx", "cyclonedx"])
    directory: str = "./sboms"
    consolidated_filename: str = "consolidated-sbom"
    include_timestamp: bool = True


@dataclass
class ScanningConfig:
    """Dependency scanning configuration."""
    supported_languages: list = field(default_factory=lambda: ["javascript", "python", "java", "csharp"])
    include_dev_dependencies: bool = False
    vulnerability_check: bool = True
    license_detection: bool = True
    max_scan_depth: int = 10


@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str = "INFO"
    file: Optional[str] = "sbom-generator.log"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    max_file_size: int = 10  # MB
    backup_count: int = 5


@dataclass
class VulnerabilityConfig:
    """Vulnerability database configuration."""
    databases: list = field(default_factory=lambda: ["https://osv.dev", "https://nvd.nist.gov"])
    enable_cache: bool = True
    cache_expiry: int = 24  # hours


@dataclass
class ConsolidationConfig:
    """SBOM consolidation configuration."""
    duplicate_strategy: str = "merge"  # merge, keep_first, keep_all
    preserve_source_info: bool = True
    generate_statistics: bool = True


@dataclass
class AWSConfig:
    """AWS configuration."""
    region: str = "us-east-1"
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None


@dataclass
class BedrockConfig:
    """AWS Bedrock configuration."""
    enable_risk_analysis: bool = True
    enable_security_recommendations: bool = True
    risk_analysis_model: str = "anthropic.claude-3-sonnet-20240229-v1:0"
    security_advisor_model: str = "anthropic.claude-3-sonnet-20240229-v1:0"
    max_tokens: int = 4000
    temperature: float = 0.1


@dataclass
class AppConfig:
    """Complete application configuration."""
    github: GitHubConfig = field(default_factory=GitHubConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    scanning: ScanningConfig = field(default_factory=ScanningConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    vulnerability: VulnerabilityConfig = field(default_factory=VulnerabilityConfig)
    consolidation: ConsolidationConfig = field(default_factory=ConsolidationConfig)
    aws: AWSConfig = field(default_factory=AWSConfig)
    bedrock: BedrockConfig = field(default_factory=BedrockConfig)


class ConfigManager:
    """
    Manages application configuration from multiple sources.
    
    Configuration is loaded in the following order (later sources override earlier):
    1. Default configuration
    2. Configuration file
    3. Environment variables
    4. Command-line arguments (when provided)
    """
    
    def __init__(self, config_file: Optional[Union[str, Path]] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_file: Path to configuration file
        """
        self.config_file = Path(config_file) if config_file else None
        self._config: Optional[AppConfig] = None
        self._env_var_mapping = self._create_env_var_mapping()
    
    def _create_env_var_mapping(self) -> Dict[str, str]:
        """Create mapping of environment variables to config paths."""
        return {
            # GitHub configuration
            "GITHUB_TOKEN": "github.access_token",
            "GITHUB_API_URL": "github.api_base_url",
            "GITHUB_TIMEOUT": "github.timeout",
            "GITHUB_MAX_RETRIES": "github.max_retries",
            
            # Output configuration
            "SBOM_OUTPUT_DIR": "output.directory",
            "SBOM_FORMATS": "output.format",
            "SBOM_FILENAME": "output.consolidated_filename",
            "SBOM_INCLUDE_TIMESTAMP": "output.include_timestamp",
            
            # Scanning configuration
            "SBOM_LANGUAGES": "scanning.supported_languages",
            "SBOM_INCLUDE_DEV": "scanning.include_dev_dependencies",
            "SBOM_VULNERABILITY_CHECK": "scanning.vulnerability_check",
            "SBOM_LICENSE_DETECTION": "scanning.license_detection",
            "SBOM_MAX_SCAN_DEPTH": "scanning.max_scan_depth",
            
            # Logging configuration
            "LOG_LEVEL": "logging.level",
            "LOG_FILE": "logging.file",
            "LOG_FORMAT": "logging.format",
            "LOG_MAX_SIZE": "logging.max_file_size",
            "LOG_BACKUP_COUNT": "logging.backup_count",
            
            # Vulnerability configuration
            "VULNERABILITY_DATABASES": "vulnerability.databases",
            "VULNERABILITY_CACHE": "vulnerability.enable_cache",
            "VULNERABILITY_CACHE_EXPIRY": "vulnerability.cache_expiry",
            
            # AWS configuration
            "AWS_REGION": "aws.region",
            "AWS_ACCESS_KEY_ID": "aws.access_key_id",
            "AWS_SECRET_ACCESS_KEY": "aws.secret_access_key",
            
            # Bedrock configuration
            "BEDROCK_ENABLE_RISK_ANALYSIS": "bedrock.enable_risk_analysis",
            "BEDROCK_ENABLE_RECOMMENDATIONS": "bedrock.enable_security_recommendations",
            "BEDROCK_RISK_MODEL": "bedrock.risk_analysis_model",
            "BEDROCK_ADVISOR_MODEL": "bedrock.security_advisor_model",
            "BEDROCK_MAX_TOKENS": "bedrock.max_tokens",
            "BEDROCK_TEMPERATURE": "bedrock.temperature",
        }
    
    def load_config(self) -> AppConfig:
        """
        Load configuration from all sources.
        
        Returns:
            Complete application configuration
        """
        if self._config is not None:
            return self._config
        
        # Start with default configuration
        config_dict = self._get_default_config()
        
        # Load from configuration file
        if self.config_file and self.config_file.exists():
            file_config = self._load_config_file(self.config_file)
            config_dict = self._merge_configs(config_dict, file_config)
        
        # Override with environment variables
        env_config = self._load_env_config()
        config_dict = self._merge_configs(config_dict, env_config)
        
        # Substitute environment variables in string values
        config_dict = self._substitute_env_vars(config_dict)
        
        # Validate configuration
        self._validate_config(config_dict)
        
        # Convert to AppConfig object
        self._config = self._dict_to_config(config_dict)
        
        return self._config
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration values."""
        return {
            "github": {
                "access_token": None,
                "api_base_url": "https://api.github.com",
                "timeout": 30,
                "max_retries": 3
            },
            "output": {
                "format": ["spdx", "cyclonedx"],
                "directory": "./sboms",
                "consolidated_filename": "consolidated-sbom",
                "include_timestamp": True
            },
            "scanning": {
                "supported_languages": ["javascript", "python", "java", "csharp"],
                "include_dev_dependencies": False,
                "vulnerability_check": True,
                "license_detection": True,
                "max_scan_depth": 10
            },
            "logging": {
                "level": "INFO",
                "file": "sbom-generator.log",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "max_file_size": 10,
                "backup_count": 5
            },
            "vulnerability": {
                "databases": ["https://osv.dev", "https://nvd.nist.gov"],
                "enable_cache": True,
                "cache_expiry": 24
            },
            "consolidation": {
                "duplicate_strategy": "merge",
                "preserve_source_info": True,
                "generate_statistics": True
            },
            "aws": {
                "region": "us-east-1",
                "access_key_id": None,
                "secret_access_key": None
            },
            "bedrock": {
                "enable_risk_analysis": True,
                "enable_security_recommendations": True,
                "risk_analysis_model": "anthropic.claude-3-sonnet-20240229-v1:0",
                "security_advisor_model": "anthropic.claude-3-sonnet-20240229-v1:0",
                "max_tokens": 4000,
                "temperature": 0.1
            }
        }
    
    def _load_config_file(self, config_path: Path) -> Dict[str, Any]:
        """
        Load configuration from YAML file.
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Configuration dictionary
        """
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                logger.info(f"Loaded configuration from {config_path}")
                return config or {}
        except Exception as e:
            logger.warning(f"Failed to load config file {config_path}: {e}")
            return {}
    
    def _load_env_config(self) -> Dict[str, Any]:
        """
        Load configuration from environment variables.
        
        Returns:
            Configuration dictionary from environment variables
        """
        env_config = {}
        
        for env_var, config_path in self._env_var_mapping.items():
            value = os.getenv(env_var)
            if value is not None:
                # Convert string values to appropriate types
                value = self._convert_env_value(value)
                self._set_nested_value(env_config, config_path, value)
        
        return env_config
    
    def _convert_env_value(self, value: str) -> Any:
        """
        Convert environment variable string to appropriate type.
        
        Args:
            value: String value from environment variable
            
        Returns:
            Converted value
        """
        # Handle boolean values
        if value.lower() in ('true', 'yes', '1', 'on'):
            return True
        elif value.lower() in ('false', 'no', '0', 'off'):
            return False
        
        # Handle numeric values
        try:
            if '.' in value:
                return float(value)
            else:
                return int(value)
        except ValueError:
            pass
        
        # Handle list values (comma-separated)
        if ',' in value:
            return [item.strip() for item in value.split(',')]
        
        # Return as string
        return value
    
    def _set_nested_value(self, config: Dict[str, Any], path: str, value: Any) -> None:
        """
        Set a nested configuration value using dot notation.
        
        Args:
            config: Configuration dictionary
            path: Dot-separated path (e.g., 'github.access_token')
            value: Value to set
        """
        keys = path.split('.')
        current = config
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
    
    def _substitute_env_vars(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Substitute environment variables in configuration values.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            Configuration with environment variables substituted
        """
        def substitute_recursive(obj):
            if isinstance(obj, dict):
                return {k: substitute_recursive(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [substitute_recursive(item) for item in obj]
            elif isinstance(obj, str) and obj.startswith('${') and obj.endswith('}'):
                env_var = obj[2:-1]
                return os.getenv(env_var, obj)
            else:
                return obj
        
        return substitute_recursive(config)
    
    def _merge_configs(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge two configuration dictionaries.
        
        Args:
            base: Base configuration
            override: Override configuration
            
        Returns:
            Merged configuration
        """
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _validate_config(self, config: Dict[str, Any]) -> None:
        """
        Validate configuration values.
        
        Args:
            config: Configuration dictionary
            
        Raises:
            ValueError: If configuration is invalid
        """
        # Validate required fields
        if not config.get("github", {}).get("access_token"):
            logger.warning("GitHub access token not configured - some features may not work")
        
        # Validate output formats
        valid_formats = {"spdx", "cyclonedx", "json"}
        output_formats = config.get("output", {}).get("format", [])
        for fmt in output_formats:
            if fmt not in valid_formats:
                raise ValueError(f"Invalid output format: {fmt}. Valid formats: {valid_formats}")
        
        # Validate logging level
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        log_level = config.get("logging", {}).get("level", "INFO")
        if log_level not in valid_levels:
            raise ValueError(f"Invalid log level: {log_level}. Valid levels: {valid_levels}")
        
        # Validate AWS region if Bedrock is enabled
        bedrock_config = config.get("bedrock", {})
        if bedrock_config.get("enable_risk_analysis") or bedrock_config.get("enable_security_recommendations"):
            aws_region = config.get("aws", {}).get("region")
            if not aws_region:
                logger.warning("AWS region not configured - Bedrock features may not work")
    
    def _dict_to_config(self, config_dict: Dict[str, Any]) -> AppConfig:
        """
        Convert configuration dictionary to AppConfig object.
        
        Args:
            config_dict: Configuration dictionary
            
        Returns:
            AppConfig object
        """
        return AppConfig(
            github=GitHubConfig(**config_dict.get("github", {})),
            output=OutputConfig(**config_dict.get("output", {})),
            scanning=ScanningConfig(**config_dict.get("scanning", {})),
            logging=LoggingConfig(**config_dict.get("logging", {})),
            vulnerability=VulnerabilityConfig(**config_dict.get("vulnerability", {})),
            consolidation=ConsolidationConfig(**config_dict.get("consolidation", {})),
            aws=AWSConfig(**config_dict.get("aws", {})),
            bedrock=BedrockConfig(**config_dict.get("bedrock", {}))
        )
    
    def get_config(self) -> AppConfig:
        """
        Get the current configuration.
        
        Returns:
            Application configuration
        """
        if self._config is None:
            return self.load_config()
        return self._config
    
    def reload_config(self) -> AppConfig:
        """
        Reload configuration from all sources.
        
        Returns:
            Reloaded application configuration
        """
        self._config = None
        return self.load_config()
    
    def save_config(self, config_path: Optional[Path] = None) -> None:
        """
        Save current configuration to file.
        
        Args:
            config_path: Path to save configuration file
        """
        if config_path is None:
            config_path = self.config_file or Path("config.yaml")
        
        config = self.get_config()
        config_dict = {
            "github": {
                "api_base_url": config.github.api_base_url,
                "timeout": config.github.timeout,
                "max_retries": config.github.max_retries
            },
            "output": {
                "format": config.output.format,
                "directory": config.output.directory,
                "consolidated_filename": config.output.consolidated_filename,
                "include_timestamp": config.output.include_timestamp
            },
            "scanning": {
                "supported_languages": config.scanning.supported_languages,
                "include_dev_dependencies": config.scanning.include_dev_dependencies,
                "vulnerability_check": config.scanning.vulnerability_check,
                "license_detection": config.scanning.license_detection,
                "max_scan_depth": config.scanning.max_scan_depth
            },
            "logging": {
                "level": config.logging.level,
                "file": config.logging.file,
                "format": config.logging.format,
                "max_file_size": config.logging.max_file_size,
                "backup_count": config.logging.backup_count
            },
            "vulnerability": {
                "databases": config.vulnerability.databases,
                "enable_cache": config.vulnerability.enable_cache,
                "cache_expiry": config.vulnerability.cache_expiry
            },
            "consolidation": {
                "duplicate_strategy": config.consolidation.duplicate_strategy,
                "preserve_source_info": config.consolidation.preserve_source_info,
                "generate_statistics": config.consolidation.generate_statistics
            },
            "aws": {
                "region": config.aws.region
            },
            "bedrock": {
                "enable_risk_analysis": config.bedrock.enable_risk_analysis,
                "enable_security_recommendations": config.bedrock.enable_security_recommendations,
                "risk_analysis_model": config.bedrock.risk_analysis_model,
                "security_advisor_model": config.bedrock.security_advisor_model,
                "max_tokens": config.bedrock.max_tokens,
                "temperature": config.bedrock.temperature
            }
        }
        
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config_dict, f, default_flow_style=False, indent=2)
        
        logger.info(f"Configuration saved to {config_path}")


# Global configuration manager instance
_config_manager: Optional[ConfigManager] = None


def get_config_manager(config_file: Optional[Union[str, Path]] = None) -> ConfigManager:
    """
    Get the global configuration manager instance.
    
    Args:
        config_file: Path to configuration file (only used on first call)
        
    Returns:
        ConfigManager instance
    """
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(config_file)
    return _config_manager


def get_config() -> AppConfig:
    """
    Get the current application configuration.
    
    Returns:
        Application configuration
    """
    return get_config_manager().get_config()