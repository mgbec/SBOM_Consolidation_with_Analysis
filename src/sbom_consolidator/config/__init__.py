"""
Configuration management for the SBOM consolidator system.
"""

from .config_manager import (
    ConfigManager, AppConfig, GitHubConfig, OutputConfig, ScanningConfig,
    LoggingConfig, VulnerabilityConfig, ConsolidationConfig, AWSConfig,
    BedrockConfig, get_config_manager, get_config
)

__all__ = [
    "ConfigManager",
    "AppConfig",
    "GitHubConfig",
    "OutputConfig",
    "ScanningConfig",
    "LoggingConfig",
    "VulnerabilityConfig",
    "ConsolidationConfig",
    "AWSConfig",
    "BedrockConfig",
    "get_config_manager",
    "get_config"
]

