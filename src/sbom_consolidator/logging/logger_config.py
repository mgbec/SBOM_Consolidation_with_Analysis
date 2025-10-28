"""
Logger configuration and setup for the SBOM consolidator.
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass

from ..config import get_config
from .log_formatter import StructuredFormatter, ColoredFormatter
from .log_handler import RotatingFileHandler, ConsoleHandler


@dataclass
class LoggerConfig:
    """Configuration for logging system."""
    level: str = "INFO"
    file_path: Optional[str] = None
    format_string: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    max_file_size: int = 10  # MB
    backup_count: int = 5
    enable_console: bool = True
    enable_file: bool = True
    enable_structured: bool = False
    enable_colors: bool = True


class LoggingManager:
    """
    Centralized logging manager for the SBOM consolidator.
    
    This class provides comprehensive logging functionality with support for
    file rotation, structured logging, colored output, and configurable levels.
    """
    
    def __init__(self):
        """Initialize the logging manager."""
        self._loggers: Dict[str, logging.Logger] = {}
        self._handlers: Dict[str, logging.Handler] = {}
        self._configured = False
        self.config = None
    
    def setup_logging(self, config: Optional[LoggerConfig] = None) -> None:
        """
        Set up the logging system with the specified configuration.
        
        Args:
            config: Logging configuration (uses app config if not provided)
        """
        if self._configured:
            return
        
        # Use provided config or create from app config
        if config is None:
            app_config = get_config()
            config = LoggerConfig(
                level=app_config.logging.level,
                file_path=app_config.logging.file,
                format_string=app_config.logging.format,
                max_file_size=app_config.logging.max_file_size,
                backup_count=app_config.logging.backup_count
            )
        
        self.config = config
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(self._get_log_level(config.level))
        
        # Clear existing handlers
        root_logger.handlers.clear()
        
        # Set up console handler
        if config.enable_console:
            console_handler = self._create_console_handler(config)
            root_logger.addHandler(console_handler)
            self._handlers['console'] = console_handler
        
        # Set up file handler
        if config.enable_file and config.file_path:
            file_handler = self._create_file_handler(config)
            root_logger.addHandler(file_handler)
            self._handlers['file'] = file_handler
        
        # Configure third-party loggers
        self._configure_third_party_loggers(config)
        
        # Log initial message
        logger = logging.getLogger(__name__)
        logger.info(f"Logging system initialized with level: {config.level}")
        
        self._configured = True
    
    def _create_console_handler(self, config: LoggerConfig) -> logging.Handler:
        """Create console handler with appropriate formatter."""
        handler = ConsoleHandler(sys.stdout)
        handler.setLevel(self._get_log_level(config.level))
        
        if config.enable_colors and sys.stdout.isatty():
            formatter = ColoredFormatter(config.format_string)
        elif config.enable_structured:
            formatter = StructuredFormatter()
        else:
            formatter = logging.Formatter(config.format_string)
        
        handler.setFormatter(formatter)
        return handler
    
    def _create_file_handler(self, config: LoggerConfig) -> logging.Handler:
        """Create rotating file handler."""
        # Ensure log directory exists
        log_path = Path(config.file_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        handler = RotatingFileHandler(
            filename=config.file_path,
            maxBytes=config.max_file_size * 1024 * 1024,  # Convert MB to bytes
            backupCount=config.backup_count,
            encoding='utf-8'
        )
        handler.setLevel(self._get_log_level(config.level))
        
        if config.enable_structured:
            formatter = StructuredFormatter()
        else:
            formatter = logging.Formatter(config.format_string)
        
        handler.setFormatter(formatter)
        return handler
    
    def _configure_third_party_loggers(self, config: LoggerConfig) -> None:
        """Configure third-party library loggers to reduce noise."""
        # Reduce verbosity of common third-party libraries
        third_party_loggers = {
            'urllib3': logging.WARNING,
            'requests': logging.WARNING,
            'git': logging.WARNING,
            'boto3': logging.WARNING,
            'botocore': logging.WARNING,
            'paramiko': logging.WARNING,
            'github': logging.WARNING
        }
        
        for logger_name, level in third_party_loggers.items():
            logger = logging.getLogger(logger_name)
            logger.setLevel(level)
    
    def _get_log_level(self, level_str: str) -> int:
        """Convert string log level to logging constant."""
        level_mapping = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }
        return level_mapping.get(level_str.upper(), logging.INFO)
    
    def get_logger(self, name: str) -> logging.Logger:
        """
        Get a logger instance for the specified name.
        
        Args:
            name: Logger name (typically __name__)
            
        Returns:
            Configured logger instance
        """
        if name not in self._loggers:
            logger = logging.getLogger(name)
            self._loggers[name] = logger
        
        return self._loggers[name]
    
    def add_handler(self, name: str, handler: logging.Handler) -> None:
        """
        Add a custom handler to the logging system.
        
        Args:
            name: Handler name
            handler: Handler instance
        """
        root_logger = logging.getLogger()
        root_logger.addHandler(handler)
        self._handlers[name] = handler
    
    def remove_handler(self, name: str) -> None:
        """
        Remove a handler from the logging system.
        
        Args:
            name: Handler name to remove
        """
        if name in self._handlers:
            root_logger = logging.getLogger()
            root_logger.removeHandler(self._handlers[name])
            del self._handlers[name]
    
    def set_level(self, level: str) -> None:
        """
        Change the logging level for all handlers.
        
        Args:
            level: New logging level
        """
        log_level = self._get_log_level(level)
        
        # Update root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        # Update all handlers
        for handler in self._handlers.values():
            handler.setLevel(log_level)
        
        logger = logging.getLogger(__name__)
        logger.info(f"Logging level changed to: {level}")
    
    def get_log_stats(self) -> Dict[str, Any]:
        """
        Get logging system statistics.
        
        Returns:
            Dictionary with logging statistics
        """
        stats = {
            "configured": self._configured,
            "loggers_created": len(self._loggers),
            "handlers_active": len(self._handlers),
            "current_level": self.config.level if self.config else "Unknown"
        }
        
        # Add handler-specific stats
        for name, handler in self._handlers.items():
            if hasattr(handler, 'baseFilename'):
                # File handler stats
                try:
                    file_path = Path(handler.baseFilename)
                    if file_path.exists():
                        stats[f"{name}_file_size"] = file_path.stat().st_size
                    else:
                        stats[f"{name}_file_size"] = 0
                except Exception:
                    stats[f"{name}_file_size"] = "unknown"
        
        return stats
    
    def flush_handlers(self) -> None:
        """Flush all handlers to ensure logs are written."""
        for handler in self._handlers.values():
            if hasattr(handler, 'flush'):
                handler.flush()
    
    def close_handlers(self) -> None:
        """Close all handlers and clean up resources."""
        for handler in self._handlers.values():
            if hasattr(handler, 'close'):
                handler.close()
        
        self._handlers.clear()
        self._configured = False


# Global logging manager instance
_logging_manager = LoggingManager()


def setup_logging(config: Optional[LoggerConfig] = None) -> None:
    """
    Set up the global logging system.
    
    Args:
        config: Logging configuration
    """
    _logging_manager.setup_logging(config)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    return _logging_manager.get_logger(name)


def set_log_level(level: str) -> None:
    """
    Set the global logging level.
    
    Args:
        level: Logging level string
    """
    _logging_manager.set_level(level)


def get_logging_stats() -> Dict[str, Any]:
    """Get logging system statistics."""
    return _logging_manager.get_log_stats()


def flush_logs() -> None:
    """Flush all log handlers."""
    _logging_manager.flush_handlers()


def close_logging() -> None:
    """Close logging system and clean up resources."""
    _logging_manager.close_handlers()