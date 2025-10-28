"""
Custom log formatters for structured and colored logging.
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional


class StructuredFormatter(logging.Formatter):
    """
    Structured JSON formatter for machine-readable logs.
    
    This formatter outputs log records as JSON objects with consistent
    structure for easy parsing and analysis.
    """
    
    def __init__(self, include_extra: bool = True):
        """
        Initialize structured formatter.
        
        Args:
            include_extra: Whether to include extra fields from log records
        """
        super().__init__()
        self.include_extra = include_extra
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record as JSON.
        
        Args:
            record: Log record to format
            
        Returns:
            JSON-formatted log string
        """
        # Base log structure
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Add process and thread info
        if record.process:
            log_entry["process_id"] = record.process
        if record.thread:
            log_entry["thread_id"] = record.thread
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        # Add stack info if present
        if record.stack_info:
            log_entry["stack_info"] = record.stack_info
        
        # Add extra fields if enabled
        if self.include_extra:
            extra_fields = self._extract_extra_fields(record)
            if extra_fields:
                log_entry["extra"] = extra_fields
        
        return json.dumps(log_entry, default=str, ensure_ascii=False)
    
    def _extract_extra_fields(self, record: logging.LogRecord) -> Dict[str, Any]:
        """Extract extra fields from log record."""
        # Standard fields that should not be included in extra
        standard_fields = {
            'name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 'filename',
            'module', 'lineno', 'funcName', 'created', 'msecs', 'relativeCreated',
            'thread', 'threadName', 'processName', 'process', 'getMessage',
            'exc_info', 'exc_text', 'stack_info', 'message'
        }
        
        extra = {}
        for key, value in record.__dict__.items():
            if key not in standard_fields and not key.startswith('_'):
                extra[key] = value
        
        return extra


class ColoredFormatter(logging.Formatter):
    """
    Colored formatter for console output with ANSI color codes.
    
    This formatter adds colors to log levels and important information
    to improve readability in terminal output.
    """
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m',       # Reset
        'BOLD': '\033[1m',        # Bold
        'DIM': '\033[2m'          # Dim
    }
    
    def __init__(self, fmt: Optional[str] = None, datefmt: Optional[str] = None):
        """
        Initialize colored formatter.
        
        Args:
            fmt: Format string
            datefmt: Date format string
        """
        super().__init__(fmt, datefmt)
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record with colors.
        
        Args:
            record: Log record to format
            
        Returns:
            Colored log string
        """
        # Get base formatted message
        formatted = super().format(record)
        
        # Apply colors based on log level
        level_color = self.COLORS.get(record.levelname, '')
        reset_color = self.COLORS['RESET']
        
        if level_color:
            # Color the entire message
            formatted = f"{level_color}{formatted}{reset_color}"
            
            # Make level name bold
            level_name = record.levelname
            bold_level = f"{self.COLORS['BOLD']}{level_name}{reset_color}{level_color}"
            formatted = formatted.replace(level_name, bold_level, 1)
        
        # Highlight logger name
        logger_name = record.name
        if logger_name in formatted:
            dim_logger = f"{self.COLORS['DIM']}{logger_name}{reset_color}"
            if level_color:
                dim_logger = f"{level_color}{dim_logger}{level_color}"
            formatted = formatted.replace(logger_name, dim_logger, 1)
        
        return formatted


class CompactFormatter(logging.Formatter):
    """
    Compact formatter for minimal log output.
    
    This formatter provides concise log messages suitable for
    production environments or when log volume is a concern.
    """
    
    def __init__(self):
        """Initialize compact formatter."""
        super().__init__()
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record in compact format.
        
        Args:
            record: Log record to format
            
        Returns:
            Compact log string
        """
        # Create compact timestamp
        dt = datetime.fromtimestamp(record.created)
        timestamp = dt.strftime("%H:%M:%S")
        
        # Get short logger name (last component)
        logger_parts = record.name.split('.')
        short_logger = logger_parts[-1] if logger_parts else record.name
        
        # Format: HH:MM:SS LEVEL logger: message
        formatted = f"{timestamp} {record.levelname[0]} {short_logger}: {record.getMessage()}"
        
        # Add exception info if present
        if record.exc_info:
            formatted += f" | {self.formatException(record.exc_info)}"
        
        return formatted


class DetailedFormatter(logging.Formatter):
    """
    Detailed formatter for comprehensive log information.
    
    This formatter includes extensive context information useful
    for debugging and detailed analysis.
    """
    
    def __init__(self):
        """Initialize detailed formatter."""
        format_string = (
            "%(asctime)s | %(levelname)-8s | %(name)s | "
            "%(filename)s:%(lineno)d | %(funcName)s() | "
            "PID:%(process)d | TID:%(thread)d | %(message)s"
        )
        super().__init__(format_string)
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record with detailed information.
        
        Args:
            record: Log record to format
            
        Returns:
            Detailed log string
        """
        formatted = super().format(record)
        
        # Add exception details if present
        if record.exc_info:
            formatted += f"\nException: {self.formatException(record.exc_info)}"
        
        # Add stack info if present
        if record.stack_info:
            formatted += f"\nStack: {record.stack_info}"
        
        return formatted


class PerformanceFormatter(logging.Formatter):
    """
    Performance-focused formatter that includes timing information.
    
    This formatter adds performance metrics to log messages to help
    with performance analysis and optimization.
    """
    
    def __init__(self, fmt: Optional[str] = None):
        """
        Initialize performance formatter.
        
        Args:
            fmt: Format string
        """
        if fmt is None:
            fmt = "%(asctime)s | %(levelname)s | %(name)s | [%(relativeCreated)dms] | %(message)s"
        super().__init__(fmt)
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record with performance information.
        
        Args:
            record: Log record to format
            
        Returns:
            Performance-enhanced log string
        """
        # Add performance metrics to record
        if not hasattr(record, 'duration'):
            record.duration = 0
        
        formatted = super().format(record)
        
        # Add duration if available
        if hasattr(record, 'duration') and record.duration > 0:
            formatted += f" | Duration: {record.duration:.3f}s"
        
        return formatted