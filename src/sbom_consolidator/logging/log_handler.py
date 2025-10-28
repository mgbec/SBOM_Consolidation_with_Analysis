"""
Custom log handlers for enhanced logging functionality.
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional, TextIO, Any
from datetime import datetime


class RotatingFileHandler(logging.handlers.RotatingFileHandler):
    """
    Enhanced rotating file handler with additional features.
    
    This handler extends the standard RotatingFileHandler with
    better error handling and additional functionality.
    """
    
    def __init__(
        self,
        filename: str,
        mode: str = 'a',
        maxBytes: int = 0,
        backupCount: int = 0,
        encoding: Optional[str] = None,
        delay: bool = False,
        errors: Optional[str] = None
    ):
        """
        Initialize rotating file handler.
        
        Args:
            filename: Log file path
            mode: File open mode
            maxBytes: Maximum file size before rotation
            backupCount: Number of backup files to keep
            encoding: File encoding
            delay: Whether to delay file opening
            errors: Error handling strategy
        """
        # Ensure directory exists
        log_path = Path(filename)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        super().__init__(filename, mode, maxBytes, backupCount, encoding, delay, errors)
        
        # Track statistics
        self.records_written = 0
        self.bytes_written = 0
        self.rotations_performed = 0
    
    def emit(self, record: logging.LogRecord) -> None:
        """
        Emit a log record with enhanced error handling.
        
        Args:
            record: Log record to emit
        """
        try:
            super().emit(record)
            self.records_written += 1
            
            # Estimate bytes written (approximate)
            if hasattr(record, 'message'):
                self.bytes_written += len(record.message.encode('utf-8', errors='ignore'))
                
        except Exception as e:
            # Handle errors gracefully
            self.handleError(record)
    
    def doRollover(self) -> None:
        """Perform log rotation with statistics tracking."""
        super().doRollover()
        self.rotations_performed += 1
    
    def get_stats(self) -> dict:
        """Get handler statistics."""
        stats = {
            'records_written': self.records_written,
            'bytes_written': self.bytes_written,
            'rotations_performed': self.rotations_performed,
            'current_file': self.baseFilename
        }
        
        # Add file size if file exists
        try:
            file_path = Path(self.baseFilename)
            if file_path.exists():
                stats['current_file_size'] = file_path.stat().st_size
            else:
                stats['current_file_size'] = 0
        except Exception:
            stats['current_file_size'] = 'unknown'
        
        return stats


class ConsoleHandler(logging.StreamHandler):
    """
    Enhanced console handler with better formatting and error handling.
    
    This handler provides improved console output with support for
    different output streams and enhanced error handling.
    """
    
    def __init__(self, stream: Optional[TextIO] = None):
        """
        Initialize console handler.
        
        Args:
            stream: Output stream (defaults to sys.stdout)
        """
        if stream is None:
            stream = sys.stdout
        
        super().__init__(stream)
        
        # Track statistics
        self.records_written = 0
        self.errors_encountered = 0
    
    def emit(self, record: logging.LogRecord) -> None:
        """
        Emit a log record to console with error handling.
        
        Args:
            record: Log record to emit
        """
        try:
            super().emit(record)
            self.records_written += 1
        except Exception as e:
            self.errors_encountered += 1
            self.handleError(record)
    
    def get_stats(self) -> dict:
        """Get handler statistics."""
        return {
            'records_written': self.records_written,
            'errors_encountered': self.errors_encountered,
            'stream_name': getattr(self.stream, 'name', 'unknown')
        }


class BufferedHandler(logging.Handler):
    """
    Buffered handler that accumulates log records in memory.
    
    This handler is useful for collecting logs for later processing
    or for implementing custom log aggregation strategies.
    """
    
    def __init__(self, capacity: int = 1000):
        """
        Initialize buffered handler.
        
        Args:
            capacity: Maximum number of records to buffer
        """
        super().__init__()
        self.capacity = capacity
        self.buffer = []
        self.records_dropped = 0
    
    def emit(self, record: logging.LogRecord) -> None:
        """
        Add record to buffer.
        
        Args:
            record: Log record to buffer
        """
        if len(self.buffer) >= self.capacity:
            # Remove oldest record
            self.buffer.pop(0)
            self.records_dropped += 1
        
        # Format and store record
        formatted_record = {
            'timestamp': datetime.fromtimestamp(record.created),
            'level': record.levelname,
            'logger': record.name,
            'message': self.format(record),
            'raw_record': record
        }
        
        self.buffer.append(formatted_record)
    
    def get_records(self, level: Optional[str] = None, count: Optional[int] = None) -> list:
        """
        Get buffered records with optional filtering.
        
        Args:
            level: Filter by log level
            count: Maximum number of records to return
            
        Returns:
            List of log records
        """
        records = self.buffer
        
        # Filter by level if specified
        if level:
            records = [r for r in records if r['level'] == level.upper()]
        
        # Limit count if specified
        if count:
            records = records[-count:]
        
        return records
    
    def clear_buffer(self) -> int:
        """
        Clear the buffer and return number of records cleared.
        
        Returns:
            Number of records that were cleared
        """
        count = len(self.buffer)
        self.buffer.clear()
        return count
    
    def get_stats(self) -> dict:
        """Get handler statistics."""
        return {
            'buffer_size': len(self.buffer),
            'capacity': self.capacity,
            'records_dropped': self.records_dropped,
            'buffer_utilization': len(self.buffer) / self.capacity
        }


class ErrorHandler(logging.Handler):
    """
    Specialized handler for error and critical log messages.
    
    This handler provides special processing for error messages,
    including error aggregation and notification capabilities.
    """
    
    def __init__(self, min_level: int = logging.ERROR):
        """
        Initialize error handler.
        
        Args:
            min_level: Minimum log level to handle
        """
        super().__init__(min_level)
        self.error_counts = {}
        self.recent_errors = []
        self.max_recent_errors = 100
    
    def emit(self, record: logging.LogRecord) -> None:
        """
        Process error record.
        
        Args:
            record: Log record to process
        """
        if record.levelno < self.level:
            return
        
        # Count errors by logger
        logger_name = record.name
        if logger_name not in self.error_counts:
            self.error_counts[logger_name] = 0
        self.error_counts[logger_name] += 1
        
        # Store recent errors
        error_info = {
            'timestamp': datetime.fromtimestamp(record.created),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'exception': self.format(record) if record.exc_info else None
        }
        
        self.recent_errors.append(error_info)
        
        # Maintain recent errors limit
        if len(self.recent_errors) > self.max_recent_errors:
            self.recent_errors.pop(0)
    
    def get_error_summary(self) -> dict:
        """Get error summary statistics."""
        total_errors = sum(self.error_counts.values())
        
        return {
            'total_errors': total_errors,
            'errors_by_logger': self.error_counts.copy(),
            'recent_error_count': len(self.recent_errors),
            'most_recent_error': self.recent_errors[-1] if self.recent_errors else None
        }
    
    def get_recent_errors(self, count: Optional[int] = None) -> list:
        """
        Get recent error records.
        
        Args:
            count: Maximum number of errors to return
            
        Returns:
            List of recent error records
        """
        if count:
            return self.recent_errors[-count:]
        return self.recent_errors.copy()


class MetricsHandler(logging.Handler):
    """
    Handler that collects metrics from log messages.
    
    This handler extracts and aggregates metrics from log messages
    for monitoring and analysis purposes.
    """
    
    def __init__(self):
        """Initialize metrics handler."""
        super().__init__()
        self.metrics = {
            'log_counts_by_level': {},
            'log_counts_by_logger': {},
            'processing_times': [],
            'error_rates': {},
            'custom_metrics': {}
        }
    
    def emit(self, record: logging.LogRecord) -> None:
        """
        Extract metrics from log record.
        
        Args:
            record: Log record to process
        """
        # Count by level
        level = record.levelname
        if level not in self.metrics['log_counts_by_level']:
            self.metrics['log_counts_by_level'][level] = 0
        self.metrics['log_counts_by_level'][level] += 1
        
        # Count by logger
        logger = record.name
        if logger not in self.metrics['log_counts_by_logger']:
            self.metrics['log_counts_by_logger'][logger] = 0
        self.metrics['log_counts_by_logger'][logger] += 1
        
        # Extract processing time if available
        if hasattr(record, 'duration'):
            self.metrics['processing_times'].append(record.duration)
        
        # Extract custom metrics from record
        if hasattr(record, 'metrics'):
            for key, value in record.metrics.items():
                if key not in self.metrics['custom_metrics']:
                    self.metrics['custom_metrics'][key] = []
                self.metrics['custom_metrics'][key].append(value)
    
    def get_metrics(self) -> dict:
        """Get collected metrics."""
        metrics = self.metrics.copy()
        
        # Calculate derived metrics
        if self.metrics['processing_times']:
            times = self.metrics['processing_times']
            metrics['avg_processing_time'] = sum(times) / len(times)
            metrics['max_processing_time'] = max(times)
            metrics['min_processing_time'] = min(times)
        
        return metrics
    
    def reset_metrics(self) -> None:
        """Reset all collected metrics."""
        self.metrics = {
            'log_counts_by_level': {},
            'log_counts_by_logger': {},
            'processing_times': [],
            'error_rates': {},
            'custom_metrics': {}
        }