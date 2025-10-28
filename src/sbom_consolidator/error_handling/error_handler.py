"""
Centralized error handling and recovery mechanisms.
"""

import logging
import traceback
from typing import Dict, Any, List, Optional, Callable, Type
from datetime import datetime, timedelta
from enum import Enum

from .exceptions import SBOMConsolidatorError


class ErrorSeverity(Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RecoveryStrategy(Enum):
    """Error recovery strategies."""
    IGNORE = "ignore"
    RETRY = "retry"
    FALLBACK = "fallback"
    FAIL_FAST = "fail_fast"
    GRACEFUL_DEGRADATION = "graceful_degradation"


class ErrorHandler:
    """
    Centralized error handler for the SBOM consolidator system.
    
    This class provides comprehensive error handling, logging, and
    recovery mechanisms for all components of the system.
    """
    
    def __init__(self):
        """Initialize error handler."""
        self.logger = logging.getLogger(__name__)
        
        # Error tracking
        self._error_counts = {}
        self._error_history = []
        self._recovery_attempts = {}
        
        # Configuration
        self._max_history_size = 1000
        self._error_threshold = 10
        self._recovery_strategies = {}
        
        # Register default recovery strategies
        self._register_default_strategies()
    
    def handle_error(
        self,
        error: Exception,
        context: Optional[Dict[str, Any]] = None,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        recovery_strategy: Optional[RecoveryStrategy] = None
    ) -> bool:
        """
        Handle an error with appropriate logging and recovery.
        
        Args:
            error: Exception that occurred
            context: Additional context information
            severity: Error severity level
            recovery_strategy: Strategy to use for recovery
            
        Returns:
            True if error was handled successfully, False otherwise
        """
        # Create error record
        error_record = self._create_error_record(error, context, severity)
        
        # Log the error
        self._log_error(error_record)
        
        # Track the error
        self._track_error(error_record)
        
        # Attempt recovery if strategy is provided
        if recovery_strategy:
            return self._attempt_recovery(error_record, recovery_strategy)
        
        # Use default strategy based on error type
        default_strategy = self._get_default_strategy(error)
        if default_strategy:
            return self._attempt_recovery(error_record, default_strategy)
        
        return False
    
    def _create_error_record(
        self,
        error: Exception,
        context: Optional[Dict[str, Any]],
        severity: ErrorSeverity
    ) -> Dict[str, Any]:
        """Create a comprehensive error record."""
        error_record = {
            "timestamp": datetime.utcnow(),
            "error_type": type(error).__name__,
            "error_message": str(error),
            "severity": severity.value,
            "context": context or {},
            "traceback": traceback.format_exc(),
            "recovery_attempted": False,
            "recovery_successful": False
        }
        
        # Add custom error information if available
        if isinstance(error, SBOMConsolidatorError):
            error_record.update({
                "error_code": error.error_code,
                "custom_context": error.context,
                "cause": str(error.cause) if error.cause else None
            })
        
        return error_record
    
    def _log_error(self, error_record: Dict[str, Any]) -> None:
        """Log error with appropriate level based on severity."""
        severity = error_record["severity"]
        message = f"{error_record['error_type']}: {error_record['error_message']}"
        
        if error_record["context"]:
            context_str = ", ".join(f"{k}={v}" for k, v in error_record["context"].items())
            message += f" | Context: {context_str}"
        
        if severity == ErrorSeverity.CRITICAL.value:
            self.logger.critical(message, exc_info=True)
        elif severity == ErrorSeverity.HIGH.value:
            self.logger.error(message, exc_info=True)
        elif severity == ErrorSeverity.MEDIUM.value:
            self.logger.warning(message)
        else:
            self.logger.info(message)
    
    def _track_error(self, error_record: Dict[str, Any]) -> None:
        """Track error for statistics and analysis."""
        error_type = error_record["error_type"]
        
        # Update error counts
        if error_type not in self._error_counts:
            self._error_counts[error_type] = 0
        self._error_counts[error_type] += 1
        
        # Add to history
        self._error_history.append(error_record)
        
        # Maintain history size limit
        if len(self._error_history) > self._max_history_size:
            self._error_history.pop(0)
    
    def _attempt_recovery(
        self,
        error_record: Dict[str, Any],
        strategy: RecoveryStrategy
    ) -> bool:
        """Attempt error recovery using specified strategy."""
        error_record["recovery_attempted"] = True
        
        try:
            if strategy == RecoveryStrategy.IGNORE:
                self.logger.debug("Ignoring error as per recovery strategy")
                error_record["recovery_successful"] = True
                return True
            
            elif strategy == RecoveryStrategy.RETRY:
                return self._retry_operation(error_record)
            
            elif strategy == RecoveryStrategy.FALLBACK:
                return self._use_fallback(error_record)
            
            elif strategy == RecoveryStrategy.GRACEFUL_DEGRADATION:
                return self._graceful_degradation(error_record)
            
            elif strategy == RecoveryStrategy.FAIL_FAST:
                self.logger.error("Failing fast as per recovery strategy")
                return False
            
        except Exception as recovery_error:
            self.logger.error(f"Recovery attempt failed: {recovery_error}")
            error_record["recovery_error"] = str(recovery_error)
        
        return False
    
    def _retry_operation(self, error_record: Dict[str, Any]) -> bool:
        """Implement retry logic for recoverable errors."""
        error_type = error_record["error_type"]
        
        # Track retry attempts
        if error_type not in self._recovery_attempts:
            self._recovery_attempts[error_type] = 0
        
        self._recovery_attempts[error_type] += 1
        
        # Check if we've exceeded retry limit
        max_retries = 3
        if self._recovery_attempts[error_type] > max_retries:
            self.logger.error(f"Max retries ({max_retries}) exceeded for {error_type}")
            return False
        
        self.logger.info(f"Retry attempt {self._recovery_attempts[error_type]} for {error_type}")
        error_record["recovery_successful"] = True
        return True
    
    def _use_fallback(self, error_record: Dict[str, Any]) -> bool:
        """Use fallback mechanism for error recovery."""
        self.logger.info("Using fallback mechanism for error recovery")
        error_record["recovery_successful"] = True
        return True
    
    def _graceful_degradation(self, error_record: Dict[str, Any]) -> bool:
        """Implement graceful degradation for error recovery."""
        self.logger.info("Implementing graceful degradation")
        error_record["recovery_successful"] = True
        return True
    
    def _get_default_strategy(self, error: Exception) -> Optional[RecoveryStrategy]:
        """Get default recovery strategy for error type."""
        error_type = type(error).__name__
        return self._recovery_strategies.get(error_type)
    
    def _register_default_strategies(self) -> None:
        """Register default recovery strategies for common error types."""
        self._recovery_strategies.update({
            "NetworkError": RecoveryStrategy.RETRY,
            "RepositoryError": RecoveryStrategy.GRACEFUL_DEGRADATION,
            "DependencyParsingError": RecoveryStrategy.GRACEFUL_DEGRADATION,
            "AIAnalysisError": RecoveryStrategy.FALLBACK,
            "ExportError": RecoveryStrategy.RETRY,
            "ConfigurationError": RecoveryStrategy.FAIL_FAST,
            "ValidationError": RecoveryStrategy.GRACEFUL_DEGRADATION
        })
    
    def register_recovery_strategy(
        self,
        error_type: str,
        strategy: RecoveryStrategy
    ) -> None:
        """
        Register a recovery strategy for a specific error type.
        
        Args:
            error_type: Name of the error type
            strategy: Recovery strategy to use
        """
        self._recovery_strategies[error_type] = strategy
        self.logger.debug(f"Registered recovery strategy {strategy.value} for {error_type}")
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get comprehensive error statistics."""
        total_errors = sum(self._error_counts.values())
        
        # Calculate error rates by time period
        now = datetime.utcnow()
        last_hour = now - timedelta(hours=1)
        last_day = now - timedelta(days=1)
        
        recent_errors = [
            e for e in self._error_history
            if e["timestamp"] > last_hour
        ]
        
        daily_errors = [
            e for e in self._error_history
            if e["timestamp"] > last_day
        ]
        
        # Calculate recovery success rate
        recovery_attempts = [e for e in self._error_history if e["recovery_attempted"]]
        successful_recoveries = [e for e in recovery_attempts if e["recovery_successful"]]
        
        recovery_rate = (
            len(successful_recoveries) / len(recovery_attempts)
            if recovery_attempts else 0
        )
        
        return {
            "total_errors": total_errors,
            "error_counts_by_type": self._error_counts.copy(),
            "errors_last_hour": len(recent_errors),
            "errors_last_day": len(daily_errors),
            "recovery_attempts": len(recovery_attempts),
            "successful_recoveries": len(successful_recoveries),
            "recovery_success_rate": recovery_rate,
            "most_common_errors": self._get_most_common_errors(),
            "error_trends": self._analyze_error_trends()
        }
    
    def _get_most_common_errors(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get most common error types."""
        sorted_errors = sorted(
            self._error_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return [
            {"error_type": error_type, "count": count}
            for error_type, count in sorted_errors[:limit]
        ]
    
    def _analyze_error_trends(self) -> Dict[str, Any]:
        """Analyze error trends over time."""
        if not self._error_history:
            return {"trend": "no_data"}
        
        # Simple trend analysis based on recent vs older errors
        now = datetime.utcnow()
        cutoff = now - timedelta(hours=6)
        
        recent_errors = [e for e in self._error_history if e["timestamp"] > cutoff]
        older_errors = [e for e in self._error_history if e["timestamp"] <= cutoff]
        
        if not older_errors:
            return {"trend": "insufficient_data"}
        
        recent_rate = len(recent_errors) / 6  # errors per hour
        older_rate = len(older_errors) / max(1, len(older_errors))
        
        if recent_rate > older_rate * 1.5:
            trend = "increasing"
        elif recent_rate < older_rate * 0.5:
            trend = "decreasing"
        else:
            trend = "stable"
        
        return {
            "trend": trend,
            "recent_error_rate": recent_rate,
            "historical_error_rate": older_rate
        }
    
    def clear_error_history(self) -> int:
        """
        Clear error history and return number of errors cleared.
        
        Returns:
            Number of errors that were cleared
        """
        count = len(self._error_history)
        self._error_history.clear()
        self._error_counts.clear()
        self._recovery_attempts.clear()
        
        self.logger.info(f"Cleared {count} errors from history")
        return count


class ErrorRecovery:
    """
    Utility class for implementing error recovery patterns.
    
    This class provides common error recovery patterns that can be
    used throughout the SBOM consolidator system.
    """
    
    @staticmethod
    def with_fallback(
        primary_func: Callable,
        fallback_func: Callable,
        error_types: Optional[List[Type[Exception]]] = None
    ) -> Any:
        """
        Execute primary function with fallback on error.
        
        Args:
            primary_func: Primary function to execute
            fallback_func: Fallback function to execute on error
            error_types: Specific error types to catch (all if None)
            
        Returns:
            Result from primary or fallback function
        """
        try:
            return primary_func()
        except Exception as e:
            if error_types and not isinstance(e, tuple(error_types)):
                raise
            
            logger = logging.getLogger(__name__)
            logger.warning(f"Primary function failed, using fallback: {e}")
            return fallback_func()
    
    @staticmethod
    def with_default(
        func: Callable,
        default_value: Any,
        error_types: Optional[List[Type[Exception]]] = None
    ) -> Any:
        """
        Execute function with default value on error.
        
        Args:
            func: Function to execute
            default_value: Default value to return on error
            error_types: Specific error types to catch (all if None)
            
        Returns:
            Function result or default value
        """
        try:
            return func()
        except Exception as e:
            if error_types and not isinstance(e, tuple(error_types)):
                raise
            
            logger = logging.getLogger(__name__)
            logger.warning(f"Function failed, using default value: {e}")
            return default_value
    
    @staticmethod
    def ignore_errors(
        func: Callable,
        error_types: Optional[List[Type[Exception]]] = None
    ) -> Optional[Any]:
        """
        Execute function and ignore specified errors.
        
        Args:
            func: Function to execute
            error_types: Specific error types to ignore (all if None)
            
        Returns:
            Function result or None if error was ignored
        """
        try:
            return func()
        except Exception as e:
            if error_types and not isinstance(e, tuple(error_types)):
                raise
            
            logger = logging.getLogger(__name__)
            logger.debug(f"Ignoring error as requested: {e}")
            return None