"""
Error handling and recovery mechanisms for the SBOM consolidator.
"""

from .exceptions import (
    SBOMConsolidatorError, RepositoryError, DependencyParsingError,
    SBOMGenerationError, ConsolidationError, ExportError, AIAnalysisError
)
from .error_handler import ErrorHandler, ErrorRecovery
from .retry_decorator import retry, RetryConfig
from .circuit_breaker import CircuitBreaker, CircuitBreakerError

__all__ = [
    "SBOMConsolidatorError",
    "RepositoryError", 
    "DependencyParsingError",
    "SBOMGenerationError",
    "ConsolidationError",
    "ExportError",
    "AIAnalysisError",
    "ErrorHandler",
    "ErrorRecovery",
    "retry",
    "RetryConfig",
    "CircuitBreaker",
    "CircuitBreakerError"
]