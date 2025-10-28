"""
Custom exceptions for the SBOM consolidator system.
"""

from typing import Optional, Dict, Any, List


class SBOMConsolidatorError(Exception):
    """
    Base exception for all SBOM consolidator errors.
    
    This is the root exception class that all other custom exceptions
    inherit from, providing common functionality and attributes.
    """
    
    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None
    ):
        """
        Initialize SBOM consolidator error.
        
        Args:
            message: Error message
            error_code: Optional error code for categorization
            context: Additional context information
            cause: Original exception that caused this error
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.context = context or {}
        self.cause = cause
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary representation."""
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "error_code": self.error_code,
            "context": self.context,
            "cause": str(self.cause) if self.cause else None
        }
    
    def __str__(self) -> str:
        """String representation of the error."""
        parts = [self.message]
        
        if self.error_code:
            parts.append(f"Code: {self.error_code}")
        
        if self.context:
            context_str = ", ".join(f"{k}={v}" for k, v in self.context.items())
            parts.append(f"Context: {context_str}")
        
        if self.cause:
            parts.append(f"Caused by: {self.cause}")
        
        return " | ".join(parts)


class RepositoryError(SBOMConsolidatorError):
    """
    Exception for repository-related errors.
    
    This exception is raised when there are issues with repository
    operations such as cloning, authentication, or file access.
    """
    
    def __init__(
        self,
        message: str,
        repository_url: Optional[str] = None,
        operation: Optional[str] = None,
        **kwargs
    ):
        """
        Initialize repository error.
        
        Args:
            message: Error message
            repository_url: URL of the repository that caused the error
            operation: Operation that failed (clone, scan, etc.)
            **kwargs: Additional arguments for base class
        """
        context = kwargs.get('context', {})
        if repository_url:
            context['repository_url'] = repository_url
        if operation:
            context['operation'] = operation
        
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        
        self.repository_url = repository_url
        self.operation = operation


class DependencyParsingError(SBOMConsolidatorError):
    """
    Exception for dependency parsing errors.
    
    This exception is raised when there are issues parsing dependency
    files or extracting dependency information.
    """
    
    def __init__(
        self,
        message: str,
        file_path: Optional[str] = None,
        parser_type: Optional[str] = None,
        line_number: Optional[int] = None,
        **kwargs
    ):
        """
        Initialize dependency parsing error.
        
        Args:
            message: Error message
            file_path: Path to the file that caused the error
            parser_type: Type of parser that failed
            line_number: Line number where error occurred
            **kwargs: Additional arguments for base class
        """
        context = kwargs.get('context', {})
        if file_path:
            context['file_path'] = file_path
        if parser_type:
            context['parser_type'] = parser_type
        if line_number:
            context['line_number'] = line_number
        
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        
        self.file_path = file_path
        self.parser_type = parser_type
        self.line_number = line_number


class SBOMGenerationError(SBOMConsolidatorError):
    """
    Exception for SBOM generation errors.
    
    This exception is raised when there are issues generating
    SBOM documents from dependency information.
    """
    
    def __init__(
        self,
        message: str,
        sbom_format: Optional[str] = None,
        component_count: Optional[int] = None,
        **kwargs
    ):
        """
        Initialize SBOM generation error.
        
        Args:
            message: Error message
            sbom_format: SBOM format that failed to generate
            component_count: Number of components being processed
            **kwargs: Additional arguments for base class
        """
        context = kwargs.get('context', {})
        if sbom_format:
            context['sbom_format'] = sbom_format
        if component_count:
            context['component_count'] = component_count
        
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        
        self.sbom_format = sbom_format
        self.component_count = component_count


class ConsolidationError(SBOMConsolidatorError):
    """
    Exception for SBOM consolidation errors.
    
    This exception is raised when there are issues consolidating
    multiple SBOMs into a unified document.
    """
    
    def __init__(
        self,
        message: str,
        sbom_count: Optional[int] = None,
        consolidation_strategy: Optional[str] = None,
        **kwargs
    ):
        """
        Initialize consolidation error.
        
        Args:
            message: Error message
            sbom_count: Number of SBOMs being consolidated
            consolidation_strategy: Strategy used for consolidation
            **kwargs: Additional arguments for base class
        """
        context = kwargs.get('context', {})
        if sbom_count:
            context['sbom_count'] = sbom_count
        if consolidation_strategy:
            context['consolidation_strategy'] = consolidation_strategy
        
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        
        self.sbom_count = sbom_count
        self.consolidation_strategy = consolidation_strategy


class ExportError(SBOMConsolidatorError):
    """
    Exception for SBOM export errors.
    
    This exception is raised when there are issues exporting
    SBOM documents to files or other formats.
    """
    
    def __init__(
        self,
        message: str,
        export_format: Optional[str] = None,
        output_path: Optional[str] = None,
        **kwargs
    ):
        """
        Initialize export error.
        
        Args:
            message: Error message
            export_format: Format being exported
            output_path: Output path that failed
            **kwargs: Additional arguments for base class
        """
        context = kwargs.get('context', {})
        if export_format:
            context['export_format'] = export_format
        if output_path:
            context['output_path'] = output_path
        
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        
        self.export_format = export_format
        self.output_path = output_path


class AIAnalysisError(SBOMConsolidatorError):
    """
    Exception for AI analysis errors.
    
    This exception is raised when there are issues with AI-powered
    risk analysis or security recommendations.
    """
    
    def __init__(
        self,
        message: str,
        analysis_type: Optional[str] = None,
        model_name: Optional[str] = None,
        component_count: Optional[int] = None,
        **kwargs
    ):
        """
        Initialize AI analysis error.
        
        Args:
            message: Error message
            analysis_type: Type of analysis that failed
            model_name: AI model that was used
            component_count: Number of components being analyzed
            **kwargs: Additional arguments for base class
        """
        context = kwargs.get('context', {})
        if analysis_type:
            context['analysis_type'] = analysis_type
        if model_name:
            context['model_name'] = model_name
        if component_count:
            context['component_count'] = component_count
        
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        
        self.analysis_type = analysis_type
        self.model_name = model_name
        self.component_count = component_count


class ConfigurationError(SBOMConsolidatorError):
    """
    Exception for configuration errors.
    
    This exception is raised when there are issues with
    configuration loading, validation, or usage.
    """
    
    def __init__(
        self,
        message: str,
        config_section: Optional[str] = None,
        config_key: Optional[str] = None,
        **kwargs
    ):
        """
        Initialize configuration error.
        
        Args:
            message: Error message
            config_section: Configuration section with error
            config_key: Specific configuration key with error
            **kwargs: Additional arguments for base class
        """
        context = kwargs.get('context', {})
        if config_section:
            context['config_section'] = config_section
        if config_key:
            context['config_key'] = config_key
        
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        
        self.config_section = config_section
        self.config_key = config_key


class ValidationError(SBOMConsolidatorError):
    """
    Exception for validation errors.
    
    This exception is raised when data validation fails
    during processing or export operations.
    """
    
    def __init__(
        self,
        message: str,
        validation_type: Optional[str] = None,
        invalid_fields: Optional[List[str]] = None,
        **kwargs
    ):
        """
        Initialize validation error.
        
        Args:
            message: Error message
            validation_type: Type of validation that failed
            invalid_fields: List of fields that failed validation
            **kwargs: Additional arguments for base class
        """
        context = kwargs.get('context', {})
        if validation_type:
            context['validation_type'] = validation_type
        if invalid_fields:
            context['invalid_fields'] = invalid_fields
        
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        
        self.validation_type = validation_type
        self.invalid_fields = invalid_fields or []


class NetworkError(SBOMConsolidatorError):
    """
    Exception for network-related errors.
    
    This exception is raised when there are network connectivity
    issues or API communication failures.
    """
    
    def __init__(
        self,
        message: str,
        url: Optional[str] = None,
        status_code: Optional[int] = None,
        retry_count: Optional[int] = None,
        **kwargs
    ):
        """
        Initialize network error.
        
        Args:
            message: Error message
            url: URL that caused the error
            status_code: HTTP status code if applicable
            retry_count: Number of retries attempted
            **kwargs: Additional arguments for base class
        """
        context = kwargs.get('context', {})
        if url:
            context['url'] = url
        if status_code:
            context['status_code'] = status_code
        if retry_count:
            context['retry_count'] = retry_count
        
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        
        self.url = url
        self.status_code = status_code
        self.retry_count = retry_count


class ResourceError(SBOMConsolidatorError):
    """
    Exception for resource-related errors.
    
    This exception is raised when there are issues with
    system resources like memory, disk space, or file handles.
    """
    
    def __init__(
        self,
        message: str,
        resource_type: Optional[str] = None,
        resource_limit: Optional[str] = None,
        **kwargs
    ):
        """
        Initialize resource error.
        
        Args:
            message: Error message
            resource_type: Type of resource that caused the error
            resource_limit: Resource limit that was exceeded
            **kwargs: Additional arguments for base class
        """
        context = kwargs.get('context', {})
        if resource_type:
            context['resource_type'] = resource_type
        if resource_limit:
            context['resource_limit'] = resource_limit
        
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        
        self.resource_type = resource_type
        self.resource_limit = resource_limit