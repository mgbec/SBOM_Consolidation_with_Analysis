"""
Base classes and interfaces for SBOM generation components.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from enum import Enum

from ..models import Dependency, SBOMDocument


class SBOMFormat(Enum):
    """Supported SBOM output formats."""
    SPDX = "spdx"
    CYCLONEDX = "cyclonedx"
    JSON = "json"


class BaseSBOMGenerator(ABC):
    """Abstract base class for SBOM generation functionality."""
    
    @abstractmethod
    def create_sbom(self, dependencies: List[Dependency], metadata: Dict[str, Any]) -> SBOMDocument:
        """
        Generate an SBOM document from dependencies and metadata.
        
        Args:
            dependencies: List of dependencies to include
            metadata: Additional metadata for the SBOM
            
        Returns:
            Generated SBOM document
        """
        pass
    
    @abstractmethod
    def add_vulnerability_info(self, sbom: SBOMDocument) -> SBOMDocument:
        """
        Enrich SBOM with vulnerability information.
        
        Args:
            sbom: SBOM document to enrich
            
        Returns:
            SBOM document with vulnerability information added
        """
        pass
    
    @abstractmethod
    def add_license_info(self, sbom: SBOMDocument) -> SBOMDocument:
        """
        Enrich SBOM with license information.
        
        Args:
            sbom: SBOM document to enrich
            
        Returns:
            SBOM document with license information added
        """
        pass
    
    @abstractmethod
    def export_format(self, sbom: SBOMDocument, format_type: SBOMFormat) -> str:
        """
        Export SBOM in specified format.
        
        Args:
            sbom: SBOM document to export
            format_type: Target export format
            
        Returns:
            Serialized SBOM in requested format
        """
        pass
    
    @abstractmethod
    def validate_sbom(self, sbom: SBOMDocument) -> bool:
        """
        Validate SBOM document compliance with standards.
        
        Args:
            sbom: SBOM document to validate
            
        Returns:
            True if SBOM is valid
        """
        pass


class BaseFormatter(ABC):
    """Abstract base class for format-specific SBOM formatters."""
    
    @abstractmethod
    def format_sbom(self, sbom: SBOMDocument) -> str:
        """
        Format SBOM document into specific output format.
        
        Args:
            sbom: SBOM document to format
            
        Returns:
            Formatted SBOM as string
        """
        pass
    
    @abstractmethod
    def validate_format(self, formatted_sbom: str) -> bool:
        """
        Validate formatted SBOM against format specification.
        
        Args:
            formatted_sbom: Formatted SBOM string
            
        Returns:
            True if format is valid
        """
        pass
    
    @property
    @abstractmethod
    def format_name(self) -> str:
        """
        Get the name of this format.
        
        Returns:
            Format name (e.g., 'SPDX', 'CycloneDX')
        """
        pass
    
    @property
    @abstractmethod
    def file_extension(self) -> str:
        """
        Get the recommended file extension for this format.
        
        Returns:
            File extension (e.g., '.spdx', '.json')
        """
        pass