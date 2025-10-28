"""
Base classes and interfaces for dependency scanning components.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from pathlib import Path

from ..models import Dependency


class DependencyParser(ABC):
    """Abstract base class for language-specific dependency parsers."""
    
    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """
        Check if this parser can handle the given file.
        
        Args:
            file_path: Path to the dependency file
            
        Returns:
            True if parser supports this file type
        """
        pass
    
    @abstractmethod
    def parse_file(self, file_path: Path) -> List[Dependency]:
        """
        Extract dependency information from the file.
        
        Args:
            file_path: Path to the dependency file
            
        Returns:
            List of dependencies found in the file
        """
        pass
    
    @abstractmethod
    def get_metadata(self, dependency: Dependency) -> Dict[str, Any]:
        """
        Retrieve additional metadata for a dependency.
        
        Args:
            dependency: The dependency to get metadata for
            
        Returns:
            Dictionary of additional metadata
        """
        pass
    
    @property
    @abstractmethod
    def supported_files(self) -> List[str]:
        """
        Get list of file patterns this parser supports.
        
        Returns:
            List of file patterns (e.g., ['package.json', '*.json'])
        """
        pass
    
    @property
    @abstractmethod
    def package_manager(self) -> str:
        """
        Get the package manager name this parser handles.
        
        Returns:
            Package manager name (e.g., 'npm', 'pip', 'maven')
        """
        pass


class BaseScanner(ABC):
    """Abstract base class for repository scanning functionality."""
    
    def __init__(self):
        self._parsers: List[DependencyParser] = []
    
    def register_parser(self, parser: DependencyParser) -> None:
        """
        Register a dependency parser with the scanner.
        
        Args:
            parser: The parser to register
        """
        self._parsers.append(parser)
    
    def get_supported_parsers(self) -> List[DependencyParser]:
        """
        Get list of registered parsers.
        
        Returns:
            List of available dependency parsers
        """
        return self._parsers.copy()
    
    @abstractmethod
    def scan_repository(self, repo_path: Path) -> Dict[str, List[Path]]:
        """
        Scan repository for dependency files.
        
        Args:
            repo_path: Path to the repository root
            
        Returns:
            Dictionary mapping file types to lists of found files
        """
        pass
    
    @abstractmethod
    def parse_dependencies(self, file_path: Path, file_type: str) -> List[Dependency]:
        """
        Parse dependencies from a specific file.
        
        Args:
            file_path: Path to the dependency file
            file_type: Type of dependency file
            
        Returns:
            List of dependencies found in the file
        """
        pass