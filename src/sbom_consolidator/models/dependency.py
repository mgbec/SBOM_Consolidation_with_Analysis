"""
Dependency data model for software components and packages.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum
import json
import hashlib


class DependencyType(Enum):
    """Types of dependencies."""
    DIRECT = "direct"
    TRANSITIVE = "transitive"
    DEV = "development"
    OPTIONAL = "optional"
    PEER = "peer"


class PackageManager(Enum):
    """Supported package managers."""
    NPM = "npm"
    YARN = "yarn"
    PIP = "pip"
    PIPENV = "pipenv"
    POETRY = "poetry"
    MAVEN = "maven"
    GRADLE = "gradle"
    NUGET = "nuget"
    COMPOSER = "composer"
    RUBYGEMS = "rubygems"
    CARGO = "cargo"
    GO_MOD = "go_mod"
    UNKNOWN = "unknown"


@dataclass
class Dependency:
    """
    Represents a software dependency with metadata and security information.
    
    This class encapsulates all information about a software component
    including version, license, vulnerabilities, and source information.
    """
    
    name: str
    version: str
    package_manager: str
    dependency_type: DependencyType = DependencyType.DIRECT
    license: Optional[str] = None
    license_url: Optional[str] = None
    homepage: Optional[str] = None
    repository_url: Optional[str] = None
    description: Optional[str] = None
    author: Optional[str] = None
    vulnerabilities: List[str] = field(default_factory=list)
    hash_value: Optional[str] = None
    hash_algorithm: str = "sha256"
    source_repository: str = ""
    source_file: str = ""
    scope: Optional[str] = None
    is_dev_dependency: bool = False
    is_optional: bool = False
    download_url: Optional[str] = None
    file_size: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization processing."""
        # Normalize package manager
        if isinstance(self.package_manager, str):
            try:
                self.package_manager = PackageManager(self.package_manager.lower())
            except ValueError:
                self.package_manager = PackageManager.UNKNOWN
        
        # Generate hash if not provided
        if not self.hash_value:
            self.hash_value = self._generate_content_hash()
    
    def _generate_content_hash(self) -> str:
        """
        Generate a content hash for the dependency.
        
        Returns:
            SHA256 hash of dependency content
        """
        content = f"{self.name}:{self.version}:{self.package_manager.value}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    @property
    def full_name(self) -> str:
        """Get the full dependency name with version."""
        return f"{self.name}@{self.version}"
    
    @property
    def has_vulnerabilities(self) -> bool:
        """Check if dependency has known vulnerabilities."""
        return len(self.vulnerabilities) > 0
    
    @property
    def vulnerability_count(self) -> int:
        """Get the number of known vulnerabilities."""
        return len(self.vulnerabilities)
    
    def add_vulnerability(self, vulnerability_id: str) -> None:
        """
        Add a vulnerability ID to the dependency.
        
        Args:
            vulnerability_id: Vulnerability identifier (CVE, GHSA, etc.)
        """
        if vulnerability_id not in self.vulnerabilities:
            self.vulnerabilities.append(vulnerability_id)
    
    def remove_vulnerability(self, vulnerability_id: str) -> None:
        """
        Remove a vulnerability ID from the dependency.
        
        Args:
            vulnerability_id: Vulnerability identifier to remove
        """
        if vulnerability_id in self.vulnerabilities:
            self.vulnerabilities.remove(vulnerability_id)
    
    def is_same_component(self, other: 'Dependency') -> bool:
        """
        Check if this dependency represents the same component as another.
        
        Args:
            other: Another dependency to compare
            
        Returns:
            True if they represent the same component
        """
        return (
            self.name == other.name and
            self.package_manager == other.package_manager
        )
    
    def is_exact_match(self, other: 'Dependency') -> bool:
        """
        Check if this dependency is an exact match with another.
        
        Args:
            other: Another dependency to compare
            
        Returns:
            True if they are exactly the same
        """
        return (
            self.is_same_component(other) and
            self.version == other.version
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert dependency to dictionary for serialization.
        
        Returns:
            Dictionary representation of the dependency
        """
        return {
            "name": self.name,
            "version": self.version,
            "full_name": self.full_name,
            "package_manager": self.package_manager.value,
            "dependency_type": self.dependency_type.value,
            "license": self.license,
            "license_url": self.license_url,
            "homepage": self.homepage,
            "repository_url": self.repository_url,
            "description": self.description,
            "author": self.author,
            "vulnerabilities": self.vulnerabilities,
            "vulnerability_count": self.vulnerability_count,
            "hash_value": self.hash_value,
            "hash_algorithm": self.hash_algorithm,
            "source_repository": self.source_repository,
            "source_file": self.source_file,
            "scope": self.scope,
            "is_dev_dependency": self.is_dev_dependency,
            "is_optional": self.is_optional,
            "download_url": self.download_url,
            "file_size": self.file_size,
            "metadata": self.metadata
        }
    
    def to_json(self) -> str:
        """
        Convert dependency to JSON string.
        
        Returns:
            JSON representation of the dependency
        """
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Dependency':
        """
        Create dependency from dictionary.
        
        Args:
            data: Dictionary containing dependency data
            
        Returns:
            Dependency instance
        """
        # Handle enum conversions
        package_manager = data.get("package_manager", "unknown")
        if isinstance(package_manager, str):
            try:
                package_manager = PackageManager(package_manager.lower())
            except ValueError:
                package_manager = PackageManager.UNKNOWN
        
        dependency_type = data.get("dependency_type", "direct")
        if isinstance(dependency_type, str):
            try:
                dependency_type = DependencyType(dependency_type.lower())
            except ValueError:
                dependency_type = DependencyType.DIRECT
        
        return cls(
            name=data["name"],
            version=data["version"],
            package_manager=package_manager,
            dependency_type=dependency_type,
            license=data.get("license"),
            license_url=data.get("license_url"),
            homepage=data.get("homepage"),
            repository_url=data.get("repository_url"),
            description=data.get("description"),
            author=data.get("author"),
            vulnerabilities=data.get("vulnerabilities", []),
            hash_value=data.get("hash_value"),
            hash_algorithm=data.get("hash_algorithm", "sha256"),
            source_repository=data.get("source_repository", ""),
            source_file=data.get("source_file", ""),
            scope=data.get("scope"),
            is_dev_dependency=data.get("is_dev_dependency", False),
            is_optional=data.get("is_optional", False),
            download_url=data.get("download_url"),
            file_size=data.get("file_size"),
            metadata=data.get("metadata", {})
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> 'Dependency':
        """
        Create dependency from JSON string.
        
        Args:
            json_str: JSON string containing dependency data
            
        Returns:
            Dependency instance
        """
        data = json.loads(json_str)
        return cls.from_dict(data)