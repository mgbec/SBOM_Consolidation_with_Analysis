"""
SBOM document data model for Software Bill of Materials.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum
import json
import uuid

from .dependency import Dependency
from .risk_analysis import RiskAnalysis, SecurityRecommendations


class RelationshipType(Enum):
    """Types of component relationships."""
    DEPENDS_ON = "depends_on"
    DEPENDENCY_OF = "dependency_of"
    CONTAINS = "contains"
    CONTAINED_BY = "contained_by"
    VARIANT_OF = "variant_of"
    BUILD_TOOL_OF = "build_tool_of"
    DEV_TOOL_OF = "dev_tool_of"
    TEST_TOOL_OF = "test_tool_of"
    RUNTIME_DEPENDENCY_OF = "runtime_dependency_of"
    OPTIONAL_DEPENDENCY_OF = "optional_dependency_of"
    PROVIDED_DEPENDENCY_OF = "provided_dependency_of"


class SBOMFormat(Enum):
    """Supported SBOM formats."""
    SPDX = "spdx"
    CYCLONEDX = "cyclonedx"
    SWID = "swid"
    CUSTOM = "custom"


@dataclass
class ComponentRelationship:
    """
    Represents a relationship between two components in an SBOM.
    """
    
    source_component: str
    target_component: str
    relationship_type: RelationshipType
    description: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization processing."""
        if isinstance(self.relationship_type, str):
            try:
                self.relationship_type = RelationshipType(self.relationship_type.lower())
            except ValueError:
                self.relationship_type = RelationshipType.DEPENDS_ON
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert relationship to dictionary."""
        return {
            "source_component": self.source_component,
            "target_component": self.target_component,
            "relationship_type": self.relationship_type.value,
            "description": self.description,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ComponentRelationship':
        """Create relationship from dictionary."""
        relationship_type = data.get("relationship_type", "depends_on")
        if isinstance(relationship_type, str):
            try:
                relationship_type = RelationshipType(relationship_type.lower())
            except ValueError:
                relationship_type = RelationshipType.DEPENDS_ON
        
        return cls(
            source_component=data["source_component"],
            target_component=data["target_component"],
            relationship_type=relationship_type,
            description=data.get("description"),
            metadata=data.get("metadata", {})
        )


@dataclass
class SBOMDocument:
    """
    Represents a complete Software Bill of Materials document.
    
    This class encapsulates all information in an SBOM including components,
    relationships, metadata, and AI-powered analysis results.
    """
    
    document_id: str
    creation_time: datetime
    creator: str
    components: List[Dependency]
    relationships: List[ComponentRelationship] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    format_version: str = "1.0"
    sbom_format: SBOMFormat = SBOMFormat.CUSTOM
    document_name: Optional[str] = None
    document_namespace: Optional[str] = None
    source_repository: Optional[str] = None
    license_list_version: Optional[str] = None
    tools: List[str] = field(default_factory=list)
    risk_analysis: Optional[RiskAnalysis] = None
    security_recommendations: Optional[SecurityRecommendations] = None
    
    def __post_init__(self):
        """Post-initialization processing."""
        # Generate document ID if not provided
        if not self.document_id:
            self.document_id = str(uuid.uuid4())
        
        # Set creation time if not provided
        if not self.creation_time:
            self.creation_time = datetime.utcnow()
        
        # Handle enum conversion
        if isinstance(self.sbom_format, str):
            try:
                self.sbom_format = SBOMFormat(self.sbom_format.lower())
            except ValueError:
                self.sbom_format = SBOMFormat.CUSTOM
        
        # Set default document name
        if not self.document_name:
            self.document_name = f"SBOM-{self.document_id[:8]}"
        
        # Add default tool
        if not self.tools:
            self.tools = ["github-sbom-consolidator"]
    
    @property
    def component_count(self) -> int:
        """Get the total number of components."""
        return len(self.components)
    
    @property
    def relationship_count(self) -> int:
        """Get the total number of relationships."""
        return len(self.relationships)
    
    @property
    def vulnerable_component_count(self) -> int:
        """Get the number of components with vulnerabilities."""
        return sum(1 for comp in self.components if comp.has_vulnerabilities)
    
    @property
    def total_vulnerability_count(self) -> int:
        """Get the total number of vulnerabilities across all components."""
        return sum(comp.vulnerability_count for comp in self.components)
    
    @property
    def package_managers(self) -> List[str]:
        """Get list of unique package managers in the SBOM."""
        return list(set(comp.package_manager.value for comp in self.components))
    
    @property
    def licenses(self) -> List[str]:
        """Get list of unique licenses in the SBOM."""
        licenses = set()
        for comp in self.components:
            if comp.license:
                licenses.add(comp.license)
        return list(licenses)
    
    def add_component(self, component: Dependency) -> None:
        """
        Add a component to the SBOM.
        
        Args:
            component: Dependency to add
        """
        # Check for duplicates
        for existing in self.components:
            if existing.is_exact_match(component):
                return  # Don't add duplicates
        
        self.components.append(component)
    
    def remove_component(self, component_name: str, version: Optional[str] = None) -> bool:
        """
        Remove a component from the SBOM.
        
        Args:
            component_name: Name of component to remove
            version: Optional version to match
            
        Returns:
            True if component was removed
        """
        for i, comp in enumerate(self.components):
            if comp.name == component_name:
                if version is None or comp.version == version:
                    del self.components[i]
                    return True
        return False
    
    def get_component(self, component_name: str, version: Optional[str] = None) -> Optional[Dependency]:
        """
        Get a component by name and optionally version.
        
        Args:
            component_name: Name of component to find
            version: Optional version to match
            
        Returns:
            Matching component or None
        """
        for comp in self.components:
            if comp.name == component_name:
                if version is None or comp.version == version:
                    return comp
        return None
    
    def add_relationship(self, relationship: ComponentRelationship) -> None:
        """
        Add a relationship to the SBOM.
        
        Args:
            relationship: Relationship to add
        """
        self.relationships.append(relationship)
    
    def get_dependencies_of(self, component_name: str) -> List[str]:
        """
        Get all dependencies of a component.
        
        Args:
            component_name: Name of component
            
        Returns:
            List of dependency names
        """
        dependencies = []
        for rel in self.relationships:
            if (rel.source_component == component_name and 
                rel.relationship_type == RelationshipType.DEPENDS_ON):
                dependencies.append(rel.target_component)
        return dependencies
    
    def get_dependents_of(self, component_name: str) -> List[str]:
        """
        Get all components that depend on a component.
        
        Args:
            component_name: Name of component
            
        Returns:
            List of dependent component names
        """
        dependents = []
        for rel in self.relationships:
            if (rel.target_component == component_name and 
                rel.relationship_type == RelationshipType.DEPENDS_ON):
                dependents.append(rel.source_component)
        return dependents
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive statistics about the SBOM.
        
        Returns:
            Dictionary of statistics
        """
        stats = {
            "document_id": self.document_id,
            "creation_time": self.creation_time.isoformat(),
            "component_count": self.component_count,
            "relationship_count": self.relationship_count,
            "vulnerable_component_count": self.vulnerable_component_count,
            "total_vulnerability_count": self.total_vulnerability_count,
            "package_managers": self.package_managers,
            "license_count": len(self.licenses),
            "licenses": self.licenses,
            "has_risk_analysis": self.risk_analysis is not None,
            "has_security_recommendations": self.security_recommendations is not None
        }
        
        # Add package manager breakdown
        pm_breakdown = {}
        for comp in self.components:
            pm = comp.package_manager.value
            pm_breakdown[pm] = pm_breakdown.get(pm, 0) + 1
        stats["package_manager_breakdown"] = pm_breakdown
        
        # Add dependency type breakdown
        type_breakdown = {}
        for comp in self.components:
            dep_type = comp.dependency_type.value
            type_breakdown[dep_type] = type_breakdown.get(dep_type, 0) + 1
        stats["dependency_type_breakdown"] = type_breakdown
        
        return stats
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert SBOM document to dictionary for serialization.
        
        Returns:
            Dictionary representation of the SBOM
        """
        return {
            "document_id": self.document_id,
            "document_name": self.document_name,
            "document_namespace": self.document_namespace,
            "creation_time": self.creation_time.isoformat(),
            "creator": self.creator,
            "format_version": self.format_version,
            "sbom_format": self.sbom_format.value,
            "source_repository": self.source_repository,
            "license_list_version": self.license_list_version,
            "tools": self.tools,
            "components": [comp.to_dict() for comp in self.components],
            "relationships": [rel.to_dict() for rel in self.relationships],
            "metadata": self.metadata,
            "statistics": self.get_statistics(),
            "risk_analysis": self.risk_analysis.to_dict() if self.risk_analysis else None,
            "security_recommendations": self.security_recommendations.to_dict() if self.security_recommendations else None
        }
    
    def to_json(self) -> str:
        """
        Convert SBOM document to JSON string.
        
        Returns:
            JSON representation of the SBOM
        """
        return json.dumps(self.to_dict(), indent=2, default=str)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SBOMDocument':
        """
        Create SBOM document from dictionary.
        
        Args:
            data: Dictionary containing SBOM data
            
        Returns:
            SBOMDocument instance
        """
        # Parse creation time
        creation_time = data.get("creation_time")
        if isinstance(creation_time, str):
            creation_time = datetime.fromisoformat(creation_time.replace('Z', '+00:00'))
        elif creation_time is None:
            creation_time = datetime.utcnow()
        
        # Parse components
        components = []
        for comp_data in data.get("components", []):
            components.append(Dependency.from_dict(comp_data))
        
        # Parse relationships
        relationships = []
        for rel_data in data.get("relationships", []):
            relationships.append(ComponentRelationship.from_dict(rel_data))
        
        # Parse risk analysis
        risk_analysis = None
        if data.get("risk_analysis"):
            risk_analysis = RiskAnalysis.from_dict(data["risk_analysis"])
        
        # Parse security recommendations
        security_recommendations = None
        if data.get("security_recommendations"):
            security_recommendations = SecurityRecommendations.from_dict(data["security_recommendations"])
        
        return cls(
            document_id=data["document_id"],
            creation_time=creation_time,
            creator=data["creator"],
            components=components,
            relationships=relationships,
            metadata=data.get("metadata", {}),
            format_version=data.get("format_version", "1.0"),
            sbom_format=data.get("sbom_format", "custom"),
            document_name=data.get("document_name"),
            document_namespace=data.get("document_namespace"),
            source_repository=data.get("source_repository"),
            license_list_version=data.get("license_list_version"),
            tools=data.get("tools", []),
            risk_analysis=risk_analysis,
            security_recommendations=security_recommendations
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> 'SBOMDocument':
        """
        Create SBOM document from JSON string.
        
        Args:
            json_str: JSON string containing SBOM data
            
        Returns:
            SBOMDocument instance
        """
        data = json.loads(json_str)
        return cls.from_dict(data)