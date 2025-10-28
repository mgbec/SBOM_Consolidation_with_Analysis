"""
Main SBOM generator that creates standardized SBOM documents from dependencies.
"""

import logging
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from ..models import Repository, Dependency, SBOMDocument, ComponentRelationship, RelationshipType
from ..config import get_config
from .base_generator import BaseSBOMGenerator, SBOMFormat

logger = logging.getLogger(__name__)


class SBOMGenerator(BaseSBOMGenerator):
    """
    Main SBOM generator that creates standardized SBOM documents from dependencies.
    
    This class implements the base generator interface and provides functionality
    to create SBOM documents with metadata enrichment, vulnerability information,
    and license data.
    """
    
    def __init__(self):
        """Initialize the SBOM generator."""
        self.config = get_config()
        
        # Statistics tracking
        self._generation_statistics = {
            "sboms_generated": 0,
            "components_processed": 0,
            "vulnerabilities_found": 0,
            "licenses_detected": 0,
            "errors": []
        }
        
        # Initialize external services
        self._vulnerability_service = None
        self._license_service = None
        
        # Initialize formatters
        self._formatters = {}
        self._initialize_formatters()
    
    def _initialize_formatters(self) -> None:
        """Initialize SBOM formatters."""
        try:
            from .spdx_formatter import SPDXFormatter
            from .cyclonedx_formatter import CycloneDXFormatter
            
            self._formatters[SBOMFormat.SPDX] = SPDXFormatter()
            self._formatters[SBOMFormat.CYCLONEDX] = CycloneDXFormatter()
            
            logger.info(f"Initialized {len(self._formatters)} SBOM formatters")
            
        except ImportError as e:
            logger.warning(f"Failed to import some formatters: {e}")
    
    def create_sbom(self, dependencies: List[Dependency], metadata: Dict[str, Any]) -> SBOMDocument:
        """
        Generate an SBOM document from dependencies and metadata.
        
        Args:
            dependencies: List of dependencies to include
            metadata: Additional metadata for the SBOM
            
        Returns:
            Generated SBOM document
        """
        logger.info(f"Creating SBOM with {len(dependencies)} dependencies")
        
        # Generate unique document ID
        document_id = str(uuid.uuid4())
        
        # Create SBOM document
        sbom = SBOMDocument(
            document_id=document_id,
            creation_time=datetime.utcnow(),
            creator="github-sbom-consolidator",
            components=dependencies.copy(),
            metadata=metadata.copy()
        )
        
        # Set document metadata from input
        if "repository" in metadata:
            sbom.source_repository = metadata["repository"]
            sbom.document_name = f"SBOM-{metadata.get('repository_name', 'unknown')}"
        
        if "namespace" in metadata:
            sbom.document_namespace = metadata["namespace"]
        
        # Generate component relationships
        self._generate_relationships(sbom)
        
        # Enrich with additional metadata
        self._enrich_component_metadata(sbom)
        
        # Update statistics
        self._generation_statistics["sboms_generated"] += 1
        self._generation_statistics["components_processed"] += len(dependencies)
        
        logger.info(f"Created SBOM {document_id} with {sbom.component_count} components")
        return sbom
    
    def _generate_relationships(self, sbom: SBOMDocument) -> None:
        """
        Generate component relationships based on dependency information.
        
        Args:
            sbom: SBOM document to add relationships to
        """
        # Group dependencies by source repository/file
        source_groups = {}
        for component in sbom.components:
            source = component.source_repository or component.source_file or "unknown"
            if source not in source_groups:
                source_groups[source] = []
            source_groups[source].append(component)
        
        # Create relationships within each source group
        for source, components in source_groups.items():
            # Create root component for the source
            root_component = f"root:{source}"
            
            for component in components:
                # Create dependency relationship
                relationship = ComponentRelationship(
                    source_component=root_component,
                    target_component=component.full_name,
                    relationship_type=RelationshipType.DEPENDS_ON,
                    description=f"Root depends on {component.name}"
                )
                sbom.add_relationship(relationship)
                
                # Create transitive relationships for nested dependencies
                if component.dependency_type.value == "transitive":
                    # Find potential parent dependencies
                    for other_component in components:
                        if (other_component != component and 
                            other_component.dependency_type.value == "direct" and
                            other_component.package_manager == component.package_manager):
                            
                            transitive_rel = ComponentRelationship(
                                source_component=other_component.full_name,
                                target_component=component.full_name,
                                relationship_type=RelationshipType.DEPENDS_ON,
                                description=f"Transitive dependency"
                            )
                            sbom.add_relationship(transitive_rel)
                            break
    
    def _enrich_component_metadata(self, sbom: SBOMDocument) -> None:
        """
        Enrich components with additional metadata.
        
        Args:
            sbom: SBOM document to enrich
        """
        for component in sbom.components:
            # Add package manager specific metadata
            self._add_package_manager_metadata(component)
            
            # Add registry information
            self._add_registry_metadata(component)
            
            # Add file information
            self._add_file_metadata(component)
    
    def _add_package_manager_metadata(self, component: Dependency) -> None:
        """Add package manager specific metadata to component."""
        if not component.metadata:
            component.metadata = {}
        
        pm = component.package_manager.value
        
        # Add ecosystem information
        ecosystem_mapping = {
            "npm": "npm",
            "yarn": "npm", 
            "pip": "pypi",
            "pipenv": "pypi",
            "poetry": "pypi",
            "maven": "maven",
            "gradle": "maven",
            "nuget": "nuget"
        }
        
        component.metadata["ecosystem"] = ecosystem_mapping.get(pm, pm)
        component.metadata["package_manager"] = pm
        
        # Add language information
        language_mapping = {
            "npm": "javascript",
            "yarn": "javascript",
            "pip": "python",
            "pipenv": "python", 
            "poetry": "python",
            "maven": "java",
            "gradle": "java",
            "nuget": "csharp"
        }
        
        component.metadata["language"] = language_mapping.get(pm, "unknown")
    
    def _add_registry_metadata(self, component: Dependency) -> None:
        """Add registry and repository metadata to component."""
        if not component.metadata:
            component.metadata = {}
        
        pm = component.package_manager.value
        name = component.name
        version = component.version
        
        # Add registry URLs based on package manager
        if pm in ["npm", "yarn"]:
            component.metadata.update({
                "registry_url": "https://registry.npmjs.org",
                "package_url": f"https://www.npmjs.com/package/{name}",
                "download_url": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"
            })
        elif pm in ["pip", "pipenv", "poetry"]:
            component.metadata.update({
                "registry_url": "https://pypi.org",
                "package_url": f"https://pypi.org/project/{name}/",
                "api_url": f"https://pypi.org/pypi/{name}/json"
            })
        elif pm in ["maven", "gradle"]:
            if ":" in name:
                group_id, artifact_id = name.split(":", 1)
                path = group_id.replace(".", "/")
                component.metadata.update({
                    "registry_url": "https://repo1.maven.org/maven2",
                    "package_url": f"https://mvnrepository.com/artifact/{group_id}/{artifact_id}",
                    "download_url": f"https://repo1.maven.org/maven2/{path}/{artifact_id}/{version}/{artifact_id}-{version}.jar"
                })
        elif pm == "nuget":
            component.metadata.update({
                "registry_url": "https://www.nuget.org",
                "package_url": f"https://www.nuget.org/packages/{name}/",
                "api_url": f"https://api.nuget.org/v3-flatcontainer/{name.lower()}/index.json"
            })
    
    def _add_file_metadata(self, component: Dependency) -> None:
        """Add file and source metadata to component."""
        if not component.metadata:
            component.metadata = {}
        
        # Add source file information
        if component.source_file:
            source_path = Path(component.source_file)
            component.metadata.update({
                "source_file": component.source_file,
                "source_file_name": source_path.name,
                "source_file_type": self._detect_file_type(source_path.name)
            })
        
        # Add repository information
        if component.source_repository:
            component.metadata["source_repository"] = component.source_repository
    
    def _detect_file_type(self, filename: str) -> str:
        """Detect the type of source file."""
        file_types = {
            "package.json": "npm_manifest",
            "package-lock.json": "npm_lock",
            "yarn.lock": "yarn_lock",
            "requirements.txt": "pip_requirements",
            "setup.py": "python_setup",
            "pyproject.toml": "python_project",
            "Pipfile": "pipenv_manifest",
            "pom.xml": "maven_manifest",
            "build.gradle": "gradle_build",
            "packages.config": "nuget_config",
            ".csproj": "dotnet_project",
            ".fsproj": "fsharp_project",
            ".vbproj": "vbnet_project"
        }
        
        for pattern, file_type in file_types.items():
            if filename.endswith(pattern):
                return file_type
        
        return "unknown"
    
    def add_vulnerability_info(self, sbom: SBOMDocument) -> SBOMDocument:
        """
        Enrich SBOM with vulnerability information.
        
        Args:
            sbom: SBOM document to enrich
            
        Returns:
            SBOM document with vulnerability information added
        """
        if not self.config.scanning.vulnerability_check:
            logger.info("Vulnerability checking disabled in configuration")
            return sbom
        
        logger.info(f"Adding vulnerability information to SBOM {sbom.document_id}")
        
        vulnerabilities_found = 0
        
        for component in sbom.components:
            try:
                # Get vulnerability information for component
                vulns = self._get_component_vulnerabilities(component)
                
                if vulns:
                    component.vulnerabilities.extend(vulns)
                    vulnerabilities_found += len(vulns)
                    
                    # Add vulnerability metadata
                    if not component.metadata:
                        component.metadata = {}
                    component.metadata["vulnerability_check_date"] = datetime.utcnow().isoformat()
                    component.metadata["vulnerability_count"] = len(component.vulnerabilities)
                
            except Exception as e:
                logger.warning(f"Failed to get vulnerabilities for {component.name}: {e}")
                self._generation_statistics["errors"].append(f"Vulnerability check failed for {component.name}: {e}")
        
        # Update statistics
        self._generation_statistics["vulnerabilities_found"] += vulnerabilities_found
        
        # Add vulnerability summary to SBOM metadata
        sbom.metadata["vulnerability_summary"] = {
            "total_vulnerabilities": vulnerabilities_found,
            "vulnerable_components": sum(1 for c in sbom.components if c.vulnerabilities),
            "check_date": datetime.utcnow().isoformat()
        }
        
        logger.info(f"Found {vulnerabilities_found} vulnerabilities across {sbom.component_count} components")
        return sbom
    
    def _get_component_vulnerabilities(self, component: Dependency) -> List[str]:
        """
        Get vulnerability information for a component.
        
        Args:
            component: Component to check for vulnerabilities
            
        Returns:
            List of vulnerability IDs
        """
        # This is a placeholder implementation
        # In a real implementation, this would query vulnerability databases
        # like OSV, NVD, GitHub Security Advisories, etc.
        
        vulnerabilities = []
        
        # Simulate vulnerability checking based on component characteristics
        # This would be replaced with actual vulnerability database queries
        
        # Example: Flag very old versions as potentially vulnerable
        if component.version and component.version != "unknown":
            try:
                # Simple heuristic: versions starting with "0." might be more vulnerable
                if component.version.startswith("0."):
                    vulnerabilities.append(f"PLACEHOLDER-VULN-{component.name}-{component.version}")
            except Exception:
                pass
        
        return vulnerabilities
    
    def add_license_info(self, sbom: SBOMDocument) -> SBOMDocument:
        """
        Enrich SBOM with license information.
        
        Args:
            sbom: SBOM document to enrich
            
        Returns:
            SBOM document with license information added
        """
        if not self.config.scanning.license_detection:
            logger.info("License detection disabled in configuration")
            return sbom
        
        logger.info(f"Adding license information to SBOM {sbom.document_id}")
        
        licenses_found = 0
        
        for component in sbom.components:
            try:
                # Get license information for component
                license_info = self._get_component_license(component)
                
                if license_info:
                    component.license = license_info.get("license")
                    component.license_url = license_info.get("license_url")
                    licenses_found += 1
                    
                    # Add license metadata
                    if not component.metadata:
                        component.metadata = {}
                    component.metadata["license_check_date"] = datetime.utcnow().isoformat()
                    if license_info.get("license_source"):
                        component.metadata["license_source"] = license_info["license_source"]
                
            except Exception as e:
                logger.warning(f"Failed to get license for {component.name}: {e}")
                self._generation_statistics["errors"].append(f"License check failed for {component.name}: {e}")
        
        # Update statistics
        self._generation_statistics["licenses_detected"] += licenses_found
        
        # Add license summary to SBOM metadata
        unique_licenses = set(c.license for c in sbom.components if c.license)
        sbom.metadata["license_summary"] = {
            "total_licensed_components": licenses_found,
            "unique_licenses": list(unique_licenses),
            "license_count": len(unique_licenses),
            "check_date": datetime.utcnow().isoformat()
        }
        
        logger.info(f"Found license information for {licenses_found} components ({len(unique_licenses)} unique licenses)")
        return sbom
    
    def _get_component_license(self, component: Dependency) -> Optional[Dict[str, str]]:
        """
        Get license information for a component.
        
        Args:
            component: Component to get license information for
            
        Returns:
            Dictionary with license information or None
        """
        # This is a placeholder implementation
        # In a real implementation, this would query package registries
        # and license databases to get accurate license information
        
        # Common license mappings for popular packages (placeholder)
        common_licenses = {
            "express": {"license": "MIT", "license_source": "npm_registry"},
            "react": {"license": "MIT", "license_source": "npm_registry"},
            "django": {"license": "BSD-3-Clause", "license_source": "pypi_registry"},
            "requests": {"license": "Apache-2.0", "license_source": "pypi_registry"},
            "junit": {"license": "EPL-2.0", "license_source": "maven_central"},
            "spring-boot": {"license": "Apache-2.0", "license_source": "maven_central"}
        }
        
        # Extract base package name for lookup
        package_name = component.name
        if ":" in package_name:
            package_name = package_name.split(":")[-1]
        
        return common_licenses.get(package_name)
    
    def export_format(self, sbom: SBOMDocument, format_type: SBOMFormat) -> str:
        """
        Export SBOM in specified format.
        
        Args:
            sbom: SBOM document to export
            format_type: Target export format
            
        Returns:
            Serialized SBOM in requested format
        """
        if format_type not in self._formatters:
            raise ValueError(f"Unsupported SBOM format: {format_type}")
        
        formatter = self._formatters[format_type]
        
        try:
            formatted_sbom = formatter.format_sbom(sbom)
            logger.info(f"Exported SBOM {sbom.document_id} in {format_type.value} format")
            return formatted_sbom
        except Exception as e:
            error_msg = f"Failed to export SBOM in {format_type.value} format: {e}"
            logger.error(error_msg)
            self._generation_statistics["errors"].append(error_msg)
            raise
    
    def validate_sbom(self, sbom: SBOMDocument) -> bool:
        """
        Validate SBOM document compliance with standards.
        
        Args:
            sbom: SBOM document to validate
            
        Returns:
            True if SBOM is valid
        """
        validation_errors = []
        
        # Basic validation checks
        if not sbom.document_id:
            validation_errors.append("Missing document ID")
        
        if not sbom.creator:
            validation_errors.append("Missing creator information")
        
        if not sbom.components:
            validation_errors.append("No components in SBOM")
        
        # Component validation
        for i, component in enumerate(sbom.components):
            if not component.name:
                validation_errors.append(f"Component {i} missing name")
            
            if not component.version:
                validation_errors.append(f"Component {i} ({component.name}) missing version")
            
            if not component.package_manager:
                validation_errors.append(f"Component {i} ({component.name}) missing package manager")
        
        # Log validation results
        if validation_errors:
            logger.warning(f"SBOM validation failed with {len(validation_errors)} errors:")
            for error in validation_errors:
                logger.warning(f"  - {error}")
            return False
        else:
            logger.info(f"SBOM {sbom.document_id} passed validation")
            return True
    
    def get_generation_statistics(self) -> Dict[str, Any]:
        """
        Get SBOM generation statistics.
        
        Returns:
            Dictionary of generation statistics
        """
        stats = self._generation_statistics.copy()
        stats["available_formatters"] = list(self._formatters.keys())
        return stats
    
    def reset_statistics(self) -> None:
        """Reset generation statistics."""
        self._generation_statistics = {
            "sboms_generated": 0,
            "components_processed": 0,
            "vulnerabilities_found": 0,
            "licenses_detected": 0,
            "errors": []
        }