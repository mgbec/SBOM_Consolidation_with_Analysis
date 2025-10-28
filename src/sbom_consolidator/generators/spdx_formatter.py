"""
SPDX formatter for exporting SBOM documents in SPDX format.
"""

import logging
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path

from ..models import SBOMDocument, Dependency, ComponentRelationship, RelationshipType
from .base_generator import BaseFormatter

logger = logging.getLogger(__name__)


class SPDXFormatter(BaseFormatter):
    """
    Formatter for SPDX (Software Package Data Exchange) format.
    
    This formatter converts SBOM documents to SPDX format compliant with
    the SPDX specification version 2.3.
    """
    
    def __init__(self):
        """Initialize the SPDX formatter."""
        self.spdx_version = "SPDX-2.3"
        self.data_license = "CC0-1.0"
    
    @property
    def format_name(self) -> str:
        """Get the name of this format."""
        return "SPDX"
    
    @property
    def file_extension(self) -> str:
        """Get the recommended file extension for this format."""
        return ".spdx"
    
    def format_sbom(self, sbom: SBOMDocument) -> str:
        """
        Format SBOM document into SPDX output format.
        
        Args:
            sbom: SBOM document to format
            
        Returns:
            Formatted SBOM as SPDX string
        """
        logger.info(f"Formatting SBOM {sbom.document_id} as SPDX")
        
        spdx_lines = []
        
        # Document creation information
        spdx_lines.extend(self._format_document_header(sbom))
        
        # Package information (root package)
        spdx_lines.extend(self._format_root_package(sbom))
        
        # Component packages
        for component in sbom.components:
            spdx_lines.extend(self._format_component_package(component, sbom))
        
        # Relationships
        spdx_lines.extend(self._format_relationships(sbom))
        
        spdx_content = "\n".join(spdx_lines)
        
        logger.info(f"Generated SPDX document with {len(sbom.components)} packages")
        return spdx_content
    
    def _format_document_header(self, sbom: SBOMDocument) -> List[str]:
        """Format SPDX document header section."""
        lines = []
        
        # SPDX version and data license
        lines.append(f"SPDXVersion: {self.spdx_version}")
        lines.append(f"DataLicense: {self.data_license}")
        lines.append("")
        
        # Document information
        lines.append(f"SPDXID: SPDXRef-DOCUMENT")
        lines.append(f"DocumentName: {sbom.document_name or sbom.document_id}")
        
        if sbom.document_namespace:
            lines.append(f"DocumentNamespace: {sbom.document_namespace}")
        else:
            # Generate namespace from document ID
            lines.append(f"DocumentNamespace: https://github.com/sbom-consolidator/{sbom.document_id}")
        
        # Creation info
        lines.append(f"CreationInfo:")
        lines.append(f"Created: {self._format_datetime(sbom.creation_time)}")
        lines.append(f"Creators: Tool: {sbom.creator}")
        
        if sbom.license_list_version:
            lines.append(f"LicenseListVersion: {sbom.license_list_version}")
        
        lines.append("")
        
        return lines
    
    def _format_root_package(self, sbom: SBOMDocument) -> List[str]:
        """Format root package information."""
        lines = []
        
        # Root package represents the analyzed repository/project
        lines.append("PackageName: RootPackage")
        lines.append("SPDXID: SPDXRef-Package-RootPackage")
        
        if sbom.source_repository:
            lines.append(f"PackageDownloadLocation: {sbom.source_repository}")
        else:
            lines.append("PackageDownloadLocation: NOASSERTION")
        
        lines.append("FilesAnalyzed: false")
        lines.append("PackageLicenseConcluded: NOASSERTION")
        lines.append("PackageLicenseDeclared: NOASSERTION")
        lines.append("PackageCopyrightText: NOASSERTION")
        
        # Add package metadata
        if sbom.metadata:
            for key, value in sbom.metadata.items():
                if isinstance(value, (str, int, float, bool)):
                    lines.append(f"PackageComment: {key}: {value}")
        
        lines.append("")
        
        return lines
    
    def _format_component_package(self, component: Dependency, sbom: SBOMDocument) -> List[str]:
        """Format a component as an SPDX package."""
        lines = []
        
        # Package name and SPDX ID
        package_name = self._sanitize_package_name(component.name)
        spdx_id = f"SPDXRef-Package-{package_name}-{component.version}"
        spdx_id = self._sanitize_spdx_id(spdx_id)
        
        lines.append(f"PackageName: {component.name}")
        lines.append(f"SPDXID: {spdx_id}")
        lines.append(f"PackageVersion: {component.version}")
        
        # Package manager and ecosystem
        if component.package_manager:
            lines.append(f"PackageSupplier: Organization: {component.package_manager.value}")
        
        # Download location
        download_url = self._get_download_url(component)
        lines.append(f"PackageDownloadLocation: {download_url}")
        
        # Files analyzed (typically false for package dependencies)
        lines.append("FilesAnalyzed: false")
        
        # License information
        license_concluded = component.license or "NOASSERTION"
        lines.append(f"PackageLicenseConcluded: {license_concluded}")
        lines.append(f"PackageLicenseDeclared: {license_concluded}")
        
        # Copyright
        lines.append("PackageCopyrightText: NOASSERTION")
        
        # Package verification (checksums)
        if component.hash_value:
            hash_algorithm = component.hash_algorithm.upper()
            lines.append(f"PackageChecksum: {hash_algorithm}: {component.hash_value}")
        
        # External references
        external_refs = self._get_external_references(component)
        for ref in external_refs:
            lines.append(f"ExternalRef: {ref}")
        
        # Package comment with metadata
        comments = []
        if component.description:
            comments.append(f"Description: {component.description}")
        
        if component.source_file:
            comments.append(f"Source File: {Path(component.source_file).name}")
        
        if component.dependency_type:
            comments.append(f"Dependency Type: {component.dependency_type.value}")
        
        if component.scope:
            comments.append(f"Scope: {component.scope}")
        
        if component.vulnerabilities:
            comments.append(f"Vulnerabilities: {len(component.vulnerabilities)} found")
        
        if comments:
            lines.append(f"PackageComment: {'; '.join(comments)}")
        
        lines.append("")
        
        return lines
    
    def _format_relationships(self, sbom: SBOMDocument) -> List[str]:
        """Format SPDX relationships."""
        lines = []
        
        if not sbom.relationships:
            # Create basic relationships if none exist
            for component in sbom.components:
                package_name = self._sanitize_package_name(component.name)
                spdx_id = f"SPDXRef-Package-{package_name}-{component.version}"
                spdx_id = self._sanitize_spdx_id(spdx_id)
                
                # Root package depends on component
                lines.append(f"Relationship: SPDXRef-Package-RootPackage DEPENDS_ON {spdx_id}")
        else:
            # Format existing relationships
            for relationship in sbom.relationships:
                spdx_relationship = self._convert_relationship_type(relationship.relationship_type)
                source_id = self._convert_to_spdx_id(relationship.source_component)
                target_id = self._convert_to_spdx_id(relationship.target_component)
                
                lines.append(f"Relationship: {source_id} {spdx_relationship} {target_id}")
        
        return lines
    
    def _sanitize_package_name(self, name: str) -> str:
        """Sanitize package name for SPDX compatibility."""
        # Replace invalid characters with hyphens
        sanitized = name.replace(":", "-").replace("/", "-").replace("@", "-")
        # Remove consecutive hyphens
        while "--" in sanitized:
            sanitized = sanitized.replace("--", "-")
        return sanitized.strip("-")
    
    def _sanitize_spdx_id(self, spdx_id: str) -> str:
        """Sanitize SPDX ID to ensure compliance."""
        # SPDX IDs must match pattern: SPDXRef-[A-Za-z0-9.-]+
        sanitized = ""
        for char in spdx_id:
            if char.isalnum() or char in ".-":
                sanitized += char
            else:
                sanitized += "-"
        
        # Remove consecutive hyphens
        while "--" in sanitized:
            sanitized = sanitized.replace("--", "-")
        
        return sanitized.strip("-")
    
    def _get_download_url(self, component: Dependency) -> str:
        """Get download URL for component."""
        if component.download_url:
            return component.download_url
        
        # Generate download URL based on package manager
        pm = component.package_manager.value
        name = component.name
        version = component.version
        
        if pm in ["npm", "yarn"]:
            return f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"
        elif pm in ["pip", "pipenv", "poetry"]:
            return f"https://pypi.org/project/{name}/{version}/"
        elif pm in ["maven", "gradle"] and ":" in name:
            group_id, artifact_id = name.split(":", 1)
            path = group_id.replace(".", "/")
            return f"https://repo1.maven.org/maven2/{path}/{artifact_id}/{version}/{artifact_id}-{version}.jar"
        elif pm == "nuget":
            return f"https://www.nuget.org/packages/{name}/{version}"
        
        return "NOASSERTION"
    
    def _get_external_references(self, component: Dependency) -> List[str]:
        """Get external references for component."""
        refs = []
        
        pm = component.package_manager.value
        name = component.name
        
        # Package manager specific references
        if pm in ["npm", "yarn"]:
            refs.append(f"PACKAGE-MANAGER npm {name}")
            refs.append(f"PACKAGE_MANAGER_URL https://www.npmjs.com/package/{name}")
        elif pm in ["pip", "pipenv", "poetry"]:
            refs.append(f"PACKAGE-MANAGER pypi {name}")
            refs.append(f"PACKAGE_MANAGER_URL https://pypi.org/project/{name}/")
        elif pm in ["maven", "gradle"]:
            refs.append(f"PACKAGE-MANAGER maven {name}")
            if ":" in name:
                group_id, artifact_id = name.split(":", 1)
                refs.append(f"PACKAGE_MANAGER_URL https://mvnrepository.com/artifact/{group_id}/{artifact_id}")
        elif pm == "nuget":
            refs.append(f"PACKAGE-MANAGER nuget {name}")
            refs.append(f"PACKAGE_MANAGER_URL https://www.nuget.org/packages/{name}/")
        
        # Add PURL (Package URL) if possible
        purl = self._generate_purl(component)
        if purl:
            refs.append(f"PACKAGE-URL {purl}")
        
        return refs
    
    def _generate_purl(self, component: Dependency) -> str:
        """Generate Package URL (PURL) for component."""
        pm = component.package_manager.value
        name = component.name
        version = component.version
        
        # PURL format: pkg:type/namespace/name@version
        purl_types = {
            "npm": "npm",
            "yarn": "npm",
            "pip": "pypi",
            "pipenv": "pypi",
            "poetry": "pypi",
            "maven": "maven",
            "gradle": "maven",
            "nuget": "nuget"
        }
        
        purl_type = purl_types.get(pm)
        if not purl_type:
            return ""
        
        if purl_type == "maven" and ":" in name:
            group_id, artifact_id = name.split(":", 1)
            return f"pkg:maven/{group_id}/{artifact_id}@{version}"
        else:
            return f"pkg:{purl_type}/{name}@{version}"
    
    def _convert_relationship_type(self, rel_type: RelationshipType) -> str:
        """Convert internal relationship type to SPDX relationship."""
        mapping = {
            RelationshipType.DEPENDS_ON: "DEPENDS_ON",
            RelationshipType.DEPENDENCY_OF: "DEPENDENCY_OF",
            RelationshipType.CONTAINS: "CONTAINS",
            RelationshipType.CONTAINED_BY: "CONTAINED_BY",
            RelationshipType.VARIANT_OF: "VARIANT_OF",
            RelationshipType.BUILD_TOOL_OF: "BUILD_TOOL_OF",
            RelationshipType.DEV_TOOL_OF: "DEV_TOOL_OF",
            RelationshipType.TEST_TOOL_OF: "TEST_TOOL_OF",
            RelationshipType.RUNTIME_DEPENDENCY_OF: "RUNTIME_DEPENDENCY_OF",
            RelationshipType.OPTIONAL_DEPENDENCY_OF: "OPTIONAL_DEPENDENCY_OF",
            RelationshipType.PROVIDED_DEPENDENCY_OF: "PROVIDED_DEPENDENCY_OF"
        }
        
        return mapping.get(rel_type, "DEPENDS_ON")
    
    def _convert_to_spdx_id(self, component_name: str) -> str:
        """Convert component name to SPDX ID."""
        if component_name.startswith("SPDXRef-"):
            return component_name
        
        if component_name.startswith("root:"):
            return "SPDXRef-Package-RootPackage"
        
        # Extract name and version if in format "name@version"
        if "@" in component_name:
            name, version = component_name.rsplit("@", 1)
            package_name = self._sanitize_package_name(name)
            spdx_id = f"SPDXRef-Package-{package_name}-{version}"
        else:
            package_name = self._sanitize_package_name(component_name)
            spdx_id = f"SPDXRef-Package-{package_name}"
        
        return self._sanitize_spdx_id(spdx_id)
    
    def _format_datetime(self, dt: datetime) -> str:
        """Format datetime for SPDX."""
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    
    def validate_format(self, formatted_sbom: str) -> bool:
        """
        Validate formatted SBOM against SPDX specification.
        
        Args:
            formatted_sbom: Formatted SBOM string
            
        Returns:
            True if format is valid
        """
        validation_errors = []
        lines = formatted_sbom.split("\n")
        
        # Check required fields
        required_fields = [
            "SPDXVersion:",
            "DataLicense:",
            "SPDXID: SPDXRef-DOCUMENT",
            "DocumentName:",
            "DocumentNamespace:",
            "CreationInfo:",
            "Created:"
        ]
        
        for required_field in required_fields:
            if not any(line.startswith(required_field) for line in lines):
                validation_errors.append(f"Missing required field: {required_field}")
        
        # Check SPDX version
        version_lines = [line for line in lines if line.startswith("SPDXVersion:")]
        if version_lines and not version_lines[0].endswith(self.spdx_version):
            validation_errors.append(f"Invalid SPDX version, expected {self.spdx_version}")
        
        # Check data license
        license_lines = [line for line in lines if line.startswith("DataLicense:")]
        if license_lines and not license_lines[0].endswith(self.data_license):
            validation_errors.append(f"Invalid data license, expected {self.data_license}")
        
        # Log validation results
        if validation_errors:
            logger.warning(f"SPDX validation failed with {len(validation_errors)} errors:")
            for error in validation_errors:
                logger.warning(f"  - {error}")
            return False
        else:
            logger.info("SPDX format validation passed")
            return True