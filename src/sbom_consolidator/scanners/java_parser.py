"""
Java dependency parser for Maven pom.xml and Gradle build files.
"""

import xml.etree.ElementTree as ET
import logging
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..models import Dependency, DependencyType, PackageManager
from .base_scanner import DependencyParser

logger = logging.getLogger(__name__)


class JavaParser(DependencyParser):
    """
    Parser for Java dependency files including Maven pom.xml and Gradle build files.
    
    This parser handles Maven and Gradle build systems and can extract
    dependencies with their scopes, versions, and metadata.
    """
    
    def __init__(self):
        """Initialize the Java parser."""
        self._supported_files = [
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "gradle.properties"
        ]
    
    @property
    def supported_files(self) -> List[str]:
        """Get list of file patterns this parser supports."""
        return self._supported_files
    
    @property
    def package_manager(self) -> str:
        """Get the package manager name this parser handles."""
        return "maven"
    
    def can_parse(self, file_path: Path) -> bool:
        """
        Check if this parser can handle the given file.
        
        Args:
            file_path: Path to the dependency file
            
        Returns:
            True if parser supports this file type
        """
        return file_path.name in self._supported_files
    
    def parse_file(self, file_path: Path) -> List[Dependency]:
        """
        Extract dependency information from the file.
        
        Args:
            file_path: Path to the dependency file
            
        Returns:
            List of dependencies found in the file
        """
        if not file_path.exists():
            logger.error(f"File does not exist: {file_path}")
            return []
        
        file_name = file_path.name
        
        try:
            if file_name == "pom.xml":
                return self._parse_pom_xml(file_path)
            elif file_name in ["build.gradle", "build.gradle.kts"]:
                return self._parse_gradle_build(file_path)
            elif file_name == "gradle.properties":
                return self._parse_gradle_properties(file_path)
            else:
                logger.warning(f"Unsupported Java file: {file_name}")
                return []
                
        except Exception as e:
            logger.error(f"Error parsing Java file {file_path}: {e}")
            return []
    
    def _parse_pom_xml(self, file_path: Path) -> List[Dependency]:
        """
        Parse Maven pom.xml file.
        
        Args:
            file_path: Path to pom.xml
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Handle XML namespaces
            namespace = self._get_namespace(root)
            ns = {'maven': namespace} if namespace else {}
            
            # Extract properties for variable substitution
            properties = self._extract_properties(root, ns)
            
            # Parse dependencies
            deps_element = root.find('.//maven:dependencies' if namespace else './/dependencies', ns)
            if deps_element is not None:
                for dep_element in deps_element.findall('maven:dependency' if namespace else 'dependency', ns):
                    dep = self._parse_maven_dependency(dep_element, properties, file_path, ns)
                    if dep:
                        dependencies.append(dep)
            
            # Parse dependency management (parent dependencies)
            dep_mgmt = root.find('.//maven:dependencyManagement/maven:dependencies' if namespace else './/dependencyManagement/dependencies', ns)
            if dep_mgmt is not None:
                for dep_element in dep_mgmt.findall('maven:dependency' if namespace else 'dependency', ns):
                    dep = self._parse_maven_dependency(dep_element, properties, file_path, ns, is_managed=True)
                    if dep:
                        dependencies.append(dep)
            
            logger.info(f"Parsed {len(dependencies)} dependencies from pom.xml")
            return dependencies
            
        except ET.ParseError as e:
            logger.error(f"Invalid XML in pom.xml {file_path}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error parsing pom.xml {file_path}: {e}")
            return []
    
    def _get_namespace(self, root) -> Optional[str]:
        """Extract XML namespace from root element."""
        tag = root.tag
        if tag.startswith('{'):
            return tag[1:tag.find('}')]
        return None
    
    def _extract_properties(self, root, ns: Dict[str, str]) -> Dict[str, str]:
        """Extract Maven properties for variable substitution."""
        properties = {}
        
        # Extract properties from properties section
        props_element = root.find('.//maven:properties' if ns else './/properties', ns)
        if props_element is not None:
            for prop in props_element:
                prop_name = prop.tag.split('}')[-1] if '}' in prop.tag else prop.tag
                properties[prop_name] = prop.text or ""
        
        # Add built-in properties
        project_element = root.find('.//maven:project' if ns else './/project', ns) or root
        
        # Extract basic project info
        group_id = self._get_element_text(project_element, 'groupId', ns)
        artifact_id = self._get_element_text(project_element, 'artifactId', ns)
        version = self._get_element_text(project_element, 'version', ns)
        
        if group_id:
            properties['project.groupId'] = group_id
        if artifact_id:
            properties['project.artifactId'] = artifact_id
        if version:
            properties['project.version'] = version
        
        return properties
    
    def _get_element_text(self, parent, tag_name: str, ns: Dict[str, str]) -> Optional[str]:
        """Get text content of an XML element."""
        element = parent.find(f'maven:{tag_name}' if ns else tag_name, ns)
        return element.text if element is not None else None
    
    def _parse_maven_dependency(self, dep_element, properties: Dict[str, str], file_path: Path, ns: Dict[str, str], is_managed: bool = False) -> Optional[Dependency]:
        """
        Parse a single Maven dependency element.
        
        Args:
            dep_element: XML element for the dependency
            properties: Maven properties for substitution
            file_path: Path to the pom.xml file
            ns: XML namespace dictionary
            is_managed: Whether this is from dependencyManagement section
            
        Returns:
            Dependency object or None
        """
        try:
            group_id = self._get_element_text(dep_element, 'groupId', ns)
            artifact_id = self._get_element_text(dep_element, 'artifactId', ns)
            version = self._get_element_text(dep_element, 'version', ns)
            scope = self._get_element_text(dep_element, 'scope', ns) or 'compile'
            optional = self._get_element_text(dep_element, 'optional', ns)
            classifier = self._get_element_text(dep_element, 'classifier', ns)
            type_elem = self._get_element_text(dep_element, 'type', ns) or 'jar'
            
            if not group_id or not artifact_id:
                return None
            
            # Substitute properties in values
            group_id = self._substitute_properties(group_id, properties)
            artifact_id = self._substitute_properties(artifact_id, properties)
            version = self._substitute_properties(version or "unknown", properties)
            
            # Create dependency name in Maven format
            name = f"{group_id}:{artifact_id}"
            
            # Determine dependency type based on scope
            dep_type = self._maven_scope_to_dependency_type(scope, is_managed)
            
            dep = Dependency(
                name=name,
                version=version,
                package_manager=PackageManager.MAVEN,
                dependency_type=dep_type,
                scope=scope,
                is_optional=optional == 'true',
                source_file=str(file_path)
            )
            
            # Add Maven-specific metadata
            dep.metadata = {
                "ecosystem": "maven",
                "registry_url": "https://repo1.maven.org/maven2",
                "group_id": group_id,
                "artifact_id": artifact_id,
                "scope": scope,
                "type": type_elem,
                "is_managed": is_managed,
                "source_file_type": file_path.name
            }
            
            if classifier:
                dep.metadata["classifier"] = classifier
            
            # Add repository URLs
            dep.metadata.update({
                "maven_central_url": f"https://repo1.maven.org/maven2/{group_id.replace('.', '/')}/{artifact_id}/{version}/",
                "mvn_repository_url": f"https://mvnrepository.com/artifact/{group_id}/{artifact_id}/{version}"
            })
            
            return dep
            
        except Exception as e:
            logger.warning(f"Failed to parse Maven dependency: {e}")
            return None
    
    def _substitute_properties(self, value: str, properties: Dict[str, str]) -> str:
        """Substitute Maven properties in a value string."""
        if not value:
            return value
        
        # Pattern to match ${property.name}
        pattern = r'\$\{([^}]+)\}'
        
        def replace_property(match):
            prop_name = match.group(1)
            return properties.get(prop_name, match.group(0))
        
        return re.sub(pattern, replace_property, value)
    
    def _maven_scope_to_dependency_type(self, scope: str, is_managed: bool) -> DependencyType:
        """Convert Maven scope to dependency type."""
        if is_managed:
            return DependencyType.OPTIONAL
        
        scope_mapping = {
            'compile': DependencyType.DIRECT,
            'runtime': DependencyType.DIRECT,
            'provided': DependencyType.OPTIONAL,
            'test': DependencyType.DEV,
            'system': DependencyType.OPTIONAL,
            'import': DependencyType.OPTIONAL
        }
        
        return scope_mapping.get(scope, DependencyType.DIRECT)
    
    def _parse_gradle_build(self, file_path: Path) -> List[Dependency]:
        """
        Parse Gradle build.gradle or build.gradle.kts file.
        
        Args:
            file_path: Path to build.gradle file
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse dependencies block
            dependencies.extend(self._parse_gradle_dependencies_block(content, file_path))
            
            logger.info(f"Parsed {len(dependencies)} dependencies from {file_path.name}")
            return dependencies
            
        except Exception as e:
            logger.error(f"Error parsing Gradle file {file_path}: {e}")
            return []
    
    def _parse_gradle_dependencies_block(self, content: str, file_path: Path) -> List[Dependency]:
        """Parse dependencies from Gradle dependencies block."""
        dependencies = []
        
        # Find dependencies blocks
        dep_blocks = re.findall(r'dependencies\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}', content, re.DOTALL)
        
        for block in dep_blocks:
            # Parse individual dependency declarations
            # Match patterns like: implementation 'group:artifact:version'
            patterns = [
                r"(implementation|api|compile|runtime|testImplementation|testCompile|compileOnly|runtimeOnly|annotationProcessor)\s+['\"]([^'\"]+)['\"]",
                r"(implementation|api|compile|runtime|testImplementation|testCompile|compileOnly|runtimeOnly|annotationProcessor)\s+group:\s*['\"]([^'\"]+)['\"],\s*name:\s*['\"]([^'\"]+)['\"],\s*version:\s*['\"]([^'\"]+)['\"]"
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, block)
                for match in matches:
                    if len(match) == 2:
                        # Simple format: 'group:artifact:version'
                        config, coords = match
                        dep = self._parse_gradle_coordinate(coords, config, file_path)
                        if dep:
                            dependencies.append(dep)
                    elif len(match) == 4:
                        # Explicit format: group: 'x', name: 'y', version: 'z'
                        config, group, name, version = match
                        coords = f"{group}:{name}:{version}"
                        dep = self._parse_gradle_coordinate(coords, config, file_path)
                        if dep:
                            dependencies.append(dep)
        
        return dependencies
    
    def _parse_gradle_coordinate(self, coordinate: str, configuration: str, file_path: Path) -> Optional[Dependency]:
        """
        Parse Gradle dependency coordinate.
        
        Args:
            coordinate: Dependency coordinate (group:artifact:version)
            configuration: Gradle configuration (implementation, testImplementation, etc.)
            file_path: Path to the build file
            
        Returns:
            Dependency object or None
        """
        try:
            parts = coordinate.split(':')
            if len(parts) < 2:
                return None
            
            group_id = parts[0]
            artifact_id = parts[1]
            version = parts[2] if len(parts) > 2 else "unknown"
            classifier = parts[3] if len(parts) > 3 else None
            
            # Create dependency name
            name = f"{group_id}:{artifact_id}"
            
            # Determine dependency type based on configuration
            dep_type = self._gradle_config_to_dependency_type(configuration)
            
            dep = Dependency(
                name=name,
                version=version,
                package_manager=PackageManager.GRADLE,
                dependency_type=dep_type,
                scope=configuration,
                source_file=str(file_path)
            )
            
            # Add Gradle-specific metadata
            dep.metadata = {
                "ecosystem": "maven",
                "registry_url": "https://repo1.maven.org/maven2",
                "group_id": group_id,
                "artifact_id": artifact_id,
                "configuration": configuration,
                "source_file_type": file_path.name
            }
            
            if classifier:
                dep.metadata["classifier"] = classifier
            
            # Add repository URLs
            dep.metadata.update({
                "maven_central_url": f"https://repo1.maven.org/maven2/{group_id.replace('.', '/')}/{artifact_id}/{version}/",
                "mvn_repository_url": f"https://mvnrepository.com/artifact/{group_id}/{artifact_id}/{version}"
            })
            
            return dep
            
        except Exception as e:
            logger.warning(f"Failed to parse Gradle coordinate {coordinate}: {e}")
            return None
    
    def _gradle_config_to_dependency_type(self, configuration: str) -> DependencyType:
        """Convert Gradle configuration to dependency type."""
        config_mapping = {
            'implementation': DependencyType.DIRECT,
            'api': DependencyType.DIRECT,
            'compile': DependencyType.DIRECT,
            'runtime': DependencyType.DIRECT,
            'runtimeOnly': DependencyType.DIRECT,
            'testImplementation': DependencyType.DEV,
            'testCompile': DependencyType.DEV,
            'testRuntime': DependencyType.DEV,
            'testRuntimeOnly': DependencyType.DEV,
            'compileOnly': DependencyType.OPTIONAL,
            'annotationProcessor': DependencyType.OPTIONAL
        }
        
        return config_mapping.get(configuration, DependencyType.DIRECT)
    
    def _parse_gradle_properties(self, file_path: Path) -> List[Dependency]:
        """
        Parse gradle.properties file.
        
        Note: gradle.properties typically doesn't contain dependencies directly,
        but may contain version information used in build.gradle files.
        
        Args:
            file_path: Path to gradle.properties
            
        Returns:
            Empty list (properties files don't contain direct dependencies)
        """
        # gradle.properties files don't typically contain dependencies
        # They contain configuration properties that might be used in build.gradle
        logger.debug(f"Gradle properties file {file_path} doesn't contain direct dependencies")
        return []
    
    def get_metadata(self, dependency: Dependency) -> Dict[str, Any]:
        """
        Retrieve additional metadata for a Java dependency.
        
        Args:
            dependency: The dependency to get metadata for
            
        Returns:
            Dictionary of additional metadata
        """
        metadata = {
            "package_manager": dependency.package_manager.value,
            "registry": "maven_central",
            "ecosystem": "maven",
            "language": "java"
        }
        
        # Extract group and artifact from name
        if ':' in dependency.name:
            group_id, artifact_id = dependency.name.split(':', 1)
            
            metadata.update({
                "group_id": group_id,
                "artifact_id": artifact_id,
                "maven_central_url": f"https://repo1.maven.org/maven2/{group_id.replace('.', '/')}/{artifact_id}/{dependency.version}/",
                "mvn_repository_url": f"https://mvnrepository.com/artifact/{group_id}/{artifact_id}/{dependency.version}",
                "maven_search_url": f"https://search.maven.org/artifact/{group_id}/{artifact_id}/{dependency.version}/jar"
            })
        
        return metadata