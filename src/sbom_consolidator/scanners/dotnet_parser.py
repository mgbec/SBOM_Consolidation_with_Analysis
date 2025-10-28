"""
.NET dependency parser for packages.config, .csproj, and other .NET project files.
"""

import xml.etree.ElementTree as ET
import logging
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..models import Dependency, DependencyType, PackageManager
from .base_scanner import DependencyParser

logger = logging.getLogger(__name__)


class DotNetParser(DependencyParser):
    """
    Parser for .NET dependency files including packages.config, .csproj, .fsproj, and .vbproj files.
    
    This parser handles NuGet package manager and can extract dependencies
    with their versions, target frameworks, and metadata.
    """
    
    def __init__(self):
        """Initialize the .NET parser."""
        self._supported_files = [
            "packages.config",
            "*.csproj",
            "*.fsproj", 
            "*.vbproj",
            "*.vcxproj",
            "Directory.Build.props",
            "Directory.Packages.props",
            "global.json",
            "nuget.config"
        ]
    
    @property
    def supported_files(self) -> List[str]:
        """Get list of file patterns this parser supports."""
        return self._supported_files
    
    @property
    def package_manager(self) -> str:
        """Get the package manager name this parser handles."""
        return "nuget"
    
    def can_parse(self, file_path: Path) -> bool:
        """
        Check if this parser can handle the given file.
        
        Args:
            file_path: Path to the dependency file
            
        Returns:
            True if parser supports this file type
        """
        file_name = file_path.name.lower()
        
        # Direct matches
        if file_name in ["packages.config", "directory.build.props", "directory.packages.props", "global.json", "nuget.config"]:
            return True
        
        # Pattern matches for project files
        if file_name.endswith((".csproj", ".fsproj", ".vbproj", ".vcxproj")):
            return True
        
        return False
    
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
        
        file_name = file_path.name.lower()
        
        try:
            if file_name == "packages.config":
                return self._parse_packages_config(file_path)
            elif file_name.endswith((".csproj", ".fsproj", ".vbproj", ".vcxproj")):
                return self._parse_project_file(file_path)
            elif file_name in ["directory.build.props", "directory.packages.props"]:
                return self._parse_directory_props(file_path)
            elif file_name == "global.json":
                return self._parse_global_json(file_path)
            elif file_name == "nuget.config":
                return self._parse_nuget_config(file_path)
            else:
                logger.warning(f"Unsupported .NET file: {file_name}")
                return []
                
        except Exception as e:
            logger.error(f"Error parsing .NET file {file_path}: {e}")
            return []
    
    def _parse_packages_config(self, file_path: Path) -> List[Dependency]:
        """
        Parse packages.config file (legacy NuGet format).
        
        Args:
            file_path: Path to packages.config
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            for package in root.findall('package'):
                package_id = package.get('id')
                version = package.get('version')
                target_framework = package.get('targetFramework')
                development_dependency = package.get('developmentDependency', 'false').lower() == 'true'
                
                if package_id and version:
                    dep = Dependency(
                        name=package_id,
                        version=version,
                        package_manager=PackageManager.NUGET,
                        dependency_type=DependencyType.DEV if development_dependency else DependencyType.DIRECT,
                        is_dev_dependency=development_dependency,
                        source_file=str(file_path)
                    )
                    
                    # Add .NET specific metadata
                    dep.metadata = {
                        "ecosystem": "nuget",
                        "registry_url": "https://www.nuget.org",
                        "package_url": f"https://www.nuget.org/packages/{package_id}/{version}",
                        "source_file_type": file_path.name,
                        "target_framework": target_framework,
                        "development_dependency": development_dependency
                    }
                    
                    dependencies.append(dep)
            
            logger.info(f"Parsed {len(dependencies)} dependencies from packages.config")
            return dependencies
            
        except ET.ParseError as e:
            logger.error(f"Invalid XML in packages.config {file_path}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error parsing packages.config {file_path}: {e}")
            return []
    
    def _parse_project_file(self, file_path: Path) -> List[Dependency]:
        """
        Parse .NET project file (.csproj, .fsproj, .vbproj).
        
        Args:
            file_path: Path to project file
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Parse PackageReference elements (modern .NET format)
            for package_ref in root.findall('.//PackageReference'):
                package_id = package_ref.get('Include')
                version = package_ref.get('Version')
                
                # Version might be in a child element
                if not version:
                    version_elem = package_ref.find('Version')
                    if version_elem is not None:
                        version = version_elem.text
                
                # Check for private assets (development dependencies)
                private_assets = package_ref.get('PrivateAssets')
                include_assets = package_ref.get('IncludeAssets')
                exclude_assets = package_ref.get('ExcludeAssets')
                
                is_dev_dependency = private_assets == 'all' or 'build' in (private_assets or '')
                
                if package_id and version:
                    dep = self._create_dotnet_dependency(
                        package_id, version, file_path, is_dev_dependency,
                        private_assets=private_assets,
                        include_assets=include_assets,
                        exclude_assets=exclude_assets
                    )
                    dependencies.append(dep)
            
            # Parse Reference elements (assembly references)
            for ref in root.findall('.//Reference'):
                include = ref.get('Include')
                if include and not include.startswith('System.'):  # Skip system assemblies
                    # Try to extract version from Include attribute
                    version = "unknown"
                    if ',' in include:
                        parts = include.split(',')
                        for part in parts[1:]:
                            if 'Version=' in part:
                                version = part.split('Version=')[1].strip()
                                break
                        include = parts[0].strip()
                    
                    dep = self._create_dotnet_dependency(include, version, file_path, False)
                    dep.metadata["reference_type"] = "assembly"
                    dependencies.append(dep)
            
            # Parse ProjectReference elements
            for proj_ref in root.findall('.//ProjectReference'):
                include = proj_ref.get('Include')
                if include:
                    project_name = Path(include).stem
                    dep = self._create_dotnet_dependency(project_name, "project", file_path, False)
                    dep.metadata["reference_type"] = "project"
                    dep.metadata["project_path"] = include
                    dependencies.append(dep)
            
            logger.info(f"Parsed {len(dependencies)} dependencies from {file_path.name}")
            return dependencies
            
        except ET.ParseError as e:
            logger.error(f"Invalid XML in project file {file_path}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error parsing project file {file_path}: {e}")
            return []
    
    def _create_dotnet_dependency(
        self, 
        package_id: str, 
        version: str, 
        file_path: Path, 
        is_dev_dependency: bool,
        **kwargs
    ) -> Dependency:
        """
        Create a .NET dependency object.
        
        Args:
            package_id: Package identifier
            version: Package version
            file_path: Source file path
            is_dev_dependency: Whether it's a development dependency
            **kwargs: Additional metadata
            
        Returns:
            Dependency object
        """
        dep = Dependency(
            name=package_id,
            version=version,
            package_manager=PackageManager.NUGET,
            dependency_type=DependencyType.DEV if is_dev_dependency else DependencyType.DIRECT,
            is_dev_dependency=is_dev_dependency,
            source_file=str(file_path)
        )
        
        # Add .NET specific metadata
        dep.metadata = {
            "ecosystem": "nuget",
            "registry_url": "https://www.nuget.org",
            "package_url": f"https://www.nuget.org/packages/{package_id}/{version}",
            "api_url": f"https://api.nuget.org/v3-flatcontainer/{package_id.lower()}/index.json",
            "source_file_type": file_path.name,
            "project_type": self._detect_project_type(file_path)
        }
        
        # Add additional metadata from kwargs
        dep.metadata.update(kwargs)
        
        return dep
    
    def _detect_project_type(self, file_path: Path) -> str:
        """Detect .NET project type from file extension."""
        extension = file_path.suffix.lower()
        project_types = {
            '.csproj': 'C#',
            '.fsproj': 'F#',
            '.vbproj': 'VB.NET',
            '.vcxproj': 'C++'
        }
        return project_types.get(extension, 'Unknown')
    
    def _parse_directory_props(self, file_path: Path) -> List[Dependency]:
        """
        Parse Directory.Build.props or Directory.Packages.props files.
        
        Args:
            file_path: Path to directory props file
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Parse PackageReference elements
            for package_ref in root.findall('.//PackageReference'):
                package_id = package_ref.get('Include')
                version = package_ref.get('Version')
                
                if package_id and version:
                    dep = self._create_dotnet_dependency(package_id, version, file_path, False)
                    dep.metadata["scope"] = "directory"
                    dependencies.append(dep)
            
            # Parse PackageVersion elements (Central Package Management)
            for package_version in root.findall('.//PackageVersion'):
                package_id = package_version.get('Include')
                version = package_version.get('Version')
                
                if package_id and version:
                    dep = self._create_dotnet_dependency(package_id, version, file_path, False)
                    dep.metadata["scope"] = "central_management"
                    dep.dependency_type = DependencyType.OPTIONAL
                    dependencies.append(dep)
            
            logger.info(f"Parsed {len(dependencies)} dependencies from {file_path.name}")
            return dependencies
            
        except ET.ParseError as e:
            logger.error(f"Invalid XML in directory props file {file_path}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error parsing directory props file {file_path}: {e}")
            return []
    
    def _parse_global_json(self, file_path: Path) -> List[Dependency]:
        """
        Parse global.json file.
        
        Args:
            file_path: Path to global.json
            
        Returns:
            List of dependencies (typically SDK versions)
        """
        dependencies = []
        
        try:
            import json
            
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Parse SDK version
            if 'sdk' in data and 'version' in data['sdk']:
                sdk_version = data['sdk']['version']
                dep = Dependency(
                    name="Microsoft.NETCore.App",
                    version=sdk_version,
                    package_manager=PackageManager.NUGET,
                    dependency_type=DependencyType.DIRECT,
                    source_file=str(file_path)
                )
                
                dep.metadata = {
                    "ecosystem": "dotnet",
                    "component_type": "sdk",
                    "source_file_type": file_path.name
                }
                
                dependencies.append(dep)
            
            # Parse MSBuild SDKs
            if 'msbuild-sdks' in data:
                for sdk_name, sdk_version in data['msbuild-sdks'].items():
                    dep = Dependency(
                        name=sdk_name,
                        version=sdk_version,
                        package_manager=PackageManager.NUGET,
                        dependency_type=DependencyType.DIRECT,
                        source_file=str(file_path)
                    )
                    
                    dep.metadata = {
                        "ecosystem": "dotnet",
                        "component_type": "msbuild_sdk",
                        "source_file_type": file_path.name
                    }
                    
                    dependencies.append(dep)
            
            logger.info(f"Parsed {len(dependencies)} dependencies from global.json")
            return dependencies
            
        except Exception as e:
            logger.error(f"Error parsing global.json {file_path}: {e}")
            return []
    
    def _parse_nuget_config(self, file_path: Path) -> List[Dependency]:
        """
        Parse nuget.config file.
        
        Note: nuget.config typically doesn't contain dependencies directly,
        but contains package source configurations.
        
        Args:
            file_path: Path to nuget.config
            
        Returns:
            Empty list (config files don't contain direct dependencies)
        """
        # nuget.config files contain configuration, not dependencies
        logger.debug(f"NuGet config file {file_path} doesn't contain direct dependencies")
        return []
    
    def get_metadata(self, dependency: Dependency) -> Dict[str, Any]:
        """
        Retrieve additional metadata for a .NET dependency.
        
        Args:
            dependency: The dependency to get metadata for
            
        Returns:
            Dictionary of additional metadata
        """
        metadata = {
            "package_manager": dependency.package_manager.value,
            "registry": "nuget",
            "ecosystem": "dotnet",
            "language": "csharp"  # Default to C#, could be F# or VB.NET
        }
        
        # Add package-specific URLs
        if dependency.name:
            package_name_lower = dependency.name.lower()
            metadata.update({
                "nuget_url": f"https://www.nuget.org/packages/{dependency.name}/{dependency.version}",
                "nuget_api_url": f"https://api.nuget.org/v3-flatcontainer/{package_name_lower}/index.json",
                "nuget_download_url": f"https://api.nuget.org/v3-flatcontainer/{package_name_lower}/{dependency.version}/{package_name_lower}.{dependency.version}.nupkg"
            })
        
        return metadata