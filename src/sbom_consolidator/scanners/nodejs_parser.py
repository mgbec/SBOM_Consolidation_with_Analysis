"""
Node.js dependency parser for package.json and lock files.
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..models import Dependency, DependencyType, PackageManager
from .base_scanner import DependencyParser

logger = logging.getLogger(__name__)


class NodeJSParser(DependencyParser):
    """
    Parser for Node.js dependency files including package.json, package-lock.json, and yarn.lock.
    
    This parser handles npm and Yarn package managers and can extract both
    production and development dependencies with their metadata.
    """
    
    def __init__(self):
        """Initialize the Node.js parser."""
        self._supported_files = [
            "package.json",
            "package-lock.json", 
            "yarn.lock",
            "npm-shrinkwrap.json"
        ]
    
    @property
    def supported_files(self) -> List[str]:
        """Get list of file patterns this parser supports."""
        return self._supported_files
    
    @property
    def package_manager(self) -> str:
        """Get the package manager name this parser handles."""
        return "npm"
    
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
            if file_name == "package.json":
                return self._parse_package_json(file_path)
            elif file_name == "package-lock.json":
                return self._parse_package_lock_json(file_path)
            elif file_name == "yarn.lock":
                return self._parse_yarn_lock(file_path)
            elif file_name == "npm-shrinkwrap.json":
                return self._parse_npm_shrinkwrap(file_path)
            else:
                logger.warning(f"Unsupported Node.js file: {file_name}")
                return []
                
        except Exception as e:
            logger.error(f"Error parsing Node.js file {file_path}: {e}")
            return []
    
    def _parse_package_json(self, file_path: Path) -> List[Dependency]:
        """
        Parse package.json file.
        
        Args:
            file_path: Path to package.json
            
        Returns:
            List of dependencies
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            dependencies = []
            
            # Parse production dependencies
            if "dependencies" in data:
                for name, version in data["dependencies"].items():
                    dep = self._create_dependency(
                        name=name,
                        version=self._clean_version(version),
                        dependency_type=DependencyType.DIRECT,
                        is_dev=False,
                        file_path=file_path
                    )
                    dependencies.append(dep)
            
            # Parse development dependencies
            if "devDependencies" in data:
                for name, version in data["devDependencies"].items():
                    dep = self._create_dependency(
                        name=name,
                        version=self._clean_version(version),
                        dependency_type=DependencyType.DEV,
                        is_dev=True,
                        file_path=file_path
                    )
                    dependencies.append(dep)
            
            # Parse peer dependencies
            if "peerDependencies" in data:
                for name, version in data["peerDependencies"].items():
                    dep = self._create_dependency(
                        name=name,
                        version=self._clean_version(version),
                        dependency_type=DependencyType.PEER,
                        is_dev=False,
                        file_path=file_path
                    )
                    dependencies.append(dep)
            
            # Parse optional dependencies
            if "optionalDependencies" in data:
                for name, version in data["optionalDependencies"].items():
                    dep = self._create_dependency(
                        name=name,
                        version=self._clean_version(version),
                        dependency_type=DependencyType.OPTIONAL,
                        is_dev=False,
                        file_path=file_path
                    )
                    dep.is_optional = True
                    dependencies.append(dep)
            
            logger.info(f"Parsed {len(dependencies)} dependencies from package.json")
            return dependencies
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in package.json {file_path}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error parsing package.json {file_path}: {e}")
            return []
    
    def _parse_package_lock_json(self, file_path: Path) -> List[Dependency]:
        """
        Parse package-lock.json file.
        
        Args:
            file_path: Path to package-lock.json
            
        Returns:
            List of dependencies
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            dependencies = []
            
            # Parse dependencies from lockfile format
            if "dependencies" in data:
                dependencies.extend(self._parse_lock_dependencies(data["dependencies"], file_path))
            
            # Handle newer lockfile format (v2+)
            if "packages" in data:
                dependencies.extend(self._parse_lock_packages(data["packages"], file_path))
            
            logger.info(f"Parsed {len(dependencies)} dependencies from package-lock.json")
            return dependencies
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in package-lock.json {file_path}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error parsing package-lock.json {file_path}: {e}")
            return []
    
    def _parse_lock_dependencies(self, deps_data: Dict[str, Any], file_path: Path) -> List[Dependency]:
        """
        Parse dependencies section from lock file.
        
        Args:
            deps_data: Dependencies data from lock file
            file_path: Path to the lock file
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        for name, info in deps_data.items():
            if isinstance(info, dict):
                version = info.get("version", "unknown")
                
                # Determine if it's a dev dependency
                is_dev = info.get("dev", False)
                dep_type = DependencyType.DEV if is_dev else DependencyType.DIRECT
                
                dep = self._create_dependency(
                    name=name,
                    version=version,
                    dependency_type=dep_type,
                    is_dev=is_dev,
                    file_path=file_path
                )
                
                # Add additional metadata from lock file
                if "resolved" in info:
                    dep.download_url = info["resolved"]
                if "integrity" in info:
                    dep.hash_value = info["integrity"]
                    dep.hash_algorithm = "sha512" if info["integrity"].startswith("sha512-") else "sha1"
                
                dependencies.append(dep)
                
                # Recursively parse nested dependencies
                if "dependencies" in info:
                    nested_deps = self._parse_lock_dependencies(info["dependencies"], file_path)
                    for nested_dep in nested_deps:
                        nested_dep.dependency_type = DependencyType.TRANSITIVE
                    dependencies.extend(nested_deps)
        
        return dependencies
    
    def _parse_lock_packages(self, packages_data: Dict[str, Any], file_path: Path) -> List[Dependency]:
        """
        Parse packages section from newer lock file format.
        
        Args:
            packages_data: Packages data from lock file
            file_path: Path to the lock file
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        for package_path, info in packages_data.items():
            if package_path == "":  # Skip root package
                continue
            
            if isinstance(info, dict):
                # Extract package name from path
                name = package_path.split("/")[-1]
                if name.startswith("@"):
                    # Handle scoped packages
                    parts = package_path.split("/")
                    if len(parts) >= 2:
                        name = f"{parts[-2]}/{parts[-1]}"
                
                version = info.get("version", "unknown")
                
                # Determine dependency type
                is_dev = info.get("dev", False) or info.get("devOptional", False)
                is_optional = info.get("optional", False)
                
                if is_dev:
                    dep_type = DependencyType.DEV
                elif is_optional:
                    dep_type = DependencyType.OPTIONAL
                else:
                    dep_type = DependencyType.DIRECT
                
                dep = self._create_dependency(
                    name=name,
                    version=version,
                    dependency_type=dep_type,
                    is_dev=is_dev,
                    file_path=file_path
                )
                
                dep.is_optional = is_optional
                
                # Add additional metadata
                if "resolved" in info:
                    dep.download_url = info["resolved"]
                if "integrity" in info:
                    dep.hash_value = info["integrity"]
                    dep.hash_algorithm = "sha512" if info["integrity"].startswith("sha512-") else "sha1"
                if "license" in info:
                    dep.license = info["license"]
                
                dependencies.append(dep)
        
        return dependencies
    
    def _parse_yarn_lock(self, file_path: Path) -> List[Dependency]:
        """
        Parse yarn.lock file.
        
        Args:
            file_path: Path to yarn.lock
            
        Returns:
            List of dependencies
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            dependencies = []
            current_package = None
            current_info = {}
            
            for line in content.split('\n'):
                line = line.strip()
                
                if not line or line.startswith('#'):
                    continue
                
                # New package entry
                if not line.startswith(' ') and ':' in line:
                    # Save previous package if exists
                    if current_package and current_info:
                        dep = self._create_yarn_dependency(current_package, current_info, file_path)
                        if dep:
                            dependencies.append(dep)
                    
                    # Start new package
                    current_package = line.split(':')[0].strip().strip('"')
                    current_info = {}
                
                # Package property
                elif line.startswith(' ') and ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip().strip('"')
                    current_info[key] = value
            
            # Don't forget the last package
            if current_package and current_info:
                dep = self._create_yarn_dependency(current_package, current_info, file_path)
                if dep:
                    dependencies.append(dep)
            
            logger.info(f"Parsed {len(dependencies)} dependencies from yarn.lock")
            return dependencies
            
        except Exception as e:
            logger.error(f"Error parsing yarn.lock {file_path}: {e}")
            return []
    
    def _create_yarn_dependency(self, package_spec: str, info: Dict[str, str], file_path: Path) -> Optional[Dependency]:
        """
        Create a dependency from Yarn lock file entry.
        
        Args:
            package_spec: Package specification (name@version)
            info: Package information dictionary
            file_path: Path to the lock file
            
        Returns:
            Dependency object or None
        """
        try:
            # Parse package name and version constraint
            if '@' in package_spec and not package_spec.startswith('@'):
                name, version_constraint = package_spec.rsplit('@', 1)
            elif package_spec.startswith('@'):
                # Scoped package
                parts = package_spec.split('@')
                if len(parts) >= 3:
                    name = f"@{parts[1]}"
                    version_constraint = '@'.join(parts[2:])
                else:
                    name = package_spec
                    version_constraint = "*"
            else:
                name = package_spec
                version_constraint = "*"
            
            # Get actual resolved version
            version = info.get("version", version_constraint)
            
            dep = self._create_dependency(
                name=name,
                version=version,
                dependency_type=DependencyType.DIRECT,
                is_dev=False,
                file_path=file_path,
                package_manager=PackageManager.YARN
            )
            
            # Add Yarn-specific metadata
            if "resolved" in info:
                dep.download_url = info["resolved"]
            if "integrity" in info:
                dep.hash_value = info["integrity"]
                dep.hash_algorithm = "sha512" if info["integrity"].startswith("sha512-") else "sha1"
            
            return dep
            
        except Exception as e:
            logger.warning(f"Failed to parse Yarn package {package_spec}: {e}")
            return None
    
    def _parse_npm_shrinkwrap(self, file_path: Path) -> List[Dependency]:
        """
        Parse npm-shrinkwrap.json file.
        
        Args:
            file_path: Path to npm-shrinkwrap.json
            
        Returns:
            List of dependencies
        """
        # npm-shrinkwrap.json has similar format to package-lock.json
        return self._parse_package_lock_json(file_path)
    
    def _create_dependency(
        self,
        name: str,
        version: str,
        dependency_type: DependencyType,
        is_dev: bool,
        file_path: Path,
        package_manager: PackageManager = PackageManager.NPM
    ) -> Dependency:
        """
        Create a Dependency object for Node.js packages.
        
        Args:
            name: Package name
            version: Package version
            dependency_type: Type of dependency
            is_dev: Whether it's a development dependency
            file_path: Path to the source file
            package_manager: Package manager (npm or yarn)
            
        Returns:
            Dependency object
        """
        dep = Dependency(
            name=name,
            version=version,
            package_manager=package_manager,
            dependency_type=dependency_type,
            is_dev_dependency=is_dev,
            source_file=str(file_path)
        )
        
        # Add Node.js specific metadata
        dep.metadata = {
            "ecosystem": "npm",
            "registry_url": "https://registry.npmjs.org",
            "package_url": f"https://www.npmjs.com/package/{name}",
            "source_file_type": file_path.name
        }
        
        return dep
    
    def _clean_version(self, version: str) -> str:
        """
        Clean version string by removing npm version prefixes.
        
        Args:
            version: Raw version string
            
        Returns:
            Cleaned version string
        """
        if not version:
            return "unknown"
        
        # Remove common npm version prefixes
        prefixes = ["^", "~", ">=", "<=", ">", "<", "="]
        cleaned = version.strip()
        
        for prefix in prefixes:
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix):].strip()
                break
        
        # Handle version ranges (take the first version)
        if " - " in cleaned:
            cleaned = cleaned.split(" - ")[0].strip()
        elif " || " in cleaned:
            cleaned = cleaned.split(" || ")[0].strip()
        
        return cleaned if cleaned else "unknown"
    
    def get_metadata(self, dependency: Dependency) -> Dict[str, Any]:
        """
        Retrieve additional metadata for a Node.js dependency.
        
        Args:
            dependency: The dependency to get metadata for
            
        Returns:
            Dictionary of additional metadata
        """
        metadata = {
            "package_manager": dependency.package_manager.value,
            "registry": "npm",
            "ecosystem": "javascript",
            "language": "javascript"
        }
        
        # Add package-specific URLs
        if dependency.name:
            metadata.update({
                "npm_url": f"https://www.npmjs.com/package/{dependency.name}",
                "registry_api_url": f"https://registry.npmjs.org/{dependency.name}",
                "unpkg_url": f"https://unpkg.com/{dependency.name}@{dependency.version}/"
            })
            
            # Handle scoped packages
            if dependency.name.startswith("@"):
                encoded_name = dependency.name.replace("/", "%2F")
                metadata["registry_api_url"] = f"https://registry.npmjs.org/{encoded_name}"
        
        return metadata