"""
Python dependency parser for requirements.txt, setup.py, pyproject.toml, and other Python dependency files.
"""

import re
import ast
import logging
import configparser
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # Fallback for older Python versions
    except ImportError:
        tomllib = None

from ..models import Dependency, DependencyType, PackageManager
from .base_scanner import DependencyParser

logger = logging.getLogger(__name__)


class PythonParser(DependencyParser):
    """
    Parser for Python dependency files including requirements.txt, setup.py, pyproject.toml, and Pipfile.
    
    This parser handles pip, pipenv, poetry, and setuptools package managers
    and can extract dependencies with their version constraints and metadata.
    """
    
    def __init__(self):
        """Initialize the Python parser."""
        self._supported_files = [
            "requirements.txt",
            "requirements-*.txt",
            "dev-requirements.txt",
            "test-requirements.txt",
            "setup.py",
            "setup.cfg",
            "pyproject.toml",
            "Pipfile",
            "Pipfile.lock",
            "poetry.lock",
            "environment.yml",
            "environment.yaml"
        ]
    
    @property
    def supported_files(self) -> List[str]:
        """Get list of file patterns this parser supports."""
        return self._supported_files
    
    @property
    def package_manager(self) -> str:
        """Get the package manager name this parser handles."""
        return "pip"
    
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
        if file_name in ["setup.py", "setup.cfg", "pyproject.toml", "pipfile", "pipfile.lock", "poetry.lock"]:
            return True
        
        # Pattern matches
        if file_name.startswith("requirements") and file_name.endswith(".txt"):
            return True
        
        if file_name.startswith("environment.") and file_name.endswith((".yml", ".yaml")):
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
            if file_name.startswith("requirements") and file_name.endswith(".txt"):
                return self._parse_requirements_txt(file_path)
            elif file_name == "setup.py":
                return self._parse_setup_py(file_path)
            elif file_name == "setup.cfg":
                return self._parse_setup_cfg(file_path)
            elif file_name == "pyproject.toml":
                return self._parse_pyproject_toml(file_path)
            elif file_name == "pipfile":
                return self._parse_pipfile(file_path)
            elif file_name == "pipfile.lock":
                return self._parse_pipfile_lock(file_path)
            elif file_name == "poetry.lock":
                return self._parse_poetry_lock(file_path)
            elif file_name.startswith("environment.") and file_name.endswith((".yml", ".yaml")):
                return self._parse_conda_environment(file_path)
            else:
                logger.warning(f"Unsupported Python file: {file_name}")
                return []
                
        except Exception as e:
            logger.error(f"Error parsing Python file {file_path}: {e}")
            return []
    
    def _parse_requirements_txt(self, file_path: Path) -> List[Dependency]:
        """
        Parse requirements.txt file.
        
        Args:
            file_path: Path to requirements.txt
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Handle -r (recursive requirements) and other pip options
                if line.startswith('-'):
                    continue
                
                # Parse requirement line
                dep = self._parse_requirement_line(line, file_path, line_num)
                if dep:
                    # Determine if it's a dev dependency based on filename
                    if "dev" in file_path.name.lower() or "test" in file_path.name.lower():
                        dep.dependency_type = DependencyType.DEV
                        dep.is_dev_dependency = True
                    
                    dependencies.append(dep)
            
            logger.info(f"Parsed {len(dependencies)} dependencies from {file_path.name}")
            return dependencies
            
        except Exception as e:
            logger.error(f"Error parsing requirements.txt {file_path}: {e}")
            return []
    
    def _parse_requirement_line(self, line: str, file_path: Path, line_num: int) -> Optional[Dependency]:
        """
        Parse a single requirement line.
        
        Args:
            line: Requirement line
            file_path: Path to the file
            line_num: Line number for error reporting
            
        Returns:
            Dependency object or None
        """
        try:
            # Remove inline comments
            if '#' in line:
                line = line.split('#')[0].strip()
            
            # Handle different requirement formats
            # Format: package==1.0.0
            # Format: package>=1.0.0,<2.0.0
            # Format: package[extra]==1.0.0
            # Format: git+https://github.com/user/repo.git@tag#egg=package
            # Format: -e git+https://github.com/user/repo.git#egg=package
            
            # Handle editable installs
            is_editable = line.startswith('-e ')
            if is_editable:
                line = line[3:].strip()
            
            # Handle VCS URLs
            if any(line.startswith(vcs) for vcs in ['git+', 'hg+', 'svn+', 'bzr+']):
                return self._parse_vcs_requirement(line, file_path, is_editable)
            
            # Handle local file paths
            if line.startswith('./') or line.startswith('../') or line.startswith('/'):
                return self._parse_local_requirement(line, file_path, is_editable)
            
            # Handle standard package requirements
            return self._parse_standard_requirement(line, file_path, is_editable)
            
        except Exception as e:
            logger.warning(f"Failed to parse requirement line {line_num} in {file_path}: {line} - {e}")
            return None
    
    def _parse_standard_requirement(self, line: str, file_path: Path, is_editable: bool) -> Optional[Dependency]:
        """Parse standard package requirement."""
        # Regex to match package[extras]version_spec
        pattern = r'^([a-zA-Z0-9_.-]+)(?:\[([^\]]+)\])?(.*)$'
        match = re.match(pattern, line)
        
        if not match:
            return None
        
        name = match.group(1)
        extras = match.group(2)
        version_spec = match.group(3).strip()
        
        # Parse version
        version = self._parse_version_spec(version_spec)
        
        dep = Dependency(
            name=name,
            version=version,
            package_manager=PackageManager.PIP,
            dependency_type=DependencyType.DIRECT,
            source_file=str(file_path)
        )
        
        # Add metadata
        dep.metadata = {
            "ecosystem": "pypi",
            "registry_url": "https://pypi.org",
            "package_url": f"https://pypi.org/project/{name}/",
            "source_file_type": file_path.name,
            "version_spec": version_spec,
            "is_editable": is_editable
        }
        
        if extras:
            dep.metadata["extras"] = extras.split(',')
        
        return dep
    
    def _parse_vcs_requirement(self, line: str, file_path: Path, is_editable: bool) -> Optional[Dependency]:
        """Parse VCS requirement (git+, hg+, etc.)."""
        # Extract package name from egg parameter
        egg_match = re.search(r'#egg=([^&]+)', line)
        if not egg_match:
            return None
        
        name = egg_match.group(1)
        
        # Extract version from tag or branch
        version = "unknown"
        if '@' in line:
            ref_part = line.split('@')[1].split('#')[0]
            version = ref_part
        
        dep = Dependency(
            name=name,
            version=version,
            package_manager=PackageManager.PIP,
            dependency_type=DependencyType.DIRECT,
            source_file=str(file_path)
        )
        
        dep.metadata = {
            "ecosystem": "pypi",
            "source_file_type": file_path.name,
            "is_editable": is_editable,
            "vcs_url": line.split('#')[0],
            "installation_type": "vcs"
        }
        
        return dep
    
    def _parse_local_requirement(self, line: str, file_path: Path, is_editable: bool) -> Optional[Dependency]:
        """Parse local file/directory requirement."""
        # Extract package name from path
        path_part = line.split('#')[0].strip()
        name = Path(path_part).name
        
        dep = Dependency(
            name=name,
            version="local",
            package_manager=PackageManager.PIP,
            dependency_type=DependencyType.DIRECT,
            source_file=str(file_path)
        )
        
        dep.metadata = {
            "ecosystem": "pypi",
            "source_file_type": file_path.name,
            "is_editable": is_editable,
            "local_path": path_part,
            "installation_type": "local"
        }
        
        return dep
    
    def _parse_version_spec(self, version_spec: str) -> str:
        """
        Parse version specification and extract a representative version.
        
        Args:
            version_spec: Version specification string
            
        Returns:
            Representative version string
        """
        if not version_spec:
            return "any"
        
        # Remove whitespace
        version_spec = version_spec.strip()
        
        # Handle exact version (==1.0.0)
        if version_spec.startswith('=='):
            return version_spec[2:].strip()
        
        # Handle other operators and extract version
        operators = ['>=', '<=', '>', '<', '~=', '!=']
        for op in operators:
            if version_spec.startswith(op):
                version = version_spec[len(op):].strip()
                # Handle version ranges (>=1.0.0,<2.0.0)
                if ',' in version:
                    version = version.split(',')[0].strip()
                return version
        
        # If no operator, assume it's a version
        if ',' in version_spec:
            return version_spec.split(',')[0].strip()
        
        return version_spec
    
    def _parse_setup_py(self, file_path: Path) -> List[Dependency]:
        """
        Parse setup.py file.
        
        Args:
            file_path: Path to setup.py
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse AST to extract setup() call
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'setup':
                    # Extract install_requires
                    for keyword in node.keywords:
                        if keyword.arg == 'install_requires':
                            deps = self._extract_list_from_ast(keyword.value)
                            for dep_str in deps:
                                dep = self._parse_requirement_line(dep_str, file_path, 0)
                                if dep:
                                    dependencies.append(dep)
                        
                        elif keyword.arg == 'extras_require':
                            # Handle extras_require dictionary
                            if isinstance(keyword.value, ast.Dict):
                                for key, value in zip(keyword.value.keys, keyword.value.values):
                                    if isinstance(key, ast.Str):
                                        extra_name = key.s
                                        extra_deps = self._extract_list_from_ast(value)
                                        for dep_str in extra_deps:
                                            dep = self._parse_requirement_line(dep_str, file_path, 0)
                                            if dep:
                                                dep.dependency_type = DependencyType.OPTIONAL
                                                dep.is_optional = True
                                                if not dep.metadata:
                                                    dep.metadata = {}
                                                dep.metadata["extra"] = extra_name
                                                dependencies.append(dep)
            
            logger.info(f"Parsed {len(dependencies)} dependencies from setup.py")
            return dependencies
            
        except Exception as e:
            logger.error(f"Error parsing setup.py {file_path}: {e}")
            return []
    
    def _extract_list_from_ast(self, node) -> List[str]:
        """Extract string list from AST node."""
        if isinstance(node, ast.List):
            items = []
            for elt in node.elts:
                if isinstance(elt, ast.Str):
                    items.append(elt.s)
                elif isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    items.append(elt.value)
            return items
        return []
    
    def _parse_setup_cfg(self, file_path: Path) -> List[Dependency]:
        """
        Parse setup.cfg file.
        
        Args:
            file_path: Path to setup.cfg
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            config = configparser.ConfigParser()
            config.read(file_path)
            
            # Parse install_requires from options section
            if config.has_section('options') and config.has_option('options', 'install_requires'):
                install_requires = config.get('options', 'install_requires')
                for line in install_requires.strip().split('\n'):
                    line = line.strip()
                    if line:
                        dep = self._parse_requirement_line(line, file_path, 0)
                        if dep:
                            dependencies.append(dep)
            
            # Parse extras_require
            if config.has_section('options.extras_require'):
                for extra_name, extra_deps in config.items('options.extras_require'):
                    for line in extra_deps.strip().split('\n'):
                        line = line.strip()
                        if line:
                            dep = self._parse_requirement_line(line, file_path, 0)
                            if dep:
                                dep.dependency_type = DependencyType.OPTIONAL
                                dep.is_optional = True
                                if not dep.metadata:
                                    dep.metadata = {}
                                dep.metadata["extra"] = extra_name
                                dependencies.append(dep)
            
            logger.info(f"Parsed {len(dependencies)} dependencies from setup.cfg")
            return dependencies
            
        except Exception as e:
            logger.error(f"Error parsing setup.cfg {file_path}: {e}")
            return []
    
    def _parse_pyproject_toml(self, file_path: Path) -> List[Dependency]:
        """
        Parse pyproject.toml file.
        
        Args:
            file_path: Path to pyproject.toml
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            if tomllib is None:
                logger.warning(f"TOML parsing not available for {file_path}. Install tomli package.")
                return []
            
            with open(file_path, 'rb') as f:
                data = tomllib.load(f)
            
            # Check for Poetry dependencies
            if 'tool' in data and 'poetry' in data['tool']:
                poetry_data = data['tool']['poetry']
                
                # Parse main dependencies
                if 'dependencies' in poetry_data:
                    for name, version_spec in poetry_data['dependencies'].items():
                        if name == 'python':  # Skip Python version requirement
                            continue
                        
                        version = self._parse_poetry_version_spec(version_spec)
                        dep = Dependency(
                            name=name,
                            version=version,
                            package_manager=PackageManager.POETRY,
                            dependency_type=DependencyType.DIRECT,
                            source_file=str(file_path)
                        )
                        
                        dep.metadata = {
                            "ecosystem": "pypi",
                            "package_manager": "poetry",
                            "source_file_type": file_path.name,
                            "version_spec": str(version_spec)
                        }
                        
                        dependencies.append(dep)
                
                # Parse dev dependencies
                if 'dev-dependencies' in poetry_data:
                    for name, version_spec in poetry_data['dev-dependencies'].items():
                        version = self._parse_poetry_version_spec(version_spec)
                        dep = Dependency(
                            name=name,
                            version=version,
                            package_manager=PackageManager.POETRY,
                            dependency_type=DependencyType.DEV,
                            is_dev_dependency=True,
                            source_file=str(file_path)
                        )
                        
                        dep.metadata = {
                            "ecosystem": "pypi",
                            "package_manager": "poetry",
                            "source_file_type": file_path.name,
                            "version_spec": str(version_spec)
                        }
                        
                        dependencies.append(dep)
            
            # Check for PEP 621 project dependencies
            if 'project' in data:
                project_data = data['project']
                
                # Parse dependencies
                if 'dependencies' in project_data:
                    for dep_str in project_data['dependencies']:
                        dep = self._parse_requirement_line(dep_str, file_path, 0)
                        if dep:
                            dependencies.append(dep)
                
                # Parse optional dependencies
                if 'optional-dependencies' in project_data:
                    for extra_name, extra_deps in project_data['optional-dependencies'].items():
                        for dep_str in extra_deps:
                            dep = self._parse_requirement_line(dep_str, file_path, 0)
                            if dep:
                                dep.dependency_type = DependencyType.OPTIONAL
                                dep.is_optional = True
                                if not dep.metadata:
                                    dep.metadata = {}
                                dep.metadata["extra"] = extra_name
                                dependencies.append(dep)
            
            logger.info(f"Parsed {len(dependencies)} dependencies from pyproject.toml")
            return dependencies
            
        except Exception as e:
            logger.error(f"Error parsing pyproject.toml {file_path}: {e}")
            return []
    
    def _parse_poetry_version_spec(self, version_spec) -> str:
        """Parse Poetry version specification."""
        if isinstance(version_spec, str):
            return self._parse_version_spec(version_spec)
        elif isinstance(version_spec, dict):
            if 'version' in version_spec:
                return self._parse_version_spec(version_spec['version'])
            elif 'git' in version_spec:
                return version_spec.get('rev', version_spec.get('tag', version_spec.get('branch', 'unknown')))
        
        return "unknown"
    
    def _parse_pipfile(self, file_path: Path) -> List[Dependency]:
        """
        Parse Pipfile.
        
        Args:
            file_path: Path to Pipfile
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            if tomllib is None:
                logger.warning(f"TOML parsing not available for {file_path}. Install tomli package.")
                return []
            
            with open(file_path, 'rb') as f:
                data = tomllib.load(f)
            
            # Parse packages (production dependencies)
            if 'packages' in data:
                for name, version_spec in data['packages'].items():
                    version = self._parse_pipfile_version_spec(version_spec)
                    dep = Dependency(
                        name=name,
                        version=version,
                        package_manager=PackageManager.PIPENV,
                        dependency_type=DependencyType.DIRECT,
                        source_file=str(file_path)
                    )
                    
                    dep.metadata = {
                        "ecosystem": "pypi",
                        "package_manager": "pipenv",
                        "source_file_type": file_path.name,
                        "version_spec": str(version_spec)
                    }
                    
                    dependencies.append(dep)
            
            # Parse dev-packages
            if 'dev-packages' in data:
                for name, version_spec in data['dev-packages'].items():
                    version = self._parse_pipfile_version_spec(version_spec)
                    dep = Dependency(
                        name=name,
                        version=version,
                        package_manager=PackageManager.PIPENV,
                        dependency_type=DependencyType.DEV,
                        is_dev_dependency=True,
                        source_file=str(file_path)
                    )
                    
                    dep.metadata = {
                        "ecosystem": "pypi",
                        "package_manager": "pipenv",
                        "source_file_type": file_path.name,
                        "version_spec": str(version_spec)
                    }
                    
                    dependencies.append(dep)
            
            logger.info(f"Parsed {len(dependencies)} dependencies from Pipfile")
            return dependencies
            
        except Exception as e:
            logger.error(f"Error parsing Pipfile {file_path}: {e}")
            return []
    
    def _parse_pipfile_version_spec(self, version_spec) -> str:
        """Parse Pipfile version specification."""
        if isinstance(version_spec, str):
            return self._parse_version_spec(version_spec)
        elif isinstance(version_spec, dict):
            if 'version' in version_spec:
                return self._parse_version_spec(version_spec['version'])
            elif 'git' in version_spec:
                return version_spec.get('ref', 'unknown')
        
        return "*"
    
    def _parse_pipfile_lock(self, file_path: Path) -> List[Dependency]:
        """
        Parse Pipfile.lock.
        
        Args:
            file_path: Path to Pipfile.lock
            
        Returns:
            List of dependencies
        """
        # Pipfile.lock parsing would be implemented here
        # For now, return empty list as it's complex and less common
        logger.info(f"Pipfile.lock parsing not yet implemented for {file_path}")
        return []
    
    def _parse_poetry_lock(self, file_path: Path) -> List[Dependency]:
        """
        Parse poetry.lock.
        
        Args:
            file_path: Path to poetry.lock
            
        Returns:
            List of dependencies
        """
        # Poetry.lock parsing would be implemented here
        # For now, return empty list as it's complex and less common
        logger.info(f"Poetry.lock parsing not yet implemented for {file_path}")
        return []
    
    def _parse_conda_environment(self, file_path: Path) -> List[Dependency]:
        """
        Parse conda environment.yml/yaml file.
        
        Args:
            file_path: Path to environment file
            
        Returns:
            List of dependencies
        """
        # Conda environment parsing would be implemented here
        # For now, return empty list as it's less common for SBOM generation
        logger.info(f"Conda environment parsing not yet implemented for {file_path}")
        return []
    
    def get_metadata(self, dependency: Dependency) -> Dict[str, Any]:
        """
        Retrieve additional metadata for a Python dependency.
        
        Args:
            dependency: The dependency to get metadata for
            
        Returns:
            Dictionary of additional metadata
        """
        metadata = {
            "package_manager": dependency.package_manager.value,
            "registry": "pypi",
            "ecosystem": "python",
            "language": "python"
        }
        
        # Add package-specific URLs
        if dependency.name:
            metadata.update({
                "pypi_url": f"https://pypi.org/project/{dependency.name}/",
                "pypi_api_url": f"https://pypi.org/pypi/{dependency.name}/json",
                "pypi_simple_url": f"https://pypi.org/simple/{dependency.name}/"
            })
        
        return metadata