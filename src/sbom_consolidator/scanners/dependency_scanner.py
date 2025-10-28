"""
Main dependency scanner that coordinates language-specific parsers.
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Set
from collections import defaultdict

from ..models import Repository, Dependency
from ..config import get_config
from .base_scanner import BaseScanner, DependencyParser

logger = logging.getLogger(__name__)


class DependencyScanner(BaseScanner):
    """
    Main dependency scanner that coordinates multiple language-specific parsers.
    
    This class implements the base scanner interface and manages the discovery
    and parsing of dependency files across different programming languages
    and package managers.
    """
    
    def __init__(self):
        """Initialize the dependency scanner with default parsers."""
        super().__init__()
        self.config = get_config()
        
        # Statistics tracking
        self._scan_statistics = {
            "repositories_scanned": 0,
            "files_discovered": 0,
            "dependencies_found": 0,
            "parsers_used": set(),
            "errors": []
        }
        
        # Auto-register available parsers
        self._auto_register_parsers()
    
    def _auto_register_parsers(self) -> None:
        """Automatically register available dependency parsers."""
        try:
            # Import and register parsers based on configuration
            supported_languages = self.config.scanning.supported_languages
            
            if "javascript" in supported_languages:
                from .nodejs_parser import NodeJSParser
                self.register_parser(NodeJSParser())
                logger.debug("Registered Node.js parser")
            
            if "python" in supported_languages:
                from .python_parser import PythonParser
                self.register_parser(PythonParser())
                logger.debug("Registered Python parser")
            
            if "java" in supported_languages:
                from .java_parser import JavaParser
                self.register_parser(JavaParser())
                logger.debug("Registered Java parser")
            
            if "csharp" in supported_languages:
                from .dotnet_parser import DotNetParser
                self.register_parser(DotNetParser())
                logger.debug("Registered .NET parser")
            
            logger.info(f"Registered {len(self._parsers)} dependency parsers")
            
        except ImportError as e:
            logger.warning(f"Failed to import some parsers: {e}")
    
    def scan_repository(self, repo_path: Path) -> Dict[str, List[Path]]:
        """
        Scan repository for dependency files.
        
        Args:
            repo_path: Path to the repository root
            
        Returns:
            Dictionary mapping file types to lists of found files
        """
        if not repo_path.exists():
            logger.error(f"Repository path does not exist: {repo_path}")
            return {}
        
        logger.info(f"Scanning repository for dependency files: {repo_path}")
        
        found_files = defaultdict(list)
        total_files_found = 0
        
        # Get all parsers and their supported file patterns
        parser_patterns = {}
        for parser in self._parsers:
            for pattern in parser.supported_files:
                parser_patterns[pattern] = parser
        
        # Search for dependency files
        try:
            for pattern, parser in parser_patterns.items():
                # Use glob to find matching files
                matches = list(repo_path.rglob(pattern))
                
                # Filter out files in common ignore directories
                filtered_matches = self._filter_ignored_files(matches)
                
                if filtered_matches:
                    file_type = parser.package_manager
                    found_files[file_type].extend(filtered_matches)
                    total_files_found += len(filtered_matches)
                    
                    logger.debug(f"Found {len(filtered_matches)} {file_type} files matching pattern '{pattern}'")
        
        except Exception as e:
            logger.error(f"Error scanning repository {repo_path}: {e}")
            self._scan_statistics["errors"].append(f"Scan error in {repo_path}: {e}")
        
        # Update statistics
        self._scan_statistics["files_discovered"] += total_files_found
        
        logger.info(f"Found {total_files_found} dependency files across {len(found_files)} package managers")
        return dict(found_files)
    
    def _filter_ignored_files(self, file_paths: List[Path]) -> List[Path]:
        """
        Filter out files in commonly ignored directories.
        
        Args:
            file_paths: List of file paths to filter
            
        Returns:
            Filtered list of file paths
        """
        ignore_directories = {
            'node_modules', '.git', '__pycache__', '.venv', 'venv',
            'target', 'build', 'dist', '.gradle', 'bin', 'obj',
            '.pytest_cache', '.tox', '.coverage', 'htmlcov',
            'vendor', 'packages', '.nuget', 'bower_components'
        }
        
        filtered_files = []
        for file_path in file_paths:
            # Check if any part of the path is in ignore directories
            if not any(part in ignore_directories for part in file_path.parts):
                filtered_files.append(file_path)
            else:
                logger.debug(f"Ignoring file in excluded directory: {file_path}")
        
        return filtered_files
    
    def parse_dependencies(self, file_path: Path, file_type: str) -> List[Dependency]:
        """
        Parse dependencies from a specific file.
        
        Args:
            file_path: Path to the dependency file
            file_type: Type of dependency file
            
        Returns:
            List of dependencies found in the file
        """
        if not file_path.exists():
            logger.error(f"Dependency file does not exist: {file_path}")
            return []
        
        # Find appropriate parser for this file
        parser = self._find_parser_for_file(file_path, file_type)
        if not parser:
            logger.warning(f"No parser found for file type '{file_type}': {file_path}")
            return []
        
        try:
            logger.debug(f"Parsing dependencies from {file_path} using {parser.__class__.__name__}")
            
            dependencies = parser.parse_file(file_path)
            
            # Add source information to dependencies
            for dep in dependencies:
                dep.source_file = str(file_path)
                if not dep.source_repository:
                    # Try to determine source repository from file path
                    dep.source_repository = self._extract_repo_name_from_path(file_path)
            
            # Update statistics
            self._scan_statistics["dependencies_found"] += len(dependencies)
            self._scan_statistics["parsers_used"].add(parser.__class__.__name__)
            
            logger.info(f"Found {len(dependencies)} dependencies in {file_path}")
            return dependencies
            
        except Exception as e:
            error_msg = f"Error parsing dependencies from {file_path}: {e}"
            logger.error(error_msg)
            self._scan_statistics["errors"].append(error_msg)
            return []
    
    def _find_parser_for_file(self, file_path: Path, file_type: str) -> Optional[DependencyParser]:
        """
        Find the appropriate parser for a given file.
        
        Args:
            file_path: Path to the file
            file_type: Type of dependency file
            
        Returns:
            Matching parser or None
        """
        # First try to find parser by file type
        for parser in self._parsers:
            if parser.package_manager == file_type and parser.can_parse(file_path):
                return parser
        
        # If no exact match, try all parsers
        for parser in self._parsers:
            if parser.can_parse(file_path):
                return parser
        
        return None
    
    def _extract_repo_name_from_path(self, file_path: Path) -> str:
        """
        Extract repository name from file path.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Repository name or empty string
        """
        try:
            # Look for common repository root indicators
            parts = file_path.parts
            for i, part in enumerate(parts):
                if part in ['.git', 'node_modules', '.venv', 'venv']:
                    if i > 0:
                        return parts[i - 1]
            
            # If no indicators found, use the deepest directory that looks like a repo
            if len(parts) >= 2:
                return parts[-2] if parts[-1] != file_path.name else parts[-3]
            
        except Exception:
            pass
        
        return ""
    
    def scan_repository_dependencies(self, repository: Repository) -> List[Dependency]:
        """
        Scan a repository for all dependencies.
        
        Args:
            repository: Repository object to scan
            
        Returns:
            List of all dependencies found in the repository
        """
        if not repository.is_cloned():
            logger.error(f"Repository {repository.full_name} is not cloned")
            return []
        
        logger.info(f"Scanning dependencies in repository: {repository.full_name}")
        
        repo_path = Path(repository.local_path)
        all_dependencies = []
        
        # Scan for dependency files
        dependency_files = self.scan_repository(repo_path)
        
        # Parse each dependency file
        for file_type, file_paths in dependency_files.items():
            for file_path in file_paths:
                dependencies = self.parse_dependencies(file_path, file_type)
                
                # Add repository information to dependencies
                for dep in dependencies:
                    dep.source_repository = repository.full_name
                    if not dep.metadata:
                        dep.metadata = {}
                    dep.metadata.update({
                        "repository_url": repository.url,
                        "repository_branch": repository.branch,
                        "repository_language": repository.language,
                        "file_path": str(file_path.relative_to(repo_path))
                    })
                
                all_dependencies.extend(dependencies)
        
        # Update statistics
        self._scan_statistics["repositories_scanned"] += 1
        
        # Remove duplicates while preserving source information
        unique_dependencies = self._deduplicate_dependencies(all_dependencies)
        
        logger.info(f"Found {len(unique_dependencies)} unique dependencies in {repository.full_name}")
        return unique_dependencies
    
    def _deduplicate_dependencies(self, dependencies: List[Dependency]) -> List[Dependency]:
        """
        Remove duplicate dependencies while preserving source information.
        
        Args:
            dependencies: List of dependencies that may contain duplicates
            
        Returns:
            List of unique dependencies
        """
        seen = {}
        unique_deps = []
        
        for dep in dependencies:
            # Create a key based on name, version, and package manager
            key = (dep.name, dep.version, dep.package_manager.value)
            
            if key not in seen:
                seen[key] = dep
                unique_deps.append(dep)
            else:
                # Merge source information for duplicates
                existing_dep = seen[key]
                
                # Combine source files
                if dep.source_file and dep.source_file not in existing_dep.source_file:
                    existing_dep.source_file += f", {dep.source_file}"
                
                # Merge metadata
                if dep.metadata:
                    if not existing_dep.metadata:
                        existing_dep.metadata = {}
                    
                    # Add source files list if not present
                    if "source_files" not in existing_dep.metadata:
                        existing_dep.metadata["source_files"] = [existing_dep.source_file]
                    
                    if dep.source_file not in existing_dep.metadata["source_files"]:
                        existing_dep.metadata["source_files"].append(dep.source_file)
        
        return unique_deps
    
    def scan_multiple_repositories(self, repositories: List[Repository]) -> Dict[str, List[Dependency]]:
        """
        Scan multiple repositories for dependencies.
        
        Args:
            repositories: List of Repository objects to scan
            
        Returns:
            Dictionary mapping repository names to their dependencies
        """
        results = {}
        
        for repository in repositories:
            try:
                dependencies = self.scan_repository_dependencies(repository)
                results[repository.full_name] = dependencies
                logger.info(f"Successfully scanned {repository.full_name}: {len(dependencies)} dependencies")
            except Exception as e:
                logger.error(f"Failed to scan repository {repository.full_name}: {e}")
                results[repository.full_name] = []
                self._scan_statistics["errors"].append(f"Repository scan error {repository.full_name}: {e}")
        
        return results
    
    def get_scan_statistics(self) -> Dict[str, any]:
        """
        Get scanning statistics.
        
        Returns:
            Dictionary of scanning statistics
        """
        stats = self._scan_statistics.copy()
        stats["parsers_used"] = list(stats["parsers_used"])
        stats["registered_parsers"] = [parser.__class__.__name__ for parser in self._parsers]
        stats["supported_package_managers"] = [parser.package_manager for parser in self._parsers]
        
        return stats
    
    def reset_statistics(self) -> None:
        """Reset scanning statistics."""
        self._scan_statistics = {
            "repositories_scanned": 0,
            "files_discovered": 0,
            "dependencies_found": 0,
            "parsers_used": set(),
            "errors": []
        }
    
    def validate_configuration(self) -> List[str]:
        """
        Validate scanner configuration.
        
        Returns:
            List of validation warnings/errors
        """
        issues = []
        
        if not self._parsers:
            issues.append("No dependency parsers registered")
        
        if self.config.scanning.max_scan_depth < 1:
            issues.append("Max scan depth must be at least 1")
        
        supported_languages = self.config.scanning.supported_languages
        if not supported_languages:
            issues.append("No supported languages configured")
        
        # Check if parsers are available for configured languages
        available_parsers = {parser.package_manager for parser in self._parsers}
        language_parser_mapping = {
            "javascript": {"npm", "yarn"},
            "python": {"pip", "pipenv", "poetry"},
            "java": {"maven", "gradle"},
            "csharp": {"nuget"}
        }
        
        for language in supported_languages:
            if language in language_parser_mapping:
                expected_parsers = language_parser_mapping[language]
                if not any(parser in available_parsers for parser in expected_parsers):
                    issues.append(f"No parsers available for configured language: {language}")
        
        return issues