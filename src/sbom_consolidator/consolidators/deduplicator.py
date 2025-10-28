"""
Component deduplicator for removing duplicate dependencies while preserving source information.
"""

import logging
from typing import List, Dict, Any, Set, Optional
from collections import defaultdict

from ..models import Dependency

logger = logging.getLogger(__name__)


class Deduplicator:
    """
    Component deduplicator that removes duplicate dependencies while preserving source information.
    
    This class provides various strategies for handling duplicate components
    and ensures that source information is maintained during deduplication.
    """
    
    def __init__(self):
        """Initialize the deduplicator."""
        self._deduplication_statistics = {
            "components_processed": 0,
            "duplicates_found": 0,
            "components_merged": 0,
            "source_info_preserved": 0
        }
    
    def deduplicate(
        self, 
        components: List[Dependency], 
        strategy: str = "merge",
        preserve_source_info: bool = True
    ) -> List[Dependency]:
        """
        Remove duplicate components using specified strategy.
        
        Args:
            components: List of components to deduplicate
            strategy: Deduplication strategy ("merge", "keep_first", "keep_all")
            preserve_source_info: Whether to preserve source information
            
        Returns:
            List of deduplicated components
        """
        if not components:
            return []
        
        logger.info(f"Deduplicating {len(components)} components using '{strategy}' strategy")
        
        self._deduplication_statistics["components_processed"] += len(components)
        
        if strategy == "merge":
            return self._merge_duplicates(components, preserve_source_info)
        elif strategy == "keep_first":
            return self._keep_first_duplicates(components)
        elif strategy == "keep_all":
            return components  # No deduplication
        else:
            logger.warning(f"Unknown deduplication strategy '{strategy}', using 'merge'")
            return self._merge_duplicates(components, preserve_source_info)
    
    def _merge_duplicates(self, components: List[Dependency], preserve_source_info: bool) -> List[Dependency]:
        """
        Merge duplicate components while preserving source information.
        
        Args:
            components: List of components to merge
            preserve_source_info: Whether to preserve source information
            
        Returns:
            List of merged components
        """
        # Group components by unique identifier
        component_groups = self._group_components(components)
        
        merged_components = []
        duplicates_found = 0
        
        for key, group in component_groups.items():
            if len(group) == 1:
                # No duplicates, add as-is
                merged_components.append(group[0])
            else:
                # Merge duplicates
                duplicates_found += len(group) - 1
                merged_component = self._merge_component_group(group, preserve_source_info)
                merged_components.append(merged_component)
                
                logger.debug(f"Merged {len(group)} duplicates of {key}")
        
        # Update statistics
        self._deduplication_statistics["duplicates_found"] += duplicates_found
        self._deduplication_statistics["components_merged"] += len(merged_components)
        
        logger.info(f"Deduplication complete: {len(components)} -> {len(merged_components)} "
                   f"({duplicates_found} duplicates merged)")
        
        return merged_components
    
    def _keep_first_duplicates(self, components: List[Dependency]) -> List[Dependency]:
        """
        Keep only the first occurrence of duplicate components.
        
        Args:
            components: List of components to deduplicate
            
        Returns:
            List of components with duplicates removed
        """
        seen_keys = set()
        unique_components = []
        duplicates_found = 0
        
        for component in components:
            key = self._get_component_key(component)
            
            if key not in seen_keys:
                seen_keys.add(key)
                unique_components.append(component)
            else:
                duplicates_found += 1
        
        # Update statistics
        self._deduplication_statistics["duplicates_found"] += duplicates_found
        
        logger.info(f"Keep-first deduplication: {len(components)} -> {len(unique_components)} "
                   f"({duplicates_found} duplicates removed)")
        
        return unique_components
    
    def _group_components(self, components: List[Dependency]) -> Dict[str, List[Dependency]]:
        """
        Group components by their unique identifier.
        
        Args:
            components: List of components to group
            
        Returns:
            Dictionary mapping component keys to lists of components
        """
        groups = defaultdict(list)
        
        for component in components:
            key = self._get_component_key(component)
            groups[key].append(component)
        
        return dict(groups)
    
    def _get_component_key(self, component: Dependency) -> str:
        """
        Generate unique key for component identification.
        
        Args:
            component: Component to generate key for
            
        Returns:
            Unique key string
        """
        # Use name, version, and package manager for uniqueness
        return f"{component.name}:{component.version}:{component.package_manager.value}"
    
    def _merge_component_group(self, components: List[Dependency], preserve_source_info: bool) -> Dependency:
        """
        Merge a group of duplicate components into a single component.
        
        Args:
            components: List of duplicate components to merge
            preserve_source_info: Whether to preserve source information
            
        Returns:
            Merged component
        """
        if not components:
            raise ValueError("Cannot merge empty component group")
        
        if len(components) == 1:
            return components[0]
        
        # Use the first component as the base
        merged = components[0]
        
        # Merge information from other components
        for other in components[1:]:
            merged = self._merge_two_components(merged, other, preserve_source_info)
        
        if preserve_source_info:
            self._deduplication_statistics["source_info_preserved"] += 1
        
        return merged
    
    def _merge_two_components(self, base: Dependency, other: Dependency, preserve_source_info: bool) -> Dependency:
        """
        Merge two components into one.
        
        Args:
            base: Base component to merge into
            other: Other component to merge from
            preserve_source_info: Whether to preserve source information
            
        Returns:
            Merged component
        """
        # Merge vulnerabilities
        if other.vulnerabilities:
            for vuln in other.vulnerabilities:
                if vuln not in base.vulnerabilities:
                    base.vulnerabilities.append(vuln)
        
        # Merge license information (prefer non-None values)
        if not base.license and other.license:
            base.license = other.license
        if not base.license_url and other.license_url:
            base.license_url = other.license_url
        
        # Merge other optional fields
        if not base.homepage and other.homepage:
            base.homepage = other.homepage
        if not base.repository_url and other.repository_url:
            base.repository_url = other.repository_url
        if not base.description and other.description:
            base.description = other.description
        if not base.author and other.author:
            base.author = other.author
        if not base.download_url and other.download_url:
            base.download_url = other.download_url
        
        # Merge source information if preserving
        if preserve_source_info:
            base = self._merge_source_information(base, other)
        
        # Merge metadata
        if other.metadata:
            if not base.metadata:
                base.metadata = {}
            
            for key, value in other.metadata.items():
                if key not in base.metadata:
                    base.metadata[key] = value
                elif isinstance(value, list) and isinstance(base.metadata[key], list):
                    # Merge lists and remove duplicates
                    combined = base.metadata[key] + value
                    base.metadata[key] = list(dict.fromkeys(combined))  # Preserve order while removing duplicates
                elif isinstance(value, dict) and isinstance(base.metadata[key], dict):
                    # Merge dictionaries
                    base.metadata[key].update(value)
                elif base.metadata[key] != value:
                    # Handle conflicting values by creating a list
                    if not isinstance(base.metadata[key], list):
                        base.metadata[key] = [base.metadata[key]]
                    if value not in base.metadata[key]:
                        base.metadata[key].append(value)
        
        return base
    
    def _merge_source_information(self, base: Dependency, other: Dependency) -> Dependency:
        """
        Merge source information from two components.
        
        Args:
            base: Base component
            other: Other component
            
        Returns:
            Component with merged source information
        """
        # Initialize metadata if needed
        if not base.metadata:
            base.metadata = {}
        
        # Merge source repositories
        source_repos = set()
        if base.source_repository:
            source_repos.add(base.source_repository)
        if other.source_repository:
            source_repos.add(other.source_repository)
        
        # Add from metadata
        if "source_repositories" in base.metadata:
            source_repos.update(base.metadata["source_repositories"])
        if other.metadata and "source_repositories" in other.metadata:
            source_repos.update(other.metadata["source_repositories"])
        
        base.metadata["source_repositories"] = list(source_repos)
        
        # Merge source files
        source_files = set()
        if base.source_file:
            source_files.add(base.source_file)
        if other.source_file:
            source_files.add(other.source_file)
        
        # Add from metadata
        if "source_files" in base.metadata:
            source_files.update(base.metadata["source_files"])
        if other.metadata and "source_files" in other.metadata:
            source_files.update(other.metadata["source_files"])
        
        base.metadata["source_files"] = list(source_files)
        
        # Merge source SBOM IDs
        source_sbom_ids = set()
        if "source_sbom_id" in base.metadata:
            source_sbom_ids.add(base.metadata["source_sbom_id"])
        if other.metadata and "source_sbom_id" in other.metadata:
            source_sbom_ids.add(other.metadata["source_sbom_id"])
        
        if source_sbom_ids:
            base.metadata["source_sbom_ids"] = list(source_sbom_ids)
        
        # Update primary source fields to most comprehensive
        if len(source_repos) > 0:
            base.source_repository = list(source_repos)[0]  # Use first as primary
        if len(source_files) > 0:
            base.source_file = list(source_files)[0]  # Use first as primary
        
        return base
    
    def find_duplicates(self, components: List[Dependency]) -> Dict[str, List[Dependency]]:
        """
        Find duplicate components without merging them.
        
        Args:
            components: List of components to analyze
            
        Returns:
            Dictionary mapping component keys to lists of duplicates
        """
        groups = self._group_components(components)
        
        # Return only groups with duplicates
        duplicates = {key: group for key, group in groups.items() if len(group) > 1}
        
        logger.info(f"Found {len(duplicates)} sets of duplicates among {len(components)} components")
        
        return duplicates
    
    def analyze_duplication(self, components: List[Dependency]) -> Dict[str, Any]:
        """
        Analyze duplication patterns in components.
        
        Args:
            components: List of components to analyze
            
        Returns:
            Dictionary with duplication analysis
        """
        groups = self._group_components(components)
        duplicates = {key: group for key, group in groups.items() if len(group) > 1}
        
        # Analyze patterns
        package_manager_duplicates = defaultdict(int)
        source_repo_duplicates = defaultdict(int)
        version_patterns = defaultdict(int)
        
        for key, group in duplicates.items():
            pm = group[0].package_manager.value
            package_manager_duplicates[pm] += len(group) - 1
            
            # Analyze source repositories
            source_repos = set(comp.source_repository for comp in group if comp.source_repository)
            if len(source_repos) > 1:
                source_repo_duplicates[key] = len(source_repos)
            
            # Analyze version patterns
            versions = set(comp.version for comp in group)
            if len(versions) > 1:
                version_patterns[key] = len(versions)
        
        analysis = {
            "total_components": len(components),
            "unique_components": len(groups),
            "duplicate_sets": len(duplicates),
            "total_duplicates": sum(len(group) - 1 for group in duplicates.values()),
            "deduplication_potential": len(components) - len(groups),
            "package_manager_duplicates": dict(package_manager_duplicates),
            "cross_repository_duplicates": len(source_repo_duplicates),
            "version_conflicts": len(version_patterns),
            "duplication_ratio": len(duplicates) / len(groups) if groups else 0
        }
        
        return analysis
    
    def get_deduplication_statistics(self) -> Dict[str, Any]:
        """Get deduplication statistics."""
        return self._deduplication_statistics.copy()
    
    def reset_statistics(self) -> None:
        """Reset deduplication statistics."""
        self._deduplication_statistics = {
            "components_processed": 0,
            "duplicates_found": 0,
            "components_merged": 0,
            "source_info_preserved": 0
        }