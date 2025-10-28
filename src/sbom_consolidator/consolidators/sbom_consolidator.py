"""
SBOM consolidator for merging multiple SBOMs into unified documents.
"""

import logging
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional, Set
from collections import defaultdict

from ..models import SBOMDocument, Dependency, ComponentRelationship, RelationshipType
from ..config import get_config
from .deduplicator import Deduplicator
from .merger import Merger

logger = logging.getLogger(__name__)


class SBOMConsolidator:
    """
    Main SBOM consolidator that merges multiple SBOMs into unified documents.
    
    This class coordinates the consolidation process including deduplication,
    merging, and preservation of source information across multiple SBOMs.
    """
    
    def __init__(self):
        """Initialize the SBOM consolidator."""
        self.config = get_config()
        self.deduplicator = Deduplicator()
        self.merger = Merger()
        
        # Statistics tracking
        self._consolidation_statistics = {
            "consolidations_performed": 0,
            "sboms_merged": 0,
            "components_before_dedup": 0,
            "components_after_dedup": 0,
            "relationships_merged": 0,
            "source_repositories": set(),
            "errors": []
        }
    
    def merge_sboms(self, sbom_list: List[SBOMDocument]) -> SBOMDocument:
        """
        Combine multiple SBOMs into unified document.
        
        Args:
            sbom_list: List of SBOM documents to merge
            
        Returns:
            Consolidated SBOM document
        """
        if not sbom_list:
            raise ValueError("Cannot merge empty SBOM list")
        
        if len(sbom_list) == 1:
            logger.info("Only one SBOM provided, returning as-is")
            return sbom_list[0]
        
        logger.info(f"Merging {len(sbom_list)} SBOMs into consolidated document")
        
        # Track statistics
        total_components_before = sum(sbom.component_count for sbom in sbom_list)
        self._consolidation_statistics["components_before_dedup"] += total_components_before
        self._consolidation_statistics["sboms_merged"] += len(sbom_list)
        
        # Collect all components from all SBOMs
        all_components = []
        all_relationships = []
        source_repositories = set()
        merged_metadata = {}
        
        for sbom in sbom_list:
            # Collect components with source information
            for component in sbom.components:
                # Ensure source repository information is preserved
                if sbom.source_repository:
                    component.source_repository = sbom.source_repository
                    source_repositories.add(sbom.source_repository)
                
                # Add SBOM-specific metadata
                if not component.metadata:
                    component.metadata = {}
                component.metadata["source_sbom_id"] = sbom.document_id
                component.metadata["source_sbom_name"] = sbom.document_name
                
                all_components.append(component)
            
            # Collect relationships
            all_relationships.extend(sbom.relationships)
            
            # Merge metadata
            if sbom.metadata:
                for key, value in sbom.metadata.items():
                    if key not in merged_metadata:
                        merged_metadata[key] = value
                    elif isinstance(value, list) and isinstance(merged_metadata[key], list):
                        merged_metadata[key].extend(value)
                    elif isinstance(value, dict) and isinstance(merged_metadata[key], dict):
                        merged_metadata[key].update(value)
        
        # Deduplicate components while preserving source information
        logger.info(f"Deduplicating {len(all_components)} components")
        deduplicated_components = self.deduplicate_components(all_components)
        
        # Merge relationships and remove duplicates
        logger.info(f"Merging {len(all_relationships)} relationships")
        merged_relationships = self._merge_relationships(all_relationships)
        
        # Create consolidated SBOM
        consolidated_sbom = SBOMDocument(
            document_id=str(uuid.uuid4()),
            creation_time=datetime.utcnow(),
            creator="github-sbom-consolidator-consolidated",
            components=deduplicated_components,
            relationships=merged_relationships,
            metadata=merged_metadata
        )
        
        # Set consolidated document properties
        consolidated_sbom.document_name = f"Consolidated-SBOM-{len(sbom_list)}-repos"
        consolidated_sbom.document_namespace = "https://github.com/sbom-consolidator/consolidated"
        
        # Add consolidation metadata
        consolidated_sbom.metadata.update({
            "consolidation_info": {
                "source_sbom_count": len(sbom_list),
                "source_sbom_ids": [sbom.document_id for sbom in sbom_list],
                "source_repositories": list(source_repositories),
                "consolidation_timestamp": datetime.utcnow().isoformat(),
                "components_before_dedup": total_components_before,
                "components_after_dedup": len(deduplicated_components),
                "deduplication_ratio": 1 - (len(deduplicated_components) / total_components_before) if total_components_before > 0 else 0
            }
        })
        
        # Merge risk analysis if present
        risk_analyses = [sbom.risk_analysis for sbom in sbom_list if sbom.risk_analysis]
        if risk_analyses:
            consolidated_sbom.risk_analysis = self.merger.merge_risk_analyses(risk_analyses)
        
        # Merge security recommendations if present
        security_recommendations = [sbom.security_recommendations for sbom in sbom_list if sbom.security_recommendations]
        if security_recommendations:
            consolidated_sbom.security_recommendations = self.merger.merge_security_recommendations(security_recommendations)
        
        # Update statistics
        self._consolidation_statistics["consolidations_performed"] += 1
        self._consolidation_statistics["components_after_dedup"] += len(deduplicated_components)
        self._consolidation_statistics["relationships_merged"] += len(merged_relationships)
        self._consolidation_statistics["source_repositories"].update(source_repositories)
        
        logger.info(f"Consolidated SBOM created with {len(deduplicated_components)} components "
                   f"(reduced from {total_components_before})")
        
        return consolidated_sbom
    
    def deduplicate_components(self, components: List[Dependency]) -> List[Dependency]:
        """
        Remove duplicate dependencies while preserving source information.
        
        Args:
            components: List of components that may contain duplicates
            
        Returns:
            List of unique components with merged source information
        """
        strategy = self.config.consolidation.duplicate_strategy
        preserve_source = self.config.consolidation.preserve_source_info
        
        return self.deduplicator.deduplicate(
            components, 
            strategy=strategy, 
            preserve_source_info=preserve_source
        )
    
    def _merge_relationships(self, relationships: List[ComponentRelationship]) -> List[ComponentRelationship]:
        """
        Merge component relationships and remove duplicates.
        
        Args:
            relationships: List of relationships to merge
            
        Returns:
            List of unique relationships
        """
        if not relationships:
            return []
        
        # Use set to track unique relationships
        unique_relationships = {}
        
        for relationship in relationships:
            # Create unique key for relationship
            key = (
                relationship.source_component,
                relationship.target_component,
                relationship.relationship_type.value
            )
            
            if key not in unique_relationships:
                unique_relationships[key] = relationship
            else:
                # Merge descriptions if different
                existing = unique_relationships[key]
                if (relationship.description and 
                    relationship.description != existing.description):
                    if existing.description:
                        existing.description += f"; {relationship.description}"
                    else:
                        existing.description = relationship.description
                
                # Merge metadata
                if relationship.metadata:
                    if not existing.metadata:
                        existing.metadata = {}
                    existing.metadata.update(relationship.metadata)
        
        return list(unique_relationships.values())
    
    def preserve_source_info(self, consolidated_sbom: SBOMDocument) -> SBOMDocument:
        """
        Maintain repository origin data for each component in the consolidated SBOM.
        
        Args:
            consolidated_sbom: SBOM to enhance with source information
            
        Returns:
            SBOM with enhanced source information
        """
        if not self.config.consolidation.preserve_source_info:
            return consolidated_sbom
        
        logger.debug("Preserving source information in consolidated SBOM")
        
        # Enhance component source information
        for component in consolidated_sbom.components:
            if not component.metadata:
                component.metadata = {}
            
            # Ensure source tracking metadata exists
            if "source_repositories" not in component.metadata:
                if component.source_repository:
                    component.metadata["source_repositories"] = [component.source_repository]
                else:
                    component.metadata["source_repositories"] = []
            
            if "source_files" not in component.metadata:
                if component.source_file:
                    component.metadata["source_files"] = [component.source_file]
                else:
                    component.metadata["source_files"] = []
            
            # Add discovery metadata
            component.metadata["discovery_method"] = "consolidation"
            component.metadata["consolidation_timestamp"] = datetime.utcnow().isoformat()
        
        # Add source summary to SBOM metadata
        source_summary = self._generate_source_summary(consolidated_sbom)
        consolidated_sbom.metadata["source_summary"] = source_summary
        
        return consolidated_sbom
    
    def _generate_source_summary(self, sbom: SBOMDocument) -> Dict[str, Any]:
        """Generate summary of source information."""
        source_repos = set()
        source_files = set()
        package_managers = defaultdict(int)
        languages = defaultdict(int)
        
        for component in sbom.components:
            if component.metadata:
                # Collect source repositories
                repos = component.metadata.get("source_repositories", [])
                source_repos.update(repos)
                
                # Collect source files
                files = component.metadata.get("source_files", [])
                source_files.update(files)
                
                # Count package managers
                if component.package_manager:
                    package_managers[component.package_manager.value] += 1
                
                # Count languages
                language = component.metadata.get("language", "unknown")
                languages[language] += 1
        
        return {
            "total_source_repositories": len(source_repos),
            "source_repositories": list(source_repos),
            "total_source_files": len(source_files),
            "package_manager_distribution": dict(package_managers),
            "language_distribution": dict(languages),
            "components_per_repository": self._count_components_per_repo(sbom)
        }
    
    def _count_components_per_repo(self, sbom: SBOMDocument) -> Dict[str, int]:
        """Count components per source repository."""
        repo_counts = defaultdict(int)
        
        for component in sbom.components:
            if component.metadata and "source_repositories" in component.metadata:
                for repo in component.metadata["source_repositories"]:
                    repo_counts[repo] += 1
            elif component.source_repository:
                repo_counts[component.source_repository] += 1
            else:
                repo_counts["unknown"] += 1
        
        return dict(repo_counts)
    
    def generate_statistics(self) -> Dict[str, Any]:
        """
        Create processing summary and statistics.
        
        Returns:
            Dictionary containing consolidation statistics
        """
        stats = self._consolidation_statistics.copy()
        
        # Convert set to list for JSON serialization
        stats["source_repositories"] = list(stats["source_repositories"])
        
        # Calculate derived statistics
        if stats["components_before_dedup"] > 0:
            stats["deduplication_ratio"] = 1 - (stats["components_after_dedup"] / stats["components_before_dedup"])
            stats["deduplication_percentage"] = stats["deduplication_ratio"] * 100
        else:
            stats["deduplication_ratio"] = 0
            stats["deduplication_percentage"] = 0
        
        if stats["sboms_merged"] > 0:
            stats["average_components_per_sbom"] = stats["components_before_dedup"] / stats["sboms_merged"]
            stats["average_relationships_per_consolidation"] = stats["relationships_merged"] / stats["consolidations_performed"] if stats["consolidations_performed"] > 0 else 0
        else:
            stats["average_components_per_sbom"] = 0
            stats["average_relationships_per_consolidation"] = 0
        
        # Add configuration information
        stats["configuration"] = {
            "duplicate_strategy": self.config.consolidation.duplicate_strategy,
            "preserve_source_info": self.config.consolidation.preserve_source_info,
            "generate_statistics": self.config.consolidation.generate_statistics
        }
        
        return stats
    
    def validate_consolidation(self, original_sboms: List[SBOMDocument], consolidated_sbom: SBOMDocument) -> Dict[str, Any]:
        """
        Validate the consolidation process and results.
        
        Args:
            original_sboms: List of original SBOM documents
            consolidated_sbom: Consolidated SBOM document
            
        Returns:
            Validation results and metrics
        """
        validation_results = {
            "is_valid": True,
            "warnings": [],
            "errors": [],
            "metrics": {}
        }
        
        try:
            # Check component counts
            original_total = sum(sbom.component_count for sbom in original_sboms)
            consolidated_total = consolidated_sbom.component_count
            
            validation_results["metrics"]["original_component_count"] = original_total
            validation_results["metrics"]["consolidated_component_count"] = consolidated_total
            validation_results["metrics"]["deduplication_count"] = original_total - consolidated_total
            
            # Validate that we didn't lose components inappropriately
            if consolidated_total > original_total:
                validation_results["errors"].append("Consolidated SBOM has more components than originals")
                validation_results["is_valid"] = False
            
            # Check for source information preservation
            if self.config.consolidation.preserve_source_info:
                components_without_source = sum(
                    1 for comp in consolidated_sbom.components 
                    if not comp.source_repository and not comp.metadata.get("source_repositories")
                )
                
                if components_without_source > 0:
                    validation_results["warnings"].append(
                        f"{components_without_source} components missing source information"
                    )
            
            # Validate relationships
            relationship_count = len(consolidated_sbom.relationships)
            validation_results["metrics"]["relationship_count"] = relationship_count
            
            # Check for metadata preservation
            if not consolidated_sbom.metadata.get("consolidation_info"):
                validation_results["warnings"].append("Missing consolidation metadata")
            
            # Validate document structure
            if not consolidated_sbom.document_id:
                validation_results["errors"].append("Missing document ID")
                validation_results["is_valid"] = False
            
            if not consolidated_sbom.creator:
                validation_results["errors"].append("Missing creator information")
                validation_results["is_valid"] = False
            
            logger.info(f"Consolidation validation: {'PASSED' if validation_results['is_valid'] else 'FAILED'}")
            
        except Exception as e:
            validation_results["errors"].append(f"Validation error: {e}")
            validation_results["is_valid"] = False
            logger.error(f"Error during consolidation validation: {e}")
        
        return validation_results
    
    def get_consolidation_statistics(self) -> Dict[str, Any]:
        """Get consolidation statistics."""
        return self._consolidation_statistics.copy()
    
    def reset_statistics(self) -> None:
        """Reset consolidation statistics."""
        self._consolidation_statistics = {
            "consolidations_performed": 0,
            "sboms_merged": 0,
            "components_before_dedup": 0,
            "components_after_dedup": 0,
            "relationships_merged": 0,
            "source_repositories": set(),
            "errors": []
        }