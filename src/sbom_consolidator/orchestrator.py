"""
Orchestration manager for coordinating SBOM generation and consolidation workflows.
"""

import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime

from .models import Repository, SBOMDocument
from .config import get_config, AppConfig
from .repository import RepositoryManager, GitHubClient
from .scanners import DependencyScanner
from .generators import SBOMGenerator
from .consolidators import SBOMConsolidator, ExportManager
from .aws import BedrockClient, AIRiskAnalyzer, SecurityAdvisor

logger = logging.getLogger(__name__)


class OrchestrationManager:
    """
    Coordinates the entire SBOM generation and consolidation process.
    
    This class serves as the main workflow coordinator, managing the interaction
    between repository management, dependency scanning, SBOM generation, and
    consolidation components.
    """
    
    def __init__(self, config: Optional[AppConfig] = None, cli_overrides: Optional[Dict[str, Any]] = None):
        """
        Initialize the orchestration manager.
        
        Args:
            config: Application configuration
            cli_overrides: CLI option overrides
        """
        self.config = config or get_config()
        self.cli_overrides = cli_overrides or {}
        
        # Initialize components
        self.github_client = GitHubClient()
        self.repository_manager = RepositoryManager(self.github_client)
        self.dependency_scanner = DependencyScanner()
        self.sbom_generator = SBOMGenerator()
        self.sbom_consolidator = SBOMConsolidator()
        self.export_manager = ExportManager(self.sbom_generator)
        
        # Initialize AI components if enabled
        self.bedrock_client = None
        self.ai_risk_analyzer = None
        self.security_advisor = None
        
        if self._is_ai_enabled():
            try:
                self.bedrock_client = BedrockClient()
                if self.bedrock_client.is_available():
                    self.ai_risk_analyzer = AIRiskAnalyzer(self.bedrock_client)
                    self.security_advisor = SecurityAdvisor(self.bedrock_client)
                    logger.info("AI-powered analysis enabled")
                else:
                    logger.warning("AI analysis requested but AWS Bedrock not available")
            except Exception as e:
                logger.warning(f"Failed to initialize AI components: {e}")
        
        # Statistics tracking
        self._orchestration_statistics = {
            "start_time": None,
            "end_time": None,
            "repositories_processed": 0,
            "repositories_failed": 0,
            "sboms_generated": 0,
            "consolidation_performed": False,
            "ai_analysis_performed": False,
            "total_dependencies": 0,
            "total_vulnerabilities": 0,
            "errors": []
        }
    
    def process_repositories(
        self,
        repo_urls: List[str],
        branch: Optional[str] = None,
        depth: int = 1,
        consolidate: bool = True,
        cleanup: bool = True
    ) -> Dict[str, Any]:
        """
        Main workflow orchestration for processing multiple repositories.
        
        Args:
            repo_urls: List of GitHub repository URLs to process
            branch: Git branch to analyze
            depth: Git clone depth
            consolidate: Whether to consolidate SBOMs
            cleanup: Whether to clean up temporary files
            
        Returns:
            Dictionary containing processing results and statistics
        """
        self._orchestration_statistics["start_time"] = datetime.utcnow()
        
        logger.info(f"Starting SBOM generation for {len(repo_urls)} repositories")
        
        try:
            # Step 1: Clone repositories
            repositories = self._clone_repositories(repo_urls, branch, depth)
            
            # Step 2: Generate individual SBOMs
            individual_sboms = self._generate_individual_sboms(repositories)
            
            # Step 3: Consolidate SBOMs if requested
            consolidated_sbom = None
            if consolidate and len(individual_sboms) > 1:
                consolidated_sbom = self._consolidate_sboms(individual_sboms)
            elif len(individual_sboms) == 1:
                consolidated_sbom = individual_sboms[0]
            
            # Step 4: Export results
            output_files = self._export_results(individual_sboms, consolidated_sbom)
            
            # Step 5: Generate final statistics
            final_statistics = self._generate_final_statistics(repositories, individual_sboms, consolidated_sbom)
            
            # Step 6: Cleanup if requested
            if cleanup:
                self._cleanup_resources(repositories)
            
            self._orchestration_statistics["end_time"] = datetime.utcnow()
            
            # Compile results
            results = {
                "repositories_processed": len(repositories),
                "repositories_failed": self._orchestration_statistics["repositories_failed"],
                "sboms_generated": len(individual_sboms),
                "consolidated_sbom": self._get_consolidated_sbom_info(consolidated_sbom),
                "output_files": output_files,
                "statistics": final_statistics,
                "errors": self._orchestration_statistics["errors"],
                "processing_time": self._calculate_processing_time()
            }
            
            logger.info(f"SBOM generation completed successfully in {results['processing_time']:.1f} seconds")
            return results
            
        except Exception as e:
            self._orchestration_statistics["errors"].append(f"Orchestration failed: {e}")
            logger.error(f"SBOM generation failed: {e}")
            raise
    
    def _clone_repositories(self, repo_urls: List[str], branch: Optional[str], depth: int) -> List[Repository]:
        """Clone GitHub repositories."""
        logger.info(f"Cloning {len(repo_urls)} repositories")
        
        repositories = []
        for repo_url in repo_urls:
            try:
                repository = self.repository_manager.clone_repository(repo_url, branch, depth)
                repositories.append(repository)
                logger.info(f"Successfully cloned {repository.full_name}")
            except Exception as e:
                error_msg = f"Failed to clone {repo_url}: {e}"
                logger.error(error_msg)
                self._orchestration_statistics["errors"].append(error_msg)
                self._orchestration_statistics["repositories_failed"] += 1
        
        self._orchestration_statistics["repositories_processed"] = len(repositories)
        return repositories
    
    def _generate_individual_sboms(self, repositories: List[Repository]) -> List[SBOMDocument]:
        """Generate SBOMs for each repository."""
        logger.info(f"Generating SBOMs for {len(repositories)} repositories")
        
        individual_sboms = []
        
        for repository in repositories:
            try:
                # Scan dependencies
                dependencies = self.dependency_scanner.scan_repository_dependencies(repository)
                
                if not dependencies:
                    logger.warning(f"No dependencies found in {repository.full_name}")
                    continue
                
                # Create SBOM metadata
                sbom_metadata = {
                    "repository": repository.full_name,
                    "repository_name": repository.name,
                    "repository_url": repository.url,
                    "branch": repository.branch,
                    "language": repository.language,
                    "namespace": f"https://github.com/{repository.full_name}"
                }
                
                # Generate SBOM
                sbom = self.sbom_generator.create_sbom(dependencies, sbom_metadata)
                
                # Add vulnerability information
                if self._is_vulnerability_check_enabled():
                    sbom = self.sbom_generator.add_vulnerability_info(sbom)
                
                # Add license information
                if self._is_license_detection_enabled():
                    sbom = self.sbom_generator.add_license_info(sbom)
                
                # Add AI-powered analysis
                if self._is_ai_enabled() and self.ai_risk_analyzer and self.security_advisor:
                    sbom = self._add_ai_analysis(sbom)
                
                individual_sboms.append(sbom)
                self._orchestration_statistics["sboms_generated"] += 1
                self._orchestration_statistics["total_dependencies"] += len(dependencies)
                self._orchestration_statistics["total_vulnerabilities"] += sbom.total_vulnerability_count
                
                logger.info(f"Generated SBOM for {repository.full_name} with {len(dependencies)} dependencies")
                
            except Exception as e:
                error_msg = f"Failed to generate SBOM for {repository.full_name}: {e}"
                logger.error(error_msg)
                self._orchestration_statistics["errors"].append(error_msg)
        
        return individual_sboms
    
    def _consolidate_sboms(self, sboms: List[SBOMDocument]) -> Optional[SBOMDocument]:
        """Consolidate multiple SBOMs into a unified document."""
        if len(sboms) <= 1:
            return sboms[0] if sboms else None
        
        logger.info(f"Consolidating {len(sboms)} SBOMs")
        
        try:
            consolidated_sbom = self.sbom_consolidator.merge_sboms(sboms)
            consolidated_sbom = self.sbom_consolidator.preserve_source_info(consolidated_sbom)
            
            self._orchestration_statistics["consolidation_performed"] = True
            
            logger.info(f"Successfully consolidated {len(sboms)} SBOMs into unified document")
            return consolidated_sbom
            
        except Exception as e:
            error_msg = f"Failed to consolidate SBOMs: {e}"
            logger.error(error_msg)
            self._orchestration_statistics["errors"].append(error_msg)
            return None
    
    def _add_ai_analysis(self, sbom: SBOMDocument) -> SBOMDocument:
        """Add AI-powered risk analysis and security recommendations."""
        try:
            # Generate risk analysis
            if self.ai_risk_analyzer:
                risk_analysis = self.ai_risk_analyzer.generate_risk_report(sbom.components)
                sbom.risk_analysis = risk_analysis
                logger.debug(f"Added AI risk analysis to SBOM {sbom.document_id}")
            
            # Generate security recommendations
            if self.security_advisor:
                security_recommendations = self.security_advisor.generate_recommendations(
                    sbom, sbom.risk_analysis
                )
                sbom.security_recommendations = security_recommendations
                logger.debug(f"Added AI security recommendations to SBOM {sbom.document_id}")
            
            self._orchestration_statistics["ai_analysis_performed"] = True
            
        except Exception as e:
            logger.warning(f"AI analysis failed for SBOM {sbom.document_id}: {e}")
            self._orchestration_statistics["errors"].append(f"AI analysis failed: {e}")
        
        return sbom
    
    def _export_results(
        self, 
        individual_sboms: List[SBOMDocument], 
        consolidated_sbom: Optional[SBOMDocument]
    ) -> List[str]:
        """Export SBOM results to files."""
        output_files = []
        
        try:
            # Determine output directory
            output_dir = Path(self.cli_overrides.get('output_directory', self.config.output.directory))
            
            # Determine formats
            formats = self.cli_overrides.get('output_formats', self.config.output.format)
            
            # Determine timestamp inclusion
            include_timestamp = self.cli_overrides.get('include_timestamp', self.config.output.include_timestamp)
            
            # Export individual SBOMs if requested
            if not consolidated_sbom or len(individual_sboms) == 1:
                for i, sbom in enumerate(individual_sboms):
                    individual_output_dir = output_dir / f"individual_{i+1}_{sbom.source_repository.replace('/', '_')}"
                    export_result = self.export_manager.export_consolidated_sbom(
                        sbom, individual_output_dir, formats, include_timestamp
                    )
                    
                    # Collect output file paths
                    for format_result in export_result.get('formats', {}).values():
                        if format_result.get('success') and format_result.get('file_path'):
                            output_files.append(format_result['file_path'])
            
            # Export consolidated SBOM
            if consolidated_sbom:
                export_result = self.export_manager.export_consolidated_sbom(
                    consolidated_sbom, output_dir, formats, include_timestamp
                )
                
                # Collect output file paths
                for format_result in export_result.get('formats', {}).values():
                    if format_result.get('success') and format_result.get('file_path'):
                        output_files.append(format_result['file_path'])
                
                # Add statistics and summary files
                if export_result.get('statistics', {}).get('success'):
                    output_files.append(export_result['statistics']['file_path'])
                if export_result.get('summary', {}).get('success'):
                    output_files.append(export_result['summary']['file_path'])
            
            logger.info(f"Exported {len(output_files)} output files")
            
        except Exception as e:
            error_msg = f"Failed to export results: {e}"
            logger.error(error_msg)
            self._orchestration_statistics["errors"].append(error_msg)
        
        return output_files
    
    def _generate_final_statistics(
        self, 
        repositories: List[Repository], 
        individual_sboms: List[SBOMDocument],
        consolidated_sbom: Optional[SBOMDocument]
    ) -> Dict[str, Any]:
        """Generate comprehensive final statistics."""
        stats = self._orchestration_statistics.copy()
        
        # Add component statistics
        if consolidated_sbom:
            stats.update({
                "consolidated_components": consolidated_sbom.component_count,
                "consolidated_vulnerabilities": consolidated_sbom.total_vulnerability_count,
                "unique_licenses": len(consolidated_sbom.licenses),
                "package_managers": consolidated_sbom.package_managers
            })
        
        # Add scanner statistics
        scanner_stats = self.dependency_scanner.get_scan_statistics()
        stats["scanning"] = scanner_stats
        
        # Add generator statistics
        generator_stats = self.sbom_generator.get_generation_statistics()
        stats["generation"] = generator_stats
        
        # Add consolidation statistics
        if self._orchestration_statistics["consolidation_performed"]:
            consolidation_stats = self.sbom_consolidator.get_consolidation_statistics()
            stats["consolidation"] = consolidation_stats
        
        # Add AI statistics
        if self._orchestration_statistics["ai_analysis_performed"]:
            if self.ai_risk_analyzer:
                stats["ai_risk_analysis"] = self.ai_risk_analyzer.get_analysis_statistics()
            if self.security_advisor:
                stats["ai_security_advisor"] = self.security_advisor.get_advisor_statistics()
        
        # Add export statistics
        export_stats = self.export_manager.get_export_statistics()
        stats["export"] = export_stats
        
        return stats
    
    def _cleanup_resources(self, repositories: List[Repository]) -> None:
        """Clean up temporary resources."""
        try:
            cleanup_count = self.repository_manager.cleanup_all_repositories()
            logger.info(f"Cleaned up {cleanup_count} temporary repositories")
        except Exception as e:
            logger.warning(f"Cleanup failed: {e}")
    
    def _get_consolidated_sbom_info(self, consolidated_sbom: Optional[SBOMDocument]) -> Optional[Dict[str, Any]]:
        """Get consolidated SBOM information for results."""
        if not consolidated_sbom:
            return None
        
        return {
            "document_id": consolidated_sbom.document_id,
            "component_count": consolidated_sbom.component_count,
            "vulnerability_count": consolidated_sbom.total_vulnerability_count,
            "relationship_count": consolidated_sbom.relationship_count,
            "has_risk_analysis": consolidated_sbom.risk_analysis is not None,
            "has_security_recommendations": consolidated_sbom.security_recommendations is not None
        }
    
    def _calculate_processing_time(self) -> float:
        """Calculate total processing time in seconds."""
        if self._orchestration_statistics["start_time"] and self._orchestration_statistics["end_time"]:
            delta = self._orchestration_statistics["end_time"] - self._orchestration_statistics["start_time"]
            return delta.total_seconds()
        return 0.0
    
    def _is_ai_enabled(self) -> bool:
        """Check if AI analysis is enabled."""
        return (
            self.cli_overrides.get('ai_analysis', True) and
            self.config.bedrock.enable_risk_analysis and
            self.config.bedrock.enable_security_recommendations
        )
    
    def _is_vulnerability_check_enabled(self) -> bool:
        """Check if vulnerability checking is enabled."""
        return self.cli_overrides.get('vulnerability_check', self.config.scanning.vulnerability_check)
    
    def _is_license_detection_enabled(self) -> bool:
        """Check if license detection is enabled."""
        return self.cli_overrides.get('license_detection', self.config.scanning.license_detection)
    
    def get_orchestration_statistics(self) -> Dict[str, Any]:
        """Get orchestration statistics."""
        return self._orchestration_statistics.copy()