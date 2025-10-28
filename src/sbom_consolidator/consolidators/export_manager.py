"""
Export manager for consolidated SBOMs with multiple format support and statistics generation.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

from ..models import SBOMDocument
from ..generators import SBOMGenerator, SBOMFormat
from ..config import get_config

logger = logging.getLogger(__name__)


class ExportManager:
    """
    Export manager for consolidated SBOMs with multiple format support.
    
    This class handles exporting consolidated SBOMs in various formats
    and generates comprehensive statistics and reports.
    """
    
    def __init__(self, sbom_generator: Optional[SBOMGenerator] = None):
        """
        Initialize export manager.
        
        Args:
            sbom_generator: Optional SBOM generator instance
        """
        self.config = get_config()
        self.sbom_generator = sbom_generator or SBOMGenerator()
        
        # Statistics tracking
        self._export_statistics = {
            "exports_performed": 0,
            "formats_exported": {},
            "files_created": 0,
            "total_size_bytes": 0,
            "errors": []
        }
    
    def export_consolidated_sbom(
        self, 
        sbom: SBOMDocument, 
        output_dir: Optional[Path] = None,
        formats: Optional[List[str]] = None,
        include_timestamp: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Export consolidated SBOM in multiple formats.
        
        Args:
            sbom: Consolidated SBOM document to export
            output_dir: Output directory for files
            formats: List of formats to export (defaults to config)
            include_timestamp: Whether to include timestamp in filenames
            
        Returns:
            Dictionary with export results and file paths
        """
        # Use configuration defaults if not specified
        output_dir = output_dir or Path(self.config.output.directory)
        formats = formats or self.config.output.format
        include_timestamp = include_timestamp if include_timestamp is not None else self.config.output.include_timestamp
        
        # Ensure output directory exists
        output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Exporting consolidated SBOM {sbom.document_id} in {len(formats)} formats to {output_dir}")
        
        export_results = {
            "sbom_id": sbom.document_id,
            "export_timestamp": datetime.utcnow().isoformat(),
            "output_directory": str(output_dir),
            "formats": {},
            "statistics": {},
            "errors": []
        }
        
        # Generate base filename
        base_filename = self._generate_filename(sbom, include_timestamp)
        
        # Export in each requested format
        for format_name in formats:
            try:
                format_result = self._export_format(sbom, output_dir, base_filename, format_name)
                export_results["formats"][format_name] = format_result
                
                # Update statistics
                self._export_statistics["formats_exported"][format_name] = self._export_statistics["formats_exported"].get(format_name, 0) + 1
                
            except Exception as e:
                error_msg = f"Failed to export {format_name} format: {e}"
                logger.error(error_msg)
                export_results["errors"].append(error_msg)
                self._export_statistics["errors"].append(error_msg)
        
        # Generate statistics report
        stats_result = self._export_statistics_report(sbom, output_dir, base_filename)
        export_results["statistics"] = stats_result
        
        # Generate summary report
        summary_result = self._export_summary_report(sbom, output_dir, base_filename, export_results)
        export_results["summary"] = summary_result
        
        # Update global statistics
        self._export_statistics["exports_performed"] += 1
        self._export_statistics["files_created"] += len([r for r in export_results["formats"].values() if r.get("success", False)])
        
        logger.info(f"Export completed: {len(export_results['formats'])} formats, "
                   f"{len(export_results['errors'])} errors")
        
        return export_results
    
    def _export_format(self, sbom: SBOMDocument, output_dir: Path, base_filename: str, format_name: str) -> Dict[str, Any]:
        """
        Export SBOM in a specific format.
        
        Args:
            sbom: SBOM document to export
            output_dir: Output directory
            base_filename: Base filename without extension
            format_name: Format to export
            
        Returns:
            Export result dictionary
        """
        format_result = {
            "format": format_name,
            "success": False,
            "file_path": None,
            "file_size": 0,
            "validation_passed": False
        }
        
        try:
            # Determine format and extension
            if format_name.lower() == "spdx":
                sbom_format = SBOMFormat.SPDX
                extension = ".spdx.json"
            elif format_name.lower() == "cyclonedx":
                sbom_format = SBOMFormat.CYCLONEDX
                extension = ".cyclonedx.json"
            elif format_name.lower() == "json":
                sbom_format = SBOMFormat.JSON
                extension = ".json"
            else:
                raise ValueError(f"Unsupported format: {format_name}")
            
            # Generate filename
            filename = f"{base_filename}{extension}"
            file_path = output_dir / filename
            
            # Export SBOM
            if sbom_format == SBOMFormat.JSON:
                # Export as custom JSON format
                exported_content = sbom.to_json()
            else:
                # Use SBOM generator for standard formats
                exported_content = self.sbom_generator.export_format(sbom, sbom_format)
            
            # Write to file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(exported_content)
            
            # Get file size
            file_size = file_path.stat().st_size
            
            # Validate export
            validation_passed = self._validate_export(file_path, format_name, exported_content)
            
            format_result.update({
                "success": True,
                "file_path": str(file_path),
                "file_size": file_size,
                "validation_passed": validation_passed
            })
            
            self._export_statistics["total_size_bytes"] += file_size
            
            logger.info(f"Exported {format_name} format to {file_path} ({file_size} bytes)")
            
        except Exception as e:
            format_result["error"] = str(e)
            logger.error(f"Failed to export {format_name} format: {e}")
        
        return format_result
    
    def _export_statistics_report(self, sbom: SBOMDocument, output_dir: Path, base_filename: str) -> Dict[str, Any]:
        """
        Export detailed statistics report.
        
        Args:
            sbom: SBOM document
            output_dir: Output directory
            base_filename: Base filename
            
        Returns:
            Statistics export result
        """
        stats_result = {
            "success": False,
            "file_path": None,
            "file_size": 0
        }
        
        try:
            # Generate comprehensive statistics
            statistics = self._generate_comprehensive_statistics(sbom)
            
            # Create statistics filename
            stats_filename = f"{base_filename}_statistics.json"
            stats_path = output_dir / stats_filename
            
            # Write statistics to file
            with open(stats_path, 'w', encoding='utf-8') as f:
                json.dump(statistics, f, indent=2, default=str)
            
            file_size = stats_path.stat().st_size
            
            stats_result.update({
                "success": True,
                "file_path": str(stats_path),
                "file_size": file_size
            })
            
            self._export_statistics["total_size_bytes"] += file_size
            
            logger.info(f"Exported statistics report to {stats_path}")
            
        except Exception as e:
            stats_result["error"] = str(e)
            logger.error(f"Failed to export statistics report: {e}")
        
        return stats_result
    
    def _export_summary_report(
        self, 
        sbom: SBOMDocument, 
        output_dir: Path, 
        base_filename: str,
        export_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Export human-readable summary report.
        
        Args:
            sbom: SBOM document
            output_dir: Output directory
            base_filename: Base filename
            export_results: Export results so far
            
        Returns:
            Summary export result
        """
        summary_result = {
            "success": False,
            "file_path": None,
            "file_size": 0
        }
        
        try:
            # Generate summary content
            summary_content = self._generate_summary_content(sbom, export_results)
            
            # Create summary filename
            summary_filename = f"{base_filename}_summary.md"
            summary_path = output_dir / summary_filename
            
            # Write summary to file
            with open(summary_path, 'w', encoding='utf-8') as f:
                f.write(summary_content)
            
            file_size = summary_path.stat().st_size
            
            summary_result.update({
                "success": True,
                "file_path": str(summary_path),
                "file_size": file_size
            })
            
            self._export_statistics["total_size_bytes"] += file_size
            
            logger.info(f"Exported summary report to {summary_path}")
            
        except Exception as e:
            summary_result["error"] = str(e)
            logger.error(f"Failed to export summary report: {e}")
        
        return summary_result
    
    def _generate_filename(self, sbom: SBOMDocument, include_timestamp: bool) -> str:
        """Generate base filename for exports."""
        base_name = self.config.output.consolidated_filename
        
        if include_timestamp:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            return f"{base_name}_{timestamp}"
        else:
            return base_name
    
    def _validate_export(self, file_path: Path, format_name: str, content: str) -> bool:
        """
        Validate exported file.
        
        Args:
            file_path: Path to exported file
            format_name: Format name
            content: File content
            
        Returns:
            True if validation passes
        """
        try:
            # Basic validation - check if file exists and has content
            if not file_path.exists() or file_path.stat().st_size == 0:
                return False
            
            # Format-specific validation
            if format_name.lower() in ["json", "cyclonedx"]:
                # Validate JSON structure
                json.loads(content)
                return True
            elif format_name.lower() == "spdx":
                # Basic SPDX validation
                return "spdxVersion" in content or "SPDXID" in content
            
            return True
            
        except Exception as e:
            logger.warning(f"Validation failed for {format_name}: {e}")
            return False
    
    def _generate_comprehensive_statistics(self, sbom: SBOMDocument) -> Dict[str, Any]:
        """Generate comprehensive statistics for the SBOM."""
        stats = sbom.get_statistics()
        
        # Add consolidation-specific statistics
        consolidation_info = sbom.metadata.get("consolidation_info", {})
        stats["consolidation"] = consolidation_info
        
        # Add risk analysis statistics
        if sbom.risk_analysis:
            risk_stats = {
                "overall_risk_score": sbom.risk_analysis.overall_risk_score,
                "overall_risk_level": sbom.risk_analysis.overall_risk_level.value,
                "component_risk_distribution": {},
                "total_risk_factors": len(sbom.risk_analysis.risk_factors),
                "transitive_risks": len(sbom.risk_analysis.transitive_risks),
                "confidence_score": sbom.risk_analysis.confidence_score
            }
            
            # Calculate risk distribution
            for risk in sbom.risk_analysis.component_risks.values():
                level = risk.risk_level.value
                risk_stats["component_risk_distribution"][level] = risk_stats["component_risk_distribution"].get(level, 0) + 1
            
            stats["risk_analysis"] = risk_stats
        
        # Add security recommendations statistics
        if sbom.security_recommendations:
            rec_stats = {
                "total_recommendations": len(sbom.security_recommendations.recommendations),
                "priority_distribution": {},
                "total_alternatives": len(sbom.security_recommendations.alternative_suggestions),
                "remediation_plan": {
                    "total_recommendations": sbom.security_recommendations.remediation_plan.total_recommendations,
                    "critical_count": sbom.security_recommendations.remediation_plan.critical_count,
                    "high_count": sbom.security_recommendations.remediation_plan.high_count,
                    "medium_count": sbom.security_recommendations.remediation_plan.medium_count,
                    "low_count": sbom.security_recommendations.remediation_plan.low_count,
                    "estimated_total_effort": sbom.security_recommendations.remediation_plan.estimated_total_effort
                }
            }
            
            # Calculate priority distribution
            for rec in sbom.security_recommendations.recommendations:
                priority = rec.priority.value
                rec_stats["priority_distribution"][priority] = rec_stats["priority_distribution"].get(priority, 0) + 1
            
            stats["security_recommendations"] = rec_stats
        
        # Add export metadata
        stats["export_info"] = {
            "export_timestamp": datetime.utcnow().isoformat(),
            "exporter": "github-sbom-consolidator",
            "export_version": "1.0"
        }
        
        return stats
    
    def _generate_summary_content(self, sbom: SBOMDocument, export_results: Dict[str, Any]) -> str:
        """Generate human-readable summary content."""
        content = f"""# SBOM Consolidation Summary

## Document Information
- **Document ID**: {sbom.document_id}
- **Document Name**: {sbom.document_name or 'N/A'}
- **Creation Time**: {sbom.creation_time.isoformat()}
- **Creator**: {sbom.creator}
- **Export Time**: {export_results['export_timestamp']}

## Component Summary
- **Total Components**: {sbom.component_count}
- **Components with Vulnerabilities**: {sbom.vulnerable_component_count}
- **Total Vulnerabilities**: {sbom.total_vulnerability_count}
- **Package Managers**: {', '.join(sbom.package_managers)}
- **Unique Licenses**: {len(sbom.licenses)}

## Consolidation Information
"""
        
        consolidation_info = sbom.metadata.get("consolidation_info", {})
        if consolidation_info:
            content += f"""- **Source SBOMs**: {consolidation_info.get('source_sbom_count', 'N/A')}
- **Source Repositories**: {len(consolidation_info.get('source_repositories', []))}
- **Components Before Deduplication**: {consolidation_info.get('components_before_dedup', 'N/A')}
- **Components After Deduplication**: {consolidation_info.get('components_after_dedup', 'N/A')}
- **Deduplication Ratio**: {consolidation_info.get('deduplication_ratio', 0):.2%}

### Source Repositories
"""
            for repo in consolidation_info.get('source_repositories', []):
                content += f"- {repo}\n"
        
        # Add risk analysis summary
        if sbom.risk_analysis:
            content += f"""
## Risk Analysis Summary
- **Overall Risk Level**: {sbom.risk_analysis.overall_risk_level.value}
- **Overall Risk Score**: {sbom.risk_analysis.overall_risk_score:.1f}/10
- **Components Analyzed**: {len(sbom.risk_analysis.component_risks)}
- **Transitive Risks**: {len(sbom.risk_analysis.transitive_risks)}
- **Confidence Score**: {sbom.risk_analysis.confidence_score:.2f}

### Risk Distribution
"""
            risk_distribution = {}
            for risk in sbom.risk_analysis.component_risks.values():
                level = risk.risk_level.value
                risk_distribution[level] = risk_distribution.get(level, 0) + 1
            
            for level, count in sorted(risk_distribution.items()):
                content += f"- **{level}**: {count} components\n"
        
        # Add security recommendations summary
        if sbom.security_recommendations:
            content += f"""
## Security Recommendations Summary
- **Total Recommendations**: {len(sbom.security_recommendations.recommendations)}
- **Alternative Suggestions**: {len(sbom.security_recommendations.alternative_suggestions)}
- **Estimated Total Effort**: {sbom.security_recommendations.remediation_plan.estimated_total_effort}

### Priority Distribution
- **Critical**: {sbom.security_recommendations.remediation_plan.critical_count}
- **High**: {sbom.security_recommendations.remediation_plan.high_count}
- **Medium**: {sbom.security_recommendations.remediation_plan.medium_count}
- **Low**: {sbom.security_recommendations.remediation_plan.low_count}
"""
        
        # Add export information
        content += f"""
## Export Information
- **Output Directory**: {export_results['output_directory']}
- **Formats Exported**: {len(export_results['formats'])}
- **Export Errors**: {len(export_results['errors'])}

### Exported Files
"""
        
        for format_name, format_result in export_results['formats'].items():
            if format_result.get('success'):
                file_size_kb = format_result['file_size'] / 1024
                content += f"- **{format_name.upper()}**: {format_result['file_path']} ({file_size_kb:.1f} KB)\n"
            else:
                content += f"- **{format_name.upper()}**: Export failed\n"
        
        if export_results.get('statistics', {}).get('success'):
            stats_size_kb = export_results['statistics']['file_size'] / 1024
            content += f"- **Statistics**: {export_results['statistics']['file_path']} ({stats_size_kb:.1f} KB)\n"
        
        return content
    
    def get_export_statistics(self) -> Dict[str, Any]:
        """Get export statistics."""
        stats = self._export_statistics.copy()
        stats["total_size_mb"] = stats["total_size_bytes"] / (1024 * 1024)
        return stats
    
    def reset_statistics(self) -> None:
        """Reset export statistics."""
        self._export_statistics = {
            "exports_performed": 0,
            "formats_exported": {},
            "files_created": 0,
            "total_size_bytes": 0,
            "errors": []
        }