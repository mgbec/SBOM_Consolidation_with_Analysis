"""
AI-powered dependency risk analyzer using AWS Bedrock AgentCore.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from ..models import Dependency, RiskAnalysis, ComponentRisk, TransitiveRisk, RiskLevel
from .bedrock_client import BedrockClient

logger = logging.getLogger(__name__)


class AIRiskAnalyzer:
    """
    AI-powered dependency risk analyzer using AWS Bedrock foundation models.
    
    This class provides intelligent dependency risk assessment by analyzing
    components, their versions, vulnerabilities, and relationships using
    advanced AI models.
    """
    
    def __init__(self, bedrock_client: Optional[BedrockClient] = None):
        """
        Initialize AI risk analyzer.
        
        Args:
            bedrock_client: Optional Bedrock client instance
        """
        self.bedrock_client = bedrock_client or BedrockClient()
        
        # Risk analysis cache to avoid redundant API calls
        self._analysis_cache = {}
        
        # Statistics tracking
        self._analysis_statistics = {
            "analyses_performed": 0,
            "components_analyzed": 0,
            "high_risk_components": 0,
            "cache_hits": 0,
            "api_calls": 0,
            "errors": []
        }
    
    def analyze_dependency_risk(self, dependency: Dependency) -> ComponentRisk:
        """
        Generate AI-powered risk score for a single dependency.
        
        Args:
            dependency: Dependency to analyze
            
        Returns:
            ComponentRisk object with AI-generated assessment
        """
        # Check cache first
        cache_key = f"{dependency.name}:{dependency.version}:{dependency.package_manager.value}"
        if cache_key in self._analysis_cache:
            self._analysis_statistics["cache_hits"] += 1
            return self._analysis_cache[cache_key]
        
        logger.debug(f"Analyzing risk for dependency: {dependency.name}@{dependency.version}")
        
        try:
            # Prepare dependency data for AI analysis
            dependency_data = {
                "dependencies": [dependency.to_dict()],
                "repository": {
                    "name": dependency.source_repository or "unknown",
                    "language": dependency.metadata.get("language", "unknown") if dependency.metadata else "unknown"
                }
            }
            
            # Get AI analysis
            ai_analysis = self.bedrock_client.analyze_dependency_risk(dependency_data)
            
            if ai_analysis and "component_risks" in ai_analysis:
                # Extract risk for this specific component
                for comp_risk in ai_analysis["component_risks"]:
                    if comp_risk.get("component_name") == dependency.name:
                        risk = self._create_component_risk_from_ai(comp_risk, dependency)
                        self._analysis_cache[cache_key] = risk
                        self._analysis_statistics["api_calls"] += 1
                        return risk
            
            # Fallback to heuristic analysis if AI fails
            logger.warning(f"AI analysis failed for {dependency.name}, using heuristic fallback")
            risk = self._heuristic_risk_analysis(dependency)
            self._analysis_cache[cache_key] = risk
            return risk
            
        except Exception as e:
            logger.error(f"Error analyzing risk for {dependency.name}: {e}")
            self._analysis_statistics["errors"].append(f"Risk analysis failed for {dependency.name}: {e}")
            
            # Return default risk assessment
            return ComponentRisk(
                component_name=dependency.name,
                risk_score=5.0,
                risk_level=RiskLevel.MEDIUM,
                risk_factors=["Analysis failed - using default assessment"],
                confidence_score=0.1,
                vulnerability_count=len(dependency.vulnerabilities),
                last_updated=datetime.utcnow()
            )
    
    def assess_transitive_risks(self, dependency_chain: List[Dependency]) -> List[TransitiveRisk]:
        """
        Analyze dependency chain risks using AI.
        
        Args:
            dependency_chain: List of dependencies in a chain
            
        Returns:
            List of transitive risks identified
        """
        if len(dependency_chain) < 2:
            return []
        
        logger.debug(f"Analyzing transitive risks for chain of {len(dependency_chain)} dependencies")
        
        try:
            # Prepare chain data for AI analysis
            chain_data = {
                "dependencies": [dep.to_dict() for dep in dependency_chain],
                "repository": {
                    "name": dependency_chain[0].source_repository or "unknown",
                    "language": dependency_chain[0].metadata.get("language", "unknown") if dependency_chain[0].metadata else "unknown"
                }
            }
            
            # Get AI analysis
            ai_analysis = self.bedrock_client.analyze_dependency_risk(chain_data)
            
            transitive_risks = []
            if ai_analysis and "transitive_risks" in ai_analysis:
                for risk_data in ai_analysis["transitive_risks"]:
                    transitive_risk = TransitiveRisk(
                        source_component=risk_data.get("source_component", "unknown"),
                        target_component=risk_data.get("target_component", "unknown"),
                        risk_path=[dep.name for dep in dependency_chain],
                        risk_score=float(risk_data.get("risk_score", 5.0)),
                        description=risk_data.get("description", "AI-identified transitive risk")
                    )
                    transitive_risks.append(transitive_risk)
            
            self._analysis_statistics["api_calls"] += 1
            return transitive_risks
            
        except Exception as e:
            logger.error(f"Error analyzing transitive risks: {e}")
            self._analysis_statistics["errors"].append(f"Transitive risk analysis failed: {e}")
            return []
    
    def evaluate_project_context(self, project_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Consider project-specific risk factors using AI.
        
        Args:
            project_metadata: Project metadata and context
            
        Returns:
            Dictionary of project-specific risk factors
        """
        logger.debug("Evaluating project context for risk assessment")
        
        try:
            # Create prompt for project context evaluation
            prompt = f"""
Analyze the following project context and identify specific security risk factors:

Project Information:
- Name: {project_metadata.get('name', 'Unknown')}
- Language: {project_metadata.get('language', 'Unknown')}
- Description: {project_metadata.get('description', 'N/A')}
- Stars: {project_metadata.get('stars', 0)}
- Forks: {project_metadata.get('forks', 0)}
- Last Updated: {project_metadata.get('last_updated', 'Unknown')}
- License: {project_metadata.get('license', 'Unknown')}

Please provide a JSON response with project-specific risk factors:
{{
  "project_risk_level": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "risk_factors": [
    "list of project-specific risk factors"
  ],
  "security_recommendations": [
    "project-specific security recommendations"
  ],
  "confidence_score": <float 0-1>
}}
"""
            
            response = self.bedrock_client.invoke_model(
                self.bedrock_client.config.bedrock.risk_analysis_model,
                prompt
            )
            
            if response:
                import json
                try:
                    context_analysis = json.loads(response)
                    self._analysis_statistics["api_calls"] += 1
                    return context_analysis
                except json.JSONDecodeError:
                    logger.warning("Failed to parse project context analysis JSON")
            
            # Fallback to basic heuristics
            return self._heuristic_project_analysis(project_metadata)
            
        except Exception as e:
            logger.error(f"Error evaluating project context: {e}")
            self._analysis_statistics["errors"].append(f"Project context evaluation failed: {e}")
            return {"project_risk_level": "MEDIUM", "risk_factors": [], "confidence_score": 0.1}
    
    def generate_risk_report(self, dependencies: List[Dependency]) -> RiskAnalysis:
        """
        Create comprehensive risk assessment for a list of dependencies.
        
        Args:
            dependencies: List of dependencies to analyze
            
        Returns:
            Complete risk analysis report
        """
        logger.info(f"Generating comprehensive risk report for {len(dependencies)} dependencies")
        
        # Analyze individual components
        component_risks = {}
        total_risk_score = 0.0
        high_risk_count = 0
        
        for dependency in dependencies:
            try:
                risk = self.analyze_dependency_risk(dependency)
                component_risks[dependency.name] = risk
                total_risk_score += risk.risk_score
                
                if risk.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                    high_risk_count += 1
                    
            except Exception as e:
                logger.error(f"Failed to analyze {dependency.name}: {e}")
                continue
        
        # Calculate overall risk
        overall_risk_score = total_risk_score / len(dependencies) if dependencies else 0.0
        overall_risk_level = self._calculate_overall_risk_level(overall_risk_score, high_risk_count, len(dependencies))
        
        # Analyze transitive risks
        transitive_risks = []
        try:
            # Group dependencies by package manager for chain analysis
            pm_groups = {}
            for dep in dependencies:
                pm = dep.package_manager.value
                if pm not in pm_groups:
                    pm_groups[pm] = []
                pm_groups[pm].append(dep)
            
            # Analyze chains within each package manager
            for pm, deps in pm_groups.items():
                if len(deps) > 1:
                    chain_risks = self.assess_transitive_risks(deps[:5])  # Limit chain size
                    transitive_risks.extend(chain_risks)
                    
        except Exception as e:
            logger.error(f"Failed to analyze transitive risks: {e}")
        
        # Compile risk factors
        risk_factors = []
        if high_risk_count > 0:
            risk_factors.append(f"{high_risk_count} high-risk components identified")
        if len(transitive_risks) > 0:
            risk_factors.append(f"{len(transitive_risks)} transitive risks found")
        
        # Add vulnerability summary
        total_vulns = sum(len(dep.vulnerabilities) for dep in dependencies)
        if total_vulns > 0:
            risk_factors.append(f"{total_vulns} known vulnerabilities across components")
        
        # Create risk analysis
        risk_analysis = RiskAnalysis(
            overall_risk_score=overall_risk_score,
            overall_risk_level=overall_risk_level,
            component_risks=component_risks,
            transitive_risks=transitive_risks,
            risk_factors=risk_factors,
            analysis_timestamp=datetime.utcnow(),
            model_used=self.bedrock_client.config.bedrock.risk_analysis_model,
            confidence_score=self._calculate_confidence_score(component_risks),
            metadata={
                "total_components": len(dependencies),
                "high_risk_components": high_risk_count,
                "total_vulnerabilities": total_vulns,
                "analysis_method": "ai_powered"
            }
        )
        
        # Update statistics
        self._analysis_statistics["analyses_performed"] += 1
        self._analysis_statistics["components_analyzed"] += len(dependencies)
        self._analysis_statistics["high_risk_components"] += high_risk_count
        
        logger.info(f"Risk analysis complete: {overall_risk_level.value} risk level ({overall_risk_score:.1f}/10)")
        return risk_analysis
    
    def _create_component_risk_from_ai(self, ai_risk_data: Dict[str, Any], dependency: Dependency) -> ComponentRisk:
        """Create ComponentRisk from AI analysis data."""
        risk_level_str = ai_risk_data.get("risk_level", "MEDIUM").upper()
        try:
            risk_level = RiskLevel(risk_level_str)
        except ValueError:
            risk_level = RiskLevel.MEDIUM
        
        return ComponentRisk(
            component_name=dependency.name,
            risk_score=float(ai_risk_data.get("risk_score", 5.0)),
            risk_level=risk_level,
            risk_factors=ai_risk_data.get("risk_factors", []),
            confidence_score=float(ai_risk_data.get("confidence_score", 0.8)),
            vulnerability_count=len(dependency.vulnerabilities),
            last_updated=datetime.utcnow(),
            metadata={
                "ai_analysis": True,
                "model_used": self.bedrock_client.config.bedrock.risk_analysis_model
            }
        )
    
    def _heuristic_risk_analysis(self, dependency: Dependency) -> ComponentRisk:
        """Fallback heuristic risk analysis when AI is unavailable."""
        risk_score = 5.0  # Default medium risk
        risk_factors = []
        
        # Factor in vulnerabilities
        vuln_count = len(dependency.vulnerabilities)
        if vuln_count > 0:
            risk_score += min(vuln_count * 1.5, 3.0)
            risk_factors.append(f"{vuln_count} known vulnerabilities")
        
        # Factor in version patterns
        if dependency.version:
            if dependency.version.startswith("0."):
                risk_score += 1.0
                risk_factors.append("Pre-1.0 version (potentially unstable)")
            elif "beta" in dependency.version.lower() or "alpha" in dependency.version.lower():
                risk_score += 1.5
                risk_factors.append("Pre-release version")
        
        # Factor in dependency type
        if dependency.dependency_type.value == "dev":
            risk_score -= 0.5  # Dev dependencies are slightly less risky
        
        # Determine risk level
        if risk_score >= 8.0:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 6.0:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 4.0:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        return ComponentRisk(
            component_name=dependency.name,
            risk_score=min(risk_score, 10.0),
            risk_level=risk_level,
            risk_factors=risk_factors,
            confidence_score=0.6,  # Lower confidence for heuristic analysis
            vulnerability_count=vuln_count,
            last_updated=datetime.utcnow(),
            metadata={"analysis_method": "heuristic"}
        )
    
    def _heuristic_project_analysis(self, project_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback heuristic project analysis."""
        risk_factors = []
        
        # Check project activity
        stars = project_metadata.get("stars", 0)
        if stars < 10:
            risk_factors.append("Low community adoption (few stars)")
        
        # Check license
        license_name = project_metadata.get("license")
        if not license_name:
            risk_factors.append("No license specified")
        
        # Determine risk level
        risk_level = "MEDIUM"
        if len(risk_factors) > 2:
            risk_level = "HIGH"
        elif len(risk_factors) == 0:
            risk_level = "LOW"
        
        return {
            "project_risk_level": risk_level,
            "risk_factors": risk_factors,
            "security_recommendations": ["Regular dependency updates", "Security scanning"],
            "confidence_score": 0.5
        }
    
    def _calculate_overall_risk_level(self, avg_score: float, high_risk_count: int, total_count: int) -> RiskLevel:
        """Calculate overall risk level from component analysis."""
        high_risk_ratio = high_risk_count / total_count if total_count > 0 else 0
        
        if avg_score >= 8.0 or high_risk_ratio >= 0.3:
            return RiskLevel.CRITICAL
        elif avg_score >= 6.0 or high_risk_ratio >= 0.1:
            return RiskLevel.HIGH
        elif avg_score >= 4.0:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _calculate_confidence_score(self, component_risks: Dict[str, ComponentRisk]) -> float:
        """Calculate overall confidence score from component analyses."""
        if not component_risks:
            return 0.0
        
        total_confidence = sum(risk.confidence_score for risk in component_risks.values())
        return total_confidence / len(component_risks)
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get risk analysis statistics."""
        return self._analysis_statistics.copy()
    
    def reset_statistics(self) -> None:
        """Reset analysis statistics."""
        self._analysis_statistics = {
            "analyses_performed": 0,
            "components_analyzed": 0,
            "high_risk_components": 0,
            "cache_hits": 0,
            "api_calls": 0,
            "errors": []
        }
    
    def clear_cache(self) -> None:
        """Clear the analysis cache."""
        self._analysis_cache.clear()
        logger.info("Risk analysis cache cleared")