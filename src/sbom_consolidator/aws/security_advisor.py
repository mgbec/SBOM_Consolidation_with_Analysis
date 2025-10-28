"""
AI-powered security advisor using AWS Bedrock AgentCore for automated recommendations.
"""

import logging
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime

from ..models import (
    SBOMDocument, SecurityRecommendations, SecurityRecommendation, 
    RemediationPlan, AlternativeSuggestion, Priority, RiskAnalysis
)
from .bedrock_client import BedrockClient

logger = logging.getLogger(__name__)


class SecurityAdvisor:
    """
    AI-powered security advisor using AWS Bedrock foundation models.
    
    This class generates automated security recommendations, suggests
    safer alternatives, and creates remediation plans based on SBOM
    analysis and risk assessment.
    """
    
    def __init__(self, bedrock_client: Optional[BedrockClient] = None):
        """
        Initialize security advisor.
        
        Args:
            bedrock_client: Optional Bedrock client instance
        """
        self.bedrock_client = bedrock_client or BedrockClient()
        
        # Statistics tracking
        self._advisor_statistics = {
            "recommendations_generated": 0,
            "remediation_plans_created": 0,
            "alternatives_suggested": 0,
            "api_calls": 0,
            "errors": []
        }
    
    def generate_recommendations(
        self, 
        sbom: SBOMDocument, 
        risk_analysis: Optional[RiskAnalysis] = None
    ) -> SecurityRecommendations:
        """
        Create security recommendations based on SBOM and risk analysis.
        
        Args:
            sbom: SBOM document to analyze
            risk_analysis: Optional risk analysis results
            
        Returns:
            Complete security recommendations
        """
        logger.info(f"Generating security recommendations for SBOM {sbom.document_id}")
        
        try:
            # Prepare data for AI analysis
            sbom_data = self._prepare_sbom_data(sbom)
            risk_data = risk_analysis.to_dict() if risk_analysis else None
            
            # Get AI-generated recommendations
            ai_recommendations = self.bedrock_client.generate_security_recommendations(
                sbom_data, risk_data
            )
            
            if ai_recommendations:
                recommendations = self._parse_ai_recommendations(ai_recommendations)
            else:
                logger.warning("AI recommendations failed, using heuristic fallback")
                recommendations = self._generate_heuristic_recommendations(sbom, risk_analysis)
            
            # Create remediation plan
            remediation_plan = self._create_remediation_plan(recommendations["recommendations"])
            
            # Generate alternative suggestions
            alternatives = recommendations.get("alternative_suggestions", [])
            if not alternatives and risk_analysis:
                alternatives = self._suggest_alternatives_from_risk(risk_analysis)
            
            # Compile final recommendations
            security_recommendations = SecurityRecommendations(
                recommendations=recommendations["recommendations"],
                remediation_plan=remediation_plan,
                alternative_suggestions=alternatives,
                contextual_guidance=recommendations.get("contextual_guidance", []),
                generation_timestamp=datetime.utcnow(),
                model_used=self.bedrock_client.config.bedrock.security_advisor_model,
                metadata={
                    "sbom_id": sbom.document_id,
                    "total_components": sbom.component_count,
                    "generation_method": "ai_powered" if ai_recommendations else "heuristic"
                }
            )
            
            # Update statistics
            self._advisor_statistics["recommendations_generated"] += len(recommendations["recommendations"])
            self._advisor_statistics["remediation_plans_created"] += 1
            self._advisor_statistics["alternatives_suggested"] += len(alternatives)
            if ai_recommendations:
                self._advisor_statistics["api_calls"] += 1
            
            logger.info(f"Generated {len(recommendations['recommendations'])} security recommendations")
            return security_recommendations
            
        except Exception as e:
            logger.error(f"Error generating security recommendations: {e}")
            self._advisor_statistics["errors"].append(f"Recommendation generation failed: {e}")
            
            # Return minimal recommendations
            return self._create_minimal_recommendations(sbom)
    
    def suggest_alternatives(self, high_risk_dependencies: List[str]) -> List[AlternativeSuggestion]:
        """
        Recommend safer alternatives for high-risk dependencies.
        
        Args:
            high_risk_dependencies: List of high-risk dependency names
            
        Returns:
            List of alternative suggestions
        """
        logger.info(f"Suggesting alternatives for {len(high_risk_dependencies)} high-risk dependencies")
        
        alternatives = []
        
        for dep_name in high_risk_dependencies:
            try:
                # Create prompt for alternative suggestions
                prompt = f"""
Suggest safer alternatives for the following high-risk software dependency:

Dependency: {dep_name}

Please provide alternative packages that:
1. Provide similar functionality
2. Have better security track records
3. Are actively maintained
4. Have good community support

Respond in JSON format:
{{
  "alternatives": [
    {{
      "alternative_component": "package_name",
      "reason": "Why this alternative is better",
      "risk_reduction": <float 0-10>,
      "compatibility_notes": "Migration considerations",
      "migration_effort": "<LOW|MEDIUM|HIGH>"
    }}
  ]
}}
"""
                
                response = self.bedrock_client.invoke_model(
                    self.bedrock_client.config.bedrock.security_advisor_model,
                    prompt,
                    max_tokens=1000
                )
                
                if response:
                    import json
                    try:
                        alt_data = json.loads(response)
                        for alt in alt_data.get("alternatives", []):
                            suggestion = AlternativeSuggestion(
                                original_component=dep_name,
                                alternative_component=alt.get("alternative_component", "unknown"),
                                reason=alt.get("reason", "AI-suggested alternative"),
                                risk_reduction=float(alt.get("risk_reduction", 5.0)),
                                compatibility_notes=alt.get("compatibility_notes", "Review compatibility before migration"),
                                migration_effort=alt.get("migration_effort", "MEDIUM")
                            )
                            alternatives.append(suggestion)
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse alternatives JSON for {dep_name}")
                
                self._advisor_statistics["api_calls"] += 1
                
            except Exception as e:
                logger.error(f"Error suggesting alternatives for {dep_name}: {e}")
                continue
        
        logger.info(f"Generated {len(alternatives)} alternative suggestions")
        return alternatives
    
    def create_remediation_plan(self, vulnerabilities: List[Dict[str, Any]]) -> RemediationPlan:
        """
        Generate step-by-step remediation plan for vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerability information
            
        Returns:
            Structured remediation plan
        """
        logger.info(f"Creating remediation plan for {len(vulnerabilities)} vulnerabilities")
        
        try:
            # Create prompt for remediation planning
            vuln_summary = "\n".join([
                f"- {vuln.get('component', 'unknown')}: {vuln.get('vulnerability_id', 'unknown')} "
                f"(Severity: {vuln.get('severity', 'unknown')})"
                for vuln in vulnerabilities[:10]  # Limit for prompt size
            ])
            
            prompt = f"""
Create a prioritized remediation plan for the following security vulnerabilities:

Vulnerabilities:
{vuln_summary}

Please provide a structured remediation plan in JSON format:
{{
  "plan_id": "unique_plan_id",
  "priority_order": ["rec_1", "rec_2", "rec_3"],
  "estimated_total_effort": "<LOW|MEDIUM|HIGH>",
  "critical_count": <number>,
  "high_count": <number>,
  "medium_count": <number>,
  "low_count": <number>
}}

Prioritize based on:
1. Vulnerability severity (Critical > High > Medium > Low)
2. Exploitability and impact
3. Ease of remediation
4. Dependency relationships
"""
            
            response = self.bedrock_client.invoke_model(
                self.bedrock_client.config.bedrock.security_advisor_model,
                prompt,
                max_tokens=800
            )
            
            if response:
                import json
                try:
                    plan_data = json.loads(response)
                    return RemediationPlan(
                        plan_id=plan_data.get("plan_id", str(uuid.uuid4())),
                        total_recommendations=len(vulnerabilities),
                        critical_count=plan_data.get("critical_count", 0),
                        high_count=plan_data.get("high_count", 0),
                        medium_count=plan_data.get("medium_count", 0),
                        low_count=plan_data.get("low_count", 0),
                        estimated_total_effort=plan_data.get("estimated_total_effort", "MEDIUM"),
                        priority_order=plan_data.get("priority_order", [])
                    )
                except json.JSONDecodeError:
                    logger.warning("Failed to parse remediation plan JSON")
            
            self._advisor_statistics["api_calls"] += 1
            
        except Exception as e:
            logger.error(f"Error creating remediation plan: {e}")
        
        # Fallback to heuristic plan
        return self._create_heuristic_remediation_plan(vulnerabilities)
    
    def provide_contextual_guidance(self, project_type: str) -> List[str]:
        """
        Offer project-specific security advice.
        
        Args:
            project_type: Type of project (web, mobile, library, etc.)
            
        Returns:
            List of contextual security guidance
        """
        logger.info(f"Providing contextual guidance for {project_type} project")
        
        try:
            prompt = f"""
Provide security best practices and guidance for a {project_type} software project.

Focus on:
1. Dependency management best practices
2. Security monitoring and alerting
3. Supply chain security measures
4. Project-specific security considerations
5. Compliance and regulatory considerations

Provide 5-10 actionable recommendations as a JSON array:
{{
  "guidance": [
    "Specific security recommendation 1",
    "Specific security recommendation 2",
    "..."
  ]
}}
"""
            
            response = self.bedrock_client.invoke_model(
                self.bedrock_client.config.bedrock.security_advisor_model,
                prompt,
                max_tokens=1000
            )
            
            if response:
                import json
                try:
                    guidance_data = json.loads(response)
                    self._advisor_statistics["api_calls"] += 1
                    return guidance_data.get("guidance", [])
                except json.JSONDecodeError:
                    logger.warning("Failed to parse contextual guidance JSON")
            
        except Exception as e:
            logger.error(f"Error providing contextual guidance: {e}")
        
        # Fallback to generic guidance
        return self._get_generic_security_guidance(project_type)
    
    def _prepare_sbom_data(self, sbom: SBOMDocument) -> Dict[str, Any]:
        """Prepare SBOM data for AI analysis."""
        return {
            "document_id": sbom.document_id,
            "component_count": sbom.component_count,
            "vulnerable_components": sbom.vulnerable_component_count,
            "total_vulnerabilities": sbom.total_vulnerability_count,
            "package_managers": sbom.package_managers,
            "licenses": sbom.licenses,
            "dependencies": [comp.to_dict() for comp in sbom.components[:50]],  # Limit for prompt size
            "repository": {
                "name": sbom.source_repository or "unknown",
                "namespace": sbom.document_namespace
            }
        }
    
    def _parse_ai_recommendations(self, ai_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse AI-generated recommendations into structured format."""
        recommendations = []
        
        for rec_data in ai_data.get("recommendations", []):
            try:
                priority_str = rec_data.get("priority", "MEDIUM").upper()
                priority = Priority(priority_str) if priority_str in [p.value for p in Priority] else Priority.MEDIUM
                
                recommendation = SecurityRecommendation(
                    recommendation_id=rec_data.get("recommendation_id", str(uuid.uuid4())),
                    priority=priority,
                    title=rec_data.get("title", "Security Recommendation"),
                    description=rec_data.get("description", ""),
                    affected_components=rec_data.get("affected_components", []),
                    remediation_steps=rec_data.get("remediation_steps", []),
                    estimated_effort=rec_data.get("estimated_effort", "MEDIUM"),
                    risk_reduction=float(rec_data.get("risk_reduction", 5.0)),
                    references=rec_data.get("references", [])
                )
                recommendations.append(recommendation)
            except Exception as e:
                logger.warning(f"Failed to parse recommendation: {e}")
                continue
        
        # Parse alternative suggestions
        alternatives = []
        for alt_data in ai_data.get("alternative_suggestions", []):
            try:
                alternative = AlternativeSuggestion(
                    original_component=alt_data.get("original_component", "unknown"),
                    alternative_component=alt_data.get("alternative_component", "unknown"),
                    reason=alt_data.get("reason", "AI-suggested alternative"),
                    risk_reduction=float(alt_data.get("risk_reduction", 5.0)),
                    compatibility_notes=alt_data.get("compatibility_notes", "Review compatibility"),
                    migration_effort=alt_data.get("migration_effort", "MEDIUM")
                )
                alternatives.append(alternative)
            except Exception as e:
                logger.warning(f"Failed to parse alternative suggestion: {e}")
                continue
        
        return {
            "recommendations": recommendations,
            "alternative_suggestions": alternatives,
            "contextual_guidance": ai_data.get("contextual_guidance", [])
        }
    
    def _generate_heuristic_recommendations(
        self, 
        sbom: SBOMDocument, 
        risk_analysis: Optional[RiskAnalysis] = None
    ) -> Dict[str, Any]:
        """Generate recommendations using heuristic rules when AI is unavailable."""
        recommendations = []
        
        # Recommendation for vulnerable components
        if sbom.vulnerable_component_count > 0:
            vuln_components = [comp.name for comp in sbom.components if comp.has_vulnerabilities]
            recommendations.append(SecurityRecommendation(
                recommendation_id="heuristic_vuln_update",
                priority=Priority.HIGH,
                title="Update Vulnerable Dependencies",
                description=f"Update {sbom.vulnerable_component_count} components with known vulnerabilities",
                affected_components=vuln_components[:10],  # Limit list size
                remediation_steps=[
                    "Review vulnerability details for each component",
                    "Update to latest secure versions",
                    "Test application after updates",
                    "Monitor for new vulnerabilities"
                ],
                estimated_effort="MEDIUM",
                risk_reduction=8.0
            ))
        
        # Recommendation for dependency monitoring
        recommendations.append(SecurityRecommendation(
            recommendation_id="heuristic_monitoring",
            priority=Priority.MEDIUM,
            title="Implement Dependency Monitoring",
            description="Set up automated monitoring for new vulnerabilities in dependencies",
            affected_components=[],
            remediation_steps=[
                "Configure automated vulnerability scanning",
                "Set up alerts for new security advisories",
                "Establish regular dependency update schedule",
                "Document security response procedures"
            ],
            estimated_effort="LOW",
            risk_reduction=6.0
        ))
        
        # High-risk component recommendations
        if risk_analysis:
            high_risk_components = [
                name for name, risk in risk_analysis.component_risks.items()
                if risk.risk_level in ["HIGH", "CRITICAL"]
            ]
            
            if high_risk_components:
                recommendations.append(SecurityRecommendation(
                    recommendation_id="heuristic_high_risk",
                    priority=Priority.HIGH,
                    title="Review High-Risk Dependencies",
                    description=f"Evaluate {len(high_risk_components)} high-risk dependencies for replacement",
                    affected_components=high_risk_components[:10],
                    remediation_steps=[
                        "Assess necessity of each high-risk dependency",
                        "Research safer alternatives",
                        "Plan migration strategy for critical components",
                        "Implement additional security controls if replacement not feasible"
                    ],
                    estimated_effort="HIGH",
                    risk_reduction=7.0
                ))
        
        return {
            "recommendations": recommendations,
            "alternative_suggestions": [],
            "contextual_guidance": [
                "Regularly update dependencies to latest secure versions",
                "Use dependency scanning tools in CI/CD pipeline",
                "Maintain an inventory of all third-party components",
                "Establish security policies for dependency management"
            ]
        }
    
    def _suggest_alternatives_from_risk(self, risk_analysis: RiskAnalysis) -> List[AlternativeSuggestion]:
        """Generate alternative suggestions based on risk analysis."""
        alternatives = []
        
        # Get high-risk components
        high_risk_components = [
            name for name, risk in risk_analysis.component_risks.items()
            if risk.risk_level in ["HIGH", "CRITICAL"]
        ]
        
        # Create generic alternative suggestions
        for component in high_risk_components[:5]:  # Limit to top 5
            alternatives.append(AlternativeSuggestion(
                original_component=component,
                alternative_component=f"safer-alternative-for-{component}",
                reason="High risk component should be replaced with safer alternative",
                risk_reduction=6.0,
                compatibility_notes="Evaluate API compatibility before migration",
                migration_effort="MEDIUM"
            ))
        
        return alternatives
    
    def _create_remediation_plan(self, recommendations: List[SecurityRecommendation]) -> RemediationPlan:
        """Create remediation plan from recommendations."""
        # Count by priority
        priority_counts = {Priority.CRITICAL: 0, Priority.HIGH: 0, Priority.MEDIUM: 0, Priority.LOW: 0}
        for rec in recommendations:
            priority_counts[rec.priority] += 1
        
        # Sort by priority for execution order
        priority_order = sorted(
            [rec.recommendation_id for rec in recommendations],
            key=lambda rec_id: next(
                (rec.priority.value for rec in recommendations if rec.recommendation_id == rec_id),
                "MEDIUM"
            ),
            reverse=True
        )
        
        # Estimate total effort
        effort_scores = {"LOW": 1, "MEDIUM": 3, "HIGH": 5}
        total_effort_score = sum(
            effort_scores.get(rec.estimated_effort, 3) for rec in recommendations
        )
        
        if total_effort_score <= 5:
            total_effort = "LOW"
        elif total_effort_score <= 15:
            total_effort = "MEDIUM"
        else:
            total_effort = "HIGH"
        
        return RemediationPlan(
            plan_id=str(uuid.uuid4()),
            total_recommendations=len(recommendations),
            critical_count=priority_counts[Priority.CRITICAL],
            high_count=priority_counts[Priority.HIGH],
            medium_count=priority_counts[Priority.MEDIUM],
            low_count=priority_counts[Priority.LOW],
            estimated_total_effort=total_effort,
            priority_order=priority_order
        )
    
    def _create_heuristic_remediation_plan(self, vulnerabilities: List[Dict[str, Any]]) -> RemediationPlan:
        """Create basic remediation plan using heuristics."""
        return RemediationPlan(
            plan_id=str(uuid.uuid4()),
            total_recommendations=len(vulnerabilities),
            critical_count=len([v for v in vulnerabilities if v.get("severity") == "CRITICAL"]),
            high_count=len([v for v in vulnerabilities if v.get("severity") == "HIGH"]),
            medium_count=len([v for v in vulnerabilities if v.get("severity") == "MEDIUM"]),
            low_count=len([v for v in vulnerabilities if v.get("severity") == "LOW"]),
            estimated_total_effort="MEDIUM",
            priority_order=[f"vuln_{i}" for i in range(len(vulnerabilities))]
        )
    
    def _create_minimal_recommendations(self, sbom: SBOMDocument) -> SecurityRecommendations:
        """Create minimal recommendations when all else fails."""
        recommendations = [
            SecurityRecommendation(
                recommendation_id="minimal_update",
                priority=Priority.MEDIUM,
                title="Review and Update Dependencies",
                description="Regularly review and update project dependencies",
                affected_components=[],
                remediation_steps=["Review current dependencies", "Update to latest versions"],
                estimated_effort="MEDIUM",
                risk_reduction=5.0
            )
        ]
        
        remediation_plan = RemediationPlan(
            plan_id=str(uuid.uuid4()),
            total_recommendations=1,
            critical_count=0,
            high_count=0,
            medium_count=1,
            low_count=0,
            estimated_total_effort="MEDIUM",
            priority_order=["minimal_update"]
        )
        
        return SecurityRecommendations(
            recommendations=recommendations,
            remediation_plan=remediation_plan,
            alternative_suggestions=[],
            contextual_guidance=["Implement basic security practices"],
            generation_timestamp=datetime.utcnow(),
            model_used="fallback",
            metadata={"generation_method": "minimal"}
        )
    
    def _get_generic_security_guidance(self, project_type: str) -> List[str]:
        """Get generic security guidance based on project type."""
        base_guidance = [
            "Regularly update dependencies to latest secure versions",
            "Use automated vulnerability scanning in CI/CD pipeline",
            "Implement dependency pinning and lock files",
            "Monitor security advisories for used components",
            "Establish incident response procedures for security issues"
        ]
        
        type_specific = {
            "web": [
                "Implement Content Security Policy (CSP)",
                "Use HTTPS for all communications",
                "Validate and sanitize all user inputs"
            ],
            "mobile": [
                "Implement certificate pinning",
                "Use secure storage for sensitive data",
                "Implement runtime application self-protection"
            ],
            "library": [
                "Minimize dependency footprint",
                "Provide security documentation for users",
                "Implement secure defaults"
            ]
        }
        
        return base_guidance + type_specific.get(project_type.lower(), [])
    
    def get_advisor_statistics(self) -> Dict[str, Any]:
        """Get security advisor statistics."""
        return self._advisor_statistics.copy()
    
    def reset_statistics(self) -> None:
        """Reset advisor statistics."""
        self._advisor_statistics = {
            "recommendations_generated": 0,
            "remediation_plans_created": 0,
            "alternatives_suggested": 0,
            "api_calls": 0,
            "errors": []
        }