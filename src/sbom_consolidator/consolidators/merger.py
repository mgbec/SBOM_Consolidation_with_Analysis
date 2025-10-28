"""
Merger for combining SBOM components, relationships, and analysis results.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from collections import defaultdict

from ..models import (
    RiskAnalysis, SecurityRecommendations, ComponentRisk, TransitiveRisk,
    SecurityRecommendation, RemediationPlan, AlternativeSuggestion,
    RiskLevel, Priority
)

logger = logging.getLogger(__name__)


class Merger:
    """
    Merger for combining SBOM components, relationships, and analysis results.
    
    This class provides functionality to merge risk analyses, security
    recommendations, and other SBOM metadata while maintaining data integrity.
    """
    
    def __init__(self):
        """Initialize the merger."""
        self._merge_statistics = {
            "risk_analyses_merged": 0,
            "security_recommendations_merged": 0,
            "component_risks_merged": 0,
            "recommendations_merged": 0
        }
    
    def merge_risk_analyses(self, risk_analyses: List[RiskAnalysis]) -> RiskAnalysis:
        """
        Merge multiple risk analyses into a single comprehensive analysis.
        
        Args:
            risk_analyses: List of risk analyses to merge
            
        Returns:
            Merged risk analysis
        """
        if not risk_analyses:
            raise ValueError("Cannot merge empty risk analyses list")
        
        if len(risk_analyses) == 1:
            return risk_analyses[0]
        
        logger.info(f"Merging {len(risk_analyses)} risk analyses")
        
        # Merge component risks
        merged_component_risks = {}
        all_risk_factors = set()
        all_transitive_risks = []
        total_confidence = 0.0
        models_used = set()
        
        for analysis in risk_analyses:
            # Merge component risks
            for comp_name, comp_risk in analysis.component_risks.items():
                if comp_name in merged_component_risks:
                    # Merge existing component risk
                    merged_component_risks[comp_name] = self._merge_component_risks(
                        merged_component_risks[comp_name], comp_risk
                    )
                else:
                    merged_component_risks[comp_name] = comp_risk
            
            # Collect risk factors
            all_risk_factors.update(analysis.risk_factors)
            
            # Collect transitive risks
            all_transitive_risks.extend(analysis.transitive_risks)
            
            # Track confidence and models
            total_confidence += analysis.confidence_score
            models_used.add(analysis.model_used)
        
        # Calculate overall risk score and level
        if merged_component_risks:
            total_risk_score = sum(risk.risk_score for risk in merged_component_risks.values())
            overall_risk_score = total_risk_score / len(merged_component_risks)
        else:
            overall_risk_score = 5.0  # Default medium risk
        
        overall_risk_level = self._calculate_overall_risk_level(merged_component_risks)
        
        # Deduplicate transitive risks
        unique_transitive_risks = self._deduplicate_transitive_risks(all_transitive_risks)
        
        # Create merged analysis
        merged_analysis = RiskAnalysis(
            overall_risk_score=overall_risk_score,
            overall_risk_level=overall_risk_level,
            component_risks=merged_component_risks,
            transitive_risks=unique_transitive_risks,
            risk_factors=list(all_risk_factors),
            analysis_timestamp=datetime.utcnow(),
            model_used=", ".join(models_used),
            confidence_score=total_confidence / len(risk_analyses),
            metadata={
                "merged_from": len(risk_analyses),
                "merge_timestamp": datetime.utcnow().isoformat(),
                "source_analyses": [analysis.analysis_timestamp.isoformat() for analysis in risk_analyses]
            }
        )
        
        self._merge_statistics["risk_analyses_merged"] += 1
        self._merge_statistics["component_risks_merged"] += len(merged_component_risks)
        
        logger.info(f"Merged risk analysis: {overall_risk_level.value} risk level "
                   f"({overall_risk_score:.1f}/10) with {len(merged_component_risks)} components")
        
        return merged_analysis
    
    def merge_security_recommendations(
        self, 
        recommendations_list: List[SecurityRecommendations]
    ) -> SecurityRecommendations:
        """
        Merge multiple security recommendations into a single set.
        
        Args:
            recommendations_list: List of security recommendations to merge
            
        Returns:
            Merged security recommendations
        """
        if not recommendations_list:
            raise ValueError("Cannot merge empty security recommendations list")
        
        if len(recommendations_list) == 1:
            return recommendations_list[0]
        
        logger.info(f"Merging {len(recommendations_list)} security recommendation sets")
        
        # Merge recommendations
        all_recommendations = []
        all_alternatives = []
        all_guidance = set()
        models_used = set()
        
        for rec_set in recommendations_list:
            all_recommendations.extend(rec_set.recommendations)
            all_alternatives.extend(rec_set.alternative_suggestions)
            all_guidance.update(rec_set.contextual_guidance)
            models_used.add(rec_set.model_used)
        
        # Deduplicate and prioritize recommendations
        unique_recommendations = self._deduplicate_recommendations(all_recommendations)
        
        # Deduplicate alternatives
        unique_alternatives = self._deduplicate_alternatives(all_alternatives)
        
        # Create merged remediation plan
        merged_remediation_plan = self._create_merged_remediation_plan(unique_recommendations)
        
        # Create merged recommendations
        merged_recommendations = SecurityRecommendations(
            recommendations=unique_recommendations,
            remediation_plan=merged_remediation_plan,
            alternative_suggestions=unique_alternatives,
            contextual_guidance=list(all_guidance),
            generation_timestamp=datetime.utcnow(),
            model_used=", ".join(models_used),
            metadata={
                "merged_from": len(recommendations_list),
                "merge_timestamp": datetime.utcnow().isoformat(),
                "original_recommendation_count": len(all_recommendations),
                "deduplicated_recommendation_count": len(unique_recommendations)
            }
        )
        
        self._merge_statistics["security_recommendations_merged"] += 1
        self._merge_statistics["recommendations_merged"] += len(unique_recommendations)
        
        logger.info(f"Merged security recommendations: {len(unique_recommendations)} unique recommendations "
                   f"(from {len(all_recommendations)} total)")
        
        return merged_recommendations
    
    def _merge_component_risks(self, risk1: ComponentRisk, risk2: ComponentRisk) -> ComponentRisk:
        """
        Merge two component risks for the same component.
        
        Args:
            risk1: First component risk
            risk2: Second component risk
            
        Returns:
            Merged component risk
        """
        # Use higher risk score
        merged_risk_score = max(risk1.risk_score, risk2.risk_score)
        
        # Use higher risk level
        risk_levels = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        merged_risk_level = max(risk1.risk_level, risk2.risk_level, key=lambda x: risk_levels.index(x))
        
        # Merge risk factors
        merged_risk_factors = list(set(risk1.risk_factors + risk2.risk_factors))
        
        # Average confidence scores
        merged_confidence = (risk1.confidence_score + risk2.confidence_score) / 2
        
        # Use higher vulnerability count
        merged_vuln_count = max(risk1.vulnerability_count, risk2.vulnerability_count)
        
        # Use more recent timestamp
        merged_timestamp = max(risk1.last_updated or datetime.min, risk2.last_updated or datetime.min)
        
        # Merge metadata
        merged_metadata = {}
        if risk1.metadata:
            merged_metadata.update(risk1.metadata)
        if risk2.metadata:
            merged_metadata.update(risk2.metadata)
        merged_metadata["merged_from_risks"] = 2
        
        return ComponentRisk(
            component_name=risk1.component_name,
            risk_score=merged_risk_score,
            risk_level=merged_risk_level,
            risk_factors=merged_risk_factors,
            confidence_score=merged_confidence,
            vulnerability_count=merged_vuln_count,
            last_updated=merged_timestamp,
            metadata=merged_metadata
        )
    
    def _calculate_overall_risk_level(self, component_risks: Dict[str, ComponentRisk]) -> RiskLevel:
        """Calculate overall risk level from component risks."""
        if not component_risks:
            return RiskLevel.MEDIUM
        
        risk_counts = defaultdict(int)
        for risk in component_risks.values():
            risk_counts[risk.risk_level] += 1
        
        total_components = len(component_risks)
        critical_ratio = risk_counts[RiskLevel.CRITICAL] / total_components
        high_ratio = risk_counts[RiskLevel.HIGH] / total_components
        
        if critical_ratio >= 0.1:  # 10% or more critical
            return RiskLevel.CRITICAL
        elif high_ratio >= 0.2 or critical_ratio > 0:  # 20% or more high, or any critical
            return RiskLevel.HIGH
        elif risk_counts[RiskLevel.MEDIUM] > risk_counts[RiskLevel.LOW]:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _deduplicate_transitive_risks(self, transitive_risks: List[TransitiveRisk]) -> List[TransitiveRisk]:
        """Deduplicate transitive risks."""
        seen_risks = set()
        unique_risks = []
        
        for risk in transitive_risks:
            # Create unique key
            key = (risk.source_component, risk.target_component, risk.description)
            
            if key not in seen_risks:
                seen_risks.add(key)
                unique_risks.append(risk)
        
        return unique_risks
    
    def _deduplicate_recommendations(self, recommendations: List[SecurityRecommendation]) -> List[SecurityRecommendation]:
        """Deduplicate security recommendations."""
        seen_recommendations = {}
        
        for rec in recommendations:
            # Create key based on title and affected components
            affected_key = tuple(sorted(rec.affected_components))
            key = (rec.title.lower().strip(), affected_key)
            
            if key not in seen_recommendations:
                seen_recommendations[key] = rec
            else:
                # Merge with existing recommendation
                existing = seen_recommendations[key]
                
                # Use higher priority
                priorities = [Priority.LOW, Priority.MEDIUM, Priority.HIGH, Priority.CRITICAL]
                if priorities.index(rec.priority) > priorities.index(existing.priority):
                    existing.priority = rec.priority
                
                # Merge remediation steps
                for step in rec.remediation_steps:
                    if step not in existing.remediation_steps:
                        existing.remediation_steps.append(step)
                
                # Merge affected components
                for comp in rec.affected_components:
                    if comp not in existing.affected_components:
                        existing.affected_components.append(comp)
                
                # Use higher risk reduction
                existing.risk_reduction = max(existing.risk_reduction, rec.risk_reduction)
                
                # Merge references
                for ref in rec.references:
                    if ref not in existing.references:
                        existing.references.append(ref)
        
        return list(seen_recommendations.values())
    
    def _deduplicate_alternatives(self, alternatives: List[AlternativeSuggestion]) -> List[AlternativeSuggestion]:
        """Deduplicate alternative suggestions."""
        seen_alternatives = {}
        
        for alt in alternatives:
            key = (alt.original_component, alt.alternative_component)
            
            if key not in seen_alternatives:
                seen_alternatives[key] = alt
            else:
                # Merge with existing alternative
                existing = seen_alternatives[key]
                
                # Use higher risk reduction
                existing.risk_reduction = max(existing.risk_reduction, alt.risk_reduction)
                
                # Combine reasons if different
                if alt.reason != existing.reason:
                    existing.reason += f"; {alt.reason}"
                
                # Combine compatibility notes
                if alt.compatibility_notes != existing.compatibility_notes:
                    existing.compatibility_notes += f"; {alt.compatibility_notes}"
        
        return list(seen_alternatives.values())
    
    def _create_merged_remediation_plan(self, recommendations: List[SecurityRecommendation]) -> RemediationPlan:
        """Create remediation plan from merged recommendations."""
        # Count by priority
        priority_counts = defaultdict(int)
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
        
        if total_effort_score <= 10:
            total_effort = "LOW"
        elif total_effort_score <= 30:
            total_effort = "MEDIUM"
        else:
            total_effort = "HIGH"
        
        return RemediationPlan(
            plan_id=f"merged_plan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            total_recommendations=len(recommendations),
            critical_count=priority_counts[Priority.CRITICAL],
            high_count=priority_counts[Priority.HIGH],
            medium_count=priority_counts[Priority.MEDIUM],
            low_count=priority_counts[Priority.LOW],
            estimated_total_effort=total_effort,
            priority_order=priority_order
        )
    
    def get_merge_statistics(self) -> Dict[str, Any]:
        """Get merge statistics."""
        return self._merge_statistics.copy()
    
    def reset_statistics(self) -> None:
        """Reset merge statistics."""
        self._merge_statistics = {
            "risk_analyses_merged": 0,
            "security_recommendations_merged": 0,
            "component_risks_merged": 0,
            "recommendations_merged": 0
        }