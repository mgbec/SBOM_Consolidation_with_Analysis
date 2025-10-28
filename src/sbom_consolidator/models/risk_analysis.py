"""
Data models for AI-powered risk analysis and security recommendations.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum


class RiskLevel(Enum):
    """Risk level enumeration."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Priority(Enum):
    """Priority level enumeration."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ComponentRisk:
    """Risk assessment for a single component."""
    component_name: str
    risk_score: float  # 0.0 to 10.0
    risk_level: RiskLevel
    risk_factors: List[str]
    confidence_score: float  # 0.0 to 1.0
    vulnerability_count: int = 0
    last_updated: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "component_name": self.component_name,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "risk_factors": self.risk_factors,
            "confidence_score": self.confidence_score,
            "vulnerability_count": self.vulnerability_count,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ComponentRisk':
        """Create from dictionary."""
        last_updated = data.get("last_updated")
        if isinstance(last_updated, str):
            last_updated = datetime.fromisoformat(last_updated.replace('Z', '+00:00'))
        
        return cls(
            component_name=data["component_name"],
            risk_score=data["risk_score"],
            risk_level=RiskLevel(data["risk_level"]),
            risk_factors=data.get("risk_factors", []),
            confidence_score=data["confidence_score"],
            vulnerability_count=data.get("vulnerability_count", 0),
            last_updated=last_updated,
            metadata=data.get("metadata", {})
        )


@dataclass
class TransitiveRisk:
    """Risk from transitive dependencies."""
    source_component: str
    target_component: str
    risk_path: List[str]
    risk_score: float
    description: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "source_component": self.source_component,
            "target_component": self.target_component,
            "risk_path": self.risk_path,
            "risk_score": self.risk_score,
            "description": self.description
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TransitiveRisk':
        """Create from dictionary."""
        return cls(
            source_component=data["source_component"],
            target_component=data["target_component"],
            risk_path=data.get("risk_path", []),
            risk_score=data["risk_score"],
            description=data["description"]
        )


@dataclass
class RiskAnalysis:
    """Complete risk analysis for an SBOM."""
    overall_risk_score: float
    overall_risk_level: RiskLevel
    component_risks: Dict[str, ComponentRisk]
    transitive_risks: List[TransitiveRisk]
    risk_factors: List[str]
    analysis_timestamp: datetime
    model_used: str
    confidence_score: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "overall_risk_score": self.overall_risk_score,
            "overall_risk_level": self.overall_risk_level.value,
            "component_risks": {k: v.to_dict() for k, v in self.component_risks.items()},
            "transitive_risks": [tr.to_dict() for tr in self.transitive_risks],
            "risk_factors": self.risk_factors,
            "analysis_timestamp": self.analysis_timestamp.isoformat(),
            "model_used": self.model_used,
            "confidence_score": self.confidence_score,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RiskAnalysis':
        """Create from dictionary."""
        # Parse timestamp
        timestamp = data.get("analysis_timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        
        # Parse component risks
        component_risks = {}
        for k, v in data.get("component_risks", {}).items():
            component_risks[k] = ComponentRisk.from_dict(v)
        
        # Parse transitive risks
        transitive_risks = []
        for tr_data in data.get("transitive_risks", []):
            transitive_risks.append(TransitiveRisk.from_dict(tr_data))
        
        return cls(
            overall_risk_score=data["overall_risk_score"],
            overall_risk_level=RiskLevel(data["overall_risk_level"]),
            component_risks=component_risks,
            transitive_risks=transitive_risks,
            risk_factors=data.get("risk_factors", []),
            analysis_timestamp=timestamp,
            model_used=data["model_used"],
            confidence_score=data["confidence_score"],
            metadata=data.get("metadata", {})
        )


@dataclass
class AlternativeSuggestion:
    """Suggestion for alternative components."""
    original_component: str
    alternative_component: str
    reason: str
    risk_reduction: float
    compatibility_notes: str
    migration_effort: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "original_component": self.original_component,
            "alternative_component": self.alternative_component,
            "reason": self.reason,
            "risk_reduction": self.risk_reduction,
            "compatibility_notes": self.compatibility_notes,
            "migration_effort": self.migration_effort
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AlternativeSuggestion':
        """Create from dictionary."""
        return cls(
            original_component=data["original_component"],
            alternative_component=data["alternative_component"],
            reason=data["reason"],
            risk_reduction=data["risk_reduction"],
            compatibility_notes=data["compatibility_notes"],
            migration_effort=data["migration_effort"]
        )


@dataclass
class SecurityRecommendation:
    """Individual security recommendation."""
    recommendation_id: str
    priority: Priority
    title: str
    description: str
    affected_components: List[str]
    remediation_steps: List[str]
    estimated_effort: str
    risk_reduction: float
    references: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "recommendation_id": self.recommendation_id,
            "priority": self.priority.value,
            "title": self.title,
            "description": self.description,
            "affected_components": self.affected_components,
            "remediation_steps": self.remediation_steps,
            "estimated_effort": self.estimated_effort,
            "risk_reduction": self.risk_reduction,
            "references": self.references
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityRecommendation':
        """Create from dictionary."""
        return cls(
            recommendation_id=data["recommendation_id"],
            priority=Priority(data["priority"]),
            title=data["title"],
            description=data["description"],
            affected_components=data.get("affected_components", []),
            remediation_steps=data.get("remediation_steps", []),
            estimated_effort=data["estimated_effort"],
            risk_reduction=data["risk_reduction"],
            references=data.get("references", [])
        )


@dataclass
class RemediationPlan:
    """Structured remediation plan."""
    plan_id: str
    total_recommendations: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    estimated_total_effort: str
    priority_order: List[str]  # List of recommendation IDs in priority order
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "plan_id": self.plan_id,
            "total_recommendations": self.total_recommendations,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "estimated_total_effort": self.estimated_total_effort,
            "priority_order": self.priority_order
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RemediationPlan':
        """Create from dictionary."""
        return cls(
            plan_id=data["plan_id"],
            total_recommendations=data["total_recommendations"],
            critical_count=data["critical_count"],
            high_count=data["high_count"],
            medium_count=data["medium_count"],
            low_count=data["low_count"],
            estimated_total_effort=data["estimated_total_effort"],
            priority_order=data.get("priority_order", [])
        )


@dataclass
class SecurityRecommendations:
    """Complete security recommendations for an SBOM."""
    recommendations: List[SecurityRecommendation]
    remediation_plan: RemediationPlan
    alternative_suggestions: List[AlternativeSuggestion]
    contextual_guidance: List[str]
    generation_timestamp: datetime
    model_used: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "recommendations": [rec.to_dict() for rec in self.recommendations],
            "remediation_plan": self.remediation_plan.to_dict(),
            "alternative_suggestions": [alt.to_dict() for alt in self.alternative_suggestions],
            "contextual_guidance": self.contextual_guidance,
            "generation_timestamp": self.generation_timestamp.isoformat(),
            "model_used": self.model_used,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityRecommendations':
        """Create from dictionary."""
        # Parse timestamp
        timestamp = data.get("generation_timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        
        # Parse recommendations
        recommendations = []
        for rec_data in data.get("recommendations", []):
            recommendations.append(SecurityRecommendation.from_dict(rec_data))
        
        # Parse alternative suggestions
        alternatives = []
        for alt_data in data.get("alternative_suggestions", []):
            alternatives.append(AlternativeSuggestion.from_dict(alt_data))
        
        return cls(
            recommendations=recommendations,
            remediation_plan=RemediationPlan.from_dict(data["remediation_plan"]),
            alternative_suggestions=alternatives,
            contextual_guidance=data.get("contextual_guidance", []),
            generation_timestamp=timestamp,
            model_used=data["model_used"],
            metadata=data.get("metadata", {})
        )