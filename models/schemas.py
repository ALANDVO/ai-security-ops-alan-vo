from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime

@dataclass
class ThreatRecord:
    id: str
    source: str
    event_type: str
    asset: str
    severity: str
    confidence: float
    score: float
    llm_classification: Optional[str] = None
    llm_summary: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=datetime.utcnow)
    correlated_incident: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "source": self.source, "event_type": self.event_type,
            "asset": self.asset, "severity": self.severity, "confidence": self.confidence,
            "score": self.score, "llm_classification": self.llm_classification,
            "llm_summary": self.llm_summary, "raw_data": self.raw_data,
            "detected_at": self.detected_at.isoformat(), "correlated_incident": self.correlated_incident,
        }

@dataclass
class IncidentRecord:
    id: str
    title: str
    severity: str
    status: str
    description: str
    threat_count: int
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    llm_analysis: Optional[str] = None
    llm_recommendation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "title": self.title, "severity": self.severity,
            "status": self.status, "description": self.description,
            "threat_count": self.threat_count,
            "created_at": self.created_at.isoformat(), "updated_at": self.updated_at.isoformat(),
            "llm_analysis": self.llm_analysis, "llm_recommendation": self.llm_recommendation,
        }

@dataclass
class ScoreRecord:
    asset: str
    score: float
    risk_level: str
    factors: List[str] = field(default_factory=list)
    last_assessed: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset": self.asset, "score": self.score, "risk_level": self.risk_level,
            "factors": self.factors, "last_assessed": self.last_assessed.isoformat(),
        }
