"""Pydantic schemas for request/response validation."""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class ThreatCreate(BaseModel):
    source: str = Field(..., description="Source of the threat event (e.g. siem, waf, edr)")
    event_type: str = Field(..., description="Type: intrusion, malware, phishing, lateral_movement, exfiltration, etc.")
    asset: str = Field(..., description="Target asset or host name")
    raw_data: Dict[str, Any] = Field(default_factory=dict, description="Raw event data payload")
    severity_hint: Optional[str] = Field(None, description="Suggested severity: critical, high, medium, low")
    timestamp: Optional[datetime] = None


class ThreatEvent(BaseModel):
    id: str
    source: str
    event_type: str
    asset: str
    severity: str
    confidence: float
    score: float
    llm_classification: Optional[str] = None
    llm_summary: Optional[str] = None
    raw_data: Dict[str, Any]
    detected_at: datetime
    correlated_incident: Optional[str] = None

    class Config:
        from_attributes = True


class IncidentCreate(BaseModel):
    title: str
    severity: str = "medium"
    description: str = ""
    related_threat_ids: List[str] = Field(default_factory=list)
    status: str = "open"


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    description: Optional[str] = None


class Incident(BaseModel):
    id: str
    title: str
    severity: str
    status: str
    description: str
    threat_count: int
    created_at: datetime
    updated_at: datetime
    llm_analysis: Optional[str] = None
    llm_recommendation: Optional[str] = None

    class Config:
        from_attributes = True


class TimelineEntry(BaseModel):
    timestamp: datetime
    event_type: str
    description: str
    severity: str
    asset: str


class QueryRequest(BaseModel):
    query: str = Field(..., description="Natural language security query")
    context: Optional[str] = None


class StatsResponse(BaseModel):
    total_threats: int
    by_severity: Dict[str, int]
    by_type: Dict[str, int]
    active_incidents: int
    avg_response_time_ms: float
    top_assets: List[str]
    threat_trend_24h: List[Dict[str, Any]]


class ScoreResponse(BaseModel):
    asset: str
    score: float
    risk_level: str
    factors: List[str]
    last_assessed: datetime
