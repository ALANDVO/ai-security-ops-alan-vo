from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional
from pydantic import BaseModel
import time

from api.auth import get_current_user, User
from api.schemas import (
    ThreatEvent, ThreatCreate, Incident, IncidentCreate,
    QueryRequest, StatsResponse, ScoreResponse
)
from services.detection import detection_engine
from services.correlation import correlation_engine
from services.scoring import scoring_engine
from services.llm import llm_service
from models.schemas import ThreatRecord, IncidentRecord

router = APIRouter(prefix="/api", tags=["security-ops"])

@router.get("/health")
async def health():
    return {"status": "ok", "service": "ai-security-ops", "version": "1.0.0"}

@router.get("/threats", response_model=List[ThreatEvent])
async def get_threats(
    severity: Optional[str] = Query(None, description="Filter by severity: critical,high,medium,low"),
    source: Optional[str] = Query(None, description="Filter by source"),
    asset: Optional[str] = Query(None, description="Filter by asset name"),
    limit: int = Query(100, le=500),
    user: User = Depends(get_current_user),
):
    threats = detection_engine.get_threats(severity=severity, source=source, asset=asset, limit=limit)
    return threats

@router.post("/threats", response_model=ThreatEvent)
async def ingest_threat(event: ThreatCreate, user: User = Depends(get_current_user)):
    threat = detection_engine.ingest(event)
    correlation_engine.process(threat)
    scoring_engine.score(threat)
    return threat

@router.get("/incidents", response_model=List[Incident])
async def get_incidents(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    user: User = Depends(get_current_user),
):
    incidents = correlation_engine.get_incidents(status=status, severity=severity, limit=limit)
    return incidents

@router.post("/incidents", response_model=Incident)
async def create_incident(incident: IncidentCreate, user: User = Depends(get_current_user)):
    inc = correlation_engine.create_incident(incident)
    return inc

@router.get("/incidents/{incident_id}/timeline")
async def get_timeline(incident_id: str, user: User = Depends(get_current_user)):
    timeline = correlation_engine.get_timeline(incident_id)
    if not timeline:
        raise HTTPException(status_code=404, detail="Incident not found")
    return timeline

@router.post("/query")
async def nl_query(req: QueryRequest, user: User = Depends(get_current_user)):
    result = await llm_service.natural_language_query(req.query)
    return result

@router.get("/stats", response_model=StatsResponse)
async def get_stats(user: User = Depends(get_current_user)):
    return detection_engine.get_stats()

@router.get("/scores", response_model=List[ScoreResponse])
async def get_scores(asset: Optional[str] = None, user: User = Depends(get_current_user)):
    return scoring_engine.get_scores(asset=asset)
