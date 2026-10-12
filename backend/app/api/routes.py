"""FastAPI API routes for security operations."""
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response

from app.api.auth import (
    User, create_demo_session, get_current_user, handle_oidc_callback,
    require_role, start_oidc_login, delete_session,
)
from app.api.schemas import (
    Incident, IncidentCreate, IncidentUpdate, QueryRequest, ScoreResponse,
    StatsResponse, ThreatCreate, ThreatEvent,
)
from app.services import correlation, detection, llm, scoring

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["security-ops"])


# ── Health ────────────────────────────────────────────────────────────────────

@router.get("/health")
async def health():
    return {"status": "ok", "service": "ai-security-ops"}


# ── Auth ──────────────────────────────────────────────────────────────────────

@router.get("/auth/login")
async def login(response: Response):
    """Start OIDC authorization-code + PKCE flow."""
    redirect_url = await start_oidc_login(response)
    return {"redirect_url": redirect_url}


@router.get("/auth/callback")
async def oidc_callback(code: str, state: str, response: Response):
    """Handle OIDC callback, exchange code for tokens, set session cookie."""
    user = await handle_oidc_callback(code, state, response)
    return {"email": user.email, "name": user.name, "role": user.role}


@router.post("/auth/demo-login")
async def demo_login(response: Response):
    """Create a demo session for local development only."""
    user = create_demo_session(response)
    return {"email": user.email, "name": user.name, "role": user.role}


@router.get("/auth/me")
async def me(user: User = Depends(get_current_user)):
    return {"email": user.email, "name": user.name, "role": user.role}


@router.post("/auth/logout")
async def logout(response: Response, request: Request):
    sid = request.cookies.get("sid")
    if sid:
        delete_session(sid)
    response.delete_cookie("sid")
    response.delete_cookie("csrf_token")
    return {"message": "Logged out"}


# ── Threats ───────────────────────────────────────────────────────────────────

@router.get("/threats", response_model=List[ThreatEvent])
async def get_threats(
    severity: Optional[str] = Query(None, description="Filter: critical,high,medium,low"),
    source: Optional[str] = Query(None),
    asset: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    user: User = Depends(get_current_user),
):
    return detection.get_threats(severity=severity, source=source, asset=asset, limit=limit)


@router.post("/threats", response_model=ThreatEvent)
async def ingest_threat(
    event: ThreatCreate,
    user: User = Depends(require_role("analyst", "admin")),
    x_csrf_token: Optional[str] = Header(None),
):
    threat = detection.ingest_threat(
        source=event.source, event_type=event.event_type, asset=event.asset,
        raw_data=event.raw_data, severity_hint=event.severity_hint, actor=user.email,
    )
    # Correlate
    inc_id = correlation.correlate_threat(threat)
    threat["correlated_incident"] = inc_id
    # Score
    scoring.score_threat(threat)
    return threat


# ── Incidents ─────────────────────────────────────────────────────────────────

@router.get("/incidents", response_model=List[Incident])
async def get_incidents(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    user: User = Depends(get_current_user),
):
    return correlation.get_incidents(status=status, severity=severity, limit=limit)


@router.post("/incidents", response_model=Incident)
async def create_incident(
    payload: IncidentCreate,
    user: User = Depends(require_role("analyst", "admin")),
):
    return correlation.create_incident(
        title=payload.title, severity=payload.severity, description=payload.description,
        status=payload.status, related_threat_ids=payload.related_threat_ids, actor=user.email,
    )


@router.patch("/incidents/{incident_id}", response_model=Incident)
async def update_incident(
    incident_id: str,
    payload: IncidentUpdate,
    user: User = Depends(require_role("analyst", "admin")),
):
    try:
        return correlation.update_incident(incident_id, payload.model_dump(exclude_none=True), actor=user.email)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/incidents/{incident_id}/timeline")
async def get_timeline(incident_id: str, user: User = Depends(get_current_user)):
    timeline = correlation.get_timeline(incident_id)
    if timeline is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return timeline


# ── NL Query ──────────────────────────────────────────────────────────────────

@router.post("/query")
async def nl_query(req: QueryRequest, user: User = Depends(get_current_user)):
    """Natural language query → structured filters. LLM is opt-in and advisory."""
    result = await llm.natural_language_query(req.query)
    return result


# ── Stats ─────────────────────────────────────────────────────────────────────

@router.get("/stats", response_model=StatsResponse)
async def get_stats(user: User = Depends(get_current_user)):
    return detection.get_stats()


# ── Asset Scores ──────────────────────────────────────────────────────────────

@router.get("/scores", response_model=List[ScoreResponse])
async def get_scores(asset: Optional[str] = None, user: User = Depends(get_current_user)):
    return scoring.get_scores(asset=asset)
