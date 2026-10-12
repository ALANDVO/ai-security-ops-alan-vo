"""Asset risk scoring engine with SQLite persistence."""
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.database import get_db

logger = logging.getLogger(__name__)

_SEV_IMPACT = {"critical": 15, "high": 10, "medium": 5, "low": 2}


def _risk_level(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _row_to_score(row) -> Dict[str, Any]:
    d = dict(row)
    d["factors"] = json.loads(d.get("factors") or "[]")
    if isinstance(d.get("last_assessed"), str):
        d["last_assessed"] = datetime.fromisoformat(d["last_assessed"].replace("Z", "+00:00"))
    return d


def score_threat(threat: Dict[str, Any]) -> None:
    """Update or create an asset risk score based on an ingested threat."""
    asset = threat["asset"]
    sev = threat.get("severity", "medium")
    event_type = threat.get("event_type", "unknown")
    impact = _SEV_IMPACT.get(sev, 3) + int(threat.get("score", 0) / 10)
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as conn:
        existing = conn.execute(
            "SELECT score, factors FROM asset_scores WHERE asset = ?", (asset,)
        ).fetchone()
        if existing:
            new_score = min(100.0, existing["score"] + impact)
            factors = json.loads(existing["factors"] or "[]")
            if event_type not in factors:
                factors.append(event_type)
            conn.execute(
                "UPDATE asset_scores SET score = ?, risk_level = ?, factors = ?, last_assessed = ? WHERE asset = ?",
                (new_score, _risk_level(new_score), json.dumps(factors), now, asset),
            )
        else:
            init_score = min(100.0, 50.0 + impact)
            conn.execute(
                "INSERT INTO asset_scores (asset, score, risk_level, factors, last_assessed) VALUES (?,?,?,?,?)",
                (asset, init_score, _risk_level(init_score), json.dumps([event_type]), now),
            )


def get_scores(asset: Optional[str] = None) -> List[Dict[str, Any]]:
    clauses, params = [], []
    if asset:
        clauses.append("asset LIKE ?")
        params.append(f"%{asset}%")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_db() as conn:
        rows = conn.execute(
            f"SELECT * FROM asset_scores {where} ORDER BY score DESC", params
        ).fetchall()
    return [_row_to_score(r) for r in rows]
