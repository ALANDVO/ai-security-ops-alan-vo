"""Threat detection engine with SQLite persistence."""
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.database import get_db

logger = logging.getLogger(__name__)

# Severity weights for score computation
_SEV_BASE = {"critical": 90, "high": 70, "medium": 45, "low": 20}
_TYPE_BOOST = {"intrusion": 10, "malware": 8, "exfiltration": 12, "lateral_movement": 7, "phishing": 5}

VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_STATUSES = {"open", "investigating", "resolved", "closed"}


def _compute_score(severity: str, event_type: str) -> float:
    base = _SEV_BASE.get(severity, 40)
    boost = _TYPE_BOOST.get(event_type, 0)
    return float(min(100, base + boost))


def _row_to_threat(row) -> Dict[str, Any]:
    d = dict(row)
    d["raw_data"] = json.loads(d.get("raw_data") or "{}")
    if isinstance(d.get("detected_at"), str):
        d["detected_at"] = datetime.fromisoformat(d["detected_at"].replace("Z", "+00:00"))
    return d


def ingest_threat(source: str, event_type: str, asset: str,
                  raw_data: Dict[str, Any], severity_hint: Optional[str],
                  actor: str = "system") -> Dict[str, Any]:
    sev = severity_hint if severity_hint in VALID_SEVERITIES else "medium"
    eid = f"threat-{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()
    score = _compute_score(sev, event_type)

    with get_db() as conn:
        conn.execute(
            """INSERT INTO threats
               (id, source, event_type, asset, severity, confidence, score,
                raw_data, detected_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (eid, source, event_type, asset, sev, 0.75, score,
             json.dumps(raw_data), now),
        )
        conn.execute(
            """INSERT INTO audit_log (actor, action, resource_type, resource_id, detail)
               VALUES (?,?,?,?,?)""",
            (actor, "ingest", "threat", eid, f"severity={sev} asset={asset}"),
        )

    threat = {
        "id": eid, "source": source, "event_type": event_type, "asset": asset,
        "severity": sev, "confidence": 0.75, "score": score,
        "llm_classification": None, "llm_summary": None,
        "raw_data": raw_data, "detected_at": datetime.fromisoformat(now),
        "correlated_incident": None,
    }
    logger.info("Ingested threat %s: %s on %s (%s)", eid, event_type, asset, sev)
    return threat


def get_threats(severity: Optional[str] = None, source: Optional[str] = None,
                asset: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    clauses, params = [], []
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if source:
        clauses.append("source = ?")
        params.append(source)
    if asset:
        clauses.append("asset LIKE ?")
        params.append(f"%{asset}%")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    with get_db() as conn:
        rows = conn.execute(
            f"SELECT * FROM threats {where} ORDER BY detected_at DESC LIMIT ?", params
        ).fetchall()
    return [_row_to_threat(r) for r in rows]


def update_threat_correlation(threat_id: str, incident_id: str) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE threats SET correlated_incident = ? WHERE id = ?",
            (incident_id, threat_id),
        )


def update_threat_llm(threat_id: str, classification: str, summary: str) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE threats SET llm_classification = ?, llm_summary = ? WHERE id = ?",
            (classification, summary, threat_id),
        )


def get_stats() -> Dict[str, Any]:
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
        by_sev_rows = conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM threats GROUP BY severity"
        ).fetchall()
        by_type_rows = conn.execute(
            "SELECT event_type, COUNT(*) as cnt FROM threats GROUP BY event_type"
        ).fetchall()
        active_inc = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE status IN ('open','investigating')"
        ).fetchone()[0]
        top_assets_rows = conn.execute(
            "SELECT asset, COUNT(*) as cnt FROM threats GROUP BY asset ORDER BY cnt DESC LIMIT 5"
        ).fetchall()
        trend_rows = conn.execute(
            """SELECT strftime('%H', detected_at) as hr, COUNT(*) as cnt
               FROM threats
               WHERE detected_at >= datetime('now', '-24 hours')
               GROUP BY hr ORDER BY hr"""
        ).fetchall()

    by_severity = {r["severity"]: r["cnt"] for r in by_sev_rows}
    by_type = {r["event_type"]: r["cnt"] for r in by_type_rows}
    top_assets = [r["asset"] for r in top_assets_rows]
    trend = [{"hour": int(r["hr"]), "count": r["cnt"]} for r in trend_rows]

    return {
        "total_threats": total,
        "by_severity": by_severity,
        "by_type": by_type,
        "active_incidents": active_inc,
        "avg_response_time_ms": 42.0,
        "top_assets": top_assets,
        "threat_trend_24h": trend,
    }
