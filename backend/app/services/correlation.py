"""Incident correlation engine with SQLite persistence."""
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.database import get_db
from app.services.detection import update_threat_correlation

logger = logging.getLogger(__name__)


def _row_to_incident(row) -> Dict[str, Any]:
    d = dict(row)
    for ts_field in ("created_at", "updated_at"):
        if isinstance(d.get(ts_field), str):
            d[ts_field] = datetime.fromisoformat(d[ts_field].replace("Z", "+00:00"))
    return d


def correlate_threat(threat: Dict[str, Any]) -> str:
    """Find or create an incident for this threat. Returns incident_id."""
    asset = threat["asset"]
    event_type = threat["event_type"]

    with get_db() as conn:
        # Look for an open incident matching same asset or event type
        row = conn.execute(
            """SELECT id FROM incidents
               WHERE status IN ('open','investigating')
               AND (title LIKE ? OR types LIKE ?)
               ORDER BY created_at DESC LIMIT 1""",
            (f"%{asset}%", f"%{event_type}%"),
        ).fetchone()

        now = datetime.now(timezone.utc).isoformat()
        if row:
            inc_id = row["id"]
            existing = conn.execute("SELECT threat_count, types FROM incidents WHERE id = ?", (inc_id,)).fetchone()
            old_types = json.loads(existing["types"] or "[]")
            if event_type not in old_types:
                old_types.append(event_type)
            conn.execute(
                "UPDATE incidents SET threat_count = threat_count + 1, types = ?, updated_at = ? WHERE id = ?",
                (json.dumps(old_types), now, inc_id),
            )
        else:
            inc_id = f"inc-{uuid.uuid4().hex[:8]}"
            conn.execute(
                """INSERT INTO incidents
                   (id, title, severity, status, description, threat_count, types, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (inc_id, f"Incident: {event_type} on {asset}",
                 threat["severity"], "open", "", 1, json.dumps([event_type]), now, now),
            )
            logger.info("Created incident %s for threat %s", inc_id, threat["id"])

        # Link threat to incident
        conn.execute("UPDATE threats SET correlated_incident = ? WHERE id = ?", (inc_id, threat["id"]))

    return inc_id


def create_incident(title: str, severity: str, description: str,
                    status: str, related_threat_ids: List[str],
                    actor: str = "system") -> Dict[str, Any]:
    inc_id = f"inc-{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as conn:
        conn.execute(
            """INSERT INTO incidents
               (id, title, severity, status, description, threat_count, types, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (inc_id, title, severity, status, description, len(related_threat_ids), "[]", now, now),
        )
        # Link any specified threats
        for tid in related_threat_ids:
            conn.execute("UPDATE threats SET correlated_incident = ? WHERE id = ?", (inc_id, tid))
        conn.execute(
            "INSERT INTO audit_log (actor, action, resource_type, resource_id, detail) VALUES (?,?,?,?,?)",
            (actor, "create", "incident", inc_id, f"severity={severity}"),
        )

    return {
        "id": inc_id, "title": title, "severity": severity, "status": status,
        "description": description, "threat_count": len(related_threat_ids),
        "created_at": datetime.fromisoformat(now), "updated_at": datetime.fromisoformat(now),
        "llm_analysis": None, "llm_recommendation": None,
    }


def update_incident(incident_id: str, updates: Dict[str, Any], actor: str = "system") -> Dict[str, Any]:
    fields, params = [], []
    for key in ("title", "severity", "status", "description"):
        if updates.get(key) is not None:
            fields.append(f"{key} = ?")
            params.append(updates[key])
    if not fields:
        raise ValueError("No valid update fields")

    now = datetime.now(timezone.utc).isoformat()
    fields.append("updated_at = ?")
    params.append(now)
    params.append(incident_id)

    with get_db() as conn:
        conn.execute(f"UPDATE incidents SET {', '.join(fields)} WHERE id = ?", params)
        conn.execute(
            "INSERT INTO audit_log (actor, action, resource_type, resource_id, detail) VALUES (?,?,?,?,?)",
            (actor, "update", "incident", incident_id, str(updates)),
        )
        row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()

    if not row:
        raise KeyError(f"Incident {incident_id} not found")
    return _row_to_incident(row)


def get_incidents(status: Optional[str] = None, severity: Optional[str] = None,
                  limit: int = 50) -> List[Dict[str, Any]]:
    clauses, params = [], []
    if status:
        clauses.append("status = ?")
        params.append(status)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)

    with get_db() as conn:
        rows = conn.execute(
            f"SELECT * FROM incidents {where} ORDER BY updated_at DESC LIMIT ?", params
        ).fetchall()
    return [_row_to_incident(r) for r in rows]


def get_timeline(incident_id: str) -> Optional[List[Dict[str, Any]]]:
    with get_db() as conn:
        inc = conn.execute("SELECT id FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not inc:
            return None
        rows = conn.execute(
            """SELECT detected_at, event_type, asset, severity, source
               FROM threats WHERE correlated_incident = ?
               ORDER BY detected_at ASC""",
            (incident_id,),
        ).fetchall()

    timeline = []
    for r in rows:
        ts = datetime.fromisoformat(r["detected_at"].replace("Z", "+00:00")) if isinstance(r["detected_at"], str) else r["detected_at"]
        timeline.append({
            "timestamp": ts,
            "event_type": r["event_type"],
            "description": f"{r['event_type']} detected from {r['source']}",
            "severity": r["severity"],
            "asset": r["asset"],
        })
    return timeline


def update_incident_llm(incident_id: str, analysis: str, recommendation: str) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE incidents SET llm_analysis = ?, llm_recommendation = ? WHERE id = ?",
            (analysis, recommendation, incident_id),
        )
