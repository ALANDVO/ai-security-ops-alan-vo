import uuid, logging
from typing import List, Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class CorrelationEngine:

    def __init__(self, correlation_window_seconds: int = 300):
        self.incidents: Dict[str, Dict[str, Any]] = {}
        self.correlation_window = correlation_window_seconds
        self.asset_index: Dict[str, List[str]] = {}

    def process(self, threat: Dict) -> Optional[str]:
        asset = threat["asset"]
        now = threat["detected_at"]
        candidates = []
        for incident in self.incidents.values():
            if incident["status"] != "open": continue
            incident_assets = [t.get("asset", "") for t in incident.get("threats", [])]
            if asset in incident_assets or threat["event_type"] in incident.get("types", []):
                candidates.append(incident)
        if candidates:
            best = max(candidates, key=lambda i: len(i.get("threats", [])))
            best["threats"].append(threat)
            best["threat_count"] = len(best["threats"])
            best["updated_at"] = now
            best["types"].add(threat["event_type"])
            threat["correlated_incident"] = best["id"]
            return best["id"]
        incident_id = f"inc-{uuid.uuid4().hex[:8]}"
        self.incidents[incident_id] = {
            "id": incident_id, "title": f"Incident: {threat['event_type']} on {asset}",
            "severity": threat["severity"], "status": "open", "description": "",
            "threats": [threat], "threat_count": 1, "types": {threat["event_type"]},
            "created_at": now, "updated_at": now,
            "llm_analysis": None, "llm_recommendation": None,
        }
        threat["correlated_incident"] = incident_id
        logger.info("Created incident %s for %s", incident_id, threat["id"])
        return incident_id

    def create_incident(self, incident_create) -> Dict:
        inc_id = f"inc-{uuid.uuid4().hex[:8]}"
        now = datetime.utcnow()
        inc = {
            "id": inc_id, "title": incident_create.title, "severity": incident_create.severity,
            "status": incident_create.status, "description": incident_create.description,
            "threats": [], "threat_count": len(incident_create.related_threat_ids),
            "types": set(), "created_at": now, "updated_at": now,
            "llm_analysis": None, "llm_recommendation": None,
        }
        self.incidents[inc_id] = inc
        return inc

    def get_incidents(self, status: Optional[str] = None, severity: Optional[str] = None,
                      limit: int = 50) -> List[Dict]:
        results = list(self.incidents.values())
        if status: results = [i for i in results if i["status"] == status]
        if severity: results = [i for i in results if i["severity"] == severity]
        results.sort(key=lambda i: i["created_at"], reverse=True)
        return results[:limit]

    def get_timeline(self, incident_id: str) -> Optional[List[Dict]]:
        incident = self.incidents.get(incident_id)
        if not incident: return None
        entries = []
        for t in sorted(incident["threats"], key=lambda x: x["detected_at"]):
            entries.append({
                "timestamp": t["detected_at"], "event_type": t["event_type"],
                "description": f"{t['event_type']} detected on {t['asset']}",
                "severity": t["severity"], "asset": t["asset"],
            })
        return entries

correlation_engine = CorrelationEngine()
