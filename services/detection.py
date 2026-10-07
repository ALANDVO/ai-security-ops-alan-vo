import uuid, logging, time
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)

class DetectionEngine:

    def __init__(self, max_events: int = 10000):
        self.events: Dict[str, Dict[str, Any]] = {}
        self.max_events = max_events
        self.severity_counts = defaultdict(int)
        self.type_counts = defaultdict(int)
        self.asset_counts = defaultdict(int)
        self.timestamps: List[float] = []

    def ingest(self, event) -> Dict[str, Any]:
        eid = f"threat-{uuid.uuid4().hex[:8]}"
        now = datetime.utcnow()
        sev = event.severity_hint or "medium"
        self.events[eid] = {
            "id": eid, "source": event.source, "event_type": event.event_type,
            "asset": event.asset, "severity": sev, "confidence": 0.75,
            "score": self._compute_score(sev, event.event_type),
            "llm_classification": None, "llm_summary": None,
            "raw_data": event.raw_data, "detected_at": now,
            "correlated_incident": None,
        }
        self.severity_counts[sev] += 1
        self.type_counts[event.event_type] += 1
        self.asset_counts[event.asset] += 1
        self.timestamps.append(time.time())
        if len(self.events) > self.max_events:
            oldest = sorted(self.events.values(), key=lambda e: e["detected_at"])[0]
            del self.events[oldest["id"]]
        logger.info("Ingested threat %s: %s on %s (%s)", eid, event.event_type, event.asset, sev)
        return self.events[eid]

    def _compute_score(self, severity: str, event_type: str) -> float:
        base = {"critical": 90, "high": 70, "medium": 45, "low": 20}.get(severity, 40)
        type_boost = {"intrusion": 10, "malware": 8, "exfiltration": 12, "lateral_movement": 7}.get(event_type, 0)
        return min(100, base + type_boost)

    def get_threats(self, severity: Optional[str] = None, source: Optional[str] = None,
                    asset: Optional[str] = None, limit: int = 100) -> List[Dict]:
        results = list(self.events.values())
        if severity: results = [t for t in results if t["severity"] == severity]
        if source: results = [t for t in results if t["source"] == source]
        if asset: results = [t for t in results if asset.lower() in t["asset"].lower()]
        results.sort(key=lambda t: t["detected_at"], reverse=True)
        return results[:limit]

    def get_stats(self) -> Dict:
        cutoff = time.time() - 86400
        last_24h = sum(1 for t in self.timestamps if t >= cutoff)
        top_assets = sorted(self.asset_counts.items(), key=lambda x: -x[1])[:5]
        return {
            "total_threats": len(self.events),
            "by_severity": dict(self.severity_counts),
            "by_type": dict(self.type_counts),
            "active_incidents": 0,
            "avg_response_time_ms": 42.5,
            "top_assets": [a for a, _ in top_assets],
            "threat_trend_24h": self._trend(),
        }

    def _trend(self) -> List[Dict]:
        hours = []
        now = time.time()
        for i in range(24, 0, -1):
            bucket_start = now - i * 3600
            count = sum(1 for t in self.timestamps if bucket_start <= t < bucket_start + 3600)
            hours.append({"hour": i, "count": count})
        return hours

detection_engine = DetectionEngine()
