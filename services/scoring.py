import logging
from typing import List, Dict, Optional
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)

class ScoringEngine:

    def __init__(self):
        self.asset_scores: Dict[str, Dict] = {}

    def score(self, threat: Dict) -> None:
        asset = threat["asset"]
        current = self.asset_scores.get(asset, {"score": 50, "risk_level": "medium", "factors": [], "last_assessed": datetime.utcnow()})
        current["score"] = min(100, current["score"] + self._threat_impact(threat))
        current["risk_level"] = self._risk_level(current["score"])
        if threat["event_type"] not in current["factors"]:
            current["factors"].append(threat["event_type"])
        current["last_assessed"] = datetime.utcnow()
        self.asset_scores[asset] = current

    def _threat_impact(self, threat: Dict) -> int:
        base = {"critical": 15, "high": 10, "medium": 5, "low": 2}.get(threat["severity"], 3)
        return base + int(threat.get("score", 0) / 10)

    def _risk_level(self, score: float) -> str:
        if score >= 80: return "critical"
        if score >= 60: return "high"
        if score >= 40: return "medium"
        return "low"

    def get_scores(self, asset: Optional[str] = None) -> List[Dict]:
        results = list(self.asset_scores.values())
        if asset: results = [s for s in results if asset.lower() in s.get("asset", "").lower()]
        results.sort(key=lambda s: -s["score"])
        return results

scoring_engine = ScoringEngine()
