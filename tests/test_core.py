import pytest
from services.detection import DetectionEngine
from services.correlation import CorrelationEngine
from services.scoring import ScoringEngine
from api.schemas import ThreatCreate, IncidentCreate

def test_detection_ingest():
    engine = DetectionEngine(max_events=100)
    event = ThreatCreate(source="siem", event_type="intrusion", asset="web-01", raw_data={"ip": "10.0.0.1"})
    threat = engine.ingest(event)
    assert threat["id"].startswith("threat-")
    assert threat["severity"] == "medium"
    assert threat["score"] > 0

def test_detection_filters():
    engine = DetectionEngine(max_events=100)
    e1 = ThreatCreate(source="siem", event_type="malware", asset="db-01", severity_hint="critical")
    e2 = ThreatCreate(source="waf", event_type="intrusion", asset="web-01", severity_hint="low")
    engine.ingest(e1)
    engine.ingest(e2)
    critical = engine.get_threats(severity="critical")
    assert len(critical) == 1
    assert critical[0]["asset"] == "db-01"

def test_correlation_groups():
    corr = CorrelationEngine()
    det = DetectionEngine(max_events=100)
    e1 = ThreatCreate(source="siem", event_type="intrusion", asset="web-01")
    e2 = ThreatCreate(source="waf", event_type="lateral_movement", asset="web-01")
    t1 = det.ingest(e1)
    t2 = det.ingest(e2)
    inc1 = corr.process(t1)
    inc2 = corr.process(t2)
    assert inc1 == inc2

def test_scoring():
    scorer = ScoringEngine()
    scorer.score({"severity": "critical", "event_type": "exfiltration", "score": 90, "asset": "prod-db"})
    scores = scorer.get_scores(asset="prod")
    assert len(scores) == 1
    assert scores[0]["risk_level"] == "critical"

def test_stats():
    engine = DetectionEngine(max_events=100)
    for i in range(5):
        engine.ingest(ThreatCreate(source="test", event_type=f"type{i}", asset=f"asset-{i}"))
    stats = engine.get_stats()
    assert stats["total_threats"] == 5
    assert "by_severity" in stats
