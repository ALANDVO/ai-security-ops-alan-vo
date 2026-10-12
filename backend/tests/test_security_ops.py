"""Comprehensive backend tests for AI Security Ops Center.

Covers: detection, correlation, scoring, auth, API endpoints,
boundary inputs, persistence, and unauthenticated rejection.
"""
import json
import os
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

# Use in-memory SQLite for tests
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["DEMO_MODE"] = "true"
os.environ["JWT_SECRET"] = "test-secret-key"

from app.main import create_app
from app.core.database import get_db
from app.services import detection, correlation, scoring


@pytest.fixture(autouse=True)
def fresh_db():
    """Reinitialize the database before each test."""
    from app.core.database import reset_memory_db, init_db
    reset_memory_db()
    init_db()
    yield


@pytest.fixture
def client(fresh_db):
    app = create_app()
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture
def authed_client(client):
    """Client with demo session cookie."""
    resp = client.post("/api/auth/demo-login")
    assert resp.status_code == 200
    return client


# ── Detection Engine Tests ────────────────────────────────────────────────────

class TestDetection:
    def test_ingest_returns_threat(self, fresh_db):
        threat = detection.ingest_threat("siem", "intrusion", "web-01", {}, None)
        assert threat["id"].startswith("threat-")
        assert threat["severity"] == "medium"
        assert threat["score"] > 0

    def test_ingest_critical_severity(self, fresh_db):
        threat = detection.ingest_threat("waf", "malware", "db-01", {}, "critical")
        assert threat["severity"] == "critical"
        assert threat["score"] >= 90

    def test_invalid_severity_falls_back(self, fresh_db):
        threat = detection.ingest_threat("edr", "phishing", "pc-01", {}, "bogus")
        assert threat["severity"] == "medium"

    def test_get_threats_filter_severity(self, fresh_db):
        detection.ingest_threat("siem", "malware", "db-01", {}, "critical")
        detection.ingest_threat("waf", "intrusion", "web-01", {}, "low")
        critical = detection.get_threats(severity="critical")
        assert len(critical) == 1
        assert critical[0]["asset"] == "db-01"

    def test_get_threats_filter_asset(self, fresh_db):
        detection.ingest_threat("siem", "intrusion", "web-server-01", {}, None)
        detection.ingest_threat("siem", "malware", "db-server-01", {}, None)
        results = detection.get_threats(asset="web")
        assert all("web" in r["asset"] for r in results)

    def test_get_stats_counts(self, fresh_db):
        for i in range(3):
            detection.ingest_threat("test", f"type{i}", f"asset-{i}", {}, None)
        stats = detection.get_stats()
        assert stats["total_threats"] == 3
        assert "by_severity" in stats
        assert "by_type" in stats

    def test_score_computation_exfiltration(self, fresh_db):
        threat = detection.ingest_threat("siem", "exfiltration", "prod-db", {}, "critical")
        assert threat["score"] == 100.0  # 90 + 12 = 102 capped at 100

    def test_ingest_stores_raw_data(self, fresh_db):
        raw = {"ip": "10.0.0.1", "port": 443}
        threat = detection.ingest_threat("siem", "intrusion", "web-01", raw, None)
        threats = detection.get_threats()
        found = next(t for t in threats if t["id"] == threat["id"])
        assert found["raw_data"] == raw


# ── Correlation Engine Tests ──────────────────────────────────────────────────

class TestCorrelation:
    def test_same_asset_correlates_to_one_incident(self, fresh_db):
        t1 = detection.ingest_threat("siem", "intrusion", "web-01", {}, None)
        t2 = detection.ingest_threat("waf", "lateral_movement", "web-01", {}, None)
        inc1 = correlation.correlate_threat(t1)
        inc2 = correlation.correlate_threat(t2)
        assert inc1 == inc2

    def test_different_assets_create_separate_incidents(self, fresh_db):
        t1 = detection.ingest_threat("siem", "intrusion", "web-01", {}, None)
        t2 = detection.ingest_threat("siem", "phishing", "mail-01", {}, None)
        inc1 = correlation.correlate_threat(t1)
        inc2 = correlation.correlate_threat(t2)
        assert inc1 != inc2

    def test_create_incident(self, fresh_db):
        inc = correlation.create_incident("Test", "high", "desc", "open", [])
        assert inc["id"].startswith("inc-")
        assert inc["title"] == "Test"

    def test_update_incident_status(self, fresh_db):
        inc = correlation.create_incident("Test", "high", "", "open", [])
        updated = correlation.update_incident(inc["id"], {"status": "resolved"})
        assert updated["status"] == "resolved"

    def test_get_incidents_filter_status(self, fresh_db):
        correlation.create_incident("Open Inc", "high", "", "open", [])
        correlation.create_incident("Resolved Inc", "low", "", "resolved", [])
        open_incs = correlation.get_incidents(status="open")
        assert all(i["status"] == "open" for i in open_incs)

    def test_timeline_empty_for_new_incident(self, fresh_db):
        inc = correlation.create_incident("Empty", "low", "", "open", [])
        timeline = correlation.get_timeline(inc["id"])
        assert timeline == []

    def test_timeline_includes_correlated_threats(self, fresh_db):
        t = detection.ingest_threat("siem", "intrusion", "web-01", {}, None)
        inc_id = correlation.correlate_threat(t)
        timeline = correlation.get_timeline(inc_id)
        assert len(timeline) >= 1
        assert timeline[0]["event_type"] == "intrusion"

    def test_get_timeline_missing_incident_returns_none(self, fresh_db):
        result = correlation.get_timeline("nonexistent-id")
        assert result is None


# ── Scoring Engine Tests ──────────────────────────────────────────────────────

class TestScoring:
    def test_score_increases_on_critical_threat(self, fresh_db):
        threat = {"asset": "prod-db", "severity": "critical", "event_type": "exfiltration", "score": 90.0}
        scoring.score_threat(threat)
        scores = scoring.get_scores(asset="prod-db")
        assert len(scores) == 1
        assert scores[0]["risk_level"] in ("critical", "high")

    def test_score_filter_by_asset(self, fresh_db):
        scoring.score_threat({"asset": "web-01", "severity": "high", "event_type": "intrusion", "score": 70.0})
        scoring.score_threat({"asset": "db-01", "severity": "low", "event_type": "phishing", "score": 20.0})
        results = scoring.get_scores(asset="web")
        assert all("web" in r["asset"] for r in results)

    def test_multiple_threats_accumulate_score(self, fresh_db):
        for _ in range(5):
            scoring.score_threat({"asset": "target", "severity": "medium", "event_type": "intrusion", "score": 45.0})
        scores = scoring.get_scores(asset="target")
        assert scores[0]["score"] > 50.0


# ── API Endpoint Tests ────────────────────────────────────────────────────────

class TestAPI:
    def test_health_no_auth(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_threats_requires_auth(self, client):
        resp = client.get("/api/threats")
        assert resp.status_code == 401

    def test_incidents_requires_auth(self, client):
        resp = client.get("/api/incidents")
        assert resp.status_code == 401

    def test_stats_requires_auth(self, client):
        resp = client.get("/api/stats")
        assert resp.status_code == 401

    def test_demo_login_and_get_threats(self, client):
        client.post("/api/auth/demo-login")
        resp = client.get("/api/threats")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_ingest_threat_via_api(self, authed_client):
        resp = authed_client.post("/api/threats", json={
            "source": "siem", "event_type": "intrusion", "asset": "web-01",
            "raw_data": {"ip": "192.168.1.1"}, "severity_hint": "high"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["severity"] == "high"
        assert data["score"] > 0

    def test_get_incidents_after_ingest(self, authed_client):
        authed_client.post("/api/threats", json={
            "source": "waf", "event_type": "malware", "asset": "db-01", "severity_hint": "critical"
        })
        resp = authed_client.get("/api/incidents")
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    def test_create_incident_via_api(self, authed_client):
        resp = authed_client.post("/api/incidents", json={
            "title": "Test Incident", "severity": "high", "description": "test"
        })
        assert resp.status_code == 200
        assert resp.json()["title"] == "Test Incident"

    def test_nl_query_deterministic_fallback(self, authed_client):
        """NL query should work without LLM key via keyword fallback."""
        resp = authed_client.post("/api/query", json={"query": "show critical threats"})
        assert resp.status_code == 200
        data = resp.json()
        assert "filters" in data

    def test_scores_endpoint(self, authed_client):
        authed_client.post("/api/threats", json={
            "source": "edr", "event_type": "intrusion", "asset": "server-01", "severity_hint": "high"
        })
        resp = authed_client.get("/api/scores")
        assert resp.status_code == 200
        scores = resp.json()
        assert any(s["asset"] == "server-01" for s in scores)

    def test_logout_clears_session(self, client):
        client.post("/api/auth/demo-login")
        client.post("/api/auth/logout")
        resp = client.get("/api/threats")
        assert resp.status_code == 401
