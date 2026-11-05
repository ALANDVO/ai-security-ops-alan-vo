"""Mocked LLM adapter tests for Anthropic and Gemini providers."""
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Set test env before importing app modules
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["DEMO_MODE"] = "true"
os.environ["JWT_SECRET"] = "test-secret-key"
os.environ["LLM_API_KEY"] = "test-key"
os.environ["LLM_BASE_URL"] = "https://api.anthropic.com"
os.environ["LLM_MODEL"] = "claude-3-sonnet-20240229"
os.environ["LLM_PROVIDER"] = "anthropic"

from app.services import llm


class MockResponse:
    """Mock httpx response."""
    def __init__(self, json_data, status_code=200):
        self._json = json_data
        self.status_code = status_code

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")


@pytest.fixture(autouse=True)
def reset_settings():
    """Reset LLM provider settings for each test."""
    from app.core.config import settings
    original_provider = settings.llm_provider
    original_model = settings.llm_model
    original_base_url = settings.llm_base_url
    original_api_key = settings.llm_api_key
    yield
    settings.llm_provider = original_provider
    settings.llm_model = original_model
    settings.llm_base_url = original_base_url
    settings.llm_api_key = original_api_key


class TestAnthropicProvider:
    """Tests for Anthropic provider."""

    @pytest.mark.asyncio
    async def test_classify_threat_returns_advisory_result(self):
        """Anthropic provider returns advisory classification result."""
        mock_response = {
            "content": [{"text": '{"classification": "malware", "summary": "Detected ransomware behavior", "recommended_action": "isolate_host"}'}]
        }

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = MockResponse(mock_response)
            event = {"source": "edr", "event_type": "malware", "asset": "workstation-01", "severity_hint": "high"}
            result = await llm.classify_threat(event)

        assert result["classification"] == "malware"
        assert result["summary"] == "Detected ransomware behavior"
        assert result["recommended_action"] == "isolate_host"

    @pytest.mark.asyncio
    async def test_correlate_incident_returns_advisory_result(self):
        """Anthropic provider returns advisory correlation result."""
        mock_response = {
            "content": [{"text": '{"analysis": "Multi-stage attack detected", "recommendation": "Activate incident response"}'}]
        }

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = MockResponse(mock_response)
            incident = {"title": "Suspicious Activity", "severity": "critical", "threat_count": 5}
            result = await llm.correlate_incident(incident)

        assert result["analysis"] == "Multi-stage attack detected"
        assert result["recommendation"] == "Activate incident response"

    @pytest.mark.asyncio
    async def test_provider_error_surfaces_without_fabricating_success(self):
        """Provider error surfaces clearly without fabricating success."""
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = Exception("Connection refused")
            event = {"source": "edr", "event_type": "intrusion", "asset": "server-01", "severity_hint": "critical"}
            result = await llm.classify_threat(event)

        assert result["classification"] == "unavailable"
        assert "LLM classification unavailable" in result["summary"]


class TestGeminiProvider:
    """Tests for Gemini provider."""

    @pytest.fixture(autouse=True)
    def set_gemini_config(self):
        """Configure Gemini provider for tests."""
        from app.core.config import settings
        settings.llm_provider = "gemini"
        settings.llm_model = "gemini-1.5-flash"
        settings.llm_base_url = "https://generativelanguage.googleapis.com/v1beta"
        settings.llm_api_key = "test-gemini-key"

    @pytest.mark.asyncio
    async def test_classify_threat_returns_advisory_result(self):
        """Gemini provider returns advisory classification result."""
        mock_response = {
            "candidates": [{
                "content": {
                    "parts": [{"text": '{"classification": "phishing", "summary": "Credential harvesting detected", "recommended_action": "block_sender"}'}]
                }
            }]
        }

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = MockResponse(mock_response)
            event = {"source": "email", "event_type": "phishing", "asset": "user-mailbox", "severity_hint": "medium"}
            result = await llm.classify_threat(event)

        assert result["classification"] == "phishing"
        assert result["summary"] == "Credential harvesting detected"
        assert result["recommended_action"] == "block_sender"

    @pytest.mark.asyncio
    async def test_correlate_incident_returns_advisory_result(self):
        """Gemini provider returns advisory correlation result."""
        mock_response = {
            "candidates": [{
                "content": {
                    "parts": [{"text": '{"analysis": "Lateral movement detected", "recommendation": "Review network logs"}'}]
                }
            }]
        }

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = MockResponse(mock_response)
            incident = {"title": "Network Anomaly", "severity": "high", "threat_count": 3}
            result = await llm.correlate_incident(incident)

        assert result["analysis"] == "Lateral movement detected"
        assert result["recommendation"] == "Review network logs"

    @pytest.mark.asyncio
    async def test_provider_error_surfaces_without_fabricating_success(self):
        """Provider error surfaces clearly without fabricating success."""
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = Exception("API quota exceeded")
            event = {"source": "firewall", "event_type": "exfiltration", "asset": "db-server", "severity_hint": "critical"}
            result = await llm.classify_threat(event)

        assert result["classification"] == "unavailable"
        assert "LLM classification unavailable" in result["summary"]


class TestLLMDeterministicFallback:
    """Tests for deterministic fallback when LLM unavailable."""

    @pytest.fixture(autouse=True)
    def unset_llm_key(self):
        """Unset LLM API key to trigger fallback."""
        from app.core.config import settings
        original_key = settings.llm_api_key
        settings.llm_api_key = ""
        yield
        settings.llm_api_key = original_key

    @pytest.mark.asyncio
    async def test_classify_threat_returns_unconfigured(self):
        """classify_threat returns unconfigured when no API key."""
        event = {"source": "edr", "event_type": "malware", "asset": "workstation-01", "severity_hint": "high"}
        result = await llm.classify_threat(event)

        assert result["classification"] == "unconfigured"
        assert "LLM not configured" in result["summary"]

    @pytest.mark.asyncio
    async def test_correlate_incident_returns_llm_not_configured(self):
        """correlate_incident returns LLM not configured when no API key."""
        incident = {"title": "Test Incident", "severity": "high", "threat_count": 2}
        result = await llm.correlate_incident(incident)

        assert result["analysis"] == "LLM not configured"
        assert result["recommendation"] == "Escalate to security team"

    @pytest.mark.asyncio
    async def test_natural_language_query_uses_keyword_fallback(self):
        """NL query uses keyword fallback when LLM unavailable."""
        result = await llm.natural_language_query("show critical threats on web servers")

        assert "filters" in result
        assert result["filters"]["severity"] == "critical"
        assert "explanation" in result
        assert "keyword matching" in result["explanation"].lower()

    @pytest.mark.asyncio
    async def test_natural_language_query_parses_event_type(self):
        """NL query fallback parses event type keywords."""
        result = await llm.natural_language_query("find phishing emails")

        assert result["filters"]["event_type"] == "phishing"

    @pytest.mark.asyncio
    async def test_natural_language_query_parses_severity(self):
        """NL query fallback parses severity keywords."""
        for sev in ("critical", "high", "medium", "low"):
            result = await llm.natural_language_query(f"show {sev} alerts")
            assert result["filters"]["severity"] == sev


class TestParseJson:
    """Tests for JSON parsing utility."""

    def test_parse_json_plain(self):
        """Parse plain JSON string."""
        raw = '{"key": "value"}'
        result = llm._parse_json(raw)
        assert result == {"key": "value"}

    def test_parse_json_markdown_fenced(self):
        """Parse JSON wrapped in markdown code fence."""
        raw = '```json\n{"key": "value"}\n```'
        result = llm._parse_json(raw)
        assert result == {"key": "value"}

    def test_parse_json_markdown_no_lang(self):
        """Parse JSON wrapped in plain markdown fence."""
        raw = '```\n{"key": "value"}\n```'
        result = llm._parse_json(raw)
        assert result == {"key": "value"}

    def test_parse_json_whitespace(self):
        """Parse JSON with surrounding whitespace."""
        raw = '  \n  {"key": "value"}  \n  '
        result = llm._parse_json(raw)
        assert result == {"key": "value"}


class TestOpenAICompatibleProvider:
    """Tests for OpenAI-compatible provider (default)."""

    @pytest.fixture(autouse=True)
    def set_openai_config(self):
        """Configure OpenAI-compatible provider for tests."""
        from app.core.config import settings
        settings.llm_provider = "openai-compatible"
        settings.llm_model = "gpt-4o-mini"
        settings.llm_base_url = "https://api.openai.com/v1"
        settings.llm_api_key = "test-openai-key"

    @pytest.mark.asyncio
    async def test_classify_threat_returns_advisory_result(self):
        """OpenAI-compatible provider returns advisory classification result."""
        mock_response = {
            "choices": [{"message": {"content": '{"classification": "intrusion", "summary": "Brute force detected", "recommended_action": "block_ip"}'}}]
        }

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = MockResponse(mock_response)
            event = {"source": "auth", "event_type": "intrusion", "asset": "ssh-gateway", "severity_hint": "high"}
            result = await llm.classify_threat(event)

        assert result["classification"] == "intrusion"
        assert result["summary"] == "Brute force detected"
        assert result["recommended_action"] == "block_ip"

    @pytest.mark.asyncio
    async def test_provider_error_surfaces_without_fabricating_success(self):
        """Provider error surfaces clearly without fabricating success."""
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = Exception("Rate limited")
            event = {"source": "edr", "event_type": "malware", "asset": "workstation-01", "severity_hint": "high"}
            result = await llm.classify_threat(event)

        assert result["classification"] == "unavailable"
        assert "LLM classification unavailable" in result["summary"]

