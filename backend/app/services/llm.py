"""LLM integration supporting OpenAI-compatible, Anthropic, and Gemini providers.

All LLM calls are opt-in, clearly labeled advisory in the UI.
Provider errors are surfaced clearly; never fabricate successful responses.
"""
import json
import logging
from typing import Any, Dict

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

_TIMEOUT = 30.0


async def _call_openai_compatible(system: str, user: str) -> str:
    """Call any OpenAI-compatible endpoint (OpenRouter, LiteLLM, Ollama, etc.)."""
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(
            f"{settings.llm_base_url.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {settings.llm_api_key}", "Content-Type": "application/json"},
            json={
                "model": settings.llm_model,
                "temperature": 0.3,
                "max_tokens": 1024,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]


async def _call_anthropic(system: str, user: str) -> str:
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": settings.llm_api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            json={
                "model": settings.llm_model,
                "max_tokens": 1024,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )
        resp.raise_for_status()
        return resp.json()["content"][0]["text"]


async def _call_gemini(system: str, user: str) -> str:
    model = settings.llm_model or "gemini-1.5-flash"
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(
            url,
            params={"key": settings.llm_api_key},
            json={
                "contents": [{"role": "user", "parts": [{"text": f"{system}\n\n{user}"}]}],
                "generationConfig": {"temperature": 0.3, "maxOutputTokens": 1024},
            },
        )
        resp.raise_for_status()
        return resp.json()["candidates"][0]["content"]["parts"][0]["text"]


async def _call_llm(system: str, user: str) -> str:
    """Dispatch to the configured provider."""
    if not settings.llm_api_key:
        raise ValueError("LLM_API_KEY not configured")
    provider = settings.llm_provider.lower()
    if provider == "anthropic":
        return await _call_anthropic(system, user)
    if provider == "gemini":
        return await _call_gemini(system, user)
    # Default: openai-compatible (covers openai, openrouter, litellm, ollama)
    return await _call_openai_compatible(system, user)


def _parse_json(raw: str) -> dict:
    cleaned = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    return json.loads(cleaned)


async def classify_threat(event: Dict[str, Any]) -> Dict[str, str]:
    """LLM-assisted threat classification. Returns advisory result."""
    system = (
        "You are a senior security analyst. Classify the threat event "
        "and provide a concise summary. Return JSON with keys: "
        "classification, summary, recommended_action."
    )
    user = json.dumps(event, default=str)[:2000]
    try:
        raw = await _call_llm(system, user)
        return _parse_json(raw)
    except ValueError as exc:
        logger.info("LLM not configured: %s", exc)
        return {"classification": "unconfigured", "summary": "LLM not configured", "recommended_action": "manual_review"}
    except Exception as exc:
        logger.warning("LLM classify_threat failed: %s", type(exc).__name__)
        return {"classification": "unavailable", "summary": "LLM classification unavailable", "recommended_action": "manual_review"}


async def correlate_incident(incident: Dict[str, Any]) -> Dict[str, str]:
    """LLM-assisted incident analysis. Returns advisory result."""
    system = (
        "You are a security operations lead. Analyze this incident. "
        "Return JSON with keys: analysis, recommendation."
    )
    user = json.dumps({
        "title": incident.get("title"), "severity": incident.get("severity"),
        "threat_count": incident.get("threat_count"),
    }, default=str)[:2000]
    try:
        raw = await _call_llm(system, user)
        return _parse_json(raw)
    except ValueError:
        return {"analysis": "LLM not configured", "recommendation": "Escalate to security team"}
    except Exception as exc:
        logger.warning("LLM correlate_incident failed: %s", type(exc).__name__)
        return {"analysis": "Incident requires manual review", "recommendation": "Escalate to security team"}


async def natural_language_query(query: str) -> Dict[str, Any]:
    """Convert NL query to structured filter. Deterministic fallback when LLM unavailable."""
    system = (
        "You are a security data query translator. Convert the user's natural language question "
        "into a structured filter object. Return JSON: "
        "{filters: {severity?, event_type?, asset?, time_range?}, explanation, suggested_followup}."
    )
    user = f"Security query: {query}"

    # Deterministic fallback parsing
    def _deterministic_parse(q: str) -> Dict[str, Any]:
        filters: Dict[str, Any] = {}
        q_lower = q.lower()
        for sev in ("critical", "high", "medium", "low"):
            if sev in q_lower:
                filters["severity"] = sev
                break
        for et in ("intrusion", "malware", "phishing", "exfiltration", "lateral_movement"):
            if et.replace("_", " ") in q_lower or et in q_lower:
                filters["event_type"] = et
                break
        return {"filters": filters, "explanation": f"Parsed '{q}' using keyword matching", "suggested_followup": "Try: Show critical intrusions on web servers"}

    try:
        raw = await _call_llm(system, user)
        return _parse_json(raw)
    except ValueError:
        return _deterministic_parse(query)
    except Exception as exc:
        logger.warning("NL query LLM failed: %s", type(exc).__name__)
        return _deterministic_parse(query)
