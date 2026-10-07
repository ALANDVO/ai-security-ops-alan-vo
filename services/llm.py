import logging, json
from typing import Optional, Dict, Any
import httpx

from config import settings

logger = logging.getLogger(__name__)

class LLMService:

    def __init__(self):
        self.base_url = settings.llm_base_url.rstrip("/")
        self.api_key = settings.llm_api_key
        self.model = settings.llm_model

    async def _chat(self, system: str, user: str, temperature: float = 0.3) -> str:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json={"model": self.model, "temperature": temperature, "max_tokens": 1024,
                      "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]},
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

    async def classify_threat(self, event: Dict[str, Any]) -> Dict[str, str]:
        system = "You are a senior security analyst. Classify the threat event and provide a one-line summary. Return JSON with keys: classification, summary, recommended_action."
        user = json.dumps(event, default=str)[:2000]
        try:
            raw = await self._chat(system, user)
            result = json.loads(raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip())
            return result
        except Exception as e:
            logger.warning("LLM classification failed: %s", e)
            return {"classification": "unknown", "summary": "LLM classification unavailable", "recommended_action": "manual_review"}

    async def correlate_incident(self, incident: Dict[str, Any]) -> Dict[str, str]:
        system = "You are a security operations lead. Analyze this incident, provide root cause hypothesis, impact assessment, and recommended actions. Return JSON: analysis, recommendation."
        user = json.dumps({
            "title": incident["title"], "severity": incident["severity"],
            "threat_count": incident["threat_count"],
            "types": list(incident.get("types", [])),
        }, default=str)[:2000]
        try:
            raw = await self._chat(system, user)
            return json.loads(raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip())
        except Exception as e:
            logger.warning("LLM correlation failed: %s", e)
            return {"analysis": "Incident requires manual review", "recommendation": "Escalate to security team"}

    async def natural_language_query(self, query: str) -> Dict[str, Any]:
        system = "You are a security data query translator. Convert the user's natural language question into a structured filter object. Return JSON: {filters: {severity?, event_type?, asset?, time_range?}, explanation, suggested_followup}."
        user = f"Security query: {query}"
        try:
            raw = await self._chat(system, user)
            result = json.loads(raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip())
            return result
        except Exception as e:
            logger.warning("NL query failed: %s", e)
            return {"filters": {}, "explanation": f"Query processed with fallback: {e}", "suggested_followup": "Try: Show critical threats on web servers in the last hour"}

llm_service = LLMService()
