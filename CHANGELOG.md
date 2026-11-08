# Changelog

## 1.5.0 — work-in-progress checkpoint

Partial code published for continued development. Known issues: STATUS.md.

## 1.4.0 — work-in-progress checkpoint

### Added (2026-11-08)
- Health endpoint (`/api/health`) now verifies database connectivity, returning `database: "connected"` on success or `database: "degraded"` with error details on failure
- Health check test validates database connectivity assertion
- Supports Docker/Kubernetes health checks and readiness probes via compose.yaml healthcheck

### Fixed
- Health endpoint no longer returns "ok" without verifying database state

Partial code published for continued development. Known issues: STATUS.md.

## 1.3.0 — work-in-progress checkpoint

### Added (2026-11-05)
- Mocked LLM adapter tests for Anthropic and Gemini providers (`backend/tests/test_llm.py`)
- 17 new unit tests covering classify_threat, correlate_incident, natural_language_query fallback, and JSON parsing
- Provider error handling tests verifying graceful degradation without fabricated success
- Total backend tests: 47 (30 original + 17 LLM)

### Fixed
- LLM service now properly tested with mocked Anthropic, Gemini, and OpenAI-compatible providers
- Deterministic fallback behavior validated for classify_threat, correlate_incident, and NL query

Partial code published for continued development. Known issues: STATUS.md.

## 1.2.0 — work-in-progress checkpoint

Partial code published for continued development. Known issues: STATUS.md.

## 1.1.0 — work-in-progress checkpoint

Partial code published for continued development. Known issues: STATUS.md.

### Fixed (2026-10-20)
- Frontend test setup: Added ResizeObserver polyfill for jsdom (recharts ResponsiveContainer)
- Backend: Migrated from deprecated `on_event("startup")` to lifespan asynccontextmanager
- Backend: Migrated Pydantic schemas from class-based `Config` to `model_config = ConfigDict(from_attributes=True)`

All notable changes to AI Security Operations Center.

## [1.0.0] — 2026-10-12

### Added
- FastAPI backend with modular structure: `backend/app/` with `api/`, `services/`, `models/`, `core/`
- SQLite persistent storage for threats, incidents, asset scores, and audit log
- Deterministic threat scoring engine: severity-weighted scores with event-type boost
- Incident correlation engine: groups related threats by asset and event type into incidents
- Asset risk scoring: accumulates score from ingested threats per asset
- Natural language query endpoint with keyword-based deterministic fallback (LLM optional)
- Multi-provider LLM adapter: OpenAI-compatible (OpenRouter/LiteLLM/Ollama), Anthropic messages, Gemini generateContent
- OIDC authorization-code + PKCE authentication via Keycloak with backend-managed sessions
- HttpOnly SameSite session cookies and CSRF token protection on mutations
- Local demo mode (`DEMO_MODE=true`) with startup refusal in non-localhost environments
- Role-based access control: `viewer`, `analyst`, `admin` with protected mutation endpoints
- React + TypeScript dashboard with threat feed, incidents timeline, NL query, and asset scores
- Filtering by severity, asset, and status across threats and incidents
- Incident status updates (open → investigating → resolved → closed)
- Docker Compose stack with backend, frontend (nginx), and Keycloak
- GitHub Actions CI: backend pytest, frontend build/test, Docker image builds
- 30 backend tests covering detection, correlation, scoring, auth, and API endpoints
- 12 frontend tests covering Dashboard, Incidents, and Scores pages

### Architecture
- `backend/app/main.py`: FastAPI create_app factory
- `backend/app/core/`: config, database, logging
- `backend/app/api/`: auth, routes, schemas
- `backend/app/services/`: detection, correlation, scoring, llm
- `frontend/src/`: React pages, components, typed API client

---

Alan Vo · [alanvo.net](https://alanvo.net) · [X: @alanvoasi](https://x.com/alanvoasi)
