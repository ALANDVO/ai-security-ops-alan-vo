# Product development plan

Each round completes one feature or repair. Future items are planned, not implemented claims.

## Current round

baseline-migration

## Roadmap

### baseline-migration — Backend structure migration with SQLite persistence

Status: done

Acceptance:
- backend/app/main.py exists as FastAPI create_app factory
- SQLite persistence for threats, incidents, asset_scores, audit_log
- 30 backend tests pass with pytest
- Frontend vitest tests pass
- All required files present: portfolio.json, CHANGELOG.md, pyproject.toml, compose.yaml, backend/Dockerfile, frontend/Dockerfile, .github/workflows/ci.yml

Implementation: `backend/app/main.py`, `backend/app/core/config.py`, `backend/app/core/database.py`, `backend/app/core/logging.py`, `backend/app/api/auth.py`, `backend/app/api/routes.py`, `backend/app/api/schemas.py`, `backend/app/services/detection.py`, `backend/app/services/correlation.py`, `backend/app/services/scoring.py`, `backend/app/services/llm.py`, `backend/requirements.txt`, `backend/Dockerfile`, `frontend/Dockerfile`, `frontend/vite.config.ts`, `frontend/src/tests/components.test.tsx`, `compose.yaml`, `pyproject.toml`, `portfolio.json`, `CHANGELOG.md`, `.github/workflows/ci.yml`

Tests: `backend/tests/test_security_ops.py`, `frontend/src/tests/components.test.tsx`

### oidc-integration-test — OIDC login/callback integration test with local test IdP

Status: planned

Acceptance:
- Test crosses real HTTP boundary with OIDC authorization code flow
- State/PKCE rejection tested
- Token propagation into authorized API request tested

### llm-anthropic-gemini-tests — Mocked LLM adapter tests for Anthropic and Gemini providers

Status: planned

Acceptance:
- Anthropic provider returns advisory classification result
- Gemini provider returns advisory classification result
- Provider error surfaces clearly without fabricating success

