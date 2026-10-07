# AI Security Operations Center

Enterprise AI-powered security operations platform with real-time threat detection, LLM-driven incident correlation, and natural language security queries.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        React Frontend                         │
│  ┌──────────┐  ┌────────────┐  ┌───────────┐  ┌──────────┐  │
│  │  Login   │  │  Dashboard │  │  Timeline │  │  Search  │  │
│  │ SAML/SSO │  │  ThreatFeed│  │  Incidents│  │  NL Query │  │
│  └──────────┘  └────────────┘  └───────────┘  └──────────┘  │
└───────────────────────────┬──────────────────────────────────┘
                            │ REST /api/*
┌───────────────────────────▼──────────────────────────────────┐
│                      FastAPI Backend                           │
│  ┌────────┐  ┌──────────────┐  ┌───────────────────────────┐  │
│  │ Auth   │  │  Middleware  │  │           Routes           │  │
│  │ SAML   │  │ Logging      │  │  /threats /incidents /api  │  │
│  │ JWT    │  │ Rate Limit   │  │  /query /stats /timeline   │  │
│  └────────┘  │ CORS         │  └───────────────────────────┘  │
│              └──────────────┘                                 │
│  ┌─────────────────────┐  ┌─────────────────────────────────┐ │
│  │   Services Layer     │  │        LLM Integration          │ │
│  │  Detection Engine    │  │  Threat Classification          │ │
│  │  Correlation Engine  │  │  Incident Correlation           │ │
│  │  Scoring Engine      │  │  NL Query Translation           │ │
│  └─────────────────────┘  └─────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
git clone https://github.com/ALANDVO/ai-security-ops-alan-vo.git
cd ai-security-ops-alan-vo
cp .env.example .env
docker compose up -d
# Open http://localhost:8000
```

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/login` | SAML/SSO login or email login |
| `GET` | `/api/auth/me` | Get current user |
| `GET` | `/api/health` | Health check |
| `GET` | `/api/threats` | Threat feed with filters |
| `POST` | `/api/threats` | Ingest threat event |
| `GET` | `/api/incidents` | Incident list |
| `POST` | `/api/incidents` | Create incident |
| `GET` | `/api/incidents/{id}/timeline` | Incident timeline |
| `POST` | `/api/query` | Natural language security query |
| `GET` | `/api/stats` | Security stats & metrics |
| `GET` | `/api/scores` | Risk scores by asset |

## SSO Setup

### SAML
1. Set `SAML_IDP_ENTITY` to your IdP metadata URL
2. Set `SAML_IDP_CERT` to your IdP X.509 certificate (base64)
3. Set `SAML_ACS_URL` to `https://yourdomain.com/saml/acs`
4. Configure SP metadata at `/saml/metadata`

### OAuth2
1. Register your app with the OAuth provider
2. Set `OAUTH_CLIENT_ID` and `OAUTH_CLIENT_SECRET`
3. Set `OAUTH_REDIRECT_URI` to `https://yourdomain.com/auth/callback`

## Tech Stack

Python 3.11, FastAPI, python3-saml, JWT, React 18, TypeScript, Vite, Recharts

## License

MIT — see [LICENSE](LICENSE)

---

**Built by [Alan Vo](https://github.com/ALANDVO)** | alanvo@gmail.com | AI, ML & Cybersecurity
