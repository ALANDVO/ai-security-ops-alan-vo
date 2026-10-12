"""Authentication: OIDC authorization-code + PKCE with backend-managed sessions.

Demo mode: local-only, explicitly selected. Refused at startup in production.
"""
import hashlib
import json
import logging
import os
import secrets
import time
from typing import Optional
from urllib.parse import urlencode

import httpx
from fastapi import Cookie, Depends, HTTPException, Request, Response
from jose import JWTError, jwt
from pydantic import BaseModel

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── Data models ──────────────────────────────────────────────────────────────

class User(BaseModel):
    email: str
    name: str = ""
    role: str = "analyst"


# ── Session management (HttpOnly SameSite cookies) ────────────────────────────

_sessions: dict[str, dict] = {}  # In-memory; replaced by DB in production scale-out


def _create_session(user_data: dict) -> str:
    sid = secrets.token_urlsafe(32)
    _sessions[sid] = {
        "user": user_data,
        "created_at": time.time(),
        "expires_at": time.time() + settings.jwt_expiry_minutes * 60,
    }
    return sid


def _get_session(sid: str) -> Optional[dict]:
    session = _sessions.get(sid)
    if not session:
        return None
    if time.time() > session["expires_at"]:
        del _sessions[sid]
        return None
    return session


def delete_session(sid: str) -> None:
    _sessions.pop(sid, None)


# ── CSRF token ────────────────────────────────────────────────────────────────

def _csrf_token_for_session(sid: str) -> str:
    return hashlib.sha256(f"{sid}{settings.jwt_secret}".encode()).hexdigest()[:32]


def verify_csrf(sid: str, token: str) -> bool:
    return secrets.compare_digest(_csrf_token_for_session(sid), token)


# ── OIDC / Keycloak discovery ──────────────────────────────────────────────────

_oidc_config: Optional[dict] = None


async def _get_oidc_config() -> dict:
    global _oidc_config
    if _oidc_config:
        return _oidc_config
    if not settings.oidc_discovery_url:
        raise HTTPException(status_code=503, detail="OIDC not configured (set OIDC_DISCOVERY_URL)")
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(settings.oidc_discovery_url)
        resp.raise_for_status()
        _oidc_config = resp.json()
    return _oidc_config


# ── Authorization code + PKCE flow ────────────────────────────────────────────

_pkce_store: dict[str, dict] = {}  # state → {verifier, nonce}


def build_auth_redirect(response: Response) -> str:
    """Build the OIDC authorization URL and store state/nonce/verifier."""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    verifier = secrets.token_urlsafe(32)
    challenge = (
        hashlib.sha256(verifier.encode())
        .digest()
        .hex()
    )
    # Store verifier+nonce keyed by state
    _pkce_store[state] = {"verifier": verifier, "nonce": nonce, "created_at": time.time()}

    if not settings.oidc_discovery_url:
        # Demo mode shortcut
        return "/api/auth/demo-callback"

    # Caller must await _get_oidc_config(); here we return a placeholder if not configured.
    return f"/api/auth/login?state={state}"


async def start_oidc_login(response: Response) -> str:
    """Return redirect URL to OIDC provider."""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    verifier = secrets.token_urlsafe(32)
    # PKCE S256
    import base64
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    _pkce_store[state] = {"verifier": verifier, "nonce": nonce, "created_at": time.time()}

    config = await _get_oidc_config()
    params = {
        "response_type": "code",
        "client_id": settings.oidc_client_id,
        "redirect_uri": settings.oidc_redirect_uri,
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return config["authorization_endpoint"] + "?" + urlencode(params)


async def handle_oidc_callback(code: str, state: str, response: Response) -> User:
    """Exchange code → tokens, validate, create session."""
    stored = _pkce_store.pop(state, None)
    if not stored:
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state")

    config = await _get_oidc_config()

    async with httpx.AsyncClient(timeout=15) as client:
        token_resp = await client.post(
            config["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": settings.oidc_redirect_uri,
                "client_id": settings.oidc_client_id,
                "client_secret": settings.oidc_client_secret,
                "code_verifier": stored["verifier"],
            },
        )
        if token_resp.status_code != 200:
            raise HTTPException(status_code=401, detail="Token exchange failed")
        tokens = token_resp.json()

    id_token = tokens.get("id_token", "")
    # Validate: fetch JWKS and verify signature/issuer/audience/nonce
    async with httpx.AsyncClient(timeout=10) as client:
        jwks_resp = await client.get(config["jwks_uri"])
        jwks = jwks_resp.json()

    try:
        from jose import jwk, jwt as jose_jwt
        claims = jose_jwt.decode(
            id_token,
            jwks,
            algorithms=["RS256"],
            audience=settings.oidc_client_id,
            issuer=config["issuer"],
            options={"verify_at_hash": False},
        )
    except JWTError as exc:
        raise HTTPException(status_code=401, detail=f"ID token validation failed: {exc}")

    if claims.get("nonce") != stored["nonce"]:
        raise HTTPException(status_code=401, detail="Nonce mismatch")

    user_data = {
        "email": claims.get("email", claims.get("sub", "")),
        "name": claims.get("name", ""),
        "role": _map_role(claims),
    }
    user = User(**user_data)
    sid = _create_session(user_data)

    response.set_cookie(
        "sid",
        sid,
        httponly=True,
        samesite="lax",
        secure=not settings.demo_mode,
        max_age=settings.jwt_expiry_minutes * 60,
    )
    response.set_cookie(
        "csrf_token",
        _csrf_token_for_session(sid),
        httponly=False,
        samesite="lax",
        secure=not settings.demo_mode,
        max_age=settings.jwt_expiry_minutes * 60,
    )
    return user


def _map_role(claims: dict) -> str:
    roles = claims.get("realm_access", {}).get("roles", [])
    if "admin" in roles:
        return "admin"
    if "operator" in roles or "analyst" in roles:
        return "analyst"
    return "viewer"


# ── Demo-mode session (localhost only) ────────────────────────────────────────

def create_demo_session(response: Response) -> User:
    """Create a demo session for local development. Refused in production."""
    if not settings.demo_mode:
        raise HTTPException(status_code=403, detail="Demo mode is not enabled (set DEMO_MODE=true for local dev)")
    user_data = {
        "email": settings.demo_user_email,
        "name": settings.demo_user_name,
        "role": settings.demo_user_role,
    }
    user = User(**user_data)
    sid = _create_session(user_data)
    response.set_cookie("sid", sid, httponly=True, samesite="lax", secure=False, max_age=3600)
    response.set_cookie("csrf_token", _csrf_token_for_session(sid), httponly=False, samesite="lax", secure=False, max_age=3600)
    return user


# ── Dependency: get current user ──────────────────────────────────────────────

def get_current_user(sid: Optional[str] = Cookie(default=None)) -> User:
    if not sid:
        raise HTTPException(status_code=401, detail="Not authenticated — please log in")
    session = _get_session(sid)
    if not session:
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    return User(**session["user"])


def require_role(*roles: str):
    def _dep(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail=f"Role '{user.role}' not authorized; required: {roles}")
        return user
    return _dep
