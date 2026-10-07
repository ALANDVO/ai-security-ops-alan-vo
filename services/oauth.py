import logging, json
from typing import Optional, Dict
import httpx

logger = logging.getLogger(__name__)

class OAuthHandler:

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str,
                 authorize_url: str = "https://accounts.google.com/o/oauth2/v2/auth",
                 token_url: str = "https://oauth2.googleapis.com/token",
                 userinfo_url: str = "https://openidconnect.com/info/claims"):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.authorize_url = authorize_url
        self.token_url = token_url
        self.userinfo_url = userinfo_url

    def build_authorize_url(self, state: str = "") -> str:
        from urllib.parse import urlencode
        params = {
            "client_id": self.client_id, "redirect_uri": self.redirect_uri,
            "response_type": "code", "scope": "openid email profile", "state": state,
        }
        return f"{self.authorize_url}?{urlencode(params)}"

    def exchange_code(self, request) -> Dict:
        from fastapi import HTTPException
        code = request.query_params.get("code", "")
        if not code:
            raise HTTPException(status_code=400, detail="Missing authorization code")
        try:
            resp = httpx.post(self.token_url, data={
                "client_id": self.client_id, "client_secret": self.client_secret,
                "code": code, "grant_type": "authorization_code", "redirect_uri": self.redirect_uri,
            }, timeout=30)
            resp.raise_for_status()
            tokens = resp.json()
            access_token = tokens.get("access_token", "")
            info = httpx.get(self.userinfo_url, headers={"Authorization": f"Bearer {access_token}"}, timeout=30)
            info.raise_for_status()
            user = info.json()
            return {
                "email": user.get("email", ""), "name": user.get("name", "oauth-user"),
                "role": "admin", "provider": "oauth2",
            }
        except Exception as e:
            logger.error("OAuth exchange failed: %s", e)
            raise HTTPException(status_code=502, detail=f"OAuth exchange failed: {e}")
