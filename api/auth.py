from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from pydantic import BaseModel
import time, os

from config import settings

bearer_scheme = HTTPBearer(auto_error=False)

class User(BaseModel):
    email: str
    name: str = ""
    role: str = "analyst"

def create_jwt(user: dict) -> str:
    payload = {
        "sub": user.get("email", "unknown"),
        "name": user.get("name", ""),
        "role": user.get("role", "analyst"),
        "exp": time.time() + settings.jwt_expiry_minutes * 60,
        "iat": time.time(),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")

def verify_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> User:
    if not creds:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    payload = verify_jwt(creds.credentials)
    return User(email=payload.get("sub", ""), name=payload.get("name", ""), role=payload.get("role", "analyst"))

def saml_login(request: Request):
    from services.saml import SAMLHandler
    handler = SAMLHandler(
        sp_entity=settings.saml_sp_entity,
        idp_entity=settings.saml_idp_entity,
        idp_cert=settings.saml_idp_cert,
        acs_url=settings.saml_acs_url,
    )
    return handler.process_response(request)

def oauth2_login(request: Request):
    from services.oauth import OAuthHandler
    handler = OAuthHandler(
        client_id=settings.oauth_client_id,
        client_secret=settings.oauth_client_secret,
        redirect_uri=settings.oauth_redirect_uri,
    )
    return handler.exchange_code(request)
