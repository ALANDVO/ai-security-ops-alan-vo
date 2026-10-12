"""Application configuration loaded from environment variables."""
import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "8000"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")

    # Database
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./security_ops.db")

    # Auth / OIDC
    oidc_discovery_url: str = os.getenv("OIDC_DISCOVERY_URL", "")
    oidc_client_id: str = os.getenv("OIDC_CLIENT_ID", "security-ops")
    oidc_client_secret: str = os.getenv("OIDC_CLIENT_SECRET", "")
    oidc_redirect_uri: str = os.getenv("OIDC_REDIRECT_URI", "http://localhost:8000/api/auth/callback")
    jwt_secret: str = os.getenv("JWT_SECRET", "change-me-in-production")
    jwt_expiry_minutes: int = int(os.getenv("JWT_EXPIRY_MINUTES", "60"))

    # Demo mode — local-only, refused in production
    demo_mode: bool = os.getenv("DEMO_MODE", "false").lower() == "true"
    demo_user_email: str = "demo@localhost"
    demo_user_name: str = "Demo User"
    demo_user_role: str = "analyst"

    # LLM
    llm_api_key: str = os.getenv("LLM_API_KEY", "")
    llm_base_url: str = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1")
    llm_model: str = os.getenv("LLM_MODEL", "gpt-4o-mini")
    llm_provider: str = os.getenv("LLM_PROVIDER", "openai-compatible")

    def validate_demo_mode(self) -> None:
        """Refuse demo mode in production environments."""
        if self.demo_mode and (self.host != "127.0.0.1" and self.host != "0.0.0.0"):
            raise RuntimeError("DEMO_MODE=true is only allowed when binding localhost. Set HOST=127.0.0.1.")


settings = Settings()
