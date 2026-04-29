# core/config.py
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """
    All configuration values are loaded from the .env file.
    Pydantic validates types and raises errors for missing required values.
    """

    # Groq LLM (free tier)
    groq_api_key: str = Field(..., description="Groq API key for LLM calls")

    # GitHub
    github_token: str = Field(..., description="GitHub personal access token")

    # GitHub Webhook Secrete
    github_webhook_secret: str = Field(..., description="Secret for verifying GitHub webhooks")

    # Email / SMTP
    smtp_email: str = Field(..., description="Gmail address for notifications")
    smtp_password: str = Field(..., description="Gmail app password")

    # Security
    secret_key: str = Field(..., description="Key for signing approval tokens")

    # Server
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000)
    debug: bool = Field(default=True)

    class Config:
        env_file = ".env"          # Load from .env automatically
        env_file_encoding = "utf-8"
        case_sensitive = False     # GROQ_API_KEY or groq_api_key both work


# Single shared instance — import this everywhere
settings = Settings()