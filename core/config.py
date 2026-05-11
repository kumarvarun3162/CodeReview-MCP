# core/config.py
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):

    # Groq LLM
    groq_api_key: str = Field(..., description="Groq API key for LLM calls")

    # GitHub
    github_token: str = Field(..., description="GitHub personal access token")
    github_webhook_secret: str = Field(..., description="Secret for verifying GitHub webhooks")

    # Email / SMTP
    smtp_email: str = Field(..., description="Gmail address for notifications")
    smtp_password: str = Field(..., description="Gmail app password")

    # Token signing
    secret_key: str = Field(..., description="Key for signing approval tokens")

    # Public URL — used to build approve/reject links in emails
    server_base_url: str = Field(..., description="Public URL of this server")

    # Server
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000)
    debug: bool = Field(default=True)

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


settings = Settings()