from functools import lru_cache
from pathlib import Path
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Literal

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"


class Settings(BaseSettings):
    app_name: str = "Security AI Platform"
    database_url: str = "sqlite:///./security_ai.db"
    jwt_secret_key: str = Field(min_length=32)
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = Field(
        default=30,
        ge=5,
        le=1440,
    )

    ai_provider: Literal["disabled", "openai"] = "disabled"
    openai_api_key: SecretStr | None = None
    openai_model: str = "gpt-5-mini"

    ai_request_timeout_seconds: float = Field(
        default=30.0,
        ge=5,
        le=300
    )

    ai_max_input_characters: int = Field(
        default=30_000,
        ge=5_000,
        le=200_000
    )

    celery_broker_url: str = "redis://redis:6379/0"

    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    threat_intel_provider: Literal[
        "disabled",
        "abuseipdb",
    ] = "disabled"

    abuseipdb_api_key: SecretStr | None = None

    abuseipdb_base_url: str = "https://api.abuseipdb.com/api/v2"

    abuseipdb_max_age_days: int = Field(
        default=90,
        ge=1,
        le=365,
    )

    threat_intel_timeout_seconds: float = Field(
        default=10.0,
        ge=1.0,
        le=60.0,
    )

    threat_intel_cache_ttl_hours: int = Field(
        default=24,
        ge=1,
        le=168,
    )


@lru_cache
def get_settings() -> Settings:
    """Return the cached application configuration."""

    return Settings()