from functools import lru_cache
from pathlib import Path
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Literal
from pydantic import model_validator
from sqlalchemy import URL

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "Security AI"

    # Database
    #
    # Local development may provide DATABASE_URL directly.
    #
    # Docker can omit DATABASE_URL and provide the POSTGRES_*
    # values instead. The validator safely constructs the
    # SQLAlchemy connection URL.
    database_url: str = ""

    postgres_host: str = "127.0.0.1"
    postgres_port: int = 5432
    postgres_db: str = "security_ai"
    postgres_user: str = "security_ai"
    postgres_password: SecretStr | None = None

    # Authentication
    #
    # Keep this as a plain string because the existing security
    # service passes it directly to PyJWT.
    jwt_secret_key: str = Field(
        min_length=32,
    )

    jwt_algorithm: str = "HS256"

    access_token_expire_minutes: int = 30

    # AI investigation
    ai_provider: Literal[
        "disabled",
        "openai",
    ] = "disabled"

    openai_api_key: SecretStr | None = None

    openai_model: str = "gpt-5-mini"

    ai_request_timeout_seconds: int = 30

    ai_max_input_chars: int = 30_000

    # Background jobs
    celery_broker_url: str = (
        "redis://localhost:6379/0"
    )

    # Threat intelligence
    threat_intel_provider: Literal[
        "disabled",
        "abuseipdb",
    ] = "disabled"

    abuseipdb_api_key: SecretStr | None = None

    abuseipdb_base_url: str = (
        "https://api.abuseipdb.com/api/v2"
    )

    abuseipdb_max_age_days: int = 90

    threat_intel_timeout_seconds: int = 10

    threat_intel_cache_ttl_hours: int = 24

    @model_validator(mode="after")
    def build_database_url(
        self,
    ) -> "Settings":
        """
        Build a safely encoded PostgreSQL URL when DATABASE_URL
        has not been supplied directly.
        """

        if self.database_url:
            return self

        if self.postgres_password is None:
            raise ValueError(
                "Either DATABASE_URL or POSTGRES_PASSWORD "
                "must be configured"
            )

        self.database_url = URL.create(
            drivername="postgresql+psycopg",
            username=self.postgres_user,
            password=(
                self.postgres_password.get_secret_value()
            ),
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_db,
            query={
                "connect_timeout": "5",
            },
        ).render_as_string(
            hide_password=False
        )

        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()