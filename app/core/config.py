from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "Security AI Platform"
    database_url: str = "sqlite:///./security_ai.db"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Return the cached application config"""

    return Settings()


