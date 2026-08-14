from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Fraud Detection Platform"
    environment: str = "development"
    debug: bool = True

    postgres_user: str = "fraud_detection"
    postgres_password: str = "fraud_detection"
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "fraud_detection"

    log_level: str = "INFO"

    # Phase 8: real LLM investigation reasoner. SecretStr so the key can
    # never leak via an accidental repr()/log of the Settings object. The
    # application must remain fully functional with llm_enabled=False.
    llm_enabled: bool = False
    llm_model: str = "claude-sonnet-5"
    llm_api_key: SecretStr | None = None
    llm_timeout: float = 20.0
    llm_max_output_tokens: int = 1024

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
