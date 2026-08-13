from functools import lru_cache

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

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
