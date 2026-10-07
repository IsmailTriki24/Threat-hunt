from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEV_PLACEHOLDER_PREFIX = "dev-only-"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    app_env: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"

    database_url: str = "postgresql+asyncpg://hunt:hunt@localhost:5432/hunt"
    redis_url: str = "redis://localhost:6379/0"

    opensearch_url: str = "http://localhost:9200"
    opensearch_username: str | None = None
    opensearch_password: str | None = None
    opensearch_verify_certs: bool = True
    # Prepended to every index / template name. Lets tests share a cluster with dev data.
    index_prefix: str = ""
    index_shards: int = 1
    index_replicas: int = 0

    jwt_secret: str = Field(default="", repr=False)
    jwt_issuer: str = "threat-hunt"
    jwt_audience: str = "threat-hunt-api"
    access_token_ttl_minutes: int = 15
    refresh_token_ttl_days: int = 7

    password_min_length: int = 12
    cors_origins: str = ""
    metrics_token: str | None = Field(default=None, repr=False)
    max_body_bytes: int = 10 * 1024 * 1024
    ingest_max_batch: int = 1000

    retention_days: int = 90

    seed_demo_data: bool = False
    seed_password: str = Field(default="", repr=False)

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def cookie_secure(self) -> bool:
        return self.app_env == "production"

    @model_validator(mode="after")
    def _validate_secrets(self) -> "Settings":
        if len(self.jwt_secret) < 32:
            raise ValueError("JWT_SECRET must be set and at least 32 characters long")
        if self.app_env == "production":
            if self.jwt_secret.startswith(DEV_PLACEHOLDER_PREFIX):
                raise ValueError("JWT_SECRET is a development placeholder; refusing to start in production")
            if DEV_PLACEHOLDER_PREFIX in self.database_url:
                raise ValueError("DATABASE_URL contains a development placeholder password")
            if self.seed_demo_data:
                raise ValueError("SEED_DEMO_DATA must not be enabled in production")
            if not self.opensearch_verify_certs and self.opensearch_url.startswith("https"):
                raise ValueError("TLS verification for OpenSearch must stay enabled in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
