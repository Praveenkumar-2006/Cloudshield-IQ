"""
CloudShield IQ — Application Configuration
==========================================
All configuration is loaded from environment variables.
No secrets are hard-coded. No defaults expose production systems.

Uses Pydantic Settings for type-safe, validated configuration.
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_BASE_DIR = Path(__file__).resolve().parent.parent.parent  # Points to /backend


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.

    Required fields have no default and will raise a validation
    error on startup if not set. This is intentional — the
    application should not start with missing critical config.
    """

    model_config = SettingsConfigDict(
        env_file=(_BASE_DIR / ".env", ".env", "backend/.env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------ #
    # Application
    # ------------------------------------------------------------------ #
    APP_NAME: str = "CloudShield IQ"
    APP_ENV: Literal["development", "staging", "production"] = "development"
    DEBUG: bool = False

    # Never exposed externally; used for internal signing only
    SECRET_KEY: SecretStr = Field(..., min_length=32)

    # ------------------------------------------------------------------ #
    # Database
    # ------------------------------------------------------------------ #
    DATABASE_URL: SecretStr = Field(
        ...,
        description="Full async PostgreSQL DSN, e.g. postgresql+asyncpg://user:pass@host/db",
    )
    DATABASE_POOL_SIZE: int = Field(10, ge=1, le=50)
    DATABASE_MAX_OVERFLOW: int = Field(20, ge=0, le=100)

    # ------------------------------------------------------------------ #
    # JWT
    # ------------------------------------------------------------------ #
    JWT_SECRET_KEY: SecretStr = Field(..., min_length=32)
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(30, ge=5, le=1440)
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = Field(7, ge=1, le=90)

    # ------------------------------------------------------------------ #
    # CORS
    # ------------------------------------------------------------------ #
    CORS_ALLOWED_ORIGINS: list[str] = [
        "http://localhost:8000",
        "http://localhost:8001",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8000",
        "http://127.0.0.1:8001",
        "http://localhost:3000",
    ]

    # ------------------------------------------------------------------ #
    # File Upload
    # ------------------------------------------------------------------ #
    UPLOAD_DIR: Path = Path("./uploads")
    MAX_UPLOAD_SIZE_MB: int = Field(50, ge=1, le=500)
    ALLOWED_UPLOAD_EXTENSIONS: set[str] = {".csv", ".json"}

    @property
    def max_upload_size_bytes(self) -> int:
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    # ------------------------------------------------------------------ #
    # ML
    # ------------------------------------------------------------------ #
    MODEL_DIR: Path = Path("./ml/models")
    MODEL_VERSION: str = "v0.1.0"

    # ------------------------------------------------------------------ #
    # LLM (Optional — all fields can be empty/None to disable)
    # ------------------------------------------------------------------ #
    LLM_PROVIDER: str | None = None
    LLM_API_KEY: SecretStr | None = None
    LLM_MODEL: str | None = None
    LLM_MAX_TOKENS: int = Field(1000, ge=100, le=8000)

    @property
    def llm_enabled(self) -> bool:
        """LLM is only active when all three fields are configured."""
        return all([self.LLM_PROVIDER, self.LLM_API_KEY, self.LLM_MODEL])

    # ------------------------------------------------------------------ #
    # Logging
    # ------------------------------------------------------------------ #
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    LOG_FORMAT: Literal["json", "console"] = "json"

    # ------------------------------------------------------------------ #
    # Validators
    # ------------------------------------------------------------------ #
    @field_validator("CORS_ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: str | list[str]) -> list[str]:
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                import json
                return json.loads(v)
            return [x.strip() for x in v.split(",") if x.strip()]
        return v

    @field_validator("ALLOWED_UPLOAD_EXTENSIONS", mode="before")
    @classmethod
    def parse_upload_extensions(cls, v: str | set[str] | list[str]) -> set[str]:
        if isinstance(v, str):
            if v.startswith("[") or v.startswith("{"):
                import json
                return set(json.loads(v))
            return {x.strip() for x in v.split(",") if x.strip()}
        return set(v)

    @field_validator("UPLOAD_DIR", "MODEL_DIR", mode="before")
    @classmethod
    def resolve_path(cls, v: str | Path) -> Path:
        return Path(v).resolve()

    @model_validator(mode="after")
    def validate_production_settings(self) -> "Settings":
        if self.APP_ENV == "production":
            if self.DEBUG:
                raise ValueError("DEBUG must be False in production")
            if self.LOG_FORMAT != "json":
                raise ValueError("LOG_FORMAT must be 'json' in production")
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return the cached application settings singleton.

    Using lru_cache ensures settings are validated once at startup
    and reused across the application without repeated disk reads.
    """
    return Settings()
