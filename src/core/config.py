"""
AegisFlow Platform — Production Configuration & Environment Validation
Author: Om Kamble

Validates required environment configurations at startup using Pydantic Settings.
Enforces security hygiene across development, testing, and production environments.
"""

import os
from typing import List, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Application Metadata
    APP_NAME: str = "AegisFlow Fraud Operations Platform"
    APP_VERSION: str = "v2.4-enterprise"
    ENVIRONMENT: str = Field(default="development", description="Environment: development, testing, production")
    DEBUG: bool = Field(default=False, description="Enable debug mode (disallowed in production)")

    # Server Configuration
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 4
    CORS_ORIGINS: List[str] = ["*"]

    # Security & Cryptography
    JWT_SECRET: str = Field(
        default="aegisflow-insecure-dev-secret-key-32chars-minimum!!",
        description="HMAC SHA-256 secret key for signing JWT tokens. Must be >= 32 characters in production."
    )
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Database Configuration (Supabase / Postgres / SQLite)
    DATABASE_URL: Optional[str] = Field(
        default=None,
        description="PostgreSQL / Supabase connection URL. If omitted, falls back to zero-setup SQLite."
    )
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20

    # Redis Feature Store & Velocity Engine
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: Optional[str] = None
    REDIS_DB: int = 0
    REDIS_SSL: bool = False

    # Financial Crime Engine Thresholds
    SLA_LATENCY_THRESHOLD_MS: float = 3.5
    FRAUD_BLOCK_THRESHOLD: float = 0.75
    FRAUD_CHALLENGE_THRESHOLD: float = 0.25
    MAX_VELOCITY_1M: int = 5
    MAX_VELOCITY_1H: int = 20

    # Rate Limiting & DoS Protection
    RATE_LIMIT_PER_MINUTE: int = 1200
    MAX_REQUEST_BODY_BYTES: int = 2 * 1024 * 1024  # 2MB default

    # Logging & Observability
    LOG_LEVEL: str = "INFO"
    STRUCTURED_LOGGING: bool = True
    MASK_PII_IN_LOGS: bool = True

    @field_validator("ENVIRONMENT")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        allowed = {"development", "testing", "staging", "production"}
        v_clean = v.lower().strip()
        if v_clean not in allowed:
            raise ValueError(f"ENVIRONMENT must be one of {allowed}, got '{v}'")
        return v_clean

    @field_validator("JWT_SECRET")
    @classmethod
    def validate_jwt_secret(cls, v: str, info) -> str:
        env = os.getenv("ENVIRONMENT", "development").lower().strip()
        if env == "production":
            if "insecure" in v.lower() or len(v) < 32:
                raise ValueError("In production, JWT_SECRET must be at least 32 characters and cannot contain insecure defaults.")
        return v

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def is_testing(self) -> bool:
        return self.ENVIRONMENT == "testing"


# Global singleton settings
settings = Settings()
