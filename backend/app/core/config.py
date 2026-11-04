from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Base directory for the backend (where .env is located)
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    """Application settings loaded from environment variables or backend/.env file."""

    APP_NAME: str = "Project Sentinel API"
    APP_VERSION: str = "0.1.0"
    DATABASE_URL: str = ""
    TEST_DATABASE_URL: str = ""

    # JWT Authentication Configuration
    JWT_SECRET_KEY: str = ""
    JWT_ALGORITHM: str = Field(default="HS256", pattern="^HS256$")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, gt=0)

    model_config = SettingsConfigDict(
        env_file=BACKEND_DIR / ".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
