import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://root:nopasswd@192.168.1.83:30432/postgres"
    SECRET_KEY: str = "so-trace-secret-key-change-in-production-2026"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    UPLOAD_DIR: str = "./uploads"

    model_config = {"env_file": ".env"}


settings = Settings()

os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
