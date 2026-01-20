from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import PostgresDsn, RedisDsn

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    PROJECT_NAME: str = "VectorGuard"
    API_V1_STR: str = "/api/v1"

    DATABASE_URL: PostgresDsn
    REDIS_URL: RedisDsn

    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days

    # ChromaDB settings
    CHROMA_PERSIST_DIRECTORY: str = "./chroma_data"

settings = Settings()
