import os
from pydantic_settings import BaseSettings
from functools import lru_cache
from pathlib import Path
from dotenv import load_dotenv

# Get the root directory of the project
ROOT_DIR = Path(__file__).parent.parent

load_dotenv(dotenv_path=f"{ROOT_DIR}/.env")


class Settings(BaseSettings):
    USERNAME: str = os.getenv("DB_USERNAME", "postgres")
    PASSWORD: str = os.getenv("DB_PASSWORD", "password")
    HOST: str = os.getenv("DB_HOST", "aws-0-us-west-1.pooler.supabase.com")
    PORT: str = os.getenv("DB_PORT", "6543")
    DBNAME: str = os.getenv("DB_NAME", "postgres")
    DB_URL: str = f"postgresql+psycopg2://{USERNAME}:{PASSWORD}@{HOST}:{PORT}/{DBNAME}?sslmode=require"
    WEBSOCKET_PORT: int = int(os.getenv("WEBSOCKET_PORT", "8765"))

    class Config:
        env_file = str(ROOT_DIR / ".env")
        env_file_encoding = "utf-8"
        extra = "ignore"


@lru_cache
def get_settings():
    return Settings()


settings = get_settings()
