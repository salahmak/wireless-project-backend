import os
from pydantic_settings import BaseSettings
from functools import lru_cache
from pathlib import Path
from dotenv import load_dotenv

# Get the root directory of the project
ROOT_DIR = Path(__file__).parent.parent

load_dotenv(dotenv_path=f"{ROOT_DIR}/.env")


class Settings(BaseSettings):
    USER: str = "postgres.bksvnmerdasmlbrwppgh"
    PASSWORD: str = os.getenv("PASSWORD", "47yjtJQHLzXMaDtQ")
    HOST: str = os.getenv("HOST", "aws-0-us-west-1.pooler.supabase.com")
    PORT: str = os.getenv("PORT", "6543")
    DBNAME: str = os.getenv("DBNAME", "postgres")
    DB_URL: str = f"postgresql+psycopg2://{USER}:{PASSWORD}@{HOST}:{PORT}/{DBNAME}?sslmode=require"
    MODEL_PATH: str = os.getenv("MODEL_PATH", "models/dt_model.pkl")
    SCALER_PATH: str = os.getenv("SCALER_PATH", "models/scaler.pkl")
    CAPTURE_INTERFACE: str = os.getenv("CAPTURE_INTERFACE", "enp58s0u1u1")
    WEBSOCKET_PORT: int = int(os.getenv("WEBSOCKET_PORT", "8765"))

    class Config:
        env_file = str(ROOT_DIR / ".env")
        env_file_encoding = "utf-8"
        extra = "ignore"


@lru_cache
def get_settings():
    return Settings()


settings = get_settings()
