from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base, NetworkFlow
from .config import settings
from sqlalchemy.pool import NullPool
import logging
from sqlalchemy.sql import text

# Set up logging
logger = logging.getLogger(__name__)


engine = create_engine(settings.DB_URL, poolclass=NullPool)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        raise


def store_malicious_flow(flow_data):
    session = SessionLocal()
    try:
        # Create a new NetworkFlow instance
        flow = NetworkFlow(**flow_data)
        session.add(flow)
        session.commit()
        logger.info(f"Stored malicious flow with ID: {flow.id}")
        return flow.id
    except Exception as e:
        session.rollback()
        logger.error(f"Error storing malicious flow: {e}")
        raise
    finally:
        session.close()


def check_db_connection():
    try:
        session = SessionLocal()
        session.execute(text("SELECT 1"))
        session.close()
        return True
    except Exception as e:
        logger.error(f"Database connection check failed: {e}")
        return False