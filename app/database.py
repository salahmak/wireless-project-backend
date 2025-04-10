from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base, NetworkFlow, MaliciousSender
from .config import settings
from sqlalchemy.pool import NullPool
import logging
from sqlalchemy.sql import text
from datetime import datetime, timezone

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
        
        # If source IP exists in the flow data, track the malicious sender
        if "source_ip" in flow_data:
            track_malicious_sender(flow_data["source_ip"], flow_data.get("attack_type", "Unknown"))
        
        return flow.id
    except Exception as e:
        session.rollback()
        logger.error(f"Error storing malicious flow: {e}")
        raise
    finally:
        session.close()


def track_malicious_sender(ip_address, attack_type, block_threshold=settings.MALICIOUS_THRESHOLD):
    session = SessionLocal()
    try:
        # Check if we already have this sender
        sender = session.query(MaliciousSender).filter_by(ip_address=ip_address).first()
        
        if sender:
            # Update existing record
            sender.detection_count += 1
            sender.last_detection = datetime.now(timezone.utc)
            
            # Check if sender should be blocked
            if sender.detection_count >= block_threshold and not sender.is_blocked:
                block_ip(ip_address, sender)
                logger.warning(f"IP {ip_address} has been blocked after {sender.detection_count} malicious detections")
        else:
            # Create new record
            sender = MaliciousSender(
                ip_address=ip_address,
                detection_count=1,
                first_detection=datetime.now(timezone.utc),
                last_detection=datetime.now(timezone.utc)
            )
            session.add(sender)
            
        session.commit()
        return sender
    except Exception as e:
        session.rollback()
        logger.error(f"Error tracking malicious sender: {e}")
        raise
    finally:
        session.close()


def block_ip(ip_address, sender=None):
    """Block an IP address using iptables"""
    import subprocess
    
    if sender is None:
        session = SessionLocal()
        try:
            sender = session.query(MaliciousSender).filter_by(ip_address=ip_address).first()
            if not sender:
                logger.error(f"Cannot block IP {ip_address}: sender not found in database")
                return False
        finally:
            session.close()
    
    # Only proceed if sender is not already blocked
    if sender.is_blocked:
        return True
    
    # Execute iptables command to block the IP
    try:
        cmd = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True)
        
        # Update the database to mark the IP as blocked
        session = SessionLocal()
        try:
            sender = session.query(MaliciousSender).filter_by(ip_address=ip_address).first()
            if sender:
                sender.is_blocked = True
                sender.blocked_timestamp = datetime.now(timezone.utc)
                session.commit()
                logger.info(f"Successfully blocked IP {ip_address}")
                return True
        except Exception as e:
            session.rollback()
            logger.error(f"Error updating blocked status for IP {ip_address}: {e}")
            return False
        finally:
            session.close()
    
    except subprocess.CalledProcessError as e:
        logger.error(f"Error blocking IP {ip_address} with iptables: {e}")
        logger.error(f"Command output: {e.output}")
        return False


def unblock_ip(ip_address):
    """Unblock a previously blocked IP address"""
    import subprocess
    
    try:
        cmd = f"sudo iptables -D INPUT -s {ip_address} -j DROP"
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True)
        
        # Update the database to mark the IP as unblocked
        session = SessionLocal()
        try:
            sender = session.query(MaliciousSender).filter_by(ip_address=ip_address).first()
            if sender:
                sender.is_blocked = False
                sender.blocked_timestamp = None
                session.commit()
                logger.info(f"Successfully unblocked IP {ip_address}")
                return True
            return False
        except Exception as e:
            session.rollback()
            logger.error(f"Error updating unblocked status for IP {ip_address}: {e}")
            return False
        finally:
            session.close()
            
    except subprocess.CalledProcessError as e:
        logger.error(f"Error unblocking IP {ip_address} with iptables: {e}")
        return False


def get_blocked_ips():
    """Get a list of all currently blocked IPs"""
    session = SessionLocal()
    try:
        blocked_senders = session.query(MaliciousSender).filter_by(is_blocked=True).all()
        return [sender.ip_address for sender in blocked_senders]
    except Exception as e:
        logger.error(f"Error retrieving blocked IPs: {e}")
        return []
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