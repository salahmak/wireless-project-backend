from sqlalchemy import Column, Integer, String, Float, DateTime, Enum
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime, timezone
import enum

Base = declarative_base()




class NetworkFlow(Base):
    __tablename__ = "network_flows"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.now(timezone.utc))
    
    # Connection details
    origin_port = Column(Integer)
    destination_port = Column(Integer)
    connection_duration = Column(Float)
    
    # Traffic metrics
    bytes_sent_by_origin = Column(Integer)
    bytes_sent_by_destination = Column(Integer)
    missed_bytes_count = Column(Integer)
    packets_sent_by_source = Column(Integer)
    ip_bytes_sent_by_source = Column(Integer)
    
    # Connection state
    connection_state = Column(Integer)
    
    # Raw data for reference
    raw_log_entry = Column(String)
    
    # Classification
    attack_type = Column(String, default="Benign")
    detection_timestamp = Column(DateTime, default=datetime.now(timezone.utc))
