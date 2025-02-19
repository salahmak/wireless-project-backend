from sqlalchemy import Column, Integer, String, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class NetworkFlow(Base):
    __tablename__ = "network_flows"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime)
    origin_port = Column(Integer)
    destination_port = Column(Integer)
    connection_duration = Column(Float)
    bytes_sent_by_origin = Column(Integer)
    bytes_sent_by_destination = Column(Integer)
    connection_state = Column(String)
    missed_bytes_count = Column(Integer)
    packets_sent_by_source = Column(Integer)
    source_ip = Column(String)
    destination_ip = Column(String)
    ip_bytes_sent_by_source = Column(Integer)
    predicted_label = Column(String)
