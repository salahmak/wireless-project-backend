import asyncio
import logging
from datetime import datetime
from app.packet_capture import ConnectionStateExtractor
from app.ml_classifier import NetworkClassifier
from app.database import init_db, store_malicious_flow, check_db_connection
from app.websocket_server import AlertWebsocketServer
from app.config import settings
from scapy.all import sniff
import queue
import threading

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NetworkMonitor:
    def __init__(self):
        self.extractor = ConnectionStateExtractor()
        self.classifier = NetworkClassifier(settings.MODEL_PATH, settings.SCALER_PATH)
        self.websocket_server = AlertWebsocketServer()
        self.alert_queue = queue.Queue()
        self.running = True

    def process_packet(self, pkt):
        try:
            self.extractor.process_packet(pkt)

            # Check if we have a complete flow
            for flow_key in self.extractor.flows:
                features = self.extractor.extract_features(flow_key)
                if features:
                    prediction = self.classifier.predict(features)

                    if prediction != "Benign":
                        # Store in database
                        flow_data = {
                            **features,
                            "predicted_label": prediction,
                            "timestamp": datetime.now(),
                        }
                        try:
                            flow_id = store_malicious_flow(flow_data)

                            # Put alert in queue instead of directly creating task
                            alert_data = {
                                "flow_id": flow_id,
                                "timestamp": flow_data["timestamp"].isoformat(),
                                "source_ip": features["source_ip"],
                                "destination_ip": features["destination_ip"],
                                "predicted_label": prediction,
                            }
                            self.alert_queue.put(alert_data)

                        except Exception as e:
                            logger.error(f"Error storing malicious flow: {e}")
                            continue

        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            return

    async def process_alerts(self):
        """Process alerts from the queue and send them via websocket"""
        while self.running:
            try:
                # Check queue for new alerts
                while not self.alert_queue.empty():
                    alert_data = self.alert_queue.get_nowait()
                    await self.websocket_server.broadcast_alert(alert_data)
                    self.alert_queue.task_done()

                # Sleep briefly to prevent busy waiting
                await asyncio.sleep(0.1)

            except Exception as e:
                logger.error(f"Error processing alerts: {e}")
                await asyncio.sleep(1)  # Wait longer on error

    def start_packet_capture(self):
        """Start packet capture in a separate thread"""
        try:
            sniff(iface=settings.CAPTURE_INTERFACE, prn=self.process_packet, store=0)
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
            self.running = False

    async def start(self):
        # Check database connection
        if not check_db_connection():
            logger.error(
                "Unable to connect to database. Please check your database configuration."
            )
            return

        try:
            # Initialize database
            init_db()

            # Start websocket server
            websocket_task = asyncio.create_task(self.websocket_server.start_server())

            # Start alert processing
            alert_task = asyncio.create_task(self.process_alerts())

            # Start packet capture in a separate thread
            capture_thread = threading.Thread(
                target=self.start_packet_capture, daemon=True
            )
            capture_thread.start()

            # Wait for tasks to complete
            await asyncio.gather(websocket_task, alert_task)

        except Exception as e:
            logger.error(f"Error in main loop: {e}")
            self.running = False
            raise
        finally:
            self.running = False
            logger.info("Shutting down...")


if __name__ == "__main__":
    monitor = NetworkMonitor()
    try:
        asyncio.run(monitor.start())
    except KeyboardInterrupt:
        print("Shutting down gracefully...")
    except Exception as e:
        print(f"Fatal error: {e}")
