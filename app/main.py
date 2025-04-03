import os
import subprocess
import time
import argparse
from typing import Dict, List, Optional
from .classifier import NetworkFlowClassifier, COLUMNS
from .database import store_malicious_flow, init_db, check_db_connection
from .config import settings


# Constants
DEFAULT_INTERFACE = "wlan0"
DEFAULT_OUTPUT_DIR = "zeek_logs"
DEFAULT_LOG_PATH = "zeek_logs/conn.log"
DEFAULT_MODEL_PATH = "models/final_dt_model.pkl"


def check_zeek_installation() -> bool:
    """Check if Zeek is installed on the system."""
    result = subprocess.run(["which", "zeek"], capture_output=True, text=True)
    return bool(result.stdout.strip())


def install_zeek() -> None:
    """Install Zeek if it's not already installed."""
    if not check_zeek_installation():
        print("Zeek not found! Installing Zeek...")
        os.system("sudo apt update && sudo apt install -y zeek")
    else:
        print("Zeek is already installed.")


def start_zeek(
    interface: str = DEFAULT_INTERFACE, output_dir: str = DEFAULT_OUTPUT_DIR
) -> None:
    """Start Zeek on the specified interface."""
    print(f"Starting Zeek on interface {interface}...")
    os.makedirs(output_dir, exist_ok=True)
    command = f"sudo -S zeek -i {interface}"
    subprocess.Popen(command, shell=True, cwd=output_dir)
    print("Zeek is running...")


def wait_for_log_file(log_path: str, timeout: int = 60) -> bool:
    """Wait for the log file to be created."""
    start_time = time.time()
    while not os.path.exists(log_path):
        if time.time() - start_time > timeout:
            print(f"Timeout waiting for {log_path} to be created")
            return False
        print(f"Waiting for {log_path} to be created...")
        time.sleep(1)
    return True


def is_valid_line(line: str) -> bool:
    # line doesn't start with # and is not empty
    if not line.strip() or line.startswith("#"):
        return False
    return True


def has_valid_field_count(line: str) -> bool:
    fields = line.strip().split("\t")
    return len(fields) == len(COLUMNS)


def monitor_conn_log(
    classifier: NetworkFlowClassifier, log_path: str = DEFAULT_LOG_PATH
) -> None:
    """Monitor the connection log file for new entries and make predictions."""
    print(f"Starting to monitor {log_path} for new records...")

    if not wait_for_log_file(log_path):
        return

    file_position = os.path.getsize(log_path)
    print("Monitoring for new connections...")
    print("-" * 80)

    while True:
        current_size = os.path.getsize(log_path)
        if current_size > file_position:
            with open(log_path, "r") as f:
                f.seek(file_position)
                for line in f:
                    if not has_valid_field_count(line) or not is_valid_line(line):
                        pass

                    attack_type, flow_data = classifier.predict(line)
                    if attack_type != "Benign":
                        print(f"{attack_type.upper()} ATTACK DETECTED!")
                        try:
                            # Add raw log entry and attack type to flow data
                            flow_data["raw_log_entry"] = line.strip()
                            flow_data["attack_type"] = attack_type
                            # Store in database
                            store_malicious_flow(flow_data)
                        except Exception as e:
                            print(f"❌ Error storing attack in database: {e}")
                    else:
                        print("Normal flow. Record")
                file_position = f.tell()
        time.sleep(0.1)


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Network Intrusion Detection System")
    parser.add_argument(
        "-i",
        "--interface",
        default=DEFAULT_INTERFACE,
        help=f"Network interface to monitor (default: {DEFAULT_INTERFACE})",
    )
    parser.add_argument(
        "-m",
        "--model",
        default=DEFAULT_MODEL_PATH,
        help=f"Path to the trained model file (default: {DEFAULT_MODEL_PATH})",
    )
    return parser.parse_args()


def main() -> None:
    """Main function to run the network monitoring system."""
    # Parse command line arguments
    args = parse_arguments()

    # Initialize database
    try:
        init_db()
        if not check_db_connection():
            print("❌ Failed to connect to database. Exiting...")
            return
        print("✅ Database initialized successfully")
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        return

    # Initialize the classifier
    try:
        classifier = NetworkFlowClassifier(args.model)
    except Exception as e:
        print(f"❌ Error initializing classifier: {e}")
        return

    # Check and install Zeek if needed
    install_zeek()

    # Start Zeek on the specified interface
    start_zeek(interface=args.interface)

    # Give Zeek a moment to initialize
    print("Waiting for Zeek to initialize...")
    time.sleep(5)

    # Start monitoring the log file
    monitor_conn_log(classifier)


if __name__ == "__main__":
    main()
