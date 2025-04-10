import os
import subprocess
import time
import pandas as pd
from joblib import load
columns = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state",
    "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts",
    "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents"
]


def install_zeek():
    print("Checking if Zeek is installed...")
    result = subprocess.run(["which", "zeek"], capture_output=True, text=True)
    if not result.stdout.strip():
        print("Zeek not found! Installing Zeek...")
        os.system("sudo apt update && sudo apt install -y zeek")
    else:
        print("Zeek is already installed.")

def start_zeek(interface="wlp1s0", output_dir="zeek_logs"):  
    print(f"Starting Zeek on interface {interface}...")
    os.makedirs(output_dir, exist_ok=True)
    command = f"echo billal | sudo -S zeek -i {interface}"
    subprocess.Popen(command, shell=True, cwd=output_dir)
    print("Zeek is running...")

def monitor_conn_log(log_path="zeek_logs/conn.log"):
    print(f"Starting to monitor {log_path} for new records...")
    
    # Wait for the log file to be created
    while not os.path.exists(log_path):
        print(f"Waiting for {log_path} to be created...")
        time.sleep(1)
    
    # Start from the end of the file
    file_position = os.path.getsize(log_path)
    
    print("Monitoring for new connections...")
    print("-" * 80)
    
    while True:
        # Check if file has been updated
        current_size = os.path.getsize(log_path)
        
        if current_size > file_position:
            with open(log_path, 'r') as f:
                # Move to the last position we read
                f.seek(file_position)
                
                # Read new lines
                for line in f:
                    if not line.startswith('#') and line.strip():  # Skip headers and empty lines
                        fields = line.strip().split("\t")
                        print(f"len(columns): {len(columns)}")
                        print(f"len(fields): {len(fields)}")


                        print(f"columns: {columns}")
                        print("-" * 80)
                        print(f"fields: {fields}")
                        if len(columns) == len(fields):
                            entry = pd.DataFrame([fields], columns=columns)
                            expected_cols = {
                                "id.orig_p": "origin_port",
                                "id.resp_p": "destination_port",
                                "duration": "connection_duration",
                                "orig_bytes": "bytes_sent_by_origin",
                                "resp_bytes": "bytes_sent_by_destination",
                                "conn_state": "connection_state",
                                "missed_bytes": "missed_bytes_count",
                                "orig_pkts": "packets_sent_by_source",
                                "orig_ip_bytes": "ip_bytes_sent_by_source"
                            }

                            missing_cols = [col for col in expected_cols.keys() if col not in entry.columns]
                            if missing_cols:
                                raise ValueError(f"Missing columns: {missing_cols}")

                            # Rename and drop categorical columns
                            df_selected = entry[list(expected_cols.keys())].rename(columns=expected_cols)

                            # Convert connection_state to numerical values
                            state_mapping = {'S0': 0, 'REJ': 1, 'RSTO': 2, 'SF': 3, 'OTH': 4, 'RSTOS0': 5, 
                                            'RSTR': 6, 'S1': 7, 'S2': 8, 'S3': 9, 'SH': 10, 'SHR': 11, 'RSTRH': 12}
                            df_selected["connection_state"] = df_selected["connection_state"].map(state_mapping)

                            # Convert non-numeric '-' to NaN, then fill with -1
                            for col in df_selected.columns:
                                df_selected[col] = pd.to_numeric(df_selected[col], errors='coerce').fillna(-1)

                            # Load model and scaler
                            model = load("models/final_dt_model.pkl")
                            predictions = model.predict(df_selected)
                            print("Intrusion Prediction:", predictions, "For record:", line.strip())

                            
                           

                
                # Update position
                file_position = f.tell()
        
        # Short sleep to prevent high CPU usage
        time.sleep(0.1)

if __name__ == "__main__":
    # Check and install Zeek if needed
    install_zeek()
    
    # Start Zeek on the specified interface
    start_zeek(interface="wlan0")
    
    # Give Zeek a moment to initialize
    print("Waiting for Zeek to initialize...")
    time.sleep(5)
    
    # Start monitoring the log file
    monitor_conn_log()