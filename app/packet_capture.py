from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time
import pandas as pd


class ConnectionStateExtractor:
    def __init__(self, timeout=120):
        self.flows = defaultdict(
            lambda: {
                "start_time": None,
                "last_time": None,
                "origin_bytes": 0,
                "destination_bytes": 0,
                "origin_packets": 0,
                "ip_bytes_origin": 0,
                "missed_bytes": 0,
                "state": "OTH",  # Default state
                "source_ip": None,
                "destination_ip": None,
                "syn_count": 0,
                "rst_count": 0,
                "ack_count": 0,
                "fin_count": 0,
            }
        )
        self.timeout = timeout

    def get_flow_key(self, pkt):
        if IP in pkt and (TCP in pkt or UDP in pkt):
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst

            if TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            else:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport

            # Create bidirectional flow key
            return (ip_src, sport, ip_dst, dport)
        return None

    def determine_connection_state(self, flow):
        """
        Determine connection state based on flag counts and connection progression
        S0: Connection attempt seen, no reply
        REJ: Connection rejected
        RSTO: Connection established, originator aborted
        SF: Normal establishment and termination
        OTH: No SYN seen, just midstream traffic
        RSTOS0: Originator sent a SYN followed by a RST
        RSTR: Established, responder aborted
        S1: Connection established, not terminated
        S2: Connection established and close attempt by originator seen
        S3: Connection established and close attempt by responder seen
        """
        if flow["syn_count"] == 0:
            return "OTH"

        if flow["syn_count"] == 1:
            if flow["rst_count"] > 0:
                return "RSTOS0" if flow["ack_count"] == 0 else "RSTO"
            if flow["ack_count"] == 0:
                return "S0"
            if flow["fin_count"] == 0:
                return "S1"
            return "SF"

        if flow["rst_count"] > 0:
            return "REJ" if flow["ack_count"] == 0 else "RSTR"

        if flow["fin_count"] > 0:
            if flow["fin_count"] == 1:
                return "S2" if flow["ack_count"] > 1 else "S3"
            return "SF"

        return "S1"

    def process_packet(self, pkt):
        flow_key = self.get_flow_key(pkt)
        if not flow_key:
            return

        current_time = time.time()
        flow = self.flows[flow_key]

        if flow["start_time"] is None:
            flow["start_time"] = current_time
            flow["source_ip"] = flow_key[0]
            flow["destination_ip"] = flow_key[2]

        # Determine packet direction and update counters
        is_origin = flow_key[0] == pkt[IP].src
        pkt_size = len(pkt)
        ip_size = len(pkt[IP])

        if is_origin:
            flow["origin_bytes"] += pkt_size
            flow["origin_packets"] += 1
            flow["ip_bytes_origin"] += ip_size
        else:
            flow["destination_bytes"] += pkt_size

        # Update TCP flags count
        if TCP in pkt:
            flags = pkt[TCP].flags
            if flags & 0x02:  # SYN
                flow["syn_count"] += 1
            if flags & 0x04:  # RST
                flow["rst_count"] += 1
            if flags & 0x10:  # ACK
                flow["ack_count"] += 1
            if flags & 0x01:  # FIN
                flow["fin_count"] += 1

        # Update missed bytes (retransmissions in TCP)
        if TCP in pkt and hasattr(pkt[TCP], "retrans"):
            flow["missed_bytes"] += pkt_size

        # Update connection state
        flow["state"] = self.determine_connection_state(flow)
        flow["last_time"] = current_time

    def extract_features(self, flow_key):
        flow = self.flows[flow_key]

        if not flow["start_time"] or not flow["last_time"]:
            return None

        features = {
            "origin_port": flow_key[1],
            "destination_port": flow_key[3],
            "connection_duration": flow["last_time"] - flow["start_time"],
            "bytes_sent_by_origin": flow["origin_bytes"],
            "bytes_sent_by_destination": flow["destination_bytes"],
            "connection_state": flow["state"],
            "missed_bytes_count": flow["missed_bytes"],
            "packets_sent_by_source": flow["origin_packets"],
            "source_ip": flow["source_ip"],
            "destination_ip": flow["destination_ip"],
            "ip_bytes_sent_by_source": flow["ip_bytes_origin"],
        }

        return features


def start_capture(interface="eth0", timeout=60, output_file="captured_flows.csv"):
    """
    Start capturing packets and extracting features.

    Args:
        interface (str): Network interface to capture packets from
        timeout (int): Duration to capture packets in seconds
        output_file (str): File to save the extracted features
    """
    print(f"Starting capture on interface {interface} for {timeout} seconds...")
    extractor = ConnectionStateExtractor()

    def packet_callback(pkt):
        extractor.process_packet(pkt)

    try:
        print("Initiating packet capture...")
        sniff(iface=interface, prn=packet_callback, timeout=timeout, store=0)
        print("Packet capture completed")
    except Exception as e:
        print(f"Error during packet capture: {e}")
        return

    # Extract features from all flows
    print("Processing captured flows...")
    all_features = []
    for flow_key in extractor.flows:
        features = extractor.extract_features(flow_key)
        if features:
            all_features.append(features)

    # Save to CSV file
    if all_features:
        df = pd.DataFrame(all_features)

        # Ensure correct column order
        expected_columns = [
            "origin_port",
            "destination_port",
            "connection_duration",
            "bytes_sent_by_origin",
            "bytes_sent_by_destination",
            "connection_state",
            "missed_bytes_count",
            "packets_sent_by_source",
            "source_ip",
            "destination_ip",
            "ip_bytes_sent_by_source",
        ]

        # Reorder columns to match dataset
        df = df[expected_columns]

        # Save to CSV
        # df.to_csv(output_file, index=False)
        # print(f"Saved {len(all_features)} flows to {output_file}")
    else:
        print("No flows captured during the monitoring period")
        print("Try running with sudo and ensure there is network activity")
