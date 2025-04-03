import pandas as pd
from joblib import load
from typing import Optional, Tuple, Dict

# Column definitions
COLUMNS = [
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "local_orig",
    "local_resp",
    "missed_bytes",
    "history",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
    "tunnel_parents",
]

# Column mapping for feature selection
COLUMN_MAPPING = {
    "id.orig_p": "origin_port",
    "id.resp_p": "destination_port",
    "duration": "connection_duration",
    "orig_bytes": "bytes_sent_by_origin",
    "resp_bytes": "bytes_sent_by_destination",
    "conn_state": "connection_state",
    "missed_bytes": "missed_bytes_count",
    "orig_pkts": "packets_sent_by_source",
    "orig_ip_bytes": "ip_bytes_sent_by_source",
}

# Connection state mapping
STATE_MAPPING = {
    "S0": 0,
    "REJ": 1,
    "RSTO": 2,
    "SF": 3,
    "OTH": 4,
    "RSTOS0": 5,
    "RSTR": 6,
    "S1": 7,
    "S2": 8,
    "S3": 9,
    "SH": 10,
    "SHR": 11,
    "RSTRH": 12,
}


class NetworkFlowClassifier:
    """Class for classifying network flows using a trained model."""

    def __init__(self, model_path: str):
        """Initialize the classifier with a trained model."""
        self.model = load(model_path)
        print(f"Successfully loaded model from {model_path}")

    def _process_log_entry(self, line: str) -> Optional[pd.DataFrame]:
        """Process a single log entry and prepare it for prediction."""
        fields = line.strip().split("\t")

        entry = pd.DataFrame([fields], columns=COLUMNS)

        # Verify all required columns exist
        missing_cols = [
            col for col in COLUMN_MAPPING.keys() if col not in entry.columns
        ]
        if missing_cols:
            raise ValueError(f"Missing columns: {missing_cols}")

        # Select and rename columns
        df_selected = entry[list(COLUMN_MAPPING.keys())].rename(columns=COLUMN_MAPPING)

        # Convert connection state to numerical values
        df_selected["connection_state"] = df_selected["connection_state"].map(
            STATE_MAPPING
        )

        # Convert non-numeric values to -1
        for col in df_selected.columns:
            df_selected[col] = pd.to_numeric(df_selected[col], errors="coerce").fillna(
                -1
            )

        return df_selected

    def predict(self, log_entry: str) -> Tuple[str, Dict]:
        """
        Predict the type of network flow.

        Args:
            log_entry: A string containing the log entry to classify

        Returns:
            Tuple containing:
            - AttackType: The predicted type of attack (or NORMAL)
            - Dict: The processed flow data for database storage
        """
        try:
            df_selected = self._process_log_entry(log_entry)
            if df_selected is not None:
                attack_type = self.model.predict(df_selected)[0]

                # Convert DataFrame to dict for database storage
                flow_data = df_selected.iloc[0].to_dict()
                return attack_type, flow_data
            return "Benign", {}
        except Exception as e:
            print(f"Error processing log entry: {e}")
            return "Unknown", {}
