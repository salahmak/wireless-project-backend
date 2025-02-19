import joblib
import pandas as pd
from sklearn.preprocessing import LabelEncoder


class NetworkClassifier:
    def __init__(self, model_path, scaler_path):
        self.model = joblib.load(model_path)
        self.label_encoder = LabelEncoder()
        self.scaler = joblib.load(scaler_path)
        self.feature_columns = [
            "origin_port",
            "destination_port",
            "connection_duration",
            "bytes_sent_by_origin",
            "bytes_sent_by_destination",
            "connection_state",
            "missed_bytes_count",
            "packets_sent_by_source",
            "ip_bytes_sent_by_source",
        ]

    def preprocess_flow(self, flow_data):
        df = pd.DataFrame([flow_data])
        # Encode categorical variables
        df["connection_state"] = self.label_encoder.fit_transform(
            df["connection_state"]
        )

        # Scale numerical features
        df[self.feature_columns] = self.scaler.transform(df[self.feature_columns])

        return df[self.feature_columns]

    def predict(self, flow_data):
        features = self.preprocess_flow(flow_data)
        prediction = self.model.predict(features)[0]
        return prediction
