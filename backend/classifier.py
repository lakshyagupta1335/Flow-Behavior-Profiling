import pandas as pd
import numpy as np
import joblib
import os
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import IsolationForest, RandomForestClassifier
import warnings

warnings.filterwarnings('ignore')

from synthetic_flow import get_synthetic_flows

class RealTimeClassifier:

    def normalize_keys(self, flow_dict):
        mapping = {
            "avg_packet_size": "Pkt Size Avg",
            "fwd_packets_s": "Fwd Pkts S",
            "bwd_packet_length_std": "Bwd Packet Length Std",
            "flow_iat_max": "Flow Iat Max",
            "flow_iat_min": "Flow Iat Min",
            "flow_iat_mean": "Flow Iat Mean",

            "ack_flag_count": "Ack Flag Cnt",
            "syn_flag_count": "Syn Flag Cnt",
            "rst_flag_count": "Rst Flag Cnt",

            "dst_port": "Dst Port",

            "flow_byts_s": "Flow Byts S",
            "flow_pkts_s": "Flow Pkts S",

            "pkt_len_max": "Pkt Len Max",
            "pkt_len_min": "Pkt Len Min",
            "pkt_len_mean": "Pkt Len Mean",
            "pkt_len_std": "Pkt Len Std",
            "pkt_len_var": "Pkt Len Var",
        }

        return {
            mapping.get(k, k): v for k, v in flow_dict.items()
        }

    def __init__(self):
        self.rf_model = None
        self.iso_forest = None
        self.le = LabelEncoder()
        self.is_trained = False
        self.SUSPICIOUS_LABELS = ["Portscan", "Infiltration", "Infiltration - Attempted", "Infiltration - Portscan"]
        self.cols_to_drop = ["Label", "Flow ID", "id", "Src IP", "Dst IP", "Timestamp", "Attempted Category", "Src Port"]

    def threat_category(self, label: str) -> str:
        if label == "BENIGN": return "Normal"
        elif label == "Anomaly": return "Anomaly"
        elif label in self.SUSPICIOUS_LABELS or "Attempted" in label: return "Suspicious"
        else: return "Attack-like"

    def load_bundle(self):
        try:
            if os.path.exists('models/rf_model.pkl'):
                self.rf_model = joblib.load('models/rf_model.pkl')
                self.iso_forest = joblib.load('models/iso_model.pkl')
                self.le = joblib.load('models/label_encoder.pkl')
                self.is_trained = True
                print("[ENGINE] Hybrid ML models loaded.")
                return True
            return False
        except Exception as e:
            print(f"[ENGINE ERROR] Load failed: {e}")
            return False

    def rule_based_check(self, data):

        try:
            dest_port = int(data.get('dst_port', 0))
            avg_packet_size = float(data.get('avg_packet_size', 0))
            fwd_packet_rate = float(data.get('fwd_packets_s', 0))
            ack_flag_count = int(data.get('ack_flag_count', 0))
            packet_variance = float(data.get('bwd_packet_length_std', 0))
            max_idle_time = float(data.get('flow_iat_max', 0))
            syn_flag_count = int(data.get('syn_flag_count', 0))
            rst_flag_count = int(data.get('rst_flag_count', 0))

            

            if ack_flag_count > 4000:
                return 'Heartbleed'

            if dest_port == 21:
                if avg_packet_size <= 5:
                    return 'FTP-Patator - Attempted'
                else:
                    return 'FTP-Patator'
            
            if dest_port == 22:
                if avg_packet_size <= 5:
                    return 'SSH-Patator - Attempted'
                else:
                    return 'SSH-Patator'
            
            if dest_port == 8080:
                if avg_packet_size <= 5:
                    return 'Botnet - Attempted'
                else:
                    return 'Botnet'

            if avg_packet_size <= 5:
                if fwd_packet_rate > 10000:
                    if syn_flag_count == 2:
                        return 'Infiltration - Portscan'
                    else:
                        return 'Portscan'
                
                if fwd_packet_rate > 200:
                    if rst_flag_count >= 1:
                        return 'Infiltration - Attempted'
                    else:
                        return 'DoS GoldenEye - Attempted'
                
                if syn_flag_count >= 7:
                    return 'DoS Slowhttptest - Attempted'
                    
                if syn_flag_count == 3:
                    if ack_flag_count == 0:
                        return 'DoS Slowloris - Attempted'
                    else:
                        return 'DoS Hulk - Attempted'
                    
                if syn_flag_count == 2:
                    if max_idle_time > 5300000:
                        return 'Web Attack - Brute Force - Attempted'
                    elif max_idle_time > 5000000:
                        return 'Web Attack - XSS - Attempted'
                    else:
                        return 'Web Attack - SQL Injection - Attempted'
                    
                return 'BENIGN'

            if packet_variance == 0 and avg_packet_size > 5:
                if max_idle_time > 80000000:
                    return 'DoS Slowhttptest'
                elif max_idle_time > 40000000:
                    return 'DoS Slowloris'
                elif max_idle_time > 20000000:
                    return 'Infiltration'

            if dest_port in [80, 443]:
                if ack_flag_count > 150:
                    if avg_packet_size > 600:
                        return 'Web Attack - XSS'
                    else:
                        return 'Web Attack - Brute Force'
                
                if 200 < avg_packet_size < 300 and packet_variance > 800:
                    if ack_flag_count >= 10:
                        return 'Web Attack - SQL Injection - Attempted'
                    else:
                        return 'Web Attack - SQL Injection'

            if avg_packet_size > 600 and packet_variance > 1500:
                if max_idle_time < 500000:
                    return 'DoS Hulk'
                else:
                    if packet_variance > 3000:
                        return 'DDoS'
                    else:
                        return 'DoS GoldenEye'

            return 'BENIGN'

            

        except:
            return "BENIGN"
 

    def train_from_dataframe(self, df):
        df.columns = df.columns.str.strip()

        benign_df = df[df['Label'].str.strip() == 'BENIGN']
        attack_df = df[df['Label'].str.strip() != 'BENIGN']

        benign_sample = benign_df.sample(n=min(100000, len(benign_df)), random_state=42)
        balanced_df = pd.concat([benign_sample, attack_df])

        numeric_cols = balanced_df.select_dtypes(include=[np.number]).columns
        balanced_df[numeric_cols] = balanced_df[numeric_cols].replace([np.inf, -np.inf], np.nan)
        balanced_df.dropna(inplace=True)

        self.le.fit(balanced_df["Label"].str.strip())
        y_encoded = self.le.transform(balanced_df["Label"].str.strip())

        X = balanced_df.drop(columns=[c for c in self.cols_to_drop if c in balanced_df.columns])

        self.rf_model = RandomForestClassifier(
            n_estimators=100,
            n_jobs=-1,
            class_weight="balanced",
            random_state=42
        )
        self.rf_model.fit(X, y_encoded)

        benign_only_df = df[df['Label'].str.strip() == 'BENIGN']

        numeric_cols = benign_only_df.select_dtypes(include=[np.number]).columns
        benign_only_df[numeric_cols] = benign_only_df[numeric_cols].replace([np.inf, -np.inf], np.nan)
        benign_only_df.dropna(inplace=True)

        X_benign_only = benign_only_df.drop(columns=[c for c in self.cols_to_drop if c in benign_only_df.columns])

        self.iso_forest = IsolationForest(
            n_estimators=100,
            contamination=0.005,
            random_state=42,
            n_jobs=-1
        )

        self.iso_forest.fit(X_benign_only)

        self.is_trained = True
        

    def predict_live(self, flow_dict):
        if not self.is_trained: return "Unclassified", "Waiting"
        try:
            # Rule Based Check
            label = self.rule_based_check(flow_dict)
            if label != 'BENIGN':
                return label, self.threat_category(label)

            # ML Model
            expected_features = self.rf_model.feature_names_in_

            flow_dict = self.normalize_keys(flow_dict)
            feature_map = {col.replace('_', ' ').title().strip(): val for col, val in flow_dict.items()}
            
            X_input = [float(feature_map.get(feat, 0)) for feat in expected_features]
            X_input = np.array(X_input).reshape(1, -1)

            rf_pred_encoded = self.rf_model.predict(X_input)
            label = self.le.inverse_transform(rf_pred_encoded)[0]

            if label == "BENIGN":
                iso_pred = self.iso_forest.predict(X_input)[0]
                if iso_pred == -1:
                    return "Anomaly", self.threat_category("Anomaly")

            return label, self.threat_category(label)
        
        except Exception as e:
            return "ML_Error", "Normal"
