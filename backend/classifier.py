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
            "src_port": "Src Port",
            "dst_port": "Dst Port",
            "protocol": "Protocol",
            "flow_duration": "Flow Duration",
            "tot_fwd_pkts": "Total Fwd Packets",
            "tot_bwd_pkts": "Total Backward Packets",
            "totlen_fwd_pkts": "Total Length of Fwd Packets",
            "totlen_bwd_pkts": "Total Length of Bwd Packets",
            "fwd_pkt_len_max": "Fwd Packet Length Max",
            "fwd_pkt_len_min": "Fwd Packet Length Min",
            "fwd_pkt_len_mean": "Fwd Packet Length Mean",
            "fwd_pkt_len_std": "Fwd Packet Length Std",
            "bwd_pkt_len_max": "Bwd Packet Length Max",
            "bwd_pkt_len_min": "Bwd Packet Length Min",
            "bwd_pkt_len_mean": "Bwd Packet Length Mean",
            "bwd_pkt_len_std": "Bwd Packet Length Std",
            "flow_byts_s": "Flow Bytes/s",
            "flow_pkts_s": "Flow Packets/s",
            "flow_iat_mean": "Flow IAT Mean",
            "flow_iat_std": "Flow IAT Std",
            "flow_iat_max": "Flow IAT Max",
            "flow_iat_min": "Flow IAT Min",
            "fwd_iat_tot": "Fwd IAT Total",
            "fwd_iat_mean": "Fwd IAT Mean",
            "fwd_iat_std": "Fwd IAT Std",
            "fwd_iat_max": "Fwd IAT Max",
            "fwd_iat_min": "Fwd IAT Min",
            "bwd_iat_tot": "Bwd IAT Total",
            "bwd_iat_mean": "Bwd IAT Mean",
            "bwd_iat_std": "Bwd IAT Std",
            "bwd_iat_max": "Bwd IAT Max",
            "bwd_iat_min": "Bwd IAT Min",
            "fwd_psh_flags": "Fwd PSH Flags",
            "bwd_psh_flags": "Bwd PSH Flags",
            "fwd_urg_flags": "Fwd URG Flags",
            "bwd_urg_flags": "Bwd URG Flags",
            "fwd_header_len": "Fwd Header Length",
            "bwd_header_len": "Bwd Header Length",
            "fwd_pkts_s": "Fwd Packets/s",
            "bwd_pkts_s": "Bwd Packets/s",
            "pkt_len_min": "Min Packet Length",
            "pkt_len_max": "Max Packet Length",
            "pkt_len_mean": "Packet Length Mean",
            "pkt_len_std": "Packet Length Std",
            "pkt_len_var": "Packet Length Variance",
            "fin_flag_cnt": "FIN Flag Count",
            "syn_flag_cnt": "SYN Flag Count",
            "rst_flag_cnt": "RST Flag Count",
            "psh_flag_cnt": "PSH Flag Count",
            "ack_flag_cnt": "ACK Flag Count",
            "urg_flag_cnt": "URG Flag Count",
            "cwr_flag_count": "CWR Flag Count",
            "ece_flag_cnt": "ECE Flag Count",
            "down_up_ratio": "Down/Up Ratio",
            "pkt_size_avg": "Average Packet Size",
            "fwd_seg_size_avg": "Avg Fwd Segment Size",
            "bwd_seg_size_avg": "Avg Bwd Segment Size",
            "fwd_byts_b_avg": "Fwd Avg Bytes/Bulk",
            "fwd_pkts_b_avg": "Fwd Avg Packets/Bulk",
            "fwd_blk_rate_avg": "Fwd Avg Bulk Rate",
            "bwd_byts_b_avg": "Bwd Avg Bytes/Bulk",
            "bwd_pkts_b_avg": "Bwd Avg Packets/Bulk",
            "bwd_blk_rate_avg": "Bwd Avg Bulk Rate",
            "subflow_fwd_pkts": "Subflow Fwd Packets",
            "subflow_fwd_byts": "Subflow Fwd Bytes",
            "subflow_bwd_pkts": "Subflow Bwd Packets",
            "subflow_bwd_byts": "Subflow Bwd Bytes",
            "init_fwd_win_byts": "Init_Win_bytes_forward",
            "init_bwd_win_byts": "Init_Win_bytes_backward",
            "fwd_act_data_pkts": "act_data_pkt_fwd",
            "fwd_seg_size_min": "min_seg_size_forward",
            "active_mean": "Active Mean",
            "active_std": "Active Std",
            "active_max": "Active Max",
            "active_min": "Active Min",
            "idle_mean": "Idle Mean",
            "idle_std": "Idle Std",
            "idle_max": "Idle Max",
            "idle_min": "Idle Min"
        }
        return {mapping.get(k, k): v for k, v in flow_dict.items()}

    def __init__(self):
        self.rf_model = None
        self.iso_forest = None
        self.le = LabelEncoder()
        self.is_trained = False
        self.SUSPICIOUS_LABELS = ["Portscan", "Infiltration", "Infiltration - Attempted", "Infiltration - Portscan"]
        self.MISCONFIGURED_LABELS = ["Dead Service", "TCP Handshake Anomaly", "Keep Alive Timeout", "Packet Size Anomaly"]
        
        self.cols_to_drop = ["Label", "Flow ID", "id", "Src IP", "Dst IP", "Timestamp", "Attempted Category", "Src Port"]

    def threat_category(self, label: str) -> str:
        if label == "BENIGN": return "Normal"
        elif label == "Anomaly": return "Anomaly"
        elif label in self.MISCONFIGURED_LABELS: return "Misconfigured"
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
            
            dest_port       = int(data.get('dst_port', 0))
            avg_packet_size = float(data.get('pkt_size_avg', 0))      
            fwd_packet_rate = float(data.get('fwd_pkts_s', 0))        
            ack_flag_count  = int(data.get('ack_flag_cnt', 0))
            packet_variance = float(data.get('bwd_pkt_len_std', 0))    
            max_idle_time   = float(data.get('flow_iat_max', 0))
            syn_flag_count  = int(data.get('syn_flag_cnt', 0))
            rst_flag_count  = int(data.get('rst_flag_cnt', 0))

            flow_pkts_s = float(data.get('flow_pkts_s', 0))
            pkt_len_max = float(data.get('pkt_len_max', 0))
            pkt_len_std = float(data.get('pkt_len_std', 0))

            if rst_flag_count >= 2 and flow_pkts_s < 10:
                return 'Dead Service'

            if syn_flag_count >= 3 and ack_flag_count == 0:
                if dest_port not in [80, 443, 21, 22]:
                    return 'TCP Handshake Anomaly'

            if max_idle_time > 60000000 and flow_pkts_s < 2:
                return 'Keep Alive Timeout'

            if pkt_len_max > 2500 and pkt_len_std > 1000:
                return 'Packet Size Anomaly'

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
        

    def predict_live(self, flow_dict, use_anomaly=True):
        if not self.is_trained: return "Unclassified", "Waiting"
        try:
            normalized_rule_data = {
                k.lower().replace(" ", "_"): v
                for k, v in flow_dict.items()
            }

            label = self.rule_based_check(normalized_rule_data)
            if label != 'BENIGN':
                return label, self.threat_category(label)

            expected_features = self.rf_model.feature_names_in_
            feature_map = self.normalize_keys(flow_dict)
            
            X_input = [float(feature_map.get(feat, 0) or 0) for feat in expected_features]
            X_input = np.array(X_input, dtype=np.float32)
            X_input[np.isinf(X_input)] = 0
            X_input[np.isnan(X_input)] = 0
            X_input = np.clip(X_input, -1e9, 1e9)
            X_input = X_input.reshape(1, -1)

            rf_pred_encoded = self.rf_model.predict(X_input)
            label = self.le.inverse_transform(rf_pred_encoded)[0]

            if use_anomaly and label == "BENIGN":
                iso_pred = self.iso_forest.predict(X_input)[0]

                if iso_pred == -1:
                    return "Anomaly", self.threat_category("Anomaly")

            return label, self.threat_category(label)
        
        except Exception as e:
            print(f"[ENGINE ERROR] Prediction failed cleanly: {e}")
            return "ML_Error", "Normal"