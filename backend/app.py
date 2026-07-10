import os
import sys
import gevent
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import time
import threading
from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from flask_cors import CORS
import random

from synthetic_flow import get_synthetic_flows
from classifier import RealTimeClassifier

import sniffer_service

synthetic_pool = get_synthetic_flows()

from metrics_calculator import MetricsCalculator
metrics_calculator = MetricsCalculator()

from client_insights import ClientInsights
client_insights = ClientInsights()
from csv_upload import register_csv_routes

import re
import platform
import subprocess
import ipaddress
import requests as req_lib
from manuf import manuf as manuf_lib
import google.generativeai as genai
from dotenv import load_dotenv      
load_dotenv()

PORT_MAP = {
    "80": "HTTP", "443": "HTTPS", "22": "SSH", "21": "FTP",
    "23": "Telnet", "25": "SMTP", "53": "DNS", "3389": "RDP",
    "3306": "MySQL", "5432": "PostgreSQL", "27017": "MongoDB",
    "445": "SMB", "139": "NetBIOS", "8080": "HTTP-Alt",
    "1433": "MSSQL", "5900": "VNC", "6379": "Redis"
}

try:
    mac_parser = manuf_lib.MacParser()
except Exception as e:
    print(f"[WARNING] MAC OUI parser failed to load: {e}")
    mac_parser = None

_ip_cache  = {}   
_mac_cache = {}   

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False

def get_mac_from_ip(ip):
    if ip in _mac_cache:
        return _mac_cache[ip]
    try:
        if platform.system() == "Windows":
            result = subprocess.run(["arp", "-a", ip], capture_output=True, text=True)
        else:
            result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True)
        match = re.search(r'([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}', result.stdout)
        mac = match.group(0) if match else None
    except:
        mac = None
    _mac_cache[ip] = mac
    return mac

def get_vendor_from_mac(mac):
    if mac_parser is None:
        return "Unknown Device"
    try:
        vendor = mac_parser.get_manuf(mac)
        return vendor if vendor else "Unknown Device"
    except:
        return "Unknown Device"

def get_ip_geo(ip):
    if ip in _ip_cache:
        return _ip_cache[ip]
    try:
        res = req_lib.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,isp,org",
            timeout=3
        )
        data = res.json()
        if data.get("status") == "success":
            info = f"{data.get('country', '?')} — {data.get('isp', data.get('org', 'Unknown ISP'))}"
            _ip_cache[ip] = info
            return info
        else:
            return "External — location unavailable"
    except:
        return "External — location unavailable"

def get_service(port):
    return PORT_MAP.get(str(port), f"Port {port}")

def enrich_ip(ip, alias_map):
    if is_private_ip(ip):
        mac     = get_mac_from_ip(ip)
        vendor  = get_vendor_from_mac(mac) if mac else "Unknown Device"
        if ip not in alias_map:
            alias_map[ip] = f"Host_{chr(65 + len(alias_map))}"
        return f"{alias_map[ip]} [Internal — {vendor}]"
    else:
        return f"{ip} [External — {get_ip_geo(ip)}]"


ENABLE_SYNTHETIC = True   # True = enable simulation, False = real-only mode

is_capturing = False
last_pos = 0  

session_state = {
    "start_time": None,

    "packet_size_sum": 0.0,
    "throughput_sum": 0.0,
    "upload_sum": 0.0,
    "download_sum": 0.0,
    "packet_rate_sum": 0.0,

    "flow_duration_sum": 0.0,

    "flow_count": 0,
    "inbound_count": 0,
    "outbound_count": 0,
    "balanced_count": 0
}

LIVE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "live_flows.csv")
engine = RealTimeClassifier()
file_lock = threading.Lock()

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", transports=['websocket'], async_mode='gevent')
register_csv_routes(app, socketio)

def inject_synthetic(batch):
    global is_capturing, session_state

    if not ENABLE_SYNTHETIC:
        return batch

    if not is_capturing:
        return batch

    if random.random() < 0.5:
        label, flow = random.choice(synthetic_pool)
        pred, category = engine.predict_live(flow)

        metrics = metrics_calculator.compute(flow)

        insights = client_insights.compute(flow, category)

        if metrics:
            session_state["packet_size_sum"] += metrics["avg_packet_size"]

            session_state["throughput_sum"] += metrics["throughput_mbps"]
            session_state["upload_sum"] += metrics["upload_mbps"]
            session_state["download_sum"] += metrics["download_mbps"]
            session_state["packet_rate_sum"] += metrics["packet_rate_pps"]

            session_state["flow_duration_sum"] += metrics["flow_duration_ms"] 

            session_state["flow_count"] += 1

            if metrics["direction"] == "Inbound Heavy":
                session_state["inbound_count"] += 1
            elif metrics["direction"] == "Outbound Heavy":
                session_state["outbound_count"] += 1
            else:
                session_state["balanced_count"] += 1
        else:
            session_state["flow_count"] += 1
            session_state["balanced_count"] += 1

        batch.append({      
            'Src IP': flow.get('src_ip', 'N/A'),
            'Dst IP': flow.get('dst_ip', 'N/A'),
            'Src Port': flow.get('src_port', 0),
            'Dst Port': flow.get('dst_port', 0),
            'Predicted Label': pred,
            'Predicted Category': category,
            'Source': 'synthetic',
            'Client Insights': insights,
            'Throughput (Mbps)': round(metrics["throughput_mbps"], 2) if metrics else 0,
            'Upload (Mbps)': round(metrics["upload_mbps"], 2) if metrics else 0,
            'Download (Mbps)': round(metrics["download_mbps"], 2) if metrics else 0,
            'Flow Duration (ms)': round(metrics["flow_duration_ms"], 2) if metrics else 0,
            'Packet Rate (pps)': round(metrics["packet_rate_pps"], 2) if metrics else 0,
            'Avg Packet Size': round(metrics["avg_packet_size"], 2) if metrics else 0,
            'Protocol': metrics["protocol_category"] if metrics else 'OTHER',
            'Direction': metrics["direction"] if metrics else 'Balanced',
            'Bytes': metrics["raw_total_bytes"] if metrics else 0,
        })

    return batch

def continuous_metrics_emitter():
    global is_capturing, session_state
    print("[SYSTEM] Session Performance Engine Active...")

    while True:
        if not is_capturing or session_state["start_time"] is None or session_state["flow_count"] == 0:
            gevent.sleep(1.0)
            continue

        count = max(session_state["flow_count"], 1)

        
        avg_throughput = session_state["throughput_sum"] / count
        avg_upload = session_state["upload_sum"] / count
        avg_download = session_state["download_sum"] / count
        avg_packet_size = session_state["packet_size_sum"] / count
        avg_packet_rate = session_state["packet_rate_sum"] / count
        avg_duration = session_state["flow_duration_sum"] / count

        summary_payload = {
            "avg_throughput_mbps": round(avg_throughput, 2),
            "avg_upload_mbps": round(avg_upload, 2),
            "avg_download_mbps": round(avg_download, 2),

            "avg_packet_size": round(avg_packet_size, 2),
            "avg_packet_rate_pps": round(avg_packet_rate, 2),
            "avg_flow_duration": round(avg_duration, 2),

            "flows": session_state["flow_count"],
            "inbound": session_state["inbound_count"],
            "outbound": session_state["outbound_count"],
            "balanced": session_state["balanced_count"]
        }

        socketio.emit('network_metrics_summary', summary_payload)
        gevent.sleep(1.0)


def file_watcher():
    global is_capturing, session_state, last_pos

    if not engine.load_bundle():
        return

    last_pos = 0

    
    headers = [
        "src_ip","dst_ip","src_port","dst_port","protocol","timestamp",
        "flow_duration","flow_byts_s","flow_pkts_s","fwd_pkts_s","bwd_pkts_s",
        "tot_fwd_pkts","tot_bwd_pkts","totlen_fwd_pkts","totlen_bwd_pkts",
        "fwd_pkt_len_max","fwd_pkt_len_min","fwd_pkt_len_mean","fwd_pkt_len_std",
        "bwd_pkt_len_max","bwd_pkt_len_min","bwd_pkt_len_mean","bwd_pkt_len_std",
        "pkt_len_max","pkt_len_min","pkt_len_mean","pkt_len_std","pkt_len_var",
        "fwd_header_len","bwd_header_len","fwd_seg_size_min","fwd_act_data_pkts",
        "flow_iat_mean","flow_iat_max","flow_iat_min","flow_iat_std",
        "fwd_iat_tot","fwd_iat_max","fwd_iat_min","fwd_iat_mean","fwd_iat_std",
        "bwd_iat_tot","bwd_iat_max","bwd_iat_min","bwd_iat_mean","bwd_iat_std",
        "fwd_psh_flags","bwd_psh_flags","fwd_urg_flags","bwd_urg_flags",
        "fin_flag_cnt","syn_flag_cnt","rst_flag_cnt","psh_flag_cnt","ack_flag_cnt",
        "urg_flag_cnt","ece_flag_cnt","down_up_ratio","pkt_size_avg",
        "init_fwd_win_byts","init_bwd_win_byts",
        "active_max","active_min","active_mean","active_std",
        "idle_max","idle_min","idle_mean","idle_std",
        "fwd_byts_b_avg","fwd_pkts_b_avg","bwd_byts_b_avg","bwd_pkts_b_avg",
        "fwd_blk_rate_avg","bwd_blk_rate_avg",
        "fwd_seg_size_avg","bwd_seg_size_avg",
        "cwr_flag_count",
        "subflow_fwd_pkts","subflow_bwd_pkts","subflow_fwd_byts","subflow_bwd_byts"
    ]

    while True:
        if not is_capturing or not os.path.exists(LIVE_FILE):
            last_pos = 0
            gevent.sleep(1)
            continue

        lines = []

        with file_lock:
            try:
                current_size = os.path.getsize(LIVE_FILE)

                if current_size < last_pos:
                    last_pos = 0
                    continue

                if current_size < 100:
                    continue

                with open(LIVE_FILE, "r", encoding='utf-8', errors='ignore') as f:
                    f.seek(last_pos)
                    lines = f.readlines()
                    last_pos = f.tell()

            except Exception:
                continue

        if lines:
            batch = []

            for line in lines:
                if not line.strip() or "src_ip" in line.lower() or "dst_ip" in line.lower():
                    continue

                parts = line.strip().split(',')

                if len(parts) < len(headers):
                    continue

                try:
                    
                    raw_data = dict(zip(headers, parts))
                    label, category = engine.predict_live(raw_data)

                    metrics = metrics_calculator.compute(raw_data)
                    insights = client_insights.compute(raw_data, category)

                    if metrics:
                        session_state["packet_size_sum"] += metrics["avg_packet_size"]
                        session_state["throughput_sum"] += metrics["throughput_mbps"]
                        session_state["upload_sum"] += metrics["upload_mbps"]
                        session_state["download_sum"] += metrics["download_mbps"]
                        session_state["packet_rate_sum"] += metrics["packet_rate_pps"]
                        session_state["flow_duration_sum"] += metrics["flow_duration_ms"] 

                        session_state["flow_count"] += 1

                        if metrics["direction"] == "Inbound Heavy":
                            session_state["inbound_count"] += 1
                        elif metrics["direction"] == "Outbound Heavy":
                            session_state["outbound_count"] += 1
                        else:
                            session_state["balanced_count"] += 1

                    batch_item = {
                        'Src IP': raw_data.get('src_ip', 'N/A'),
                        'Dst IP': raw_data.get('dst_ip', 'N/A'),
                        'Src Port': raw_data.get('src_port', 'N/A'),
                        'Dst Port': raw_data.get('dst_port', 'N/A'),
                        'Predicted Label': label,
                        'Predicted Category': category,
                        'Source': 'real',
                        'Client Insights': insights
                    }

                    if metrics:
                        batch_item.update({
                            'Throughput (Mbps)': round(metrics["throughput_mbps"], 2),
                            'Upload (Mbps)': round(metrics["upload_mbps"], 2),
                            'Download (Mbps)': round(metrics["download_mbps"], 2),
                            'Packet Rate (pps)': round(metrics["packet_rate_pps"], 2),
                            'Avg Packet Size': round(metrics["avg_packet_size"], 2),
                            'Flow Duration (ms)': round(metrics["flow_duration_ms"], 2),
                            'Protocol': metrics["protocol_category"],
                            'Direction': metrics["direction"],
                            'Bytes': metrics["raw_total_bytes"],
                        })

                    batch.append(batch_item)

                except Exception as e:
                    print(f"[PARSING ERROR] Skipping malformed row: {e}")
                    continue

            if batch:
                if ENABLE_SYNTHETIC:
                    batch = inject_synthetic(batch)
               
                socketio.emit('new_flow_batch', batch)
                gevent.sleep(0)

        gevent.sleep(0.1)


@socketio.on('start_capture')
def handle_start_capture(data):
    global is_capturing, session_state, last_pos

    interface = data.get('interface')

    is_capturing = False
    last_pos = 0

    session_state = {
        "start_time": time.time(),

        "packet_size_sum": 0.0,
        "throughput_sum": 0.0,
        "upload_sum": 0.0,
        "download_sum": 0.0,
        "packet_rate_sum": 0.0,
        "flow_duration_sum": 0.0,

        "flow_count": 0,
        "inbound_count": 0,
        "outbound_count": 0,
        "balanced_count": 0
    }

    with file_lock:
        try:
            if os.path.exists(LIVE_FILE):
                os.remove(LIVE_FILE)
        except Exception:
            pass

    threading.Thread(
        target=sniffer_service.run_live_sniffer,
        args=(interface, LIVE_FILE),
        daemon=True
    ).start()

    gevent.sleep(2)
    is_capturing = True
    socketio.emit('status_update', f"Monitoring {interface}...")


@socketio.on('get_interfaces')
def handle_get_interfaces():
    try:
        from services import runtime_sniffer
        interfaces = runtime_sniffer.get_system_interfaces()
        socketio.emit('interfaces_list', interfaces)
    except Exception as e:
        print(f"[ERROR] Could not fetch interfaces: {e}")


@socketio.on('stop_capture')
def handle_stop_capture():
    global is_capturing
    is_capturing = False
    socketio.emit('status_update', "Capture Stopped. Ready.")


GEMINI_KEY = os.environ.get("GEMINI_API_KEY")
genai.configure(api_key=GEMINI_KEY)

@app.route('/api/generate-report', methods=['POST'])
def generate_report():
    try:
        _mac_cache.clear()
        current_external_ips = set()
        alias_map = {}

        data = request.json
        summary = data.get('summary', {})
        rows = data.get('rows', [])
        
        current_date = datetime.now().strftime("%B %d, %Y")
        
        flagged_details = []
        for row in rows:
            category = row.get('Predicted Category', '')
           
            if category in ['Suspicious', 'Attack-like', 'Anomaly', 'Misconfigured']:
                label        = row.get('Predicted Label', 'Unknown')
                src          = row.get('Src IP', 'N/A')
                dst          = row.get('Dst IP', 'N/A')
                src_port     = row.get('Src Port', 'N/A')
                dst_port     = row.get('Dst Port', 'N/A')
                
                src_info     = enrich_ip(src, alias_map) if src not in ('N/A', '?', '') else src
                dst_info     = enrich_ip(dst, alias_map) if dst not in ('N/A', '?', '') else dst
                service_name = get_service(dst_port)
                
                if not is_private_ip(src) and src not in ('N/A', '?', ''):
                    current_external_ips.add(src)
                if not is_private_ip(dst) and dst not in ('N/A', '?', ''):
                    current_external_ips.add(dst)

                flow_info = (
                    f"- [Type: {label}] "
                    f"Src: {src_info} (Port: {src_port}) "
                    f"-> Dst: {dst_info} via {service_name}"
                )
                flagged_details.append(flow_info)
        
        unique_flagged = list(set(flagged_details))[:25]
        
        flagged_telemetry_str = "\n".join(unique_flagged) if unique_flagged else "No high-risk malicious traffic rows recorded in telemetry."
        
        prompt = f"""
You are a Senior Security Operations Center (SOC) Analyst writing an official incident report for a network security team. Your report must be clear, professional, and immediately actionable. Avoid jargon where plain language works better. Every section must be grounded strictly in the data provided — do not invent IPs, labels, or statistics not present in the telemetry.

---

SESSION TELEMETRY INPUT:

Date of Report: {current_date}

Dashboard Metrics:
- Total Flows Captured : {summary.get('total', 0)}
- Normal Flows         : {summary.get('Normal', 0)}
- Misconfigured Flows  : {summary.get('Misconfigured', 0)}
- Suspicious Flows     : {summary.get('Suspicious', 0)}
- Attack-like Flows    : {summary.get('Attack-like', 0)}
- Anomalies Detected   : {summary.get('Anomaly', 0)}

Session Flow Sample (top flagged entries):
{flagged_telemetry_str}

---

REPORT OUTPUT INSTRUCTIONS:

Generate the report using exactly the structure below. Do not add extra sections. Do not skip sections. Use the heading text exactly as written.

---

# Network Behavior Analysis Report

**Date of Report:** {current_date}

---

## 1. Executive Summary

Write exactly 4 sentences in plain, direct language:
- Sentence 1: State the total number of flows and the overall session health (stable / degraded / under active threat).
- Sentence 2: Quantify the breakdown of traffic categories observed (Normal, Misconfigured, Suspicious, Attack-like).
- Sentence 3: Name the most critical threat or configuration issue observed and what it indicates at a high level.
- Sentence 4: State the immediate risk level to the network (Low / Medium / High / Critical) and why.

---

## 2. Threat & Configuration Breakdown

List only the top 5 most severe flow entries from the telemetry. If fewer than 5 exist, list all of them. Do not pad with Normal/Benign rows.

Assign Severity using this logic:
- Critical : Heartbleed, Botnet, Infiltration
- High     : Web Attack - Brute Force, FTP-Patator, SSH-Patator, DDoS, DoS Hulk, DoS GoldenEye
- Medium   : Web Attack - XSS, Web Attack - SQL Injection, Portscan, Anomaly
- Low      : Attempted attack variants, Dead Service, TCP Handshake Anomaly, Keep Alive Timeout, Packet Size Anomaly

| Src IP | Dst IP | Port | Label | Severity |
| :----- | :----- | :--- | :---- | :------- |
| (data) | (data) | (data) | (data) | (data) |

---

## 3. Behavioral Analysis

For each unique attack or misconfiguration label found in the telemetry, write one bullet point using this format:

**[Label Name]:** What this flow behavior does in one sentence. What it means for this specific network based on the destination IP and port observed. If it is an attack, state the likely goal. If it is a misconfiguration, state the likely root cause.

Keep each bullet to 2-3 sentences maximum. Focus on what was actually seen in the data.

---

## 4. Risk Assessment

Provide a single short paragraph (3 sentences) that:
- States the overall risk posture of this session
- Identifies the highest-risk source IP, attack vector, or failing service observed
- Explains the potential blast radius if the threat or misconfiguration is not contained

---

## 5. Recommended Actions

Provide exactly 5 actionable recommendations ordered from most urgent to least urgent. Each must:
- Start with a strong action verb (Block, Isolate, Patch, Escalate, Review, Deploy, Disable, Reconfigure)
- Be specific to the exact IPs, ports, protocols, and device vendors observed in this session
- If a device vendor is visible in the telemetry, reference the specific hardware
- Include the exact technical step required — name the specific firewall rule, log query, service, or protocol configuration
- Assign a priority tag based on urgency

Format each as:
**[IMMEDIATE / WITHIN 4 HOURS / WITHIN 24 HOURS] [Action Verb] [specific target]:** One sentence on what to do and what issue it directly resolves.

---

FORMATTING RULES:
- Use **bold** only for label names and action verbs, nowhere else.
- Do not use bold for entire sentences or paragraphs.
- Keep all prose tight — no filler phrases like "It is important to note that..." or "In conclusion..."
- Tables must use the exact column names specified.
- Severity values in the table must be exactly one of: Critical / High / Medium / Low
- Do not include any closing remarks, signatures, or meta-commentary about the report itself.
"""
        
        model = genai.GenerativeModel('gemini-3.1-flash-lite')
        response = model.generate_content(prompt)

        report_text = response.text
        for real_ip, alias in alias_map.items():
            report_text = report_text.replace(alias, real_ip)
        
        fingerprint_rows = []
        for ip, mac in _mac_cache.items():
            if mac:
                vendor = get_vendor_from_mac(mac)
                fingerprint_rows.append(f"| {ip} | {mac} | {vendor} |")

        geo_rows = []
        for ip in current_external_ips:
            if ip in _ip_cache:
                geo_rows.append(f"| {ip} | {_ip_cache[ip]} |")

        device_section = ""

        if fingerprint_rows:
            device_section += "\n\n---\n\n## 6. Device Fingerprint (MAC OUI Analysis)\n\n"
            device_section += "| IP Address | MAC Address | Vendor (OUI) |\n"
            device_section += "| :--------- | :---------- | :----------- |\n"
            device_section += "\n".join(fingerprint_rows)

        if geo_rows:
            device_section += "\n\n### External IP Geolocation\n\n"
            device_section += "| IP Address | Location — ISP |\n"
            device_section += "| :--------- | :------------- |\n"
            device_section += "\n".join(geo_rows)

        if not device_section:
            device_section = "\n\n---\n\n## 6. Device Fingerprint (MAC OUI Analysis)\n\n*No physical devices resolved via ARP in this session.*"

        final_report = report_text + device_section
        return jsonify({"report": final_report}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print("MAIN BLOCK EXECUTING")
    threading.Thread(target=file_watcher, daemon=True).start()
    gevent.spawn(continuous_metrics_emitter)
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, use_reloader=False)


