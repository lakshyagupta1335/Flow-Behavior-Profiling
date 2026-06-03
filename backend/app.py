import os
import sys
import gevent

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import time
import threading
from multiprocessing import Process
import psutil
from flask import Flask
from flask_socketio import SocketIO
from flask_cors import CORS
import random

from synthetic_flow import get_synthetic_flows
from classifier import RealTimeClassifier
from sniffer_service import run_live_sniffer

# Import the dynamic platform runtime service wrapper
from services import runtime_sniffer

synthetic_pool = get_synthetic_flows()

try:
    from scipy import stats
    print("[SYSTEM] Scientific libraries (scipy) loaded.")
except ImportError as e:
    print(f"[SYSTEM WARNING] Memory/DLL issue detected: {e}")

is_capturing = False
last_pos = 0  
sniffer_process = None
LIVE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "live_flows.csv")
engine = RealTimeClassifier()
file_lock = threading.Lock()

app = Flask(__name__)
CORS(app)

socketio = SocketIO(app, cors_allowed_origins="*", transports=['websocket'], async_mode='gevent')

# function for synthetic traffic
def inject_synthetic(batch):
    global is_capturing
    if not is_capturing:
        return batch
    if random.random() < 0.5:
        label, flow = random.choice(synthetic_pool)

        # run through SAME ML prediction logic
        pred, category = engine.predict_live(flow)

        batch.append({      
            'Src IP': flow.get('src_ip', 'N/A'),
            'Dst IP': flow.get('dst_ip', 'N/A'),
            'Src Port': flow.get('src_port', 0),
            'Dst Port': flow.get('dst_port', 0),
            'Predicted Label': pred,
            'Predicted Category': category
        })

    return batch

def file_watcher():
    global is_capturing
    if not engine.load_bundle(): return

    last_pos = 0
    while True:
        if not is_capturing or not os.path.exists(LIVE_FILE):
            last_pos = 0
            time.sleep(1)
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
                if not line.strip() or "src_ip" in line.lower(): continue
                parts = line.strip().split(',')
                if len(parts) < 10: continue
                
                try:
                    headers = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']
                    raw_data = dict(zip(headers, parts))
                    label, category = engine.predict_live(raw_data)
                    batch.append({
                        'Src IP': raw_data.get('src_ip', 'N/A'),
                        'Dst IP': raw_data.get('dst_ip', 'N/A'),
                        'Src Port': raw_data.get('src_port', 'N/A'),
                        'Dst Port': raw_data.get('dst_port', 'N/A'),
                        'Predicted Label': label,
                        'Predicted Category': category
                    })
                except: continue

            if batch:
                if is_capturing:
                    batch = inject_synthetic(batch)
                socketio.emit('new_flow_batch', batch)
                gevent.sleep(0)
        
        time.sleep(0.5)

@socketio.on('start_capture')
def handle_start_capture(data):
    global sniffer_process, is_capturing
    interface = data.get('interface')
    
    is_capturing = False 
    
    with file_lock: 
        # Leverage the dynamic runtime sniffer to terminate any running process
        runtime_sniffer.stop_live_capture()
        
        for _ in range(5): 
            try:
                if os.path.exists(LIVE_FILE):
                    os.remove(LIVE_FILE)
                with open(LIVE_FILE, 'w') as f:
                    f.write("")
                print(f"[ENGINE] {LIVE_FILE} cleared.")
                break
            except PermissionError:
                time.sleep(0.5)

    # Start Sniffer via the cross-platform platform driver layer
    runtime_sniffer.start_live_capture(interface, LIVE_FILE)
    
    time.sleep(3) 
    is_capturing = True
    socketio.emit('status_update', f"Monitoring {interface}...")

@socketio.on('get_interfaces')
def handle_get_interfaces():
    try:
        # Dynamically targets platform native interfaces (Win32 API vs POSIX Net_Ifs)
        interfaces = runtime_sniffer.get_system_interfaces()
        socketio.emit('interfaces_list', interfaces)
    except Exception as e:
        print(f"[ERROR] Could not fetch interfaces: {e}")

@socketio.on('stop_capture')
def handle_stop_capture():
    global is_capturing
    is_capturing = False
    last_pos = 0 
    
    # Gracefully stops capture process trees depending on underlying OS capabilities
    runtime_sniffer.stop_live_capture()
    socketio.emit('status_update', "Capture Stopped. Ready.")


if __name__ == "__main__":
    # Keep using standard Python OS threads natively!
    threading.Thread(target=file_watcher, daemon=True).start()
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, use_reloader=False)
