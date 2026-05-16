import subprocess
import os

def run_live_sniffer(interface="Wi-Fi", output_file="live_flows.csv"):
    """
    Starts cicflowmeter. Handles Windows PermissionErrors if the file 
    is currently being read by the Flask watcher.
    """
    print(f"[SNIFFER] Initializing capture for {output_file}...")
    
    if os.path.exists(output_file):
        try:
            os.remove(output_file)
            print("[SNIFFER] Previous session file cleared.")
        except PermissionError:

            print("[SNIFFER] File is busy. Appending to current session.")
        except Exception as e:
            print(f"[SNIFFER] Note: {e}")
        
    print(f"[SNIFFER] Starting live capture on interface: {interface}")
    try:
        subprocess.run(["cicflowmeter", "-i", interface, "-c", output_file], check=True)
    except Exception as e:
        print(f"[SNIFFER ERROR] Failed to run cicflowmeter: {e}")