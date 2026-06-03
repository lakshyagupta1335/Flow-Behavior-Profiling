import os
import signal
import time
import subprocess
import psutil
from services.base_sniffer import BaseSnifferService

def run_linux_native_sniffer(interface, output_file):
    """Executes cicflowmeter as a clean POSIX process group leader."""
    print(f"[LINUX SNIFFER] Initiating raw capture on {interface}...")
    if os.path.exists(output_file):
        try:
            os.remove(output_file)
        except Exception:
            pass
            
    try:
        # shell=False prevents command injection vulnerabilities
        subprocess.run(["cicflowmeter", "-i", interface, "-c", output_file], check=True)
    except Exception as e:
        print(f"[LINUX SNIFFER ERROR] Pipeline failure: {e}")

class LinuxSnifferService(BaseSnifferService):
    def __init__(self):
        self.sniffer_process = None

    def get_system_interfaces(self) -> list:
        try:
            # Filters out virtual loopback and docker interfaces to keep your UI clean
            addrs = psutil.net_if_addrs()
            return [iface for iface in addrs.keys() if iface != 'lo' and not iface.startswith('docker')]
        except Exception as e:
            print(f"[LINUX ENGINE ERROR] Interface fetch failed: {e}")
            return []

    def start_live_capture(self, interface: str, output_file: str):
        # preexec_fn=os.setsid detaches the process into its own group
        # This allows us to target the entire tree when stopping capture
        from multiprocessing import Process
        self.sniffer_process = subprocess.Popen(
            ["cicflowmeter", "-i", interface, "-c", output_file],
            preexec_fn=os.setsid,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return self.sniffer_process

    def stop_live_capture(self):
        if self.sniffer_process and self.sniffer_process.poll() is None:
            try:
                # Kills the entire process group cleanly via POSIX signal matching
                os.killpg(os.getpgid(self.sniffer_process.pid), signal.SIGINT)
                time.sleep(0.5)
                if self.sniffer_process.poll() is None:
                    os.killpg(os.getpgid(self.sniffer_process.pid), signal.SIGKILL)
            except Exception as e:
                print(f"[LINUX CLEANUP WARNING] Process group termination message: {e}")
        self.sniffer_process = None