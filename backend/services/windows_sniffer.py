import os
import time
from multiprocessing import Process
import psutil
from services.base_sniffer import BaseSnifferService
from sniffer_service import run_live_sniffer

class WindowsSnifferService(BaseSnifferService):
    def __init__(self):
        self.sniffer_process = None

    def get_system_interfaces(self) -> list:
        try:
            return list(psutil.net_if_addrs().keys())
        except Exception as e:
            print(f"[WINDOWS ENGINE ERROR] Interface fetch failed: {e}")
            return []

    def start_live_capture(self, interface: str, output_file: str):
        self.sniffer_process = Process(target=run_live_sniffer, args=(interface, output_file))
        self.sniffer_process.start()
        return self.sniffer_process

    def stop_live_capture(self):
        if self.sniffer_process and self.sniffer_process.is_alive():
            self.sniffer_process.terminate()
            self.sniffer_process.join(timeout=1)
        self.sniffer_process = None