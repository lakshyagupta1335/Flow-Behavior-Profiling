from abc import ABC, abstractmethod

class BaseSnifferService(ABC):
    @abstractmethod
    def get_system_interfaces(self) -> list:
        """Fetch system network interface names."""
        pass

    @abstractmethod
    def start_live_capture(self, interface: str, output_file: str):
        """Spawn the background packet capturing engine."""
        pass

    @abstractmethod
    def stop_live_capture(self):
        """Gracefully terminate the background packet capture process tree."""
        pass