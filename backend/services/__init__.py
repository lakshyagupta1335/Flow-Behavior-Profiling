import sys

if sys.platform == "win32":
    print("[SYSTEM ENVIRONMENT] Microsoft Windows runtime detected. Loading Win32 Network Adapter Hooks.")
    from services.windows_sniffer import WindowsSnifferService as SnifferService
else:
    print("[SYSTEM ENVIRONMENT] Linux/POSIX runtime detected. Loading Native Libpcap Sockets.")
    from services.linux_sniffer import LinuxSnifferService as SnifferService

# A single instance export to preserve state across socket triggers
runtime_sniffer = SnifferService()