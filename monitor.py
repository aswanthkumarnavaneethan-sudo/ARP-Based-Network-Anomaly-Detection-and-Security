"""
NETGUARD — Network Security & ARP Threat Detection System
Network Sniffer & Packet Monitoring Core (Scapy Engine)
"""

import sys
import os
import threading
import time
from datetime import datetime

# Auto-resolve venv site-packages if executed with global system Python
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
venv_site = os.path.join(BASE_DIR, "venv", "Lib", "site-packages")
if os.path.exists(venv_site) and venv_site not in sys.path:
    sys.path.insert(0, venv_site)


class NetworkMonitor:

    def __init__(self):
        self.running = False
        self.interface = None
        self.raw_interface = None
        self.thread = None
        self.last_error = None
        self.packet_count = 0
        self.start_time = None
        self.interface_map = {}

    def get_interfaces(self):
        """
        Enumerate network interfaces with clean, human-readable labels and IP information.
        Maps friendly labels to underlying Scapy adapter strings.
        """
        self.interface_map = {}

        try:
            from scapy.arch.windows import get_windows_if_list
            ifs = get_windows_if_list()
            for item in ifs:
                name = item.get("name", "")
                desc = item.get("description", "")
                ips = item.get("ips", [])
                ipv4 = [ip for ip in ips if "." in ip and not ip.startswith("169.254.")]

                # Focus on real active physical/virtual adapters
                if name and not "Filter" in name and not "Scheduler" in name and not "Tunneling" in name:
                    if ipv4:
                        friendly_name = f"{name} ({desc} — {ipv4[0]})"
                    else:
                        friendly_name = f"{name} ({desc})"
                    self.interface_map[friendly_name] = name
        except Exception:
            pass

        # Fallback if Windows interface list unavailable
        if not self.interface_map:
            try:
                from scapy.all import get_if_list
                for iface in get_if_list():
                    self.interface_map[iface] = iface
            except Exception:
                self.interface_map["Wi-Fi"] = "Wi-Fi"
                self.interface_map["Ethernet"] = "Ethernet"

        # Priority sort: Active Wi-Fi with IP 172.100 at the top, followed by main Wi-Fi and Ethernet
        def sort_priority(k):
            if "172.100" in k:
                return 0
            if k.startswith("Wi-Fi"):
                return 1
            if "Ethernet" in k:
                return 2
            return 3

        sorted_keys = sorted(list(self.interface_map.keys()), key=sort_priority)
        return sorted_keys

    def process_packet(self, packet):
        """Callback executed for every captured packet matching the ARP filter."""
        try:
            from scapy.all import ARP

            if not packet.haslayer(ARP):
                return

            arp = packet[ARP]
            ip_address = str(arp.psrc).strip()
            mac_address = str(arp.hwsrc).strip().upper()

            if not ip_address or not mac_address or ip_address == "0.0.0.0":
                return

            self.packet_count += 1

            from database import observe_device
            result = observe_device(ip_address, mac_address)

            if result == "MAPPING_CHANGE":
                print(f"[NETGUARD ALERT] Suspicious ARP mapping change: IP={ip_address} MAC={mac_address}")
            elif result == "NEW_DEVICE":
                print(f"[NETGUARD INFO] Real host verified: IP={ip_address} MAC={mac_address}")

        except Exception as error:
            print(f"[NETGUARD PACKET ERROR] {error}")

    def capture_loop(self):
        """Continuous background capture thread loop."""
        try:
            from scapy.all import sniff

            # If raw_interface is not bound, fallback to 'Wi-Fi'
            target_iface = self.raw_interface or self.interface or "Wi-Fi"
            if target_iface and "(" in target_iface:
                target_iface = target_iface.split("(")[0].strip()

            last_sync_time = time.time()

            while self.running:
                # 1. Passive sniff for live ARP packets (1 second timeout to stay responsive)
                try:
                    sniff(
                        iface=target_iface,
                        filter="arp",
                        prn=self.process_packet,
                        store=False,
                        timeout=1
                    )
                except Exception as sniff_err:
                    print(f"[NETGUARD SNIFFER] Adapter sniff warning: {sniff_err}")

                # 2. Continuous real-time network sync every 4 seconds to maintain active device telemetry
                if time.time() - last_sync_time >= 4:
                    try:
                        from database import sync_real_network_devices
                        sync_real_network_devices()
                        last_sync_time = time.time()
                    except Exception:
                        pass

        except Exception as error:
            self.last_error = f"Capture engine notice: {error}"
            self.running = False
            print(f"[NETGUARD MONITOR ERROR] {self.last_error}")

    def start(self, interface):
        """Start passive monitoring on the designated network interface."""
        if self.running:
            return False

        # Resolve raw interface from friendly name
        self.interface = interface
        self.raw_interface = "Wi-Fi"
        for friendly, raw in self.interface_map.items():
            if interface == friendly or interface == raw or (interface.lower() == raw.lower()):
                self.interface = friendly
                self.raw_interface = raw
                break
        if "(" in self.raw_interface:
            self.raw_interface = self.raw_interface.split("(")[0].strip()

        self.last_error = None
        self.packet_count = 0
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.running = True

        # Sync real active network devices immediately upon starting
        try:
            from database import sync_real_network_devices
            sync_real_network_devices()
        except Exception as e:
            print("[NETGUARD] Initial sync error:", e)

        self.thread = threading.Thread(
            target=self.capture_loop,
            daemon=True,
            name="NetGuard-Capture-Worker"
        )
        self.thread.start()
        return True

    def stop(self):
        """Stop packet monitoring safely."""
        self.running = False

        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.5)

        return True

    def get_telemetry(self):
        """Return diagnostic telemetry regarding the capture engine."""
        return {
            "running": self.running,
            "interface": self.interface or "None Selected",
            "error": self.last_error,
            "packet_count": self.packet_count,
            "start_time": self.start_time
        }


# Singleton monitor instance used across the Flask application
monitor = NetworkMonitor()
