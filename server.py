"""
NETGUARD — Production WSGI Deployment Server
High-concurrency, multi-threaded production deployment using Waitress.
Designed for on-premises government/enterprise cybersecurity sensor deployments.
"""

import sys
import os
import socket

# Auto-resolve venv site-packages if executed with global system Python
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
venv_site = os.path.join(BASE_DIR, "venv", "Lib", "site-packages")
if os.path.exists(venv_site) and venv_site not in sys.path:
    sys.path.insert(0, venv_site)

from app import app
from waitress import serve


def get_lan_ip():
    """Detect the host primary IP on the local network."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def run_production(host="0.0.0.0", port=None, threads=8):
    """Launch the production WSGI server."""
    if port is None:
        port = int(os.environ.get("PORT", 5000))
    lan_ip = get_lan_ip()
    
    print("\n" + "=" * 72)
    print("  NETGUARD — NETWORK SECURITY & ARP THREAT DETECTION SYSTEM")
    print("  PRODUCTION ENTERPRISE DEPLOYMENT (WSGI / WAITRESS)")
    print("=" * 72)
    print(f"  [+] Engine Type:        Multi-Threaded Production WSGI Server")
    print(f"  [+] Worker Threads:     {threads} Concurrent Request Threads")
    print(f"  [+] Local Dashboard:    http://127.0.0.1:{port}")
    print(f"  [+] LAN / Wi-Fi Access: http://{lan_ip}:{port}")
    print(f"  [+] Capture Probe:      Passive Promiscuous Sniffer Active")
    print(f"  [+] Sensor Mode:        Real Hardware Layer-2 Telemetry")
    print("=" * 72)
    print("  Ready for live demonstration & network security evaluation.")
    print("  Press Ctrl+C to stop the production service.\n")

    serve(
        app,
        host=host,
        port=port,
        threads=threads,
        channel_timeout=60,
        cleanup_interval=30
    )


if __name__ == "__main__":
    run_production()
