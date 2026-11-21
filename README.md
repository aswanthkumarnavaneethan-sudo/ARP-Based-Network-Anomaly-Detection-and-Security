# NETGUARD — Network Security & ARP Threat Detection System

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11-blue?logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Framework-Flask%203.x-lightgrey?logo=flask)](https://palletsprojects.com/p/flask/)
[![Scapy](https://img.shields.io/badge/Engine-Scapy%202.8-red?logo=wireshark)](https://scapy.net/)
[![Waitress](https://img.shields.io/badge/Production%20WSGI-Waitress-green)](https://docs.pylonsproject.org/projects/waitress/)
[![UI Style](https://img.shields.io/badge/Design-Metallic%20Silver%20Industrial-silver)](#user-interface)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**NETGUARD** is an enterprise-grade Network Intrusion Detection Sensor (NIDS) designed to detect, analyze, and mitigate **Address Resolution Protocol (ARP) Cache Poisoning** and **Man-in-the-Middle (MITM)** attacks across physical and virtual Local Area Networks (LANs). 

Featuring a metallic silver cybersecurity control center inspired by brushed aluminum, chrome hardware, and automotive telemetry consoles, NETGUARD monitors Layer-2 broadcast traffic in real time and maintains an auditable baseline of physical network devices.

---

## 🛡️ Key Capabilities

- **Passive Layer-2 Packet Sniffing**: Uses Scapy and Npcap in promiscuous capture mode to intercept live `ARP Request (0x0001)` and `ARP Reply (0x0002)` frames without perturbing network traffic.
- **Deterministic Threat Detection Core**: Algorithmic validation engine flags conflicting MAC-to-IP associations, unprompted gratuitous ARP anomalies, and rapid IP reassignment events.
- **Physical Device Inventory & Hardware OUI Resolution**: Discovers active network nodes, resolves IEEE MAC Organizationally Unique Identifiers (e.g. Cisco, Ruijie, Apple, Intel, Samsung), and tracks observation frequency.
- **Multi-Threaded Production WSGI**: Powered by **Waitress** production server (8 worker threads), accessible both locally (`127.0.0.1:5000`) and across the entire local subnet (`http://<LAN-IP>:5000`).
- **Incident Response & Acknowledgment Workflow**: Security analysts can review alerts, verify IP/MAC conflict timelines, and acknowledge resolved threats.
- **Compliance & Audit Reporting**: One-click RFC-compliant CSV export for device inventories and incident logs, plus a print-optimized executive dossier view.
- **Safety Simulation Mode**: Built-in test mechanism allows security evaluators to safely test the alerting pipeline without damaging production network routes.

---

## 🏛️ System Architecture

```
+-------------------------------------------------------------------------------+
|                       LOCAL AREA NETWORK (Subnet / Wi-Fi)                     |
|                                                                               |
|   +--------------------+     +--------------------+     +-----------------+   |
|   |   Default Gateway  |     |   Legitimate Hosts |     |   Rogue Node    |   |
|   |   172.100.0.1      |     | (Apple, Samsung...) |     | (ARP Poisoner)  |   |
|   +---------+----------+     +---------+----------+     +--------+--------+   |
|             |                          |                         |            |
|             +--------------------------+-------------------------+            |
|                                        |                                      |
|                       [ Layer-2 Broadcast Domain ]                           |
|                                        |                                      |
|                                        v                                      |
|   +-----------------------------------------------------------------------+   |
|   |                     NETGUARD SENSOR APPLIANCE                         |   |
|   |                                                                       |   |
|   |   +---------------------------------------------------------------+   |   |
|   |   |  Hardware Capture Engine (Npcap / Scapy Sniffer)              |   |   |
|   |   +-------------------------------+-------------------------------+   |   |
|   |                                   |                                   |   |
|   |   +-------------------------------v-------------------------------+   |   |
|   |   |  Algorithmic Threat Detector (detector.py)                   |   |   |
|   |   +-------------------------------+-------------------------------+   |   |
|   |                                   |                                   |   |
|   |   +-------------------------------v-------------------------------+   |   |
|   |   |  SQLite Relational Security Audit Store (security.db)         |   |   |
|   |   +-------------------------------+-------------------------------+   |   |
|   |                                   |                                   |   |
|   |   +-------------------------------v-------------------------------+   |   |
|   |   |  Production WSGI Engine (Waitress Multi-Threaded: 0.0.0.0)    |   |   |
|   |   +-------------------------------+-------------------------------+   |   |
|   +-----------------------------------|-----------------------------------+   |
+---------------------------------------|---------------------------------------+
                                        |
                 +----------------------+----------------------+
                 |                                             |
                 v                                             v
     [ Local Station Console ]                     [ Evaluation Panel / Remote ]
      http://127.0.0.1:5000                         http://<Host-IP>:5000
```

---

## 📂 Project Structure

```
├── app.py                     # Flask REST API and route controllers
├── server.py                  # Production WSGI server (Waitress)
├── monitor.py                 # Scapy packet capture sniffer thread
├── detector.py                # Deterministic ARP anomaly detector logic
├── database.py                # SQLite schema, OUI resolver, query persistence
├── requirements.txt           # Python package specifications
├── deploy_production.bat      # 1-Click Windows deployment launcher
├── Dockerfile                 # Container specification with libpcap
├── docker-compose.yml         # Compose configuration (host network mode)
├── static/
│   ├── style.css              # Metallic silver design tokens & animations
│   └── script.js              # State manager, real-time polling & Chart.js
└── templates/
    └── index.html             # Metallic silver single-page dashboard
```

---

## 🚀 Quickstart & Installation

### Prerequisites
1. **Python 3.10+**: Ensure Python is added to your system `PATH`.
2. **Packet Capture Driver**:
   - **Windows**: Install [Npcap](https://npcap.com/) (select *"Install Npcap in WinPcap API-compatible Mode"* during installation).
   - **Linux**: `sudo apt install libpcap-dev tcpdump`

### 1. Clone the Repository
```bash
git clone https://github.com/<your-username>/netguard-arp-detection.git
cd netguard-arp-detection
```

### 2. Install Dependencies
```bash
python -m pip install -r requirements.txt
```

### 3. Launch in Production Mode
**Option A — Windows 1-Click Launcher:**
Double-click `deploy_production.bat`.

**Option B — Command Line:**
```bash
python server.py
```

Open your browser to:
- **Local Console:** [http://127.0.0.1:5000](http://127.0.0.1:5000)
- **LAN Access:** `http://<your-ip>:5000`

---

## 🐳 Docker Deployment (Linux Appliance)

Deploy NETGUARD as an isolated container on Linux security gateways or Raspberry Pi sensors:

```bash
docker-compose up -d --build
```

> **Note:** `network_mode: "host"` is required to give the container direct access to Layer-2 physical network interfaces.

---

## 📡 REST API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/status` | `GET` | Returns telemetry of the packet capture engine and active adapter. |
| `/api/interfaces` | `GET` | Lists host physical and virtual network adapters. |
| `/api/devices` | `GET` | Returns the inventory of discovered network devices. |
| `/api/events` | `GET` | Returns logged security events and ARP mapping anomalies. |
| `/api/stats` | `GET` | Provides high-level metrics for dashboard cards. |
| `/api/start` | `POST` | Initializes passive packet monitoring on a selected network interface. |
| `/api/stop` | `POST` | Suspends active packet sniffing. |
| `/api/scan` | `POST` | Triggers a live ARP broadcast sweep across the local subnet. |
| `/api/simulate-attack` | `POST` | Injects a safe ARP discrepancy alert for testing and evaluation. |
| `/api/events/<id>/ack` | `POST` | Updates the investigation and acknowledgment status of an event. |
| `/api/export/<type>` | `GET` | Generates RFC-compliant CSV files for `devices` or `events`. |

---

## 🔒 Security & Privacy Notice

NETGUARD operates in **pure passive listening mode** by default:
- It does **not** transmit rogue packets, corrupt network routes, or inject man-in-the-middle proxies during normal monitoring.
- The `Test Threat Detection` feature simulates alert conditions purely at the application level to safely demonstrate detection capabilities to reviewers without disrupting network connectivity.

---

## 👨‍💻 Author

**Aswanth Kumar**  
Network Security & Cyber Threat Intelligence  
Email: [aswanthkumarnavaneethan@gmail.com](mailto:aswanthkumarnavaneethan@gmail.com)
