"""
NETGUARD — Network Security & ARP Threat Detection System
Deterministic ARP Mapping Change Detector
"""

from datetime import datetime


class ARPDetector:
    """
    Deterministic ARP analysis engine that tracks known IP-MAC bindings
    and raises security alerts when mapping changes or new hosts emerge.
    """

    def __init__(self):
        # Known baseline device table for demonstration / validation
        self.device_table = {
            "192.168.1.1": "00:1A:2B:3C:4D:5E",
            "192.168.1.10": "00:0C:29:4F:88:12",
            "192.168.1.20": "F8:75:A4:11:22:33"
        }
        self.alerts = []

    def check_device(self, ip_address, mac_address):
        """
        Evaluate an IP-MAC pair against baseline bindings.
        Returns status dict describing the observation.
        """
        ip_address = str(ip_address).strip()
        mac_address = str(mac_address).strip().upper()

        if ip_address in self.device_table:
            old_mac = self.device_table[ip_address].upper()

            if old_mac != mac_address:
                alert = {
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "ip": ip_address,
                    "old_mac": old_mac,
                    "new_mac": mac_address,
                    "status": "WARNING",
                    "severity": "HIGH",
                    "message": "Unexpected IP-MAC mapping conflict. Potential ARP poisoning attempt."
                }
                self.alerts.append(alert)
                return alert
            else:
                return {
                    "status": "NORMAL",
                    "severity": "INFO",
                    "ip": ip_address,
                    "mac": mac_address,
                    "message": "Device mapping matches established baseline"
                }
        else:
            # Register new host
            self.device_table[ip_address] = mac_address
            return {
                "status": "NEW DEVICE",
                "severity": "INFO",
                "ip": ip_address,
                "mac": mac_address,
                "message": "New host discovered and added to baseline"
            }


if __name__ == "__main__":
    detector = ARPDetector()
    print("=" * 60)
    print("NETGUARD — ARP DETECTION SYSTEM ENGINE TEST")
    print("=" * 60)

    # Test 1: Normal device
    r1 = detector.check_device("192.168.1.10", "00:0C:29:4F:88:12")
    print(f"\n[TEST 1 - Existing Baseline Device]:\n{r1}")

    # Test 2: New device
    r2 = detector.check_device("192.168.1.55", "3C:52:82:99:88:77")
    print(f"\n[TEST 2 - New Device Discovery]:\n{r2}")

    # Test 3: Simulated suspicious mapping change
    r3 = detector.check_device("192.168.1.1", "EE:FF:11:22:33:44")
    print(f"\n[TEST 3 - Suspicious Mapping Change]:\n{r3}")

    print("\nRecorded Security Alerts:")
    for a in detector.alerts:
        print(f"  • {a}")
