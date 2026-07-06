import json
import re
from datetime import datetime

class PhantomBlue:
    def __init__(self, log_file="/var/log/suricata/fast.log"):
        self.log_file = log_file
        self.alerts = []

    def parse_alert(self, line):
        pattern = r'(\d+/\d+/\d+-\d+:\d+:\d+\.\d+)\s+\[\*\*\]\s+\[(\d+:\d+:\d+)\]\s+(.+?)\s+\[\*\*\]\s+\[Classification:\s+(.+?)\]\s+\[Priority:\s+(\d+)\]\s+\{(\w+)\}\s+(\S+)\s+->\s+(\S+)'
        match = re.match(pattern, line)
        if match:
            src = match.group(7)
            dst = match.group(8)
            return {
                "timestamp": match.group(1),
                "rule_id": match.group(2),
                "message": match.group(3),
                "classification": match.group(4),
                "priority": int(match.group(5)),
                "protocol": match.group(6),
                "src_ip": src.split(":")[0],
                "src_port": src.split(":")[1] if ":" in src else "N/A",
                "dst_ip": dst.split(":")[0],
                "dst_port": dst.split(":")[1] if ":" in dst else "N/A",
                "severity": self.get_severity(int(match.group(5))),
                "mitre": self.map_mitre(match.group(3))
            }
        return None

    def get_severity(self, priority):
        if priority == 1:
            return "🔴 CRITICAL"
        elif priority == 2:
            return "🟠 HIGH"
        elif priority == 3:
            return "🟡 MEDIUM"
        else:
            return "🟢 LOW"

    def map_mitre(self, message):
        message = message.lower()
        if "scan" in message:
            return "T1046 — Network Service Scanning"
        elif "brute" in message or "login" in message:
            return "T1110 — Brute Force"
        elif "sql" in message:
            return "T1190 — Exploit Public App"
        elif "exploit" in message:
            return "T1203 — Exploitation"
        elif "backdoor" in message or "trojan" in message:
            return "T1059 — Command and Scripting"
        else:
            return "T1046 — Network Service Scanning"

    def analyze(self):
        print("[🔵 PHANTOM BLUE] Analyse des alertes Suricata...")
        try:
            with open(self.log_file, 'r') as f:
                lines = f.readlines()
            for line in lines:
                alert = self.parse_alert(line.strip())
                if alert:
                    self.alerts.append(alert)
                    print(f"\n[🚨 ALERTE] {alert['severity']}")
                    print(f"  Message  : {alert['message']}")
                    print(f"  Source   : {alert['src_ip']}:{alert['src_port']}")
                    print(f"  Dest     : {alert['dst_ip']}:{alert['dst_port']}")
                    print(f"  MITRE    : {alert['mitre']}")
                    print(f"  Time     : {alert['timestamp']}")
        except FileNotFoundError:
            print(f"[❌ ERROR] Log file not found: {self.log_file}")

    def save(self):
        with open("blue_alerts.json", "w") as f:
            json.dump(self.alerts, f, indent=4)
        print(f"\n[📄 PHANTOM BLUE] {len(self.alerts)} alertes sauvegardées dans blue_alerts.json")

if __name__ == "__main__":
    blue = PhantomBlue("/var/log/suricata/fast.log")
    blue.analyze()
    blue.save()
