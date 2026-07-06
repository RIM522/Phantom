import nmap
import json
from datetime import datetime

class PhantomScanner:
    def __init__(self, target):
        self.target = target
        self.scanner = nmap.PortScanner()
        self.results = {}

    def scan(self):
        print(f"[👻 PHANTOM RED] Scanning {self.target}...")
        self.scanner.scan(self.target, '1-1000', arguments='-sS -Pn -sV --version-intensity 5')
        for host in self.scanner.all_hosts():
            self.results[host] = {
                "timestamp": str(datetime.now()),
                "status": self.scanner[host].state(),
                "ports": []
            }
            for proto in self.scanner[host].all_protocols():
                for port in self.scanner[host][proto]:
                    service = self.scanner[host][proto][port]
                    self.results[host]["ports"].append({
                        "port": port,
                        "state": service["state"],
                        "service": service["name"],
                        "version": service["version"],
                        "mitre": "T1046"
                    })
        print(f"[✅ PHANTOM RED] Scan terminé — {len(self.results)} hôte(s) trouvé(s)")
        return self.results

    def save_results(self):
        with open("scan_results.json", "w") as f:
            json.dump(self.results, f, indent=4)
        print("[📄 PHANTOM RED] Résultats sauvegardés dans scan_results.json")

if __name__ == "__main__":
    scanner = PhantomScanner("192.168.100.20")
    results = scanner.scan()
    scanner.save_results()
    print(json.dumps(results, indent=4))
