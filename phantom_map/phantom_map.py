import json

TECHNIQUE_MAP = {
    "T1046": {"name": "Network Service Scanning", "tactic": "discovery"},
    "T1110": {"name": "Brute Force", "tactic": "credential-access"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial-access"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "privilege-escalation"},
    "T1021": {"name": "Remote Services", "tactic": "lateral-movement"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "exfiltration"},
    "T1078": {"name": "Valid Accounts", "tactic": "initial-access"},
    "T1040": {"name": "Network Sniffing", "tactic": "credential-access"},
}

class PhantomMap:
    def __init__(self):
        self.kill_chain = []

    def load_alerts(self, blue_file, intel_file):
        with open(blue_file, 'r') as f:
            self.blue_alerts = json.load(f)
        with open(intel_file, 'r') as f:
            self.intel_results = json.load(f)

    def map_technique(self, technique_id):
        if technique_id in TECHNIQUE_MAP:
            t = TECHNIQUE_MAP[technique_id]
            return {
                "id": technique_id,
                "name": t["name"],
                "tactic": t["tactic"]
            }
        return {"id": technique_id, "name": "Unknown", "tactic": "Unknown"}

    def build_kill_chain(self):
        print("[🗺️ PHANTOM MAP] Construction de la Kill Chain...")
        techniques_seen = set()

        for alert in self.blue_alerts:
            mitre_id = alert["mitre"].split(" ")[0]
            if mitre_id not in techniques_seen:
                technique = self.map_technique(mitre_id)
                technique["source"] = "Phantom Blue"
                technique["timestamp"] = alert["timestamp"]
                technique["severity"] = alert["severity"]
                self.kill_chain.append(technique)
                techniques_seen.add(mitre_id)
                print(f"  ✅ {mitre_id} — {technique['name']} [{technique['tactic']}]")

        for host, services in self.intel_results.items():
            for technique_info in [
                {"id": "T1190", "source": "Phantom Intel"},
                {"id": "T1046", "source": "Phantom Intel"}
            ]:
                if technique_info["id"] not in techniques_seen:
                    technique = self.map_technique(technique_info["id"])
                    technique["source"] = technique_info["source"]
                    technique["severity"] = "🔴 CRITICAL"
                    self.kill_chain.append(technique)
                    techniques_seen.add(technique_info["id"])
                    print(f"  ✅ {technique_info['id']} — {technique['name']} [{technique['tactic']}]")

    def display_kill_chain(self):
        print("\n" + "="*60)
        print("🗺️  PHANTOM KILL CHAIN — MITRE ATT&CK")
        print("="*60)

        tactics_order = [
            "reconnaissance", "initial-access", "execution",
            "persistence", "privilege-escalation", "defense-evasion",
            "credential-access", "discovery", "lateral-movement",
            "collection", "exfiltration", "impact"
        ]

        for tactic in tactics_order:
            techniques = [t for t in self.kill_chain if t["tactic"] == tactic]
            if techniques:
                print(f"\n📍 {tactic.upper()}")
                for t in techniques:
                    print(f"   └─ {t['id']} — {t['name']}")
                    print(f"      Source   : {t.get('source', 'N/A')}")
                    print(f"      Severity : {t.get('severity', 'N/A')}")

    def save(self):
        with open("kill_chain.json", "w") as f:
            json.dump(self.kill_chain, f, indent=4)
        print(f"\n[📄 PHANTOM MAP] Kill chain sauvegardée dans kill_chain.json")

if __name__ == "__main__":
    mapper = PhantomMap()
    mapper.load_alerts(
        "../phantom_blue/blue_alerts.json",
        "../phantom_intel/intel_results.json"
    )
    mapper.build_kill_chain()
    mapper.display_kill_chain()
    mapper.save()
