import json

class PhantomScore:
    def __init__(self):
        self.scores = {}
        self.total_score = 0
        self.details = []

    def load_data(self):
        try:
            with open('../phantom_red/scan_results.json') as f:
                self.scan = json.load(f)
        except:
            self.scan = {}

        try:
            with open('../phantom_intel/intel_results.json') as f:
                self.intel = json.load(f)
        except:
            self.intel = {}

        try:
            with open('../phantom_blue/blue_alerts.json') as f:
                self.alerts = json.load(f)
        except:
            self.alerts = []

        try:
            with open('../phantom_map/kill_chain.json') as f:
                self.kill_chain = json.load(f)
        except:
            self.kill_chain = []

    def score_attack_surface(self):
        total_ports = 0
        for host, data in self.scan.items():
            total_ports += len(data.get('ports', []))

        if total_ports == 0:
            score = 100
        elif total_ports <= 3:
            score = 70
        elif total_ports <= 7:
            score = 40
        else:
            score = 10

        self.scores['attack_surface'] = score
        self.details.append({
            "category": "Attack Surface",
            "score": score,
            "max": 100,
            "detail": f"{total_ports} ports ouverts détectés",
            "status": "✅" if score >= 70 else "❌"
        })

    def score_vulnerabilities(self):
        critical = 0
        high = 0
        for host, services in self.intel.items():
            for service in services:
                for cve in service.get('cves', []):
                    if cve.get('severity') == 'CRITICAL':
                        critical += 1
                    elif cve.get('severity') == 'HIGH':
                        high += 1

        if critical == 0 and high == 0:
            score = 100
        elif critical == 0:
            score = 60
        elif critical <= 2:
            score = 20
        else:
            score = 5

        self.scores['vulnerabilities'] = score
        self.details.append({
            "category": "Vulnerabilities",
            "score": score,
            "max": 100,
            "detail": f"{critical} CRITICAL, {high} HIGH CVEs",
            "status": "✅" if score >= 70 else "❌"
        })

    def score_detection(self):
        total_alerts = len(self.alerts)
        if total_alerts == 0:
            score = 0
        elif total_alerts <= 2:
            score = 50
        elif total_alerts <= 5:
            score = 75
        else:
            score = 95

        self.scores['detection'] = score
        self.details.append({
            "category": "Detection Capability",
            "score": score,
            "max": 100,
            "detail": f"{total_alerts} attaques détectées",
            "status": "✅" if score >= 70 else "⚠️"
        })

    def score_kill_chain(self):
        steps = len(self.kill_chain)
        if steps == 0:
            score = 100
        elif steps <= 2:
            score = 60
        elif steps <= 4:
            score = 30
        else:
            score = 10

        self.scores['kill_chain'] = score
        self.details.append({
            "category": "Kill Chain Coverage",
            "score": score,
            "max": 100,
            "detail": f"{steps} techniques MITRE détectées",
            "status": "✅" if score >= 70 else "❌"
        })
    def score_exploits(self):
        try:
            with open('../phantom_red/exploit_results.json') as f:
                exploits = json.load(f)
        except:
            exploits = []

        try:
            with open('../phantom_red/bruteforce_results.json') as f:
                bruteforce = json.load(f)
        except:
            bruteforce = []

        successful_exploits = sum(1 for e in exploits if e.get('success'))
        successful_bf = sum(1 for b in bruteforce if b.get('success'))

        if successful_exploits == 0 and successful_bf == 0:
            score = 100
        elif successful_exploits == 0:
            score = 40
        elif successful_exploits <= 1:
            score = 10
        else:
            score = 0

        self.scores['exploits'] = score
        self.details.append({
            "category": "Exploit Resistance",
            "score": score,
            "max": 100,
            "detail": f"{successful_exploits} exploits réussis, {successful_bf} brute force réussis",
            "status": "✅" if score >= 70 else "❌"
        })

    def calculate_total(self):
        weights = {
           'attack_surface': 0.20,
           'vulnerabilities': 0.30,
           'detection': 0.20,
           'kill_chain': 0.10,
            'exploits': 0.20
        }
        total = sum(self.scores[k] * weights[k] for k in self.scores)
        self.total_score = round(total)

    def get_level(self):
        if self.total_score >= 71:
            return "🟢 SECURE"
        elif self.total_score >= 51:
            return "🟡 MODERATE"
        elif self.total_score >= 31:
            return "🟠 VULNERABLE"
        else:
            return "🔴 CRITICAL"

    def display(self):
        print("\n" + "="*60)
        print("🛡️  PHANTOM SECURITY SCORE")
        print("="*60)
        for detail in self.details:
            print(f"\n{detail['status']} {detail['category']}")
            print(f"   Score  : {detail['score']}/100")
            print(f"   Detail : {detail['detail']}")
        print("\n" + "="*60)
        print(f"🎯 SCORE GLOBAL : {self.total_score}/100")
        print(f"📊 NIVEAU       : {self.get_level()}")
        print("="*60)

    def save(self):
        result = {
            "total_score": self.total_score,
            "level": self.get_level(),
            "details": self.details,
            "scores": self.scores
        }
        with open("score_results.json", "w") as f:
            json.dump(result, f, indent=4)
        print("\n[📄 PHANTOM SCORE] Résultats sauvegardés dans score_results.json")

if __name__ == "__main__":
    score = PhantomScore()
    score.load_data()
    score.score_attack_surface()
    score.score_vulnerabilities()
    score.score_detection()
    score.score_kill_chain()
    score.score_exploits()
    score.calculate_total()
    score.display()
    score.save()
