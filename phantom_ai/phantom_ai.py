import json
import requests

class PhantomAI:
    def __init__(self):
        self.api_url = "https://api.groq.com/openai/v1/chat/completions"
        self.model = "llama-3.3-70b-versatile"
        self.api_key = "Groq API Key"

    def load_data(self):
        try:
            with open('../phantom_score/score_results.json') as f:
                self.score = json.load(f)
        except:
            self.score = {}
        try:
            with open('../phantom_map/kill_chain.json') as f:
                self.kill_chain = json.load(f)
        except:
            self.kill_chain = []
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

    def build_prompt(self):
        critical_cves = []
        for host, services in self.intel.items():
            for service in services:
                for cve in service.get('cves', []):
                    if cve.get('severity') in ['CRITICAL', 'HIGH']:
                        critical_cves.append(
                            cve['id'] + ' (' + cve['severity'] + ') - ' + 
                            service['service'] + ' ' + service['version']
                        )

        kill_chain_str = ""
        for t in self.kill_chain:
            kill_chain_str += "- " + t['id'] + " " + t['name'] + " [" + t['tactic'] + "]\n"

        cves_str = "\n".join(critical_cves[:5])

        prompt = (
            "You are a senior SOC analyst reviewing a cybersecurity simulation report.\n\n"
            "TARGET ASSESSMENT:\n"
            "- Security Score: " + str(self.score.get('total_score', 'N/A')) + "/100\n"
            "- Risk Level: " + str(self.score.get('level', 'N/A')) + "\n"
            "- Total Alerts Detected: " + str(len(self.alerts)) + "\n\n"
            "CRITICAL VULNERABILITIES FOUND:\n" + cves_str + "\n\n"
            "ATTACK KILL CHAIN DETECTED:\n" + kill_chain_str + "\n\n"
            "Please provide a professional security analysis report with:\n"
            "1. Executive Summary (2-3 sentences)\n"
            "2. Critical Findings (top 3 most dangerous issues)\n"
            "3. Attack Scenario (what an attacker could do)\n"
            "4. Immediate Recommendations (top 3 actions)\n"
            "5. Risk Assessment conclusion\n\n"
            "Be specific, professional, and actionable. Write in English."
        )
        return prompt

    def analyze(self):
        print("[🤖 PHANTOM AI] Generation de l analyse IA...")
        prompt = self.build_prompt()
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + self.api_key
        }
        data = {
            "model": self.model,
            "max_tokens": 1000,
            "messages": [
                {"role": "system", "content": "You are a senior SOC analyst."},
                {"role": "user", "content": prompt}
            ]
        }
        try:
            response = requests.post(self.api_url, headers=headers, json=data)
            result = response.json()
            self.analysis = result['choices'][0]['message']['content']
            print("\n" + "="*60)
            print("🤖 PHANTOM AI ANALYST REPORT")
            print("="*60)
            print(self.analysis)
            return self.analysis
        except Exception as e:
            print("[ERROR] " + str(e))
            print(str(response.text))
            self.analysis = "AI analysis unavailable"
            return self.analysis

    def save(self):
        with open("ai_analysis.json", "w") as f:
            json.dump({
                "analysis": self.analysis,
                "score": self.score.get('total_score'),
                "level": self.score.get('level')
            }, f, indent=4)
        print("\n[📄 PHANTOM AI] Analyse sauvegardee dans ai_analysis.json")

if __name__ == "__main__":
    ai = PhantomAI()
    ai.load_data()
    ai.analyze()
    ai.save()
