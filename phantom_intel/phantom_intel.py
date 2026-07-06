import json
import requests

# Services à ignorer (pas des logiciels réels)
SKIP_SERVICES = ["shell", "login", "exec", "unknown", "tcpwrapped"]

# Mapping service → vrai nom du logiciel
SERVICE_MAPPING = {
    "ftp": lambda v: f"vsftpd {v}" if v else "vsftpd",
    "ssh": lambda v: f"OpenSSH {v.split()[0]}" if v else "OpenSSH",
    "http": lambda v: f"Apache {v}" if v else "Apache",
    "smtp": lambda v: v.split()[0] if v else "smtp",
    "domain": lambda v: f"BIND {v}" if v else "BIND",
    "netbios-ssn": lambda v: f"Samba {v.split()[0]}" if v else "Samba",
    "rpcbind": lambda v: "rpcbind",
    "telnet": lambda v: "telnet",
}

def get_confidence(service, version):
    """Calcule le score de confiance de la recherche CVE"""
    if service in SERVICE_MAPPING and version:
        return 95
    elif service in SERVICE_MAPPING and not version:
        return 50
    elif version:
        return 40
    else:
        return 20

def get_search_query(service, version):
    """Retourne la requête de recherche optimisée"""
    if service in SERVICE_MAPPING:
        return SERVICE_MAPPING[service](version)
    return f"{service} {version}".strip()

def search_cve(query):
    """Cherche les CVEs sur NVD"""
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage=5"
        response = requests.get(url, timeout=10)
        data = response.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            metrics = cve.get("metrics", {})
            severity = "UNKNOWN"
            cvss_score = "N/A"
            if "cvssMetricV31" in metrics:
                severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                severity = metrics["cvssMetricV2"][0]["baseSeverity"]
                cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
            cves.append({
                "id": cve["id"],
                "severity": severity,
                "cvss_score": cvss_score,
                "description": cve["descriptions"][0]["value"][:300]
            })
        return cves
    except:
        return []

# Base de connaissances des services
SERVICE_KNOWLEDGE = {
    "vsftpd 2.3.4": {
        "attack_surface": "FTP service uses vsftpd 2.3.4. This version contains a known backdoor (CVE-2011-2523) that opens a shell on port 6200 when a smiley ':)' is sent in the username field.",
        "impact": "If exploited, the attacker gains a root shell without any authentication — full system compromise.",
        "mitre": ["T1190 — Exploit Public-Facing Application", "T1059 — Command and Scripting Interpreter"],
        "tactics": ["Initial Access", "Execution"],
        "recommendation": [
            "Upgrade immediately to vsftpd >= 2.3.5",
            "Disable anonymous FTP access",
            "Block port 21 from external access",
            "Monitor port 6200 for unexpected connections"
        ]
    },
    "OpenSSH": {
        "attack_surface": "SSH service exposes remote login. Older versions are susceptible to brute force and user enumeration attacks.",
        "impact": "An attacker could gain unauthorized access via brute force or exploit known SSH vulnerabilities.",
        "mitre": ["T1110 — Brute Force", "T1078 — Valid Accounts"],
        "tactics": ["Credential Access", "Initial Access"],
        "recommendation": [
            "Upgrade to OpenSSH >= 8.x",
            "Disable password authentication, use SSH keys only",
            "Enable fail2ban to block brute force attempts",
            "Restrict SSH access by IP"
        ]
    },
    "telnet": {
        "attack_surface": "Telnet transmits all data including credentials in plaintext over the network.",
        "impact": "Any attacker on the same network can capture usernames, passwords, and all session data via sniffing.",
        "mitre": ["T1040 — Network Sniffing", "T1078 — Valid Accounts"],
        "tactics": ["Credential Access", "Discovery"],
        "recommendation": [
            "Disable Telnet immediately",
            "Replace with SSH for all remote management",
            "Block port 23 at the firewall"
        ]
    },
    "Samba": {
        "attack_surface": "SMB/Samba service exposes network file sharing. Older versions contain critical remote code execution vulnerabilities.",
        "impact": "Attacker could execute arbitrary code remotely, perform lateral movement, or exfiltrate sensitive files.",
        "mitre": ["T1021.002 — SMB/Windows Admin Shares", "T1570 — Lateral Tool Transfer"],
        "tactics": ["Lateral Movement", "Collection"],
        "recommendation": [
            "Upgrade Samba to latest stable version",
            "Disable SMBv1 protocol",
            "Restrict SMB access to trusted IPs only",
            "Enable SMB signing"
        ]
    },
    "Apache": {
        "attack_surface": "HTTP web server Apache 2.2.x is outdated and contains multiple known vulnerabilities including remote denial of service.",
        "impact": "Attacker could crash the server, exploit web application vulnerabilities, or gain unauthorized access.",
        "mitre": ["T1190 — Exploit Public-Facing Application", "T1499 — Endpoint Denial of Service"],
        "tactics": ["Initial Access", "Impact"],
        "recommendation": [
            "Upgrade to Apache 2.4.x or later",
            "Disable unnecessary modules",
            "Enable ModSecurity WAF",
            "Hide server version information"
        ]
    },
    "default": {
        "attack_surface": "Service exposes an attack surface that could be exploited by a remote attacker.",
        "impact": "Potential unauthorized access or information disclosure.",
        "mitre": ["T1046 — Network Service Scanning"],
        "tactics": ["Discovery"],
        "recommendation": [
            "Review service necessity",
            "Apply latest security patches",
            "Restrict access by firewall rules"
        ]
    }
}

def generate_ai_analysis(service, version, cves, query):
    """Génère une analyse professionnelle en langage naturel"""
    
    # Trouver la bonne base de connaissance
    knowledge = None
    for key in SERVICE_KNOWLEDGE:
        if key.lower() in query.lower():
            knowledge = SERVICE_KNOWLEDGE[key]
            break
    if not knowledge:
        knowledge = SERVICE_KNOWLEDGE["default"]
    
    # Calculer la sévérité globale
    critical = [c for c in cves if c["severity"] == "CRITICAL"]
    high = [c for c in cves if c["severity"] == "HIGH"]
    
    if critical:
        risk_level = "🔴 CRITICAL RISK"
    elif high:
        risk_level = "🟠 HIGH RISK"
    elif cves:
        risk_level = "🟡 MEDIUM RISK"
    else:
        risk_level = "🟢 LOW RISK"
    
    # Construire l'analyse
    analysis = {
        "risk_level": risk_level,
        "attack_surface": knowledge["attack_surface"],
        "impact": knowledge["impact"],
        "mitre_techniques": knowledge["mitre"],
        "mitre_tactics": knowledge["tactics"],
        "recommendations": knowledge["recommendation"]
    }
    
    return analysis
def analyze(scan_file):
    with open(scan_file, 'r') as f:
        scan_data = json.load(f)
    
    intel_results = {}
    
    for host, data in scan_data.items():
        intel_results[host] = []
        print(f"\n[👻 PHANTOM INTEL] Analyse de {host}")
        print("=" * 60)
        
        for port in data["ports"]:
            service = port["service"]
            version = port["version"]
            
            # Ignorer les services non-logiciels
            if service in SKIP_SERVICES:
                print(f"[⏭️  SKIP] Port {port['port']} → {service} (non-software)")
                continue
            
            # Recherche optimisée
            query = get_search_query(service, version)
            confidence = get_confidence(service, version)
            
            print(f"\n[🌍 INTEL] Port {port['port']} → {query} (Confidence: {confidence}%)")
            
            cves = search_cve(query)
            ai_analysis = generate_ai_analysis(service, version, cves, query)
            result = {
                "port": port["port"],
                "service": service,
                "version": version,
                "search_query": query,
                "confidence": confidence,
                "cves": cves,
                "ai_analysis": ai_analysis
            }
            
            intel_results[host].append(result)
            
            if cves:
                for cve in cves[:3]:
                    print(f"  ⚠️  {cve['id']} — {cve['severity']} (CVSS: {cve['cvss_score']})")
            
            print(f"\n  📊 ANALYSIS:")
            print(f"  Risk     : {ai_analysis['risk_level']}")
            print(f"  Surface  : {ai_analysis['attack_surface'][:100]}")
            print(f"  Impact   : {ai_analysis['impact'][:100]}")
            print(f"  MITRE    : {', '.join(ai_analysis['mitre_techniques'])}")
            print(f"  Action   : {ai_analysis['recommendations'][0]}")
    
    return intel_results

def save(intel_results):
    with open("intel_results.json", "w") as f:
        json.dump(intel_results, f, indent=4)
    print("\n[📄 PHANTOM INTEL] Résultats sauvegardés dans intel_results.json")

if __name__ == "__main__":
    results = analyze("../phantom_red/scan_results.json")
    save(results)

