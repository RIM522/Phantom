# 👻 PHANTOM
### Real-time Attack Simulation & Defense Intelligence Platform

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Metasploit](https://img.shields.io/badge/Metasploit-6.x-red)
![Suricata](https://img.shields.io/badge/Suricata-8.x-orange)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-purple)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 🎯 Description

**Phantom** est une plateforme complète de simulation de cyberattaques et de défense intelligente. Elle simule des attaques réelles contre un environnement contrôlé, les détecte en temps réel, reconstitue automatiquement la kill chain MITRE ATT&CK, et génère un rapport d'analyse IA professionnel.

> *"Ce que les outils commerciaux font pour des milliers d'euros, Phantom le fait gratuitement, de façon reproductible, et en moins de 5 minutes."*

---

## 🏗️ Architecture
👻 PHANTOM
 🔴 Phantom Red        → Attaques automatisées (Nmap, Metasploit, Hydra)

 🌍 Phantom Intel      → CVE Intelligence (NVD API)

 🔵 Phantom Blue       → Détection temps réel (Suricata)

 🧠 Phantom Blue ML    → Détection d'anomalies (Isolation Forest)

 🗺️ Phantom Map        → Kill Chain MITRE ATT&CK

 📊 Phantom Board      → Dashboard live (Flask + WebSockets)

 🛡️ Phantom Score      → Score de maturité sécurité

 🤖 Phantom AI Analyst → Rapport IA (Groq API / LLama)

 📄 Phantom Report     → Rapport PDF automatique

---

## 🌐 Environnement
┌─────────────────────────────────────────────────┐
│           Réseau isolé phantom-network           │
│                                                  │
│  KALI (.10)    METASPLOITABLE (.20)  UBUNTU (.50)│
│  Phantom Red → La victime        ← Phantom Blue  │
└─────────────────────────────────────────────────
| Machine | IP | Rôle |
|---|---|---|
| Kali Linux | 192.168.100.10 | Phantom Red (attaquant) |
| Metasploitable 2 | 192.168.100.20 | Cible vulnérable |
| Ubuntu Desktop | 192.168.100.50 | Phantom Blue (défenseur) |

---

## 🚀 Lancement rapide

```bash
# Sur Kali — Lance toute la simulation
sudo python3 phantom_orchestrator.py

# Sur Ubuntu — Lance le dashboard
source phantom-env/bin/activate
python3 phantom_board/app.py
# Ouvre http://127.0.0.1:5000
```

---

## 🔴 Phantom Red — Modules d'attaque

### Scanner (Nmap)
```bash
sudo python3 phantom_red/scanner.py
```
→ Scanne les 1000 premiers ports de la cible
→ Détecte les services et versions
→ Tague chaque port avec MITRE T1046

### Exploiter (Metasploit)
```bash
sudo python3 phantom_red/exploiter.py
```
→ Exploite CVE-2011-2523 (vsftpd backdoor)
→ Obtient un shell ROOT en < 30 secondes
→ Exploite CVE-2007-2447 (Samba)

### Bruteforce (Hydra/Metasploit)
```bash
sudo python3 phantom_red/bruteforce.py
```
→ Brute force SSH et FTP
→ Trouve les credentials faibles
→ Technique MITRE T1110

---

## 🌍 Phantom Intel — CVE Intelligence

```bash
python3 phantom_intel/phantom_intel.py
```

→ Interroge l'API NVD officielle
→ Trouve les CVEs pour chaque service
→ Calcule un score de confiance
→ Génère une analyse professionnelle

**Résultats clés sur Metasploitable :**
| Service | CVE | Sévérité | CVSS |
|---|---|---|---|
| vsftpd 2.3.4 | CVE-2011-2523 | CRITICAL | 9.8 |
| telnet | CVE-1999-0073 | HIGH | 10.0 |
| BIND 9.4.2 | CVE-2008-0122 | HIGH | 10.0 |
| Samba 3.x | CVE-2004-0186 | HIGH | 7.2 |

---

## 🔵 Phantom Blue — Détection & Réponse

```bash
python3 phantom_blue/phantom_blue.py
```

→ Parse les alertes Suricata en temps réel
→ Calcule la sévérité (CRITICAL/HIGH/MEDIUM/LOW)
→ Mappe sur MITRE ATT&CK automatiquement
→ Sauvegarde dans blue_alerts.json

---

## 🗺️ Phantom Map — Kill Chain MITRE

```bash
python3 phantom_map/phantom_map.py
```

→ Reconstitue la kill chain automatiquement
→ Trie par ordre tactique MITRE
DISCOVERY      → T1046 Network Service Scanning
INITIAL-ACCESS → T1190 Exploit Public-Facing App
CREDENTIAL     → T1110 Brute Force
---

## 📊 Phantom Board — Dashboard Live

```bash
python3 phantom_board/app.py
# http://127.0.0.1:5000
```

**Features :**
- Score Red vs Blue animé en temps réel
- Kill Chain MITRE interactive
- Alertes détectées live
- Ports découverts
- CVEs critiques
- Mise à jour automatique toutes les 5 secondes

---

## 🛡️ Phantom Score — Score de Maturité

```bash
python3 phantom_score/phantom_score.py
```
Attack Surface     : 10/100 ❌
Vulnerabilities    : 20/100 ❌
Detection          : 50/100 ⚠️
Kill Chain         : 60/100 ❌
Exploit Resistance : 10/100 ❌
SCORE GLOBAL : 26/100 🔴 CRITICAL
---

## 🤖 Phantom AI Analyst

```bash
python3 phantom_ai/phantom_ai.py
```

→ Utilise Groq API (LLama 3.3 70B)
→ Génère un rapport professionnel :
  - Executive Summary
  - Critical Findings
  - Attack Scenario
  - Recommendations
  - Risk Assessment

---

## 📄 Phantom Report — PDF Automatique

```bash
python3 phantom_report/phantom_report.py
```

→ Génère un rapport PDF 3 pages
→ Inclut score, CVEs, kill chain, alertes
→ Rapport IA intégré
→ En 1 clic !

---

## 🛠️ Stack Technologique

| Catégorie | Technologies |
|---|---|
| Langage | Python 3.10+ |
| Red Team | Nmap, Metasploit, Hydra |
| Blue Team | Suricata IDS |
| Intelligence | NVD API, MITRE ATT&CK |
| Dashboard | Flask, Socket.IO |
| IA | Groq API (LLama 3.3 70B) |
| Rapport | ReportLab PDF |
| Infra | VirtualBox, réseau interne |

---

## 📦 Installation

```bash
# Cloner le repo
git clone https://github.com/RIM522/Phantom.git
cd Phantom

# Créer l'environnement virtuel
python3 -m venv phantom-env
source phantom-env/bin/activate

# Installer les dépendances
pip install python-nmap flask flask-socketio requests scapy
pip install scikit-learn reportlab attackcti
```

---

## ⚠️ Avertissement

> Ce projet est destiné **uniquement à des fins éducatives** dans un environnement isolé et contrôlé. N'utilisez jamais ces outils sur des systèmes sans autorisation explicite.

---

## 👩‍💻 Auteur

**Rym** — Étudiante en Cybersécurité
- GitHub : [@RIM522](https://github.com/RIM522)

---

## 📄 Licence

MIT License — voir [LICENSE](LICENSE) pour plus de détails.



