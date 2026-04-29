import nmap
import requests
import mysql.connector
import re
import nmap
import requests
import mysql.connector
import re
from datetime import datetime

# Ajout du chemin Nmap
import os
os.environ["PATH"] += os.pathsep + r"C:\Program Files (x86)\Nmap"
from datetime import datetime

db = mysql.connector.connect(
    host="localhost",
    port=3307,
    user="root",
    password="root123",
    database="vulndb"
)
cursor = db.cursor()

def get_cvss_score(cve_id):
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        response = requests.get(url, timeout=10)
        data = response.json()
        vuln = data['vulnerabilities'][0]['cve']
        score = vuln['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
        desc = vuln['descriptions'][0]['value']
        return score, desc
    except:
        return None, "Description non disponible"

def get_criticite(score):
    if score is None: return "Inconnue"
    if score >= 9.0: return "Critique"
    if score >= 7.0: return "Haute"
    if score >= 4.0: return "Moyenne"
    return "Faible"

def scanner_ip(cible):
    print(f"\n Scan de {cible} en cours...")
    nm = nmap.PortScanner()
    nm.scan(cible, arguments='-sV --script vuln')

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                service = nm[host][proto][port].get('name', 'inconnu')
                script_output = nm[host][proto][port].get('script', {})

                cve_id = None
                for script_name, output in script_output.items():
                    if 'CVE-' in output:
                        cves = re.findall(r'CVE-\d{4}-\d+', output)
                        if cves:
                            cve_id = cves[0]
                            break

                score, description = (None, "Aucune CVE detectee")
                if cve_id:
                    score, description = get_cvss_score(cve_id)

                criticite = get_criticite(score)

                cursor.execute("""
                    INSERT INTO vulnerabilites
                    (ip, port, service, cve_id, score_cvss, criticite, description)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (host, port, service, cve_id, score, criticite, description))
                db.commit()

                print(f"  {host}:{port} ({service}) | CVE: {cve_id} | CVSS: {score} | {criticite}")

scanner_ip("127.0.0.1")
print("\n Scan termine et sauvegarde en base !")
