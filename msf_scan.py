#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import time
import requests
from datetime import datetime
import subprocess
import re

# Configuration API
API_CONFIG = {
    'endpoint': 'http://127.0.0.1:5000/api/v1/report/upload_json/',
    'timeout': 30
}

def run_msf_command(command):
    """Exécute une commande Metasploit et retourne la sortie"""
    try:
        result = subprocess.run(
            ['msfconsole', '-q', '-x', command],
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Timeout lors de l'exécution de la commande"
    except Exception as e:
        return f"Erreur : {str(e)}"

def scan_target(target):
    """Exécute un scan Metasploit sur la cible"""
    try:
        print(f"▶ Début du scan Metasploit sur la cible : {target}")
        
        # Vérification de la cible
        print("⏳ Vérification de la cible...")
        ping_result = run_msf_command(f"ping -c 1 {target}")
        if "1 received" not in ping_result:
            print(f"⚠️ Attention : La cible {target} ne répond pas au ping")
        
        # Scan de ports
        print("🔍 Scan des ports...")
        port_scan = run_msf_command(f"""
        use auxiliary/scanner/portscan/tcp
        set RHOSTS {target}
        set PORTS 1-1000
        run
        exit
        """)
        
        # Scan de vulnérabilités
        print("🔍 Scan des vulnérabilités...")
        vuln_scan = run_msf_command(f"""
        use auxiliary/scanner/ssh/ssh_version
        set RHOSTS {target}
        run
        use auxiliary/scanner/smb/smb_version
        set RHOSTS {target}
        run
        use auxiliary/scanner/http/http_version
        set RHOSTS {target}
        run
        exit
        """)
        
        # Analyse des résultats
        open_ports = re.findall(r"(\d+)/tcp\s+open", port_scan)
        services = re.findall(r"(\d+)/tcp\s+open\s+(\w+)", port_scan)
        vulns = re.findall(r"\[\+\]\s+(.*?)\s+-\s+(.*?)(?:\n|$)", vuln_scan)
        
        # Construction du rapport
        results = {
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'scan_results': {
                'open_ports': open_ports,
                'services': [{'port': port, 'service': service} for port, service in services],
                'vulnerabilities': [{'name': name, 'details': details} for name, details in vulns]
            },
            'summary': {
                'total_ports': len(open_ports),
                'total_services': len(services),
                'total_vulns': len(vulns)
            }
        }
        
        return results
        
    except Exception as e:
        print(f"❌ Erreur lors du scan : {str(e)}")
        return {
            'error': str(e),
            'timestamp': datetime.now().isoformat(),
            'target': target
        }

def display_results(results):
    """Affiche les résultats du scan de manière formatée"""
    print("\n📊 Résultats du scan :")
    print("=" * 50)
    
    if "error" in results:
        print(f"❌ Erreur : {results['error']}")
        return
    
    if "scan_results" not in results:
        print("❌ Aucun résultat disponible")
        return
    
    scan = results["scan_results"]
    summary = results["summary"]
    
    print(f"\n📈 Résumé :")
    print(f"Ports ouverts : {summary['total_ports']}")
    print(f"Services détectés : {summary['total_services']}")
    print(f"Vulnérabilités trouvées : {summary['total_vulns']}")
    
    print(f"\n🔍 Ports ouverts :")
    for port in scan['open_ports']:
        print(f"• Port {port}")
    
    print(f"\n🔍 Services détectés :")
    for service in scan['services']:
        print(f"• Port {service['port']} : {service['service']}")
    
    print(f"\n🔍 Vulnérabilités :")
    for vuln in scan['vulnerabilities']:
        print(f"\n• {vuln['name']}")
        print(f"  Détails : {vuln['details']}")
        print("-" * 50)

def main():
    """Fonction principale"""
    if len(sys.argv) < 2:
        print("❌ Usage: python3 msf_scan.py <target> [--verbose]")
        sys.exit(1)
    
    target = sys.argv[1]
    verbose = "--verbose" in sys.argv
    
    # Exécution du scan
    results = scan_target(target)
    
    # Génération du nom de fichier
    safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"msf-result-{safe_target}-{timestamp}.json"
    
    # Sauvegarde des résultats
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    print(f"💾 Rapport sauvegardé dans : {filename}")
    
    # Affichage des résultats
    display_results(results)
    
    # Envoi à l'API
    print("⏳ Envoi des résultats à l'API...")
    try:
        response = requests.post(
            API_CONFIG['endpoint'],
            json=results,
            timeout=API_CONFIG['timeout']
        )
        response.raise_for_status()
        print("✅ Résultats envoyés avec succès à l'API")
    except Exception as e:
        print(f"❌ Erreur lors de l'envoi à l'API : {str(e)}")
        print("ℹ Les résultats sont disponibles localement dans le fichier JSON")

if __name__ == "__main__":
    main() 
