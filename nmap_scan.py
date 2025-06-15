#!/usr/bin/env python3
import nmap
import json
import sys
import os
import datetime
import requests
import logging
from typing import Dict, Any, Optional

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class NmapScanner:
    def __init__(self, api_url: str = "http://127.0.0.1:5000/api/v1/report/upload_json/"):
        """Initialise le scanner Nmap avec l'URL de l'API."""
        self.api_url = api_url
        self.results_dir = "results"
        os.makedirs(self.results_dir, exist_ok=True)
        self.scanner = nmap.PortScanner()

    def scan_target(self, target: str, options: str = "-sT -sV -O -A -p 1-1000") -> Dict[str, Any]:
        """
        Effectue un scan Nmap sur la cible spécifiée.
        
        Args:
            target: Adresse IP ou nom de domaine à scanner
            options: Options de scan Nmap
            
        Returns:
            Dict contenant les résultats du scan
        """
        logger.info(f"🔍 Scan en cours sur {target} avec options : {options}...")

        try:
            self.scanner.scan(target, arguments=options)
        except Exception as e:
            logger.error(f"❌ Erreur pendant le scan : {e}")
            raise

        if not self.scanner.all_hosts():
            logger.warning(f"⚠️ Aucun résultat pour {target}. Cible injoignable ou tous ports filtrés.")
            return {}

        results = {}
        for host in self.scanner.all_hosts():
            host_info = {
                "state": self.scanner[host].state(),
                "hostname": self.scanner[host].hostname(),
                "protocols": {},
                "osmatch": self.scanner[host].get('osmatch', [])
            }

            for proto in self.scanner[host].all_protocols():
                ports_info = {}
                for port in self.scanner[host][proto]:
                    ports_info[port] = {
                        "state": self.scanner[host][proto][port]['state'],
                        "name": self.scanner[host][proto][port].get('name', ''),
                        "product": self.scanner[host][proto][port].get('product', ''),
                        "version": self.scanner[host][proto][port].get('version', ''),
                        "extrainfo": self.scanner[host][proto][port].get('extrainfo', ''),
                        "reason": self.scanner[host][proto][port].get('reason', ''),
                        "conf": self.scanner[host][proto][port].get('conf', '')
                    }
                host_info["protocols"][proto] = ports_info

            results[host] = host_info

        return {
            "timestamp": datetime.datetime.now().isoformat(),
            "target": target,
            "scan_options": options,
            "results": results
        }

    def save_results(self, results: Dict[str, Any]) -> str:
        """
        Sauvegarde les résultats dans un fichier JSON.
        
        Args:
            results: Résultats du scan
            
        Returns:
            Chemin du fichier de résultats
        """
        timestamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
        target = results["target"].replace('.', '_')
        output_file = os.path.join(self.results_dir, f"nmap_scan_{target}_{timestamp}.json")
        
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
            
        logger.info(f"💾 Résultats sauvegardés dans : {output_file}")
        return output_file

    def send_to_api(self, results: Dict[str, Any]) -> bool:
        """
        Envoie les résultats à l'API.
        
        Args:
            results: Résultats du scan
            
        Returns:
            True si l'envoi a réussi, False sinon
        """
        try:
            response = requests.post(
                self.api_url,
                json=results,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            logger.info("✅ Résultats envoyés avec succès à l'API")
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Erreur lors de l'envoi à l'API : {e}")
            return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python nmap_scan.py <ip_ou_nom_domaine> [options_nmap]")
        sys.exit(1)

    target = sys.argv[1]
    options = sys.argv[2] if len(sys.argv) > 2 else "-sT -sV -O -A -p 1-1000"

    try:
        # Initialisation du scanner
        scanner = NmapScanner()
        
        # Exécution du scan
        results = scanner.scan_target(target, options)
        
        if not results:
            print("Aucun résultat obtenu du scan.")
            sys.exit(1)
        
        # Sauvegarde des résultats
        output_file = scanner.save_results(results)
        
        # Envoi à l'API
        if scanner.send_to_api(results):
            print("Analyse terminée avec succès")
        else:
            print("Analyse terminée mais échec de l'envoi à l'API")
            
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse : {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
