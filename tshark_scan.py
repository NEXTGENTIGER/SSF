#!/usr/bin/env python3
import subprocess
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

class TsharkCapture:
    def __init__(self, api_url: str = "http://localhost:8000/api/scan-results/"):
        """Initialise le capteur Tshark avec l'URL de l'API."""
        self.api_url = api_url
        self.results_dir = "results"
        os.makedirs(self.results_dir, exist_ok=True)

    def capture_packets(self, interface: str, packet_count: int = 10) -> Dict[str, Any]:
        """
        Capture des paquets réseau avec tshark.
        
        Args:
            interface: Interface réseau à surveiller
            packet_count: Nombre de paquets à capturer
            
        Returns:
            Dict contenant les résultats de la capture
        """
        logger.info(f"Capture de {packet_count} paquets sur {interface}...")
        
        cmd = [
            "tshark",
            "-i", interface,
            "-c", str(packet_count),
            "-T", "json",
            "-n",  # Ne pas résoudre les noms d'hôtes
            "-l",  # Mode ligne par ligne
            "-q"   # Mode silencieux
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            packets = json.loads(result.stdout)
            
            # Analyse basique des paquets
            analysis = self._analyze_packets(packets)
            
            return {
                "timestamp": datetime.datetime.now().isoformat(),
                "interface": interface,
                "packet_count": len(packets),
                "analysis": analysis,
                "raw_packets": packets
            }
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Erreur tshark : {e}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Erreur décodage JSON : {e}")
            raise

    def _analyze_packets(self, packets: list) -> Dict[str, Any]:
        """
        Analyse les paquets capturés pour extraire des informations utiles.
        
        Args:
            packets: Liste des paquets capturés
            
        Returns:
            Dict contenant l'analyse des paquets
        """
        analysis = {
            "protocols": {},
            "top_ips": {},
            "top_ports": {},
            "suspicious_patterns": []
        }

        for packet in packets:
            try:
                # Analyse des protocoles
                if "_source" in packet and "layers" in packet["_source"]:
                    layers = packet["_source"]["layers"]
                    
                    # Comptage des protocoles
                    for layer in layers:
                        if layer not in ["frame", "eth"]:
                            analysis["protocols"][layer] = analysis["protocols"].get(layer, 0) + 1
                    
                    # Analyse IP
                    if "ip" in layers:
                        src_ip = layers["ip"].get("ip.src", "unknown")
                        dst_ip = layers["ip"].get("ip.dst", "unknown")
                        analysis["top_ips"][src_ip] = analysis["top_ips"].get(src_ip, 0) + 1
                        analysis["top_ips"][dst_ip] = analysis["top_ips"].get(dst_ip, 0) + 1
                    
                    # Analyse des ports
                    if "tcp" in layers:
                        src_port = layers["tcp"].get("tcp.srcport", "unknown")
                        dst_port = layers["tcp"].get("tcp.dstport", "unknown")
                        analysis["top_ports"][src_port] = analysis["top_ports"].get(src_port, 0) + 1
                        analysis["top_ports"][dst_port] = analysis["top_ports"].get(dst_port, 0) + 1
                    
                    # Détection de patterns suspects
                    if "data" in layers:
                        data = layers["data"].get("data.data", "")
                        if any(pattern in data.lower() for pattern in ["password", "admin", "root"]):
                            analysis["suspicious_patterns"].append({
                                "packet_number": packet.get("_index", "unknown"),
                                "pattern": "Sensitive data detected"
                            })
            except Exception as e:
                logger.warning(f"Erreur lors de l'analyse du paquet : {e}")
                continue

        # Trier les résultats
        analysis["top_ips"] = dict(sorted(analysis["top_ips"].items(), key=lambda x: x[1], reverse=True)[:10])
        analysis["top_ports"] = dict(sorted(analysis["top_ports"].items(), key=lambda x: x[1], reverse=True)[:10])
        
        return analysis

    def save_results(self, results: Dict[str, Any]) -> str:
        """
        Sauvegarde les résultats dans un fichier JSON.
        
        Args:
            results: Résultats de la capture
            
        Returns:
            Chemin du fichier de résultats
        """
        timestamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
        output_file = os.path.join(self.results_dir, f"tshark_capture_{timestamp}.json")
        
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
            
        logger.info(f"Résultats sauvegardés dans : {output_file}")
        return output_file

    def send_to_api(self, results: Dict[str, Any]) -> bool:
        """
        Envoie les résultats à l'API.
        
        Args:
            results: Résultats de la capture
            
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
            logger.info("Résultats envoyés avec succès à l'API")
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Erreur lors de l'envoi à l'API : {e}")
            return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python tshark_scan.py <interface> [nombre_paquets]")
        sys.exit(1)

    interface = sys.argv[1]
    packet_count = int(sys.argv[2]) if len(sys.argv) > 2 else 10

    try:
        # Initialisation du capteur
        capturer = TsharkCapture()
        
        # Capture des paquets
        results = capturer.capture_packets(interface, packet_count)
        
        # Sauvegarde des résultats
        output_file = capturer.save_results(results)
        
        # Envoi à l'API
        if capturer.send_to_api(results):
            print("Analyse terminée avec succès")
        else:
            print("Analyse terminée mais échec de l'envoi à l'API")
            
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse : {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
