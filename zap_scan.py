#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import datetime
import json
import requests
from zapv2 import ZAPv2

# Configuration API
API_CONFIG = {
    'endpoint': 'http://127.0.0.1:5000/api/v1/report/upload_json/',
    'timeout': 30
}

# Configuration ZAP
ZAP_CONFIG = {
    'host': os.getenv('ZAP_HOST', 'zap'),
    'port': os.getenv('ZAP_PORT', '8080'),
    'api_key': os.getenv('ZAP_API_KEY', '')
}

def scan_target(target_url):
    """Effectue un scan ZAP sur l'URL cible"""
    results = {
        "timestamp": datetime.datetime.now().isoformat(),
        "target": target_url,
        "scan": {}
    }
    
    try:
        # Initialisation de ZAP
        zap = ZAPv2(
            apikey=ZAP_CONFIG['api_key'],
            proxies={
                "http": f"http://{ZAP_CONFIG['host']}:{ZAP_CONFIG['port']}",
                "https": f"http://{ZAP_CONFIG['host']}:{ZAP_CONFIG['port']}"
            }
        )
        
        # Vérification de l'accessibilité
        print("⏳ Vérification de l'accessibilité de la cible...")
        zap.urlopen(target_url)
        time.sleep(5)
        
        # Lancement du scan actif
        print("🚀 Lancement du scan actif...")
        scan_id = zap.ascan.scan(target_url)
        
        # Suivi de la progression
        while int(zap.ascan.status(scan_id)) < 100:
            progress = zap.ascan.status(scan_id)
            print(f"🔄 Progression du scan : {progress}%")
            time.sleep(5)
        
        # Récupération des résultats
        print("✅ Scan terminé. Récupération des résultats...")
        alerts = zap.core.alerts(baseurl=target_url)
        
        # Ajout des résultats au rapport
        results["scan"] = {
            "alerts": alerts,
            "summary": {
                "total_alerts": len(alerts),
                "high_alerts": len([a for a in alerts if a['risk'] == 'High']),
                "medium_alerts": len([a for a in alerts if a['risk'] == 'Medium']),
                "low_alerts": len([a for a in alerts if a['risk'] == 'Low']),
                "info_alerts": len([a for a in alerts if a['risk'] == 'Informational'])
            }
        }
        
        return results
    except Exception as e:
        return {"error": str(e)}

def main():
    if len(sys.argv) < 2:
        print("❌ Usage : python3 zap_scan.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    
    print(f"▶️ Début du scan ZAP sur la cible : {target}")
    
    # Exécution du scan
    results = scan_target(target)
    
    # Sauvegarde locale
    safe_target = target.replace("https://", "").replace("http://", "").replace("/", "_")
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"zap-result-{safe_target}-{timestamp}.json"
    
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"💾 Rapport sauvegardé dans : {filename}")
    
    # Envoi à l'API
    print("⏳ Envoi des résultats à l'API...")
    try:
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        response = requests.post(
            API_CONFIG['endpoint'],
            json=results,
            headers=headers,
            timeout=API_CONFIG['timeout']
        )
        response.raise_for_status()
        print("✅ Résultats envoyés avec succès à l'API")
    except Exception as e:
        print(f"❌ Erreur lors de l'envoi à l'API : {str(e)}")

if __name__ == "__main__":
    main() 
