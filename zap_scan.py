#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import time
import requests
from datetime import datetime
from zapv2 import ZAPv2

# Configuration API
API_CONFIG = {
    'endpoint': 'http://127.0.0.1:5000/api/v1/report/upload_json/',
    'timeout': 30
}

# Configuration ZAP
ZAP_CONFIG = {
    'host': os.getenv('ZAP_HOST', 'localhost'),
    'port': os.getenv('ZAP_PORT', '8080'),
    'api_key': os.getenv('ZAP_API_KEY', 'changeme')
}

def scan_target(target_url):
    """Exécute un scan ZAP sur l'URL cible"""
    try:
        # Connexion à ZAP
        zap = ZAPv2(apikey=ZAP_CONFIG['api_key'],
                    proxies={'http': f'http://{ZAP_CONFIG["host"]}:{ZAP_CONFIG["port"]}',
                            'https': f'http://{ZAP_CONFIG["host"]}:{ZAP_CONFIG["port"]}'})
        
        print("⏳ Vérification de l'accessibilité de la cible...")
        # Vérifier si la cible est accessible
        try:
            zap.urlopen(target_url)
        except Exception as e:
            print(f"⚠️ Attention : Impossible d'accéder à la cible directement : {str(e)}")
            print("ℹ️ Le scan continuera via le proxy ZAP...")
        
        print("🚀 Lancement du scan actif...")
        # Lancer le scan actif
        scan_id = zap.ascan.scan(target_url)
        
        # Suivre la progression
        while True:
            progress = int(zap.ascan.status(scan_id))
            print(f"⏳ Progression du scan : {progress}%")
            if progress >= 100:
                break
            time.sleep(5)
        
        print("✅ Scan terminé. Récupération des résultats...")
        # Récupérer les alertes
        alerts = zap.core.alerts()
        
        # Récupérer les statistiques
        stats = {
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Informational': 0
        }
        
        for alert in alerts:
            risk = alert.get('risk', 'Informational')
            stats[risk] = stats.get(risk, 0) + 1
        
        return {
            'timestamp': datetime.now().isoformat(),
            'target': target_url,
            'alerts': alerts,
            'summary': {
                'total_alerts': len(alerts),
                'risk_distribution': stats
            }
        }
        
    except Exception as e:
        print(f"❌ Erreur lors du scan : {str(e)}")
        return {
            'error': str(e),
            'timestamp': datetime.now().isoformat(),
            'target': target_url
        }

def display_results(results):
    """Affiche les résultats du scan"""
    print("\n📊 Résultats du scan :")
    print("=" * 50)
    
    if "error" in results:
        print(f"❌ Erreur : {results['error']}")
        return
    
    summary = results["scan"]["summary"]
    print(f"\n📈 Résumé :")
    print(f"Total des alertes : {summary['total_alerts']}")
    for risk, count in summary['risk_distribution'].items():
        print(f"{risk.capitalize()} : {count}")
    
    print(f"\n🔍 Détail des alertes :")
    for alert in results["scan"]["alerts"]:
        print("\n" + "=" * 50)
        print(f"Risque : {alert['risk']}")
        print(f"Confiance : {alert['confidence']}")
        print(f"Description : {alert['description']}")
        print(f"URL : {alert['url']}")
        if 'solution' in alert:
            print(f"Solution : {alert['solution']}")

def main():
    """Fonction principale"""
    if len(sys.argv) < 2:
        print("❌ Usage: python3 zap_scan.py <url> [--verbose]")
        sys.exit(1)
    
    target = sys.argv[1]
    verbose = "--verbose" in sys.argv
    
    print(f"▶ Début du scan ZAP sur la cible : {target}")
    
    # Exécution du scan
    results = scan_target(target)
    
    # Génération du nom de fichier
    safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"zap-result-{safe_target}-{timestamp}.json"
    
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
