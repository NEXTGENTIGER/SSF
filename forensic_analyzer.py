#!/usr/bin/env python3
import os
import json
import subprocess
import platform
import requests
from datetime import datetime
import hashlib
import logging
import sys
import pkg_resources
import importlib
from typing import Dict, List, Any
import glob
import argparse

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def check_and_install_dependencies():
    """Vérifie et installe les dépendances nécessaires."""
    required_packages = {
        'requests': 'requests>=2.31.0',
        'python-magic': 'python-magic>=0.4.27',
        'pefile': 'pefile>=2023.2.7',
        'yara-python': 'yara-python>=4.3.1',
        'python-clamd': 'python-clamd>=0.4.1',
        'volatility3': 'volatility3>=2.4.1',
        'r2pipe': 'r2pipe>=1.7.0',
        'exiftool': 'exiftool>=0.5.5'
    }

    def install_package(package_name, package_spec):
        try:
            importlib.import_module(package_name)
            logger.info(f"{package_name} est déjà installé")
        except ImportError:
            logger.info(f"Installation de {package_name}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package_spec])
            logger.info(f"{package_name} installé avec succès")

    # Installation des packages Python
    for package_name, package_spec in required_packages.items():
        install_package(package_name, package_spec)

    # Installation des dépendances système selon l'OS
    if platform.system() == "Linux":
        try:
            # Vérification de ClamAV
            subprocess.run(['clamd', '--version'], capture_output=True, check=True)
            logger.info("ClamAV est déjà installé")
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.info("Installation de ClamAV...")
            subprocess.run(['sudo', 'apt-get', 'update'], check=True)
            subprocess.run(['sudo', 'apt-get', 'install', '-y', 'clamav', 'clamav-daemon'], check=True)
            logger.info("ClamAV installé avec succès")

        try:
            # Vérification de radare2
            subprocess.run(['r2', '-version'], capture_output=True, check=True)
            logger.info("radare2 est déjà installé")
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.info("Installation de radare2...")
            subprocess.run(['sudo', 'apt-get', 'install', '-y', 'radare2'], check=True)
            logger.info("radare2 installé avec succès")

    elif platform.system() == "Windows":
        logger.info("Sur Windows, veuillez installer manuellement :")
        logger.info("1. ClamAV : https://www.clamav.net/downloads")
        logger.info("2. radare2 : https://github.com/radareorg/radare2/releases")

    # Import des modules après installation
    global magic, pefile, yara, clamd, r2pipe, vol, interfaces, exiftool
    import magic
    import pefile
    import yara
    import clamd
    import r2pipe
    import volatility3.framework as vol
    from volatility3.framework import interfaces
    import exiftool

# Vérification et installation des dépendances au démarrage
check_and_install_dependencies()

class ForensicAnalyzer:
    def __init__(self, target_path: str, api_endpoint: str = None, yara_rules_path: str = None, host_machine: bool = False):
        """
        Initialise l'analyseur forensique.
        
        Args:
            target_path (str): Chemin du fichier ou dossier à analyser
            api_endpoint (str, optional): URL de l'API pour l'envoi des résultats
            yara_rules_path (str, optional): Chemin vers les règles YARA
            host_machine (bool): Si True, analyse les fichiers de la machine hôte
        """
        self.target_path = target_path
        self.api_endpoint = api_endpoint
        self.yara_rules_path = yara_rules_path
        self.host_machine = host_machine
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "target": target_path,
            "system_info": self._get_system_info(),
            "analysis_results": {}
        }
        
        # Initialisation des outils
        self._init_tools()

    def _init_tools(self):
        """Initialise les différents outils d'analyse."""
        try:
            # Initialisation de ClamAV
            if self.host_machine:
                # Connexion à ClamAV sur la machine hôte
                self.clamd_client = clamd.ClamdNetworkSocket(host='host.docker.internal', port=3310)
            else:
                self.clamd_client = clamd.ClamdUnixSocket()
        except Exception as e:
            logger.warning(f"ClamAV non disponible: {str(e)}")
            self.clamd_client = None

        # Chargement des règles YARA si spécifiées
        if self.yara_rules_path and os.path.exists(self.yara_rules_path):
            try:
                self.yara_rules = yara.compile(self.yara_rules_path)
            except Exception as e:
                logger.error(f"Erreur lors du chargement des règles YARA: {str(e)}")
                self.yara_rules = None
        else:
            self.yara_rules = None

    def _get_system_info(self) -> Dict[str, str]:
        """Récupère les informations système."""
        return {
            "os": platform.system(),
            "os_version": platform.version(),
            "python_version": platform.python_version(),
            "hostname": platform.node()
        }

    def analyze_mime_type(self) -> Dict[str, str]:
        """Analyse le type MIME du fichier."""
        try:
            mime = magic.Magic(mime=True)
            return {
                "mime_type": mime.from_file(self.target_path)
            }
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse MIME: {str(e)}")
            return {"error": str(e)}

    def analyze_pe_file(self) -> Dict[str, Any]:
        """Analyse la structure des fichiers PE (.exe)."""
        if not self.target_path.lower().endswith(('.exe', '.dll')):
            return {"error": "Le fichier n'est pas un fichier PE"}

        try:
            pe = pefile.PE(self.target_path)
            return {
                "machine_type": hex(pe.FILE_HEADER.Machine),
                "timestamp": datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat(),
                "sections": [{
                    "name": section.Name.decode().rstrip('\x00'),
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": hex(section.Misc_VirtualSize),
                    "raw_size": hex(section.SizeOfRawData)
                } for section in pe.sections],
                "imports": [{
                    "dll": entry.dll.decode(),
                    "functions": [imp.name.decode() for imp in entry.imports]
                } for entry in pe.DIRECTORY_ENTRY_IMPORT]
            }
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse PE: {str(e)}")
            return {"error": str(e)}

    def analyze_exiftool(self) -> Dict[str, Any]:
        """Analyse les métadonnées avec exiftool."""
        try:
            with exiftool.ExifTool() as et:
                metadata = et.get_metadata(self.target_path)
            return metadata
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse exiftool: {str(e)}")
            return {"error": str(e)}

    def analyze_yara(self) -> Dict[str, Any]:
        """Analyse le fichier avec les règles YARA."""
        if not self.yara_rules:
            # Utilisation des règles par défaut si aucune n'est spécifiée
            default_rules_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'malware.yar')
            if os.path.exists(default_rules_path):
                try:
                    self.yara_rules = yara.compile(default_rules_path)
                except Exception as e:
                    logger.error(f"Erreur lors du chargement des règles YARA par défaut: {str(e)}")
                    return {"error": str(e)}
            else:
                return {"error": "Aucune règle YARA trouvée"}

        try:
            matches = self.yara_rules.match(self.target_path)
            results = {
                "matches": [],
                "summary": {
                    "total_matches": len(matches),
                    "high_severity": 0,
                    "medium_severity": 0,
                    "low_severity": 0
                }
            }

            for match in matches:
                match_info = {
                    "rule": match.rule,
                    "description": match.meta.get('description', ''),
                    "severity": match.meta.get('severity', 'UNKNOWN'),
                    "strings": [{
                        "offset": s[0],
                        "matched": s[1].decode('utf-8', errors='ignore'),
                        "identifier": s[2]
                    } for s in match.strings]
                }
                results["matches"].append(match_info)
                
                # Mise à jour du résumé
                severity = match.meta.get('severity', 'UNKNOWN').upper()
                if severity == 'HIGH':
                    results["summary"]["high_severity"] += 1
                elif severity == 'MEDIUM':
                    results["summary"]["medium_severity"] += 1
                elif severity == 'LOW':
                    results["summary"]["low_severity"] += 1

            return results
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse YARA: {str(e)}")
            return {"error": str(e)}

    def analyze_clamav(self) -> Dict[str, Any]:
        """Analyse le fichier avec ClamAV."""
        if not self.clamd_client:
            return {"error": "ClamAV non disponible"}

        try:
            result = self.clamd_client.scan(self.target_path)
            return result
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse ClamAV: {str(e)}")
            return {"error": str(e)}

    def analyze_radare2(self) -> Dict[str, Any]:
        """Analyse le fichier avec radare2."""
        try:
            r2 = r2pipe.open(self.target_path)
            r2.cmd('aaa')  # Analyse complète
            
            info = {
                "file_info": r2.cmdj('ij'),
                "imports": r2.cmdj('iij'),
                "exports": r2.cmdj('iEj'),
                "strings": r2.cmdj('izj'),
                "functions": r2.cmdj('aflj')
            }
            
            r2.quit()
            return info
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse radare2: {str(e)}")
            return {"error": str(e)}

    def analyze_volatility(self) -> Dict[str, Any]:
        """Analyse le fichier avec Volatility3."""
        if not self.target_path.lower().endswith(('.dmp', '.raw', '.img')):
            return {"error": "Le fichier n'est pas un dump mémoire"}

        try:
            # Configuration de Volatility
            ctx = vol.Context()
            automagic = vol.automagic.Automagic()
            plugin_list = vol.plugins.get_plugin_list()
            
            # Analyse basique
            results = {}
            for plugin in ['windows.info.Info', 'windows.pslist.PsList']:
                try:
                    plugin_config = interfaces.configuration.HierarchicalDict()
                    plugin_config['automagic.LayerStacker.single_location'] = self.target_path
                    plugin = plugin_list[plugin](ctx, plugin_config)
                    results[plugin.__class__.__name__] = plugin.run()
                except Exception as e:
                    logger.error(f"Erreur avec le plugin {plugin}: {str(e)}")
            
            return results
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse Volatility: {str(e)}")
            return {"error": str(e)}

    def analyze_directory(self, directory_path: str) -> Dict[str, Any]:
        """Analyse tous les fichiers d'un répertoire."""
        results = {
            "directory": directory_path,
            "files_analyzed": 0,
            "suspicious_files": [],
            "analysis_results": {}
        }

        # Parcours récursif du répertoire
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    # Analyse du fichier
                    file_results = self.analyze_file(file_path)
                    results["files_analyzed"] += 1
                    
                    # Vérification des résultats suspects
                    if self._is_suspicious(file_results):
                        results["suspicious_files"].append({
                            "path": file_path,
                            "reason": self._get_suspicious_reason(file_results)
                        })
                    
                    results["analysis_results"][file_path] = file_results
                except Exception as e:
                    logger.error(f"Erreur lors de l'analyse de {file_path}: {str(e)}")

        return results

    def _is_suspicious(self, results: Dict[str, Any]) -> bool:
        """Détermine si les résultats d'analyse sont suspects."""
        # Vérification des règles YARA
        if "yara_analysis" in results.get("security_analysis", {}):
            yara_results = results["security_analysis"]["yara_analysis"]
            if "matches" in yara_results and yara_results["matches"]:
                return True

        # Vérification de ClamAV
        if "clamav_analysis" in results.get("security_analysis", {}):
            clamav_results = results["security_analysis"]["clamav_analysis"]
            if isinstance(clamav_results, dict) and clamav_results.get("status") == "FOUND":
                return True

        return False

    def _get_suspicious_reason(self, results: Dict[str, Any]) -> str:
        """Retourne la raison pour laquelle le fichier est suspect."""
        reasons = []

        if "yara_analysis" in results.get("security_analysis", {}):
            yara_results = results["security_analysis"]["yara_analysis"]
            if "matches" in yara_results and yara_results["matches"]:
                reasons.append("Correspondance avec des règles YARA")

        if "clamav_analysis" in results.get("security_analysis", {}):
            clamav_results = results["security_analysis"]["clamav_analysis"]
            if isinstance(clamav_results, dict) and clamav_results.get("status") == "FOUND":
                reasons.append(f"Virus détecté: {clamav_results.get('virus', 'Inconnu')}")

        return "; ".join(reasons) if reasons else "Raison inconnue"

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyse un fichier spécifique."""
        self.target_path = file_path
        return self.run_analysis()

    def run_analysis(self) -> Dict[str, Any]:
        """Exécute l'analyse complète."""
        logger.info(f"Démarrage de l'analyse de {self.target_path}")
        
        self.results["analysis_results"] = {
            "basic_info": {
                "hashes": self.calculate_hash(),
                "metadata": self.analyze_file_metadata(),
                "mime_type": self.analyze_mime_type(),
                "strings": self.analyze_strings()
            },
            "static_analysis": {
                "pe_analysis": self.analyze_pe_file(),
                "exiftool_analysis": self.analyze_exiftool()
            },
            "security_analysis": {
                "yara_analysis": self.analyze_yara(),
                "clamav_analysis": self.analyze_clamav()
            },
            "advanced_analysis": {
                "radare2_analysis": self.analyze_radare2(),
                "volatility_analysis": self.analyze_volatility()
            }
        }
        
        return self.results

    def calculate_hash(self) -> Dict[str, str]:
        """Calcule les hash MD5, SHA1 et SHA256 du fichier cible."""
        if not os.path.isfile(self.target_path):
            return {"error": "Le chemin spécifié n'est pas un fichier"}

        hashes = {}
        hash_functions = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256
        }

        try:
            with open(self.target_path, 'rb') as f:
                file_content = f.read()
                for hash_name, hash_func in hash_functions.items():
                    hashes[hash_name] = hash_func(file_content).hexdigest()
            return hashes
        except Exception as e:
            logger.error(f"Erreur lors du calcul des hash: {str(e)}")
            return {"error": str(e)}

    def analyze_file_metadata(self) -> Dict[str, Any]:
        """Analyse les métadonnées du fichier."""
        try:
            stat = os.stat(self.target_path)
            return {
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
                "permissions": oct(stat.st_mode)[-3:]
            }
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse des métadonnées: {str(e)}")
            return {"error": str(e)}

    def analyze_strings(self) -> List[str]:
        """Extrait les chaînes de caractères du fichier."""
        try:
            result = subprocess.run(
                ['strings', self.target_path],
                capture_output=True,
                text=True
            )
            return result.stdout.splitlines()
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction des chaînes: {str(e)}")
            return []

    def generate_report(self, output_path: str = None) -> str:
        """Génère un rapport au format JSON."""
        if output_path is None:
            output_path = f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=4, ensure_ascii=False)
            logger.info(f"Rapport généré avec succès: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport: {str(e)}")
            return None

    def send_to_api(self) -> bool:
        """Envoie les résultats à l'API spécifiée."""
        if not self.api_endpoint:
            logger.warning("Aucun endpoint API spécifié")
            return False

        try:
            response = requests.post(
                self.api_endpoint,
                json=self.results,
                headers={'Content-Type': 'application/json'}
            )
            response.raise_for_status()
            logger.info("Données envoyées avec succès à l'API")
            return True
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi à l'API: {str(e)}")
            return False

def main():
    parser = argparse.ArgumentParser(description='Analyseur Forensique')
    parser.add_argument('target', help='Chemin du fichier ou répertoire à analyser')
    parser.add_argument('--api', default='http://127.0.0.1:5000/api/v1/report/upload_json/',
                      help='URL de l\'API pour l\'envoi des résultats')
    parser.add_argument('--yara-rules', default='malware.yar',
                      help='Chemin vers les règles YARA')
    parser.add_argument('--host', action='store_true',
                      help='Analyser les fichiers de la machine hôte')
    parser.add_argument('--output', default='reports',
                      help='Répertoire de sortie pour les rapports')

    args = parser.parse_args()

    # Création du répertoire de sortie
    os.makedirs(args.output, exist_ok=True)

    # Initialisation de l'analyseur
    analyzer = ForensicAnalyzer(
        args.target,
        args.api,
        args.yara_rules,
        args.host
    )

    # Analyse
    if os.path.isdir(args.target):
        results = analyzer.analyze_directory(args.target)
    else:
        results = analyzer.analyze_file(args.target)

    # Génération du rapport
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_path = os.path.join(args.output, f'forensic_report_{timestamp}.json')
    
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

    print(f"Rapport généré: {report_path}")

    # Envoi à l'API
    if analyzer.send_to_api():
        print("Rapport envoyé avec succès à l'API")
    else:
        print("Erreur lors de l'envoi du rapport à l'API")

if __name__ == "__main__":
    main() 