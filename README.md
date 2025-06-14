# Analyseur Forensique Avancé

Ce script Python permet d'effectuer des analyses forensiques complètes sur des fichiers en utilisant une suite d'outils gratuits et open source. Il peut analyser à la fois les fichiers dans le conteneur Docker et sur la machine hôte.

## Fonctionnalités

### 1. Analyse de base
- Calcul des hash (MD5, SHA1, SHA256)
- Analyse des métadonnées des fichiers
- Extraction des chaînes de caractères
- Détection du type MIME

### 2. Analyse statique
- Analyse des fichiers PE (.exe) avec pefile
- Extraction des métadonnées avec exiftool
- Analyse des chaînes de caractères
- Analyse approfondie avec radare2

### 3. Analyse de sécurité
- Scan avec règles YARA personnalisées
- Analyse antivirus avec ClamAV
- Détection de signatures malveillantes
- Détection de comportements suspects

### 4. Analyse avancée
- Analyse de mémoire avec Volatility3
- Analyse de code avec radare2
- Génération de rapports détaillés au format JSON
- Envoi automatique des résultats à une API

## Prérequis

### Système
- Docker et Docker Compose
- ClamAV installé sur la machine hôte (pour l'analyse des fichiers hôtes)
- radare2 installé sur la machine hôte (pour l'analyse des fichiers hôtes)

## Installation

1. Clonez ce dépôt :
```bash
git clone <repository-url>
cd <repository-name>
```

2. Créez le répertoire pour les rapports :
```bash
mkdir -p reports
```

## Utilisation

### Analyse de fichiers sur la machine hôte

1. Analyser un fichier spécifique :
```bash
TARGET_PATH=/chemin/vers/fichier docker-compose up
```

2. Analyser un répertoire :
```bash
TARGET_PATH=/chemin/vers/dossier docker-compose up
```

3. Analyser avec des options spécifiques :
```bash
TARGET_PATH=/chemin/vers/fichier docker-compose run --rm forensic-analyzer python forensic_analyzer.py /host/chemin/vers/fichier --host --yara-rules custom_rules.yar
```

### Options disponibles

- `--api` : URL de l'API pour l'envoi des résultats (défaut: http://127.0.0.1:5000/api/v1/report/upload_json/)
- `--yara-rules` : Chemin vers les règles YARA (défaut: malware.yar)
- `--host` : Analyser les fichiers de la machine hôte
- `--output` : Répertoire de sortie pour les rapports (défaut: reports)

## Format du rapport

Le rapport est généré au format JSON et contient les sections suivantes :

```json
{
    "timestamp": "2024-03-14T12:00:00",
    "target": "/chemin/vers/fichier",
    "system_info": {
        "os": "Linux",
        "os_version": "5.4.0",
        "python_version": "3.8.5"
    },
    "analysis_results": {
        "basic_info": {
            "hashes": { "md5": "...", "sha1": "...", "sha256": "..." },
            "metadata": { "size": 1024, "created": "...", "modified": "..." },
            "mime_type": "application/x-dosexec",
            "strings": ["chaîne1", "chaîne2"]
        },
        "static_analysis": {
            "pe_analysis": { "sections": [...], "imports": [...] },
            "exiftool_analysis": { ... }
        },
        "security_analysis": {
            "yara_analysis": {
                "matches": [...],
                "summary": {
                    "total_matches": 1,
                    "high_severity": 1,
                    "medium_severity": 0,
                    "low_severity": 0
                }
            },
            "clamav_analysis": { ... }
        },
        "advanced_analysis": {
            "radare2_analysis": { ... },
            "volatility_analysis": { ... }
        }
    }
}
```

## Structure des fichiers

```
.
├── Dockerfile              # Configuration Docker
├── docker-compose.yml      # Configuration Docker Compose
├── forensic_analyzer.py    # Script principal
├── malware.yar            # Règles YARA par défaut
├── README.md              # Documentation
└── reports/               # Répertoire des rapports générés
```

## Sécurité

- Le système de fichiers hôte est monté en lecture seule
- Les analyses sont effectuées dans un conteneur isolé
- Les rapports sont générés localement avant l'envoi à l'API
- Utilisez HTTPS pour l'envoi des données à l'API
- Ne partagez pas les rapports contenant des informations sensibles

## Dépannage

1. Si ClamAV n'est pas détecté :
   - Vérifiez que ClamAV est installé sur la machine hôte
   - Vérifiez que le daemon ClamAV est en cours d'exécution
   - Vérifiez les permissions du socket ClamAV

2. Si radare2 n'est pas détecté :
   - Vérifiez que radare2 est installé sur la machine hôte
   - Vérifiez que radare2 est dans votre PATH

3. Si Volatility3 ne fonctionne pas :
   - Vérifiez que le fichier est bien un dump mémoire
   - Assurez-vous d'avoir les plugins nécessaires installés

4. Problèmes de permissions :
   - Vérifiez les permissions du répertoire cible
   - Vérifiez les permissions du répertoire reports
   - Utilisez sudo si nécessaire pour l'analyse de certains répertoires système 