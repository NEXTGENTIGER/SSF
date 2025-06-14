FROM python:3.9-slim

# Installation des dépendances système
RUN apt-get update && apt-get install -y \
    clamav \
    clamav-daemon \
    radare2 \
    exiftool \
    && rm -rf /var/lib/apt/lists/*

# Création du répertoire de travail
WORKDIR /app

# Copie des fichiers nécessaires
COPY forensic_analyzer.py .
COPY malware.yar .

# Installation des dépendances Python
RUN pip install --no-cache-dir \
    requests>=2.31.0 \
    python-magic>=0.4.27 \
    pefile>=2023.2.7 \
    yara-python>=4.3.1 \
    python-clamd>=0.4.1 \
    volatility3>=2.4.1 \
    r2pipe>=1.7.0 \
    exiftool>=0.5.5

# Création d'un utilisateur non-root
RUN useradd -m -s /bin/bash forensic
RUN chown -R forensic:forensic /app

# Configuration de ClamAV
RUN mkdir -p /run/clamav && \
    chown -R clamav:clamav /run/clamav && \
    freshclam

# Passage à l'utilisateur non-root
USER forensic

# Point d'entrée
ENTRYPOINT ["python", "forensic_analyzer.py"] 