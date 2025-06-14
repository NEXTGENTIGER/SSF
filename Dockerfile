# Dockerfile minimal optimisé pour forensic_analyzer.py avec YARA intégré inline
FROM python:3.11-slim

# Installation minimale des outils requis
RUN apt-get update && apt-get install -y \
    yara \
    clamav \
    binwalk \
    exiftool \
    iproute2 \
    net-tools \
    libmagic1 \
    binutils \
 && rm -rf /var/lib/apt/lists/*

# Dépendances Python nécessaires
RUN pip install --no-cache-dir python-magic-bin requests

# Préparer environnement d'analyse
RUN mkdir /samples

# Copier le script unique
COPY forensic_analyzer.py /app/forensic_analyzer.py
WORKDIR /app

CMD ["python", "forensic_analyzer.py"]
