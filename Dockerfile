# Dockerfile pour forensic_analyzer.py avec YARA intégré inline
FROM python:3.11-slim

# Installation des outils système nécessaires
RUN apt-get update && apt-get install -y \
    yara \
    clamav \
    binwalk \
    exiftool \
    net-tools \
    iproute2 \
    binutils \
    libmagic1 \
    lsb-release \
    procps \
    util-linux \
    systemd \
 && rm -rf /var/lib/apt/lists/*

# Installation des bibliothèques Python nécessaires
RUN pip install --no-cache-dir python-magic-bin requests

# Dossier des fichiers à analyser
RUN mkdir /samples

# Copie du script principal uniquement (YARA est intégré inline)
COPY forensic_analyzer.py /app/forensic_analyzer.py
WORKDIR /app

# Commande par défaut
CMD ["python", "forensic_analyzer.py"]
