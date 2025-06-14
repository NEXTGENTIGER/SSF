FROM python:3.9-slim

# Installation des dépendances système
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    gcc \
    make \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    yara \
    exiftool \
    sleuthkit \
    libmagic1 \
    libyara-dev \
    git \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Configuration du répertoire de travail
WORKDIR /app

# Copie des fichiers nécessaires
COPY forensic_analyzer.py .
COPY malware.yar .

# Installation des dépendances Python
RUN pip3 install --no-cache-dir \
    requests \
    python-magic \
    yara-python \
    git+https://github.com/graingert/python-clamd.git@master \
    distorm3 \
    pycryptodome \
    pefile \
    capstone \
    volatility3

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
