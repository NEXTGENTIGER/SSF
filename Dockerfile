# Dockerfile
FROM python:3.11-slim

# Installer les dépendances système
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
 && apt-get clean

# Installer les dépendances Python
RUN pip install --no-cache-dir python-magic-bin requests

# Créer dossier d'analyse
RUN mkdir /samples

# Copier le script et les règles yara
COPY forensic_analyzer.py /app/forensic_analyzer.py
COPY yara_rules.yar /app/yara_rules.yar
WORKDIR /app

CMD ["python", "forensic_analyzer.py"]
