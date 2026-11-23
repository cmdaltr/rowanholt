# Elrond Forensics Engine Dockerfile
# Complete forensics workstation with all tools integrated

# Stage 1: Base image with forensic tools
FROM ubuntu:22.04 AS base

LABEL maintainer="Elrond Team"
LABEL description="Elrond Digital Forensics Automation Tool - Complete Forensics Workstation"
LABEL version="2.2.0"

# Prevent interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV TZ=UTC

# Install system dependencies and forensic tools
RUN apt-get update && apt-get install -y \
    # Python and build tools (using system python3 = 3.10 on Ubuntu 22.04)
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    python3-setuptools \
    python3-wheel \
    build-essential \
    gcc \
    g++ \
    make \
    cmake \
    pkg-config \
    autoconf \
    automake \
    libtool \
    # Forensic imaging tools
    ewf-tools \
    libewf-dev \
    afflib-tools \
    libafflib-dev \
    sleuthkit \
    # Volume Shadow Copy tools
    libvshadow-utils \
    # File system tools
    ntfs-3g \
    exfat-fuse \
    exfatprogs \
    hfsutils \
    hfsprogs \
    e2fsprogs \
    xfsprogs \
    # Mounting tools
    fuse3 \
    libfuse3-dev \
    kpartx \
    # Archive tools
    p7zip-full \
    unzip \
    zip \
    bzip2 \
    xz-utils \
    plocate \
    # Network tools
    curl \
    wget \
    netcat \
    # Hash tools
    md5deep \
    ssdeep \
    # Hex editors and viewers
    xxd \
    bsdmainutils \
    # Text processing
    jq \
    xmlstarlet \
    # System utilities
    git \
    sudo \
    vim \
    less \
    tree \
    file \
    lsof \
    strace \
    ca-certificates \
    gnupg \
    lsb-release \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create elrond user with sudo privileges
RUN useradd -m -s /bin/bash -u 1000 elrond && \
    echo "elrond ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    mkdir -p /home/elrond/.ssh && \
    chown -R elrond:elrond /home/elrond

# Stage 2: Install Python forensic tools
FROM base AS forensic-tools

WORKDIR /tmp

# Upgrade pip and install build tools
RUN python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel

# Install plaso dependencies from apt
RUN apt-get update && apt-get install -y \
    libbde-utils \
    libesedb-utils \
    libevt-utils \
    libevtx-utils \
    libfsapfs-utils \
    libfsntfs-utils \
    libfvde-utils \
    libfwnt-utils \
    libluksde-utils \
    libqcow-utils \
    libsigscan-utils \
    libsmdev-utils \
    libsmraw-utils \
    libvhdi-utils \
    libvmdk-utils \
    libvsapm-utils \
    libvsgpt-utils \
    libvshadow-utils \
    libvslvm-utils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* || true

# Install volatility3 (memory analysis)
RUN pip3 install --no-cache-dir \
    volatility3 \
    pycryptodome \
    pycryptodomex

# Install plaso (timeline analysis) from pip
RUN pip3 install --no-cache-dir plaso || true

# Install core forensic Python packages
RUN pip3 install --no-cache-dir \
    python-registry \
    regipy \
    dissect \
    dissect.cstruct \
    dissect.target \
    dfvfs \
    pytsk3 \
    pefile \
    yara-python \
    oletools \
    pyopenssl

# Install Artemis - comprehensive Rust-based forensic parser
# Supports: prefetch, eventlogs, mft, shimcache, amcache, registry, userassist,
# shellbags, usnjrnl, bits, srum, search, tasks, services, shortcuts, jumplists,
# recyclebin, outlook, wmipersist - all with --alt-file/--alt-dir for offline analysis
RUN ARTEMIS_VERSION="v0.16.0" && \
    ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        ARTEMIS_ARCH="x86_64-unknown-linux-gnu"; \
    elif [ "$ARCH" = "aarch64" ]; then \
        ARTEMIS_ARCH="aarch64-unknown-linux-gnu"; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    curl -L -o /tmp/artemis.tar.gz "https://github.com/puffyCid/artemis/releases/download/${ARTEMIS_VERSION}/artemis-${ARTEMIS_VERSION}-${ARTEMIS_ARCH}.tar.gz" && \
    tar -xzf /tmp/artemis.tar.gz -C /tmp && \
    cp /tmp/artemis-${ARTEMIS_VERSION}-${ARTEMIS_ARCH}/artemis /usr/local/bin/ && \
    chmod +x /usr/local/bin/artemis && \
    rm -rf /tmp/artemis.tar.gz /tmp/artemis-${ARTEMIS_VERSION}-${ARTEMIS_ARCH}

# Install additional analysis tools (rekall-core removed due to Python 2 incompatibility)
RUN pip3 install --no-cache-dir \
    libscca-python \
    libesedb-python \
    libevtx-python \
    libevt-python \
    libfwnt-python \
    libfwsi-python \
    liblnk-python \
    libmsiecf-python \
    libolecf-python \
    libregf-python \
    libsigscan-python \
    libsmraw-python \
    libvshadow-python \
    libvslvm-python \
    construct \
    unicodecsv || true

# Install network and malware analysis tools
RUN pip3 install --no-cache-dir \
    dpkt \
    scapy \
    pyshark \
    requests \
    beautifulsoup4 \
    lxml

# Install data processing and analysis
RUN pip3 install --no-cache-dir \
    pandas \
    numpy \
    matplotlib \
    openpyxl \
    xlrd

# Install Splunk (pinned) and Elastic (8.x) during build
# Splunk direct download requires a concrete version/build; using 9.1.1 here.
ARG SPLUNK_VERSION=9.1.1
ARG SPLUNK_BUILD=64e843ea36b1
ARG SPLUNK_TGZ_URL=https://download.splunk.com/products/splunk/releases/${SPLUNK_VERSION}/linux/splunk-${SPLUNK_VERSION}-${SPLUNK_BUILD}-Linux-x86_64.tgz
RUN set -eux; \
    cd /tmp; \
    curl -L -o splunk.tgz "$SPLUNK_TGZ_URL"; \
    tar -xzf splunk.tgz -C /opt; \
    rm splunk.tgz; \
    ln -s /opt/splunk/bin/splunk /usr/local/bin/splunk

RUN set -eux; \
    apt-get update; \
    apt-get install -y gnupg apt-transport-https; \
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic-archive-keyring.gpg; \
    echo "deb [signed-by=/usr/share/keyrings/elastic-archive-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list; \
    apt-get update; \
    apt-get install -y elasticsearch kibana; \
    rm -rf /var/lib/apt/lists/*

# Stage 3: Application stage
FROM forensic-tools AS app

# Set working directory
WORKDIR /opt/elrond

# Copy application code
COPY --chown=elrond:elrond . /opt/elrond/

# Install Elrond Python dependencies if requirements file exists
RUN if [ -f requirements.txt ]; then \
        pip3 install --no-cache-dir -r requirements.txt; \
    fi

# Install web backend dependencies for integrated operation
RUN if [ -f web/backend/requirements.txt ]; then \
        pip3 install --no-cache-dir -r web/backend/requirements.txt; \
    fi

# Create necessary directories with proper permissions
RUN mkdir -p \
    /mnt/elrond_images \
    /mnt/elrond_mount00 \
    /mnt/elrond_mount01 \
    /mnt/elrond_mount02 \
    /mnt/elrond_mount03 \
    /mnt/elrond_mount04 \
    /mnt/elrond_mount05 \
    /mnt/elrond_mount06 \
    /mnt/elrond_mount07 \
    /mnt/elrond_mount08 \
    /mnt/elrond_mount09 \
    /cases \
    /evidence \
    /output \
    /tmp/elrond/uploads \
    /tmp/elrond/jobs \
    /var/log/elrond \
    && chown -R elrond:elrond \
    /mnt/elrond_* \
    /cases \
    /evidence \
    /output \
    /tmp/elrond \
    /var/log/elrond

# Make scripts executable
RUN find /opt/elrond/scripts -name "*.sh" -exec chmod +x {} \;

# Set environment variables
ENV PATH="/opt/elrond:/opt/elrond/scripts:${PATH}"
ENV PYTHONPATH="/opt/elrond:${PYTHONPATH}"
ENV ELROND_HOME="/opt/elrond"
ENV ELROND_OUTPUT="/output"
ENV ELROND_EVIDENCE="/evidence"
ENV ELROND_CASES="/cases"
ENV ELROND_LOG_DIR="/var/log/elrond"
ENV ELROND_NONINTERACTIVE="1"

# Create enhanced entrypoint script
USER root
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Banner\n\
echo "================================================"\n\
echo "  Elrond Forensics Engine v2.2.0"\n\
echo "  Digital Forensics Automation Tool"\n\
echo "================================================"\n\
echo ""\n\
\n\
# Ensure mount points exist\n\
echo "[*] Creating mount points..."\n\
mkdir -p /mnt/elrond_mount{00..09}\n\
mkdir -p /evidence /output /cases /tmp/elrond\n\
\n\
# Fix permissions\n\
echo "[*] Setting permissions..."\n\
chown -R elrond:elrond /mnt/elrond_* /evidence /output /cases /tmp/elrond /var/log/elrond 2>/dev/null || true\n\
\n\
# Check for FUSE device\n\
if [ ! -e /dev/fuse ]; then\n\
    echo "[!] Warning: /dev/fuse not available - disk mounting may not work"\n\
    echo "[!] Start container with --device /dev/fuse or --privileged"\n\
fi\n\
\n\
# Display environment\n\
echo "[*] Environment:"\n\
echo "    ELROND_HOME: ${ELROND_HOME}"\n\
echo "    ELROND_OUTPUT: ${ELROND_OUTPUT}"\n\
echo "    ELROND_EVIDENCE: ${ELROND_EVIDENCE}"\n\
echo ""\n\
\n\
# Execute command\n\
if [ "$#" -eq 0 ]; then\n\
    echo "[*] No command specified, starting interactive shell"\n\
    exec su - elrond\n\
elif [ "$(id -u)" -eq 0 ]; then\n\
    # Running as root, switch to elrond user\n\
    exec su elrond -c "cd /opt/elrond && $*"\n\
else\n\
    # Already running as elrond\n\
    cd /opt/elrond\n\
    exec "$@"\n\
fi\n\
' > /usr/local/bin/docker-entrypoint.sh && \
    chmod +x /usr/local/bin/docker-entrypoint.sh

# Create helper script for running analyses
RUN echo '#!/bin/bash\n\
# Helper script to run Elrond analyses\n\
python3 /opt/elrond/elrond.py "$@"\n\
' > /usr/local/bin/elrond-analyze && \
    chmod +x /usr/local/bin/elrond-analyze

# Switch to elrond user for security
USER elrond

# Expose volumes
VOLUME ["/evidence", "/output", "/cases", "/tmp/elrond"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import sys; sys.path.insert(0, '/opt/elrond'); from core.engine import ElrondEngine; sys.exit(0)" || exit 1

# Default command
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["python3", "cli.py", "--help"]
