FROM amazoncorretto:21-alpine

# Install dependencies (including Python3 for quarantine decryption)
RUN apk add --no-cache \
    bash \
    curl \
    unzip \
    coreutils \
    python3 \
    py3-pip \
    py3-cryptography \
    gcompat \
    p7zip \
    file && \
    pip3 install --break-system-packages python-dotenv yara-python

# Download and install Ghidra 11.2
ENV GHIDRA_VERSION=12.0.3 \
    GHIDRA_DATE=20260210 \
    GHIDRA_SHA=90d3fffb20b00030dcef8d2a24dd0f422d3a61e432b3ad43f77233ac6d667981

RUN curl -fsSL -o /tmp/ghidra.zip \
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" && \
    echo "${GHIDRA_SHA}  /tmp/ghidra.zip" | sha256sum -c - && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra && \
    rm /tmp/ghidra.zip

# Copy analysis scripts
COPY scripts/ /opt/ghidra-scripts/

# Copy quarantine decryption script
COPY decrypt_quarantine.py /opt/ghidra-scripts/decrypt_quarantine.py

# Fix decompiler permissions: needs +r for dynamic loader, +x for execution
# (must be done before switching to non-root user)
RUN chmod +rx /opt/ghidra/Ghidra/Features/Decompiler/os/linux_x86_64/decompile || true && \
    chmod +rx /opt/ghidra/Ghidra/Features/Decompiler/os/linux_arm_64/decompile || true

# Create non-root user for container security
RUN addgroup -S ghidra && adduser -S ghidra -G ghidra

# Create working directories
RUN mkdir -p /analysis/input /analysis/output /analysis/projects && \
    chown -R ghidra:ghidra /analysis /opt/ghidra-scripts

WORKDIR /analysis

ENV GHIDRA_HOME=/opt/ghidra \
    MAXMEM=4G

USER ghidra

# Keep container running
CMD ["sleep", "infinity"]
