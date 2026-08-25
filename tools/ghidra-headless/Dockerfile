FROM amazoncorretto:21-alpine

# Runtime dependencies (Python3 is required for quarantine decryption).
# libstdc++ / libgcc / openssl are runtime deps of the compiled wheels installed
# further down (yara-python, binary2strings, python-flirt) and must stay in the
# image after the build toolchain is removed.
RUN apk add --no-cache \
    bash \
    curl \
    unzip \
    coreutils \
    python3 \
    py3-pip \
    py3-cryptography \
    gcompat \
    libstdc++ \
    libgcc \
    openssl \
    p7zip \
    file \
    py3-numpy \
    py3-matplotlib

# Download and install Ghidra
ENV GHIDRA_VERSION=12.1.3 \
    GHIDRA_DATE=20260817 \
    GHIDRA_SHA=93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54

RUN curl -fsSL -o /tmp/ghidra.zip \
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" && \
    echo "${GHIDRA_SHA}  /tmp/ghidra.zip" | sha256sum -c - && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra && \
    rm /tmp/ghidra.zip

# Install the Jython extension (REQUIRED — do not remove).
# Ghidra 12.1 moved Jython out of the default distribution into an opt-in
# extension (GP-6754) and 12.1.1 deleted support/jythonRun (GP-6826).
# Every script in scripts/ declares "# @runtime Jython", so without this step
# analyzeHeadless refuses to run any of them ("Can't find runtime Jython").
# The extension zip ships inside the distribution under Extensions/Ghidra/ and
# is activated by unzipping it into <install>/Ghidra/Extensions/.
RUN set -eu; \
    echo "[*] Extensions shipped with this distribution:"; \
    ls -1 /opt/ghidra/Extensions/Ghidra/; \
    jython_count=$(ls -1 /opt/ghidra/Extensions/Ghidra/*[Jj]ython*.zip | wc -l); \
    [ "$jython_count" = "1" ] || { echo "ERROR: expected exactly 1 Jython extension zip, found $jython_count"; exit 1; }; \
    unzip -q /opt/ghidra/Extensions/Ghidra/*[Jj]ython*.zip -d /opt/ghidra/Ghidra/Extensions/; \
    chmod -R a+rX /opt/ghidra/Ghidra/Extensions; \
    echo "[*] Installed extensions:"; \
    ls -1 /opt/ghidra/Ghidra/Extensions/

# Python analysis tooling.
# capa / FLOSS / pefile run INSIDE this container on purpose: CLAUDE.md forbids
# decrypting malware on the host, so run_container_tool() in ghidra.sh executes
# capa_scanner.py / floss_analyzer.py / pe_fallback_extract.py here instead of
# host-side. Versions are pinned deliberately — bump them together with the
# scanner scripts.
# yara-python, binary2strings and python-flirt have no musl wheels and must be
# compiled, hence the throwaway .build-deps virtual package.
ENV CAPA_VERSION=9.4.0 \
    FLOSS_VERSION=3.1.1

RUN apk add --no-cache --virtual .build-deps \
        build-base python3-dev libffi-dev openssl-dev && \
    pip3 install --break-system-packages --no-cache-dir \
        python-dotenv \
        yara-python \
        oletools \
        pefile \
        flare-capa==${CAPA_VERSION} \
        flare-floss==${FLOSS_VERSION} && \
    apk del .build-deps && \
    capa --version && floss --version && \
    python3 -c "import yara, pefile, oletools; print('yara/pefile/oletools OK')"

# capa installed from PyPI ships NO rules ("default embedded rules not found!
# maybe you installed capa as a library?"), so fetch the rule set and the FLIRT
# signatures for the pinned version. capa_scanner.py picks these up through
# CAPA_RULES_DIR / CAPA_SIGS_DIR and falls back to plain `capa -j` when unset.
ENV CAPA_RULES_DIR=/opt/capa/rules \
    CAPA_SIGS_DIR=/opt/capa/sigs

RUN set -eu; \
    mkdir -p "$CAPA_RULES_DIR" "$CAPA_SIGS_DIR"; \
    curl -fsSL -o /tmp/capa-rules.tgz \
        "https://github.com/mandiant/capa-rules/archive/refs/tags/v${CAPA_VERSION}.tar.gz"; \
    tar -xzf /tmp/capa-rules.tgz -C "$CAPA_RULES_DIR" --strip-components=1; \
    curl -fsSL -o /tmp/capa-src.tgz \
        "https://github.com/mandiant/capa/archive/refs/tags/v${CAPA_VERSION}.tar.gz"; \
    tar -xzf /tmp/capa-src.tgz -C "$CAPA_SIGS_DIR" --strip-components=2 "capa-${CAPA_VERSION}/sigs"; \
    rm -f /tmp/capa-rules.tgz /tmp/capa-src.tgz; \
    rule_count=$(find "$CAPA_RULES_DIR" -name '*.yml' | wc -l); \
    [ "$rule_count" -gt 100 ] || { echo "ERROR: capa rules missing (found $rule_count)"; exit 1; }; \
    echo "[*] capa rules: $rule_count .yml files"; \
    ls -1 "$CAPA_SIGS_DIR"

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
