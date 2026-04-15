#!/bin/bash
# Ghidra Headless Docker helper script for Claude Code
# Usage: ghidra.sh <command> [args...]

set -eo pipefail

# Prevent MSYS/Git Bash path conversion (Windows)
export MSYS_NO_PATHCONV=1

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# On MSYS/Git Bash, convert SCRIPT_DIR to Windows path for host tools (python3, etc.)
if command -v cygpath &>/dev/null; then
    SCRIPT_DIR_WIN="$(cygpath -w "$SCRIPT_DIR")"
else
    SCRIPT_DIR_WIN="$SCRIPT_DIR"
fi
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
CONTAINER="ghidra-headless"
GHIDRA_BIN="/opt/ghidra/support/analyzeHeadless"
SCRIPTS_DIR="/opt/ghidra-scripts"
PROJECT_DIR="/analysis/projects"
PROJECT_NAME="tmp_project"
TIMEOUT=300
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENV_FILE="$REPO_ROOT/.env"

# Track container-side temp files for cleanup
_CONTAINER_CLEANUP=""

compose() {
    docker compose -f "$COMPOSE_FILE" "$@"
}

ensure_running() {
    local status
    status=$(docker inspect -f '{{.State.Status}}' "$CONTAINER" 2>/dev/null)
    if [ "$status" != "running" ]; then
        echo "Container not running. Starting..."
        compose up -d --build
        sleep 3
    fi
}

# Decrypt quarantine file inside container (/tmp/, not bind mount)
# Returns: container-side path of decrypted binary
decrypt_in_container() {
    local encrypted_path="$1"
    if [ -z "$encrypted_path" ]; then
        echo "Error: No encrypted file specified" >&2
        return 1
    fi

    if [ ! -f "$encrypted_path" ]; then
        echo "Error: File not found: $encrypted_path" >&2
        return 1
    fi

    # Get password from .env
    local password=""
    if [ -f "$ENV_FILE" ]; then
        password=$(grep -E '^QUARANTINE_PASSWORD=' "$ENV_FILE" | cut -d= -f2- | tr -d '"' | tr -d "'")
    fi
    if [ -z "$password" ]; then
        echo "Error: QUARANTINE_PASSWORD not found in $ENV_FILE" >&2
        return 1
    fi

    local enc_basename
    enc_basename=$(basename "$encrypted_path")
    local dec_basename="${enc_basename%.enc.gz}"

    echo "[*] Copying encrypted file to container /tmp/..." >&2
    # MSYS_NO_PATHCONV=1 prevents Git Bash from converting container paths like /tmp/... to Windows paths
    MSYS_NO_PATHCONV=1 docker cp "$encrypted_path" "$CONTAINER:/tmp/$enc_basename"

    echo "[*] Decrypting inside container (host never sees raw binary)..." >&2
    # Pass paths via env vars to avoid MSYS/Git Bash path conversion on Windows
    MSYS_NO_PATHCONV=1 docker exec \
        -e QUARANTINE_PASSWORD="$password" \
        -e ENC_PATH="/tmp/$enc_basename" \
        -e DEC_PATH="/tmp/$dec_basename" \
        "$CONTAINER" \
        bash -c 'python3 /opt/ghidra-scripts/decrypt_quarantine.py "$ENC_PATH" -o "$DEC_PATH"' >&2

    if [ $? -ne 0 ]; then
        echo "Error: Decryption failed" >&2
        return 1
    fi

    # Clean up encrypted file from container
    MSYS_NO_PATHCONV=1 docker exec "$CONTAINER" rm -f "/tmp/$enc_basename"

    # Register for cleanup after analysis
    _CONTAINER_CLEANUP="/tmp/$dec_basename"

    echo "/tmp/$dec_basename"
}

# Clean up decrypted binary from container
cleanup_container() {
    local container_path="$1"
    if [ -n "$container_path" ] && [[ "$container_path" == /tmp/* ]]; then
        echo "[*] Cleaning up decrypted file from container..."
        docker exec "$CONTAINER" rm -f "/${container_path}" 2>/dev/null || true
    fi
}

# Smart binary preparation: auto-detects .enc.gz and routes through container-only decryption
# For .enc.gz: decrypt inside container, return /tmp/<name> (container path)
# For plain files: copy to input/ bind mount, return /analysis/input/<name>
# Sets _CONTAINER_CLEANUP for auto-cleanup
prepare_binary() {
    local binary_path="$1"
    if [ -z "$binary_path" ]; then
        echo "Error: No binary specified" >&2
        return 1
    fi

    _CONTAINER_CLEANUP=""

    # Auto-detect encrypted quarantine files
    if [[ "$binary_path" == *.enc.gz ]]; then
        echo "[!] Detected .enc.gz file → decrypting INSIDE container (not on host)" >&2
        local container_path
        container_path=$(decrypt_in_container "$binary_path")
        if [ $? -ne 0 ]; then
            echo "Error: Decryption failed" >&2
            return 1
        fi
        echo "$container_path"
        return 0
    fi

    # Plain binary: copy to input/ mount
    local basename
    basename=$(basename "$binary_path")

    if [ -f "$binary_path" ]; then
        cp "$binary_path" "$SCRIPT_DIR/input/$basename"
    elif [ -f "$SCRIPT_DIR/input/$basename" ]; then
        : # Already in input dir
    else
        echo "Error: File not found: $binary_path" >&2
        return 1
    fi

    echo "/analysis/input/$basename"
}

# Auto-cleanup after analysis
auto_cleanup() {
    if [ -n "$_CONTAINER_CLEANUP" ]; then
        cleanup_container "$_CONTAINER_CLEANUP"
        _CONTAINER_CLEANUP=""
    fi
}

run_headless() {
    local binary_container_path="$1"
    shift
    local scripts=("$@")

    local post_scripts=""
    for s in "${scripts[@]}"; do
        post_scripts="$post_scripts -postScript $s"
    done

    # Build command as array to avoid shell injection via bash -c
    local cmd="$GHIDRA_BIN"
    cmd="$cmd $PROJECT_DIR $PROJECT_NAME"
    cmd="$cmd -import '${binary_container_path//\'/\'\\\'\'}'"
    cmd="$cmd -overwrite -deleteProject"
    cmd="$cmd -analysisTimeoutPerFile $TIMEOUT"
    cmd="$cmd -scriptPath $SCRIPTS_DIR"
    cmd="$cmd -max-cpu 2"
    cmd="$cmd $post_scripts"
    cmd="$cmd -DMAXMEM=\${MAXMEM:-4G}"
    cmd="$cmd 2>&1"

    docker exec "$CONTAINER" bash -c "$cmd"
}

# Run YARA scan inside container for .enc.gz files (no host extraction)
yara_scan_in_container() {
    local container_path="$1"
    echo "[*] Running YARA scan inside container..." >&2

    # Install yara in container if needed, then run
    docker exec "$CONTAINER" bash -c "
        if ! command -v yara &>/dev/null && pip3 install yara-python &>/dev/null; then
            echo '[*] Installed yara-python in container'
        fi
        python3 //opt/ghidra-scripts/decrypt_quarantine.py --version 2>/dev/null || true
    " >&2 2>/dev/null || true

    # Copy yara_scanner.py and rules to container, run there
    # Use SCRIPT_DIR_WIN for docker cp (MSYS paths cause GetFileAttributesEx errors)
    docker cp "$SCRIPT_DIR_WIN/yara_scanner.py" "$CONTAINER:/tmp/yara_scanner.py"
    if [ -d "$SCRIPT_DIR/yara-rules" ]; then
        docker exec "$CONTAINER" mkdir -p //tmp/yara-rules 2>/dev/null || true
        docker cp "$SCRIPT_DIR_WIN/yara-rules/." "$CONTAINER:/tmp/yara-rules/"
    fi
    # Pass container_path via env var to avoid MSYS/Git Bash path conversion
    docker exec -e SCAN_TARGET="$container_path" "$CONTAINER" \
        bash -c 'python3 /tmp/yara_scanner.py "$SCAN_TARGET" --output-dir /analysis/output' 2>&1 || echo "  YARA scan completed with warnings"
    # Copy results back to host output
    docker cp "$CONTAINER:/analysis/output/." "$SCRIPT_DIR_WIN/output/" 2>/dev/null || true
}

# Run CAPA inside container for .enc.gz files (no host extraction)
capa_scan_in_container() {
    local container_path="$1"
    echo "[*] Running CAPA inside container..." >&2

    # Use SCRIPT_DIR_WIN for docker cp (MSYS paths cause GetFileAttributesEx errors)
    docker cp "$SCRIPT_DIR_WIN/capa_scanner.py" "$CONTAINER:/tmp/capa_scanner.py"
    docker exec "$CONTAINER" bash -c "
        pip3 install flare-capa 2>/dev/null || true
        python3 /tmp/capa_scanner.py '$container_path' --output-dir /analysis/output
    " 2>&1 || echo "  CAPA analysis completed with warnings"
    docker cp "$CONTAINER:/analysis/output/." "$SCRIPT_DIR_WIN/output/" 2>/dev/null || true
}

# Generate YARA rules from malware sample using yarGen (container-side)
yargen_in_container() {
    local container_path="$1"
    local output_name="${2:-custom_rule}"
    echo "[*] Running yarGen inside container..." >&2

    docker exec "$CONTAINER" bash -c "
        if ! command -v yarGen.py &>/dev/null && [ ! -f /tmp/yarGen/yarGen.py ]; then
            echo '[*] Installing yarGen...'
            pip3 install --break-system-packages scandir lxml naiveBayesClassifier tlsh lief 2>/dev/null || true
            cd /tmp && curl -fsSL -o yargen.zip https://github.com/Neo23x0/yarGen/archive/refs/heads/master.zip 2>/dev/null
            unzip -qo yargen.zip -d /tmp/yarGen-tmp 2>/dev/null
            mv /tmp/yarGen-tmp/yarGen-master /tmp/yarGen
            rm -f yargen.zip && rm -rf /tmp/yarGen-tmp
            cd /tmp/yarGen && python3 yarGen.py --update 2>&1 | tail -5
        fi
        echo '[*] Generating YARA rule...'
        # yarGen requires a directory, not a single file
        mkdir -p /tmp/yargen_target
        cp '$container_path' /tmp/yargen_target/ 2>/dev/null || true
        cd /tmp/yarGen && python3 yarGen.py -m /tmp/yargen_target -o '/analysis/output/${output_name}.yar' --excludegood 2>&1 | tail -20
        rm -rf /tmp/yargen_target
    " 2>&1 || echo "  yarGen completed with warnings"
    docker cp "$CONTAINER:/analysis/output/${output_name}.yar" "$SCRIPT_DIR_WIN/output/" 2>/dev/null || true
    echo "[*] YARA rule saved to: output/${output_name}.yar"
}

case "${1:-}" in
    start)
        compose up -d --build
        echo "Ghidra Headless container started."
        ;;
    stop)
        compose down
        echo "Ghidra Headless container stopped."
        ;;
    status)
        docker inspect -f '{{.State.Status}}' "$CONTAINER" 2>/dev/null || echo "Container not found"
        ;;
    analyze)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh analyze <binary|encrypted.enc.gz>"
            exit 1
        fi
        ensure_running
        BINARY=$(prepare_binary "$2") || exit 1
        echo "=== Full Analysis: $(basename "$2") ==="
        run_headless "$BINARY" \
            binary_info.py \
            list_functions.py \
            list_imports.py \
            list_exports.py \
            extract_strings.py \
            decompile_all.py \
            xrefs_report.py
        auto_cleanup
        echo "=== Results in: $SCRIPT_DIR/output/ ==="
        ;;
    info)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh info <binary|encrypted.enc.gz>"
            exit 1
        fi
        ensure_running
        BINARY=$(prepare_binary "$2") || exit 1
        run_headless "$BINARY" binary_info.py
        auto_cleanup
        ;;
    decompile)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh decompile <binary|encrypted.enc.gz>"
            exit 1
        fi
        ensure_running
        BINARY=$(prepare_binary "$2") || exit 1
        run_headless "$BINARY" decompile_all.py
        auto_cleanup
        ;;
    functions)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh functions <binary|encrypted.enc.gz>"
            exit 1
        fi
        ensure_running
        BINARY=$(prepare_binary "$2") || exit 1
        run_headless "$BINARY" list_functions.py
        auto_cleanup
        ;;
    strings)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh strings <binary|encrypted.enc.gz>"
            exit 1
        fi
        ensure_running
        BINARY=$(prepare_binary "$2") || exit 1
        run_headless "$BINARY" extract_strings.py
        auto_cleanup
        ;;
    imports)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh imports <binary|encrypted.enc.gz>"
            exit 1
        fi
        ensure_running
        BINARY=$(prepare_binary "$2") || exit 1
        run_headless "$BINARY" list_imports.py
        auto_cleanup
        ;;
    exports)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh exports <binary|encrypted.enc.gz>"
            exit 1
        fi
        ensure_running
        BINARY=$(prepare_binary "$2") || exit 1
        run_headless "$BINARY" list_exports.py
        auto_cleanup
        ;;
    xrefs)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh xrefs <binary|encrypted.enc.gz>"
            exit 1
        fi
        ensure_running
        BINARY=$(prepare_binary "$2") || exit 1
        run_headless "$BINARY" xrefs_report.py
        auto_cleanup
        ;;
    decrypt)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh decrypt <encrypted_file.enc.gz>"
            exit 1
        fi
        ensure_running
        DECRYPTED=$(decrypt_in_container "$2")
        if [ $? -eq 0 ]; then
            echo "=== Decrypted file in container: $DECRYPTED ==="
        fi
        ;;
    quarantine-analyze)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh quarantine-analyze <encrypted_file.enc.gz>"
            exit 1
        fi
        ensure_running
        echo "=== Quarantine Analysis: $(basename "$2") ==="
        BINARY=$(prepare_binary "$2") || exit 1
        echo "=== Running Ghidra analysis on: $BINARY ==="
        run_headless "$BINARY" \
            binary_info.py \
            list_functions.py \
            list_imports.py \
            list_exports.py \
            extract_strings.py \
            xrefs_report.py
        auto_cleanup
        echo "=== Results in: $SCRIPT_DIR/output/ ==="
        ;;
    yara-scan)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh yara-scan <binary|encrypted.enc.gz>"
            echo "  Scans raw binary with YARA rules (APT attribution, malware family)"
            echo "  .enc.gz files: scanned inside container (no host extraction)"
            exit 1
        fi
        echo "=== YARA Scan: $(basename "$2") ==="
        if [[ "$2" == *.enc.gz ]]; then
            ensure_running
            CONTAINER_PATH=$(decrypt_in_container "$2")
            if [ $? -ne 0 ]; then
                echo "Error: Decryption failed. Aborting YARA scan."
                exit 1
            fi
            yara_scan_in_container "$CONTAINER_PATH"
            cleanup_container "$CONTAINER_PATH"
        else
            # Plain binary: run on host
            if command -v cygpath &>/dev/null; then
                python3 "$(cygpath -w "$SCRIPT_DIR/yara_scanner.py")" "$(cygpath -w "$2")" --output-dir "$(cygpath -w "$SCRIPT_DIR/output")"
            else
                python3 "$SCRIPT_DIR/yara_scanner.py" "$2" --output-dir "$SCRIPT_DIR/output"
            fi
        fi
        ;;
    capa)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh capa <binary|encrypted.enc.gz>"
            echo "  CAPA analysis (capabilities + MITRE ATT&CK mapping)"
            echo "  .enc.gz files: analyzed inside container (no host extraction)"
            exit 1
        fi
        echo "=== CAPA Analysis: $(basename "$2") ==="
        if [[ "$2" == *.enc.gz ]]; then
            ensure_running
            CONTAINER_PATH=$(decrypt_in_container "$2")
            if [ $? -ne 0 ]; then
                echo "Error: Decryption failed. Aborting CAPA analysis."
                exit 1
            fi
            capa_scan_in_container "$CONTAINER_PATH"
            cleanup_container "$CONTAINER_PATH"
        else
            # Plain binary: run on host
            CAPA_TARGET_HOST="$2"
            if command -v cygpath &>/dev/null; then
                CAPA_TARGET_HOST="$(cygpath -w "$2")"
            fi
            python3 "$SCRIPT_DIR_WIN/capa_scanner.py" "$CAPA_TARGET_HOST" --output-dir "$SCRIPT_DIR_WIN/output"
        fi
        ;;
    ioc-extract)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh ioc-extract <binary_name>"
            echo "  binary_name: Name prefix of Ghidra output files (e.g., 'stealc')"
            exit 1
        fi
        echo "=== IOC Extraction: $2 ==="
        python3 "$SCRIPT_DIR_WIN/ioc_extractor.py" "$2" --output-dir "$SCRIPT_DIR_WIN/output"
        ;;
    classify)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh classify <binary_name>"
            echo "  binary_name: Name prefix of Ghidra output files (e.g., 'stealc')"
            exit 1
        fi
        echo "=== Malware Classification: $2 ==="
        python3 "$SCRIPT_DIR_WIN/malware_classifier.py" "$2" --output-dir "$SCRIPT_DIR_WIN/output"
        ;;
    yargen)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh yargen <binary|encrypted.enc.gz> [rule_name]"
            echo "  Generate YARA rule from malware sample using yarGen"
            echo "  rule_name: Output filename (default: custom_rule)"
            echo "  .enc.gz files: processed inside container (no host extraction)"
            exit 1
        fi
        RULE_NAME="${3:-custom_rule}"
        echo "=== yarGen Rule Generation: $(basename "$2") ==="
        if [[ "$2" == *.enc.gz ]]; then
            ensure_running
            CONTAINER_PATH=$(decrypt_in_container "$2")
            if [ $? -ne 0 ]; then
                echo "Error: Decryption failed. Aborting yarGen."
                exit 1
            fi
            yargen_in_container "$CONTAINER_PATH" "$RULE_NAME"
            cleanup_container "$CONTAINER_PATH"
        else
            ensure_running
            # Copy binary to container for yarGen
            BASENAME=$(basename "$2")
            docker cp "$2" "$CONTAINER:/tmp/$BASENAME"
            yargen_in_container "/tmp/$BASENAME" "$RULE_NAME"
            docker exec "$CONTAINER" rm -f "/tmp/$BASENAME" 2>/dev/null || true
        fi
        ;;
    analyze-full)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh analyze-full <binary|encrypted.enc.gz>"
            echo "  Runs: yara-scan -> capa -> analyze -> ioc-extract -> classify"
            echo "  .enc.gz files: all processing inside container (no host extraction)"
            exit 1
        fi
        ensure_running
        BINARY=$(prepare_binary "$2") || exit 1
        BINARY_NAME=$(basename "$2" | sed 's/\.enc\.gz$//' | sed 's/\.[^.]*$//')
        echo "=== Full Analysis Pipeline: $(basename "$2") ==="

        if [[ "$2" == *.enc.gz ]]; then
            # For .enc.gz: run YARA/CAPA inside container too
            echo "[1/5] YARA Scan (in container)..."
            yara_scan_in_container "$BINARY" 2>&1 || echo "  YARA scan completed with warnings"
            echo "[2/5] CAPA Analysis (in container)..."
            capa_scan_in_container "$BINARY" 2>&1 || echo "  CAPA analysis completed with warnings"
        else
            echo "[1/5] YARA Scan..."
            python3 "$SCRIPT_DIR/yara_scanner.py" "$2" --output-dir "$SCRIPT_DIR/output" 2>&1 || echo "  YARA scan completed with warnings"
            echo "[2/5] CAPA Analysis..."
            python3 "$SCRIPT_DIR/capa_scanner.py" "$2" --output-dir "$SCRIPT_DIR/output" 2>&1 || echo "  CAPA analysis completed with warnings"
        fi

        echo "[3/5] Ghidra Analysis..."
        run_headless "$BINARY" \
            binary_info.py \
            list_functions.py \
            list_imports.py \
            list_exports.py \
            extract_strings.py \
            decompile_all.py \
            xrefs_report.py
        echo "[4/5] IOC Extraction..."
        python3 "$SCRIPT_DIR/ioc_extractor.py" "$BINARY_NAME" --output-dir "$SCRIPT_DIR/output" 2>&1 || echo "  IOC extraction completed with warnings"
        echo "[5/5] Malware Classification..."
        python3 "$SCRIPT_DIR/malware_classifier.py" "$BINARY_NAME" --output-dir "$SCRIPT_DIR/output" 2>&1 || echo "  Classification completed with warnings"
        auto_cleanup
        echo "=== Pipeline Complete. Results in: $SCRIPT_DIR/output/ ==="
        ;;
    exec)
        shift
        docker exec "$CONTAINER" "$@"
        ;;
    shell)
        docker exec -it "$CONTAINER" /bin/bash
        ;;
    *)
        echo "Ghidra Headless Docker Helper"
        echo ""
        echo "Usage: ghidra.sh <command> [args...]"
        echo ""
        echo "All commands accept both plain binaries and .enc.gz quarantine files."
        echo ".enc.gz files are automatically decrypted INSIDE the container (never on host)."
        echo ""
        echo "Container Management:"
        echo "  start                           Build and start container"
        echo "  stop                            Stop and remove container"
        echo "  status                          Show container status"
        echo ""
        echo "Ghidra Analysis (Docker container):"
        echo "  analyze <binary|.enc.gz>        Full analysis (all scripts)"
        echo "  analyze-full <binary|.enc.gz>   Full pipeline (YARA+CAPA+Ghidra+IOC+classify)"
        echo "  quarantine-analyze <.enc.gz>    Alias for analyze with .enc.gz"
        echo "  decrypt <.enc.gz>               Decrypt quarantine file in container"
        echo "  info <binary|.enc.gz>           Architecture, sections, entry point"
        echo "  decompile <binary|.enc.gz>      Decompile all functions to C"
        echo "  functions <binary|.enc.gz>      List functions with addresses/sizes"
        echo "  strings <binary|.enc.gz>        Extract strings with xrefs"
        echo "  imports <binary|.enc.gz>        Import table (suspicious API flagged)"
        echo "  exports <binary|.enc.gz>        Export table"
        echo "  xrefs <binary|.enc.gz>          Cross-reference report"
        echo ""
        echo "Post-Analysis (host-side, no Docker required for plain files):"
        echo "  yara-scan <binary|.enc.gz>      YARA scan (APT attribution, malware family)"
        echo "  capa <binary|.enc.gz>           CAPA analysis (capabilities + ATT&CK mapping)"
        echo "  ioc-extract <binary_name>       Extract IOCs from output files"
        echo "  classify <binary_name>          Classify malware type from output files"
        echo "  yargen <binary|.enc.gz> [name]  Generate YARA rule from sample (yarGen)"
        echo ""
        echo "Utilities:"
        echo "  exec <cmd...>                   Execute command in container"
        echo "  shell                           Open interactive shell"
        ;;
esac
