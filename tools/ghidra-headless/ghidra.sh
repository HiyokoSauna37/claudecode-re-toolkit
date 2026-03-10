#!/bin/bash
# Ghidra Headless Docker helper script for Claude Code
# Usage: ghidra.sh <command> [args...]

set -eo pipefail

# Prevent MSYS/Git Bash path conversion (Windows)
export MSYS_NO_PATHCONV=1

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
CONTAINER="ghidra-headless"
GHIDRA_BIN="/opt/ghidra/support/analyzeHeadless"
SCRIPTS_DIR="/opt/ghidra-scripts"
PROJECT_DIR="/analysis/projects"
PROJECT_NAME="tmp_project"
TIMEOUT=300
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENV_FILE="$REPO_ROOT/.env"

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

# Copy binary from host to container input dir, return container-side path
prepare_binary() {
    local binary_path="$1"
    if [ -z "$binary_path" ]; then
        echo "Error: No binary specified" >&2
        return 1
    fi

    local basename
    basename=$(basename "$binary_path")

    # Copy to input/ on host side (which is mounted to /analysis/input)
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
    docker cp "$encrypted_path" "$CONTAINER:/tmp/$enc_basename"

    echo "[*] Decrypting inside container..." >&2
    docker exec -e QUARANTINE_PASSWORD="$password" "$CONTAINER" \
        python3 /opt/ghidra-scripts/decrypt_quarantine.py "/tmp/$enc_basename" -o "/tmp/$dec_basename" >&2

    if [ $? -ne 0 ]; then
        echo "Error: Decryption failed" >&2
        return 1
    fi

    # Clean up encrypted file
    docker exec "$CONTAINER" rm -f "/tmp/$enc_basename"

    echo "/tmp/$dec_basename"
}

# Clean up decrypted binary from container
cleanup_container() {
    local container_path="$1"
    if [ -n "$container_path" ] && [[ "$container_path" == /tmp/* ]]; then
        echo "[*] Cleaning up decrypted file from container..."
        docker exec "$CONTAINER" rm -f "$container_path"
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

    docker exec "$CONTAINER" bash -c "\
        $GHIDRA_BIN $PROJECT_DIR $PROJECT_NAME \
        -import '$binary_container_path' \
        -overwrite \
        -deleteProject \
        -analysisTimeoutPerFile $TIMEOUT \
        -scriptPath $SCRIPTS_DIR \
        -max-cpu 2 \
        $post_scripts \
        -DMAXMEM=\${MAXMEM:-4G} \
        2>&1"
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
            echo "Usage: ghidra.sh analyze <binary>"
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
        echo "=== Results in: $SCRIPT_DIR/output/ ==="
        ;;
    info)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh info <binary>"
            exit 1
        fi
        ensure_running
        BINARY=$(prepare_binary "$2") || exit 1
        run_headless "$BINARY" binary_info.py
        ;;
    decompile)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh decompile <binary>"
            exit 1
        fi
        ensure_running
        BINARY=$(prepare_binary "$2") || exit 1
        run_headless "$BINARY" decompile_all.py
        ;;
    functions)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh functions <binary>"
            exit 1
        fi
        ensure_running
        BINARY=$(prepare_binary "$2") || exit 1
        run_headless "$BINARY" list_functions.py
        ;;
    strings)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh strings <binary>"
            exit 1
        fi
        ensure_running
        BINARY=$(prepare_binary "$2") || exit 1
        run_headless "$BINARY" extract_strings.py
        ;;
    imports)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh imports <binary>"
            exit 1
        fi
        ensure_running
        BINARY=$(prepare_binary "$2") || exit 1
        run_headless "$BINARY" list_imports.py
        ;;
    exports)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh exports <binary>"
            exit 1
        fi
        ensure_running
        BINARY=$(prepare_binary "$2") || exit 1
        run_headless "$BINARY" list_exports.py
        ;;
    xrefs)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh xrefs <binary>"
            exit 1
        fi
        ensure_running
        BINARY=$(prepare_binary "$2") || exit 1
        run_headless "$BINARY" xrefs_report.py
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
        DECRYPTED=$(decrypt_in_container "$2")
        if [ $? -ne 0 ]; then
            echo "Error: Decryption failed. Aborting analysis."
            exit 1
        fi
        echo "=== Running Ghidra analysis on: $DECRYPTED ==="
        run_headless "$DECRYPTED" \
            binary_info.py \
            list_functions.py \
            list_imports.py \
            list_exports.py \
            extract_strings.py \
            xrefs_report.py
        cleanup_container "$DECRYPTED"
        echo "=== Results in: $SCRIPT_DIR/output/ ==="
        ;;
    yara-scan)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh yara-scan <binary>"
            echo "  Scans raw binary with YARA rules (APT attribution, malware family)"
            exit 1
        fi
        echo "=== YARA Scan: $(basename "$2") ==="
        python3 "$SCRIPT_DIR/yara_scanner.py" "$2" --output-dir "$SCRIPT_DIR/output"
        ;;
    capa)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh capa <binary>"
            echo "  CAPA analysis (capabilities + MITRE ATT&CK mapping)"
            exit 1
        fi
        echo "=== CAPA Analysis: $(basename "$2") ==="
        python3 "$SCRIPT_DIR/capa_scanner.py" "$2" --output-dir "$SCRIPT_DIR/output"
        ;;
    ioc-extract)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh ioc-extract <binary_name>"
            echo "  binary_name: Name prefix of Ghidra output files (e.g., 'stealc')"
            exit 1
        fi
        echo "=== IOC Extraction: $2 ==="
        python3 "$SCRIPT_DIR/ioc_extractor.py" "$2" --output-dir "$SCRIPT_DIR/output"
        ;;
    classify)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh classify <binary_name>"
            echo "  binary_name: Name prefix of Ghidra output files (e.g., 'stealc')"
            exit 1
        fi
        echo "=== Malware Classification: $2 ==="
        python3 "$SCRIPT_DIR/malware_classifier.py" "$2" --output-dir "$SCRIPT_DIR/output"
        ;;
    analyze-full)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh analyze-full <binary>"
            echo "  Runs: yara-scan -> capa -> analyze -> ioc-extract -> classify"
            exit 1
        fi
        ensure_running
        BINARY=$(prepare_binary "$2") || exit 1
        BINARY_NAME=$(basename "$2" | sed 's/\.[^.]*$//')
        echo "=== Full Analysis Pipeline: $(basename "$2") ==="
        echo "[1/5] YARA Scan..."
        python3 "$SCRIPT_DIR/yara_scanner.py" "$2" --output-dir "$SCRIPT_DIR/output" 2>&1 || echo "  YARA scan completed with warnings"
        echo "[2/5] CAPA Analysis..."
        python3 "$SCRIPT_DIR/capa_scanner.py" "$2" --output-dir "$SCRIPT_DIR/output" 2>&1 || echo "  CAPA analysis completed with warnings"
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
        echo "Container Management:"
        echo "  start                           Build and start container"
        echo "  stop                            Stop and remove container"
        echo "  status                          Show container status"
        echo ""
        echo "Ghidra Analysis (Docker container):"
        echo "  analyze <binary>                Full analysis (all scripts)"
        echo "  analyze-full <binary>           Full pipeline (YARA+CAPA+Ghidra+IOC+classify)"
        echo "  quarantine-analyze <file.enc.gz> Decrypt + full analysis (proxy-web quarantine)"
        echo "  decrypt <file.enc.gz>           Decrypt quarantine file in container"
        echo "  info <binary>                   Architecture, sections, entry point"
        echo "  decompile <binary>              Decompile all functions to C"
        echo "  functions <binary>              List functions with addresses/sizes"
        echo "  strings <binary>                Extract strings with xrefs"
        echo "  imports <binary>                Import table (suspicious API flagged)"
        echo "  exports <binary>                Export table"
        echo "  xrefs <binary>                  Cross-reference report"
        echo ""
        echo "Post-Analysis (host-side, no Docker required):"
        echo "  yara-scan <binary>              YARA scan (APT attribution, malware family)"
        echo "  capa <binary>                   CAPA analysis (capabilities + ATT&CK mapping)"
        echo "  ioc-extract <binary_name>       Extract IOCs from output files"
        echo "  classify <binary_name>          Classify malware type from output files"
        echo ""
        echo "Utilities:"
        echo "  exec <cmd...>                   Execute command in container"
        echo "  shell                           Open interactive shell"
        ;;
esac
