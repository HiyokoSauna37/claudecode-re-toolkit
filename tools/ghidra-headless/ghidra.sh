#!/bin/bash
# Ghidra Headless Docker helper script for Claude Code
# Usage: ghidra.sh <command> [args...]

set -eo pipefail

# --- MSYS/Git Bash path conversion prevention ---
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

# Wrapper: docker exec with MSYS path conversion disabled
dexec() {
    MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker exec "$@"
}

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
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

# Processor/language override (e.g., "ARM:LE:32:v8T", "x86:LE:64:default")
PROCESSOR_ID=""

# Standard script sets
ALL_SCRIPTS=(binary_info.py list_functions.py list_imports.py list_exports.py extract_strings.py decompile_all.py xrefs_report.py)

# --- Core functions ---

compose() { docker compose -f "$COMPOSE_FILE" "$@"; }

ensure_running() {
    local status
    status=$(docker inspect -f '{{.State.Status}}' "$CONTAINER" 2>/dev/null)
    if [ "$status" != "running" ]; then
        echo "Container not running. Starting..."
        compose up -d --build
        sleep 3
    fi
}

# Auto-detect processor from ELF header (file command + raw EI_DATA byte)
auto_detect_processor() {
    local container_path="$1"
    [ -n "$PROCESSOR_ID" ] && return

    local file_output
    file_output=$(dexec "$CONTAINER" file "$container_path" 2>/dev/null) || return

    if echo "$file_output" | grep -q "ARM" && echo "$file_output" | grep -q "32-bit"; then
        local ei_data
        ei_data=$(dexec "$CONTAINER" python3 -c "
with open('$container_path','rb') as f:
    f.seek(5)
    print(f.read(1)[0])
" 2>/dev/null) || ei_data=""
        local endian="LE"
        [ "$ei_data" = "2" ] && endian="BE"
        PROCESSOR_ID="ARM:${endian}:32:v8T"
        echo "[*] Auto-detected ARM 32-bit ELF (EI_DATA=$ei_data) → processor ARM:${endian}:32:v8T" >&2
    fi
}

# --- Binary resolution ---

prepare_binary() {
    local binary_path="$1"
    [ -z "$binary_path" ] && { echo "Error: No binary specified" >&2; return 1; }

    local bname
    bname=$(basename "$binary_path")

    if [ -f "$binary_path" ]; then
        cp "$binary_path" "$SCRIPT_DIR/input/$bname"
    elif [ ! -f "$SCRIPT_DIR/input/$bname" ]; then
        echo "Error: File not found: $binary_path" >&2
        return 1
    fi
    echo "/analysis/input/$bname"
}

RESOLVED_BINARY=""
NEEDS_CLEANUP=0

resolve_binary() {
    local binary_path="$1"
    [ -z "$binary_path" ] && { echo "Error: No binary specified" >&2; return 1; }

    # Container-internal path
    if [[ "$binary_path" == /tmp/* ]] || [[ "$binary_path" == /analysis/* ]]; then
        if dexec "$CONTAINER" test -f "$binary_path" 2>/dev/null; then
            echo "[*] Using container-internal path: $binary_path" >&2
            RESOLVED_BINARY="$binary_path"
            NEEDS_CLEANUP=0
            return 0
        fi
    fi

    if [[ "$binary_path" == *.enc.gz ]]; then
        echo "[*] Detected .enc.gz quarantine file, auto-decrypting in container..." >&2
        RESOLVED_BINARY=$(decrypt_in_container "$binary_path") || { echo "Error: Decryption failed" >&2; return 1; }
        NEEDS_CLEANUP=1
    else
        RESOLVED_BINARY=$(prepare_binary "$binary_path") || return 1
        NEEDS_CLEANUP=0
    fi
}

cleanup_resolved() {
    if [ "$NEEDS_CLEANUP" -eq 1 ] && [ -n "$RESOLVED_BINARY" ]; then
        cleanup_container "$RESOLVED_BINARY"
    fi
    RESOLVED_BINARY=""
    NEEDS_CLEANUP=0
}
trap cleanup_resolved EXIT

# --- Decryption ---

decrypt_in_container() {
    local encrypted_path="$1"
    [ -z "$encrypted_path" ] && { echo "Error: No encrypted file specified" >&2; return 1; }
    [ ! -f "$encrypted_path" ] && { echo "Error: File not found: $encrypted_path" >&2; return 1; }

    local password=""
    [ -f "$ENV_FILE" ] && password=$(grep -E '^QUARANTINE_PASSWORD=' "$ENV_FILE" | cut -d= -f2- | tr -d '"' | tr -d "'")
    [ -z "$password" ] && { echo "Error: QUARANTINE_PASSWORD not found in $ENV_FILE" >&2; return 1; }

    local enc_basename dec_basename
    enc_basename=$(basename "$encrypted_path")
    dec_basename="${enc_basename%.enc.gz}"

    echo "[*] Copying encrypted file to container /tmp/..." >&2
    docker cp "$encrypted_path" "$CONTAINER:/tmp/$enc_basename"

    echo "[*] Decrypting inside container..." >&2
    dexec -e QUARANTINE_PASSWORD="$password" "$CONTAINER" \
        python3 /opt/ghidra-scripts/decrypt_quarantine.py "/tmp/$enc_basename" -o "/tmp/$dec_basename" >&2
    [ $? -ne 0 ] && { echo "Error: Decryption failed" >&2; return 1; }

    dexec "$CONTAINER" rm -f "/tmp/$enc_basename"
    echo "/tmp/$dec_basename"
}

cleanup_container() {
    local container_path="$1"
    if [ -n "$container_path" ] && [[ "$container_path" == /tmp/* ]]; then
        echo "[*] Cleaning up decrypted file from container..."
        dexec "$CONTAINER" rm -f "$container_path"
    fi
}

# --- Ghidra execution (array-based, no bash -c) ---

run_headless() {
    local binary_container_path="$1"
    shift
    local scripts=("$@")

    # Per-invocation unique project name → multiple ghidra.sh commands in
    # parallel no longer collide on `tmp_project` lock (KB-23). -deleteProject
    # ensures we don't accumulate stale projects.
    local proj_name="${PROJECT_NAME}_$$_$(date +%s%N)"

    local cmd=("$GHIDRA_BIN" "$PROJECT_DIR" "$proj_name"
        -import "$binary_container_path"
        -overwrite -deleteProject
        -analysisTimeoutPerFile "$TIMEOUT"
        -scriptPath "$SCRIPTS_DIR"
        -max-cpu 2)

    [ -n "$PROCESSOR_ID" ] && {
        cmd+=(-processor "$PROCESSOR_ID")
        echo "[*] Using processor: $PROCESSOR_ID" >&2
    }

    for s in "${scripts[@]}"; do
        cmd+=(-postScript "$s")
    done

    # Must use bash -c for MAXMEM env var expansion inside container
    local cmd_str=""
    for arg in "${cmd[@]}"; do
        cmd_str="$cmd_str '$arg'"
    done
    cmd_str="$cmd_str -DMAXMEM=\${MAXMEM:-4G} 2>&1"

    dexec "$CONTAINER" bash -c "$cmd_str"
}

# --- High-level helpers ---

# Run Ghidra analysis with auto-detect, resolve, and cleanup
# Usage: run_ghidra_scripts <binary_path> <script1.py> [script2.py ...]
run_ghidra_scripts() {
    local binary="$1"
    shift
    local scripts=("$@")
    ensure_running
    resolve_binary "$binary" || exit 1
    auto_detect_processor "$RESOLVED_BINARY"
    run_headless "$RESOLVED_BINARY" "${scripts[@]}"
    cleanup_resolved
}

# Run host-side Python tool with optional .enc.gz decryption
# Usage: run_host_tool <binary_path> <python_script> [extra_args...]
run_host_tool() {
    local binary="$1"
    local py_script="$2"
    shift 2
    local extra_args=("$@")
    local target="$binary"
    local tmp_dir=""

    if [[ "$binary" == *.enc.gz ]]; then
        ensure_running
        local container_path
        container_path=$(decrypt_in_container "$binary") || { echo "Error: Decryption failed." >&2; exit 1; }
        local win_temp="${USERPROFILE}/AppData/Local/Temp"
        tmp_dir=$(mktemp -d -p "$win_temp")
        local dec_name
        dec_name=$(basename "$container_path")
        docker cp "$CONTAINER:$container_path" "$tmp_dir/$dec_name"
        cleanup_container "$container_path"
        target="$tmp_dir/$dec_name"
    fi

    python3 "$SCRIPT_DIR_WIN/$py_script" "$target" "${extra_args[@]}"

    [ -n "$tmp_dir" ] && rm -rf "$tmp_dir"
}

# Run dotnet-decompile tool
run_dotnet() {
    local subcmd="$1"
    local binary="$2"
    local tool="$REPO_ROOT/tools/dotnet-decompiler/dotnet-decompile.exe"
    [ ! -f "$tool" ] && {
        echo "Error: dotnet-decompile.exe not found. Build with: cd tools/dotnet-decompiler && go build -o dotnet-decompile.exe ."
        exit 1
    }
    "$tool" "$subcmd" "$binary"
}

# --- Auto command logging ---
# Logs every analysis command to logs/YYYYMMDD_<binary>.md for audit trail.
# Designed to NEVER break the main script: I/O failures are silently ignored.

_auto_log() {
    local subcmd="${1:-}"
    # Skip meta commands (no analysis target → no log)
    case "$subcmd" in
        start|stop|status|help|--help|-h|log-show|shell|exec|output)
            return 0
            ;;
    esac

    # Find binary target, skipping flags AND values of known value-taking flags.
    # Without this, "analyze --processor ARM:LE:32:v8T malware.exe" would log under
    # "ARM:LE:32:v8T" instead of "malware.exe".
    local target=""
    local _skip_next=0
    local _arg
    for _arg in "${@:2}"; do
        if [ "$_skip_next" = "1" ]; then
            _skip_next=0
            continue
        fi
        case "$_arg" in
            --processor|--output-dir|--rules-dir)
                _skip_next=1
                continue
                ;;
            --*)
                continue
                ;;
        esac
        target="$_arg"
        break
    done
    if [ -z "$target" ]; then
        return 0
    fi

    # Derive log filename from binary name (strip .enc.gz then strip extension)
    local bname logfile
    bname=$(basename "${target%.enc.gz}")
    bname="${bname%.*}"
    logfile="$SCRIPT_DIR/logs/$(date +%Y%m%d)_${bname}.md"

    # All I/O in error-suppressed group: logging never breaks the main script
    {
        mkdir -p "$SCRIPT_DIR/logs"
        if [ ! -f "$logfile" ]; then
            printf '# Ghidra 解析ログ: %s\n**Date:** %s  \n**Path:** `%s`\n\n## コマンド履歴\n\n| 時刻 | コマンド |\n|---|---|\n' \
                "$(basename "$target")" "$(date '+%Y-%m-%d')" "$target" > "$logfile"
        fi
        printf '| %s | `bash tools/ghidra-headless/ghidra.sh %s` |\n' \
            "$(date '+%H:%M:%S')" "$*" >> "$logfile"
    } 2>/dev/null || true
    return 0
}

# --- Command dispatch ---
# Defensive: never let logging errors kill the main flow
_auto_log "$@" || true

case "${1:-}" in
    # --- Container management ---
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

    # --- Ghidra analysis (Docker) ---
    analyze|quarantine-analyze)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh analyze [--processor <lang_id>] <binary|file.enc.gz|container_path>"
            exit 1
        fi
        # Parse --processor flag
        ANALYZE_TARGET=""
        while [ $# -gt 1 ]; do
            case "$2" in
                --processor) PROCESSOR_ID="$3"; shift 2 ;;
                *) ANALYZE_TARGET="$2"; shift; break ;;
            esac
        done
        [ -z "$ANALYZE_TARGET" ] && ANALYZE_TARGET="$2"
        echo "=== Full Analysis: $(basename "$ANALYZE_TARGET") ==="
        run_ghidra_scripts "$ANALYZE_TARGET" "${ALL_SCRIPTS[@]}"
        echo "=== Results in: $SCRIPT_DIR_WIN/output/ ==="
        ;;
    info)
        [ -z "$2" ] && { echo "Usage: ghidra.sh info <binary>"; exit 1; }
        run_ghidra_scripts "$2" binary_info.py
        ;;
    decompile)
        [ -z "$2" ] && { echo "Usage: ghidra.sh decompile <binary>"; exit 1; }
        run_ghidra_scripts "$2" decompile_all.py
        ;;
    functions)
        [ -z "$2" ] && { echo "Usage: ghidra.sh functions <binary>"; exit 1; }
        run_ghidra_scripts "$2" list_functions.py
        ;;
    strings)
        [ -z "$2" ] && { echo "Usage: ghidra.sh strings <binary>"; exit 1; }
        run_ghidra_scripts "$2" extract_strings.py
        ;;
    imports)
        [ -z "$2" ] && { echo "Usage: ghidra.sh imports <binary>"; exit 1; }
        run_ghidra_scripts "$2" list_imports.py
        ;;
    exports)
        [ -z "$2" ] && { echo "Usage: ghidra.sh exports <binary>"; exit 1; }
        run_ghidra_scripts "$2" list_exports.py
        ;;
    xrefs)
        [ -z "$2" ] && { echo "Usage: ghidra.sh xrefs <binary>"; exit 1; }
        run_ghidra_scripts "$2" xrefs_report.py
        ;;
    decrypt)
        [ -z "$2" ] && { echo "Usage: ghidra.sh decrypt <encrypted_file.enc.gz>"; exit 1; }
        ensure_running
        DECRYPTED=$(decrypt_in_container "$2")
        [ $? -eq 0 ] && echo "=== Decrypted file in container: $DECRYPTED ==="
        ;;

    # --- Host-side post-analysis ---
    yara-scan)
        # Usage:
        #   ghidra.sh yara-scan <host-path-or-.enc.gz>
        #   ghidra.sh yara-scan --in-container <container-absolute-path>
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh yara-scan <binary|encrypted.enc.gz>"
            echo "       ghidra.sh yara-scan --in-container <container-path>"
            exit 1
        fi
        ensure_running
        SCAN_TARGET=""
        YARA_CLEANUP=""
        if [ "$2" = "--in-container" ]; then
            [ -z "$3" ] && { echo "Error: --in-container requires a path argument"; exit 1; }
            # Verify the file exists inside the container before proceeding
            if ! dexec "$CONTAINER" test -f "$3" 2>/dev/null; then
                echo "Error: File not found inside container: $3"
                exit 1
            fi
            SCAN_TARGET="$3"
            YARA_CLEANUP=""  # do NOT delete: the file belongs to the caller
        elif [[ "$2" == *.enc.gz ]]; then
            SCAN_TARGET=$(decrypt_in_container "$2") || { echo "Error: Decryption failed."; exit 1; }
            YARA_CLEANUP="$SCAN_TARGET"
        else
            local_name=$(basename "$2")
            docker cp "$2" "$CONTAINER:/tmp/$local_name"
            SCAN_TARGET="/tmp/$local_name"
            YARA_CLEANUP="$SCAN_TARGET"
        fi
        docker cp "$SCRIPT_DIR_WIN/yara_scanner.py" "$CONTAINER:/tmp/yara_scanner.py"
        docker cp "$SCRIPT_DIR_WIN/yara-rules" "$CONTAINER:/tmp/yara-rules"
        dexec "$CONTAINER" mkdir -p /tmp/output
        echo "=== YARA Scan: $(basename "$SCAN_TARGET") ==="
        dexec "$CONTAINER" python3 /tmp/yara_scanner.py "$SCAN_TARGET" \
            --output-dir /tmp/output --rules-dir /tmp/yara-rules
        yara_json="/tmp/output/$(basename "${SCAN_TARGET%.*}")_yara.json"
        docker cp "$CONTAINER:$yara_json" "$SCRIPT_DIR_WIN/output/" 2>/dev/null || \
            docker cp "$CONTAINER:/tmp/output/" "$SCRIPT_DIR_WIN/output/" 2>/dev/null || true
        [ -n "$YARA_CLEANUP" ] && cleanup_container "$YARA_CLEANUP"
        echo "=== Results in: $SCRIPT_DIR_WIN/output/ ==="
        ;;
    capa)
        [ -z "$2" ] && { echo "Usage: ghidra.sh capa <binary|encrypted.enc.gz>"; exit 1; }
        echo "=== CAPA Analysis: $(basename "$2") ==="
        run_host_tool "$2" capa_scanner.py --output-dir "$SCRIPT_DIR_WIN/output"
        ;;
    pe-triage)
        # Usage:
        #   ghidra.sh pe-triage <host-path-or-.enc.gz>
        #   ghidra.sh pe-triage --in-container <container-absolute-path>
        #
        # Path policy:
        #   - .enc.gz files are decrypted INSIDE the container, then pe_triage.py
        #     is executed INSIDE the container. The plaintext binary never lands on
        #     the host (and we avoid MSYS path-mangling of `C:\Users\...\Temp\...`
        #     when handing off to host Python — see KB-22).
        #   - Plain host binaries still run host-side (fast path).
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh pe-triage <binary|file.enc.gz>"
            echo "       ghidra.sh pe-triage --in-container <container-path>"
            exit 1
        fi
        if [ "$2" = "--in-container" ]; then
            [ -z "$3" ] && { echo "Error: --in-container requires a path argument"; exit 1; }
            ensure_running
            if ! dexec "$CONTAINER" test -f "$3" 2>/dev/null; then
                echo "Error: File not found inside container: $3"
                exit 1
            fi
            echo "=== PE Triage (in-container): $(basename "$3") ==="
            docker cp "$SCRIPT_DIR_WIN/pe_triage.py" "$CONTAINER:/tmp/pe_triage.py"
            dexec "$CONTAINER" mkdir -p /tmp/output
            dexec "$CONTAINER" python3 /tmp/pe_triage.py "$3" --output-dir /tmp/output
            mkdir -p "$SCRIPT_DIR_WIN/output"
            docker cp "$CONTAINER:/tmp/output/." "$SCRIPT_DIR_WIN/output/" 2>/dev/null || true
        elif [[ "$2" == *.enc.gz ]]; then
            # Auto-route .enc.gz through in-container path (avoids MSYS host-path bug).
            ensure_running
            resolve_binary "$2" || exit 1
            local_target="$RESOLVED_BINARY"
            echo "=== PE Triage (in-container, auto-decrypted): $(basename "$2") ==="
            docker cp "$SCRIPT_DIR_WIN/pe_triage.py" "$CONTAINER:/tmp/pe_triage.py"
            dexec "$CONTAINER" mkdir -p /tmp/output
            dexec "$CONTAINER" python3 /tmp/pe_triage.py "$local_target" --output-dir /tmp/output
            mkdir -p "$SCRIPT_DIR_WIN/output"
            docker cp "$CONTAINER:/tmp/output/." "$SCRIPT_DIR_WIN/output/" 2>/dev/null || true
            cleanup_resolved
        else
            echo "=== PE Triage: $(basename "$2") ==="
            run_host_tool "$2" pe_triage.py --output-dir "$SCRIPT_DIR_WIN/output"
        fi
        ;;
    ioc-extract)
        [ -z "$2" ] && { echo "Usage: ghidra.sh ioc-extract <binary_name|file.enc.gz|host-path>"; exit 1; }
        # Accept full paths and .enc.gz: ioc_extractor.py needs the bare basename
        # (the Ghidra output files are named after the binary without the .enc.gz suffix).
        ioc_target=$(basename "${2%.enc.gz}")
        echo "=== IOC Extraction: $ioc_target ==="
        python3 "$SCRIPT_DIR_WIN/ioc_extractor.py" "$ioc_target" --output-dir "$SCRIPT_DIR_WIN/output"
        ;;
    classify)
        [ -z "$2" ] && { echo "Usage: ghidra.sh classify <binary_name|file.enc.gz|host-path>"; exit 1; }
        clf_target=$(basename "${2%.enc.gz}")
        echo "=== Malware Classification: $clf_target ==="
        python3 "$SCRIPT_DIR_WIN/malware_classifier.py" "$clf_target" --output-dir "$SCRIPT_DIR_WIN/output"
        ;;

    # --- Full pipeline ---
    analyze-full)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh analyze-full <binary|file.enc.gz>"
            exit 1
        fi
        ensure_running
        BINARY_NAME=$(basename "$2" | sed 's/\.enc\.gz$//' | sed 's/\.[^.]*$//')
        echo "=== Full Analysis Pipeline: $(basename "$2") ==="

        # Resolve binary once
        if [[ "$2" == *.enc.gz ]]; then
            resolve_binary "$2" || exit 1
            PIPELINE_BINARY="$RESOLVED_BINARY"
            win_temp="${USERPROFILE}/AppData/Local/Temp"
            PIPELINE_TMPDIR=$(mktemp -d -p "$win_temp")
            dec_name=$(basename "$PIPELINE_BINARY")
            docker cp "$CONTAINER:$PIPELINE_BINARY" "$PIPELINE_TMPDIR/$dec_name"
            HOST_BINARY="$PIPELINE_TMPDIR/$dec_name"
        else
            resolve_binary "$2" || exit 1
            PIPELINE_BINARY="$RESOLVED_BINARY"
            HOST_BINARY="$2"
            PIPELINE_TMPDIR=""
        fi
        auto_detect_processor "$PIPELINE_BINARY"

        # Run pipeline steps directly (no recursive shell invocation)
        PIPELINE_ERRORS=()

        echo "[0/5] PE Triage..."
        if ! python3 "$SCRIPT_DIR_WIN/pe_triage.py" "$HOST_BINARY" --output-dir "$SCRIPT_DIR_WIN/output" 2>&1; then
            echo "[!] PE Triage failed (non-critical, continuing)" >&2
            PIPELINE_ERRORS+=("PE-Triage")
        fi

        echo "[1/5] YARA Scan..."
        docker cp "$SCRIPT_DIR_WIN/yara_scanner.py" "$CONTAINER:/tmp/yara_scanner.py"
        docker cp "$SCRIPT_DIR_WIN/yara-rules" "$CONTAINER:/tmp/yara-rules"
        dexec "$CONTAINER" mkdir -p /tmp/output
        if ! dexec "$CONTAINER" python3 /tmp/yara_scanner.py "$PIPELINE_BINARY" \
            --output-dir /tmp/output --rules-dir /tmp/yara-rules 2>&1; then
            echo "[!] YARA scan failed (non-critical, continuing)" >&2
            PIPELINE_ERRORS+=("YARA-Scan")
        fi
        docker cp "$CONTAINER:/tmp/output/" "$SCRIPT_DIR_WIN/output/" 2>/dev/null || true

        echo "[2/5] CAPA Analysis..."
        if ! python3 "$SCRIPT_DIR_WIN/capa_scanner.py" "$HOST_BINARY" --output-dir "$SCRIPT_DIR_WIN/output" 2>&1; then
            echo "[!] CAPA analysis failed (non-critical, continuing)" >&2
            PIPELINE_ERRORS+=("CAPA")
        fi

        echo "[3/5] Ghidra Analysis..."
        if ! run_headless "$PIPELINE_BINARY" "${ALL_SCRIPTS[@]}"; then
            echo "[!] Ghidra analysis failed" >&2
            PIPELINE_ERRORS+=("Ghidra")
        fi

        echo "[4/5] IOC Extraction..."
        if ! python3 "$SCRIPT_DIR_WIN/ioc_extractor.py" "$BINARY_NAME" --output-dir "$SCRIPT_DIR_WIN/output" 2>&1; then
            echo "[!] IOC extraction failed (non-critical, continuing)" >&2
            PIPELINE_ERRORS+=("IOC-Extraction")
        fi

        echo "[5/5] Malware Classification..."
        if ! python3 "$SCRIPT_DIR_WIN/malware_classifier.py" "$BINARY_NAME" --output-dir "$SCRIPT_DIR_WIN/output" 2>&1; then
            echo "[!] Classification failed (non-critical, continuing)" >&2
            PIPELINE_ERRORS+=("Classification")
        fi

        cleanup_resolved
        [ -n "$PIPELINE_TMPDIR" ] && rm -rf "$PIPELINE_TMPDIR"
        if [ ${#PIPELINE_ERRORS[@]} -gt 0 ]; then
            echo "[!] Pipeline completed with errors: ${PIPELINE_ERRORS[*]}" >&2
            echo "=== Partial results in: $SCRIPT_DIR_WIN/output/ ==="
        else
            echo "=== Pipeline Complete. Results in: $SCRIPT_DIR_WIN/output/ ==="
        fi

        # Next-step guidance (skill chain is not auto-invokable from shell)
        echo ""
        echo "=== Next step (manual) ==="
        echo "Generate narrative report: invoke 'watchtowr-report' skill in Claude Code with these artifacts:"
        for _f in "${BINARY_NAME}_triage.json" "${BINARY_NAME}_yara.json" "${BINARY_NAME}_capa.json" "${BINARY_NAME}_iocs.json" "${BINARY_NAME}_classification.json"; do
            if [ -f "$SCRIPT_DIR_WIN/output/$_f" ]; then
                echo "  - $SCRIPT_DIR_WIN/output/$_f"
            fi
        done
        echo "After report: review with reviewer-style skill (e.g. ask Claude to spot blind spots)."
        ;;

    # --- AdaptixC2 beacon analysis ---
    # adaptix-profile:
    #   Extract embedded RC4-encrypted HTTP/SMB/TCP/DNS profile from an AdaptixC2
    #   beacon. .enc.gz inputs are decrypted INSIDE the container; the plaintext
    #   binary never lands on the host. Output JSON is saved to output/.
    #
    # adaptix-hash-match:
    #   Map all hash constants observed in agent.x64.exe_decompiled.c to API
    #   names using a bundled snapshot of AdaptixC2/ApiDefines.h. Requires the
    #   binary to have already been processed by `analyze` or `decompile`.
    adaptix-profile)
        [ -z "$2" ] && { echo "Usage: ghidra.sh adaptix-profile <binary|file.enc.gz>"; exit 1; }
        ensure_running
        resolve_binary "$2" || exit 1
        ax_target="$RESOLVED_BINARY"
        ax_bname=$(basename "${2%.enc.gz}")
        ax_bname="${ax_bname%.*}"
        echo "=== AdaptixC2 Profile Extraction: $(basename "$2") ===" >&2
        docker cp "$SCRIPT_DIR_WIN/scripts/adaptix_profile_extract.py" "$CONTAINER:/tmp/adaptix_profile_extract.py"
        mkdir -p "$SCRIPT_DIR_WIN/output"
        out_json="$SCRIPT_DIR_WIN/output/${ax_bname}_profile.json"
        if dexec "$CONTAINER" python3 /tmp/adaptix_profile_extract.py "$ax_target" > "$out_json"; then
            echo "[*] Saved: $out_json" >&2
            cat "$out_json"
        else
            rc=$?
            echo "[!] adaptix_profile_extract.py failed (rc=$rc) — pass --profile-rva / --profile-size if non-default layout" >&2
            rm -f "$out_json"
            cleanup_resolved
            exit $rc
        fi
        cleanup_resolved
        ;;
    adaptix-hash-match)
        [ -z "$2" ] && { echo "Usage: ghidra.sh adaptix-hash-match <binary|file.enc.gz>"; exit 1; }
        ensure_running
        ahm_bname=$(basename "${2%.enc.gz}")
        decomp_path="/analysis/output/${ahm_bname}_decompiled.c"
        if ! dexec "$CONTAINER" test -f "$decomp_path" 2>/dev/null; then
            echo "Error: $decomp_path not found inside container." >&2
            echo "  Run \`ghidra.sh analyze $2\` (or \`decompile $2\`) first." >&2
            exit 1
        fi
        echo "=== AdaptixC2 API Hash Match: $ahm_bname ===" >&2
        docker cp "$SCRIPT_DIR_WIN/scripts/adaptix_hash_match.py" "$CONTAINER:/tmp/adaptix_hash_match.py"
        docker cp "$SCRIPT_DIR_WIN/scripts/adaptix_apidefines.h" "$CONTAINER:/tmp/adaptix_apidefines.h"
        mkdir -p "$SCRIPT_DIR_WIN/output"
        out_csv="$SCRIPT_DIR_WIN/output/${ahm_bname}_api_hashes.csv"
        if dexec "$CONTAINER" python3 /tmp/adaptix_hash_match.py "$decomp_path" /tmp/adaptix_apidefines.h > "$out_csv"; then
            echo "[*] Saved: $out_csv" >&2
            head -1 "$out_csv"
            tail -n +2 "$out_csv" | wc -l | awk '{print "[*] " $1 " hashes resolved"}' >&2
        else
            rc=$?
            echo "[!] adaptix_hash_match.py failed (rc=$rc)" >&2
            rm -f "$out_csv"
            exit $rc
        fi
        ;;

    # --- .NET analysis ---
    dotnet-decompile)
        [ -z "$2" ] && { echo "Usage: ghidra.sh dotnet-decompile <binary|file.enc.gz>"; exit 1; }
        run_dotnet decompile "$2"
        ;;
    dotnet-metadata)
        [ -z "$2" ] && { echo "Usage: ghidra.sh dotnet-metadata <binary|file.enc.gz>"; exit 1; }
        run_dotnet metadata "$2"
        ;;
    dotnet-types)
        [ -z "$2" ] && { echo "Usage: ghidra.sh dotnet-types <binary|file.enc.gz>"; exit 1; }
        run_dotnet list-types "$2"
        ;;

    # --- Output file access (MSYS-safe) ---
    output)
        ensure_running
        subcmd="${2:-ls}"
        case "$subcmd" in
            ls)   dexec "$CONTAINER" bash -c "ls -la /analysis/output/${3:-*} 2>/dev/null || echo 'No files found'" ;;
            cat)  [ -z "$3" ] && { echo "Usage: ghidra.sh output cat <filename>" >&2; exit 1; }
                  dexec "$CONTAINER" cat "/analysis/output/$3" ;;
            head) [ -z "$3" ] && { echo "Usage: ghidra.sh output head <filename> [lines]" >&2; exit 1; }
                  dexec "$CONTAINER" head -n "${4:-50}" "/analysis/output/$3" ;;
            grep) [ -z "$3" ] || [ -z "$4" ] && { echo "Usage: ghidra.sh output grep <pattern> <filename>" >&2; exit 1; }
                  dexec "$CONTAINER" grep -n "$3" "/analysis/output/$4" ;;
            *)    echo "Usage: output {ls|cat|head|grep}" >&2; exit 1 ;;
        esac
        ;;

    # --- Utilities ---
    exec)  shift; dexec "$CONTAINER" "$@" ;;
    shell) MSYS_NO_PATHCONV=1 docker exec -it "$CONTAINER" /bin/bash ;;

    # --- Log ---
    log-show)
        _ls_target="${2:-}"
        if [ -z "$_ls_target" ]; then
            echo "Usage:" >&2
            echo "  ghidra.sh log-show <binary>           # latest log for binary (any date)" >&2
            echo "  ghidra.sh log-show <binary> --all     # all matching logs" >&2
            echo "  ghidra.sh log-show --list             # list every log file" >&2
            exit 1
        fi

        if [ "$_ls_target" = "--list" ]; then
            echo "Available command logs in $SCRIPT_DIR/logs/:"
            if [ -d "$SCRIPT_DIR/logs" ]; then
                ls -lt "$SCRIPT_DIR/logs/" 2>/dev/null | tail -n +2 | head -30 || true
            else
                echo "  (logs directory does not exist)"
            fi
            exit 0
        fi

        _ls_bname=$(basename "${_ls_target%.enc.gz}")
        _ls_bname="${_ls_bname%.*}"
        _ls_show_all=0
        if [ "${3:-}" = "--all" ]; then
            _ls_show_all=1
        fi

        # Find all logs matching this binary (across all dates), sorted newest first
        _ls_matches=""
        if [ -d "$SCRIPT_DIR/logs" ]; then
            _ls_matches=$(ls -t "$SCRIPT_DIR/logs/"*_"${_ls_bname}".md 2>/dev/null || true)
        fi

        if [ -z "$_ls_matches" ]; then
            echo "No log found for binary: $_ls_bname" >&2
            echo "Available logs:" >&2
            if [ -d "$SCRIPT_DIR/logs" ]; then
                ls "$SCRIPT_DIR/logs/" 2>/dev/null | head -10 >&2 || true
            else
                echo "  (logs directory does not exist)" >&2
            fi
            exit 1
        fi

        if [ "$_ls_show_all" = "1" ]; then
            for _ls_f in $_ls_matches; do
                echo "===== $(basename "$_ls_f") ====="
                cat "$_ls_f"
                echo ""
            done
        else
            _ls_latest=$(echo "$_ls_matches" | head -n 1)
            cat "$_ls_latest"
        fi
        ;;

    # --- Help ---
    help|--help|-h)
        cat <<'HELP'
Ghidra Headless Docker Helper

Usage: ghidra.sh <command> [args...]

Container Management:
  start                           Build and start container
  stop                            Stop and remove container
  status                          Show container status

Ghidra Analysis (Docker container):
  analyze [--processor ID] <bin>  Full analysis (all 7 scripts)
  info <binary>                   Architecture, sections, entry point
  decompile <binary>              Decompile all functions to C
  functions <binary>              List functions with addresses/sizes
  strings <binary>                Extract strings with xrefs
  imports <binary>                Import table (suspicious API flagged)
  exports <binary>                Export table
  xrefs <binary>                  Cross-reference report

Post-Analysis (host-side):
  pe-triage <binary>              PE Triage (pefile + DiE CLI)
  pe-triage --in-container <path> PE Triage on a file already inside the container
  yara-scan <binary>              YARA scan (APT attribution)
  yara-scan --in-container <path> YARA scan on a file already inside the container
  capa <binary>                   CAPA (capabilities + ATT&CK)
  ioc-extract <name>              Extract IOCs from output files
  classify <name>                 Classify malware type
  analyze-full <binary>           Full pipeline (all of the above)

.NET Analysis (ILSpy Docker):
  dotnet-decompile <binary>       Decompile to C# source
  dotnet-metadata <binary>        Extract assembly metadata
  dotnet-types <binary>           List types/classes

Output (MSYS-safe):
  output ls [pattern]             List output files
  output cat <filename>           Print file contents
  output head <filename> [N]      Print first N lines
  output grep <pattern> <file>    Search in output file

Utilities:
  decrypt <file.enc.gz>           Decrypt quarantine file in container
  exec <cmd...>                   Execute command in container
  shell                           Open interactive shell

Logging:
  log-show <binary>               Show today's command log for binary
  logs are auto-saved to: tools/ghidra-headless/logs/YYYYMMDD_<binary>.md

All commands auto-detect .enc.gz and ARM processor.
HELP
        ;;
    *)
        echo "ghidra.sh: unknown command '$1'" >&2
        echo "Run: bash tools/ghidra-headless/ghidra.sh help" >&2
        exit 1
        ;;
esac
