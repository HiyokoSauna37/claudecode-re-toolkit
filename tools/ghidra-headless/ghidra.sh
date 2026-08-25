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
# Raw binary mode (no PE header — shellcode/blob): uses BinaryLoader
RAW_BINARY=0
# Keep the staging copy that prepare_binary drops in input/ (opt-in, --keep-input-copy)
KEEP_INPUT_COPY=0

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

# Results of the last prepare_binary call. They are returned via globals rather
# than stdout so that the collision notice below can never leak into a caller's
# command substitution.
PREPARED_CONTAINER_PATH=""   # path to hand to the container
PREPARED_HOST_COPY=""        # host file WE created ("" = nothing of ours)
PREPARED_STAGE_DIR=""        # host dir WE created ("" = none)

# Stage a host file into input/ (bind-mounted to /analysis/input) and record the
# container path in PREPARED_CONTAINER_PATH. The copy is transient by default:
# resolve_binary moves it into RESOLVED_HOST_COPY / RESOLVED_STAGE_DIR and
# cleanup_resolved deletes it, so scanning a sample no longer leaves a plaintext
# copy inside the repo working tree.
#
# Collision policy: input/ may already hold a file with the same basename that
# the user put there deliberately. It is NEVER overwritten and NEVER deleted.
# The sample is staged into a private subdirectory input/.stage_<pid>_<ns>/
# instead, keeping the basename intact -- Ghidra names every output file after
# the imported program, so renaming the sample would rename all of its
# artifacts. The whole subdirectory is removed by cleanup_resolved.
prepare_binary() {
    local binary_path="$1"
    PREPARED_CONTAINER_PATH=""
    PREPARED_HOST_COPY=""
    PREPARED_STAGE_DIR=""
    [ -z "$binary_path" ] && { echo "Error: No binary specified" >&2; return 1; }

    local bname in_dir src_dir
    bname=$(basename "$binary_path")
    in_dir=$(cd "$SCRIPT_DIR/input" 2>/dev/null && pwd -P) || in_dir="$SCRIPT_DIR/input"

    if [ ! -f "$binary_path" ]; then
        # Not a host file -- accept a bare name that already sits in input/.
        if [ -f "$SCRIPT_DIR/input/$bname" ]; then
            PREPARED_CONTAINER_PATH="/analysis/input/$bname"
            return 0
        fi
        echo "Error: File not found: $binary_path" >&2
        return 1
    fi

    src_dir=$(cd "$(dirname "$binary_path")" 2>/dev/null && pwd -P) || src_dir=""

    # Source already lives in input/: nothing to copy (the self-copy used to
    # print "cp: ... are the same file"), and nothing of ours to delete later.
    if [ -n "$src_dir" ] && [ "$src_dir" = "$in_dir" ]; then
        PREPARED_CONTAINER_PATH="/analysis/input/$bname"
        return 0
    fi

    if [ -e "$SCRIPT_DIR/input/$bname" ]; then
        local stage
        stage=".stage_$$_$(date +%s%N)"
        if ! mkdir -p "$SCRIPT_DIR/input/$stage"; then
            echo "Error: could not create staging dir input/$stage" >&2
            return 1
        fi
        if ! cp "$binary_path" "$SCRIPT_DIR/input/$stage/$bname"; then
            rmdir "$SCRIPT_DIR/input/$stage" 2>/dev/null || true
            echo "Error: failed to stage $binary_path" >&2
            return 1
        fi
        echo "[*] input/$bname already exists - staged under input/$stage/ instead (existing file untouched)" >&2
        PREPARED_CONTAINER_PATH="/analysis/input/$stage/$bname"
        PREPARED_HOST_COPY="$SCRIPT_DIR/input/$stage/$bname"
        PREPARED_STAGE_DIR="$SCRIPT_DIR/input/$stage"
        return 0
    fi

    if ! cp "$binary_path" "$SCRIPT_DIR/input/$bname"; then
        echo "Error: failed to stage $binary_path" >&2
        return 1
    fi
    PREPARED_CONTAINER_PATH="/analysis/input/$bname"
    PREPARED_HOST_COPY="$SCRIPT_DIR/input/$bname"
    return 0
}

RESOLVED_BINARY=""
NEEDS_CLEANUP=0
# Host-side staging copy created by prepare_binary that cleanup_resolved must
# delete (empty = nothing to delete: container path, .enc.gz, .zip, a file the
# user deliberately put in input/, or --keep-input-copy).
RESOLVED_HOST_COPY=""
# Staging subdirectory input/.stage_* created on a basename collision; removed
# together with RESOLVED_HOST_COPY.
RESOLVED_STAGE_DIR=""

ZIP_PASSWORD=""

extract_zip_in_container() {
    local zip_path="$1"
    local password="$2"
    local bname
    bname=$(basename "$zip_path")

    echo "[*] Copying ZIP to container..." >&2
    docker cp "$zip_path" "$CONTAINER:/tmp/$bname"

    echo "[*] Extracting ZIP inside container..." >&2
    dexec "$CONTAINER" rm -rf /tmp/zip_extracted
    dexec "$CONTAINER" mkdir -p /tmp/zip_extracted
    if [ -n "$password" ]; then
        dexec "$CONTAINER" 7z x -p"$password" -o/tmp/zip_extracted "/tmp/$bname" -y >&2
    else
        dexec "$CONTAINER" 7z x -o/tmp/zip_extracted "/tmp/$bname" -y >&2
    fi
    dexec "$CONTAINER" rm -f "/tmp/$bname" 2>/dev/null || true

    # Select largest file (typical: single malware in ZIP)
    local target
    target=$(dexec "$CONTAINER" sh -c "find /tmp/zip_extracted -type f -exec ls -lS {} + | head -1 | awk '{print \$NF}'" 2>/dev/null)
    [ -z "$target" ] && { echo "Error: ZIP extraction produced no files" >&2; return 1; }
    echo "[*] ZIP target: $(basename "$target")" >&2
    echo "$target"
}

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

    if [[ "$binary_path" == *.zip ]]; then
        echo "[*] Detected ZIP archive, extracting in container..." >&2
        RESOLVED_BINARY=$(extract_zip_in_container "$binary_path" "$ZIP_PASSWORD") || { echo "Error: ZIP extraction failed" >&2; return 1; }
        NEEDS_CLEANUP=1
    elif [[ "$binary_path" == *.enc.gz ]]; then
        echo "[*] Detected .enc.gz quarantine file, auto-decrypting in container..." >&2
        RESOLVED_BINARY=$(decrypt_in_container "$binary_path") || { echo "Error: Decryption failed" >&2; return 1; }
        NEEDS_CLEANUP=1
    else
        # prepare_binary decides what (if anything) it had to create; only what
        # IT created is ever deleted, so a file the user put in input/ himself
        # is neither overwritten nor removed.
        prepare_binary "$binary_path" || return 1
        RESOLVED_BINARY="$PREPARED_CONTAINER_PATH"
        NEEDS_CLEANUP=0
        if [ "$KEEP_INPUT_COPY" -eq 0 ]; then
            RESOLVED_HOST_COPY="$PREPARED_HOST_COPY"
            RESOLVED_STAGE_DIR="$PREPARED_STAGE_DIR"
        elif [ -n "$PREPARED_HOST_COPY" ]; then
            echo "[*] --keep-input-copy: sample kept at ${PREPARED_HOST_COPY#"$SCRIPT_DIR/"}" >&2
        fi
    fi
}

cleanup_resolved() {
    if [ "$NEEDS_CLEANUP" -eq 1 ] && [ -n "$RESOLVED_BINARY" ]; then
        cleanup_container "$RESOLVED_BINARY"
    fi
    if [ -n "$RESOLVED_HOST_COPY" ] && [ -f "$RESOLVED_HOST_COPY" ]; then
        echo "[*] Removing staged copy: ${RESOLVED_HOST_COPY#"$SCRIPT_DIR/"}" >&2
        rm -f "$RESOLVED_HOST_COPY" 2>/dev/null || true
    fi
    if [ -n "$RESOLVED_STAGE_DIR" ] && [ -d "$RESOLVED_STAGE_DIR" ]; then
        rmdir "$RESOLVED_STAGE_DIR" 2>/dev/null || true
    fi
    RESOLVED_BINARY=""
    NEEDS_CLEANUP=0
    RESOLVED_HOST_COPY=""
    RESOLVED_STAGE_DIR=""
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

    # `docker cp` writes as root, so the ghidra user cannot unlink it from the
    # sticky /tmp — drop the encrypted copy as root and never let it be fatal.
    dexec -u root "$CONTAINER" rm -f "/tmp/$enc_basename" >/dev/null 2>&1 || true
    echo "/tmp/$dec_basename"
}

cleanup_container() {
    local container_path="$1"
    if [ -n "$container_path" ] && [[ "$container_path" == /tmp/* ]]; then
        echo "[*] Cleaning up decrypted file from container..."
        dexec "$CONTAINER" rm -f "$container_path"
    fi
}

# --- Per-invocation container output dirs ---
#
# The shared /tmp/output inside the container is never cleared, so any step that
# later `docker cp`s its results back used to drag artifacts of unrelated earlier
# samples into the host output/ dir. Every such step now writes into a fresh dir
# (same convention run_container_tool already used) and removes it afterwards.

mk_container_out() {
    local tag="${1:-out}"
    local d="/tmp/${tag}_out_$$_$(date +%s%N)"
    dexec "$CONTAINER" mkdir -p "$d" /analysis/output >/dev/null 2>&1 || true
    echo "$d"
}

# Publish a container output dir to /analysis/output (bind mount) and to the host
# output/ dir, then remove it unless <keep> is 1 (steps of one analyze-full run
# share a dir and keep it until the pipeline ends).
publish_container_out() {
    local d="$1"
    local keep="${2:-0}"
    [ -z "$d" ] && return 0
    dexec "$CONTAINER" sh -c "cp -f '$d'/* /analysis/output/ 2>/dev/null" >/dev/null 2>&1 || true
    mkdir -p "$SCRIPT_DIR_WIN/output"
    docker cp "$CONTAINER:$d/." "$SCRIPT_DIR_WIN/output/" >/dev/null 2>&1 || true
    [ "$keep" = "1" ] || dexec "$CONTAINER" rm -rf "$d" >/dev/null 2>&1 || true
    return 0
}

# Remove a container output dir without publishing it (failed step).
drop_container_out() {
    [ -n "$1" ] && dexec "$CONTAINER" rm -rf "$1" >/dev/null 2>&1
    return 0
}

# --- Output-file naming conventions -------------------------------------------
#
# output/ holds TWO different naming conventions and they do not agree:
#
#   Ghidra post-scripts (scripts/*.py -> ghidra_common.GhidraReport, which uses
#   program.getName()) name their files after the imported program, i.e. the
#   file name WITH its extension:
#       sample.exe_strings.txt   sample.exe_imports.txt   sample.exe_exports.txt
#       sample.exe_info.txt      sample.exe_functions.txt sample.exe_xrefs.txt
#       sample.exe_decompiled.c
#
#   The container Python tools use pathlib Path.stem, i.e. WITHOUT the last
#   extension:
#       sample_triage.json  sample_floss.json  sample_viz.json
#       sample_yara.json    sample_capa.json   sample_office.json
#       sample_pe_strings.txt  sample_pe_imports.txt   (pe_fallback_extract.py)
#
# ioc_extractor.py / malware_classifier.py / maldev_techniques.py read the FIRST
# group via ghidra_output_utils.find_ghidra_outputs(), falling back to
# pe_fallback_extract.py's files from the second group. They must therefore be
# handed the name that is actually on disk. The stand-alone ioc-extract /
# classify / maldev-detect subcommands already pass the full basename;
# analyze-full used to strip the extension, which is why every sample with an
# extension silently produced no _iocs.json and no _classification.json.
#
# _have_report_inputs <name>: true when output/ holds at least one file that
# find_ghidra_outputs() would pick up for <name>.
_have_report_inputs() {
    local n="$1" s
    if [ -z "$n" ]; then return 1; fi
    for s in _strings.txt _imports.txt _exports.txt _decompiled.c \
             _decompiled_functions.c _info.txt _functions.txt _xrefs.txt \
             _decrypted_strings.txt _pe_strings.txt _pe_imports.txt; do
        if [ -f "$SCRIPT_DIR/output/${n}${s}" ]; then
            return 0
        fi
    done
    return 1
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

    [ "$RAW_BINARY" -eq 1 ] && {
        cmd+=(-loader BinaryLoader -loader-baseAddr 0x0)
        echo "[*] Raw binary mode: BinaryLoader @ base 0x0" >&2
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

# Run a Python analysis tool INSIDE the container.
#
# Path policy (same rule as the pe-triage --in-container branch, KB-22):
#   Any tool that opens the sample itself (capa / FLOSS / pe_triage /
#   pe_fallback_extract) MUST run in the container. Decrypted malware never
#   lands on the host — CLAUDE.md forbids it — and we also avoid MSYS mangling
#   of `C:\Users\...\Temp\...` when handing paths to host Python.
#   capa / floss / pefile are baked into the image (see Dockerfile).
#
# Output convention (same as yara-scan): the tool writes to a per-invocation
# /tmp dir, results are published to /analysis/output (bind-mounted to ./output)
# and copied back to the host output dir as a fallback.
#
# Usage: run_container_tool <container_binary_path> <python_script> [extra_args...]
run_container_tool() {
    local target="$1"
    local py_script="$2"
    shift 2
    local outdir
    outdir=$(mk_container_out tool)
    local rc=0

    docker cp "$SCRIPT_DIR_WIN/$py_script" "$CONTAINER:/tmp/$py_script" >/dev/null 2>&1
    dexec "$CONTAINER" python3 "/tmp/$py_script" "$target" --output-dir "$outdir" "$@" || rc=$?
    # Publish only on success - the same rule the office-analyze branch already
    # follows. A failed step may have written a half-finished JSON, and
    # analyze-full's later ioc-extract / classify steps read output/*.json
    # indiscriminately, so a truncated file there is worse than no file at all.
    # No caller wants partial output: pe_triage / capa_scanner / floss_analyzer /
    # pe_fallback_extract only exit non-zero when they could not analyse the
    # sample at all, and every analyze-full step already tolerates a missing
    # artifact.
    if [ "$rc" -eq 0 ]; then
        publish_container_out "$outdir"
    else
        drop_container_out "$outdir"
    fi
    return $rc
}

# Resolve <binary> (host path / .enc.gz / .zip / container path) and run a
# Python analysis tool on it inside the container.
# Usage: run_tool_on_binary <binary_path> <python_script> [extra_args...]
run_tool_on_binary() {
    local binary="$1"
    local py_script="$2"
    shift 2
    local rc=0
    ensure_running
    resolve_binary "$binary" || exit 1
    run_container_tool "$RESOLVED_BINARY" "$py_script" "$@" || rc=$?
    cleanup_resolved
    return $rc
}

# Run dotnet-decompile tool
run_dotnet() {
    local subcmd="$1"
    local binary="$2"
    local tool="$REPO_ROOT/tools/dotnet-decompiler/dotnet-decompile.exe"
    [ ! -f "$tool" ] && {
        echo "Error: dotnet-decompile.exe not found. Build with: cd tools/dotnet-decompiler && go build -trimpath -ldflags=\"-s -w\" -o dotnet-decompile.exe ."
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

# --- Global flag pre-parse ---
# --keep-input-copy: keep the sample copy that prepare_binary stages in input/.
# By default that copy is transient (see cleanup_resolved) so scanning a sample
# does not leave a plaintext binary in the repo working tree.
# Not stripped for `exec`/`shell`: their args are forwarded verbatim.
if [ "${1:-}" != "exec" ] && [ "${1:-}" != "shell" ]; then
    _gargs=()
    for _ga in "$@"; do
        if [ "$_ga" = "--keep-input-copy" ]; then
            KEEP_INPUT_COPY=1
        else
            _gargs+=("$_ga")
        fi
    done
    set -- "${_gargs[@]}"
fi

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
                --raw-x64) PROCESSOR_ID="x86:LE:64:default"; RAW_BINARY=1; shift ;;
                --raw-x86) PROCESSOR_ID="x86:LE:32:default"; RAW_BINARY=1; shift ;;
                *) ANALYZE_TARGET="$2"; shift; break ;;
            esac
        done
        [ -z "$ANALYZE_TARGET" ] && ANALYZE_TARGET="$2"
        echo "=== Full Analysis: $(basename "$ANALYZE_TARGET") ==="
        run_ghidra_scripts "$ANALYZE_TARGET" "${ALL_SCRIPTS[@]}"
        echo "=== Results in: $SCRIPT_DIR_WIN/output/ ==="
        ;;
    info|decompile|functions|strings|imports|exports|xrefs)
        subcmd="$1"
        shift
        # Parse optional --raw-x64 / --raw-x86 / --processor flags
        target=""
        while [ $# -gt 0 ]; do
            case "$1" in
                --raw-x64) PROCESSOR_ID="x86:LE:64:default"; RAW_BINARY=1; shift ;;
                --raw-x86) PROCESSOR_ID="x86:LE:32:default"; RAW_BINARY=1; shift ;;
                --processor) PROCESSOR_ID="$2"; shift 2 ;;
                *) target="$1"; shift; break ;;
            esac
        done
        [ -z "$target" ] && { echo "Usage: ghidra.sh $subcmd [--raw-x64|--raw-x86|--processor ID] <binary>"; exit 1; }
        script_map="info:binary_info.py decompile:decompile_all.py functions:list_functions.py strings:extract_strings.py imports:list_imports.py exports:list_exports.py xrefs:xrefs_report.py"
        script=""
        for entry in $script_map; do
            key="${entry%%:*}"
            val="${entry#*:}"
            [ "$key" = "$subcmd" ] && script="$val"
        done
        run_ghidra_scripts "$target" "$script"
        ;;
    # xrefs) is handled by the unified info|decompile|...|xrefs) case above
    decrypt)
        [ -z "$2" ] && { echo "Usage: ghidra.sh decrypt <encrypted_file.enc.gz>"; exit 1; }
        ensure_running
        DECRYPTED=$(decrypt_in_container "$2")
        [ $? -eq 0 ] && echo "=== Decrypted file in container: $DECRYPTED ==="
        ;;

    encrypt)
        [ -z "$2" ] && { echo "Usage: ghidra.sh encrypt <container_path>  (re-encrypt to .enc.gz)"; exit 1; }
        ensure_running
        CONTAINER_FILE="$2"
        BASENAME=$(basename "$CONTAINER_FILE")
        ENC_GZ_NAME="${BASENAME}.enc.gz"
        ENC_GZ_CONTAINER="/tmp/${ENC_GZ_NAME}"
        echo "[*] Encrypting $CONTAINER_FILE -> $ENC_GZ_NAME"
        # The password lives in .env on the host; it must be handed to the
        # container explicitly (docker exec does not inherit the host env).
        ENC_PASSWORD=""
        [ -f "$ENV_FILE" ] && ENC_PASSWORD=$(grep -E '^QUARANTINE_PASSWORD=' "$ENV_FILE" | cut -d= -f2- | tr -d '"' | tr -d "'")
        [ -z "$ENC_PASSWORD" ] && { echo "Error: QUARANTINE_PASSWORD not found in $ENV_FILE"; exit 1; }
        dexec -e QUARANTINE_PASSWORD="$ENC_PASSWORD" "$CONTAINER" python3 -c "
import hashlib, gzip, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
password = os.environ.get('QUARANTINE_PASSWORD', '')
if not password:
    print('ERROR: QUARANTINE_PASSWORD not set'); exit(1)
key = hashlib.sha256(password.encode()).digest()
data = open('$CONTAINER_FILE', 'rb').read()
iv = os.urandom(16)
padder = padding.PKCS7(128).padder()
padded = padder.update(data) + padder.finalize()
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encrypted = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
with gzip.open('$ENC_GZ_CONTAINER', 'wb') as gz:
    gz.write(iv + encrypted)
print(f'[OK] Encrypted: $ENC_GZ_CONTAINER ({os.path.getsize(\"$ENC_GZ_CONTAINER\")} bytes)')
print(f'[OK] Original SHA256: {hashlib.sha256(data).hexdigest()}')
"
        # OUTPUT_DIR was never defined here — the copy used to land in the drive
        # root (`/name.enc.gz` → C:\name.enc.gz under MSYS).
        mkdir -p "$SCRIPT_DIR_WIN/output"
        HOST_OUTPUT="$SCRIPT_DIR_WIN/output/$ENC_GZ_NAME"
        docker cp "$CONTAINER:$ENC_GZ_CONTAINER" "$HOST_OUTPUT" 2>/dev/null && \
            echo "[OK] Copied to host: $HOST_OUTPUT" || \
            echo "[*] Encrypted file in container: $ENC_GZ_CONTAINER"
        ;;

    # --- Host-side post-analysis ---
    yara-scan)
        # Usage:
        #   ghidra.sh yara-scan <host-path-or-.enc.gz>
        #   ghidra.sh yara-scan --in-container <container-absolute-path>
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh yara-scan <binary|encrypted.enc.gz>"
            echo "       ghidra.sh yara-scan --in-container <container-path>"
            echo ""
            echo "  --keep-input-copy   Keep the sample copy staged in input/"
            echo "                      (default: it is removed when the scan ends)"
            exit 1
        fi
        ensure_running
        SCAN_TARGET=""
        if [ "$2" = "--in-container" ]; then
            [ -z "$3" ] && { echo "Error: --in-container requires a path argument"; exit 1; }
            # Verify the file exists inside the container before proceeding
            if ! dexec "$CONTAINER" test -f "$3" 2>/dev/null; then
                echo "Error: File not found inside container: $3"
                exit 1
            fi
            SCAN_TARGET="$3"   # do NOT delete: the file belongs to the caller
        else
            # resolve_binary handles .enc.gz (decrypt in container), .zip and plain
            # host files (staged via the mounted input/ dir). Never docker-cp the
            # sample into /tmp: that lands as root and blocks a later decryption of
            # the same basename.
            resolve_binary "$2" || exit 1
            SCAN_TARGET="$RESOLVED_BINARY"  # cleanup_resolved owns it
        fi
        docker cp "$SCRIPT_DIR_WIN/yara_scanner.py" "$CONTAINER:/tmp/yara_scanner.py"
        docker cp "$SCRIPT_DIR_WIN/yara-rules" "$CONTAINER:/tmp/yara-rules"
        YARA_OUT=$(mk_container_out yara)
        echo "=== YARA Scan: $(basename "$SCAN_TARGET") ==="
        _yara_rc=0
        dexec "$CONTAINER" python3 /tmp/yara_scanner.py "$SCAN_TARGET" \
            --output-dir "$YARA_OUT" --rules-dir /tmp/yara-rules || _yara_rc=$?
        publish_container_out "$YARA_OUT"
        cleanup_resolved
        [ "$_yara_rc" -eq 0 ] || exit "$_yara_rc"
        echo "=== Results in: $SCRIPT_DIR_WIN/output/ ==="
        ;;
    capa)
        [ -z "$2" ] && { echo "Usage: ghidra.sh capa [--keep-input-copy] <binary|encrypted.enc.gz>"; exit 1; }
        echo "=== CAPA Analysis: $(basename "$2") ==="
        run_tool_on_binary "$2" capa_scanner.py "${@:3}"
        echo "=== Results in: $SCRIPT_DIR_WIN/output/ ==="
        ;;
    pe-fallback-extract)
        [ -z "$2" ] && { echo "Usage: ghidra.sh pe-fallback-extract [--keep-input-copy] <binary|file.enc.gz>"; exit 1; }
        echo "=== PE Fallback Extraction: $(basename "$2") ==="
        run_tool_on_binary "$2" pe_fallback_extract.py
        echo "=== Results in: $SCRIPT_DIR_WIN/output/ ==="
        ;;
    pe-triage)
        # Usage:
        #   ghidra.sh pe-triage <host-path-or-.enc.gz>
        #   ghidra.sh pe-triage --in-container <container-absolute-path>
        #
        # Path policy (KB-22): pe_triage.py ALWAYS runs inside the container —
        # plain host files included. The plaintext binary never lands on the host,
        # and Windows temp paths are never handed to host Python (MSYS mangles
        # `C:\Users\...\Temp\...`).
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh pe-triage <binary|file.enc.gz>"
            echo "       ghidra.sh pe-triage --in-container <container-path>"
            echo ""
            echo "  --keep-input-copy   Keep the sample copy staged in input/"
            echo "                      (default: it is removed when triage ends)"
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
            run_container_tool "$3" pe_triage.py
        else
            echo "=== PE Triage (in-container): $(basename "$2") ==="
            run_tool_on_binary "$2" pe_triage.py
        fi
        echo "=== Results in: $SCRIPT_DIR_WIN/output/ ==="
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
    maldev-detect|maldev|mdt)
        if [ -z "$2" ] || [ "$2" = "-h" ] || [ "$2" = "--help" ]; then
            cat <<'MDT_HELP'
Usage:
  ghidra.sh maldev-detect <binary>                   # analyze 既存output (デフォルト)
  ghidra.sh maldev-detect scan-binary <path>         # 生バイナリから直接検出
  ghidra.sh maldev-detect list                       # 検出可能 15 テクニック一覧
  ghidra.sh maldev-detect <binary> --min-severity high
  ghidra.sh maldev-detect <binary> --json-only

説明:
  f00crew 0x33 系のオペレータ技術 (PEB walking / API hashing / Process Hollowing /
  Early Bird APC / Kernel callback abuse / DKOM / 多層暗号 / Direct syscall) を
  検出して MITRE ATT&CK にマップする。

モード:
  analyze       既存の analyze-full output を読んで検出（精密、デフォルト）
  scan-binary   生バイナリ直接スキャン（Ghidra 不要、5 秒以内）
  list          15 テクニックのカタログ表示

出力:
  output/<binary>_maldev.json  severity / confidence / 証拠 / ATT&CK 付き

例:
  ghidra.sh maldev-detect stealc                    # ステム名
  ghidra.sh maldev-detect input/stealc.exe          # フルパス
  ghidra.sh maldev-detect sample.enc.gz             # 暗号化済 (.enc.gz は自動展開しない、scan-binary を使う)
  ghidra.sh maldev-detect scan-binary sample.exe    # Ghidra 結果を待ちたくない時
  ghidra.sh maldev-detect list                      # 何が検出できるか確認

備考:
  - analyze モードは先に `ghidra.sh analyze <binary>` が必要
  - YARA カスタムルール (yara-rules/custom/maldev_techniques.yar) と相補的
MDT_HELP
            exit 0
        fi

        # サブコマンド (scan-binary / list) はそのまま透過、それ以外はステム化
        case "$2" in
            list)
                python3 "$SCRIPT_DIR_WIN/maldev_techniques.py" list
                ;;
            scan-binary)
                [ -z "$3" ] && { echo "Usage: ghidra.sh maldev-detect scan-binary <path>"; exit 1; }
                echo "=== MalDev Scan: $(basename "$3") ==="
                python3 "$SCRIPT_DIR_WIN/maldev_techniques.py" scan-binary \
                    "$3" --output-dir "$SCRIPT_DIR_WIN/output" "${@:4}"
                ;;
            analyze)
                [ -z "$3" ] && { echo "Usage: ghidra.sh maldev-detect analyze <binary>"; exit 1; }
                mdt_target=$(basename "${3%.enc.gz}")
                echo "=== MalDev Detect: $mdt_target ==="
                python3 "$SCRIPT_DIR_WIN/maldev_techniques.py" analyze \
                    "$mdt_target" --output-dir "$SCRIPT_DIR_WIN/output" "${@:4}"
                ;;
            *)
                # 後方互換: analyze モードのショートカット
                mdt_target=$(basename "${2%.enc.gz}")
                echo "=== MalDev Detect: $mdt_target ==="
                python3 "$SCRIPT_DIR_WIN/maldev_techniques.py" analyze \
                    "$mdt_target" --output-dir "$SCRIPT_DIR_WIN/output" "${@:3}"
                ;;
        esac
        ;;

    # --- FLOSS obfuscated string analysis (in-container) ---
    floss)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh floss <binary|file.enc.gz> [--min-len N] [--timeout SEC]"
            echo "                       [--keep-input-copy]"
            echo ""
            echo "Extracts strings that raw extraction misses:"
            echo "  Stack strings   — built byte-by-byte on the stack"
            echo "  Tight-loop      — XOR/ROT obfuscation loops"
            echo "  Decoded strings — emulation-based dynamic extraction"
            echo ""
            echo "(FLOSS runs inside the Ghidra container — no host install needed)"
            echo "--keep-input-copy keeps the staged copy in input/ (default: removed after the run)"
            exit 1
        fi
        echo "=== FLOSS Analysis: $(basename "$2") ==="
        run_tool_on_binary "$2" floss_analyzer.py "${@:3}"
        echo "=== Results in: $SCRIPT_DIR_WIN/output/ ==="
        ;;

    # --- Office document analysis (oletools, in-container) ---
    office-analyze)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh office-analyze <file|file.enc.gz> [--force]"
            echo ""
            echo "Analyzes Office documents for malicious content:"
            echo "  VBA macros, auto-exec triggers (AutoOpen/Document_Open/...)"
            echo "  Suspicious API calls (Shell, CreateObject, PowerShell, ...)"
            echo "  OLE streams, embedded objects"
            echo ""
            echo "Supported: .doc .xls .ppt .docx .xlsm .docm .rtf .msg .pptm ..."
            echo "(auto-detected by magic bytes if extension is missing)"
            exit 1
        fi
        ensure_running
        resolve_binary "$2" || exit 1
        _off_target="$RESOLVED_BINARY"
        echo "=== Office Analysis: $(basename "$2") ==="
        docker cp "$SCRIPT_DIR_WIN/office_analyzer.py" "$CONTAINER:/tmp/office_analyzer.py"
        _off_out=$(mk_container_out office)
        if dexec "$CONTAINER" python3 /tmp/office_analyzer.py "$_off_target" \
            --output-dir "$_off_out" "${@:3}"; then
            publish_container_out "$_off_out"
            echo "=== Results in: $SCRIPT_DIR_WIN/output/ ==="
        else
            _off_rc=$?
            drop_container_out "$_off_out"
            cleanup_resolved
            exit $_off_rc
        fi
        cleanup_resolved
        ;;

    # --- Binary visualization (entropy profile, bigram, histogram) ---
    viz)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh viz <binary|file.enc.gz> [--no-plot] [--max-mb N]"
            echo ""
            echo "Generates 3-panel visualization for packer triage:"
            echo "  Entropy profile  — packed sections stay near 8.0 bits/byte"
            echo "  Byte histogram   — flat distribution = encrypted/packed"
            echo "  Bigram heatmap   — uniform = packed/compressed (log scale)"
            echo ""
            echo "Entropy verdict:"
            echo "  PACKED_OR_ENCRYPTED  avg > 7.2 or > 60% windows above 7.0"
            echo "  COMPRESSED_OR_MIXED  avg 6.0–7.2"
            echo "  LIKELY_CLEAN         avg < 6.0"
            echo ""
            echo "  --no-plot    JSON only (faster, no matplotlib needed)"
            echo "  --max-mb N   Read limit in MB (default: 200)"
            exit 1
        fi
        ensure_running
        resolve_binary "$2" || exit 1
        _viz_target="$RESOLVED_BINARY"
        # Collect extra flags (--no-plot, --max-mb N) and pass through
        _viz_flags=""
        _i=3
        while [ "$_i" -le "$#" ]; do
            eval "_viz_flags=\"$_viz_flags \${$_i}\""
            _i=$(( _i + 1 ))
        done
        echo "=== Binary Visualization: $(basename "$2") ==="
        docker cp "$SCRIPT_DIR_WIN/binary_viz.py" "$CONTAINER:/tmp/binary_viz.py"
        _viz_out=$(mk_container_out viz)
        _viz_rc=0
        # shellcheck disable=SC2086
        dexec "$CONTAINER" python3 /tmp/binary_viz.py "$_viz_target" \
            --output-dir "$_viz_out" $_viz_flags || _viz_rc=$?
        publish_container_out "$_viz_out"
        echo "=== Results in: $SCRIPT_DIR_WIN/output/ ==="
        cleanup_resolved
        [ "$_viz_rc" -eq 0 ] || exit "$_viz_rc"
        ;;

    # --- Full pipeline ---
    analyze-full)
        if [ -z "$2" ]; then
            echo "Usage: ghidra.sh analyze-full [--zip-password PW] <binary|file.enc.gz|file.zip>"
            exit 1
        fi
        # Parse --zip-password flag
        _target="$2"
        if [ "$2" = "--zip-password" ]; then
            ZIP_PASSWORD="$3"
            _target="$4"
            [ -z "$_target" ] && { echo "Usage: ghidra.sh analyze-full --zip-password PW <file.zip>"; exit 1; }
        fi
        ensure_running
        # BINARY_NAME         = Path.stem convention  -> _triage/_floss/_viz/...
        # GHIDRA_PROGRAM_NAME = Ghidra program name   -> _strings/_imports/...
        # (see the "Output-file naming conventions" block above)
        BINARY_NAME=$(basename "$_target" | sed 's/\.enc\.gz$//' | sed 's/\.[^.]*$//')
        GHIDRA_PROGRAM_NAME=$(basename "$_target" | sed 's/\.enc\.gz$//')
        echo "=== Full Analysis Pipeline: $(basename "$_target") ==="

        # Resolve binary once. Every tool that touches the sample runs INSIDE the
        # container (CLAUDE.md: no plaintext malware on the host), so the pipeline
        # only ever holds a container-internal path.
        resolve_binary "$_target" || exit 1
        PIPELINE_BINARY="$RESOLVED_BINARY"
        # One output dir for the whole run: steps may accumulate artifacts within
        # this invocation, but nothing from an earlier run can bleed in.
        PIPELINE_OUT=$(mk_container_out pipeline)
        # Update both names from the actual resolved binary (a ZIP / .enc.gz may
        # carry a different filename than the argument we were given).
        BINARY_NAME=$(basename "$PIPELINE_BINARY" | sed 's/\.enc\.gz$//' | sed 's/\.[^.]*$//')
        GHIDRA_PROGRAM_NAME=$(basename "$PIPELINE_BINARY")
        auto_detect_processor "$PIPELINE_BINARY"

        # Run pipeline steps directly (no recursive shell invocation)
        PIPELINE_ERRORS=()

        echo "[0/7] PE Triage..."
        _triage_exit=0
        _triage_output=$(run_container_tool "$PIPELINE_BINARY" pe_triage.py --json 2>&1) || _triage_exit=$?
        if [ $_triage_exit -ne 0 ]; then
            echo "[!] PE Triage failed (non-critical, continuing)" >&2
            PIPELINE_ERRORS+=("PE-Triage")
        else
            echo "$_triage_output" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('verdict',[''])[0])" 2>/dev/null | read -r _verdict || true
        fi

        # MSI detected: extract and analyze embedded PEs individually
        if echo "$_triage_output" | grep -q '"MSI_INSTALLER"' 2>/dev/null; then
            echo "[*] MSI installer detected — extracting embedded PEs..." >&2
            dexec "$CONTAINER" mkdir -p /tmp/msi_extracted
            dexec "$CONTAINER" sh -c "cd /tmp/msi_extracted && 7z x '$PIPELINE_BINARY' -y" >/dev/null 2>&1
            # Find all PE files inside
            _pe_list=$(dexec "$CONTAINER" sh -c "cd /tmp/msi_extracted && file * 2>/dev/null | grep -i 'PE32\|executable' | cut -d: -f1" 2>/dev/null)
            if [ -n "$_pe_list" ]; then
                echo "[*] Found PEs in MSI: $_pe_list" >&2
                # Select the largest PE as main analysis target
                _largest=$(dexec "$CONTAINER" sh -c "cd /tmp/msi_extracted && ls -lS $_pe_list 2>/dev/null | head -1 | awk '{print \$NF}'" 2>/dev/null)
                if [ -n "$_largest" ]; then
                    PIPELINE_BINARY="/tmp/msi_extracted/$_largest"
                    BINARY_NAME=$(echo "$_largest" | sed 's/\.[^.]*$//')
                    GHIDRA_PROGRAM_NAME="$_largest"
                    echo "[*] MSI primary target: $_largest" >&2
                    # Run YARA on ALL extracted PEs
                    echo "[*] Running YARA on all MSI-embedded PEs..." >&2
                    for _pe in $_pe_list; do
                        _yara_out=$(dexec "$CONTAINER" python3 /opt/ghidra-scripts/yara_scanner.py "/tmp/msi_extracted/$_pe" 2>/dev/null | grep -v '^$' | head -3)
                        [ -n "$_yara_out" ] && echo "  YARA [$_pe]: $_yara_out" >&2
                    done
                fi
            else
                echo "[!] No PE files found in MSI extraction" >&2
                PIPELINE_ERRORS+=("MSI-NoPE")
            fi
        fi

        echo "[1/7] FLOSS Obfuscated String Analysis..."
        if run_container_tool "$PIPELINE_BINARY" floss_analyzer.py; then
            echo "[+] FLOSS complete" >&2
        else
            echo "[!] FLOSS failed (non-critical, continuing)" >&2
            PIPELINE_ERRORS+=("FLOSS")
        fi

        echo "[2/7] Binary Visualization..."
        docker cp "$SCRIPT_DIR_WIN/binary_viz.py" "$CONTAINER:/tmp/binary_viz.py"
        if dexec "$CONTAINER" python3 /tmp/binary_viz.py "$PIPELINE_BINARY" \
            --output-dir "$PIPELINE_OUT" 2>&1; then
            publish_container_out "$PIPELINE_OUT" 1
        else
            echo "[!] Binary viz failed (non-critical, continuing)" >&2
            PIPELINE_ERRORS+=("BinaryViz")
        fi

        # Auto-detect Office documents and run oletools
        _sample_ext="$(basename "$PIPELINE_BINARY")"
        _sample_ext="${_sample_ext##*.}"
        _sample_ext=$(echo "$_sample_ext" | tr '[:upper:]' '[:lower:]')
        case "$_sample_ext" in
            doc|dot|xls|xlt|ppt|docx|docm|dotm|xlsx|xlsm|xltm|pptx|pptm|rtf|msg)
                echo "[2b/7] Office Document Detected — running oletools..."
                docker cp "$SCRIPT_DIR_WIN/office_analyzer.py" "$CONTAINER:/tmp/office_analyzer.py"
                if dexec "$CONTAINER" python3 /tmp/office_analyzer.py "$PIPELINE_BINARY" \
                    --output-dir "$PIPELINE_OUT" 2>&1; then
                    publish_container_out "$PIPELINE_OUT" 1
                else
                    echo "[!] Office analysis failed (non-critical)" >&2
                    PIPELINE_ERRORS+=("OleTools")
                fi
                ;;
        esac

        echo "[3/7] YARA Scan..."
        docker cp "$SCRIPT_DIR_WIN/yara_scanner.py" "$CONTAINER:/tmp/yara_scanner.py"
        docker cp "$SCRIPT_DIR_WIN/yara-rules" "$CONTAINER:/tmp/yara-rules"
        if ! dexec "$CONTAINER" python3 /tmp/yara_scanner.py "$PIPELINE_BINARY" \
            --output-dir "$PIPELINE_OUT" --rules-dir /tmp/yara-rules 2>&1; then
            echo "[!] YARA scan failed (non-critical, continuing)" >&2
            PIPELINE_ERRORS+=("YARA-Scan")
        fi
        publish_container_out "$PIPELINE_OUT" 1

        echo "[4/7] CAPA Analysis..."
        if ! run_container_tool "$PIPELINE_BINARY" capa_scanner.py; then
            echo "[!] CAPA analysis failed (non-critical, continuing)" >&2
            PIPELINE_ERRORS+=("CAPA")
        fi

        echo "[5/7] Ghidra Analysis..."
        if ! run_headless "$PIPELINE_BINARY" "${ALL_SCRIPTS[@]}"; then
            echo "[!] Ghidra analysis failed — running PE fallback extraction" >&2
            PIPELINE_ERRORS+=("Ghidra")
            run_container_tool "$PIPELINE_BINARY" pe_fallback_extract.py || true
        fi

        # Which name must the report tools be given? Normally the Ghidra program
        # name; but if Ghidra failed and step [5/7] fell back to
        # pe_fallback_extract.py, the only readable inputs are its stem-named
        # _pe_strings.txt / _pe_imports.txt, so fall back to BINARY_NAME.
        REPORT_NAME="$GHIDRA_PROGRAM_NAME"
        if ! _have_report_inputs "$REPORT_NAME"; then
            if _have_report_inputs "$BINARY_NAME"; then
                echo "[*] No ${GHIDRA_PROGRAM_NAME}_* Ghidra outputs - using PE-fallback name '$BINARY_NAME'" >&2
                REPORT_NAME="$BINARY_NAME"
            else
                echo "[!] output/ holds no Ghidra or PE-fallback files for '$GHIDRA_PROGRAM_NAME'" >&2
            fi
        fi

        echo "[6/7] IOC Extraction..."
        _ioc_ok=1
        python3 "$SCRIPT_DIR_WIN/ioc_extractor.py" "$REPORT_NAME" --output-dir "$SCRIPT_DIR_WIN/output" 2>&1 || _ioc_ok=0
        # Exit status alone is not enough: a step that finds no inputs must never
        # pass for success, so the artifact itself has to be there.
        [ -f "$SCRIPT_DIR/output/${REPORT_NAME}_iocs.json" ] || _ioc_ok=0
        if [ "$_ioc_ok" -ne 1 ]; then
            echo "[!] IOC extraction produced no ${REPORT_NAME}_iocs.json (continuing)" >&2
            PIPELINE_ERRORS+=("IOC-Extraction")
        fi

        echo "[7/7] Malware Classification..."
        _clf_ok=1
        python3 "$SCRIPT_DIR_WIN/malware_classifier.py" "$REPORT_NAME" --output-dir "$SCRIPT_DIR_WIN/output" 2>&1 || _clf_ok=0
        [ -f "$SCRIPT_DIR/output/${REPORT_NAME}_classification.json" ] || _clf_ok=0
        if [ "$_clf_ok" -ne 1 ]; then
            echo "[!] Classification produced no ${REPORT_NAME}_classification.json (continuing)" >&2
            PIPELINE_ERRORS+=("Classification")
        fi

        drop_container_out "$PIPELINE_OUT"
        cleanup_resolved
        if [ ${#PIPELINE_ERRORS[@]} -gt 0 ]; then
            echo "[!] Pipeline completed with errors: ${PIPELINE_ERRORS[*]}" >&2
            echo "=== Partial results in: $SCRIPT_DIR_WIN/output/ ==="
        else
            echo "=== Pipeline Complete. Results in: $SCRIPT_DIR_WIN/output/ ==="
        fi

        # Next-step guidance (skill chain is not auto-invokable from shell)
        echo ""
        echo "=== Next step (manual) ==="
        echo "Generate sandbox hints: bash tools/malware-sandbox/sandbox.sh hint $SCRIPT_DIR_WIN/output"
        echo "Generate narrative report: invoke 'watchtowr-report' skill in Claude Code with these artifacts:"
        # Two conventions again: the container tools name their JSON after the
        # stem (BINARY_NAME); ioc_extractor / malware_classifier name theirs
        # after whatever they were given (REPORT_NAME).
        for _f in "${BINARY_NAME}_triage.json" "${BINARY_NAME}_floss.json" "${BINARY_NAME}_viz.json" \
                   "${BINARY_NAME}_yara.json" "${BINARY_NAME}_capa.json" \
                   "${REPORT_NAME}_iocs.json" "${REPORT_NAME}_classification.json"; do
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
  analyze [flags] <binary>        Full analysis (all 7 scripts)
  info [flags] <binary>           Architecture, sections, entry point
  decompile [flags] <binary>      Decompile all functions to C
  functions [flags] <binary>      List functions with addresses/sizes
  strings [flags] <binary>        Extract strings with xrefs
  imports [flags] <binary>        Import table (suspicious API flagged)
  exports [flags] <binary>        Export table
  xrefs [flags] <binary>          Cross-reference report

  [flags] for all Ghidra commands:
    --raw-x64                     Raw x64 shellcode/blob (no PE header)
    --raw-x86                     Raw x86 shellcode/blob (no PE header)
    --processor <lang_id>         Custom processor (e.g., ARM:LE:32:v8T)
  Example: ghidra.sh decompile --raw-x64 shellcode.bin

Post-Analysis (binary-touching tools run in-container; report tools host-side):
  pe-triage <binary>              PE Triage (PE parser + DiE CLI)
  pe-triage --in-container <path> PE Triage on a file already inside the container
  floss <binary>                  FLOSS obfuscated string extraction (stack/decoded strings)
  yara-scan <binary>              YARA scan (APT attribution)
  yara-scan --in-container <path> YARA scan on a file already inside the container
  capa <binary>                   CAPA (capabilities + ATT&CK)
  ioc-extract <name>              Extract IOCs from output files
  classify <name>                 Classify malware type
  maldev-detect <name>            Detect operator-tier maldev techniques
  maldev-detect scan-binary <p>   ↳ direct binary scan (no Ghidra needed)
  maldev-detect list              ↳ list catalog of 14 detectable techniques
                                  (PEB walking, API hashing, hollowing, Early Bird APC,
                                   kernel callback abuse, DKOM, multi-layer crypto,
                                   direct syscalls / Hell's Gate)
                                  Run 'maldev-detect --help' for full help.
  analyze-full <binary>           Full pipeline (all of the above, 7 steps)

  Global flag (any command that takes a host binary):
    --keep-input-copy             Keep the sample copy staged in input/.
                                  Default: the staged copy is deleted when the
                                  command ends. A file you placed in input/
                                  yourself is never deleted.

Office Document Analysis (in-container, oletools):
  office-analyze <file>           VBA macro + auto-exec + OLE stream analysis
                                  (.doc .xls .docx .xlsm .rtf .msg .ppt etc.)

Binary Visualization (in-container):
  viz <binary> [--no-plot]        Entropy profile + bigram heatmap + byte histogram
                                  Outputs: <name>_viz.json + <name>_viz.png

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
