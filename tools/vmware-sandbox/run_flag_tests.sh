#!/bin/bash
# Vidar Config Flag Isolation Test - Host Orchestrator
# =====================================================
# Runs babi.exe 5 times, each with one flag (positions 1-5) disabled.
# Compares Frida output to map each flag to its stealing module.
#
# Usage: bash Tools/vmware-sandbox/run_flag_tests.sh [start_run]
#   start_run: Resume from specific run number (1-5, default: 1)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SANDBOX="$SCRIPT_DIR/sandbox.sh"
INPUT_DIR="$SCRIPT_DIR/input"
OUTPUT_DIR="$SCRIPT_DIR/output/flag_tests_$(date +%Y%m%d_%H%M%S)"
START_RUN="${1:-1}"

# Load .env (CRLF safe, same as sandbox.sh)
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
if [ -f "$PROJECT_ROOT/.env" ]; then
    while IFS='=' read -r key value; do
        key="${key%$'\r'}"
        value="${value%$'\r'}"
        [[ -z "$key" || "$key" =~ ^# ]] && continue
        case "$key" in
            VM_*) declare "$key=$value" ;;
        esac
    done < "$PROJECT_ROOT/.env"
fi

GUEST_PROFILE="${VM_GUEST_PROFILE:-C:\\Users\\${VM_GUEST_USER}}"
GUEST_ANALYSIS_DIR="${GUEST_PROFILE}\\Desktop\\analysis"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { printf '%b %s\n' "${GREEN}[*]${NC}" "$1"; }
warn() { printf '%b %s\n' "${YELLOW}[!]${NC}" "$1"; }
err()  { printf '%b %s\n' "${RED}[-]${NC}" "$1"; }

mkdir -p "$OUTPUT_DIR"
log "Output directory: $OUTPUT_DIR"

run_test() {
    local run_num=$1
    local run_dir="$OUTPUT_DIR/run${run_num}"
    mkdir -p "$run_dir"

    printf '\n%b\n' "${CYAN}============================================================${NC}"
    log "FLAG TEST RUN $run_num / 5  (flag $run_num disabled)"
    printf '%b\n\n' "${CYAN}============================================================${NC}"

    # 1. Revert to clean snapshot
    log "[$run_num/5] Step 1: Revert to clean_with_tools..."
    bash "$SANDBOX" revert clean_with_tools
    sleep 10

    # 2. Copy common files
    log "[$run_num/5] Step 2: Copying files to guest..."
    bash "$SANDBOX" copy-to "$INPUT_DIR/fake_steam_profile.html" 2>/dev/null || warn "  Failed: fake_steam_profile.html"
    bash "$SANDBOX" copy-to "$INPUT_DIR/custom_responses.ini" 2>/dev/null || warn "  Failed: custom_responses.ini"
    bash "$SANDBOX" copy-to "$INPUT_DIR/dummy_dll_response.bin" 2>/dev/null || warn "  Failed: dummy_dll_response.bin"
    bash "$SANDBOX" copy-to "$INPUT_DIR/run_flag_test.ps1" 2>/dev/null || warn "  Failed: run_flag_test.ps1"
    bash "$SANDBOX" copy-to "$INPUT_DIR/frida-scripts/hook_run5_c2.js" \
        "${GUEST_ANALYSIS_DIR}\\hook_run5_c2.js" 2>/dev/null || warn "  Failed: hook_run5_c2.js"

    # Copy encrypted malware
    local enc_malware="$SCRIPT_DIR/../proxy-web/Quarantine/62.60.226.97_5553/20260301_144239/babi.exe.enc.gz"
    if [ -f "$enc_malware" ]; then
        bash "$SANDBOX" copy-to "$enc_malware" \
            "${GUEST_ANALYSIS_DIR}\\babi.exe.enc.gz" 2>/dev/null || warn "  Failed: babi.exe.enc.gz"
    else
        err "Encrypted malware not found: $enc_malware"
        return 1
    fi

    # Create wheels directory in guest
    bash "$SANDBOX" guest-cmd --timeout 10 "New-Item -Path '${GUEST_ANALYSIS_DIR}\\wheels' -ItemType Directory -Force" /dev/null 2>/dev/null || true

    # Copy Frida wheels
    log "  Copying Frida wheels..."
    local wheels_dir="$INPUT_DIR/frida_wheels"
    local wheel_files=(
        "frida-17.7.3-cp37-abi3-win_amd64.whl"
        "frida_tools-14.6.0-py3-none-any.whl"
        "colorama-0.4.6-py2.py3-none-any.whl"
        "prompt_toolkit-3.0.52-py3-none-any.whl"
        "pygments-2.19.2-py3-none-any.whl"
        "websockets-13.1-cp310-cp310-win_amd64.whl"
        "typing_extensions-4.15.0-py3-none-any.whl"
        "wcwidth-0.6.0-py3-none-any.whl"
    )
    for whl in "${wheel_files[@]}"; do
        if [ -f "$wheels_dir/$whl" ]; then
            bash "$SANDBOX" copy-to "$wheels_dir/$whl" \
                "${GUEST_ANALYSIS_DIR}\\wheels\\${whl}" 2>/dev/null || true
        fi
    done

    # Copy run-specific config response
    local config_file="$INPUT_DIR/vidar_config_flag${run_num}.txt"
    if [ ! -f "$config_file" ]; then
        err "Config file not found: $config_file"
        return 1
    fi
    bash "$SANDBOX" copy-to "$config_file" || { err "Failed to copy config"; return 1; }
    log "  Config deployed: vidar_config_flag${run_num}.txt"

    # Create run number file for guest script
    local run_num_file="$INPUT_DIR/_current_run_num.txt"
    echo "$run_num" > "$run_num_file"
    bash "$SANDBOX" copy-to "$run_num_file" \
        "${GUEST_ANALYSIS_DIR}\\current_run_num.txt" 2>/dev/null || warn "  Failed: run_num file"
    rm -f "$run_num_file"

    # 3. Run guest-side test script (300s timeout for 120s Frida + setup)
    log "[$run_num/5] Step 3: Running flag test (expect ~180s)..."
    bash "$SANDBOX" run-script "$INPUT_DIR/run_flag_test.ps1" 300 || {
        warn "  Script returned non-zero (may be normal)"
    }

    # 4. Collect results
    log "[$run_num/5] Step 4: Collecting results..."
    bash "$SANDBOX" copy-from "${GUEST_ANALYSIS_DIR}\\frida_flag_test${run_num}.log" \
        "$run_dir/frida_flag_test${run_num}.log" 2>/dev/null || warn "  Could not retrieve Frida log"

    bash "$SANDBOX" copy-from "${GUEST_ANALYSIS_DIR}\\flag_test_run${run_num}_progress.log" \
        "$run_dir/flag_test_run${run_num}_progress.log" 2>/dev/null || warn "  Could not retrieve progress log"

    # 5. Display results
    log "[$run_num/5] Results:"
    if [ -f "$run_dir/flag_test_run${run_num}_progress.log" ]; then
        grep -E "Behavior Summary|:.*[0-9]" "$run_dir/flag_test_run${run_num}_progress.log" 2>/dev/null | tail -20 || true
    fi

    local frida_size=0
    if [ -f "$run_dir/frida_flag_test${run_num}.log" ]; then
        frida_size=$(stat -c%s "$run_dir/frida_flag_test${run_num}.log" 2>/dev/null || stat -f%z "$run_dir/frida_flag_test${run_num}.log" 2>/dev/null || echo 0)
    fi
    log "  Frida log: ${frida_size} bytes"
    log "Run $run_num complete."
}

# Main loop
for run_num in $(seq "$START_RUN" 5); do
    run_test "$run_num"
done

# Summary
printf '\n%b\n' "${CYAN}============================================================${NC}"
log "ALL RUNS COMPLETE"
printf '%b\n\n' "${CYAN}============================================================${NC}"

log "Results directory: $OUTPUT_DIR"

# Generate comparison summary
log "Generating comparison summary..."
summary_file="$OUTPUT_DIR/comparison_summary.txt"

{
    echo "Vidar Config Flag Isolation Test - Summary"
    echo "==========================================="
    echo ""
    for run_num in $(seq 1 5); do
        echo "--- Run $run_num (flag $run_num disabled) ---"
        progress_log="$OUTPUT_DIR/run${run_num}/flag_test_run${run_num}_progress.log"
        if [ -f "$progress_log" ]; then
            grep -E ":\s+[0-9]" "$progress_log" 2>/dev/null || true
        else
            echo "  (no results)"
        fi
        echo ""
    done
} > "$summary_file"

log "Summary saved: $summary_file"
echo ""
cat "$summary_file"
