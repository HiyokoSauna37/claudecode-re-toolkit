#!/bin/bash
# VMware Sandbox - Dynamic Malware Analysis Helper
# Usage: bash Tools/vmware-sandbox/sandbox.sh <command> [args]

set -e
export MSYS_NO_PATHCONV=1

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -W 2>/dev/null || pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -W 2>/dev/null || pwd)"

# Load .env (safe: declare instead of eval)
if [ -f "$PROJECT_ROOT/.env" ]; then
    while IFS='=' read -r key value; do
        # Strip CRLF line endings (\r) that break all vmrun commands
        key="${key%$'\r'}"
        value="${value%$'\r'}"
        [[ -z "$key" || "$key" =~ ^# ]] && continue
        case "$key" in
            VM_*|VIRUSTOTAL_*|VMRUN_TIMEOUT) declare "$key=$value" ;;
        esac
    done < "$PROJECT_ROOT/.env"
fi

VMRUN="/c/Program Files (x86)/VMware/VMware Workstation/vmrun.exe"
VMRUN_WRAPPER="$SCRIPT_DIR/vmrun-wrapper/vmrun-wrapper.exe"
NET_ISOLATE="$SCRIPT_DIR/net_isolate.py"
VMX_PATH="${VM_VMX_PATH}"
GU="${VM_GUEST_USER}"
GP="${VM_GUEST_PASS}"
# Guest profile path (MS account shortens folder name)
GUEST_PROFILE="${VM_GUEST_PROFILE:-C:\\Users\\${GU}}"
GUEST_ANALYSIS_DIR="${GUEST_PROFILE}\\Desktop\\analysis"
GUEST_TOOLS_DIR="${GUEST_PROFILE}\\Desktop\\tools"
SNAPSHOT_CLEAN="clean_with_tools"

OUTPUT_DIR="$SCRIPT_DIR/output"
INPUT_DIR="$SCRIPT_DIR/input"
LOGS_DIR="$SCRIPT_DIR/logs"

# Default timeout for vmrun commands (seconds); overridable via .env VMRUN_TIMEOUT
VMRUN_TIMEOUT="${VMRUN_TIMEOUT:-30}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { printf '%b %s\n' "${GREEN}[*]${NC}" "$1"; }
warn() { printf '%b %s\n' "${YELLOW}[!]${NC}" "$1"; }
err() { printf '%b %s\n' "${RED}[-]${NC}" "$1"; }

# vmrun with timeout (uses wrapper if available, fallback to timeout command)
vmrun_t() {
    local timeout="${VMRUN_TIMEOUT}"
    if [ -f "$VMRUN_WRAPPER" ]; then
        "$VMRUN_WRAPPER" --timeout "$timeout" "$@"
    else
        timeout "$timeout" "$VMRUN" "$@"
    fi
}

vmrun_script() {
    # Run script in guest via runScriptInGuest (more reliable than runProgramInGuest)
    local timeout_sec="${1:-60}"
    shift
    local script_cmd="$*"
    timeout "$timeout_sec" "$VMRUN" -T ws -gu "$GU" -gp "$GP" \
        runScriptInGuest "$VMX_PATH" "" "$script_cmd"
}

vm_running() {
    "$VMRUN" list 2>/dev/null | grep -qi "$(basename "$VMX_PATH" .vmx)" && return 0 || return 1
}

cmd_start() {
    if vm_running; then
        log "VM is already running"
    else
        log "Starting VM..."
        "$VMRUN" -T ws start "$VMX_PATH" nogui
        log "VM started (nogui)"
    fi
    sleep 5
    local ip
    ip=$(vmrun_t -T ws -gu "$GU" -gp "$GP" getGuestIPAddress "$VMX_PATH" 2>/dev/null || echo "unknown")
    log "Guest IP: $ip"
}

cmd_stop() {
    if vm_running; then
        log "Stopping VM..."
        "$VMRUN" -T ws stop "$VMX_PATH" soft
        log "VM stopped"
    else
        warn "VM is not running"
    fi
}

cmd_force_stop() {
    log "Force-stopping VM by killing vmware-vmx.exe, vmware.exe, vmrun.exe..."
    local vmx_basename
    vmx_basename=$(basename "$VMX_PATH" .vmx)
    local vmx_dir
    vmx_dir=$(dirname "$(cygpath -w "$VMX_PATH" 2>/dev/null || echo "$VMX_PATH")")

    # Kill vmware-vmx.exe, vmware.exe (GUI), and zombie vmrun.exe processes
    powershell.exe -NoProfile -Command "
        foreach (\$procName in @('vmware-vmx', 'vmware', 'vmrun')) {
            Get-Process \$procName -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue
        }
    " 2>/dev/null || true
    sleep 2

    # Clean up .lck directories that block subsequent VM operations
    local vmx_unix_dir
    vmx_unix_dir=$(dirname "$(cygpath -u "$VMX_PATH" 2>/dev/null || echo "$VMX_PATH")")
    if [ -d "$vmx_unix_dir" ]; then
        local lck_count=0
        for lck in "$vmx_unix_dir"/*.lck; do
            [ -d "$lck" ] || continue
            rm -rf "$lck"
            lck_count=$((lck_count + 1))
        done
        [ "$lck_count" -gt 0 ] && log "Cleaned up $lck_count .lck directories"
    fi

    if vm_running; then
        err "VM still appears running. Try: taskkill /F /IM vmware-vmx.exe"
    else
        log "VM force-stopped"
    fi
}

cmd_status() {
    if vm_running; then
        log "VM is running"
        local ip
        ip=$(vmrun_t -T ws -gu "$GU" -gp "$GP" getGuestIPAddress "$VMX_PATH" 2>/dev/null || echo "unknown")
        log "Guest IP: $ip"
        log "Snapshot list:"
        "$VMRUN" -T ws listSnapshots "$VMX_PATH"
        # Show network status
        cmd_net_status
    else
        warn "VM is not running"
    fi
}

cmd_revert() {
    local snapshot="${1:-$SNAPSHOT_CLEAN}"
    log "Reverting to snapshot: $snapshot"
    "$VMRUN" -T ws revertToSnapshot "$VMX_PATH" "$snapshot"
    log "Reverted. Starting VM..."
    "$VMRUN" -T ws start "$VMX_PATH" nogui
    sleep 8
    local ip
    ip=$(vmrun_t -T ws -gu "$GU" -gp "$GP" getGuestIPAddress "$VMX_PATH" 2>/dev/null || echo "unknown")
    log "VM ready. Guest IP: $ip"
}

cmd_snapshot() {
    local name="${1:-snapshot_$(date +%Y%m%d_%H%M%S)}"
    log "Creating snapshot: $name"
    "$VMRUN" -T ws snapshot "$VMX_PATH" "$name"
    log "Snapshot created: $name"
}

cmd_copy_to() {
    local src="$1"
    local dst="$2"
    if [ -z "$src" ]; then
        err "Usage: sandbox.sh copy-to <local_file> [guest_path]"
        exit 1
    fi
    # Validate source file exists and is not 0 bytes
    if [ ! -f "$src" ]; then
        err "Source file not found: $src"
        exit 1
    fi
    local filesize
    filesize=$(stat -c%s "$src" 2>/dev/null || stat -f%z "$src" 2>/dev/null || echo 0)
    if [ "$filesize" -eq 0 ]; then
        err "Source file is 0 bytes (empty): $src"
        err "This may indicate a failed build or missing file in snapshot"
        exit 1
    fi
    if [ -z "$dst" ]; then
        dst="${GUEST_ANALYSIS_DIR}\\$(basename "$src")"
    fi
    vmrun_t -T ws -gu "$GU" -gp "$GP" createDirectoryInGuest "$VMX_PATH" "$GUEST_ANALYSIS_DIR" 2>/dev/null || true
    log "Copying $(basename "$src") ($filesize bytes) to guest..."
    vmrun_t -T ws -gu "$GU" -gp "$GP" copyFileFromHostToGuest "$VMX_PATH" "$(cygpath -w "$src" 2>/dev/null || echo "$src")" "$dst"
    log "Copied to $dst"
}

cmd_copy_from() {
    local src="$1"
    local dst="$2"
    if [ -z "$src" ]; then
        err "Usage: sandbox.sh copy-from <guest_path> [local_path]"
        exit 1
    fi
    if [ -z "$dst" ]; then
        dst="$OUTPUT_DIR/$(basename "$src")"
    fi
    log "Copying from guest..."
    vmrun_t -T ws -gu "$GU" -gp "$GP" copyFileFromGuestToHost "$VMX_PATH" "$src" "$(cygpath -w "$dst" 2>/dev/null || echo "$dst")"
    log "Copied to $dst"
}

cmd_exec() {
    if [ -z "$1" ]; then
        err "Usage: sandbox.sh exec <program> [args...]"
        exit 1
    fi
    local prog="$1"
    shift
    local args="$*"
    log "Executing: $prog $args"
    vmrun_t -T ws -gu "$GU" -gp "$GP" runProgramInGuest "$VMX_PATH" "$prog" $args
}

# Safe PowerShell execution (avoids cmd.exe hang issues)
cmd_ps() {
    if [ -z "$1" ]; then
        err "Usage: sandbox.sh ps <powershell_command>"
        exit 1
    fi
    local command="$*"
    log "PowerShell: $command"
    vmrun_t -T ws -gu "$GU" -gp "$GP" runProgramInGuest "$VMX_PATH" \
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" \
        -NoProfile -NonInteractive -Command "$command"
}

cmd_guest_cmd() {
    # Parse --timeout flag
    local cmd_timeout="$VMRUN_TIMEOUT"
    if [[ "$1" == "--timeout" ]]; then
        cmd_timeout="$2"
        shift 2
    fi
    if [ -z "$1" ]; then
        err "Usage: sandbox.sh guest-cmd [--timeout N] <powershell_command> [local_output_file]"
        err "  Runs PowerShell command in guest, captures output to host"
        err "Example: sandbox.sh guest-cmd --timeout 120 'Get-Process | Select Name,Id'"
        exit 1
    fi
    local command="$1"
    local local_out="$2"
    local guest_tmp="${GUEST_ANALYSIS_DIR}\\guest_cmd_out.txt"

    log "Guest-CMD (timeout=${cmd_timeout}s): $command"

    # 1. Run PowerShell command with Out-File in guest
    local saved_timeout="$VMRUN_TIMEOUT"
    VMRUN_TIMEOUT="$cmd_timeout"
    vmrun_t -T ws -gu "$GU" -gp "$GP" createDirectoryInGuest "$VMX_PATH" "$GUEST_ANALYSIS_DIR" 2>/dev/null || true
    vmrun_t -T ws -gu "$GU" -gp "$GP" runProgramInGuest "$VMX_PATH" \
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" \
        -NoProfile -NonInteractive -Command "$command | Out-File -Encoding UTF8 $guest_tmp"
    VMRUN_TIMEOUT="$saved_timeout"

    # 2. Copy result from guest to host
    local host_tmp="$OUTPUT_DIR/guest_cmd_out.txt"
    vmrun_t -T ws -gu "$GU" -gp "$GP" copyFileFromGuestToHost "$VMX_PATH" \
        "$guest_tmp" "$(cygpath -w "$host_tmp" 2>/dev/null || echo "$host_tmp")"

    # 3. Display or save
    if [ -n "$local_out" ]; then
        cp "$host_tmp" "$local_out"
        log "Output saved to: $local_out"
    else
        cat "$host_tmp" 2>/dev/null || true
    fi
}

cmd_processes() {
    vmrun_t -T ws -gu "$GU" -gp "$GP" listProcessesInGuest "$VMX_PATH"
}

cmd_screenshot() {
    local dst="${1:-$OUTPUT_DIR/screenshot_$(date +%Y%m%d_%H%M%S).png}"
    vmrun_t -T ws -gu "$GU" -gp "$GP" captureScreen "$VMX_PATH" "$(cygpath -w "$dst" 2>/dev/null || echo "$dst")"
    log "Screenshot saved: $dst"
}

cmd_ip() {
    vmrun_t -T ws -gu "$GU" -gp "$GP" getGuestIPAddress "$VMX_PATH"
}

# Network management commands
cmd_net_isolate() {
    log "Setting network to Host-Only (isolated)..."
    python "$NET_ISOLATE" isolate
}

cmd_net_nat() {
    warn "Setting network to NAT - guest will have internet access!"
    python "$NET_ISOLATE" nat
}

cmd_net_disconnect() {
    log "Disconnecting network completely..."
    python "$NET_ISOLATE" disconnect
}

cmd_net_status() {
    python "$NET_ISOLATE" status
}

# Anti-VM Hardening: .vmx settings
cmd_harden_vmx() {
    local vmx_file
    vmx_file=$(cygpath -w "$VMX_PATH" 2>/dev/null || echo "$VMX_PATH")
    local vmx_unix
    vmx_unix=$(cygpath -u "$VMX_PATH" 2>/dev/null || echo "$VMX_PATH")

    # VM must be stopped
    if vm_running; then
        log "Stopping VM for .vmx editing..."
        "$VMRUN" -T ws stop "$VMX_PATH" soft
        sleep 3
    fi

    log "Applying anti-VM hardening to .vmx..."

    # Settings to apply (key=value pairs)
    # NOTE: isolation.tools.* settings break VMware Tools communication - DO NOT use
    # NOTE: cpuid.1.ecx mask and monitor_control.disable_directexec cause VM boot failure
    local -a settings=(
        'hypervisor.cpuid.v0 = "FALSE"'
        'monitor_control.restrict_backdoor = "TRUE"'
        'SMBIOS.reflectHost = "TRUE"'
        'SMBIOS.noOEMStrings = "TRUE"'
        'board-product.value = "440BX Desktop Reference Platform"'
        'ethernet0.addressType = "static"'
        'ethernet0.Address = "D4:5D:64:A1:B2:C3"'
    )

    for setting in "${settings[@]}"; do
        local key="${setting%%=*}"
        key=$(echo "$key" | sed 's/ *$//')  # trim trailing spaces

        # Remove existing line with this key (case-insensitive)
        sed -i "/^${key} *=/Id" "$vmx_unix"

        # Append new setting
        echo "$setting" >> "$vmx_unix"
        log "  Set: $setting"
    done

    # Remove generated MAC (conflicts with static)
    sed -i '/^ethernet0\.generatedAddress/Id' "$vmx_unix"
    sed -i '/^ethernet0\.generatedAddressOffset/Id' "$vmx_unix"

    log "Anti-VM hardening applied to .vmx"
    log "Starting VM..."
    "$VMRUN" -T ws start "$VMX_PATH" nogui
    sleep 8
    local ip
    ip=$(vmrun_t -T ws -gu "$GU" -gp "$GP" getGuestIPAddress "$VMX_PATH" 2>/dev/null || echo "unknown")
    log "VM ready. Guest IP: $ip"
}

# Anti-VM Hardening: Guest-side (registry, services)
cmd_harden_guest() {
    if ! vm_running; then
        err "VM is not running. Start or harden-vmx first."
        exit 1
    fi

    log "Applying guest-side anti-VM hardening..."

    # PowerShell script for guest hardening
    local ps_script='
# --- VMware Registry Keys ---
$vmKeys = @(
    "HKLM:\SOFTWARE\VMware, Inc.",
    "HKLM:\SOFTWARE\VMware, Inc.\VMware Tools"
)
foreach ($k in $vmKeys) {
    if (Test-Path $k) {
        Remove-Item -Path $k -Recurse -Force -ErrorAction SilentlyContinue
        Write-Output "Removed: $k"
    }
}

# --- Disk Enum (VMware virtual disk string) ---
try {
    $diskEnum = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\disk\Enum" -ErrorAction Stop
    if ($diskEnum.PSObject.Properties["0"] -and $diskEnum."0" -match "VMware") {
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\disk\Enum" -Name "0" -Value "NVMe Samsung SSD 980 PRO 1TB"
        Write-Output "Spoofed disk enum"
    }
} catch { Write-Output "Disk enum: no change needed" }

# --- VMware service display names ---
$vmServices = @{
    "vmci"    = "System Interface Core"
    "vmhgfs"  = "Host Shared Folders"
    "vmmouse" = "PS/2 Pointer Device"
    "vmrawdsk"= "Raw Disk Helper"
    "vmusbmouse" = "USB Pointer Device"
    "VMTools" = "System Management Service"
    "VGAuthService" = "Guest Authentication Service"
    "vm3dservice" = "Display Adapter Service"
}
foreach ($svc in $vmServices.GetEnumerator()) {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Key)"
    if (Test-Path $regPath) {
        Set-ItemProperty $regPath -Name "DisplayName" -Value $svc.Value -ErrorAction SilentlyContinue
        Write-Output "Renamed service: $($svc.Key) -> $($svc.Value)"
    }
}

# --- System BIOS registry ---
try {
    Set-ItemProperty "HKLM:\HARDWARE\DESCRIPTION\System\BIOS" -Name "SystemManufacturer" -Value "Dell Inc." -ErrorAction SilentlyContinue
    Set-ItemProperty "HKLM:\HARDWARE\DESCRIPTION\System\BIOS" -Name "SystemProductName" -Value "OptiPlex 7090" -ErrorAction SilentlyContinue
    Write-Output "Spoofed BIOS registry"
} catch { Write-Output "BIOS registry: failed" }

Write-Output "Guest hardening complete"
'

    # Write script to guest and execute
    local guest_script="${GUEST_ANALYSIS_DIR}\\harden_guest.ps1"

    # Create temp file on host, copy to guest, execute
    local host_tmp="$OUTPUT_DIR/harden_guest.ps1"
    echo "$ps_script" > "$host_tmp"

    vmrun_t -T ws -gu "$GU" -gp "$GP" createDirectoryInGuest "$VMX_PATH" "$GUEST_ANALYSIS_DIR" 2>/dev/null || true
    vmrun_t -T ws -gu "$GU" -gp "$GP" copyFileFromHostToGuest "$VMX_PATH" \
        "$(cygpath -w "$host_tmp" 2>/dev/null || echo "$host_tmp")" "$guest_script"

    log "Running hardening script in guest..."
    vmrun_t -T ws -gu "$GU" -gp "$GP" runProgramInGuest "$VMX_PATH" \
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" \
        -NoProfile -NonInteractive -ExecutionPolicy Bypass \
        -File "$guest_script"

    # Capture output
    local guest_out="${GUEST_ANALYSIS_DIR}\\harden_result.txt"
    vmrun_t -T ws -gu "$GU" -gp "$GP" runProgramInGuest "$VMX_PATH" \
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" \
        -NoProfile -NonInteractive -ExecutionPolicy Bypass \
        -Command "powershell -ExecutionPolicy Bypass -File $guest_script 2>&1 | Out-File -Encoding UTF8 $guest_out"

    vmrun_t -T ws -gu "$GU" -gp "$GP" copyFileFromGuestToHost "$VMX_PATH" \
        "$guest_out" "$(cygpath -w "$OUTPUT_DIR/harden_result.txt" 2>/dev/null || echo "$OUTPUT_DIR/harden_result.txt")" 2>/dev/null || true

    log "Guest hardening result:"
    cat "$OUTPUT_DIR/harden_result.txt" 2>/dev/null || warn "Could not read result"

    rm -f "$host_tmp"
    log "Guest-side hardening complete"
}

cmd_guest_tools() {
    log "Checking guest tools..."
    local ps_cmd
    ps_cmd='$paths = @('
    ps_cmd+="\"${GUEST_TOOLS_DIR}\\pe-sieve64.exe\","
    ps_cmd+="\"${GUEST_TOOLS_DIR}\\hollows_hunter64.exe\","
    ps_cmd+="\"${GUEST_TOOLS_DIR}\\memdump-racer.exe\","
    ps_cmd+="\"${GUEST_TOOLS_DIR}\\x64dbg\\release\\x64\\x64dbg.exe\","
    ps_cmd+="\"${GUEST_TOOLS_DIR}\\procmon\\Procmon.exe\""
    ps_cmd+='); foreach ($p in $paths) { $e = Test-Path $p; Write-Output "$e : $p" }'

    vmrun_t -T ws -gu "$GU" -gp "$GP" runProgramInGuest "$VMX_PATH" \
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" \
        -NoProfile -NonInteractive -Command "$ps_cmd | Out-File -Encoding UTF8 ${GUEST_ANALYSIS_DIR}\\tools_check.txt"
    vmrun_t -T ws -gu "$GU" -gp "$GP" copyFileFromGuestToHost "$VMX_PATH" \
        "${GUEST_ANALYSIS_DIR}\\tools_check.txt" "$(cygpath -w "$OUTPUT_DIR/tools_check.txt" 2>/dev/null || echo "$OUTPUT_DIR/tools_check.txt")"
    log "Tools check result:"
    cat "$OUTPUT_DIR/tools_check.txt" 2>/dev/null || true
}

cmd_memdump() {
    local guest_target="$1"
    local delays="${2:-0,100,200,300,500}"
    local guest_outdir="${3:-${GUEST_ANALYSIS_DIR}\\memdump_output}"

    if [ -z "$guest_target" ]; then
        err "Usage: sandbox.sh memdump <guest_target_path> [delays_csv] [guest_outdir]"
        err "Example: sandbox.sh memdump 'C:\\Users\\malwa\\Desktop\\analysis\\install.exe'"
        exit 1
    fi

    local racer_guest="${GUEST_TOOLS_DIR}\\memdump-racer.exe"
    local racer_local="$SCRIPT_DIR/memdump-racer/memdump-racer.exe"

    # Copy memdump-racer.exe to guest if not present
    log "Ensuring memdump-racer.exe is on guest..."
    vmrun_t -T ws -gu "$GU" -gp "$GP" copyFileFromHostToGuest "$VMX_PATH" \
        "$(cygpath -w "$racer_local" 2>/dev/null || echo "$racer_local")" "$racer_guest" 2>/dev/null || true

    # Create output directory on guest
    vmrun_t -T ws -gu "$GU" -gp "$GP" createDirectoryInGuest "$VMX_PATH" "$guest_outdir" 2>/dev/null || true

    # Run memdump-racer on guest
    log "Running memdump-racer: target=$guest_target delays=$delays"
    vmrun_t -T ws -gu "$GU" -gp "$GP" runProgramInGuest "$VMX_PATH" \
        "$racer_guest" \
        --target "$guest_target" \
        --outdir "$guest_outdir" \
        --delays "$delays"

    # Copy log back
    local local_outdir="$OUTPUT_DIR/memdump_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$local_outdir"
    vmrun_t -T ws -gu "$GU" -gp "$GP" copyFileFromGuestToHost "$VMX_PATH" \
        "${guest_outdir}\\log.txt" "$(cygpath -w "$local_outdir/log.txt" 2>/dev/null || echo "$local_outdir/log.txt")" 2>/dev/null || true

    log "memdump-racer complete. Guest output: $guest_outdir"
    log "Log copied to: $local_outdir/log.txt"
}

cmd_analyze() {
    local binary="$1"
    local wait_time="${2:-60}"
    if [ -z "$binary" ]; then
        err "Usage: sandbox.sh analyze <binary_path|encrypted.enc.gz> [wait_seconds=60]"
        exit 1
    fi

    local bname=$(basename "$binary")
    local is_encrypted=false

    # Detect .enc.gz quarantine files
    if [[ "$bname" == *.enc.gz ]]; then
        is_encrypted=true
        log "Detected .enc.gz quarantine file. Will decrypt inside VM."
    fi

    # For encrypted files, use the decrypted name for result dir
    local exe_name="$bname"
    if $is_encrypted; then
        exe_name="${bname%.enc.gz}"
    fi

    local timestamp=$(date +%Y%m%d_%H%M%S)
    local result_dir="$OUTPUT_DIR/${exe_name}_${timestamp}"
    mkdir -p "$result_dir"

    log "=== Dynamic Analysis: $exe_name ==="

    # Step 1: Revert to snapshot (VM stops after revert)
    log "Step 1: Reverting to clean_with_tools snapshot..."
    "$VMRUN" -T ws revertToSnapshot "$VMX_PATH" "$SNAPSHOT_CLEAN"
    log "Reverted."

    # Step 2: Network isolation BEFORE starting VM (safest approach)
    log "Step 2: Setting network to Host-Only (VMX edit, VM is stopped)..."
    python "$NET_ISOLATE" isolate --no-restart

    # Step 3: Start VM with Host-Only already applied
    log "Step 3: Starting VM..."
    "$VMRUN" -T ws start "$VMX_PATH" nogui
    sleep 10
    local ip
    ip=$(vmrun_t -T ws -gu "$GU" -gp "$GP" getGuestIPAddress "$VMX_PATH" 2>/dev/null || echo "unknown")
    log "VM ready. Guest IP: $ip"

    # Step 4: Create analysis directory
    log "Step 4: Preparing guest..."
    vmrun_t -T ws -gu "$GU" -gp "$GP" createDirectoryInGuest "$VMX_PATH" "$GUEST_ANALYSIS_DIR" 2>/dev/null || true

    # Step 5: Copy malware to guest (with .enc.gz auto-decrypt)
    log "Step 5: Copying malware to guest..."
    local guest_binary="${GUEST_ANALYSIS_DIR}\\${exe_name}"
    local win_binary
    win_binary=$(cygpath -w "$binary" 2>/dev/null || echo "$binary")
    vmrun_t -T ws -gu "$GU" -gp "$GP" copyFileFromHostToGuest "$VMX_PATH" "$win_binary" "${GUEST_ANALYSIS_DIR}\\${bname}"

    if $is_encrypted; then
        log "Step 5.5: Decrypting .enc.gz inside VM..."
        # Copy decrypt script to VM
        local decrypt_ps1="$INPUT_DIR/vm_quarantine_decrypt.ps1"
        if [ ! -f "$decrypt_ps1" ]; then
            err "Decrypt script not found: $decrypt_ps1"
            err "Run: sandbox.sh setup-decrypt to create it"
            exit 1
        fi
        local win_decrypt
        win_decrypt=$(cygpath -w "$decrypt_ps1" 2>/dev/null || echo "$decrypt_ps1")
        vmrun_t -T ws -gu "$GU" -gp "$GP" copyFileFromHostToGuest "$VMX_PATH" "$win_decrypt" "${GUEST_ANALYSIS_DIR}\\vm_quarantine_decrypt.ps1"

        # Get quarantine password from .env
        local q_password=""
        if [ -f "$SCRIPT_DIR/../../.env" ]; then
            q_password=$(grep -E '^QUARANTINE_PASSWORD=' "$SCRIPT_DIR/../../.env" | cut -d= -f2- | tr -d '"' | tr -d "'" | tr -d $'\r')
        fi
        if [ -z "$q_password" ]; then
            err "QUARANTINE_PASSWORD not found in .env"
            exit 1
        fi

        # Execute decrypt inside VM via run-script approach
        local tmp_decrypt_runner
        tmp_decrypt_runner=$(mktemp --suffix=.ps1)
        cat > "$tmp_decrypt_runner" <<EOPS
\$ErrorActionPreference = "Stop"
try {
    & "${GUEST_ANALYSIS_DIR}\\vm_quarantine_decrypt.ps1" -InputFile "${GUEST_ANALYSIS_DIR}\\${bname}" -OutputFile "${GUEST_ANALYSIS_DIR}\\${exe_name}" -Password "${q_password}"
    "OK" | Out-File -Encoding UTF8 "${GUEST_ANALYSIS_DIR}\\decrypt_status.txt"
} catch {
    "FAIL: \$(\$_.Exception.Message)" | Out-File -Encoding UTF8 "${GUEST_ANALYSIS_DIR}\\decrypt_status.txt"
}
EOPS
        # Copy and run the decrypt runner
        local win_runner
        win_runner=$(cygpath -w "$tmp_decrypt_runner" 2>/dev/null || echo "$tmp_decrypt_runner")
        vmrun_t -T ws -gu "$GU" -gp "$GP" copyFileFromHostToGuest "$VMX_PATH" "$win_runner" "${GUEST_ANALYSIS_DIR}\\run_decrypt_tmp.ps1"
        vmrun_t -T ws -gu "$GU" -gp "$GP" runProgramInGuest "$VMX_PATH" \
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" \
            -ExecutionPolicy Bypass -NonInteractive -File "${GUEST_ANALYSIS_DIR}\\run_decrypt_tmp.ps1" 2>/dev/null || true
        rm -f "$tmp_decrypt_runner"

        # Verify decryption
        local status_file="$result_dir/decrypt_status.txt"
        vmrun_t -T ws -gu "$GU" -gp "$GP" copyFileFromGuestToHost "$VMX_PATH" \
            "${GUEST_ANALYSIS_DIR}\\decrypt_status.txt" "$(cygpath -w "$status_file" 2>/dev/null || echo "$status_file")" 2>/dev/null || true
        if [ -f "$status_file" ]; then
            local status_content
            status_content=$(cat "$status_file" | tr -d '\r')
            if [[ "$status_content" == *"FAIL"* ]]; then
                err "Decryption failed inside VM: $status_content"
                exit 1
            fi
            log "Decryption successful inside VM"
        else
            warn "Could not verify decryption status (status file not retrieved)"
        fi
    fi

    # Step 6: Pre-execution screenshot + process list
    log "Step 6: Pre-execution snapshot..."
    cmd_screenshot "$result_dir/pre_execution.png"
    vmrun_t -T ws -gu "$GU" -gp "$GP" listProcessesInGuest "$VMX_PATH" > "$result_dir/processes_before.txt"

    # Step 7: Execute malware
    log "Step 7: Executing malware (wait: ${wait_time}s)..."
    vmrun_t -T ws -gu "$GU" -gp "$GP" runProgramInGuest "$VMX_PATH" "$guest_binary" -nowait 2>/dev/null || true

    # Step 8: Wait
    log "Step 8: Waiting ${wait_time} seconds for malware activity..."
    sleep "$wait_time"

    # Step 9: Post-execution screenshot + process list
    log "Step 9: Post-execution snapshot..."
    cmd_screenshot "$result_dir/post_execution.png"
    vmrun_t -T ws -gu "$GU" -gp "$GP" listProcessesInGuest "$VMX_PATH" > "$result_dir/processes_after.txt"

    # Step 10: Run HollowsHunter
    log "Step 10: Running HollowsHunter64..."
    vmrun_t -T ws -gu "$GU" -gp "$GP" runProgramInGuest "$VMX_PATH" \
        "${GUEST_TOOLS_DIR}\\hollows_hunter64.exe" /dir "$GUEST_ANALYSIS_DIR\\hh_output" 2>/dev/null || true

    # Step 11: Diff processes
    log "Step 11: Comparing processes..."
    diff "$result_dir/processes_before.txt" "$result_dir/processes_after.txt" > "$result_dir/processes_diff.txt" 2>&1 || true

    log "=== Analysis complete ==="
    log "Results: $result_dir"

    # Step 12: Revert to clean_with_tools (restore NAT for normal use)
    log "Step 12: Reverting to clean_with_tools snapshot..."
    "$VMRUN" -T ws revertToSnapshot "$VMX_PATH" "$SNAPSHOT_CLEAN"
    python "$NET_ISOLATE" nat --no-restart
    "$VMRUN" -T ws start "$VMX_PATH" nogui
    log "VM reverted and NAT restored."
}

# ============================================================
# 3-Level Unpacking System
# ============================================================

cmd_unpack() {
    local binary="$1"
    local level="${2:-auto}"

    if [ -z "$binary" ]; then
        err "Usage: sandbox.sh unpack <binary> [level]"
        err "  level: 1 (memdump-racer), 2 (TinyTracer), 3 (manual x64dbg), auto (default)"
        err "Example: sandbox.sh unpack /path/to/packed.exe auto"
        exit 1
    fi

    local bname
    bname=$(basename "$binary")
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local result_dir="$OUTPUT_DIR/unpack_${bname}_${timestamp}"
    mkdir -p "$result_dir"

    log "=== 3-Level Unpacking: $bname (level=$level) ==="

    case "$level" in
        1)       unpack_level1 "$binary" "$result_dir" ;;
        2)       unpack_level2 "$binary" "$result_dir" ;;
        3)       unpack_level3_instructions "$binary" ;;
        auto)    unpack_auto "$binary" "$result_dir" ;;
        *)       err "Unknown level: $level (use 1, 2, 3, or auto)"; exit 1 ;;
    esac
}

unpack_level1() {
    local binary="$1"
    local result_dir="$2"
    local bname
    bname=$(basename "$binary")
    local guest_target="${GUEST_ANALYSIS_DIR}\\${bname}"
    local guest_outdir="${GUEST_ANALYSIS_DIR}\\memdump_output"

    log "--- Level 1: memdump-racer ---"

    local racer_guest="${GUEST_TOOLS_DIR}\\memdump-racer.exe"
    local racer_local="$SCRIPT_DIR/memdump-racer/memdump-racer.exe"

    # Copy memdump-racer.exe to guest
    log "Copying memdump-racer.exe to guest..."
    vmrun_t -T ws -gu "$GU" -gp "$GP" copyFileFromHostToGuest "$VMX_PATH" \
        "$(cygpath -w "$racer_local" 2>/dev/null || echo "$racer_local")" "$racer_guest" 2>/dev/null || true

    # Copy target to guest
    log "Copying target to guest..."
    vmrun_t -T ws -gu "$GU" -gp "$GP" createDirectoryInGuest "$VMX_PATH" "$GUEST_ANALYSIS_DIR" 2>/dev/null || true
    vmrun_t -T ws -gu "$GU" -gp "$GP" copyFileFromHostToGuest "$VMX_PATH" \
        "$(cygpath -w "$binary" 2>/dev/null || echo "$binary")" "$guest_target"

    # Create output directory on guest
    vmrun_t -T ws -gu "$GU" -gp "$GP" createDirectoryInGuest "$VMX_PATH" "$guest_outdir" 2>/dev/null || true

    # Run memdump-racer (timeout 120s)
    log "Running memdump-racer (timeout: 120s)..."
    local saved_timeout="$VMRUN_TIMEOUT"
    VMRUN_TIMEOUT=120
    vmrun_t -T ws -gu "$GU" -gp "$GP" runProgramInGuest "$VMX_PATH" \
        "$racer_guest" \
        --target "$guest_target" \
        --outdir "$guest_outdir" \
        --delays "0,100,200,300,500" || true
    VMRUN_TIMEOUT="$saved_timeout"

    # Collect results
    collect_unpack_results "$guest_outdir" "$result_dir" "level1"

    # Check quality
    check_unpack_quality "$result_dir/level1"
}

unpack_level2() {
    local binary="$1"
    local result_dir="$2"
    local bname
    bname=$(basename "$binary")
    local guest_target="${GUEST_ANALYSIS_DIR}\\${bname}"
    local guest_outdir="${GUEST_ANALYSIS_DIR}\\tiny_unpack_output"

    log "--- Level 2: TinyTracer (tiny-unpack) ---"

    local tunpack_guest="${GUEST_TOOLS_DIR}\\tiny-unpack.exe"
    local tunpack_local="$SCRIPT_DIR/tiny-unpack/tiny-unpack.exe"

    # Check if tiny-unpack.exe exists locally
    if [ ! -f "$tunpack_local" ]; then
        err "tiny-unpack.exe not found at $tunpack_local"
        err "Build it first: cd Tools/vmware-sandbox/tiny-unpack && GOOS=windows GOARCH=amd64 go build -o tiny-unpack.exe ."
        return 1
    fi

    # Copy tiny-unpack.exe to guest
    log "Copying tiny-unpack.exe to guest..."
    vmrun_t -T ws -gu "$GU" -gp "$GP" copyFileFromHostToGuest "$VMX_PATH" \
        "$(cygpath -w "$tunpack_local" 2>/dev/null || echo "$tunpack_local")" "$tunpack_guest" 2>/dev/null || true

    # Copy target to guest (if not already there from Level 1)
    log "Copying target to guest..."
    vmrun_t -T ws -gu "$GU" -gp "$GP" createDirectoryInGuest "$VMX_PATH" "$GUEST_ANALYSIS_DIR" 2>/dev/null || true
    vmrun_t -T ws -gu "$GU" -gp "$GP" copyFileFromHostToGuest "$VMX_PATH" \
        "$(cygpath -w "$binary" 2>/dev/null || echo "$binary")" "$guest_target" 2>/dev/null || true

    # Create output directory on guest
    vmrun_t -T ws -gu "$GU" -gp "$GP" createDirectoryInGuest "$VMX_PATH" "$guest_outdir" 2>/dev/null || true

    # Run tiny-unpack (timeout 300s)
    log "Running tiny-unpack (timeout: 300s)..."
    local saved_timeout="$VMRUN_TIMEOUT"
    VMRUN_TIMEOUT=300
    vmrun_t -T ws -gu "$GU" -gp "$GP" runProgramInGuest "$VMX_PATH" \
        "$tunpack_guest" \
        --target "$guest_target" \
        --outdir "$guest_outdir" || true
    VMRUN_TIMEOUT="$saved_timeout"

    # Collect results
    collect_unpack_results "$guest_outdir" "$result_dir" "level2"

    # Check quality
    check_unpack_quality "$result_dir/level2"
}

unpack_auto() {
    local binary="$1"
    local result_dir="$2"

    log "=== Auto-escalation: L1 -> L2 -> L3 ==="

    # Level 1
    unpack_level1 "$binary" "$result_dir"
    if check_unpack_quality "$result_dir/level1"; then
        log "Level 1 produced GOOD results. Running Ghidra on best dump..."
        run_ghidra_on_best "$result_dir/level1"
        return 0
    fi
    warn "Level 1 quality: POOR. Escalating to Level 2..."

    # Level 2
    unpack_level2 "$binary" "$result_dir"
    if check_unpack_quality "$result_dir/level2"; then
        log "Level 2 produced GOOD results. Running Ghidra on best dump..."
        run_ghidra_on_best "$result_dir/level2"
        return 0
    fi
    warn "Level 2 quality: POOR. Escalating to Level 3 (manual)..."

    # Level 3
    unpack_level3_instructions "$binary"
}

check_unpack_quality() {
    local level_dir="$1"
    local quality_file="$level_dir/quality.txt"

    if [ -f "$quality_file" ]; then
        local quality
        quality=$(cat "$quality_file" 2>/dev/null | tr -d '[:space:]')
        if [ "$quality" = "GOOD" ]; then
            log "Quality check: GOOD"
            return 0
        fi
    fi

    # Fallback: check if any dump file is > 50KB
    local has_large_dump=false
    if [ -d "$level_dir" ]; then
        while IFS= read -r -d '' f; do
            local size
            size=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo 0)
            if [ "$size" -gt 51200 ]; then
                has_large_dump=true
                break
            fi
        done < <(find "$level_dir" -type f \( -name "*.exe" -o -name "*.dll" \) -print0 2>/dev/null)
    fi

    if [ "$has_large_dump" = true ]; then
        log "Quality check: FAIR (large dump found but quality.txt not GOOD)"
        return 1
    fi

    warn "Quality check: POOR"
    return 1
}

collect_unpack_results() {
    local guest_outdir="$1"
    local local_result_dir="$2"
    local level_name="$3"
    local level_dir="$local_result_dir/$level_name"
    mkdir -p "$level_dir"

    log "Collecting results from guest: $guest_outdir -> $level_dir"

    # Copy quality.txt
    vmrun_t -T ws -gu "$GU" -gp "$GP" copyFileFromGuestToHost "$VMX_PATH" \
        "${guest_outdir}\\quality.txt" \
        "$(cygpath -w "$level_dir/quality.txt" 2>/dev/null || echo "$level_dir/quality.txt")" 2>/dev/null || true

    # Copy manifest.txt
    vmrun_t -T ws -gu "$GU" -gp "$GP" copyFileFromGuestToHost "$VMX_PATH" \
        "${guest_outdir}\\manifest.txt" \
        "$(cygpath -w "$level_dir/manifest.txt" 2>/dev/null || echo "$level_dir/manifest.txt")" 2>/dev/null || true

    # Copy log.txt
    vmrun_t -T ws -gu "$GU" -gp "$GP" copyFileFromGuestToHost "$VMX_PATH" \
        "${guest_outdir}\\log.txt" \
        "$(cygpath -w "$level_dir/log.txt" 2>/dev/null || echo "$level_dir/log.txt")" 2>/dev/null || true

    # Copy dumped files listed in manifest.txt
    if [ -f "$level_dir/manifest.txt" ]; then
        local count=0
        while IFS= read -r guest_file; do
            guest_file=$(echo "$guest_file" | tr -d '\r' | xargs)
            [ -z "$guest_file" ] && continue
            local fname
            fname=$(basename "$guest_file")
            vmrun_t -T ws -gu "$GU" -gp "$GP" copyFileFromGuestToHost "$VMX_PATH" \
                "$guest_file" \
                "$(cygpath -w "$level_dir/$fname" 2>/dev/null || echo "$level_dir/$fname")" 2>/dev/null || {
                warn "Failed to copy: $guest_file"
                continue
            }
            count=$((count + 1))
        done < "$level_dir/manifest.txt"
        log "Collected $count dump files"
    else
        warn "No manifest.txt found, cannot collect individual dump files"
    fi

    log "Results saved to: $level_dir"
}

run_ghidra_on_best() {
    local level_dir="$1"

    # Find the largest PE file as the best unpack candidate
    local best_file=""
    local best_size=0

    if [ -d "$level_dir" ]; then
        for f in "$level_dir"/*.exe "$level_dir"/*.dll; do
            [ -f "$f" ] || continue
            local size
            size=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo 0)
            if [ "$size" -gt "$best_size" ]; then
                best_size=$size
                best_file=$f
            fi
        done
    fi

    if [ -z "$best_file" ]; then
        warn "No PE files found for Ghidra analysis"
        return 1
    fi

    log "Best unpack candidate: $(basename "$best_file") ($best_size bytes)"
    log "Running Ghidra headless analysis..."

    local ghidra_script="$PROJECT_ROOT/Tools/ghidra-headless/ghidra.sh"
    if [ -f "$ghidra_script" ]; then
        bash "$ghidra_script" analyze "$best_file" || {
            warn "Ghidra analysis failed (non-fatal)"
            return 1
        }
    else
        warn "Ghidra script not found at $ghidra_script"
        log "Manually run: bash Tools/ghidra-headless/ghidra.sh analyze $best_file"
        return 1
    fi
}

unpack_level3_instructions() {
    local binary="$1"
    local bname
    bname=$(basename "$binary")

    echo ""
    echo "============================================================"
    echo " Level 3: Manual Unpacking with x64dbg"
    echo "============================================================"
    echo ""
    echo "Automatic unpacking failed. Follow these manual steps:"
    echo ""
    echo "1. Load the binary in x64dbg:"
    echo "   sandbox.sh exec \"${GUEST_TOOLS_DIR}\\x64dbg\\release\\x64\\x64dbg.exe\" \"${GUEST_ANALYSIS_DIR}\\${bname}\""
    echo ""
    echo "2. Set breakpoints at common OEP patterns:"
    echo "   - VirtualAlloc / VirtualProtect return"
    echo "   - Section permission changes (PAGE_EXECUTE_READWRITE)"
    echo "   - Long jumps to .text section"
    echo ""
    echo "3. Run until OEP is reached (look for standard prologue: push ebp/mov ebp,esp)"
    echo ""
    echo "4. Dump with Scylla plugin (x64dbg built-in):"
    echo "   - Plugins -> Scylla -> IAT Autosearch -> Get Imports -> Dump"
    echo ""
    echo "5. Copy dump from guest:"
    echo "   sandbox.sh copy-from \"${GUEST_ANALYSIS_DIR}\\${bname}_dump.exe\""
    echo ""
    echo "6. Analyze with Ghidra:"
    echo "   bash Tools/ghidra-headless/ghidra.sh analyze output/${bname}_dump.exe"
    echo ""
    echo "Tips:"
    echo "  - VMProtect: Break on VirtualProtect, trace section transitions"
    echo "  - Themida: Break on VirtualAlloc, look for large allocation then jump"
    echo "  - UPX: Just use 'upx -d' (no manual unpacking needed)"
    echo "============================================================"
}

# ==================== Devirtualization (Mergen) ====================

cmd_devirt() {
    local binary="$1"
    local address="$2"

    if [ -z "$binary" ]; then
        err "Usage: sandbox.sh devirt <binary> [address]"
        err "  With address:    devirtualize single VMP function"
        err "  Without address: auto-detect VMP functions & batch devirt"
        err ""
        err "Pipeline: dump-triage (VMP addr scan) -> Mergen (LLVM IR lift)"
        err "Prerequisite: unpack the binary first if packed"
        exit 1
    fi

    if [ ! -f "$binary" ]; then
        err "File not found: $binary"
        exit 1
    fi

    local mergen_script="$PROJECT_ROOT/Tools/mergen/mergen.sh"
    local dump_triage="$PROJECT_ROOT/Tools/dump-triage/dump-triage.exe"

    if [ ! -f "$mergen_script" ]; then
        err "Mergen not found. Expected: $mergen_script"
        exit 1
    fi

    local bname
    bname=$(basename "$binary")
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)

    if [ -n "$address" ]; then
        # Single function devirtualization
        log "Devirtualizing: $bname @ $address"
        bash "$mergen_script" devirt "$binary" "$address"
    else
        # Auto-detect VMP function addresses and batch devirt
        log "=== Auto Devirtualization: $bname ==="

        # Step 1: Detect VMP function addresses
        if [ ! -f "$dump_triage" ]; then
            err "dump-triage.exe not found. Build it: cd Tools/dump-triage && go build -o dump-triage.exe ."
            exit 1
        fi

        local addr_file="$OUTPUT_DIR/vmp_addrs_${bname}_${timestamp}.txt"
        log "Step 1: Scanning for VMP function addresses..."
        "$dump_triage" --vmp-addrs "$binary" > "$addr_file" 2>&1

        # Count non-comment, non-empty lines
        local addr_count
        addr_count=$(grep -c '^0x' "$addr_file" 2>/dev/null || echo 0)

        if [ "$addr_count" -eq 0 ]; then
            warn "No VMP function addresses detected"
            cat "$addr_file"
            return 1
        fi

        log "Found $addr_count VMP function candidates"
        cat "$addr_file"

        # Step 2: Batch devirtualize
        log "Step 2: Batch devirtualization via Mergen..."
        bash "$mergen_script" devirt-batch "$binary" "$addr_file"

        log "=== Devirtualization complete ==="
        log "Address list: $addr_file"
        log "LLVM IR output: Tools/mergen/output/"
    fi
}

# ==================== Run Script (copy + execute + collect log) ====================

cmd_run_script() {
    local script="$1"
    local script_timeout="${2:-60}"

    if [ -z "$script" ]; then
        err "Usage: sandbox.sh run-script <local_script.ps1> [timeout=60]"
        err "  Copies .ps1 to guest, executes it, and retrieves output log"
        exit 1
    fi
    if [ ! -f "$script" ]; then
        err "Script not found: $script"
        exit 1
    fi
    local filesize
    filesize=$(stat -c%s "$script" 2>/dev/null || stat -f%z "$script" 2>/dev/null || echo 0)
    if [ "$filesize" -eq 0 ]; then
        err "Script is 0 bytes: $script"
        exit 1
    fi

    local sname
    sname=$(basename "$script")
    local guest_script="${GUEST_ANALYSIS_DIR}\\${sname}"
    local guest_log="${GUEST_ANALYSIS_DIR}\\${sname%.ps1}_output.txt"
    local host_log="$OUTPUT_DIR/${sname%.ps1}_output.txt"

    # 1. Copy script to guest
    vmrun_t -T ws -gu "$GU" -gp "$GP" createDirectoryInGuest "$VMX_PATH" "$GUEST_ANALYSIS_DIR" 2>/dev/null || true
    log "Copying $sname to guest..."
    vmrun_t -T ws -gu "$GU" -gp "$GP" copyFileFromHostToGuest "$VMX_PATH" \
        "$(cygpath -w "$script" 2>/dev/null || echo "$script")" "$guest_script"

    # 2. Execute with timeout
    log "Executing $sname (timeout=${script_timeout}s)..."
    local saved_timeout="$VMRUN_TIMEOUT"
    VMRUN_TIMEOUT="$script_timeout"
    vmrun_t -T ws -gu "$GU" -gp "$GP" runProgramInGuest "$VMX_PATH" \
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" \
        -NoProfile -NonInteractive -ExecutionPolicy Bypass \
        -Command "& '$guest_script' 2>&1 | Out-File -Encoding UTF8 '$guest_log'" || true
    VMRUN_TIMEOUT="$saved_timeout"

    # 3. Retrieve output log
    vmrun_t -T ws -gu "$GU" -gp "$GP" copyFileFromGuestToHost "$VMX_PATH" \
        "$guest_log" "$(cygpath -w "$host_log" 2>/dev/null || echo "$host_log")" 2>/dev/null || true

    if [ -f "$host_log" ]; then
        log "=== Script Output ==="
        cat "$host_log"
        log "Output saved to: $host_log"
    else
        warn "Could not retrieve script output"
    fi
}

# ==================== Set Clock (VMware Tools sync disable + SetSystemTime) ====================

cmd_set_clock() {
    local datetime="$*"
    if [ -z "$datetime" ]; then
        err "Usage: sandbox.sh set-clock <YYYY-MM-DD HH:MM:SS>"
        err "  Disables VMware Tools time sync and sets guest clock"
        err "Example: sandbox.sh set-clock 2025-10-01 12:00:00"
        exit 1
    fi

    # 1. Disable VMware Tools time sync in .vmx (VM must be stopped or settings applied on next boot)
    local vmx_unix
    vmx_unix=$(cygpath -u "$VMX_PATH" 2>/dev/null || echo "$VMX_PATH")
    local sync_settings=(
        'tools.syncTime = "FALSE"'
        'time.synchronize.continue = "FALSE"'
        'time.synchronize.restore = "FALSE"'
        'time.synchronize.resume.disk = "FALSE"'
        'time.synchronize.shrink = "FALSE"'
    )
    for setting in "${sync_settings[@]}"; do
        local skey="${setting%%=*}"
        skey=$(echo "$skey" | sed 's/ *$//')
        sed -i "/^${skey} *=/Id" "$vmx_unix" 2>/dev/null || true
        echo "$setting" >> "$vmx_unix"
    done
    log "VMware Tools time sync disabled in .vmx"

    # 2. Create and copy the safe_set_clock.ps1 script
    local clock_script="$INPUT_DIR/safe_set_clock.ps1"
    if [ ! -f "$clock_script" ]; then
        log "Creating safe_set_clock.ps1..."
        cat > "$clock_script" << 'CLOCKEOF'
# safe_set_clock.ps1 - Set system time using P/Invoke SetSystemTime (no UAC popup)
param([string]$DateTime)
if (-not $DateTime) { Write-Error "Usage: safe_set_clock.ps1 -DateTime '2025-10-01 12:00:00'"; exit 1 }

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class WinTime {
    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEMTIME {
        public ushort wYear, wMonth, wDayOfWeek, wDay, wHour, wMinute, wSecond, wMilliseconds;
    }
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetSystemTime(ref SYSTEMTIME st);
}
"@

$dt = [DateTime]::Parse($DateTime).ToUniversalTime()
$st = New-Object WinTime+SYSTEMTIME
$st.wYear = $dt.Year; $st.wMonth = $dt.Month; $st.wDay = $dt.Day
$st.wHour = $dt.Hour; $st.wMinute = $dt.Minute; $st.wSecond = $dt.Second
$st.wMilliseconds = 0; $st.wDayOfWeek = [int]$dt.DayOfWeek

if ([WinTime]::SetSystemTime([ref]$st)) {
    Write-Output "OK: System time set to $($dt.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
} else {
    Write-Error "FAILED: SetSystemTime returned false (may need SeSystemtimePrivilege)"
    exit 1
}
CLOCKEOF
    fi

    # 3. Copy and execute on guest
    local guest_script="${GUEST_ANALYSIS_DIR}\\safe_set_clock.ps1"
    vmrun_t -T ws -gu "$GU" -gp "$GP" createDirectoryInGuest "$VMX_PATH" "$GUEST_ANALYSIS_DIR" 2>/dev/null || true
    vmrun_t -T ws -gu "$GU" -gp "$GP" copyFileFromHostToGuest "$VMX_PATH" \
        "$(cygpath -w "$clock_script" 2>/dev/null || echo "$clock_script")" "$guest_script"

    log "Setting guest clock to: $datetime"
    vmrun_t -T ws -gu "$GU" -gp "$GP" runProgramInGuest "$VMX_PATH" \
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" \
        -NoProfile -NonInteractive -ExecutionPolicy Bypass \
        -File "$guest_script" -DateTime "$datetime"
    log "Clock set command sent"
}

# ==================== Frida DBI Analysis ====================

cmd_frida_analyze() {
    local binary="$1"
    local wait_sec="${2:-60}"
    local frida_script_dir="$(cd "$(dirname "$0")" && pwd)/frida-scripts"

    if [ -z "$binary" ]; then
        err "Usage: sandbox.sh frida-analyze <binary_path> [wait_seconds=60] [--bypass-only|--dump-only]"
        exit 1
    fi

    if [ ! -f "$binary" ]; then
        err "File not found: $binary"
        exit 1
    fi

    local bname="$(basename "$binary")"
    local timestamp="$(date +%Y%m%d_%H%M%S)"
    local result_dir="$(cd "$(dirname "$0")" && pwd)/output/frida_${bname}_${timestamp}"
    mkdir -p "$result_dir"

    log "=== Frida DBI Analysis: $bname ==="
    log "Wait time: ${wait_sec}s"
    log "Output: $result_dir"

    local wheels_dir="$(cd "$(dirname "$0")" && pwd)/input/frida_wheels"

    # 1. Revert to clean snapshot
    log "Step 1/9: Reverting to clean_with_tools..."
    cmd_revert clean_with_tools
    sleep 10  # Wait for VMware Tools to fully start

    # 2. Install Frida (offline from wheels)
    log "Step 2/9: Installing Frida (offline)..."
    vmrun_script 30 "cmd.exe /c mkdir \"${GUEST_ANALYSIS_DIR}\\wheels\" 2>nul"

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
            timeout 60 "$VMRUN" -T ws -gu "$GU" -gp "$GP" copyFileFromHostToGuest "$VMX_PATH" \
                "$wheels_dir/$whl" "${GUEST_ANALYSIS_DIR}\\wheels\\${whl}" 2>/dev/null || true
        fi
    done

    vmrun_script 120 "cmd.exe /c pip install --no-index --find-links=\"${GUEST_ANALYSIS_DIR}\\wheels\" frida-tools > \"${GUEST_ANALYSIS_DIR}\\frida_install.txt\" 2>&1"
    log "Frida installed"

    # 3. Network isolation
    log "Step 3/9: Network isolation..."
    cmd_net_isolate 2>/dev/null || true

    # 4. Copy binary to guest
    log "Step 4/9: Copying binary to guest..."
    vmrun_script 30 "cmd.exe /c mkdir \"${GUEST_ANALYSIS_DIR}\" 2>nul"
    vmrun_script 30 "cmd.exe /c mkdir \"${GUEST_ANALYSIS_DIR}\\dumps\" 2>nul"
    timeout 60 "$VMRUN" -T ws -gu "$GU" -gp "$GP" copyFileFromHostToGuest "$VMX_PATH" \
        "$binary" "${GUEST_ANALYSIS_DIR}\\${bname}"

    # 5. Copy Frida scripts to guest
    log "Step 5/9: Copying Frida scripts..."
    for script in bypass_vmdetect.js dump_payload.js; do
        if [ -f "$frida_script_dir/$script" ]; then
            timeout 30 "$VMRUN" -T ws -gu "$GU" -gp "$GP" copyFileFromHostToGuest "$VMX_PATH" \
                "$frida_script_dir/$script" "${GUEST_ANALYSIS_DIR}\\${script}"
        fi
    done

    # 6. Pre-execution state
    log "Step 6/9: Capturing pre-execution state..."
    vmrun_script 30 "cmd.exe /c tasklist /fo csv > \"${GUEST_ANALYSIS_DIR}\\processes_before.txt\" 2>&1"
    cmd_screenshot "$result_dir/screenshot_before.png" 2>/dev/null || true

    # 7. Launch with Frida (spawn mode, -q quiet, -t timeout, --kill-on-exit)
    log "Step 7/9: Launching with Frida (spawn mode, wait ${wait_sec}s)..."

    local frida_timeout=$((wait_sec + 60))
    vmrun_script "$frida_timeout" \
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"frida -f '${GUEST_ANALYSIS_DIR}\\${bname}' -l '${GUEST_ANALYSIS_DIR}\\bypass_vmdetect.js' -l '${GUEST_ANALYSIS_DIR}\\dump_payload.js' -q -t ${wait_sec} --kill-on-exit 2>&1 | Out-File -Encoding UTF8 '${GUEST_ANALYSIS_DIR}\\frida_log.txt'\"" || true

    # Capture post-execution process list
    vmrun_script 30 "cmd.exe /c tasklist /fo csv > \"${GUEST_ANALYSIS_DIR}\\processes_after.txt\" 2>&1" || true

    # 8. Post-execution collection
    log "Step 8/9: Collecting results..."
    cmd_screenshot "$result_dir/screenshot_after.png" 2>/dev/null || true

    # Run HollowsHunter
    log "Running HollowsHunter..."
    vmrun_script 60 "cmd.exe /c \"${GUEST_TOOLS_DIR}\\hollows_hunter64.exe\" /dir \"${GUEST_ANALYSIS_DIR}\\hh_output\" > \"${GUEST_ANALYSIS_DIR}\\hh_log.txt\" 2>&1" || true

    # Copy results from guest
    log "Copying results to host..."
    for f in frida_log.txt processes_before.txt processes_after.txt hh_log.txt; do
        timeout 30 "$VMRUN" -T ws -gu "$GU" -gp "$GP" copyFileFromGuestToHost "$VMX_PATH" \
            "${GUEST_ANALYSIS_DIR}\\${f}" "$result_dir/${f}" 2>/dev/null || true
    done

    # Copy dump files
    vmrun_script 30 "cmd.exe /c dir /b \"${GUEST_ANALYSIS_DIR}\\dumps\\*.bin\" > \"${GUEST_ANALYSIS_DIR}\\dump_list.txt\" 2>&1" || true
    timeout 20 "$VMRUN" -T ws -gu "$GU" -gp "$GP" copyFileFromGuestToHost "$VMX_PATH" \
        "${GUEST_ANALYSIS_DIR}\\dump_list.txt" "$result_dir/dump_list.txt" 2>/dev/null || true

    if [ -f "$result_dir/dump_list.txt" ]; then
        while IFS= read -r dumpfile; do
            dumpfile="$(echo "$dumpfile" | tr -d '\r')"
            [ -z "$dumpfile" ] && continue
            [[ "$dumpfile" == *"not found"* ]] && continue
            log "Retrieving dump: $dumpfile"
            timeout 60 "$VMRUN" -T ws -gu "$GU" -gp "$GP" copyFileFromGuestToHost "$VMX_PATH" \
                "${GUEST_ANALYSIS_DIR}\\dumps\\${dumpfile}" "$result_dir/${dumpfile}" 2>/dev/null || true
        done < "$result_dir/dump_list.txt"
    fi

    # Copy HollowsHunter output
    vmrun_script 30 "cmd.exe /c dir /b \"${GUEST_ANALYSIS_DIR}\\hh_output\\*\" > \"${GUEST_ANALYSIS_DIR}\\hh_list.txt\" 2>&1" || true
    timeout 20 "$VMRUN" -T ws -gu "$GU" -gp "$GP" copyFileFromGuestToHost "$VMX_PATH" \
        "${GUEST_ANALYSIS_DIR}\\hh_list.txt" "$result_dir/hh_list.txt" 2>/dev/null || true

    if [ -f "$result_dir/hh_list.txt" ]; then
        mkdir -p "$result_dir/hh_output"
        while IFS= read -r hhfile; do
            hhfile="$(echo "$hhfile" | tr -d '\r')"
            [ -z "$hhfile" ] && continue
            [[ "$hhfile" == *"not found"* ]] && continue
            timeout 60 "$VMRUN" -T ws -gu "$GU" -gp "$GP" copyFileFromGuestToHost "$VMX_PATH" \
                "${GUEST_ANALYSIS_DIR}\\hh_output\\${hhfile}" "$result_dir/hh_output/${hhfile}" 2>/dev/null || true
        done < "$result_dir/hh_list.txt"
    fi

    # 9. Revert
    log "Step 9/9: Reverting to clean state..."
    cmd_revert clean_with_tools

    # Summary
    echo ""
    log "=== Frida Analysis Complete ==="
    log "Results: $result_dir"
    [ -f "$result_dir/frida_log.txt" ] && log "Frida log: frida_log.txt"
    local dump_count=$(ls "$result_dir"/*.bin 2>/dev/null | wc -l)
    log "Memory dumps: $dump_count"
    [ -d "$result_dir/hh_output" ] && log "HollowsHunter: hh_output/"
    echo ""
}

# Main
case "${1:-}" in
    start)          cmd_start ;;
    stop)           cmd_stop ;;
    force-stop)     cmd_force_stop ;;
    status)         cmd_status ;;
    revert)         cmd_revert "$2" ;;
    snapshot)       cmd_snapshot "$2" ;;
    copy-to)        cmd_copy_to "$2" "$3" ;;
    copy-from)      cmd_copy_from "$2" "$3" ;;
    exec)           shift; cmd_exec "$@" ;;
    ps)             shift; cmd_ps "$@" ;;
    guest-cmd)      shift; cmd_guest_cmd "$@" ;;
    processes)      cmd_processes ;;
    screenshot)     cmd_screenshot "$2" ;;
    ip)             cmd_ip ;;
    net-isolate)    cmd_net_isolate ;;
    net-nat)        cmd_net_nat ;;
    net-disconnect) cmd_net_disconnect ;;
    net-status)     cmd_net_status ;;
    guest-tools)    cmd_guest_tools ;;
    harden-vmx)     cmd_harden_vmx ;;
    harden-guest)   cmd_harden_guest ;;
    memdump)        cmd_memdump "$2" "$3" "$4" ;;
    analyze)        cmd_analyze "$2" "$3" ;;
    unpack)         cmd_unpack "$2" "$3" ;;
    run-script)     cmd_run_script "$2" "$3" ;;
    set-clock)      shift; cmd_set_clock "$@" ;;
    frida-analyze)  cmd_frida_analyze "$2" "$3" ;;
    fakenet-validate)
        local validate_dir="${2:-$INPUT_DIR}"
        log "Running FakeNet validation on: $validate_dir"
        python3 "$SCRIPT_DIR/fakenet_validate.py" check-all "$validate_dir"
        ;;
    build-response)
        shift
        python3 "$SCRIPT_DIR/build_http_response.py" "$@"
        ;;
    devirt)         cmd_devirt "$2" "$3" ;;
    regshot-diff)
        if [ -z "$2" ]; then
            echo "Usage: sandbox.sh regshot-diff <export.txt>"
            echo "  Analyze Regshot text export for persistence indicators"
            exit 1
        fi
        log "Analyzing Regshot diff: $2"
        python3 "$SCRIPT_DIR/regshot_diff.py" "$2"
        ;;
    evasion-check)
        log "Running sandbox evasion check on guest..."
        # Copy and run the evasion checker on guest
        local checker_exe="$SCRIPT_DIR/sandbox-evasion-check/sandbox-evasion-check.exe"
        if [ ! -f "$checker_exe" ]; then
            err "sandbox-evasion-check.exe not found. Build it first:"
            err "  cd Tools/vmware-sandbox/sandbox-evasion-check && GOOS=windows GOARCH=amd64 go build -o sandbox-evasion-check.exe"
            exit 1
        fi
        ensure_running
        local guest_checker="${GUEST_ANALYSIS_DIR}\\sandbox-evasion-check.exe"
        local guest_report="${GUEST_ANALYSIS_DIR}\\sandbox-evasion-report.json"
        vmrun_t copyFileFromHostToGuest "$VMX_PATH" -gu "$GU" -gp "$GP" "$checker_exe" "$guest_checker"
        vmrun_t runProgramInGuest "$VMX_PATH" -gu "$GU" -gp "$GP" -activeWindow "$guest_checker"
        sleep 3
        local local_report="$OUTPUT_DIR/sandbox-evasion-report.json"
        vmrun_t copyFileFromGuestToHost "$VMX_PATH" -gu "$GU" -gp "$GP" "$guest_report" "$local_report" 2>/dev/null
        if [ -f "$local_report" ]; then
            log "Report saved: $local_report"
            cat "$local_report" | python3 -m json.tool 2>/dev/null || cat "$local_report"
        else
            warn "Could not retrieve report. Check VM GUI for results."
        fi
        ;;
    *)
        echo "VMware Sandbox - Dynamic Malware Analysis"
        echo ""
        echo "Usage: bash Tools/vmware-sandbox/sandbox.sh <command> [args]"
        echo ""
        echo "VM Management:"
        echo "  start                          Start VM (headless)"
        echo "  stop                           Stop VM (soft, via VMware Tools)"
        echo "  force-stop                     Kill vmware-vmx.exe (when stop hangs)"
        echo "  status                         Show VM status, IP & network"
        echo "  revert [snapshot]              Revert to snapshot (default: clean_with_tools)"
        echo "  snapshot [name]                Create snapshot"
        echo ""
        echo "Network (IMPORTANT for safety):"
        echo "  net-isolate                    Host-Only mode (use before malware exec)"
        echo "  net-nat                        NAT mode (C2 capture only)"
        echo "  net-disconnect                 Fully disconnected"
        echo "  net-status                     Show current network mode"
        echo ""
        echo "File Transfer:"
        echo "  copy-to <local_file> [guest]   Copy file to guest"
        echo "  copy-from <guest_file> [local] Copy file from guest"
        echo ""
        echo "Execution:"
        echo "  exec <program> [args]          Run program in guest"
        echo "  ps <powershell_command>        Run PowerShell in guest (safe, no hang)"
        echo "  guest-cmd [--timeout N] <cmd> [outfile]"
        echo "                                 Run PowerShell & capture output to host"
        echo "  run-script <script.ps1> [timeout=60]"
        echo "                                 Copy .ps1 to guest, execute, retrieve output"
        echo "  set-clock <YYYY-MM-DD HH:MM:SS>"
        echo "                                 Disable time sync & set guest clock"
        echo "  processes                      List guest processes"
        echo "  screenshot [output_path]       Capture guest screen"
        echo "  ip                             Get guest IP address"
        echo ""
        echo "Anti-VM Hardening:"
        echo "  harden-vmx                     Apply anti-VM settings to .vmx (stop->edit->start)"
        echo "  harden-guest                   Spoof VMware registry/services inside guest"
        echo ""
        echo "Tools:"
        echo "  guest-tools                    Check guest analysis tools existence"
        echo "  memdump <target> [delays] [outdir]"
        echo "                                 Run memdump-racer on guest"
        echo "                                 (CreateProcessW + pe-sieve64 + MiniDump)"
        echo ""
        echo "Analysis:"
        echo "  analyze <binary> [wait_sec]    Full dynamic analysis workflow"
        echo "                                 (revert->isolate->copy->exec->collect->revert)"
        echo ""
        echo "Unpacking:"
        echo "  unpack <binary> [level]        Automated unpacking (3-level system)"
        echo "                                 level: 1=memdump-racer, 2=TinyTracer,"
        echo "                                        3=manual x64dbg, auto=escalate (default)"
        echo ""
        echo "Frida DBI (VM-detection bypass + payload dump):"
        echo "  frida-analyze <binary> [wait]  Launch with Frida spawn mode (default: 60s)"
        echo "                                 Loads bypass_vmdetect.js + dump_payload.js"
        echo "                                 Auto: revert->isolate->frida->HH->collect->revert"
        echo ""
        echo "Devirtualization (VMProtect code virtualization removal):"
        echo "  devirt <binary> [address]      Unpack + devirtualize VMP functions"
        echo "                                 Pipeline: dump-triage(VMP scan) -> Mergen(LLVM lift)"
        echo "                                 If address given, devirt single function"
        echo "                                 If omitted, auto-detect & batch devirt"
        echo ""
        echo "FakeNet Validation:"
        echo "  fakenet-validate [dir]         Validate CA cert, INI config, response files"
        echo "                                 (default: input/ directory)"
        echo "  build-response [args]          Build raw HTTP response with CRLF"
        echo "                                 --template vidar-config|vidar-client|generic-json"
        echo "                                 --list-templates for all options"
        echo ""
        echo "Post-Analysis:"
        echo "  regshot-diff <export.txt>      Analyze Regshot diff for persistence indicators"
        echo "  evasion-check                  Run sandbox evasion diagnostic on guest VM"
        ;;
esac
