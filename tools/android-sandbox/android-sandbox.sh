#!/usr/bin/env bash
# android-sandbox.sh — Android SDK Emulator-based APK dynamic analysis CLI
# Usage: bash tools/android-sandbox/android-sandbox.sh <command> [args...]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Load .env
if [[ -f "$REPO_ROOT/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source <(grep -v '^#\|^$\|[()]' "$REPO_ROOT/.env" 2>/dev/null || true)
  set +a
fi

# Defaults
ANDROID_SDK_PATH="${ANDROID_SDK_PATH:-$HOME/android-sdk}"
ANDROID_AVD_NAME="${ANDROID_AVD_NAME:-malware_analysis}"
ANDROID_API_LEVEL="${ANDROID_API_LEVEL:-28}"

ADB="$ANDROID_SDK_PATH/platform-tools/adb.exe"
EMULATOR="$ANDROID_SDK_PATH/emulator/emulator.exe"
AVDMANAGER="$ANDROID_SDK_PATH/cmdline-tools/latest/bin/avdmanager.bat"
SDKMANAGER="$ANDROID_SDK_PATH/cmdline-tools/latest/bin/sdkmanager.bat"

OUTPUT_DIR="$SCRIPT_DIR/output"
LOGS_DIR="$SCRIPT_DIR/logs"
FRIDA_SCRIPTS="$SCRIPT_DIR/frida-scripts"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[0;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[*]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*"; }

# ============================================================
# Preflight
# ============================================================
preflight() {
  local ok=true
  echo -e "${CYAN}=== android-sandbox preflight ===${NC}"

  if [[ -f "$ADB" ]]; then
    echo -e "  [${GREEN}OK${NC}] adb"
  else
    echo -e "  [${RED}NG${NC}] adb not found at $ADB"
    ok=false
  fi

  if [[ -f "$EMULATOR" ]]; then
    echo -e "  [${GREEN}OK${NC}] emulator"
  else
    echo -e "  [${RED}NG${NC}] emulator not found at $EMULATOR"
    ok=false
  fi

  # Check AVD exists
  if [[ -d "$HOME/.android/avd/${ANDROID_AVD_NAME}.avd" ]]; then
    echo -e "  [${GREEN}OK${NC}] AVD: $ANDROID_AVD_NAME"
  else
    echo -e "  [${RED}NG${NC}] AVD '$ANDROID_AVD_NAME' not found"
    ok=false
  fi

  # Check Java
  if command -v java &>/dev/null; then
    local jver
    jver=$(java -version 2>&1 | head -1)
    echo -e "  [${GREEN}OK${NC}] Java: $jver"
  else
    echo -e "  [${RED}NG${NC}] Java not found"
    ok=false
  fi

  # Check Frida
  if python3 -c "import frida; print(frida.__version__)" 2>/dev/null; then
    echo -e "  [${GREEN}OK${NC}] frida-tools"
  else
    echo -e "  [${YELLOW}WARN${NC}] frida-tools not available (Python 3.11+ required)"
  fi

  # Check quarantine password
  if [[ -n "${QUARANTINE_PASSWORD:-}" ]]; then
    echo -e "  [${GREEN}OK${NC}] QUARANTINE_PASSWORD"
  else
    echo -e "  [${YELLOW}WARN${NC}] QUARANTINE_PASSWORD not set (.enc.gz auto-decrypt disabled)"
  fi

  if $ok; then
    echo -e "\n  ${GREEN}Ready to run android-sandbox${NC}"
    return 0
  else
    echo -e "\n  ${RED}Not ready — fix the issues above${NC}"
    return 1
  fi
}

# ============================================================
# Emulator management
# ============================================================
cmd_start() {
  local gui_flag="--no-window"
  [[ "${1:-}" == "--gui" ]] && gui_flag=""

  info "Starting emulator: $ANDROID_AVD_NAME"
  "$EMULATOR" -avd "$ANDROID_AVD_NAME" \
    $gui_flag -no-snapshot -no-audio -gpu swiftshader_indirect \
    -no-boot-anim -wipe-data &
  local pid=$!
  info "Emulator PID: $pid"

  info "Waiting for boot..."
  until "$ADB" wait-for-device shell getprop sys.boot_completed 2>/dev/null | grep -q "1"; do
    sleep 3
  done
  info "Emulator booted!"
  "$ADB" devices
}

cmd_stop() {
  info "Stopping emulator..."
  "$ADB" emu kill 2>/dev/null || true
  info "Emulator stopped"
}

cmd_status() {
  echo -e "${CYAN}=== Emulator Status ===${NC}"
  "$ADB" devices 2>&1
  echo ""
  "$ADB" shell getprop ro.build.version.release 2>/dev/null && \
    echo "Android version: $("$ADB" shell getprop ro.build.version.release 2>/dev/null)" || \
    warn "No emulator running"
}

# ============================================================
# APK management
# ============================================================
cmd_install() {
  local apk_path="$1"

  # Auto-decrypt .enc.gz
  if [[ "$apk_path" == *.enc.gz ]]; then
    if [[ -z "${QUARANTINE_PASSWORD:-}" ]]; then
      error "QUARANTINE_PASSWORD not set, cannot decrypt .enc.gz"
      return 1
    fi
    info "Decrypting .enc.gz → temp APK..."
    local tmp_apk
    tmp_apk=$(mktemp --suffix=.apk)
    python3 -c "
import gzip, hashlib, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
key = hashlib.sha256(b'${QUARANTINE_PASSWORD}').digest()
with open(r'${apk_path}', 'rb') as f:
    raw = gzip.decompress(f.read())
iv = raw[:16]; ct = raw[16:]
c = Cipher(algorithms.AES(key), modes.CBC(iv))
d = c.decryptor()
pp = d.update(ct) + d.finalize()
u = padding.PKCS7(128).unpadder()
data = u.update(pp) + u.finalize()
with open(r'${tmp_apk}', 'wb') as f:
    f.write(data)
print(f'Decrypted: {len(data)} bytes')
" 2>&1
    info "Installing decrypted APK..."
    "$ADB" install -r -t "$tmp_apk" 2>&1
    rm -f "$tmp_apk"
    info "Temp file deleted"
  else
    info "Installing APK: $apk_path"
    "$ADB" install -r -t "$apk_path" 2>&1
  fi
}

cmd_uninstall() {
  local package="$1"
  info "Uninstalling: $package"
  "$ADB" uninstall "$package" 2>&1
}

cmd_launch() {
  local package="$1"
  info "Launching: $package"
  # Find the main activity
  local activity
  activity=$("$ADB" shell cmd package resolve-activity --brief "$package" 2>/dev/null | tail -1)
  if [[ -n "$activity" ]]; then
    "$ADB" shell am start -n "$activity" 2>&1
  else
    "$ADB" shell monkey -p "$package" -c android.intent.category.LAUNCHER 1 2>&1
  fi
}

# ============================================================
# Network management
# ============================================================
cmd_net_isolate() {
  info "Enabling airplane mode (network isolation)..."
  "$ADB" shell settings put global airplane_mode_on 1
  "$ADB" shell am broadcast -a android.intent.action.AIRPLANE_MODE --ez state true 2>/dev/null || true
  info "Network isolated"
}

cmd_net_enable() {
  info "Disabling airplane mode..."
  "$ADB" shell settings put global airplane_mode_on 0
  "$ADB" shell am broadcast -a android.intent.action.AIRPLANE_MODE --ez state false 2>/dev/null || true
  info "Network enabled"
}

# ============================================================
# Analysis commands
# ============================================================
cmd_screenshot() {
  local output="${1:-screenshot_$(date +%Y%m%d_%H%M%S).png}"
  "$ADB" shell screencap -p /sdcard/tmp_screen.png
  "$ADB" pull /sdcard/tmp_screen.png "$output" 2>&1
  "$ADB" shell rm /sdcard/tmp_screen.png
  info "Screenshot saved: $output"
}

cmd_logcat() {
  local filter="${1:-}"
  if [[ -n "$filter" ]]; then
    "$ADB" logcat -d 2>/dev/null | grep -iE "$filter"
  else
    "$ADB" logcat -d 2>/dev/null
  fi
}

cmd_processes() {
  "$ADB" shell ps -A 2>/dev/null
}

cmd_network_connections() {
  echo -e "${CYAN}=== Network Connections ===${NC}"
  "$ADB" shell cat /proc/net/tcp 2>/dev/null | while IFS= read -r line; do
    if echo "$line" | grep -qv "local_address"; then
      local rem
      rem=$(echo "$line" | awk '{print $3}')
      local hex_ip="${rem%%:*}"
      local hex_port="${rem##*:}"
      if [[ ${#hex_ip} -eq 8 && "$hex_ip" != "00000000" ]]; then
        local ip=""
        for i in 6 4 2 0; do
          local octet=$((16#${hex_ip:$i:2}))
          ip="${ip}${ip:+.}${octet}"
        done
        local port=$((16#$hex_port))
        local uid
        uid=$(echo "$line" | awk '{print $8}')
        echo "  $ip:$port (uid=$uid)"
      fi
    fi
  done
}

# ============================================================
# CDP (Chrome DevTools Protocol) WebView inspection
# ============================================================
cmd_cdp_inspect() {
  local package="$1"
  local pid
  pid=$("$ADB" shell pidof "$package" 2>/dev/null || echo "")
  if [[ -z "$pid" ]]; then
    error "App $package is not running"
    return 1
  fi

  info "Connecting to WebView DevTools (PID: $pid)..."
  "$ADB" forward tcp:9224 "localabstract:webview_devtools_remote_${pid}" 2>/dev/null

  # Get page info
  local pages
  pages=$(curl -s "http://localhost:9224/json" 2>/dev/null)
  if [[ -z "$pages" ]]; then
    error "No WebView debug endpoint found"
    return 1
  fi

  echo -e "${CYAN}=== WebView Pages ===${NC}"
  echo "$pages" | python3 -c "
import json, sys
pages = json.load(sys.stdin)
for p in pages:
    print(f\"  Title: {p.get('title', 'N/A')}\")
    print(f\"  URL:   {p.get('url', 'N/A')}\")
    print(f\"  WS:    {p.get('webSocketDebuggerUrl', 'N/A')}\")
    print()
" 2>/dev/null

  # Check for JS bridges
  local ws_url
  ws_url=$(echo "$pages" | python3 -c "import json,sys; print(json.load(sys.stdin)[0].get('webSocketDebuggerUrl',''))" 2>/dev/null)

  if [[ -n "$ws_url" ]]; then
    info "Checking JS bridges..."
    python3 -c "
import json, websocket
ws = websocket.create_connection('$ws_url', timeout=10)
ws.send(json.dumps({'id':1,'method':'Runtime.evaluate','params':{'expression':'''
(function() {
    var bridges = [];
    var names = ['Android','android','JSBridge','jsBridge','native','app','NativeBridge'];
    for (var i = 0; i < names.length; i++) {
        if (typeof window[names[i]] !== 'undefined') {
            var methods = [];
            for (var m in window[names[i]]) { methods.push(m); }
            bridges.push(names[i] + ': [' + methods.join(', ') + ']');
        }
    }
    return bridges.length > 0 ? bridges.join('\\n') : 'No JS bridges found';
})()
'''}}))
r = json.loads(ws.recv())
print('  ' + r.get('result',{}).get('result',{}).get('value','error'))
ws.close()
" 2>/dev/null
  fi
}

cmd_cdp_eval() {
  local package="$1"
  local js_expr="$2"
  local pid
  pid=$("$ADB" shell pidof "$package" 2>/dev/null || echo "")
  [[ -z "$pid" ]] && { error "App not running"; return 1; }

  "$ADB" forward tcp:9224 "localabstract:webview_devtools_remote_${pid}" 2>/dev/null

  local ws_url
  ws_url=$(curl -s "http://localhost:9224/json" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)[0].get('webSocketDebuggerUrl',''))" 2>/dev/null)

  python3 -c "
import json, websocket
ws = websocket.create_connection('$ws_url', timeout=10)
ws.send(json.dumps({'id':1,'method':'Runtime.evaluate','params':{'expression':'''$js_expr'''}}))
r = json.loads(ws.recv())
val = r.get('result',{}).get('result',{}).get('value', r.get('result',{}).get('result',{}).get('description','error'))
print(val)
ws.close()
" 2>/dev/null
}

cmd_cdp_monitor() {
  local package="$1"
  local duration="${2:-30}"
  local pid
  pid=$("$ADB" shell pidof "$package" 2>/dev/null || echo "")
  [[ -z "$pid" ]] && { error "App not running"; return 1; }

  "$ADB" forward tcp:9224 "localabstract:webview_devtools_remote_${pid}" 2>/dev/null
  local ws_url
  ws_url=$(curl -s "http://localhost:9224/json" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)[0].get('webSocketDebuggerUrl',''))" 2>/dev/null)

  info "Monitoring network requests for ${duration}s..."
  python3 -c "
import json, time, websocket
ws = websocket.create_connection('$ws_url', timeout=10)
ws.send(json.dumps({'id':1,'method':'Network.enable'}))
ws.recv()
ws.settimeout(2)
start = time.time()
while time.time() - start < $duration:
    try:
        msg = json.loads(ws.recv())
        m = msg.get('method','')
        if m == 'Network.requestWillBeSent':
            req = msg['params']['request']
            url = req.get('url','')
            if 'gstatic' not in url and 'google' not in url:
                print(f\"[{req.get('method','')}] {url[:150]}\")
                if req.get('postData'):
                    print(f\"  POST: {req['postData'][:200]}\")
        elif m == 'Network.responseReceived':
            resp = msg['params']['response']
            url = resp.get('url','')
            if 'gstatic' not in url and 'google' not in url:
                print(f\"[{resp.get('status','')}] {url[:150]}\")
    except websocket.WebSocketTimeoutException:
        pass
    except:
        break
ws.close()
" 2>/dev/null
}

# ============================================================
# Frida
# ============================================================
cmd_frida_setup() {
  info "Setting up Frida server on emulator..."

  # Find frida-server binary
  local frida_server=""
  for candidate in \
    "$SCRIPT_DIR/frida-server" \
    "$HOME/Downloads/android-x86/frida-server" \
    "$HOME/Downloads/frida-server"; do
    if [[ -f "$candidate" ]]; then
      frida_server="$candidate"
      break
    fi
  done

  if [[ -z "$frida_server" ]]; then
    error "frida-server binary not found. Download from https://github.com/frida/frida/releases"
    return 1
  fi

  info "Pushing frida-server to emulator..."
  "$ADB" push "$frida_server" /data/local/tmp/frida-server 2>&1
  "$ADB" shell chmod 755 /data/local/tmp/frida-server
  "$ADB" shell "nohup /data/local/tmp/frida-server -D > /dev/null 2>&1 &"
  sleep 2

  if "$ADB" shell "ps -A | grep frida-server" 2>/dev/null | grep -q frida; then
    info "Frida server running"
  else
    error "Frida server failed to start"
    return 1
  fi
}

cmd_frida_hook() {
  local package="$1"
  local script="$2"

  # Resolve script path
  if [[ ! -f "$script" && -f "$FRIDA_SCRIPTS/$script" ]]; then
    script="$FRIDA_SCRIPTS/$script"
  fi

  if [[ ! -f "$script" ]]; then
    error "Script not found: $script"
    return 1
  fi

  info "Hooking $package with $script..."
  frida -U -l "$script" -f "$package" --no-pause 2>&1
}

cmd_frida_dump_dex() {
  local package="$1"
  local script="$FRIDA_SCRIPTS/dump_dex.js"

  if [[ ! -f "$script" ]]; then
    error "dump_dex.js not found at $script"
    return 1
  fi

  local outdir="$OUTPUT_DIR/dex_dump_$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$outdir"

  info "Dumping DEX from $package (output: $outdir)..."
  timeout 60 frida -U -l "$script" -f "$package" --no-pause 2>&1 || true

  # Pull dumped DEX files
  "$ADB" shell "ls /sdcard/dumped_dex_*.dex 2>/dev/null" | while IFS= read -r f; do
    f=$(echo "$f" | tr -d '\r')
    [[ -n "$f" ]] && "$ADB" pull "$f" "$outdir/" 2>/dev/null
  done

  local count
  count=$(find "$outdir" -name "*.dex" 2>/dev/null | wc -l)
  info "Dumped $count DEX file(s) to $outdir"

  # Cleanup
  "$ADB" shell "rm -f /sdcard/dumped_dex_*.dex" 2>/dev/null
}

# ============================================================
# Static triage (no emulator needed)
# ============================================================
cmd_apk_triage() {
  local apk_path="$1"

  echo -e "${CYAN}=== APK Static Triage ===${NC}"

  # Handle .enc.gz
  local actual_apk="$apk_path"
  local tmp_apk=""
  if [[ "$apk_path" == *.enc.gz ]]; then
    if [[ -z "${QUARANTINE_PASSWORD:-}" ]]; then
      error "QUARANTINE_PASSWORD not set"
      return 1
    fi
    tmp_apk=$(mktemp --suffix=.apk)
    python3 -c "
import gzip, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
key = hashlib.sha256(b'${QUARANTINE_PASSWORD}').digest()
with open(r'${apk_path}', 'rb') as f:
    raw = gzip.decompress(f.read())
iv = raw[:16]; ct = raw[16:]
c = Cipher(algorithms.AES(key), modes.CBC(iv))
d = c.decryptor()
pp = d.update(ct) + d.finalize()
u = padding.PKCS7(128).unpadder()
data = u.update(pp) + u.finalize()
with open(r'${tmp_apk}', 'wb') as f:
    f.write(data)
print(f'Decrypted: {len(data)} bytes')
" 2>&1
    actual_apk="$tmp_apk"
  fi

  # Run Python triage
  python3 -c "
import zipfile, struct, hashlib, re, io, os, sys

apk_path = r'$actual_apk'
data = open(apk_path, 'rb').read()
sha256 = hashlib.sha256(data).hexdigest()
print(f'SHA256: {sha256}')
print(f'Size:   {len(data)} bytes ({len(data)/1024/1024:.1f} MB)')

apk = zipfile.ZipFile(io.BytesIO(data))
names = apk.namelist()
print(f'Entries: {len(names)}')

# DEX files
dex = [n for n in names if n.endswith('.dex')]
print(f'DEX:    {dex}')

# Native libs
so = [n for n in names if n.endswith('.so')]
print(f'Native: {so}')

# Packer detection
packer = 'Unknown'
if any('libnmmp' in s for s in so):
    packer = 'NMMP (nmm-protect)'
elif any('libjiagu' in s for s in so):
    packer = 'Jiagu (360)'
elif any('libsecexe' in s for s in so):
    packer = 'Bangcle/SecShell'
elif any('libDexHelper' in s for s in so):
    packer = 'DexProtector'
print(f'Packer: {packer}')

# Assets
assets = [n for n in names if n.startswith('assets/')]
large_assets = [(n, apk.getinfo(n).file_size) for n in assets if apk.getinfo(n).file_size > 1000000]
if large_assets:
    print(f'Large assets (>1MB):')
    for n, s in large_assets:
        print(f'  {n}: {s/1024/1024:.1f} MB')

# JNI strings from native libs (NMMP leak)
if packer == 'NMMP (nmm-protect)':
    print(f'\\n=== JNI String Extraction (NMMP) ===')
    for so_name in so:
        if 'libnmmp' in so_name and 'x86' in so_name:
            try:
                so_data = apk.read(so_name)
                strings_found = re.findall(rb'[\\x20-\\x7e]{6,}', so_data)
                interesting = []
                for s in strings_found:
                    s = s.decode('ascii', errors='replace')
                    sl = s.lower()
                    if any(k in sl for k in ['vpn', 'webview', 'loadurl', 'javascript',
                                               'sms', 'install', 'poll', 'cipher', 'aes',
                                               'sandbox', 'package', 'broadcast', 'service',
                                               'activity', '.apk', 'http']):
                        interesting.append(s)
                for s in sorted(set(interesting)):
                    print(f'  {s}')
            except:
                pass

apk.close()
" 2>&1

  # Cleanup temp
  [[ -n "$tmp_apk" ]] && rm -f "$tmp_apk"
}

# ============================================================
# One-command analysis
# ============================================================
cmd_analyze() {
  local apk_path="$1"
  local wait="${2:-60}"
  local bname
  bname=$(basename "$apk_path" | sed 's/\.enc\.gz$//' | sed 's/\.apk$//')
  local ts
  ts=$(date +%Y%m%d_%H%M%S)
  local outdir="$OUTPUT_DIR/${bname}_${ts}"
  mkdir -p "$outdir"

  info "=== Android Sandbox Analysis ==="
  info "Target: $apk_path"
  info "Output: $outdir"
  info "Wait:   ${wait}s"

  # Log
  local logfile="$LOGS_DIR/${ts}_${bname}.md"
  mkdir -p "$LOGS_DIR"
  {
    echo "# Android Analysis: $bname"
    echo "Date: $(date)"
    echo "Target: $apk_path"
    echo ""
  } > "$logfile"

  # Step 1: Static triage
  info "Step 1: Static triage..."
  cmd_apk_triage "$apk_path" | tee -a "$logfile"

  # Step 2: Start emulator
  info "Step 2: Starting emulator..."
  cmd_start --gui 2>&1 | tee -a "$logfile"

  # Step 3: Install APK
  info "Step 3: Installing APK..."
  cmd_install "$apk_path" 2>&1 | tee -a "$logfile"

  # Step 4: Pre-execution state
  info "Step 4: Pre-execution baseline..."
  cmd_screenshot "$outdir/pre_execution.png"
  cmd_processes > "$outdir/processes_before.txt" 2>/dev/null

  # Step 5: Launch
  local package
  package=$("$ADB" shell pm list packages -3 2>/dev/null | tail -1 | sed 's/package://')
  info "Step 5: Launching $package..."
  cmd_launch "$package" 2>&1 | tee -a "$logfile"

  # Step 6: Wait
  info "Step 6: Waiting ${wait}s for malware activity..."
  sleep "$wait"

  # Step 7: Post-execution state
  info "Step 7: Collecting results..."
  cmd_screenshot "$outdir/post_execution.png"
  cmd_processes > "$outdir/processes_after.txt" 2>/dev/null
  diff "$outdir/processes_before.txt" "$outdir/processes_after.txt" > "$outdir/processes_diff.txt" 2>/dev/null || true
  cmd_logcat "" > "$outdir/logcat.txt" 2>/dev/null
  cmd_network_connections > "$outdir/network_connections.txt" 2>/dev/null

  # Step 8: CDP inspection (if WebView active)
  info "Step 8: CDP WebView inspection..."
  cmd_cdp_inspect "$package" >> "$outdir/cdp_inspect.txt" 2>/dev/null || warn "No WebView found"

  info "=== Analysis Complete ==="
  info "Output: $outdir"
  ls -la "$outdir/"
}

# ============================================================
# Main dispatcher
# ============================================================
usage() {
  cat <<EOF
Usage: $(basename "$0") <command> [args...]

Emulator:
  start [--gui]              Start emulator (headless by default)
  stop                       Stop emulator
  status                     Show emulator status

APK:
  install <apk>              Install APK (.enc.gz auto-decrypt)
  uninstall <package>        Uninstall package
  launch <package>           Launch app

Network:
  net-isolate                Enable airplane mode
  net-enable                 Disable airplane mode

Analysis:
  analyze <apk> [wait=60]    One-command analysis
  logcat [filter]            Capture logcat
  screenshot [output]        Take screenshot
  processes                  List processes
  network-connections        Show TCP connections (decoded)

CDP (WebView):
  cdp-inspect <package>      Inspect WebView pages + JS bridges
  cdp-eval <package> "<js>"  Evaluate JS in WebView
  cdp-monitor <package> [s]  Monitor network requests

Frida:
  frida-setup                Push + start frida-server
  frida-hook <pkg> <script>  Hook with Frida script
  frida-dump-dex <package>   Runtime DEX dump (NMMP unpack)

Static:
  apk-triage <apk>           Static triage (no emulator needed)
  preflight                  Check environment

EOF
}

case "${1:-}" in
  preflight)           preflight ;;
  start)               cmd_start "${2:-}" ;;
  stop)                cmd_stop ;;
  status)              cmd_status ;;
  install)             cmd_install "${2:?Usage: install <apk>}" ;;
  uninstall)           cmd_uninstall "${2:?Usage: uninstall <package>}" ;;
  launch)              cmd_launch "${2:?Usage: launch <package>}" ;;
  net-isolate)         cmd_net_isolate ;;
  net-enable)          cmd_net_enable ;;
  analyze)             cmd_analyze "${2:?Usage: analyze <apk>}" "${3:-60}" ;;
  logcat)              cmd_logcat "${2:-}" ;;
  screenshot)          cmd_screenshot "${2:-}" ;;
  processes)           cmd_processes ;;
  network-connections) cmd_network_connections ;;
  cdp-inspect)         cmd_cdp_inspect "${2:?Usage: cdp-inspect <package>}" ;;
  cdp-eval)            cmd_cdp_eval "${2:?Usage: cdp-eval <package> '<js>'}" "${3:?}" ;;
  cdp-monitor)         cmd_cdp_monitor "${2:?Usage: cdp-monitor <package>}" "${3:-30}" ;;
  frida-setup)         cmd_frida_setup ;;
  frida-hook)          cmd_frida_hook "${2:?Usage: frida-hook <package> <script>}" "${3:?}" ;;
  frida-dump-dex)      cmd_frida_dump_dex "${2:?Usage: frida-dump-dex <package>}" ;;
  apk-triage)          cmd_apk_triage "${2:?Usage: apk-triage <apk>}" ;;
  *)                   usage ;;
esac
