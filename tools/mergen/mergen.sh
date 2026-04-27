#!/bin/bash
# Mergen - VMProtect Devirtualization via LLVM IR Lifting
# Usage: bash Tools/mergen/mergen.sh <command> [args]

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONTAINER_NAME="mergen"
OUTPUT_DIR="$SCRIPT_DIR/output"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { printf '%b %s\n' "${GREEN}[*]${NC}" "$1"; }
warn() { printf '%b %s\n' "${YELLOW}[!]${NC}" "$1"; }
err() { printf '%b %s\n' "${RED}[-]${NC}" "$1"; }

ensure_container() {
    local status
    status=$(docker inspect -f '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "none")
    if [ "$status" = "none" ]; then
        log "Building Mergen container (first run, takes ~10min)..."
        docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d --build
    elif [ "$status" != "running" ]; then
        log "Starting Mergen container..."
        docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d
    fi
}

prepare_binary() {
    local host_path="$1"
    local basename
    basename=$(basename "$host_path")
    # Copy binary into container /work/
    docker cp "$host_path" "${CONTAINER_NAME}:/work/${basename}"
    echo "/work/${basename}"
}

cmd_start() {
    ensure_container
    log "Mergen container running"
}

cmd_stop() {
    docker compose -f "$SCRIPT_DIR/docker-compose.yml" down
    log "Mergen container stopped"
}

cmd_status() {
    local status
    status=$(docker inspect -f '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "not found")
    log "Mergen container: $status"
}

cmd_devirt() {
    local binary="$1"
    local address="$2"

    if [ -z "$binary" ] || [ -z "$address" ]; then
        err "Usage: mergen.sh devirt <binary> <address>"
        err "  address: hex address of VMP function (e.g., 0x140001000)"
        exit 1
    fi

    ensure_container

    local bname
    bname=$(basename "$binary")
    local container_path
    container_path=$(prepare_binary "$binary")

    log "Devirtualizing: $bname @ $address"
    local outfile="output/${bname}_${address}.ll"

    docker exec "$CONTAINER_NAME" lifter "$container_path" "$address" \
        > "$OUTPUT_DIR/${bname}_${address}.ll" 2>"$OUTPUT_DIR/${bname}_${address}.log" || {
        err "Devirtualization failed. Check log: $OUTPUT_DIR/${bname}_${address}.log"
        cat "$OUTPUT_DIR/${bname}_${address}.log"
        return 1
    }

    local ll_size
    ll_size=$(stat -c%s "$OUTPUT_DIR/${bname}_${address}.ll" 2>/dev/null || stat -f%z "$OUTPUT_DIR/${bname}_${address}.ll" 2>/dev/null || echo 0)
    if [ "$ll_size" -gt 0 ]; then
        log "LLVM IR output: $OUTPUT_DIR/${bname}_${address}.ll ($ll_size bytes)"
    else
        warn "No LLVM IR output. Check log for errors."
        cat "$OUTPUT_DIR/${bname}_${address}.log" 2>/dev/null
    fi
}

cmd_devirt_batch() {
    local binary="$1"
    local addr_file="$2"

    if [ -z "$binary" ] || [ -z "$addr_file" ]; then
        err "Usage: mergen.sh devirt-batch <binary> <addresses_file>"
        err "  addresses_file: one hex address per line"
        exit 1
    fi

    if [ ! -f "$addr_file" ]; then
        err "Address file not found: $addr_file"
        exit 1
    fi

    ensure_container
    prepare_binary "$binary" > /dev/null

    local total=0
    local success=0
    local failed=0

    while IFS= read -r addr; do
        addr=$(echo "$addr" | tr -d '[:space:]')
        [ -z "$addr" ] && continue
        [[ "$addr" == \#* ]] && continue
        total=$((total + 1))

        log "[$total] Devirtualizing $addr..."
        if cmd_devirt "$binary" "$addr" 2>/dev/null; then
            success=$((success + 1))
        else
            failed=$((failed + 1))
        fi
    done < "$addr_file"

    log "Batch complete: $success/$total succeeded, $failed failed"
    log "Results in: $OUTPUT_DIR/"
}

cmd_scan() {
    local binary="$1"

    if [ -z "$binary" ]; then
        err "Usage: mergen.sh scan <binary>"
        err "  Scans for VMP section entry point candidates"
        exit 1
    fi

    # Use dump-triage if available for VMP address detection
    local dump_triage="$SCRIPT_DIR/../dump-triage/dump-triage.exe"
    if [ -f "$dump_triage" ]; then
        log "Using dump-triage for VMP function detection..."
        "$dump_triage" --vmp-addrs "$binary"
    else
        warn "dump-triage not found. Build it: cd Tools/dump-triage && go build -o dump-triage.exe ."
        warn "Falling back to manual section analysis..."
        ensure_container
        local container_path
        container_path=$(prepare_binary "$binary")
        # Basic section analysis using readelf/objdump in container
        docker exec "$CONTAINER_NAME" bash -c "
            python3 -c \"
import struct, sys
data = open('$container_path', 'rb').read()
if data[:2] != b'MZ': sys.exit('Not a PE file')
pe_off = struct.unpack_from('<I', data, 60)[0]
num_sec = struct.unpack_from('<H', data, pe_off+6)[0]
opt_size = struct.unpack_from('<H', data, pe_off+20)[0]
sec_off = pe_off + 24 + opt_size
ep_rva = struct.unpack_from('<I', data, pe_off+40)[0]
print(f'EntryPoint RVA: 0x{ep_rva:08X}')
print()
print('VMP Section Candidates:')
std = {'.text','.rdata','.data','.bss','.rsrc','.reloc','.idata','.edata','.pdata','.tls','.CRT','.gfids','.00cfg'}
for i in range(num_sec):
    off = sec_off + i*40
    name = data[off:off+8].rstrip(b'\x00').decode('ascii','replace')
    va = struct.unpack_from('<I', data, off+12)[0]
    vs = struct.unpack_from('<I', data, off+8)[0]
    chars = struct.unpack_from('<I', data, off+36)[0]
    is_exec = bool(chars & 0x20000000)
    if name.lower() not in {s.lower() for s in std} and is_exec:
        print(f'  {name}: VA=0x{va:08X} Size=0x{vs:X} [EXECUTABLE]')
        if va <= ep_rva < va + vs:
            print(f'    ^ EntryPoint is inside this section')
\" 2>&1" || true
    fi
}

cmd_shell() {
    ensure_container
    docker exec -it "$CONTAINER_NAME" /bin/bash
}

# Main
case "${1:-}" in
    start)          cmd_start ;;
    stop)           cmd_stop ;;
    status)         cmd_status ;;
    devirt)         cmd_devirt "$2" "$3" ;;
    devirt-batch)   cmd_devirt_batch "$2" "$3" ;;
    scan)           cmd_scan "$2" ;;
    shell)          cmd_shell ;;
    *)
        echo "Mergen - VMProtect Devirtualization via LLVM IR Lifting"
        echo ""
        echo "Usage: bash Tools/mergen/mergen.sh <command> [args]"
        echo ""
        echo "Container:"
        echo "  start                          Build & start Mergen container"
        echo "  stop                           Stop container"
        echo "  status                         Show container status"
        echo "  shell                          Open shell in container"
        echo ""
        echo "Devirtualization:"
        echo "  devirt <binary> <address>      Devirtualize a single VMP function"
        echo "                                 address: hex RVA (e.g., 0x140001000)"
        echo "                                 Output: LLVM IR (.ll file)"
        echo "  devirt-batch <binary> <file>   Batch devirtualize from address list"
        echo "                                 file: one hex address per line"
        echo "  scan <binary>                  Detect VMP sections & entry candidates"
        echo ""
        echo "Pipeline:"
        echo "  1. sandbox.sh unpack <packed.exe>     # Remove packing layer"
        echo "  2. mergen.sh scan <unpacked.exe>      # Find VMP function addresses"
        echo "  3. mergen.sh devirt <unpacked.exe> <addr>  # Lift to LLVM IR"
        echo "  4. ghidra.sh analyze <unpacked.exe>   # Cross-reference with decompile"
        echo ""
        echo "Output: Tools/mergen/output/"
        ;;
esac
