# Ghidra Headless Script: decompile_function.py
# Decompile specific functions by offset, name, or address range.
# @category Analysis
# @runtime Jython
#
# Usage:
#   analyzeHeadless ... -process binary.dll -noanalysis \
#     -scriptPath /opt/ghidra-scripts \
#     -postScript decompile_function.py /analysis/output/func.txt 0xc8d0 FUN_18000a8a0 0xc000-0xd000
#
# Target specifiers (space-separated after the output path):
#   0xOFFSET       - ImageBase-relative offset (e.g. 0xc8d0)
#   FUNC_NAME      - function name (e.g. FUN_18000c8d0, entry)
#   0xSTART-0xEND  - range of offsets; all functions whose entry falls within

import codecs
import os

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

SCRIPT_NAME = "decompile_function.py"


def log(level, msg):
    print("[%s] %s: %s" % (level, SCRIPT_NAME, msg))


def parse_targets(program, specs):
    """Resolve target specifiers into a list of Function objects."""
    fm = program.getFunctionManager()
    image_base = program.getImageBase().getOffset()
    addr_space = program.getAddressFactory().getDefaultAddressSpace()
    targets = []
    seen = set()

    for spec in specs:
        spec = spec.strip()
        if not spec:
            continue

        # Range: 0xSTART-0xEND
        if "-" in spec and spec.startswith("0x"):
            parts = spec.split("-", 1)
            try:
                start_off = int(parts[0], 16)
                end_off = int(parts[1], 16)
            except ValueError:
                log("ERROR", "Invalid range: %s" % spec)
                continue
            abs_start = image_base + start_off
            abs_end = image_base + end_off
            log("INFO", "Range 0x%x-0x%x (abs 0x%x-0x%x)" % (start_off, end_off, abs_start, abs_end))
            func_iter = fm.getFunctions(True)
            count = 0
            for func in func_iter:
                entry = func.getEntryPoint().getOffset()
                if abs_start <= entry <= abs_end:
                    key = func.getEntryPoint().toString()
                    if key not in seen:
                        seen.add(key)
                        targets.append(func)
                        count += 1
            log("INFO", "  Found %d functions in range" % count)

        # Offset: 0xNNNN (no dash)
        elif spec.startswith("0x") or spec.startswith("0X"):
            try:
                offset = int(spec, 16)
            except ValueError:
                log("ERROR", "Invalid hex offset: %s" % spec)
                continue
            abs_addr = image_base + offset
            addr = addr_space.getAddress(abs_addr)
            func = fm.getFunctionContaining(addr)
            if func is None:
                func = fm.getFunctionAt(addr)
            if func:
                key = func.getEntryPoint().toString()
                if key not in seen:
                    seen.add(key)
                    targets.append(func)
                    log("INFO", "Offset 0x%x -> %s @ 0x%s" % (offset, func.getName(), func.getEntryPoint()))
            else:
                log("ERROR", "No function found at offset 0x%x (abs 0x%x)" % (offset, abs_addr))

        # Name: anything else
        else:
            found = False
            func_iter = fm.getFunctions(True)
            for func in func_iter:
                if func.getName() == spec:
                    key = func.getEntryPoint().toString()
                    if key not in seen:
                        seen.add(key)
                        targets.append(func)
                        log("INFO", "Name '%s' -> 0x%s" % (spec, func.getEntryPoint()))
                    found = True
                    break
            if not found:
                log("ERROR", "Function not found by name: %s" % spec)

    return targets


def get_callees(func):
    """Return a list of (address, name) tuples for functions called by func."""
    callees = []
    seen = set()
    refs = func.getProgram().getReferenceManager()
    body = func.getBody()
    addr_iter = body.getAddresses(True)
    fm = func.getProgram().getFunctionManager()
    while addr_iter.hasNext():
        addr = addr_iter.next()
        for ref in refs.getReferencesFrom(addr):
            if ref.getReferenceType().isCall():
                target = ref.getToAddress()
                target_func = fm.getFunctionAt(target)
                if target_func and target.toString() not in seen:
                    seen.add(target.toString())
                    callees.append((target.toString(), target_func.getName()))
    return callees


# --- Main ---
args = getScriptArgs()
if len(args) < 2:
    log("ERROR", "Usage: decompile_function.py <output_path> <spec1> [spec2] ...")
    log("ERROR", "  spec: 0xOFFSET | FUNC_NAME | 0xSTART-0xEND")
    import sys
    sys.exit(1)

output_path = args[0]
specs = args[1:]

log("INFO", "Output: %s" % output_path)
log("INFO", "Targets: %s" % " ".join(specs))

program = currentProgram
image_base = program.getImageBase().getOffset()
log("INFO", "Program: %s (ImageBase=0x%x)" % (program.getName(), image_base))

targets = parse_targets(program, specs)
log("INFO", "Resolved %d function(s) to decompile" % len(targets))

if not targets:
    log("ERROR", "No functions resolved. Check your specifiers.")
    import sys
    sys.exit(1)

# Init decompiler
monitor = ConsoleTaskMonitor()
decomp = DecompInterface()
opts = DecompileOptions()
decomp.setOptions(opts)
open_ok = decomp.openProgram(program)
if not open_ok:
    log("ERROR", "DecompInterface.openProgram() failed")

lines = []
lines.append("=" * 70)
lines.append("Targeted Decompilation: %s" % program.getName())
lines.append("ImageBase: 0x%x" % image_base)
lines.append("Functions: %d" % len(targets))
lines.append("=" * 70)

success = 0
errors = 0

for func in targets:
    func_name = func.getName()
    func_addr = func.getEntryPoint()
    func_offset = func_addr.getOffset() - image_base
    func_size = func.getBody().getNumAddresses()

    lines.append("")
    lines.append("// " + "=" * 66)
    lines.append("// Function: %s" % func_name)
    lines.append("// Address:  0x%s  (offset: 0x%x)" % (func_addr, func_offset))
    lines.append("// Size:     %d bytes" % func_size)

    # Callees
    callees = get_callees(func)
    if callees:
        lines.append("// Callees:  %d" % len(callees))
        for addr, name in callees:
            callee_off = int(addr, 16) - image_base if addr.startswith("0") else 0
            lines.append("//   0x%s  %s  (offset: 0x%x)" % (addr, name, callee_off))
    else:
        lines.append("// Callees:  (none)")

    lines.append("// " + "=" * 66)

    # Decompile
    results = decomp.decompileFunction(func, 120, monitor)

    if results and results.getDecompiledFunction():
        c_code = results.getDecompiledFunction().getC()
        if c_code:
            lines.append(c_code)
            success += 1
            log("INFO", "OK: %s @ 0x%s (offset 0x%x, %d bytes)" % (func_name, func_addr, func_offset, func_size))
        else:
            lines.append("// [ERROR] No C output available")
            errors += 1
            log("ERROR", "No C output: %s" % func_name)
    else:
        error_msg = results.getErrorMessage() if results else "Decompilation failed"
        lines.append("// [ERROR] %s" % error_msg)
        errors += 1
        log("ERROR", "Failed: %s -- %s" % (func_name, error_msg))

decomp.dispose()

lines.append("")
lines.append("// " + "=" * 66)
lines.append("// Summary: %d succeeded, %d failed, %d total" % (success, errors, len(targets)))

output = "\n".join(lines) + "\n"

# Write output
output_dir = os.path.dirname(output_path)
if output_dir and not os.path.exists(output_dir):
    os.makedirs(output_dir)
try:
    with codecs.open(output_path, "w", encoding="utf-8") as f:
        f.write(output)
    log("INFO", "Saved to %s" % output_path)
except Exception as e:
    log("ERROR", "Failed to write %s: %s" % (output_path, str(e)))

print(output)
log("INFO", "Complete: %d/%d functions decompiled" % (success, len(targets)))
