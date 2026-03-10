# Ghidra Headless Script: decompile_all.py
# Decompiles all functions to C pseudocode using DecompInterface
# @category Analysis
# @runtime Jython

import os
import codecs
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

print("[INFO] decompile_all.py: Script started")

program = currentProgram
name = program.getName()
output_dir = "/analysis/output"

print("[INFO] decompile_all.py: Processing program='%s', output_dir='%s'" % (name, output_dir))

print("[DEBUG] decompile_all.py: Initializing DecompInterface")
monitor = ConsoleTaskMonitor()
decomp = DecompInterface()
opts = DecompileOptions()
decomp.setOptions(opts)
decomp.openProgram(program)
print("[DEBUG] decompile_all.py: DecompInterface initialized successfully")

fm = program.getFunctionManager()
total_functions = fm.getFunctionCount()
functions = fm.getFunctions(True)

print("[INFO] decompile_all.py: Total functions to decompile: %d" % total_functions)

lines = []
lines.append("=" * 60)
lines.append("Decompiled Output: %s" % name)
lines.append("Total functions: %d" % total_functions)
lines.append("=" * 60)

count = 0
errors = 0

for func in functions:
    if monitor.isCancelled():
        print("[INFO] decompile_all.py: Monitor cancelled, stopping decompilation")
        break

    func_name = func.getName()
    func_addr = func.getEntryPoint()
    print("[DEBUG] decompile_all.py: Decompiling function '%s' @ 0x%s" % (func_name, func_addr))

    results = decomp.decompileFunction(func, 60, monitor)

    lines.append("")
    lines.append("// " + "-" * 56)
    lines.append("// Function: %s @ 0x%s" % (func_name, func_addr))
    lines.append("// Size: %d bytes" % func.getBody().getNumAddresses())
    lines.append("// " + "-" * 56)

    if results and results.getDecompiledFunction():
        c_code = results.getDecompiledFunction().getC()
        if c_code:
            lines.append(c_code)
            count += 1
            print("[DEBUG] decompile_all.py: Successfully decompiled '%s'" % func_name)
        else:
            lines.append("// [ERROR] No C output available")
            errors += 1
            print("[ERROR] decompile_all.py: No C output for function '%s' @ 0x%s" % (func_name, func_addr))
    else:
        error_msg = results.getErrorMessage() if results else "Decompilation failed"
        lines.append("// [ERROR] %s" % error_msg)
        errors += 1
        print("[ERROR] decompile_all.py: Decompilation error for '%s' @ 0x%s: %s" % (func_name, func_addr, error_msg))

print("[INFO] decompile_all.py: Decompilation complete - success=%d, errors=%d, total=%d" % (count, errors, count + errors))

lines.append("")
lines.append("// " + "=" * 56)
lines.append("// Decompiled: %d functions, Errors: %d" % (count, errors))

print("[DEBUG] decompile_all.py: Disposing DecompInterface")
decomp.dispose()

output = "\n".join(lines)
print("[*] Decompiled %d functions (%d errors)" % (count, errors))

outfile = os.path.join(output_dir, "%s_decompiled.c" % name)
print("[DEBUG] decompile_all.py: Writing output to '%s'" % outfile)
try:
    with codecs.open(outfile, "w", encoding="utf-8") as f:
        f.write(output + "\n")
    print("[*] Saved to %s" % outfile)
    print("[INFO] decompile_all.py: Script completed successfully")
except Exception as e:
    print("[ERROR] decompile_all.py: Failed to write output file '%s': %s" % (outfile, str(e)))
