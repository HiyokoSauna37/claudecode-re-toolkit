# Ghidra Headless Script: decompile_all.py
# Decompiles all functions to C pseudocode using DecompInterface
# @category Analysis
# @runtime Jython

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
from ghidra_common import GhidraReport

report = GhidraReport("decompile_all.py", "decompiled.c", "Decompiled Output", currentProgram)
program = report.program
name = report.name

report.log("DEBUG", "Initializing DecompInterface")
monitor = ConsoleTaskMonitor()
decomp = DecompInterface()
opts = DecompileOptions()
decomp.setOptions(opts)

open_ok = decomp.openProgram(program)
if not open_ok:
    report.log("ERROR", "DecompInterface.openProgram() failed")
    report.log("ERROR", "This usually means the decompiler binary is missing or has wrong permissions")
    report.log("ERROR", "Fix: docker exec -u root ghidra-headless chmod +rx /opt/ghidra/Ghidra/Features/Decompiler/os/linux_x86_64/decompile")
report.log("DEBUG", "DecompInterface initialized (openProgram=%s)" % open_ok)

fm = program.getFunctionManager()
total_functions = fm.getFunctionCount()
functions = fm.getFunctions(True)

report.log("INFO", "Total functions to decompile: %d" % total_functions)

lines = []
lines.append("=" * 60)
lines.append("Decompiled Output: %s" % name)
lines.append("Total functions: %d" % total_functions)
lines.append("=" * 60)

count = 0
errors = 0

for func in functions:
    if monitor.isCancelled():
        report.log("INFO", "Monitor cancelled, stopping decompilation")
        break

    func_name = func.getName()
    func_addr = func.getEntryPoint()
    report.log("DEBUG", "Decompiling function '%s' @ 0x%s" % (func_name, func_addr))

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
            report.log("DEBUG", "Successfully decompiled '%s'" % func_name)
        else:
            lines.append("// [ERROR] No C output available")
            errors += 1
            report.log("ERROR", "No C output for function '%s' @ 0x%s" % (func_name, func_addr))
    else:
        error_msg = results.getErrorMessage() if results else "Decompilation failed"
        lines.append("// [ERROR] %s" % error_msg)
        errors += 1
        report.log("ERROR", "Decompilation error for '%s' @ 0x%s: %s" % (func_name, func_addr, error_msg))

    # Early failure detection: if first 10 functions ALL fail, likely a systemic issue
    if (count + errors) == 10 and count == 0:
        report.log("CRITICAL", "First 10 functions ALL failed to decompile!")
        report.log("CRITICAL", "Likely cause: decompiler binary permission issue")
        report.log("CRITICAL", "Fix: docker exec -u root ghidra-headless chmod +rx /opt/ghidra/Ghidra/Features/Decompiler/os/linux_x86_64/decompile")
        report.log("CRITICAL", "Then re-run the analysis")

report.log("INFO", "Decompilation complete - success=%d, errors=%d, total=%d" % (count, errors, count + errors))

lines.append("")
lines.append("// " + "=" * 56)
lines.append("// Decompiled: %d functions, Errors: %d" % (count, errors))

report.log("DEBUG", "Disposing DecompInterface")
decomp.dispose()

output = "\n".join(lines)
print("[*] Decompiled %d functions (%d errors)" % (count, errors))

report.save_custom("decompiled.c", output + "\n")
report.log("INFO", "Script completed successfully")
