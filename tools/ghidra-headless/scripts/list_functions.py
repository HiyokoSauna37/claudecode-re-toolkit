# Ghidra Headless Script: list_functions.py
# Lists all functions with address, size, and calling convention
# @category Analysis
# @runtime Jython

from ghidra_common import GhidraReport

report = GhidraReport("list_functions.py", "functions", "Function List", currentProgram)
program = report.program

fm = program.getFunctionManager()
total_functions = fm.getFunctionCount()
functions = fm.getFunctions(True)

report.log("INFO", "Total functions to enumerate: %d" % total_functions)

report.add_blank()
report.add("%-14s %-8s %-12s %s" % ("Address", "Size", "Convention", "Name"))
report.add("-" * 70)

count = 0
thunk_count = 0
extern_count = 0

report.log("DEBUG", "Iterating over functions")
for func in functions:
    addr = func.getEntryPoint()
    size = func.getBody().getNumAddresses()
    cc = func.getCallingConventionName() or "unknown"
    fname = func.getName()

    # Flag thunks and external
    tags = []
    if func.isThunk():
        tags.append("THUNK")
        thunk_count += 1
    if func.isExternal():
        tags.append("EXTERN")
        extern_count += 1

    tag_str = " [%s]" % ",".join(tags) if tags else ""
    report.add("0x%-12s %-8d %-12s %s%s" % (addr, size, cc, fname, tag_str))
    count += 1

report.log("INFO", "Enumerated %d functions (thunks=%d, external=%d)" % (count, thunk_count, extern_count))

report.add_blank()
report.add("Total: %d functions" % count)

report.save()
