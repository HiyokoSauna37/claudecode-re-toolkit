# Ghidra Headless Script: list_exports.py
# Lists export table entries
# @category Analysis
# @runtime Jython

from ghidra_common import GhidraReport

report = GhidraReport("list_exports.py", "exports", "Export Table", currentProgram)
program = report.program

sym_table = program.getSymbolTable()
entry_points = sym_table.getExternalEntryPointIterator()

report.add_blank()
report.add("%-14s %-8s %s" % ("Address", "Type", "Name"))
report.add("-" * 50)

count = 0
func_count = 0
data_count = 0

report.log("DEBUG", "Enumerating export entry points")
for addr in entry_points:
    func = program.getFunctionManager().getFunctionAt(addr)
    if func:
        fname = func.getName()
        ftype = "FUNC"
        func_count += 1
    else:
        symbols = sym_table.getSymbols(addr)
        fname = symbols[0].getName() if symbols else "<unknown>"
        ftype = "DATA"
        data_count += 1

    report.add("0x%-12s %-8s %s" % (addr, ftype, fname))
    count += 1

report.log("INFO", "Found %d exports (FUNC=%d, DATA=%d)" % (count, func_count, data_count))

report.add_blank()
report.add("Total: %d exports" % count)

report.save()
