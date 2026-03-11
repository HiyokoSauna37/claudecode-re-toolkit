# Ghidra Headless Script: list_exports.py
# Lists export table entries
# @category Analysis
# @runtime Jython

import os
import codecs

print("[INFO] list_exports.py: Script started")

program = currentProgram
name = program.getName()
output_dir = "/analysis/output"

print("[INFO] list_exports.py: Processing program='%s', output_dir='%s'" % (name, output_dir))

sym_table = program.getSymbolTable()
entry_points = sym_table.getExternalEntryPointIterator()

lines = []
lines.append("=" * 60)
lines.append("Export Table: %s" % name)
lines.append("=" * 60)
lines.append("")
lines.append("%-14s %-8s %s" % ("Address", "Type", "Name"))
lines.append("-" * 50)

count = 0
func_count = 0
data_count = 0

print("[DEBUG] list_exports.py: Enumerating export entry points")
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

    lines.append("0x%-12s %-8s %s" % (addr, ftype, fname))
    count += 1

print("[INFO] list_exports.py: Found %d exports (FUNC=%d, DATA=%d)" % (count, func_count, data_count))

lines.append("")
lines.append("Total: %d exports" % count)

output = "\n".join(lines)
print(output)

outfile = os.path.join(output_dir, "%s_exports.txt" % name)
print("[DEBUG] list_exports.py: Writing output to '%s'" % outfile)
try:
    with codecs.open(outfile, "w", encoding="utf-8") as f:
        f.write(output + "\n")
    print("\n[*] Saved to %s" % outfile)
    print("[INFO] list_exports.py: Script completed successfully")
except Exception as e:
    print("[ERROR] list_exports.py: Failed to write output file '%s': %s" % (outfile, str(e)))
