# Ghidra Headless Script: list_functions.py
# Lists all functions with address, size, and calling convention
# @category Analysis
# @runtime Jython

import os
import codecs

print("[INFO] list_functions.py: Script started")

program = currentProgram
name = program.getName()
output_dir = "/analysis/output"

print("[INFO] list_functions.py: Processing program='%s', output_dir='%s'" % (name, output_dir))

fm = program.getFunctionManager()
total_functions = fm.getFunctionCount()
functions = fm.getFunctions(True)

print("[INFO] list_functions.py: Total functions to enumerate: %d" % total_functions)

lines = []
lines.append("=" * 60)
lines.append("Function List: %s" % name)
lines.append("=" * 60)
lines.append("")
lines.append("%-14s %-8s %-12s %s" % ("Address", "Size", "Convention", "Name"))
lines.append("-" * 70)

count = 0
thunk_count = 0
extern_count = 0

print("[DEBUG] list_functions.py: Iterating over functions")
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
    lines.append("0x%-12s %-8d %-12s %s%s" % (addr, size, cc, fname, tag_str))
    count += 1

print("[INFO] list_functions.py: Enumerated %d functions (thunks=%d, external=%d)" % (count, thunk_count, extern_count))

lines.append("")
lines.append("Total: %d functions" % count)

output = "\n".join(lines)
print(output)

outfile = os.path.join(output_dir, "%s_functions.txt" % name)
print("[DEBUG] list_functions.py: Writing output to '%s'" % outfile)
try:
    with codecs.open(outfile, "w", encoding="utf-8") as f:
        f.write(output + "\n")
    print("\n[*] Saved to %s" % outfile)
    print("[INFO] list_functions.py: Script completed successfully")
except Exception as e:
    print("[ERROR] list_functions.py: Failed to write output file '%s': %s" % (outfile, str(e)))
