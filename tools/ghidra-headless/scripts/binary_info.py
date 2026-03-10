# Ghidra Headless Script: binary_info.py
# Outputs architecture, sections, entry point, and basic metadata
# @category Analysis
# @runtime Jython

import os
import codecs
from ghidra.program.model.mem import MemoryBlock

print("[INFO] binary_info.py: Script started")

program = currentProgram
name = program.getName()
output_dir = "/analysis/output"

print("[INFO] binary_info.py: Processing program='%s', output_dir='%s'" % (name, output_dir))

lines = []
lines.append("=" * 60)
lines.append("Binary Info: %s" % name)
lines.append("=" * 60)

# Basic metadata
print("[DEBUG] binary_info.py: Extracting basic metadata")
lang = program.getLanguage()
lines.append("Format:         %s" % program.getExecutableFormat())
lines.append("Architecture:   %s" % lang.getProcessor())
lines.append("Endian:         %s" % lang.isBigEndian() and "Big" or "Little")
lines.append("Address Size:   %d-bit" % lang.getDefaultSpace().getSize())
lines.append("Compiler:       %s" % program.getCompilerSpec().getCompilerSpecID())
lines.append("Image Base:     0x%s" % program.getImageBase())
print("[DEBUG] binary_info.py: Metadata extracted - Format=%s, Arch=%s" % (program.getExecutableFormat(), lang.getProcessor()))

# Entry points
print("[DEBUG] binary_info.py: Enumerating entry points")
entry_points = program.getSymbolTable().getExternalEntryPointIterator()
lines.append("")
lines.append("--- Entry Points ---")
count = 0
while entry_points.hasNext():
    addr = entry_points.next()
    func = program.getFunctionManager().getFunctionAt(addr)
    fname = func.getName() if func else "<unknown>"
    lines.append("  0x%s  %s" % (addr, fname))
    count += 1
    if count > 20:
        lines.append("  ... (truncated, >20 entry points)")
        print("[DEBUG] binary_info.py: Entry points truncated at >20")
        break
print("[INFO] binary_info.py: Found %d entry points" % count)

# Memory sections
print("[DEBUG] binary_info.py: Enumerating memory sections")
lines.append("")
lines.append("--- Sections ---")
lines.append("%-20s %-14s %-10s %-6s %-6s %-6s" % ("Name", "Address", "Size", "R", "W", "X"))
lines.append("-" * 70)
memory = program.getMemory()
section_count = 0
for block in memory.getBlocks():
    lines.append("%-20s 0x%-12s %-10d %-6s %-6s %-6s" % (
        block.getName(),
        block.getStart(),
        block.getSize(),
        "Y" if block.isRead() else "N",
        "Y" if block.isWrite() else "N",
        "Y" if block.isExecute() else "N"
    ))
    section_count += 1
print("[INFO] binary_info.py: Found %d memory sections" % section_count)

# Function count
fm = program.getFunctionManager()
func_count = fm.getFunctionCount()
lines.append("")
lines.append("Total Functions: %d" % func_count)
print("[INFO] binary_info.py: Total functions: %d" % func_count)

output = "\n".join(lines)
print(output)

outfile = os.path.join(output_dir, "%s_info.txt" % name)
print("[DEBUG] binary_info.py: Writing output to '%s'" % outfile)
try:
    with codecs.open(outfile, "w", encoding="utf-8") as f:
        f.write(output + "\n")
    print("\n[*] Saved to %s" % outfile)
    print("[INFO] binary_info.py: Script completed successfully")
except Exception as e:
    print("[ERROR] binary_info.py: Failed to write output file '%s': %s" % (outfile, str(e)))
