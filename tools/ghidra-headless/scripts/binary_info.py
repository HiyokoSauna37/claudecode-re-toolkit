# Ghidra Headless Script: binary_info.py
# Outputs architecture, sections, entry point, and basic metadata
# @category Analysis
# @runtime Jython

from ghidra.program.model.mem import MemoryBlock
from ghidra_common import GhidraReport

report = GhidraReport("binary_info.py", "info", "Binary Info", currentProgram)
program = report.program

# Basic metadata
report.log("DEBUG", "Extracting basic metadata")
lang = program.getLanguage()
endian_str = "Big Endian" if lang.isBigEndian() else "Little Endian"
report.add("Format:         %s" % program.getExecutableFormat())
report.add("Architecture:   %s" % lang.getProcessor())
report.add("Endian:         %s" % endian_str)
report.add("Language ID:    %s" % lang.getLanguageID())
report.add("Address Size:   %d-bit" % lang.getDefaultSpace().getSize())
report.add("Compiler:       %s" % program.getCompilerSpec().getCompilerSpecID())
report.add("Image Base:     0x%s" % program.getImageBase())
report.log("DEBUG", "Metadata extracted - Format=%s, Arch=%s" % (program.getExecutableFormat(), lang.getProcessor()))

# Entry points
report.log("DEBUG", "Enumerating entry points")
entry_points = program.getSymbolTable().getExternalEntryPointIterator()
report.add_section("Entry Points")
count = 0
while entry_points.hasNext():
    addr = entry_points.next()
    func = program.getFunctionManager().getFunctionAt(addr)
    fname = func.getName() if func else "<unknown>"
    report.add("  0x%s  %s" % (addr, fname))
    count += 1
    if count > 20:
        report.add("  ... (truncated, >20 entry points)")
        report.log("DEBUG", "Entry points truncated at >20")
        break
report.log("INFO", "Found %d entry points" % count)

# Memory sections
report.log("DEBUG", "Enumerating memory sections")
report.add_section("Sections")
report.add("%-20s %-14s %-10s %-6s %-6s %-6s" % ("Name", "Address", "Size", "R", "W", "X"))
report.add("-" * 70)
memory = program.getMemory()
section_count = 0
for block in memory.getBlocks():
    report.add("%-20s 0x%-12s %-10d %-6s %-6s %-6s" % (
        block.getName(),
        block.getStart(),
        block.getSize(),
        "Y" if block.isRead() else "N",
        "Y" if block.isWrite() else "N",
        "Y" if block.isExecute() else "N"
    ))
    section_count += 1
report.log("INFO", "Found %d memory sections" % section_count)

# Function count
fm = program.getFunctionManager()
func_count = fm.getFunctionCount()
report.add_blank()
report.add("Total Functions: %d" % func_count)
report.log("INFO", "Total functions: %d" % func_count)

report.save()
