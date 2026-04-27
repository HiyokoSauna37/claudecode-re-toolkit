# Ghidra Headless Script: extract_strings.py
# Extracts defined strings with cross-references
# @category Analysis
# @runtime Jython

from ghidra.program.model.data import StringDataInstance
from ghidra_common import GhidraReport

report = GhidraReport("extract_strings.py", "strings", "Strings", currentProgram)
program = report.program

listing = program.getListing()
memory = program.getMemory()
ref_mgr = program.getReferenceManager()

report.add_blank()

count = 0
skipped_null = 0
skipped_short = 0

report.log("DEBUG", "Iterating over defined data for strings")
data_iter = listing.getDefinedData(True)
for data in data_iter:
    sdi = StringDataInstance.getStringDataInstance(data)
    if sdi is None or sdi.getStringLength() <= 0:
        skipped_null += 1
        continue

    string_val = sdi.getStringValue()
    if string_val is None or len(string_val) < 2:
        skipped_short += 1
        continue

    addr = data.getAddress()

    # Get cross-references to this string
    refs = ref_mgr.getReferencesTo(addr)
    xref_addrs = []
    for ref in refs:
        from_addr = ref.getFromAddress()
        func = program.getFunctionManager().getFunctionContaining(from_addr)
        if func:
            xref_addrs.append("0x%s (%s)" % (from_addr, func.getName()))
        else:
            xref_addrs.append("0x%s" % from_addr)

    # Truncate very long strings
    display_str = string_val
    if len(display_str) > 120:
        display_str = display_str[:120] + "..."

    # Escape control characters for display
    display_str = display_str.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")

    report.add("0x%-12s  \"%s\"" % (addr, display_str))
    if xref_addrs:
        for xref in xref_addrs[:5]:
            report.add("               <- %s" % xref)
        if len(xref_addrs) > 5:
            report.add("               <- ... +%d more refs" % (len(xref_addrs) - 5))
    report.add_blank()
    count += 1

report.log("INFO", "Extracted %d strings (skipped: %d null/empty, %d too short)" % (count, skipped_null, skipped_short))

report.add("Total: %d strings" % count)

print("[*] Extracted %d strings" % count)

report.save()
