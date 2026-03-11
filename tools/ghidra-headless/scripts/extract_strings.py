# Ghidra Headless Script: extract_strings.py
# Extracts defined strings with cross-references
# @category Analysis
# @runtime Jython

import os
import codecs
from ghidra.program.model.data import StringDataInstance

print("[INFO] extract_strings.py: Script started")

program = currentProgram
name = program.getName()
output_dir = "/analysis/output"

print("[INFO] extract_strings.py: Processing program='%s', output_dir='%s'" % (name, output_dir))

listing = program.getListing()
memory = program.getMemory()
ref_mgr = program.getReferenceManager()

lines = []
lines.append("=" * 60)
lines.append("Strings: %s" % name)
lines.append("=" * 60)
lines.append("")

count = 0
skipped_null = 0
skipped_short = 0

print("[DEBUG] extract_strings.py: Iterating over defined data for strings")
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

    lines.append("0x%-12s  \"%s\"" % (addr, display_str))
    if xref_addrs:
        for xref in xref_addrs[:5]:
            lines.append("               <- %s" % xref)
        if len(xref_addrs) > 5:
            lines.append("               <- ... +%d more refs" % (len(xref_addrs) - 5))
    lines.append("")
    count += 1

print("[INFO] extract_strings.py: Extracted %d strings (skipped: %d null/empty, %d too short)" % (count, skipped_null, skipped_short))

lines.append("Total: %d strings" % count)

output = "\n".join(lines)
print("[*] Extracted %d strings" % count)

outfile = os.path.join(output_dir, "%s_strings.txt" % name)
print("[DEBUG] extract_strings.py: Writing output to '%s'" % outfile)
try:
    with codecs.open(outfile, "w", encoding="utf-8") as f:
        f.write(output + "\n")
    print("[*] Saved to %s" % outfile)
    print("[INFO] extract_strings.py: Script completed successfully")
except Exception as e:
    print("[ERROR] extract_strings.py: Failed to write output file '%s': %s" % (outfile, str(e)))
