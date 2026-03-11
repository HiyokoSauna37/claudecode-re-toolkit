# Ghidra Headless Script: xrefs_report.py
# Generates cross-reference report for all functions
# @category Analysis
# @runtime Jython

import os
import codecs

print("[INFO] xrefs_report.py: Script started")

program = currentProgram
name = program.getName()
output_dir = "/analysis/output"

print("[INFO] xrefs_report.py: Processing program='%s', output_dir='%s'" % (name, output_dir))

fm = program.getFunctionManager()
ref_mgr = program.getReferenceManager()
total_functions = fm.getFunctionCount()
functions = fm.getFunctions(True)

print("[INFO] xrefs_report.py: Total functions to analyze: %d" % total_functions)

lines = []
lines.append("=" * 60)
lines.append("Cross-Reference Report: %s" % name)
lines.append("=" * 60)

# Collect call graph data
call_graph = {}  # func -> {"callers": [], "callees": []}

analyzed_count = 0
for func in functions:
    fname = func.getName()
    entry = func.getEntryPoint()

    callers = []
    callees = []

    # Find who calls this function (references TO entry point)
    refs_to = ref_mgr.getReferencesTo(entry)
    for ref in refs_to:
        if ref.getReferenceType().isCall():
            caller_func = fm.getFunctionContaining(ref.getFromAddress())
            if caller_func:
                callers.append(caller_func.getName())

    # Find what this function calls (references FROM this function's body)
    addr_set = func.getBody()
    addr_iter = addr_set.getAddresses(True)
    seen_callees = set()
    for addr in addr_iter:
        refs_from = ref_mgr.getReferencesFrom(addr)
        for ref in refs_from:
            if ref.getReferenceType().isCall():
                callee_func = fm.getFunctionAt(ref.getToAddress())
                if callee_func and callee_func.getName() not in seen_callees:
                    callees.append(callee_func.getName())
                    seen_callees.add(callee_func.getName())

    call_graph[fname] = {"callers": callers, "callees": callees, "addr": str(entry)}
    analyzed_count += 1

    if analyzed_count % 500 == 0:
        print("[DEBUG] xrefs_report.py: Analyzed %d / %d functions" % (analyzed_count, total_functions))

print("[INFO] xrefs_report.py: Call graph analysis complete - %d functions analyzed" % analyzed_count)

# Output: functions sorted by number of callers (most-called first)
sorted_funcs = sorted(call_graph.items(), key=lambda x: len(x[1]["callers"]), reverse=True)

# High-value targets (many callers)
lines.append("")
lines.append("--- Most Called Functions (top 30) ---")
lines.append("%-8s %-8s %-14s %s" % ("Callers", "Callees", "Address", "Function"))
lines.append("-" * 60)
for fname, data in sorted_funcs[:30]:
    lines.append("%-8d %-8d 0x%-12s %s" % (
        len(data["callers"]), len(data["callees"]), data["addr"], fname
    ))

if sorted_funcs:
    top_fname, top_data = sorted_funcs[0]
    print("[INFO] xrefs_report.py: Most-called function: '%s' with %d callers" % (top_fname, len(top_data["callers"])))

# Leaf functions (no callees - potential utility/crypto)
lines.append("")
lines.append("--- Leaf Functions (no callees, potential crypto/utility) ---")
leaves = [(f, d) for f, d in sorted_funcs if len(d["callees"]) == 0 and not f.startswith("FUN_")]
print("[INFO] xrefs_report.py: Found %d named leaf functions" % len(leaves))
for fname, data in leaves[:20]:
    lines.append("  0x%-12s %s  (called by %d)" % (data["addr"], fname, len(data["callers"])))
if len(leaves) > 20:
    lines.append("  ... +%d more" % (len(leaves) - 20))

# Count isolated nodes
isolated_count = 0

# Full call graph detail
lines.append("")
lines.append("--- Full Call Graph ---")
for fname, data in sorted_funcs:
    if len(data["callers"]) == 0 and len(data["callees"]) == 0:
        isolated_count += 1
        continue  # Skip isolated nodes
    lines.append("")
    lines.append("[%s] @ 0x%s" % (fname, data["addr"]))
    if data["callers"]:
        lines.append("  Called by: %s" % ", ".join(data["callers"][:10]))
        if len(data["callers"]) > 10:
            lines.append("            ... +%d more" % (len(data["callers"]) - 10))
    if data["callees"]:
        lines.append("  Calls:    %s" % ", ".join(data["callees"][:10]))
        if len(data["callees"]) > 10:
            lines.append("            ... +%d more" % (len(data["callees"]) - 10))

print("[DEBUG] xrefs_report.py: Skipped %d isolated nodes (no callers, no callees)" % isolated_count)

lines.append("")
lines.append("Total: %d functions analyzed" % len(call_graph))

output = "\n".join(lines)
print("[*] Analyzed %d functions" % len(call_graph))

outfile = os.path.join(output_dir, "%s_xrefs.txt" % name)
print("[DEBUG] xrefs_report.py: Writing output to '%s'" % outfile)
try:
    with codecs.open(outfile, "w", encoding="utf-8") as f:
        f.write(output + "\n")
    print("[*] Saved to %s" % outfile)
    print("[INFO] xrefs_report.py: Script completed successfully")
except Exception as e:
    print("[ERROR] xrefs_report.py: Failed to write output file '%s': %s" % (outfile, str(e)))
