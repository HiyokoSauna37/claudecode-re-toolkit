# Ghidra Headless Script: xrefs_report.py
# Generates cross-reference report for all functions
# @category Analysis
# @runtime Jython

from ghidra_common import GhidraReport

report = GhidraReport("xrefs_report.py", "xrefs", "Cross-Reference Report", currentProgram)
program = report.program

fm = program.getFunctionManager()
ref_mgr = program.getReferenceManager()
total_functions = fm.getFunctionCount()
functions = fm.getFunctions(True)

report.log("INFO", "Total functions to analyze: %d" % total_functions)

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
        report.log("DEBUG", "Analyzed %d / %d functions" % (analyzed_count, total_functions))

report.log("INFO", "Call graph analysis complete - %d functions analyzed" % analyzed_count)

# Output: functions sorted by number of callers (most-called first)
sorted_funcs = sorted(call_graph.items(), key=lambda x: len(x[1]["callers"]), reverse=True)

# High-value targets (many callers)
report.add_section("Most Called Functions (top 30)")
report.add("%-8s %-8s %-14s %s" % ("Callers", "Callees", "Address", "Function"))
report.add("-" * 60)
for fname, data in sorted_funcs[:30]:
    report.add("%-8d %-8d 0x%-12s %s" % (
        len(data["callers"]), len(data["callees"]), data["addr"], fname
    ))

if sorted_funcs:
    top_fname, top_data = sorted_funcs[0]
    report.log("INFO", "Most-called function: '%s' with %d callers" % (top_fname, len(top_data["callers"])))

# Leaf functions (no callees - potential utility/crypto)
report.add_section("Leaf Functions (no callees, potential crypto/utility)")
leaves = [(f, d) for f, d in sorted_funcs if len(d["callees"]) == 0 and not f.startswith("FUN_")]
report.log("INFO", "Found %d named leaf functions" % len(leaves))
for fname, data in leaves[:20]:
    report.add("  0x%-12s %s  (called by %d)" % (data["addr"], fname, len(data["callers"])))
if len(leaves) > 20:
    report.add("  ... +%d more" % (len(leaves) - 20))

# Count isolated nodes
isolated_count = 0

# Full call graph detail
report.add_section("Full Call Graph")
for fname, data in sorted_funcs:
    if len(data["callers"]) == 0 and len(data["callees"]) == 0:
        isolated_count += 1
        continue  # Skip isolated nodes
    report.add_blank()
    report.add("[%s] @ 0x%s" % (fname, data["addr"]))
    if data["callers"]:
        report.add("  Called by: %s" % ", ".join(data["callers"][:10]))
        if len(data["callers"]) > 10:
            report.add("            ... +%d more" % (len(data["callers"]) - 10))
    if data["callees"]:
        report.add("  Calls:    %s" % ", ".join(data["callees"][:10]))
        if len(data["callees"]) > 10:
            report.add("            ... +%d more" % (len(data["callees"]) - 10))

report.log("DEBUG", "Skipped %d isolated nodes (no callers, no callees)" % isolated_count)

report.add_blank()
report.add("Total: %d functions analyzed" % len(call_graph))

print("[*] Analyzed %d functions" % len(call_graph))

report.save()
