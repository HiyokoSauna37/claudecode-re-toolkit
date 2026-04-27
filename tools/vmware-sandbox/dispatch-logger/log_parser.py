#!/usr/bin/env python3
"""
dispatch_log_parser.py - IDispatch Log Post-Processor
Reconstructs script COM calls from DispatchLogger proxy logs.

Port of Form1.frm / ProxyInfo.cls (VB6) by David Zimmer <dzzie@yahoo.com>
Copyright: Cisco Talos 2025 / License: Apache 2.0

Usage:
    python dispatch_log_parser.py <logfile>
    python dispatch_log_parser.py -          # read from stdin
    cat sample_log.txt | python dispatch_log_parser.py
"""

import sys
import re


# ---------------------------------------------------------------------------
# Proxy tracker (equivalent to ProxyInfo class + Proxies collection)
# ---------------------------------------------------------------------------
class ProxyInfo:
    def __init__(self, proxy_id, object_name):
        self.proxy_id    = proxy_id
        self.object_name = object_name


# ---------------------------------------------------------------------------
# Noise filters - lines we skip entirely
# ---------------------------------------------------------------------------
SKIP_PATTERNS = (
    "[INIT]",
    "[SHUTDOWN]",
    "[HOOK]",
    "AddRef:",
    "Release:",
    "QueryInterface:",
    "GetTypeInfo:",
    "[WRAP]",
    "GetIDsOfNames:",       # handled implicitly via Invoke
    "========",
    "[FACTORY]",            # factory bookkeeping noise
    "[CoGetClassObject]",
)


def should_skip(line):
    for pat in SKIP_PATTERNS:
        if pat in line:
            return True
    return False


# ---------------------------------------------------------------------------
# Per-line processors
# ---------------------------------------------------------------------------
def process_clsid_from_progid(line, output):
    """[CLSIDFromProgID] 'Scripting.FileSystemObject' -> {GUID}"""
    m = re.search(r"'([^']+)'", line)
    if m:
        output.append(f'CreateObject("{m.group(1)}")')


def process_proxy_creation(line, proxies):
    """[PROXY] Created proxy #1 for FileSystemObject (Original: 0x...)"""
    m = re.search(r"proxy #(\d+) for (\S+)", line)
    if m:
        pid  = m.group(1)
        name = m.group(2)
        proxies[pid] = ProxyInfo(pid, name)


def process_method_call(lines, idx, output):
    """
    [PROXY #1] >>> Invoke: FileSystemObject.GetSpecialFolder (METHOD PROPGET ) ArgCount=1
        Arg[0]: 2
    [PROXY #1] <<< Result: IDispatch:0x... (HRESULT=0x00000000)
    Returns the new index after consuming result line.
    """
    line = lines[idx]

    # Extract Object.Method
    m = re.search(r"Invoke:\s+(\S+)\s+\(", line)
    if not m:
        return idx
    object_method = m.group(1)

    # Call type flags
    is_prop_get = "PROPGET" in line
    is_prop_put = "PROPPUT" in line
    is_method   = "METHOD"  in line and not is_prop_get

    # Collect Arg lines
    args = []
    i = idx + 1
    while i < len(lines):
        al = lines[i].strip()
        if "Arg[" in al:
            cm = re.search(r"Arg\[\d+\]:\s+(.*)", al)
            if cm:
                args.append(cm.group(1).strip())
            i += 1
        else:
            break

    # Find result line
    result = ""
    while i < len(lines):
        rl = lines[i].strip()
        if "<<< Result:" in rl:
            rm = re.search(r"<<< Result:\s+(.*?)\s+\(HRESULT", rl)
            if rm:
                result = rm.group(1).strip()
            i += 1
            break
        # Stop scanning if we hit the next Invoke or something unrelated
        if ">>> Invoke:" in rl or should_skip(rl):
            break
        i += 1

    # Build the output expression
    if is_prop_put:
        val = args[-1] if args else ""
        expr = f"{object_method} = {val}"
    elif is_prop_get:
        if args:
            expr = f"{object_method}({', '.join(args)})"
        else:
            expr = object_method
        if result and result != "(void)":
            expr += f"  ' Returns: {result}"
    else:
        expr = f"{object_method}({', '.join(args)})"
        if result and result != "(void)":
            expr += f"  ' Returns: {result}"

    output.append(clean_output(expr))
    return i - 1   # caller will +1 on next iteration


# ---------------------------------------------------------------------------
# Output cleanup (mirrors CleanOutput() in VB6)
# ---------------------------------------------------------------------------
REPLACEMENTS = [
    ("IDispatch:",                           "Object:"),
    ("FileSystemObject.GetSpecialFolder.",   ""),
    ("FileSystemObject.",                    "fso."),
    ("WScript.Shell.",                       "shell."),
    ("Scripting.Dictionary.",                "dict."),
    ("GetSpecialFolder(2)",                  "GetSpecialFolder(TemporaryFolder)"),
]

def clean_output(text):
    for old, new in REPLACEMENTS:
        text = text.replace(old, new)
    return text


# ---------------------------------------------------------------------------
# Main log processor
# ---------------------------------------------------------------------------
def process_log(log_text):
    proxies = {}
    output  = []

    lines = log_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()

        if not line or should_skip(line):
            i += 1
            continue

        if "[CLSIDFromProgID]" in line:
            process_clsid_from_progid(line, output)

        elif "[PROXY] Created proxy" in line:
            process_proxy_creation(line, proxies)

        elif ">>> Invoke:" in line:
            i = process_method_call(lines, i, output)

        i += 1

    return output


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    src = sys.argv[1]
    if src == "-":
        log_text = sys.stdin.read()
    else:
        try:
            with open(src, "r", encoding="utf-8", errors="replace") as fh:
                log_text = fh.read()
        except FileNotFoundError:
            print(f"Error: file not found: {src}", file=sys.stderr)
            sys.exit(1)

    results = process_log(log_text)

    if not results:
        print("(no COM activity reconstructed)")
    else:
        for line in results:
            print(line)


if __name__ == "__main__":
    main()
