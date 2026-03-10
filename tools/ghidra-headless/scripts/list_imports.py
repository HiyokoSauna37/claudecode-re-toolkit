# Ghidra Headless Script: list_imports.py
# Lists import table with suspicious API flagging for malware analysis
# @category Analysis
# @runtime Jython

import os
import codecs

print("[INFO] list_imports.py: Script started")

program = currentProgram
name = program.getName()
output_dir = "/analysis/output"

print("[INFO] list_imports.py: Processing program='%s', output_dir='%s'" % (name, output_dir))

# Suspicious Windows API patterns for malware triage
SUSPICIOUS_APIS = set([
    # Process injection
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
    "CreateRemoteThreadEx", "NtCreateThreadEx", "RtlCreateUserThread",
    "QueueUserAPC", "NtQueueApcThread", "SetThreadContext",
    "NtMapViewOfSection", "NtUnmapViewOfSection",
    # Process/thread manipulation
    "OpenProcess", "OpenThread", "CreateProcess", "CreateProcessA", "CreateProcessW",
    "CreateProcessAsUser", "CreateProcessWithLogon", "CreateProcessWithToken",
    "WinExec", "ShellExecute", "ShellExecuteA", "ShellExecuteW", "ShellExecuteEx",
    # Memory
    "HeapCreate", "RtlAllocateHeap", "NtAllocateVirtualMemory",
    # DLL injection
    "LoadLibrary", "LoadLibraryA", "LoadLibraryW", "LoadLibraryEx",
    "GetProcAddress", "LdrLoadDll",
    # Registry
    "RegCreateKey", "RegSetValue", "RegSetValueEx",
    "RegCreateKeyA", "RegCreateKeyW", "RegSetValueExA", "RegSetValueExW",
    # File system
    "CreateFile", "CreateFileA", "CreateFileW", "DeleteFile", "MoveFile",
    "WriteFile", "ReadFile", "CopyFile",
    # Network
    "InternetOpen", "InternetOpenUrl", "InternetConnect", "HttpOpenRequest",
    "HttpSendRequest", "URLDownloadToFile", "URLDownloadToFileA", "URLDownloadToFileW",
    "WSAStartup", "connect", "send", "recv", "socket",
    "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
    # Crypto
    "CryptEncrypt", "CryptDecrypt", "CryptCreateHash", "CryptHashData",
    "CryptDeriveKey", "CryptGenKey", "CryptAcquireContext",
    # Anti-debug / evasion
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "GetTickCount", "QueryPerformanceCounter", "Sleep", "SleepEx",
    "NtDelayExecution", "SetUnhandledExceptionFilter",
    # Privilege
    "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValue",
    # Service
    "CreateService", "CreateServiceA", "CreateServiceW",
    "StartService", "ControlService", "OpenSCManager",
])

print("[DEBUG] list_imports.py: Loaded %d suspicious API patterns" % len(SUSPICIOUS_APIS))

fm = program.getFunctionManager()
ext_funcs = fm.getExternalFunctions()

lines = []
lines.append("=" * 60)
lines.append("Import Table: %s" % name)
lines.append("=" * 60)
lines.append("")

# Group by library
imports = {}
suspicious_found = []

print("[DEBUG] list_imports.py: Enumerating external functions")
for func in ext_funcs:
    ext_loc = func.getExternalLocation()
    lib = ext_loc.getLibraryName() or "<unknown>"
    fname = func.getName()

    if lib not in imports:
        imports[lib] = []
    imports[lib].append(fname)

    # Check suspicious
    base_name = fname.rstrip("AW")  # Strip A/W suffix for matching
    if fname in SUSPICIOUS_APIS or base_name in SUSPICIOUS_APIS:
        suspicious_found.append((lib, fname))
        print("[DEBUG] list_imports.py: Suspicious API found: [%s] %s" % (lib, fname))

print("[INFO] list_imports.py: Found %d libraries with imports" % len(imports))

# Output grouped by library
for lib in sorted(imports.keys()):
    lines.append("[%s]" % lib)
    for fname in sorted(imports[lib]):
        flag = " *** SUSPICIOUS ***" if any(f == fname for _, f in suspicious_found) else ""
        lines.append("  %s%s" % (fname, flag))
    lines.append("")

# Suspicious summary
if suspicious_found:
    lines.append("=" * 60)
    lines.append("!!! SUSPICIOUS API IMPORTS (%d) !!!" % len(suspicious_found))
    lines.append("=" * 60)
    for lib, fname in sorted(suspicious_found):
        lines.append("  [%s] %s" % (lib, fname))
    print("[INFO] list_imports.py: %d suspicious APIs detected" % len(suspicious_found))
else:
    lines.append("[*] No suspicious API imports detected.")
    print("[INFO] list_imports.py: No suspicious APIs detected")

lines.append("")
total = sum(len(v) for v in imports.values())
lines.append("Total: %d imports from %d libraries" % (total, len(imports)))

output = "\n".join(lines)
print("[*] %d imports, %d suspicious" % (total, len(suspicious_found)))

outfile = os.path.join(output_dir, "%s_imports.txt" % name)
print("[DEBUG] list_imports.py: Writing output to '%s'" % outfile)
try:
    with codecs.open(outfile, "w", encoding="utf-8") as f:
        f.write(output + "\n")
    print("[*] Saved to %s" % outfile)
    print("[INFO] list_imports.py: Script completed successfully")
except Exception as e:
    print("[ERROR] list_imports.py: Failed to write output file '%s': %s" % (outfile, str(e)))
