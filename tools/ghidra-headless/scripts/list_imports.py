# Ghidra Headless Script: list_imports.py
# Lists import table with suspicious API flagging for malware analysis
# @category Analysis
# @runtime Jython

from ghidra_common import GhidraReport

report = GhidraReport("list_imports.py", "imports", "Import Table", currentProgram)
program = report.program

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

report.log("DEBUG", "Loaded %d suspicious API patterns" % len(SUSPICIOUS_APIS))

fm = program.getFunctionManager()
ext_funcs = fm.getExternalFunctions()

report.add_blank()

# Group by library
imports = {}
suspicious_found = []

report.log("DEBUG", "Enumerating external functions")
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
        report.log("DEBUG", "Suspicious API found: [%s] %s" % (lib, fname))

report.log("INFO", "Found %d libraries with imports" % len(imports))

# Output grouped by library
for lib in sorted(imports.keys()):
    report.add("[%s]" % lib)
    for fname in sorted(imports[lib]):
        flag = " *** SUSPICIOUS ***" if any(f == fname for _, f in suspicious_found) else ""
        report.add("  %s%s" % (fname, flag))
    report.add_blank()

# Suspicious summary
if suspicious_found:
    report.add("=" * 60)
    report.add("!!! SUSPICIOUS API IMPORTS (%d) !!!" % len(suspicious_found))
    report.add("=" * 60)
    for lib, fname in sorted(suspicious_found):
        report.add("  [%s] %s" % (lib, fname))
    report.log("INFO", "%d suspicious APIs detected" % len(suspicious_found))
else:
    report.add("[*] No suspicious API imports detected.")
    report.log("INFO", "No suspicious APIs detected")

report.add_blank()
total = sum(len(v) for v in imports.values())
report.add("Total: %d imports from %d libraries" % (total, len(imports)))

print("[*] %d imports, %d suspicious" % (total, len(suspicious_found)))

report.save()
