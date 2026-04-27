"""
PE Triage Script (Phase 0)
Ghidra解析の前段で実行する高速トリアージ。
pefile + Detect It Easy (DiE) CLI でファイル種別・パッカー・エントロピー・anomalyを判定。

Usage:
    python tools/ghidra-headless/pe_triage.py <binary_path> [--json]

Requirements:
    - pefile (pip install pefile)
    - diec (optional): Detect It Easy CLI for packer detection
      Install: choco install die  OR  https://github.com/horsicq/Detect-It-Easy/releases
"""

import sys
import json
import math
import struct
import hashlib
import argparse
import shutil
import subprocess
from pathlib import Path
from datetime import datetime, timezone


def calc_entropy(data: bytes) -> float:
    """Shannon entropy (0-8 bits per byte)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def file_hashes(filepath: Path) -> dict:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def run_die(filepath: str) -> list[dict] | None:
    """Run Detect It Easy CLI (diec) if available."""
    diec = shutil.which("diec")
    if not diec:
        return None
    try:
        r = subprocess.run(
            [diec, "-j", "-d", filepath],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode == 0 and r.stdout.strip():
            data = json.loads(r.stdout)
            detects = data.get("detects", [])
            results = []
            for det in detects:
                for v in det.get("values", []):
                    results.append({
                        "type": v.get("type", ""),
                        "name": v.get("name", ""),
                        "version": v.get("version", ""),
                        "info": v.get("info", ""),
                    })
            return results
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        pass
    return None


def analyze_pe(filepath: str) -> dict:
    import pefile

    binary = Path(filepath)
    result = {
        "file": binary.name,
        "path": str(binary),
        "size": binary.stat().st_size,
        "timestamp": datetime.now().isoformat(),
        "hashes": file_hashes(binary),
    }

    # Full file entropy
    raw = binary.read_bytes()
    result["file_entropy"] = calc_entropy(raw)

    try:
        pe = pefile.PE(str(binary))
    except pefile.PEFormatError as e:
        result["error"] = f"Not a valid PE: {e}"
        result["verdict"] = ["NOT_PE"]
        return result

    # Basic info
    result["machine"] = hex(pe.FILE_HEADER.Machine)
    machine_map = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64"}
    result["architecture"] = machine_map.get(pe.FILE_HEADER.Machine, "unknown")
    result["is_dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    result["is_exe"] = not result["is_dll"]

    # Compilation timestamp
    ts = pe.FILE_HEADER.TimeDateStamp
    try:
        result["compile_time"] = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (ValueError, OSError):
        result["compile_time"] = f"invalid ({hex(ts)})"

    # Entry point
    result["entrypoint"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    result["imagebase"] = hex(pe.OPTIONAL_HEADER.ImageBase)

    # Subsystem
    subsystem_map = {1: "Native", 2: "GUI", 3: "Console", 7: "POSIX", 14: "EFI"}
    result["subsystem"] = subsystem_map.get(pe.OPTIONAL_HEADER.Subsystem, str(pe.OPTIONAL_HEADER.Subsystem))

    # Sections
    sections = []
    anomalies = []
    for sec in pe.sections:
        name = sec.Name.decode("utf-8", errors="replace").rstrip("\x00")
        entropy = round(sec.get_entropy(), 3)
        sec_info = {
            "name": name,
            "virtual_size": sec.Misc_VirtualSize,
            "raw_size": sec.SizeOfRawData,
            "entropy": entropy,
            "characteristics": hex(sec.Characteristics),
            "readable": bool(sec.Characteristics & 0x40000000),
            "writable": bool(sec.Characteristics & 0x80000000),
            "executable": bool(sec.Characteristics & 0x20000000),
        }
        sections.append(sec_info)

        # Anomaly detection
        if sec_info["readable"] and sec_info["writable"] and sec_info["executable"]:
            anomalies.append(f"RWX section: {name} (self-modifying code / packer)")
        if entropy > 7.0:
            anomalies.append(f"High entropy section: {name} ({entropy}) - likely packed/encrypted")
        if sec.SizeOfRawData == 0 and sec.Misc_VirtualSize > 0:
            anomalies.append(f"Empty raw section: {name} (virtual={sec.Misc_VirtualSize}) - runtime unpacking")
        if sec.Misc_VirtualSize > 0 and sec.SizeOfRawData > 0:
            ratio = sec.Misc_VirtualSize / sec.SizeOfRawData
            if ratio > 10:
                anomalies.append(f"Virtual/Raw ratio {ratio:.1f}x in {name} - possible unpacking stub")

    result["sections"] = sections
    result["section_count"] = len(sections)

    # Imports
    imports = {}
    suspicious_apis = []
    suspicious_api_list = {
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "RtlCreateUserThread",
        "CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW",
        "WinExec", "CreateProcessInternalW",
        "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA", "InternetOpenW",
        "HttpSendRequestA", "HttpSendRequestW", "WinHttpOpen",
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "BCryptEncrypt",
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "GetTickCount", "QueryPerformanceCounter",
        "OpenProcess", "TerminateProcess", "NtUnmapViewOfSection",
        "SetWindowsHookExA", "SetWindowsHookExW",
        "AdjustTokenPrivileges", "LookupPrivilegeValueA",
        "CreateServiceA", "CreateServiceW",
        "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    }

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="replace")
            funcs = []
            for imp in entry.imports:
                fname = imp.name.decode("utf-8", errors="replace") if imp.name else f"ord_{imp.ordinal}"
                funcs.append(fname)
                if fname in suspicious_api_list:
                    suspicious_apis.append({"api": fname, "dll": dll_name})
            imports[dll_name] = funcs

    result["import_dll_count"] = len(imports)
    result["import_total_count"] = sum(len(v) for v in imports.values())
    result["suspicious_apis"] = suspicious_apis
    result["imports"] = {k: len(v) for k, v in imports.items()}  # DLL -> count

    # Low import count anomaly
    if len(imports) < 3 and not result["is_dll"]:
        anomalies.append(f"Very few imports ({len(imports)} DLLs) - dynamic API resolution likely")

    # Exports (for DLLs)
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode("utf-8", errors="replace") if exp.name else f"ord_{exp.ordinal}"
            exports.append(name)
    result["exports"] = exports
    result["export_count"] = len(exports)

    # Resources
    resource_anomalies = []
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(res_type, "directory"):
                for res_id in res_type.directory.entries:
                    if hasattr(res_id, "directory"):
                        for res_lang in res_id.directory.entries:
                            size = res_lang.data.struct.Size
                            if size > 100000:
                                resource_anomalies.append(
                                    f"Large resource: type={res_type.id} size={size} bytes"
                                )
    if resource_anomalies:
        anomalies.extend(resource_anomalies)

    # Overlay
    overlay_offset = pe.get_overlay_data_start_offset()
    if overlay_offset:
        overlay_size = result["size"] - overlay_offset
        result["overlay"] = {"offset": overlay_offset, "size": overlay_size}
        if overlay_size > 10000:
            anomalies.append(f"Overlay data: {overlay_size} bytes at offset {hex(overlay_offset)}")
    else:
        result["overlay"] = None

    # PE warnings from pefile
    pe_warnings = pe.get_warnings()
    if pe_warnings:
        for w in pe_warnings[:5]:
            anomalies.append(f"PE warning: {w}")

    result["anomalies"] = anomalies
    result["anomaly_count"] = len(anomalies)

    # Detect It Easy (optional)
    die_results = run_die(str(binary))
    result["die_detections"] = die_results

    # --- Verdict ---
    verdict = []
    if any("RWX" in a for a in anomalies):
        verdict.append("RWX_SECTION")
    if any("High entropy" in a for a in anomalies):
        verdict.append("HIGH_ENTROPY_PACKED")
    if any("Very few imports" in a for a in anomalies):
        verdict.append("LOW_IMPORTS_DYNAMIC_API")
    if result["file_entropy"] > 7.0:
        verdict.append("FILE_ENTROPY_HIGH")
    if len(suspicious_apis) > 5:
        verdict.append("MANY_SUSPICIOUS_APIS")
    if die_results:
        packer_names = [d["name"] for d in die_results if d["type"] in ("Packer", "Protector")]
        if packer_names:
            verdict.append(f"PACKER_DETECTED:{','.join(packer_names)}")
    if not verdict:
        verdict.append("CLEAN_TRIAGE")

    result["verdict"] = verdict

    pe.close()
    return result


def print_report(result: dict):
    v = result.get("verdict", [])
    print(f"\n{'='*60}")
    print(f"  PE Triage Report: {result['file']}")
    print(f"{'='*60}")

    if "error" in result:
        print(f"  Error: {result['error']}")
        print(f"{'='*60}\n")
        return

    print(f"  Arch        : {result.get('architecture', '?')}")
    print(f"  Type        : {'DLL' if result.get('is_dll') else 'EXE'}")
    print(f"  Subsystem   : {result.get('subsystem', '?')}")
    print(f"  Compile Time: {result.get('compile_time', '?')}")
    print(f"  Entrypoint  : {result.get('entrypoint', '?')}")
    print(f"  File Entropy: {result.get('file_entropy', '?')}")
    print(f"  Sections    : {result.get('section_count', 0)}")
    print(f"  Imports     : {result.get('import_dll_count', 0)} DLLs, {result.get('import_total_count', 0)} functions")
    print(f"  Exports     : {result.get('export_count', 0)}")
    print(f"  Suspicious APIs: {len(result.get('suspicious_apis', []))}")
    print(f"  Anomalies   : {result.get('anomaly_count', 0)}")
    print(f"  Verdict     : {', '.join(v)}")

    print(f"\n  SHA256: {result['hashes']['sha256']}")

    # DiE
    die = result.get("die_detections")
    if die:
        print(f"\n  --- Detect It Easy ---")
        for d in die:
            info = f" ({d['info']})" if d.get("info") else ""
            print(f"    [{d['type']}] {d['name']} {d.get('version', '')}{info}")
    elif die is None:
        print(f"\n  (diec not found - install for packer detection: choco install die)")

    # Sections
    print(f"\n  --- Sections ---")
    print(f"  {'Name':<10} {'VSize':>8} {'RSize':>8} {'Entropy':>8} {'Flags'}")
    for s in result.get("sections", []):
        flags = ""
        if s["readable"]: flags += "R"
        if s["writable"]: flags += "W"
        if s["executable"]: flags += "X"
        marker = " !!" if s["entropy"] > 7.0 or (s["readable"] and s["writable"] and s["executable"]) else ""
        print(f"  {s['name']:<10} {s['virtual_size']:>8} {s['raw_size']:>8} {s['entropy']:>8} {flags}{marker}")

    # Suspicious APIs
    apis = result.get("suspicious_apis", [])
    if apis:
        print(f"\n  --- Suspicious APIs ({len(apis)}) ---")
        for a in apis[:20]:
            print(f"    {a['dll']:.<30s} {a['api']}")

    # Anomalies
    anomalies = result.get("anomalies", [])
    if anomalies:
        print(f"\n  --- Anomalies ({len(anomalies)}) ---")
        for a in anomalies:
            print(f"    {a}")

    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(description="PE Triage (Phase 0)")
    parser.add_argument("binary", help="Path to PE binary")
    parser.add_argument("--json", action="store_true", help="JSON output to stdout")
    parser.add_argument("--output-dir", "-o", help="Output directory")
    args = parser.parse_args()

    binary = Path(args.binary)
    if not binary.exists():
        print(f"ERROR: File not found: {args.binary}")
        sys.exit(1)

    result = analyze_pe(str(binary))

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print_report(result)

    # Save JSON
    out_dir = Path(args.output_dir) if args.output_dir else Path(__file__).parent / "output"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_file = out_dir / f"{binary.stem}_triage.json"
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"[*] JSON saved: {json_file}")


if __name__ == "__main__":
    main()
