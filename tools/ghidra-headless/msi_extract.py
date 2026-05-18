"""
MSI Static Extraction Tool
MSI (OLE compound document) からファイルテーブル・CustomAction・メタデータを抽出し、
内包PEを特定する。ghidra.sh analyze-full のMSI分岐から呼ばれる。

Usage:
    python tools/ghidra-headless/msi_extract.py <msi_path> [--json] [--output-dir DIR]

Requirements:
    - olefile (pip install olefile)

Output:
    - MSI metadata (ProductName, Manufacturer, ProductCode, UpgradeCode)
    - File table (CAB内ファイル名 → インストール名マッピング)
    - CustomAction table entries
    - Install directory
    - Embedded PE/DLL identification with entropy
"""

import sys
import json
import math
import hashlib
import argparse
import struct
import re
from pathlib import Path

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    return round(
        sum(-f / length * math.log2(f / length) for f in freq if f > 0), 3
    )


def extract_msi_strings(ole) -> list[str]:
    """Extract all readable ASCII strings from small OLE streams."""
    all_strings = []
    for stream in ole.listdir():
        sname = "/".join(stream)
        size = ole.get_size(sname)
        if size > 200000:
            continue
        try:
            data = ole.openstream(sname).read()
        except Exception:
            continue
        current = []
        for b in data:
            if 32 <= b < 127:
                current.append(chr(b))
            else:
                if len(current) >= 3:
                    all_strings.append("".join(current))
                current = []
        if len(current) >= 3:
            all_strings.append("".join(current))
    return all_strings


def parse_msi_metadata(strings: list[str]) -> dict:
    """Extract MSI metadata from string pool."""
    meta = {}
    guids = []
    for s in strings:
        if re.match(r"^\{[0-9A-Fa-f-]{36}\}$", s):
            guids.append(s)

    # Find known property values by context (adjacent strings)
    keywords = {
        "ProductName": None,
        "ProductVersion": None,
        "Manufacturer": None,
        "ProductCode": None,
        "UpgradeCode": None,
    }
    for i, s in enumerate(strings):
        if s in keywords and i + 1 < len(strings):
            candidate = strings[i + 1] if i + 1 < len(strings) else None
            if candidate and candidate not in keywords:
                keywords[s] = candidate

    # If ProductCode/UpgradeCode not found by adjacency, use GUIDs
    if not keywords["ProductCode"] and len(guids) >= 1:
        keywords["ProductCode"] = guids[0]
    if not keywords["UpgradeCode"] and len(guids) >= 2:
        keywords["UpgradeCode"] = guids[1]

    return {k: v for k, v in keywords.items() if v is not None}


def parse_file_table(strings: list[str]) -> list[dict]:
    """Extract file table entries (short|long name mappings)."""
    files = []
    seen = set()
    for s in strings:
        if "|" in s and len(s) < 200:
            parts = s.split("|")
            if len(parts) == 2:
                short_name, long_name = parts
                lower = long_name.lower()
                if any(lower.endswith(ext) for ext in
                       [".exe", ".dll", ".sys", ".ocx", ".dat", ".db",
                        ".idx", ".bin", ".cfg", ".inf", ".msi"]):
                    if long_name not in seen:
                        files.append({
                            "short_name": short_name,
                            "long_name": long_name,
                        })
                        seen.add(long_name)
    return files


def parse_custom_actions(strings: list[str]) -> list[str]:
    """Find CustomAction-like entries."""
    actions = []
    action_keywords = ["LaunchFile", "LaunchApp", "RunExe", "CustomAction",
                       "InstallFinalize", "ExecCommand"]
    for s in strings:
        if any(k.lower() in s.lower() for k in action_keywords):
            if len(s) < 100:
                actions.append(s)
    return list(set(actions))[:10]


def parse_install_directory(strings: list[str]) -> str | None:
    """Find the target install directory."""
    dir_patterns = [
        r"LocalAppDataFolder",
        r"ProgramFilesFolder",
        r"CommonAppDataFolder",
        r"AppDataFolder",
        r"SystemFolder",
    ]
    for s in strings:
        for pat in dir_patterns:
            if pat in s:
                # The directory name is often the next unique string
                idx = strings.index(s)
                for j in range(idx + 1, min(idx + 5, len(strings))):
                    candidate = strings[j]
                    if "|" in candidate:
                        parts = candidate.split("|")
                        return f"{pat}\\{parts[-1]}"
                    elif re.match(r"^[A-Za-z0-9_-]+$", candidate) and len(candidate) < 50:
                        return f"{pat}\\{candidate}"
    return None


def analyze_msi(msi_path: str) -> dict:
    """Main MSI analysis function."""
    try:
        import olefile
    except ImportError:
        return {"error": "olefile not installed. Install: pip install olefile"}

    path = Path(msi_path)
    if not path.exists():
        return {"error": f"File not found: {msi_path}"}

    raw = path.read_bytes()
    if raw[:8] != OLE_MAGIC:
        return {"error": "Not an OLE/MSI file"}

    result = {
        "file": path.name,
        "size": path.stat().st_size,
        "entropy": calc_entropy(raw),
        "md5": hashlib.md5(raw).hexdigest(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }

    try:
        ole = olefile.OleFileIO(str(path))
    except Exception as e:
        result["error"] = f"OLE parse error: {e}"
        return result

    # Stream inventory
    streams = ["/".join(s) for s in ole.listdir()]
    result["ole_stream_count"] = len(streams)

    # Extract string pool
    strings = extract_msi_strings(ole)
    result["string_count"] = len(strings)

    # Parse metadata
    result["metadata"] = parse_msi_metadata(strings)

    # File table
    result["file_table"] = parse_file_table(strings)

    # Custom actions
    result["custom_actions"] = parse_custom_actions(strings)

    # Install directory
    install_dir = parse_install_directory(strings)
    if install_dir:
        result["install_directory"] = install_dir

    # Identify PE files in the file table
    pe_files = [f for f in result["file_table"]
                if f["long_name"].lower().endswith((".exe", ".dll"))]
    result["pe_count"] = len(pe_files)
    result["data_files"] = [f for f in result["file_table"]
                            if not f["long_name"].lower().endswith((".exe", ".dll"))]

    # Verdict
    verdicts = ["MSI_INSTALLER"]
    if result["pe_count"] > 2:
        verdicts.append("MULTIPLE_PE_SIDELOADING_CANDIDATE")
    if any("LaunchFile" in a or "LaunchApp" in a for a in result["custom_actions"]):
        verdicts.append("HAS_LAUNCH_ACTION")
    if result["entropy"] > 7.0:
        verdicts.append("HIGH_ENTROPY")

    result["verdict"] = verdicts

    ole.close()
    return result


def print_report(result: dict):
    """Human-readable output."""
    print("=" * 60)
    print(f"MSI Triage: {result.get('file', 'unknown')}")
    print("=" * 60)
    print(f"  Size:    {result.get('size', 0):,} bytes")
    print(f"  Entropy: {result.get('entropy', 0)}")
    print(f"  SHA256:  {result.get('sha256', 'N/A')}")
    print()

    meta = result.get("metadata", {})
    if meta:
        print("[MSI Metadata]")
        for k, v in meta.items():
            print(f"  {k}: {v}")
        print()

    install_dir = result.get("install_directory")
    if install_dir:
        print(f"[Install Directory] {install_dir}")
        print()

    file_table = result.get("file_table", [])
    if file_table:
        print(f"[File Table] ({len(file_table)} entries)")
        for f in file_table:
            print(f"  {f['long_name']}")
        print()

    actions = result.get("custom_actions", [])
    if actions:
        print(f"[Custom Actions]")
        for a in actions:
            print(f"  {a}")
        print()

    verdicts = result.get("verdict", [])
    print(f"[Verdict] {' | '.join(verdicts)}")
    print()
    if "MULTIPLE_PE_SIDELOADING_CANDIDATE" in verdicts:
        print("  ⚠ Multiple PE files detected — possible DLL sideloading package")
    if "HAS_LAUNCH_ACTION" in verdicts:
        print("  ⚠ MSI has CustomAction to launch executable after install")


def main():
    parser = argparse.ArgumentParser(description="MSI Static Extraction Tool")
    parser.add_argument("msi", help="Path to MSI file")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--output-dir", "-o", help="Output directory for JSON")
    args = parser.parse_args()

    result = analyze_msi(args.msi)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        if "error" in result:
            print(f"ERROR: {result['error']}")
            sys.exit(1)
        print_report(result)

    # Save JSON
    if args.output_dir:
        out_dir = Path(args.output_dir)
    else:
        out_dir = Path(__file__).parent / "output"
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(args.msi).stem
    json_file = out_dir / f"{stem}_msi_triage.json"
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n[*] JSON saved: {json_file}")


if __name__ == "__main__":
    main()
