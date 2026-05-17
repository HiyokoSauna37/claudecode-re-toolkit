#!/usr/bin/env python3
"""PE Fallback Extractor — Ghidra-compatible strings/imports from raw PE.

When Ghidra scripts fail, this generates _pe_strings.txt and _pe_imports.txt
in the same format that ioc_extractor.py and malware_classifier.py expect.

Uses pefile for imports and raw byte scanning for strings (ASCII + UTF-16LE).
"""

import argparse
import re
import struct
import sys
from pathlib import Path

try:
    import pefile
except ImportError:
    print("Error: pefile not installed (pip install pefile)", file=sys.stderr)
    sys.exit(1)

SCRIPT_DIR = Path(__file__).parent
DEFAULT_OUTPUT_DIR = SCRIPT_DIR / "output"
MIN_STRING_LEN = 4


def extract_strings(data: bytes):
    """Extract ASCII and UTF-16LE strings from raw bytes."""
    results = []

    # ASCII strings
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LEN, data):
        results.append((m.start(), m.group().decode("ascii", errors="ignore")))

    # UTF-16LE strings
    i = 0
    while i < len(data) - 1:
        s = bytearray()
        start = i
        while i < len(data) - 1:
            c = data[i : i + 2]
            if c[1] == 0 and 0x20 <= c[0] <= 0x7E:
                s.append(c[0])
                i += 2
            else:
                break
        if len(s) >= MIN_STRING_LEN:
            results.append((start, s.decode("ascii", errors="ignore")))
        i += 2

    results.sort(key=lambda x: x[0])
    return results


def extract_imports(pe):
    """Extract imports in Ghidra _imports.txt compatible format."""
    lines = []
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return lines

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode("utf-8", errors="ignore")
        lines.append(f"[{dll_name}]")
        for imp in entry.imports:
            if imp.name:
                lines.append(f"  {imp.name.decode('utf-8', errors='ignore')}")
            elif imp.ordinal:
                lines.append(f"  Ordinal_{imp.ordinal}")
        lines.append("")

    return lines


def main():
    parser = argparse.ArgumentParser(description="PE fallback extraction")
    parser.add_argument("binary", help="Path to PE binary")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    args = parser.parse_args()

    binary_path = Path(args.binary)
    if not binary_path.exists():
        print(f"Error: File not found: {binary_path}", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    base_name = binary_path.stem

    data = binary_path.read_bytes()

    # Parse PE
    try:
        pe = pefile.PE(data=data)
    except pefile.PEFormatError as e:
        print(f"Error: Not a valid PE file: {e}", file=sys.stderr)
        sys.exit(1)

    # Generate _pe_strings.txt
    print(f"[*] Extracting strings from {binary_path.name}...")
    strings = extract_strings(data)
    strings_file = output_dir / f"{base_name}_pe_strings.txt"
    with open(strings_file, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write(f"Strings (PE fallback): {base_name}\n")
        f.write("=" * 60 + "\n\n")
        for offset, s in strings:
            s_escaped = s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
            if len(s_escaped) > 200:
                s_escaped = s_escaped[:200] + "..."
            f.write(f'0x{offset:<12x}  "{s_escaped}"\n')
        f.write(f"\nTotal: {len(strings)} strings\n")
    print(f"  -> {strings_file} ({len(strings)} strings)")

    # Generate _pe_imports.txt
    print(f"[*] Extracting imports from {binary_path.name}...")
    import_lines = extract_imports(pe)
    imports_file = output_dir / f"{base_name}_pe_imports.txt"
    with open(imports_file, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write(f"Import Table (PE fallback): {base_name}\n")
        f.write("=" * 60 + "\n\n")
        f.write("\n".join(import_lines) + "\n")
    print(f"  -> {imports_file}")

    pe.close()
    print("[*] PE fallback extraction complete.")


if __name__ == "__main__":
    main()
