#!/usr/bin/env python3
"""
YARA Scanner for malware binary analysis.

Scans raw binaries against YARA rules for APT attribution
and malware family identification.

Usage:
    python yara_scanner.py <binary_path>
    python yara_scanner.py stealc.exe --rules-dir ./yara-rules --output-dir ./output
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

TOOL_VERSION = "1.0.0"
SCRIPT_DIR = Path(__file__).parent
DEFAULT_RULES_DIR = SCRIPT_DIR / "yara-rules"
DEFAULT_OUTPUT_DIR = SCRIPT_DIR / "output"


def find_rule_files(rules_dir):
    """Recursively find all .yar/.yara files."""
    rule_files = []
    for ext in ("*.yar", "*.yara"):
        rule_files.extend(rules_dir.rglob(ext))
    return sorted(rule_files)


def compile_rules(rules_dir):
    """Compile YARA rules, skipping files that fail to compile."""
    try:
        import yara
    except ImportError:
        print("Error: yara-python not installed. Run: pip install yara-python", file=sys.stderr)
        sys.exit(1)

    rule_files = find_rule_files(rules_dir)
    if not rule_files:
        print(f"Error: No .yar/.yara files found in {rules_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(rule_files)} rule files in {rules_dir}")

    # External variables that some rules (especially signature-base) require
    externals = {
        "filename": "",
        "filepath": "",
        "filetype": "",
        "extension": "",
        "owner": "",
        "FileType": "",
        "IsShortcut": False,
    }

    # Try compiling all rules together first (fastest)
    filepaths = {}
    for i, rf in enumerate(rule_files):
        namespace = rf.stem
        # Ensure unique namespace
        if namespace in filepaths:
            namespace = f"{namespace}_{i}"
        filepaths[namespace] = str(rf)

    try:
        rules = yara.compile(filepaths=filepaths, externals=externals)
        print(f"Compiled all {len(filepaths)} rule files successfully")
        return rules, len(filepaths), 0
    except yara.SyntaxError:
        pass  # Fall through to per-file compilation

    # Per-file compilation: skip broken rules
    print("Some rules failed to compile. Compiling individually...")
    valid_filepaths = {}
    skipped = 0
    for namespace, filepath in filepaths.items():
        try:
            yara.compile(filepath=filepath, externals=externals)
            valid_filepaths[namespace] = filepath
        except (yara.SyntaxError, yara.Error) as e:
            skipped += 1
            rel = os.path.relpath(filepath, rules_dir)
            print(f"  Warning: Skipping {rel}: {e}", file=sys.stderr)

    if not valid_filepaths:
        print("Error: No valid YARA rules could be compiled", file=sys.stderr)
        sys.exit(1)

    rules = yara.compile(filepaths=valid_filepaths, externals=externals)
    print(f"Compiled {len(valid_filepaths)} rule files ({skipped} skipped)")
    return rules, len(valid_filepaths), skipped


def scan_binary(rules, binary_path):
    """Scan a binary file with compiled YARA rules."""
    matches = rules.match(str(binary_path))
    results = []
    for match in matches:
        result = {
            "rule": match.rule,
            "tags": list(match.tags),
            "meta": dict(match.meta) if match.meta else {},
            "namespace": match.namespace,
            "strings_matched": len(match.strings),
        }
        results.append(result)
    return results


def print_summary(matches, binary_name):
    """Print human-readable summary."""
    print(f"\n{'='*60}")
    print(f"YARA Scan Results: {binary_name}")
    print(f"{'='*60}")

    if not matches:
        print("No matches found.")
        return

    print(f"Total matches: {len(matches)}\n")

    # Group by tags
    apt_matches = [m for m in matches if any(t in m["tags"] for t in ("apt", "APT", "threat_actor"))]
    malware_matches = [m for m in matches if any(t in m["tags"] for t in ("malware", "mal", "trojan", "stealer", "ransomware", "rat"))]
    other_matches = [m for m in matches if m not in apt_matches and m not in malware_matches]

    if apt_matches:
        print(f"[APT Attribution] ({len(apt_matches)} matches)")
        for m in apt_matches:
            desc = m["meta"].get("description", "")
            print(f"  - {m['rule']}: {desc}")
        print()

    if malware_matches:
        print(f"[Malware Family] ({len(malware_matches)} matches)")
        for m in malware_matches:
            desc = m["meta"].get("description", "")
            print(f"  - {m['rule']}: {desc}")
        print()

    if other_matches:
        print(f"[Other] ({len(other_matches)} matches)")
        for m in other_matches:
            desc = m["meta"].get("description", "")
            print(f"  - {m['rule']}: {desc}")
        print()


def main():
    parser = argparse.ArgumentParser(description="YARA Scanner for malware binaries")
    parser.add_argument("binary", help="Path to binary file to scan")
    parser.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES_DIR,
                        help=f"YARA rules directory (default: {DEFAULT_RULES_DIR})")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
                        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})")
    parser.add_argument("--json-only", action="store_true",
                        help="Output JSON only (no summary)")
    args = parser.parse_args()

    binary_path = Path(args.binary)
    if not binary_path.exists():
        print(f"Error: File not found: {binary_path}", file=sys.stderr)
        sys.exit(1)

    if not args.rules_dir.exists():
        print(f"Error: Rules directory not found: {args.rules_dir}", file=sys.stderr)
        print("Run: bash Tools/ghidra-headless/setup_yara_rules.sh", file=sys.stderr)
        sys.exit(1)

    # Compile rules
    rules, rules_loaded, rules_skipped = compile_rules(args.rules_dir)

    # Scan
    print(f"\nScanning: {binary_path}")
    matches = scan_binary(rules, binary_path)

    # Build output
    binary_name = binary_path.stem
    output = {
        "binary_name": binary_path.name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool_version": TOOL_VERSION,
        "rules_loaded": rules_loaded,
        "rules_skipped": rules_skipped,
        "rules_dir": str(args.rules_dir),
        "total_matches": len(matches),
        "matches": matches,
    }

    # Save JSON
    args.output_dir.mkdir(parents=True, exist_ok=True)
    output_file = args.output_dir / f"{binary_name}_yara.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\nJSON saved: {output_file}")

    # Print summary
    if not args.json_only:
        print_summary(matches, binary_path.name)

    return 0 if matches else 0


if __name__ == "__main__":
    sys.exit(main())
