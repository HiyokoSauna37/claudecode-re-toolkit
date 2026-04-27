#!/usr/bin/env python3
"""FLOSS obfuscated string analyzer (host-side).

Runs FLARE FLOSS to extract strings that raw string extraction misses:
- Stack strings (built byte-by-byte on the stack at runtime)
- Tight-loop strings (XOR/ROT obfuscation loops)
- Decoded strings (emulation-based dynamic extraction)

Usage:
    python floss_analyzer.py <binary_path>
    python floss_analyzer.py malware.exe --output-dir ./output
"""

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

TOOL_VERSION = "1.0.0"
SCRIPT_DIR = Path(__file__).parent
DEFAULT_OUTPUT_DIR = SCRIPT_DIR / "output"

C2_KEYWORDS = ("http://", "https://", ".onion", "tcp://", "ftp://")
SUSPICIOUS_KEYWORDS = (
    "powershell", "cmd.exe", "regsvr32", "certutil", "bitsadmin",
    "mshta", "wscript", "cscript", "rundll32", "schtasks",
    "HKCU\\", "HKLM\\", "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
)


def check_floss() -> None:
    if shutil.which("floss") is None:
        print("Error: floss not found.", file=sys.stderr)
        print("Install: pip install flare-floss", file=sys.stderr)
        print("  or download pre-built binary from:", file=sys.stderr)
        print("  https://github.com/mandiant/flare-floss/releases", file=sys.stderr)
        sys.exit(1)


def run_floss(binary_path: Path) -> dict | None:
    cmd = ["floss", "--json", str(binary_path)]
    print(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        print("Error: FLOSS timed out (>10min)", file=sys.stderr)
        return None
    except FileNotFoundError:
        print("Error: floss command not found", file=sys.stderr)
        return None

    if result.returncode not in (0, 1):  # FLOSS may return 1 on partial results
        print(f"Error: floss exited with code {result.returncode}", file=sys.stderr)
        if result.stderr:
            print(result.stderr[:500], file=sys.stderr)
        return None

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print("Error: Could not parse FLOSS JSON output", file=sys.stderr)
        return None


def extract_strings(raw: dict) -> dict:
    strings_block = raw.get("strings", {})
    return {
        "static": [s.get("string", "") for s in strings_block.get("static_strings", [])],
        "stack": [s.get("string", "") for s in strings_block.get("stack_strings", [])],
        "tight_loop": [s.get("string", "") for s in strings_block.get("tight_loop_strings", [])],
        "decoded": [s.get("string", "") for s in strings_block.get("decoded_strings", [])],
    }


def find_interesting(strings: dict) -> dict:
    interesting: dict[str, list[str]] = {"c2_candidates": [], "suspicious_commands": [], "decoded_highlights": []}
    all_obfuscated = strings["stack"] + strings["tight_loop"] + strings["decoded"]
    for s in all_obfuscated:
        sl = s.lower()
        if any(kw in sl for kw in C2_KEYWORDS):
            interesting["c2_candidates"].append(s)
        if any(kw in sl for kw in SUSPICIOUS_KEYWORDS):
            interesting["suspicious_commands"].append(s)
    interesting["decoded_highlights"] = strings["decoded"][:30]
    # Deduplicate
    for k in interesting:
        interesting[k] = list(dict.fromkeys(interesting[k]))
    return interesting


def main() -> int:
    parser = argparse.ArgumentParser(description="FLOSS obfuscated string analyzer")
    parser.add_argument("binary", help="Binary to analyze")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    args = parser.parse_args()

    check_floss()
    binary = Path(args.binary)
    if not binary.is_file():
        print(f"Error: File not found: {binary}", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    raw = run_floss(binary)
    if raw is None:
        sys.exit(1)

    strings = extract_strings(raw)
    interesting = find_interesting(strings)
    bname = binary.stem

    output = {
        "tool": "floss",
        "version": TOOL_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "binary": binary.name,
        "summary": {
            "static_count": len(strings["static"]),
            "stack_count": len(strings["stack"]),
            "tight_loop_count": len(strings["tight_loop"]),
            "decoded_count": len(strings["decoded"]),
            "c2_candidates": len(interesting["c2_candidates"]),
            "suspicious_commands": len(interesting["suspicious_commands"]),
        },
        "interesting": interesting,
        "strings": strings,
    }

    output_path = output_dir / f"{bname}_floss.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"[*] Saved: {output_path}")

    print(f"\nFLOSS Summary: {binary.name}")
    print(f"  Static:     {len(strings['static'])}")
    print(f"  Stack:      {len(strings['stack'])}")
    print(f"  Tight-loop: {len(strings['tight_loop'])}")
    print(f"  Decoded:    {len(strings['decoded'])}")

    if interesting["c2_candidates"]:
        print(f"\n[!] C2 candidates ({len(interesting['c2_candidates'])}):")
        for s in interesting["c2_candidates"][:10]:
            print(f"  {s}")

    if interesting["suspicious_commands"]:
        print(f"\n[!] Suspicious commands ({len(interesting['suspicious_commands'])}):")
        for s in interesting["suspicious_commands"][:10]:
            print(f"  {s}")

    if strings["decoded"] and not interesting["c2_candidates"]:
        print(f"\n[+] Decoded strings (top 10):")
        for s in strings["decoded"][:10]:
            print(f"  {s}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
