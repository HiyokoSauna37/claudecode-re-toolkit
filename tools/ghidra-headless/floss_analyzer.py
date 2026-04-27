#!/usr/bin/env python3
"""FLOSS obfuscated string analyzer (host-side).

Extracts strings that plain string extraction misses:
  - Stack strings   : built byte-by-byte on stack (e.g. "cmd.exe" pushed in pieces)
  - Tight-loop      : short XOR / ROT loops that produce short strings
  - Decoded strings : emulation-based extraction of longer deobfuscation routines

Install:
    pip install flare-floss

Usage:
    python floss_analyzer.py malware.exe
    python floss_analyzer.py malware.exe --output-dir ./output
    python floss_analyzer.py malware.exe --min-len 6 --timeout 300
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

TOOL_VERSION = "1.1.0"
SCRIPT_DIR = Path(__file__).parent
DEFAULT_OUTPUT_DIR = SCRIPT_DIR / "output"

# --- ANSI colors (no external deps) ---
R = "\033[91m"; Y = "\033[93m"; G = "\033[92m"; C = "\033[96m"; B = "\033[1m"; E = "\033[0m"

def _c(color: str, text: str) -> str:
    return f"{color}{text}{E}" if sys.stdout.isatty() else text

# --- IOC keyword sets ---
C2_MARKERS = ("http://", "https://", "tcp://", "ftp://", ".onion", "ws://")
SUSPICIOUS_KEYWORDS = (
    "powershell", "cmd.exe", "regsvr32", "certutil", "bitsadmin",
    "mshta", "wscript", "cscript", "rundll32", "schtasks",
    "HKCU\\Software", "HKLM\\Software", "CurrentVersion\\Run",
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
)

MAX_FILE_SIZE_MB = 100


def check_floss() -> None:
    if shutil.which("floss") is None:
        print(_c(R, "✗ floss not found in PATH"), file=sys.stderr)
        print("  Install: pip install flare-floss", file=sys.stderr)
        print("  Or download: https://github.com/mandiant/flare-floss/releases", file=sys.stderr)
        sys.exit(1)


def run_floss(binary: Path, timeout: int, min_len: int) -> dict | None:
    cmd = ["floss", "--json", f"--minimum-length={min_len}", str(binary)]
    print(f"  Running: floss --minimum-length={min_len} {binary.name}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(_c(Y, f"  ⚠ FLOSS timed out after {timeout}s (partial results may exist)"), file=sys.stderr)
        return None
    except FileNotFoundError:
        print(_c(R, "  ✗ floss binary disappeared — reinstall flare-floss"), file=sys.stderr)
        return None

    # FLOSS returns 0 on success, 1 on partial (e.g. emulation errors on some functions)
    if result.returncode not in (0, 1):
        print(_c(R, f"  ✗ floss exited {result.returncode}"), file=sys.stderr)
        if result.stderr:
            print(f"  {result.stderr[:400]}", file=sys.stderr)
        return None

    try:
        return json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        print(_c(R, "  ✗ Could not parse FLOSS JSON output"), file=sys.stderr)
        return None


def extract_strings(raw: dict) -> dict[str, list[str]]:
    block = raw.get("strings", {})
    def pluck(key: str) -> list[str]:
        return [
            s.get("string", "") for s in block.get(key, [])
            if isinstance(s, dict) and s.get("string")
        ]
    return {
        "static":     pluck("static_strings"),
        "stack":      pluck("stack_strings"),
        "tight_loop": pluck("tight_loop_strings"),
        "decoded":    pluck("decoded_strings"),
    }


def categorize(strings: dict[str, list[str]]) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {"c2_urls": [], "suspicious_cmds": [], "registry_keys": [], "other_notable": []}
    obfuscated = strings["stack"] + strings["tight_loop"] + strings["decoded"]
    for s in obfuscated:
        sl = s.lower()
        if any(m in sl for m in C2_MARKERS):
            hits["c2_urls"].append(s)
        elif any(kw in s for kw in SUSPICIOUS_KEYWORDS):
            hits["suspicious_cmds"].append(s)
        elif s.startswith(("HKEY_", "HKCU", "HKLM")):
            hits["registry_keys"].append(s)
    # Deduplicate
    for k in hits:
        hits[k] = list(dict.fromkeys(hits[k]))
    return hits


def print_report(binary: Path, strings: dict[str, list[str]], hits: dict[str, list[str]], out_path: Path) -> None:
    total_obfuscated = len(strings["stack"]) + len(strings["tight_loop"]) + len(strings["decoded"])
    print()
    print(_c(B, f"╔══ FLOSS: {binary.name} ══"))
    print(f"  Static strings   : {len(strings['static'])}")
    print(f"  Stack strings    : {_c(Y, str(len(strings['stack'])))}")
    print(f"  Tight-loop       : {_c(Y, str(len(strings['tight_loop'])))}")
    print(f"  Decoded strings  : {_c(C, str(len(strings['decoded'])))}")
    print(f"  ─────────────────────────────")
    print(f"  Obfuscated total : {_c(Y, str(total_obfuscated))}")

    if hits["c2_urls"]:
        print(_c(R, f"\n  ⚡ C2 / URL candidates ({len(hits['c2_urls'])}):"))
        for s in hits["c2_urls"][:15]:
            print(f"    {s}")

    if hits["suspicious_cmds"]:
        print(_c(Y, f"\n  ⚠ Suspicious commands ({len(hits['suspicious_cmds'])}):"))
        for s in hits["suspicious_cmds"][:10]:
            print(f"    {s}")

    if hits["registry_keys"]:
        print(_c(Y, f"\n  ⚠ Registry keys ({len(hits['registry_keys'])}):"))
        for s in hits["registry_keys"][:8]:
            print(f"    {s}")

    if not any(hits.values()) and strings["decoded"]:
        print(_c(G, f"\n  ✓ Decoded strings (top 15):"))
        for s in strings["decoded"][:15]:
            print(f"    {s}")

    print(f"\n  Saved: {_c(G, str(out_path))}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="FLOSS obfuscated string extractor — finds strings that raw extraction misses",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python floss_analyzer.py malware.exe
  python floss_analyzer.py sample.dll --output-dir ./results
  python floss_analyzer.py loader.exe --min-len 6 --timeout 600

Output file: <binary_stem>_floss.json
  .strings.decoded    — emulation-extracted strings (most interesting)
  .strings.stack      — stack-built strings
  .interesting.c2_urls — direct C2 candidates

Install FLOSS: pip install flare-floss
""",
    )
    parser.add_argument("binary", help="PE/ELF binary to analyze")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), metavar="DIR",
                        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})")
    parser.add_argument("--min-len", type=int, default=4, metavar="N",
                        help="Minimum string length to report (default: 4)")
    parser.add_argument("--timeout", type=int, default=600, metavar="SEC",
                        help="FLOSS timeout in seconds (default: 600)")
    args = parser.parse_args()

    binary = Path(args.binary)
    if not binary.exists():
        print(_c(R, f"✗ File not found: {binary}"), file=sys.stderr)
        sys.exit(1)
    if not binary.is_file():
        print(_c(R, f"✗ Not a file: {binary}"), file=sys.stderr)
        sys.exit(1)

    size_mb = binary.stat().st_size / (1024 * 1024)
    if size_mb > MAX_FILE_SIZE_MB:
        print(_c(Y, f"⚠ Large file ({size_mb:.1f} MB) — FLOSS may be slow"), file=sys.stderr)

    check_floss()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(_c(C, f"\n→ FLOSS Analysis: {binary.name}"))
    raw = run_floss(binary, args.timeout, args.min_len)
    if raw is None:
        print(_c(R, "✗ FLOSS produced no output"), file=sys.stderr)
        sys.exit(1)

    strings = extract_strings(raw)
    hits = categorize(strings)
    bname = binary.stem

    output = {
        "tool": "floss",
        "version": TOOL_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "binary": binary.name,
        "summary": {
            "static": len(strings["static"]),
            "stack": len(strings["stack"]),
            "tight_loop": len(strings["tight_loop"]),
            "decoded": len(strings["decoded"]),
            "c2_candidates": len(hits["c2_urls"]),
            "suspicious_cmds": len(hits["suspicious_cmds"]),
        },
        "interesting": hits,
        "strings": strings,
    }

    out_path = output_dir / f"{bname}_floss.json"
    try:
        out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError as e:
        print(_c(R, f"✗ Could not write output: {e}"), file=sys.stderr)
        sys.exit(1)

    print_report(binary, strings, hits, out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
