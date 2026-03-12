#!/usr/bin/env python3
"""
CAPA Scanner for malware binary analysis.

Runs Mandiant CAPA (with Vivisect backend) to extract malware capabilities
and MITRE ATT&CK mappings.

Usage:
    python capa_scanner.py <binary_path>
    python capa_scanner.py stealc.exe --output-dir ./output
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


def check_capa():
    """Check if capa is installed and accessible."""
    if shutil.which("capa") is None:
        print("Error: capa not found. Install with: pip install flare-capa", file=sys.stderr)
        print("Then update rules: capa --update-rules", file=sys.stderr)
        sys.exit(1)


def run_capa(binary_path):
    """Run capa with JSON output and return parsed result."""
    cmd = ["capa", "-j", str(binary_path)]

    # If running inside container with rules at /opt/capa-rules, use them explicitly
    rules_dir = Path("/opt/capa-rules")
    sigs_dir = Path("/opt/capa-sigs")
    if rules_dir.is_dir():
        cmd.extend(["-r", str(rules_dir)])
    if sigs_dir.is_dir():
        cmd.extend(["-s", str(sigs_dir)])
    print(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        print("Error: CAPA analysis timed out (>10min)", file=sys.stderr)
        return None
    except FileNotFoundError:
        print("Error: capa command not found", file=sys.stderr)
        return None

    if result.returncode != 0:
        stderr = result.stderr.strip()
        if stderr:
            print(f"CAPA stderr: {stderr}", file=sys.stderr)
        # capa returns non-zero for unsupported formats, etc.
        if not result.stdout.strip():
            print("Error: CAPA produced no output", file=sys.stderr)
            return None

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse CAPA JSON output: {e}", file=sys.stderr)
        return None


def extract_summary(capa_result):
    """Extract summary information from CAPA JSON output."""
    summary = {
        "attack_techniques": [],
        "mbc_behaviors": [],
        "capabilities": [],
        "total_capabilities": 0,
    }

    if not capa_result:
        return summary

    rules = capa_result.get("rules", {})
    summary["total_capabilities"] = len(rules)

    for rule_name, rule_data in rules.items():
        meta = rule_data.get("meta", {})

        # Extract ATT&CK techniques
        attack = meta.get("attack", [])
        for entry in attack:
            technique = {
                "id": entry.get("id", ""),
                "tactic": entry.get("tactic", ""),
                "technique": entry.get("technique", ""),
                "subtechnique": entry.get("subtechnique", ""),
            }
            if technique["id"] and technique not in summary["attack_techniques"]:
                summary["attack_techniques"].append(technique)

        # Extract MBC behaviors
        mbc = meta.get("mbc", [])
        for entry in mbc:
            behavior = {
                "id": entry.get("id", ""),
                "objective": entry.get("objective", ""),
                "behavior": entry.get("behavior", ""),
            }
            if behavior["id"] and behavior not in summary["mbc_behaviors"]:
                summary["mbc_behaviors"].append(behavior)

        # Collect capability names
        namespace = meta.get("namespace", "")
        summary["capabilities"].append({
            "name": rule_name,
            "namespace": namespace,
        })

    return summary


def print_summary(summary, binary_name):
    """Print human-readable summary."""
    print(f"\n{'='*60}")
    print(f"CAPA Analysis Results: {binary_name}")
    print(f"{'='*60}")
    print(f"Total capabilities detected: {summary['total_capabilities']}")

    if summary["attack_techniques"]:
        print(f"\n[MITRE ATT&CK Techniques] ({len(summary['attack_techniques'])})")
        # Group by tactic
        by_tactic = {}
        for t in summary["attack_techniques"]:
            tactic = t["tactic"] or "Unknown"
            by_tactic.setdefault(tactic, []).append(t)
        for tactic, techniques in sorted(by_tactic.items()):
            print(f"  {tactic}:")
            for t in techniques:
                name = t["technique"]
                if t["subtechnique"]:
                    name += f" :: {t['subtechnique']}"
                print(f"    - {t['id']}: {name}")

    if summary["mbc_behaviors"]:
        print(f"\n[MBC Behaviors] ({len(summary['mbc_behaviors'])})")
        by_objective = {}
        for b in summary["mbc_behaviors"]:
            obj = b["objective"] or "Unknown"
            by_objective.setdefault(obj, []).append(b)
        for obj, behaviors in sorted(by_objective.items()):
            print(f"  {obj}:")
            for b in behaviors:
                print(f"    - {b['id']}: {b['behavior']}")

    if summary["capabilities"]:
        print(f"\n[Capabilities] ({len(summary['capabilities'])})")
        # Group by namespace prefix
        by_ns = {}
        for c in summary["capabilities"]:
            ns = c["namespace"].split("/")[0] if c["namespace"] else "other"
            by_ns.setdefault(ns, []).append(c["name"])
        for ns, names in sorted(by_ns.items()):
            print(f"  {ns}/ ({len(names)})")
            for name in names[:10]:
                print(f"    - {name}")
            if len(names) > 10:
                print(f"    ... and {len(names) - 10} more")

    print()


def main():
    parser = argparse.ArgumentParser(description="CAPA Scanner for malware binaries")
    parser.add_argument("binary", help="Path to binary file to analyze")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
                        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})")
    parser.add_argument("--json-only", action="store_true",
                        help="Output JSON only (no summary)")
    args = parser.parse_args()

    binary_path = Path(args.binary)
    if not binary_path.exists():
        print(f"Error: File not found: {binary_path}", file=sys.stderr)
        sys.exit(1)

    check_capa()

    # Run CAPA
    capa_result = run_capa(binary_path)
    if capa_result is None:
        sys.exit(1)

    # Extract summary
    summary = extract_summary(capa_result)

    # Build output
    binary_name = binary_path.stem
    output = {
        "binary_name": binary_path.name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool_version": TOOL_VERSION,
        "summary": summary,
        "capa_raw": capa_result,
    }

    # Save JSON
    args.output_dir.mkdir(parents=True, exist_ok=True)
    output_file = args.output_dir / f"{binary_name}_capa.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\nJSON saved: {output_file}")

    # Print summary
    if not args.json_only:
        print_summary(summary, binary_path.name)


if __name__ == "__main__":
    main()
