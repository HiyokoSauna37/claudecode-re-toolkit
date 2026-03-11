#!/usr/bin/env python3
"""
Regshot Diff Analyzer - Registry persistence detection tool.

Parses Regshot text export (before/after diff) and flags persistence-related
registry changes based on ATT&CK T1547 and related techniques.

Usage:
    python regshot_diff.py <regshot_export.txt>
    python regshot_diff.py export.txt --json-only
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

TOOL_VERSION = "1.0.0"

# =============================================================================
# ATT&CK T1547 Persistence Registry Paths (17 patterns)
# =============================================================================

PERSISTENCE_PATTERNS = [
    # T1547.001 - Registry Run Keys / Startup Folder
    {
        "pattern": r"\\CurrentVersion\\Run(?:Once)?(?:\\|$)",
        "technique": "T1547.001",
        "description": "Run/RunOnce auto-start",
        "risk": "HIGH",
    },
    {
        "pattern": r"\\Policies\\Explorer\\Run(?:\\|$)",
        "technique": "T1547.001",
        "description": "Group Policy Run key",
        "risk": "HIGH",
    },
    # T1547.004 - Winlogon Helper DLL
    {
        "pattern": r"\\Winlogon\\(?:Shell|Userinit|Notify|TaskMan)",
        "technique": "T1547.004",
        "description": "Winlogon helper DLL/shell",
        "risk": "HIGH",
    },
    # T1547.001 - Explorer extensions
    {
        "pattern": r"\\Explorer\\(?:ShellExecuteHooks|ShellServiceObjects|SharedTaskScheduler)",
        "technique": "T1547.001",
        "description": "Explorer shell extensions",
        "risk": "HIGH",
    },
    # T1547.012 - Print Processors
    {
        "pattern": r"\\Print\\(?:Monitors|Providers|Processors)",
        "technique": "T1547.012",
        "description": "Print Monitor/Processor persistence",
        "risk": "HIGH",
    },
    # T1547.010 - Port Monitors
    {
        "pattern": r"\\Control\\Print\\Monitors\\",
        "technique": "T1547.010",
        "description": "Port Monitor persistence",
        "risk": "HIGH",
    },
    # Services (T1543.003)
    {
        "pattern": r"\\Services\\[^\\]+\\(?:ImagePath|Start|Type|ServiceDll)",
        "technique": "T1543.003",
        "description": "Service creation/modification",
        "risk": "HIGH",
    },
    {
        "pattern": r"\\Services\\[^\\]+$",
        "technique": "T1543.003",
        "description": "New service registration",
        "risk": "HIGH",
    },
    # Scheduled Tasks (T1053.005)
    {
        "pattern": r"\\Schedule\\TaskCache\\",
        "technique": "T1053.005",
        "description": "Scheduled Task registration",
        "risk": "HIGH",
    },
    # COM Objects (T1546.015)
    {
        "pattern": r"\\(?:CLSID|InprocServer32|LocalServer32)",
        "technique": "T1546.015",
        "description": "COM Object hijacking",
        "risk": "MEDIUM",
    },
    # Image File Execution Options (T1546.012)
    {
        "pattern": r"\\Image File Execution Options\\",
        "technique": "T1546.012",
        "description": "IFEO debugger persistence",
        "risk": "HIGH",
    },
    # AppInit_DLLs (T1546.010)
    {
        "pattern": r"\\Windows\\(?:CurrentVersion\\)?(?:AppInit_DLLs|LoadAppInit_DLLs)",
        "technique": "T1546.010",
        "description": "AppInit_DLLs injection",
        "risk": "HIGH",
    },
    # Boot Execute (T1547.001)
    {
        "pattern": r"\\Session Manager\\BootExecute",
        "technique": "T1547.001",
        "description": "Boot Execute persistence",
        "risk": "HIGH",
    },
    # LSA packages (T1547.002)
    {
        "pattern": r"\\Lsa\\(?:Authentication Packages|Notification Packages|Security Packages)",
        "technique": "T1547.002",
        "description": "LSA authentication package",
        "risk": "HIGH",
    },
    # Shell open command hijack
    {
        "pattern": r"\\shell\\open\\command",
        "technique": "T1546.001",
        "description": "File association hijack",
        "risk": "MEDIUM",
    },
    # Startup approved
    {
        "pattern": r"\\StartupApproved\\",
        "technique": "T1547.001",
        "description": "Startup approved list modification",
        "risk": "MEDIUM",
    },
    # Browser Helper Objects
    {
        "pattern": r"\\Browser Helper Objects\\",
        "technique": "T1176",
        "description": "Browser Helper Object (BHO)",
        "risk": "MEDIUM",
    },
]

# Additional suspicious patterns (not directly persistence but noteworthy)
SUSPICIOUS_PATTERNS = [
    {
        "pattern": r"\\SOFTWARE\\Microsoft\\Windows Defender\\",
        "description": "Windows Defender configuration change",
        "risk": "MEDIUM",
    },
    {
        "pattern": r"\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\",
        "description": "Windows Defender policy change",
        "risk": "HIGH",
    },
    {
        "pattern": r"\\DisableAntiSpyware",
        "description": "Anti-spyware disabled",
        "risk": "HIGH",
    },
    {
        "pattern": r"\\Firewall\\(?:StandardProfile|DomainProfile|PublicProfile)",
        "description": "Firewall configuration change",
        "risk": "MEDIUM",
    },
    {
        "pattern": r"\\Environment\\(?:Path|ComSpec|PATHEXT)",
        "description": "Environment variable modification",
        "risk": "LOW",
    },
    {
        "pattern": r"\\Uninstall\\",
        "description": "Software installation/uninstallation",
        "risk": "LOW",
    },
]


# =============================================================================
# Regshot Parser
# =============================================================================

def detect_encoding(filepath: str) -> str:
    """Detect file encoding via BOM or fallback heuristic."""
    raw = Path(filepath).read_bytes(8192 if Path(filepath).stat().st_size > 8192 else -1)
    # Check BOM
    if raw.startswith(b"\xff\xfe"):
        return "utf-16-le"
    if raw.startswith(b"\xfe\xff"):
        return "utf-16-be"
    if raw.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    # Try UTF-8
    try:
        raw.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError:
        pass
    # Fallback: Shift_JIS for Japanese environments, then cp1252
    for enc in ("shift_jis", "cp1252"):
        try:
            raw.decode(enc)
            return enc
        except (UnicodeDecodeError, LookupError):
            continue
    return "utf-8"


def parse_regshot_export(filepath: str) -> dict:
    """Parse Regshot text export file."""
    encoding = detect_encoding(filepath)
    content = Path(filepath).read_text(encoding=encoding, errors="replace")

    sections = {
        "keys_added": [],
        "keys_deleted": [],
        "values_added": [],
        "values_deleted": [],
        "values_modified": [],
    }

    current_section = None
    section_map = {
        "Keys added": "keys_added",
        "Keys deleted": "keys_deleted",
        "Values added": "values_added",
        "Values deleted": "values_deleted",
        "Values modified": "values_modified",
    }

    for line in content.splitlines():
        line = line.strip()

        # Detect section headers
        for header, key in section_map.items():
            if line.startswith(header):
                current_section = key
                break

        # Skip headers and separators
        if not line or line.startswith("--") or line.startswith("=="):
            continue
        if any(line.startswith(h) for h in section_map):
            continue
        if line.startswith("Total"):
            current_section = None
            continue

        # Add entries to current section
        if current_section and (line.startswith("HK") or line.startswith("  ")):
            sections[current_section].append(line)

    return sections


# =============================================================================
# Analysis
# =============================================================================

def analyze_changes(sections: dict) -> list:
    """Analyze registry changes for persistence indicators."""
    findings = []

    # Combine all change entries
    all_entries = []
    for change_type, entries in sections.items():
        for entry in entries:
            all_entries.append({"type": change_type, "entry": entry})

    for item in all_entries:
        entry = item["entry"]
        change_type = item["type"]

        # Check persistence patterns
        for rule in PERSISTENCE_PATTERNS:
            if re.search(rule["pattern"], entry, re.IGNORECASE):
                findings.append({
                    "entry": entry,
                    "change_type": change_type,
                    "risk": rule["risk"],
                    "technique": rule.get("technique", ""),
                    "description": rule["description"],
                    "category": "persistence",
                })
                break  # One match per entry for persistence
        else:
            # Check suspicious patterns
            for rule in SUSPICIOUS_PATTERNS:
                if re.search(rule["pattern"], entry, re.IGNORECASE):
                    findings.append({
                        "entry": entry,
                        "change_type": change_type,
                        "risk": rule["risk"],
                        "description": rule["description"],
                        "category": "suspicious",
                    })
                    break

    # Sort by risk level
    risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda x: risk_order.get(x["risk"], 3))

    return findings


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Analyze Regshot diff export for persistence indicators"
    )
    parser.add_argument("export_file", help="Path to Regshot text export file")
    parser.add_argument("--json-only", action="store_true", help="Output JSON only")
    args = parser.parse_args()

    if not Path(args.export_file).exists():
        print(f"Error: File not found: {args.export_file}", file=sys.stderr)
        sys.exit(1)

    # Parse
    sections = parse_regshot_export(args.export_file)
    findings = analyze_changes(sections)

    # Stats
    stats = {
        "keys_added": len(sections["keys_added"]),
        "keys_deleted": len(sections["keys_deleted"]),
        "values_added": len(sections["values_added"]),
        "values_deleted": len(sections["values_deleted"]),
        "values_modified": len(sections["values_modified"]),
    }

    risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        risk_counts[f["risk"]] = risk_counts.get(f["risk"], 0) + 1

    output = {
        "export_file": str(args.export_file),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
        "tool_version": TOOL_VERSION,
        "stats": stats,
        "risk_summary": risk_counts,
        "total_findings": len(findings),
        "findings": findings,
    }

    # Write JSON
    json_path = Path(args.export_file).with_suffix(".analysis.json")
    json_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")

    if args.json_only:
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return

    # Human-readable output
    print(f"{'='*60}")
    print(f"Regshot Diff Analysis")
    print(f"{'='*60}")
    print(f"File: {args.export_file}")
    print(f"\nRegistry Changes:")
    for key, count in stats.items():
        if count > 0:
            print(f"  {key.replace('_', ' ').title():20s}: {count}")

    print(f"\nFindings: {len(findings)}")
    print(f"  HIGH:   {risk_counts.get('HIGH', 0)}")
    print(f"  MEDIUM: {risk_counts.get('MEDIUM', 0)}")
    print(f"  LOW:    {risk_counts.get('LOW', 0)}")

    if findings:
        print(f"\n{'='*60}")
        print("Findings (sorted by risk):")
        print(f"{'='*60}")

        for f in findings:
            risk_color = {"HIGH": "!!!", "MEDIUM": "! ", "LOW": "  "}.get(f["risk"], "  ")
            technique = f" [{f['technique']}]" if f.get("technique") else ""
            print(f"\n  [{f['risk']:6s}] {risk_color} {f['description']}{technique}")
            print(f"          Change: {f['change_type'].replace('_', ' ')}")
            print(f"          Entry:  {f['entry'][:120]}")
    else:
        print("\nNo persistence-related changes detected.")

    print(f"\nJSON output: {json_path}")


if __name__ == "__main__":
    main()
