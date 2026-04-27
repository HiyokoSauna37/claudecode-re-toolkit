#!/usr/bin/env python3
"""Office document malware analyzer — oletools wrapper (runs inside container).

Analyzes Office files for:
  - VBA macros (auto-exec triggers, suspicious API calls)
  - OLE streams / embedded objects
  - External links, DDE payloads, RTF objects

Supported formats:
  .doc .dot .xls .xlt .ppt        (OLE2 binary)
  .docx .docm .dotm .xlsx .xlsm
  .xltm .pptx .pptm               (OOXML/ZIP)
  .rtf .msg .mhtml                 (other)

Usage:
    python office_analyzer.py invoice.doc --output-dir /tmp/output
    python office_analyzer.py suspicious.xlsm --output-dir /tmp/output
    python office_analyzer.py unknown_file --output-dir /tmp/output --force
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

TOOL_VERSION = "1.1.0"

OFFICE_EXTENSIONS = {
    ".doc", ".dot", ".xls", ".xlt", ".ppt",
    ".docx", ".docm", ".dotm", ".xlsx", ".xlsm", ".xltm",
    ".pptx", ".pptm", ".rtf", ".msg", ".mhtml", ".mht",
}
OLE_MAGIC  = b"\xd0\xcf\x11\xe0"
OOXML_MAGIC = b"PK\x03\x04"
RTF_MAGIC  = b"{\\rtf"

AUTO_EXEC_TRIGGERS = {
    "AutoOpen", "AutoClose", "AutoExec", "AutoNew", "AutoExit",
    "Document_Open", "Document_Close", "Workbook_Open", "Workbook_BeforeClose",
    "Auto_Open", "Auto_Close", "Shell_Open",
}
SUSPICIOUS_APIS = {
    "Shell", "CreateObject", "GetObject", "WScript.Shell",
    "PowerShell", "cmd.exe", "environ", "CallByName",
    "Execute", "Eval", "CreateProcessA", "URLDownloadToFile",
    "InternetOpenUrl", "WinExec", "ShellExecute",
}


def detect_office(path: Path) -> bool:
    if path.suffix.lower() in OFFICE_EXTENSIONS:
        return True
    try:
        header = path.read_bytes()[:5]
        return (
            header[:4] == OLE_MAGIC
            or header[:4] == OOXML_MAGIC
            or header[:5] == RTF_MAGIC
        )
    except OSError:
        return False


def _run(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timed out"
    except FileNotFoundError:
        return -2, "", f"not found: {cmd[0]}"


def _safe_json(text: str) -> object:
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def run_oleid(filepath: str) -> dict:
    rc, out, _ = _run(["oleid", "--json", filepath])
    if rc == 0:
        result = _safe_json(out)
        if isinstance(result, (dict, list)):
            return result if isinstance(result, dict) else {"indicators": result}
    return {}


def run_olevba(filepath: str) -> dict:
    # Try JSON output first
    rc, out, _ = _run(["olevba", "--json", filepath])
    if rc in (0, 1, 2) and out.strip():
        result = _safe_json(out)
        if result is not None:
            if isinstance(result, list):
                return {"entries": result}
            if isinstance(result, dict):
                return result
    # Fallback to plain text (always works)
    _, out2, _ = _run(["olevba", filepath])
    return {"raw_text": out2[:8000]} if out2 else {}


def run_oledump(filepath: str) -> str:
    rc, out, _ = _run(["oledump.py", filepath], timeout=60)
    return out[:3000] if (rc in (0, 1) and out) else ""


def parse_verdict(olevba_data: dict) -> dict:
    indicators: list[str] = []
    auto_exec: list[str] = []
    suspicious_lines: list[str] = []
    has_macro = False

    entries = olevba_data.get("entries", [])
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, dict):
                continue

            # Macro presence
            if entry.get("type") in ("VBA", "VBA_P-code", "pcode"):
                has_macro = True

            # Indicators list (various olevba versions use different keys)
            for ind_key in ("indicators", "flags", "keywords"):
                ind_list = entry.get(ind_key, [])
                if not isinstance(ind_list, list):
                    continue
                for ind in ind_list:
                    # ind may be dict {"name": "...", "risk": "..."} or plain string
                    name = ind.get("name", ind.get("keyword", "")) if isinstance(ind, dict) else str(ind)
                    if not name:
                        continue
                    if name in AUTO_EXEC_TRIGGERS:
                        if name not in auto_exec:
                            auto_exec.append(name)
                        indicators.append(f"AUTO_EXEC:{name}")
                    if name in SUSPICIOUS_APIS:
                        indicators.append(f"SUSPICIOUS_API:{name}")

            # Scan VBA code text for suspicious calls
            code = entry.get("code", entry.get("vba_code", ""))
            if not isinstance(code, str):
                code = ""
            for line in code.splitlines():
                ls = line.strip()
                if any(api.lower() in ls.lower() for api in SUSPICIOUS_APIS):
                    if ls and ls not in suspicious_lines:
                        suspicious_lines.append(ls[:200])

    # Fallback: parse raw text output
    raw = olevba_data.get("raw_text", "")
    if raw:
        if "VBA MACRO" in raw or "VBA FORM" in raw:
            has_macro = True
        for trigger in AUTO_EXEC_TRIGGERS:
            if trigger in raw and f"AUTO_EXEC:{trigger}" not in indicators:
                auto_exec.append(trigger)
                indicators.append(f"AUTO_EXEC:{trigger}")
        for api in SUSPICIOUS_APIS:
            if api in raw and f"SUSPICIOUS_API:{api}" not in indicators:
                indicators.append(f"SUSPICIOUS_API:{api}")

    return {
        "has_macro": has_macro,
        "auto_exec_triggers": list(dict.fromkeys(auto_exec)),
        "indicators": list(dict.fromkeys(indicators)),
        "suspicious_lines": suspicious_lines[:30],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Office document malware analyzer (VBA macros, OLE streams, auto-exec)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Supported formats:
  OLE2 binary : .doc .dot .xls .xlt .ppt
  OOXML/ZIP   : .docx .docm .dotm .xlsx .xlsm .xltm .pptx .pptm
  Other       : .rtf .msg .mhtml .mht
  (auto-detected by magic bytes if extension is missing/wrong)

Examples:
  python office_analyzer.py invoice.doc --output-dir /tmp/output
  python office_analyzer.py suspicious.xlsm --output-dir /tmp/output
  python office_analyzer.py unknown_file --output-dir /tmp/output --force

Output: <stem>_office.json
  .verdict.risk              HIGH | LOW
  .verdict.has_macro         boolean
  .verdict.auto_exec_triggers list of triggered auto-exec names
  .verdict.indicators        all detected indicators
  .suspicious_lines          VBA code lines that reference suspicious APIs
""",
    )
    parser.add_argument("filepath", help="Office document to analyze")
    parser.add_argument("--output-dir", default="/tmp/output", metavar="DIR",
                        help="Output directory (default: /tmp/output inside container)")
    parser.add_argument("--force", action="store_true",
                        help="Analyze even if extension/magic bytes not recognized as Office")
    args = parser.parse_args()

    filepath = Path(args.filepath)
    if not filepath.exists():
        print(f"✗ File not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    if not filepath.is_file():
        print(f"✗ Not a file: {filepath}", file=sys.stderr)
        sys.exit(1)

    if not args.force and not detect_office(filepath):
        print(f"✗ {filepath.name} does not look like an Office document.", file=sys.stderr)
        print("  Recognized: .doc .xls .ppt .docx .xlsm .rtf .msg .pptm ...", file=sys.stderr)
        print("  Use --force to analyze anyway.", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    bname = filepath.stem

    print(f"→ Office Analysis: {filepath.name}")

    oleid  = run_oleid(str(filepath))
    olevba = run_olevba(str(filepath))
    oledump_txt = run_oledump(str(filepath))
    verdict = parse_verdict(olevba)

    risk = "HIGH" if (verdict["has_macro"] or verdict["auto_exec_triggers"]) else "LOW"

    output = {
        "tool":      "oletools",
        "version":   TOOL_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "file":      filepath.name,
        "verdict": {
            "risk":                risk,
            "has_macro":           verdict["has_macro"],
            "auto_exec_triggers":  verdict["auto_exec_triggers"],
            "indicators":          verdict["indicators"],
        },
        "suspicious_lines": verdict["suspicious_lines"],
        "oleid":            oleid,
        "olevba":           olevba,
        "oledump_summary":  oledump_txt,
    }

    out_path = output_dir / f"{bname}_office.json"
    try:
        out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError as e:
        print(f"✗ Could not write output: {e}", file=sys.stderr)
        sys.exit(1)

    # --- Summary ---
    risk_label = f"[RISK: {risk}]"
    print(f"\n{risk_label}")
    print(f"  Has macro       : {verdict['has_macro']}")
    if verdict["auto_exec_triggers"]:
        print(f"  Auto-exec       : {', '.join(verdict['auto_exec_triggers'])}")
    if verdict["indicators"]:
        for ind in verdict["indicators"][:8]:
            print(f"  [!] {ind}")
    if verdict["suspicious_lines"]:
        print(f"\nSuspicious VBA code lines (top 8):")
        for line in verdict["suspicious_lines"][:8]:
            print(f"  {line}")
    print(f"\nSaved: {out_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
