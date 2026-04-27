#!/usr/bin/env python3
"""Office document malware analyzer using oletools (runs inside container).

Extracts VBA macros, OLE streams, and auto-exec triggers from Office files:
  .doc/.xls/.ppt (OLE2), .docx/.xlsm/.docm (OOXML), .rtf, .msg

Usage (inside container):
    python office_analyzer.py <file_path> --output-dir /tmp/output
    python office_analyzer.py doc.enc.gz --output-dir /tmp/output   # auto-decrypted
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

TOOL_VERSION = "1.0.0"

OFFICE_EXTENSIONS = {
    ".doc", ".dot", ".xls", ".xlt", ".ppt",
    ".docx", ".docm", ".dotm", ".xlsx", ".xlsm", ".xltm",
    ".pptx", ".pptm", ".rtf", ".msg", ".mhtml",
}
OLE_MAGIC = b"\xd0\xcf\x11\xe0"
OOXML_MAGIC = b"PK\x03\x04"
RTF_MAGIC = b"{\\rtf"

AUTO_EXEC_TRIGGERS = (
    "AutoOpen", "AutoClose", "AutoExec", "AutoNew", "AutoExit",
    "Document_Open", "Document_Close", "Workbook_Open", "Workbook_BeforeClose",
    "Auto_Open", "Auto_Close",
)
SUSPICIOUS_APIS = (
    "Shell", "CreateObject", "GetObject", "WScript.Shell",
    "PowerShell", "cmd.exe", "environ", "Chr(", "ChrW(",
    "CallByName", "Execute", "Eval",
)


def is_office_file(path: Path) -> bool:
    if path.suffix.lower() in OFFICE_EXTENSIONS:
        return True
    try:
        header = path.read_bytes()[:5]
        return header[:4] in (OLE_MAGIC, OOXML_MAGIC) or header == RTF_MAGIC
    except (IOError, PermissionError):
        return False


def _run(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -2, "", f"not found: {cmd[0]}"


def run_oleid(filepath: str) -> dict:
    rc, out, _ = _run(["oleid", "--json", filepath])
    if rc == 0 and out.strip():
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            pass
    return {}


def run_olevba(filepath: str) -> dict:
    rc, out, err = _run(["olevba", "--json", filepath])
    if rc in (0, 1, 2) and out.strip():
        try:
            data = json.loads(out)
            return data if isinstance(data, dict) else {"entries": data}
        except json.JSONDecodeError:
            pass
    # Fallback: plain text output
    rc2, out2, _ = _run(["olevba", filepath])
    return {"raw_text": out2[:5000]} if out2 else {}


def run_oledump(filepath: str) -> str:
    rc, out, _ = _run(["oledump.py", filepath], timeout=60)
    return out[:3000] if out else ""


def parse_vba_verdict(olevba_data: dict) -> dict:
    indicators: list[str] = []
    has_macro = False
    auto_exec = []
    suspicious_lines: list[str] = []

    entries = olevba_data.get("entries", [])
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            # olevba JSON structure varies by version; handle both styles
            indicators_list = entry.get("indicators", entry.get("flags", []))
            for ind in indicators_list:
                name = ind.get("name", ind.get("keyword", "")) if isinstance(ind, dict) else str(ind)
                if "macro" in name.lower():
                    has_macro = True
                    indicators.append("VBA_MACRO")
                if name in AUTO_EXEC_TRIGGERS:
                    auto_exec.append(name)
                    indicators.append(f"AUTO_EXEC:{name}")
                if name in SUSPICIOUS_APIS:
                    indicators.append(f"SUSPICIOUS_API:{name}")

            code = entry.get("code", entry.get("vba_code", ""))
            for line in code.splitlines():
                ls = line.strip()
                if any(api.lower() in ls.lower() for api in SUSPICIOUS_APIS):
                    suspicious_lines.append(ls[:200])

    # Also check raw_text fallback
    raw = olevba_data.get("raw_text", "")
    if raw:
        has_macro = has_macro or "VBA MACRO" in raw
        for trigger in AUTO_EXEC_TRIGGERS:
            if trigger in raw and f"AUTO_EXEC:{trigger}" not in indicators:
                auto_exec.append(trigger)
                indicators.append(f"AUTO_EXEC:{trigger}")

    return {
        "has_macro": has_macro,
        "auto_exec_triggers": list(dict.fromkeys(auto_exec)),
        "indicators": list(dict.fromkeys(indicators)),
        "suspicious_lines": suspicious_lines[:30],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Office document malware analyzer")
    parser.add_argument("filepath", help="Office document to analyze")
    parser.add_argument("--output-dir", default="/tmp/output")
    parser.add_argument("--force", action="store_true", help="Analyze even if extension unknown")
    args = parser.parse_args()

    filepath = Path(args.filepath)
    if not filepath.is_file():
        print(f"Error: File not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    if not args.force and not is_office_file(filepath):
        print(f"[!] {filepath.name} does not appear to be an Office document.")
        print("    Extensions: .doc .xls .ppt .docx .xlsm .docm .rtf .msg")
        print("    Use --force to analyze anyway.")
        sys.exit(0)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    bname = filepath.stem

    print(f"=== Office Malware Analysis: {filepath.name} ===")

    oleid = run_oleid(str(filepath))
    olevba = run_olevba(str(filepath))
    oledump_summary = run_oledump(str(filepath))
    verdict = parse_vba_verdict(olevba)

    risk = "HIGH" if verdict["has_macro"] or verdict["auto_exec_triggers"] else "LOW"

    output = {
        "tool": "oletools",
        "version": TOOL_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "file": filepath.name,
        "verdict": {
            "risk": risk,
            "has_macro": verdict["has_macro"],
            "auto_exec_triggers": verdict["auto_exec_triggers"],
            "indicators": verdict["indicators"],
        },
        "suspicious_lines": verdict["suspicious_lines"],
        "oleid": oleid,
        "olevba": olevba,
        "oledump_summary": oledump_summary,
    }

    out_path = output_dir / f"{bname}_office.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"[*] Saved: {out_path}")

    print(f"\nVerdict: {risk}")
    for ind in verdict["indicators"][:10]:
        print(f"  [!] {ind}")
    if verdict["suspicious_lines"]:
        print("\nSuspicious VBA lines (top 10):")
        for line in verdict["suspicious_lines"][:10]:
            print(f"  {line}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
