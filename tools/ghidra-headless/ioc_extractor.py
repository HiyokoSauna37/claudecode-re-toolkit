#!/usr/bin/env python3
"""
IOC Extractor for Ghidra Headless output files.

Extracts IOCs (Indicators of Compromise) from Ghidra output:
- IPv4 addresses, domains, URLs, email addresses
- BTC wallets, .onion addresses
- Registry keys, Windows file paths
- Hash values (MD5, SHA1, SHA256)

Usage:
    python ioc_extractor.py <binary_name>
    python ioc_extractor.py stealc --output-dir /path/to/output
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

TOOL_VERSION = "1.0.0"
SCRIPT_DIR = Path(__file__).parent
DEFAULT_OUTPUT_DIR = SCRIPT_DIR / "output"

# Ensure shared modules are importable
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

# =============================================================================
# Regex Patterns
# =============================================================================

PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|io|info|biz|co|uk|de|ru|cn|jp|kr|fr|it|nl|"
        r"au|ca|br|in|mx|es|se|no|fi|dk|pl|cz|sk|hu|ro|bg|hr|si|"
        r"xyz|top|club|online|site|tech|shop|pro|cc|tv|me|us|gov|mil|edu|"
        r"ai|app|dev|cloud|link|pw|tk|ga|cf|ml|gq)\b",
        re.IGNORECASE,
    ),
    "url": re.compile(
        r"https?://[^\s<>\"')\],]+[^\s<>\"')\],.\!?;:]"
    ),
    "email": re.compile(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    ),
    "btc_wallet": re.compile(
        r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{39,59})\b"
    ),
    "onion": re.compile(
        r"\b[a-z2-7]{16,56}\.onion\b", re.IGNORECASE
    ),
    "registry_key": re.compile(
        r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|"
        r"HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)"
        r"\\[^\s\"']{5,}\b"
    ),
    "windows_path": re.compile(
        r"\b[A-Z]:\\(?:[^\s\\\"'<>|]{1,}\\)*[^\s\\\"'<>|]{1,}\.[a-zA-Z0-9]{1,10}\b"
    ),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
}

# =============================================================================
# False Positive Filters
# =============================================================================

# Ghidra-generated artifacts
GHIDRA_ARTIFACTS = re.compile(
    r"^(?:FUN_|DAT_|LAB_|PTR_|EXT_|thunk_|CONCAT|case_|switchD_|s_|u_|SUB_)"
)

# Private/reserved IP ranges
PRIVATE_IP_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "0.", "255.",
    "169.254.",
)

# C runtime / compiler strings to ignore
C_RUNTIME_STRINGS = {
    "bad allocation", "bad function call", "string too long",
    "invalid argument", "out of range", "bad cast",
    "bad typeid", "bad exception", "bad array new length",
    "overflow error", "underflow error", "domain error",
    "length error", "runtime error", "logic error",
    "system_error", "bad_alloc", "bad_cast",
}

# Common benign domains (includes .NET namespace false positives like system.io)
BENIGN_DOMAINS = {
    "microsoft.com", "windows.com", "google.com", "github.com",
    "mozilla.org", "w3.org", "xml.org", "apache.org",
    "openssl.org", "sqlite.org", "python.org",
    "sysinternals.com", "visualstudio.com",
    # .NET namespace false positives (appear as domains in C# source)
    "system.io", "system.net", "system.text", "system.threading",
    "system.collections", "system.diagnostics", "system.runtime",
    "system.security", "system.reflection", "system.componentmodel",
    "system.linq", "system.globalization", "system.resources",
}

# Hash false positive patterns
HASH_FP = re.compile(r"^0{8,}$|^f{8,}$|^a{8,}$|^[0-9]+$", re.IGNORECASE)


def is_private_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in PRIVATE_IP_PREFIXES)


def is_hash_false_positive(value: str) -> bool:
    if HASH_FP.match(value):
        return True
    if len(set(value.lower())) <= 2:
        return True
    return False


def is_benign_domain(domain: str) -> bool:
    d = domain.lower()
    if d in BENIGN_DOMAINS:
        return True
    return any(d.endswith("." + bd) for bd in BENIGN_DOMAINS)


def is_ghidra_artifact(text: str) -> bool:
    return bool(GHIDRA_ARTIFACTS.match(text))


# =============================================================================
# File Discovery
# =============================================================================

from ghidra_output_utils import find_ghidra_outputs  # shared utility


# =============================================================================
# IOC Extraction
# =============================================================================

def is_c_runtime_line(line: str) -> bool:
    """Check if a line is a C runtime / compiler string (false positive source)."""
    lower = line.strip().lower()
    return any(crt in lower for crt in C_RUNTIME_STRINGS)


def extract_iocs(text: str) -> dict:
    """Extract all IOC types from text, with dedup and false positive filtering."""
    # Pre-compute C runtime lines to skip (these produce domain/email false positives)
    crt_ranges = set()
    for i, line in enumerate(text.splitlines()):
        if is_c_runtime_line(line):
            crt_ranges.add(i)

    results = {}
    seen = set()

    def add(ioc_type: str, value: str):
        key = (ioc_type, value.lower())
        if key not in seen:
            seen.add(key)
            results.setdefault(ioc_type, []).append(value)

    # SHA-256
    for m in PATTERNS["sha256"].finditer(text):
        v = m.group()
        if not is_hash_false_positive(v):
            add("sha256", v.lower())

    sha256_vals = {v for v in results.get("sha256", [])}

    # SHA-1 (exclude SHA-256 substrings)
    for m in PATTERNS["sha1"].finditer(text):
        v = m.group()
        if is_hash_false_positive(v):
            continue
        if any(v.lower() in s for s in sha256_vals):
            continue
        add("sha1", v.lower())

    sha1_vals = {v for v in results.get("sha1", [])}
    longer = sha256_vals | sha1_vals

    # MD5 (exclude longer hash substrings)
    for m in PATTERNS["md5"].finditer(text):
        v = m.group()
        if is_hash_false_positive(v):
            continue
        if any(v.lower() in s for s in longer):
            continue
        add("md5", v.lower())

    # URLs
    for m in PATTERNS["url"].finditer(text):
        url = m.group()
        if not any(bd in url.lower() for bd in BENIGN_DOMAINS):
            add("url", url)

    url_vals = {v.lower() for v in results.get("url", [])}

    # IPv4
    for m in PATTERNS["ipv4"].finditer(text):
        ip = m.group()
        if not is_private_ip(ip):
            # Skip version-like patterns (X.Y.Z.0 where all < 20)
            octets = [int(o) for o in ip.split(".")]
            if octets[3] == 0 and all(o <= 20 for o in octets):
                continue
            add("ipv4", ip)

    # Domains (skip if already part of URL or in C runtime context)
    for m in PATTERNS["domain"].finditer(text):
        domain = m.group().lower()
        if is_benign_domain(domain):
            continue
        if any(domain in u for u in url_vals):
            continue
        # Skip matches within C runtime string lines
        line_num = text[:m.start()].count("\n")
        if line_num in crt_ranges:
            continue
        # Skip Ghidra artifact context
        start = max(0, m.start() - 20)
        context = text[start:m.start()]
        if is_ghidra_artifact(context.split()[-1] if context.split() else ""):
            continue
        add("domain", domain)

    # Email
    for m in PATTERNS["email"].finditer(text):
        email = m.group()
        if not any(bd in email.lower() for bd in BENIGN_DOMAINS):
            add("email", email)

    # BTC Wallets
    for m in PATTERNS["btc_wallet"].finditer(text):
        add("btc_wallet", m.group())

    # .onion addresses
    for m in PATTERNS["onion"].finditer(text):
        add("onion", m.group().lower())

    # Registry keys
    for m in PATTERNS["registry_key"].finditer(text):
        key = m.group()
        # Include keys that are NOT under \Classes\ (generic registry IOCs),
        # but also include \Classes\ keys if they reference CLSID (COM hijacking indicator).
        # This filters out noisy HKCR file association entries while keeping suspicious ones.
        if "\\Classes\\" not in key or "CLSID" in key:
            add("registry_key", key)

    # Windows file paths (filter Ghidra artifacts and C runtime)
    for m in PATTERNS["windows_path"].finditer(text):
        path = m.group()
        basename = path.split("\\")[-1].lower()
        if basename in {"kernel32.dll", "ntdll.dll", "msvcrt.dll", "user32.dll",
                        "advapi32.dll", "ws2_32.dll", "ole32.dll", "shell32.dll",
                        "gdi32.dll", "comctl32.dll"}:
            continue
        add("windows_path", path)

    return results


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Extract IOCs from Ghidra Headless output files"
    )
    parser.add_argument("binary_name", help="Binary name (without extension suffixes)")
    parser.add_argument(
        "--output-dir", "-o",
        default=str(DEFAULT_OUTPUT_DIR),
        help=f"Ghidra output directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument("--json-only", action="store_true", help="Output JSON only")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    files = find_ghidra_outputs(args.binary_name, output_dir)

    if not files:
        print(f"Error: No Ghidra output files found for '{args.binary_name}' in {output_dir}", file=sys.stderr)
        print(f"  Looked for: {args.binary_name}_strings.txt, {args.binary_name}_imports.txt, etc.", file=sys.stderr)
        sys.exit(1)

    # Read all files
    all_text = []
    sources = []
    for key, path in files.items():
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            all_text.append(content)
            sources.append({"type": key, "path": str(path), "size": len(content)})
        except Exception as e:
            print(f"Warning: Failed to read {path}: {e}", file=sys.stderr)

    combined = "\n".join(all_text)
    iocs = extract_iocs(combined)

    # Build output JSON
    total_count = sum(len(v) for v in iocs.values())
    output = {
        "binary_name": args.binary_name,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
        "tool_version": TOOL_VERSION,
        "sources": sources,
        "total_iocs": total_count,
        "iocs": iocs,
    }

    # Write JSON
    json_path = output_dir / f"{args.binary_name}_iocs.json"
    json_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")

    if args.json_only:
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return

    # Human-readable summary
    print(f"{'='*60}")
    print(f"IOC Extraction: {args.binary_name}")
    print(f"{'='*60}")
    print(f"Sources: {len(sources)} files")
    for s in sources:
        print(f"  - {s['type']}: {Path(s['path']).name}")
    print(f"\nTotal IOCs: {total_count}")
    print(f"{'='*60}")

    type_labels = {
        "ipv4": "IPv4 Addresses",
        "domain": "Domains",
        "url": "URLs",
        "email": "Email Addresses",
        "btc_wallet": "BTC Wallets",
        "onion": "Onion Addresses",
        "registry_key": "Registry Keys",
        "windows_path": "Windows File Paths",
        "sha256": "SHA-256 Hashes",
        "sha1": "SHA-1 Hashes",
        "md5": "MD5 Hashes",
    }

    for ioc_type, label in type_labels.items():
        values = iocs.get(ioc_type, [])
        if values:
            print(f"\n[{label}] ({len(values)})")
            for v in values[:20]:  # Limit display
                print(f"  {v}")
            if len(values) > 20:
                print(f"  ... and {len(values) - 20} more")

    print(f"\nJSON output: {json_path}")


if __name__ == "__main__":
    main()
