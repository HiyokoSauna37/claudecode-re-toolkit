#!/usr/bin/env python3
"""
js_deobfuscate.py - JavaScript deobfuscation & ClickFix pattern analyzer

Analyzes obfuscated JavaScript files and extracts:
- Decoded string arrays (Base64/hex/unicode)
- XOR+Base64 obfuscation (ClearFake / BW-style)
- ClickFix indicators (clipboard, Terminal, reCAPTCHA, shell commands)
- ClearFake blockchain C2 patterns (Polygon contract, mode map, API key)
- Language support detection
- IOCs (domains, IPs, URLs, file paths)

Usage:
    python3 js_deobfuscate.py <file.js>              # analyze local file
    python3 js_deobfuscate.py --url <URL>            # fetch URL (no disk write)
    python3 js_deobfuscate.py <file.enc.gz>          # decrypt quarantine file first
    python3 js_deobfuscate.py - < input.js           # read from stdin
    python3 js_deobfuscate.py <file> --json          # JSON output
    python3 js_deobfuscate.py <file> --ioc-only      # IOCs only
"""

import argparse
import base64
import json
import re
import sys

from _jslib import (
    load_js_source,
    unwrap_html_pre,
    decode_xor_base64,
    extract_clearfake_config,
)


def decode_hex_escapes(s: str) -> str:
    """Decode \\x20, \\xNN hex escapes in a string."""
    def _replace(m):
        return chr(int(m.group(1), 16))
    return re.sub(r'\\x([0-9a-fA-F]{2})', _replace, s)


def decode_unicode_escapes(s: str) -> str:
    """Decode \\uNNNN unicode escapes."""
    def _replace(m):
        return chr(int(m.group(1), 16))
    return re.sub(r'\\u([0-9a-fA-F]{4})', _replace, s)


def try_base64_decode(s: str) -> str | None:
    """Try to decode a Base64 string. Returns decoded text or None."""
    if len(s) < 4:
        return None
    try:
        # Standard Base64
        decoded = base64.b64decode(s + '=' * (4 - len(s) % 4) if len(s) % 4 else s)
        text = decoded.decode('utf-8', errors='strict')
        # Heuristic: if mostly printable, it's valid
        printable_ratio = sum(1 for c in text if c.isprintable() or c in '\n\r\t') / max(len(text), 1)
        if printable_ratio > 0.8:
            return text
    except Exception:
        pass
    return None


def extract_string_array(js: str) -> list[str]:
    """Extract the obfuscator.io string array (large array of encoded strings)."""
    strings = []

    # Pattern 1: var _0xNNNN = ['str1', 'str2', ...]
    # Pattern 2: return ['str1', 'str2', ...];  (inside function)
    array_patterns = [
        r"(?:var\s+_0x[a-f0-9]+\s*=\s*|return\s+)\[([^\]]{200,})\]",
    ]

    for pat in array_patterns:
        for m in re.finditer(pat, js):
            raw = m.group(1)
            # Extract individual strings
            for sm in re.finditer(r"'([^']*)'", raw):
                s = sm.group(1)
                decoded = decode_hex_escapes(s)
                decoded = decode_unicode_escapes(decoded)
                strings.append(decoded)

    # Also extract inline hex-escaped strings throughout the code
    for m in re.finditer(r"'((?:\\x[0-9a-fA-F]{2}|[^']){4,})'", js):
        s = m.group(1)
        if '\\x' in s:
            decoded = decode_hex_escapes(s)
            decoded = decode_unicode_escapes(decoded)
            if decoded not in strings:
                strings.append(decoded)

    return strings


def detect_clickfix_patterns(js: str, strings: list[str]) -> dict:
    """Detect ClickFix-specific patterns in code and decoded strings."""
    all_text = js + '\n' + '\n'.join(strings)

    indicators = {
        'is_clickfix': False,
        'target_os': [],
        'clipboard_method': [],
        'social_engineering': [],
        'shell_commands': [],
        'languages': [],
        'fake_captcha': False,
        'terminal_instructions': False,
        'history_clearing': False,
        'ab_testing': False,
        'wordpress_targeting': False,
        'tracking_endpoint': None,
    }

    # OS targeting
    if re.search(r'Macintosh', all_text, re.I):
        indicators['target_os'].append('macOS')
    if re.search(r'Windows\s*NT|Win32|Win64', all_text, re.I):
        indicators['target_os'].append('Windows')
    if re.search(r'iPad|iPhone|iPod', all_text, re.I):
        indicators['target_os'].append('iOS (excluded)')

    # Clipboard methods
    if 'clipboard' in all_text and 'writeText' in all_text:
        indicators['clipboard_method'].append('navigator.clipboard.writeText')
    if 'execCommand' in all_text:
        indicators['clipboard_method'].append('document.execCommand("copy")')

    # Social engineering
    if re.search(r'reCAPTCHA|captcha|CAPTCHA', all_text):
        indicators['fake_captcha'] = True
        indicators['social_engineering'].append('Fake reCAPTCHA')
    if re.search(r'Terminal|terminal\.app', all_text, re.I):
        indicators['terminal_instructions'] = True
        indicators['social_engineering'].append('Terminal instructions')
    if re.search(r'PowerShell|powershell', all_text):
        indicators['social_engineering'].append('PowerShell instructions')
    if re.search(r'Win\+R|Win\s*\+\s*R|Run\s*dialog', all_text, re.I):
        indicators['social_engineering'].append('Win+R Run dialog')
    if re.search(r'Spotlight|⌘\s*\+?\s*Space', all_text):
        indicators['social_engineering'].append('macOS Spotlight')

    # Shell commands
    shell_patterns = [
        (r'base64\s*-[dD]?\s*\|\s*/bin/sh', 'base64 pipe to /bin/sh'),
        (r'base64\s*-[dD]?\s*\|\s*bash', 'base64 pipe to bash'),
        (r'curl\s+.*\|\s*(?:bash|sh|zsh)', 'curl pipe to shell'),
        (r'Invoke-(?:Expression|WebRequest)', 'PowerShell IEX/IWR'),
        (r'iex\s*\(', 'PowerShell iex'),
        (r'rm\s+-f\b', 'file deletion (rm -f)'),
        (r'history\s+-d|fc\s+-p', 'history clearing'),
    ]
    for pat, desc in shell_patterns:
        if re.search(pat, all_text, re.I):
            indicators['shell_commands'].append(desc)
            if 'history' in desc:
                indicators['history_clearing'] = True

    # Language detection
    lang_pattern = r"'([a-z]{2}(?:-[a-z]+)?)'\s*:\s*\{\s*'(?:botProtection|bot_protection|title|step1|header)'"
    langs = re.findall(lang_pattern, all_text)
    if langs:
        indicators['languages'] = sorted(set(langs))

    # A/B testing
    if '__abVariant' in all_text or 'abVariant' in all_text or 'variant' in all_text.lower():
        if re.search(r'__abVariant|ab_variant|abtest', all_text, re.I):
            indicators['ab_testing'] = True

    # WordPress targeting
    if 'wp-login' in all_text or 'wp-admin' in all_text or 'wordpress' in all_text.lower():
        indicators['wordpress_targeting'] = True

    # Tracking endpoint
    collect_match = re.search(r"['\"](/collect)['\"]", all_text)
    if collect_match:
        indicators['tracking_endpoint'] = collect_match.group(1)

    # Overall ClickFix determination
    if (indicators['clipboard_method'] and
        (indicators['fake_captcha'] or indicators['terminal_instructions']) and
        indicators['shell_commands']):
        indicators['is_clickfix'] = True

    return indicators


def extract_iocs(js: str, strings: list[str]) -> dict:
    """Extract IOCs from JS source and decoded strings."""
    all_text = js + '\n' + '\n'.join(strings)

    iocs = {
        'domains': [],
        'ips': [],
        'urls': [],
        'emails': [],
        'paths': [],
        'base64_payloads': [],
    }

    # URLs
    url_pattern = r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'
    for m in re.finditer(url_pattern, all_text):
        url = m.group(0).rstrip("'\")")
        if url not in iocs['urls'] and len(url) > 10:
            # Skip common CDN/legitimate URLs
            if not any(safe in url for safe in ['google.com/recaptcha', 'gstatic.com', 'googleapis.com', 'w3.org']):
                iocs['urls'].append(url)

    # IPs
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)\b'
    for m in re.finditer(ip_pattern, all_text):
        ip = m.group(0)
        if ip not in iocs['ips'] and not ip.startswith('0.') and not ip.startswith('127.'):
            iocs['ips'].append(ip)

    # Domains from strings (more targeted)
    domain_pattern = r'\b([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.(?:icu|top|xyz|shop|pw|cc|tk|ml|ga|cf|gq|buzz|live|club|online|site|fun|space|info|io|co|me|dev))\b'
    for m in re.finditer(domain_pattern, all_text, re.I):
        d = m.group(1).lower()
        if d not in iocs['domains']:
            iocs['domains'].append(d)

    # Base64 payloads (long strings that decode to something)
    b64_pattern = r'[A-Za-z0-9+/]{40,}={0,2}'
    for m in re.finditer(b64_pattern, all_text):
        candidate = m.group(0)
        decoded = try_base64_decode(candidate)
        if decoded and len(decoded) > 20:
            iocs['base64_payloads'].append({
                'encoded_preview': candidate[:80] + '...' if len(candidate) > 80 else candidate,
                'decoded_preview': decoded[:200] + '...' if len(decoded) > 200 else decoded,
            })

    # File paths
    path_pattern = r'(?:/(?:bin|usr|tmp|etc|var|opt|home)/[a-zA-Z0-9_./-]+|[A-Z]:\\\\[a-zA-Z0-9_.\\/-]+)'
    for m in re.finditer(path_pattern, all_text):
        p = m.group(0)
        if p not in iocs['paths']:
            iocs['paths'].append(p)

    return iocs


def extract_interesting_strings(strings: list[str]) -> list[str]:
    """Filter decoded strings to only interesting ones (skip noise)."""
    interesting = []
    skip_patterns = [
        r'^[a-zA-Z0-9]{1,3}$',  # Very short strings
        r'^0x[0-9a-f]+$',       # Hex numbers
        r'^[0-9]+$',            # Pure numbers
        r'^_0x',                # Obfuscator variable names
    ]

    for s in strings:
        if len(s) < 3:
            continue
        if any(re.match(p, s) for p in skip_patterns):
            continue
        # Keep strings with readable content
        if any(c.isalpha() for c in s) and len(s) >= 4:
            interesting.append(s)

    return interesting


def analyze_file(filepath: str | None = None, json_output: bool = False,
                 strings_only: bool = False, ioc_only: bool = False,
                 url: str | None = None) -> dict:
    """Main analysis function."""
    try:
        js, source_name = load_js_source(filepath, url)
    except (FileNotFoundError, RuntimeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    js = unwrap_html_pre(js)

    # Attempt XOR+Base64 decode (ClearFake/BW-style loaders)
    xor_decoded, xor_key = decode_xor_base64(js)
    if xor_decoded:
        js = xor_decoded

    strings = extract_string_array(js)
    interesting = extract_interesting_strings(strings)
    clearfake = extract_clearfake_config(js)

    result = {
        'file': source_name,
        'size': len(js),
        'xor_decoded': xor_key is not None,
        'xor_key': xor_key,
        'total_strings_extracted': len(strings),
        'interesting_strings': len(interesting),
        'clearfake': clearfake,
    }

    if strings_only:
        result['strings'] = interesting
        if json_output:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            for s in interesting:
                print(s)
        return result

    # ClickFix detection
    clickfix = detect_clickfix_patterns(js, strings)
    result['clickfix'] = clickfix

    # IOC extraction
    iocs = extract_iocs(js, strings)
    result['iocs'] = iocs

    if ioc_only:
        if json_output:
            print(json.dumps({'iocs': iocs}, ensure_ascii=False, indent=2))
        else:
            for category, items in iocs.items():
                if items:
                    print(f"\n=== {category} ===")
                    for item in items:
                        if isinstance(item, dict):
                            print(f"  {json.dumps(item, ensure_ascii=False)}")
                        else:
                            print(f"  {item}")
        return result

    # Full analysis output
    if json_output:
        result['strings_sample'] = interesting[:50]
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_report(result, interesting)

    return result


def print_clearfake_section(cf: dict):
    """Print ClearFake-specific findings."""
    if not cf.get('is_clearfake'):
        return
    print(f"\n  \033[31m[!] CLEARFAKE BLOCKCHAIN C2 DETECTED\033[0m")
    if cf.get('contract_address'):
        print(f"  Contract (Polygon): {cf['contract_address']}")
    if cf.get('function_selector'):
        print(f"  Function Selector:  0x{cf['function_selector']}")
    if cf.get('api_key_hex'):
        print(f"  API Key (RC4/GCM):  {cf['api_key_hex']}")
    if cf.get('storage_key'):
        print(f"  localStorage Key:   {cf['storage_key']}")
    if cf.get('mode_map'):
        print(f"  Mode Map:")
        for mode, script in cf['mode_map'].items():
            print(f"    {mode:15s} → {script}")
    if cf.get('rpc_hosts'):
        print(f"  Polygon RPCs ({len(cf['rpc_hosts'])}):")
        for h in cf['rpc_hosts'][:4]:
            print(f"    {h}")


def print_report(result: dict, strings: list[str]):
    """Print human-readable analysis report."""
    cf = result.get('clickfix', {})
    iocs = result.get('iocs', {})
    clearfake = result.get('clearfake', {})

    print(f"\033[1m\033[36m{'='*60}\033[0m")
    print(f"\033[1m\033[36m  JS Deobfuscation & ClickFix Analysis\033[0m")
    print(f"\033[1m\033[36m{'='*60}\033[0m")
    print(f"  Source: {result['file']}")
    print(f"  Size: {result['size']:,} bytes")
    if result.get('xor_decoded'):
        print(f"  \033[33m[XOR+Base64 decoded] key={result['xor_key']}\033[0m")
    print(f"  Strings extracted: {result['total_strings_extracted']}")
    print(f"  Interesting strings: {result['interesting_strings']}")

    print_clearfake_section(clearfake)

    if cf.get('is_clickfix'):
        print(f"\n  \033[31m[!] CLICKFIX DETECTED\033[0m")
    elif clearfake.get('is_clearfake'):
        print(f"\n  \033[31m[!] CLEARFAKE LOADER (delivers ClickFix payload via blockchain)\033[0m")
    else:
        print(f"\n  \033[32m[OK] No ClickFix patterns detected\033[0m")

    if cf.get('target_os'):
        print(f"  Target OS: {', '.join(cf['target_os'])}")
    if cf.get('languages'):
        print(f"  Languages: {', '.join(cf['languages'])} ({len(cf['languages'])} total)")
    if cf.get('clipboard_method'):
        print(f"  Clipboard: {', '.join(cf['clipboard_method'])}")
    if cf.get('social_engineering'):
        print(f"  Social Engineering: {', '.join(cf['social_engineering'])}")
    if cf.get('shell_commands'):
        print(f"  Shell Commands: {', '.join(cf['shell_commands'])}")
    if cf.get('ab_testing'):
        print(f"  A/B Testing: \033[33mYes (__abVariant)\033[0m")
    if cf.get('wordpress_targeting'):
        print(f"  WordPress: \033[33mYes (wp-login detection)\033[0m")
    if cf.get('tracking_endpoint'):
        print(f"  Tracking: {cf['tracking_endpoint']}")
    if cf.get('history_clearing'):
        print(f"  History Clearing: \033[31mYes\033[0m")

    # IOCs
    for category in ['domains', 'ips', 'urls', 'paths']:
        items = iocs.get(category, [])
        if items:
            print(f"\n\033[36m  === {category.upper()} ({len(items)}) ===\033[0m")
            for item in items[:20]:
                print(f"    {item}")
            if len(items) > 20:
                print(f"    ... and {len(items) - 20} more")

    b64 = iocs.get('base64_payloads', [])
    if b64:
        print(f"\n\033[36m  === BASE64 PAYLOADS ({len(b64)}) ===\033[0m")
        for p in b64[:5]:
            print(f"    Encoded: {p['encoded_preview']}")
            print(f"    Decoded: {p['decoded_preview']}")
            print()

    # Sample interesting strings
    if strings:
        print(f"\n\033[36m  === INTERESTING STRINGS (top 30) ===\033[0m")
        for s in strings[:30]:
            # Truncate long strings
            display = s[:120] + '...' if len(s) > 120 else s
            print(f"    {display}")

    print(f"\n\033[1m\033[36m{'='*60}\033[0m")


def main():
    parser = argparse.ArgumentParser(
        description='JS deobfuscation & ClickFix/ClearFake pattern analyzer')
    parser.add_argument('file', nargs='?', default=None,
                        help='JS file (.js/.html/.enc.gz) or "-" for stdin')
    parser.add_argument('--url', '-u', metavar='URL',
                        help='Fetch URL directly (no disk write, bypasses Defender)')
    parser.add_argument('--json', action='store_true', help='JSON output')
    parser.add_argument('--strings-only', action='store_true', help='Only extract decoded strings')
    parser.add_argument('--ioc-only', action='store_true', help='Only extract IOCs')
    args = parser.parse_args()

    if not args.file and not args.url:
        parser.print_help()
        sys.exit(1)

    analyze_file(args.file, json_output=args.json,
                 strings_only=args.strings_only, ioc_only=args.ioc_only,
                 url=args.url)


if __name__ == '__main__':
    main()
