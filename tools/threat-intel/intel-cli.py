#!/usr/bin/env python3
"""threat-intel CLI: friendly OSINT / threat-intelligence dispatcher.

Smart mode (recommended) — auto-detects input type:
    intel-cli.py 8.8.8.8                      → IP correlation
    intel-cli.py 44d88612fea8a8f36de82e1278abb02f  → hash correlation
    intel-cli.py example.com                  → domain workflow
    intel-cli.py CVE-2024-3400                → CVE workflow (NIST + VulnCheck)
    intel-cli.py https://malicious.example/   → URL submit + VT lookup
    intel-cli.py /path/to/report.pdf          → IOC extraction

Inspect what's available:
    intel-cli.py status                       → API key status per service
    intel-cli.py cache stats                  → SQLite cache size

Aliases for the smart workflows (skip auto-detect):
    intel-cli.py hash <h>     intel-cli.py ip <ip>
    intel-cli.py cve <cve>    intel-cli.py url <url>
    intel-cli.py domain <d>   intel-cli.py file <path>

Specific service queries (when you know exactly what you want):
    intel-cli.py vt {hash|ip|domain|url|behavior} <value>
    intel-cli.py ha hash <hash>
    intel-cli.py triage {search|summary|dynamic} <value>
    intel-cli.py bazaar hash <hash>
    intel-cli.py threatfox {ioc|recent} <value>
    intel-cli.py otx {hash|ip|domain} <value>
    intel-cli.py urlhaus {url|hash|tag|recent-urls|recent-payloads} [<value>]
    intel-cli.py urlscanio {submit|result|search|domain|ip} <value>
    intel-cli.py shodan {ip|search} <value>
    intel-cli.py abuseipdb ip <ip>
    intel-cli.py greynoise ip <ip>
    intel-cli.py ipinfo ip <ip>
    intel-cli.py bgpview ip <ip>
    intel-cli.py whois {domain|ip} <value>
    intel-cli.py nist {cve|cpe|severity|keyword|cwe} <value>
    intel-cli.py vulncheck {indexes|kev|kev-cve|mitre|mitre-cve|nvd2|nvd2-cve|backup} [<value>]
    intel-cli.py malpedia {actors|families|payloads|actor|family|yara|sample} [<value>]
    intel-cli.py malshare {list|hash} [<value>]

Other:
    intel-cli.py ioc extract <file|url>       → IOC extract (txt/pdf/eml/url)
    intel-cli.py yara <rules> <target>        → YARA scan
    intel-cli.py attack <tag1> <tag2> ...     → MITRE ATT&CK tag mapping
    intel-cli.py report html|pdf <out> [--from result.json]

Global flags (apply to any command):
    --output-format text|json|csv  (default: text)
    --proxy URL                    (HTTP/HTTPS/SOCKS5)
    --no-cache / --cache-ttl SEC   (SQLite cache)
    --quiet / --verbose
    --background 0|1               (0=light terminal, 1=dark default)
    --report html|pdf --report-file PATH
"""

import argparse
import os
import sys
from pathlib import Path

# Allow `python intel-cli.py ...` without -m
sys.path.insert(0, str(Path(__file__).resolve().parent))

from threat_intel.lib import configvars as cv  # noqa: E402
from threat_intel.lib.output import collector  # noqa: E402
from threat_intel.lib.colors import printr, mycolors  # noqa: E402
from threat_intel.lib.sanitize import (  # noqa: E402
    sanitize_hash, sanitize_ip, sanitize_domain, sanitize_url,
    sanitize_cve, sanitize_path, sanitize_tag, sanitize_general,
    sanitize_uuid,
)
from threat_intel.auto import detect as auto_detect  # noqa: E402

# Subcommands that should be parsed by argparse. If sys.argv[1] is not
# in this list and doesn't start with `-`, we inject `auto` so users can
# type `intel-cli.py 8.8.8.8` directly.
KNOWN_CMDS = {
    'auto', 'status', 'cache',
    'hash', 'ip', 'cve', 'url', 'domain', 'file',
    'vt', 'ha', 'triage', 'bazaar', 'threatfox', 'otx',
    'urlhaus', 'urlscanio', 'shodan', 'abuseipdb', 'greynoise',
    'ipinfo', 'bgpview', 'whois', 'nist', 'vulncheck',
    'malpedia', 'malshare',
    'correlate-hash', 'correlate-ip', 'ioc', 'yara', 'attack', 'report',
}


def _exit_input_error(err):
    print(f"Input error: {err}", file=sys.stderr)
    sys.exit(2)


def _check(sanitizer, value, label):
    if value is None or value == '':
        _exit_input_error(f"{label} is required")
    cleaned, err = sanitizer(value)
    if err:
        _exit_input_error(f"{label}: {err}")
    return cleaned


def _need_value(value, label):
    if value is None or value == '':
        _exit_input_error(f"{label} is required")
    return value


# ─────────────────────────────────────────────────────────────────
# Argument parser
# ─────────────────────────────────────────────────────────────────

EPILOG_MAIN = """\
EXAMPLES:
  Smart auto-detect (recommended):
    intel-cli.py 8.8.8.8                           # → IP correlation
    intel-cli.py 44d88612fea8a8f36de82e1278abb02f  # → hash correlation
    intel-cli.py example.com                       # → domain workflow
    intel-cli.py CVE-2024-3400                     # → CVE workflow
    intel-cli.py https://example.com               # → URL workflow
    intel-cli.py report.pdf                        # → IOC extract

  Status / setup:
    intel-cli.py status                            # show which API keys are set
    intel-cli.py cache stats                       # cache size + db path
    intel-cli.py cache clear                       # wipe cache

  Specific service:
    intel-cli.py vt hash <sha256>
    intel-cli.py shodan search 'apache port:80'
    intel-cli.py urlhaus tag Emotet
    intel-cli.py vulncheck kev-cve CVE-2024-3400

  JSON output for piping into other tools:
    intel-cli.py --output-format json vt hash <sha256> | jq .

  Save report:
    intel-cli.py --report html --report-file out.html vt hash <sha256>
"""


def _build_parser():
    p = argparse.ArgumentParser(
        prog='intel-cli.py',
        description='Threat-intelligence CLI: smart auto-detect + 18 OSINT services.',
        epilog=EPILOG_MAIN,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument('--output-format', choices=['text', 'json', 'csv'], default='text',
                   help='Output format (default: text with ANSI colors)')
    p.add_argument('--proxy', default='', metavar='URL',
                   help='HTTP/HTTPS/SOCKS5 proxy URL (e.g. socks5://127.0.0.1:9050)')
    p.add_argument('--no-cache', action='store_true',
                   help='Disable SQLite result cache')
    p.add_argument('--cache-ttl', type=int, default=3600, metavar='SEC',
                   help='Cache TTL in seconds (default: 3600)')
    p.add_argument('--quiet', action='store_true', help='Suppress non-essential output')
    p.add_argument('--verbose', action='store_true', help='Show debug info')
    p.add_argument('--background', type=int, choices=[0, 1], default=1,
                   help='1=dark terminal (default), 0=light')
    p.add_argument('--report', dest='report_format', choices=['', 'html', 'pdf'], default='',
                   help='Generate report after the command (use with --report-file)')
    p.add_argument('--report-file', dest='report_file', default='', metavar='PATH',
                   help='Output path for --report')

    sub = p.add_subparsers(dest='command', required=True,
                           description='Run with no arguments to see this help.')

    # ─── auto / status / cache ───
    auto_p = sub.add_parser('auto',
        help='Auto-detect input type (hash/ip/url/cve/domain/file)',
        description='Auto-detect what kind of indicator the value is and run the right workflow.',
        epilog="Aliases: simply omit `auto`, e.g. `intel-cli.py 8.8.8.8`",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    auto_p.add_argument('value', help='hash | ip | url | cve | domain | file path')

    sub.add_parser('status',
        help='Show which API keys are configured',
        description='List every supported service and whether its API key is set in .env / environment.')

    cache_p = sub.add_parser('cache',
        help='Cache management (stats / clear / prune)',
        description='Inspect or manage the SQLite result cache at ~/.threat_intel_cache.db',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="EXAMPLES:\n  intel-cli.py cache stats\n  intel-cli.py cache clear\n  intel-cli.py cache prune")
    cache_p.add_argument('action', choices=['stats', 'clear', 'prune'])

    # ─── workflow aliases ───
    for name, helptext in [
        ('hash', 'Hash correlation across VT/Bazaar/OTX/URLHaus/HA/Triage'),
        ('ip', 'IP correlation across BGPView/IPInfo/VT/OTX/Shodan/AbuseIPDB/GreyNoise'),
        ('cve', 'CVE workflow (NIST NVD + VulnCheck KEV/MITRE/NVD2)'),
        ('url', 'URL workflow (URLScan submit + VT URL lookup)'),
        ('domain', 'Domain workflow (Whois + URLScan + VT + OTX)'),
        ('file', 'IOC extract from file (txt/pdf/eml)'),
    ]:
        ap = sub.add_parser(name, help=helptext, description=helptext)
        ap.add_argument('value', help='Input value')

    # ─── correlate (explicit names, kept for back-compat) ───
    ch = sub.add_parser('correlate-hash', help='Same as `hash` alias')
    ch.add_argument('value', help='MD5 / SHA1 / SHA256')
    ci = sub.add_parser('correlate-ip', help='Same as `ip` alias')
    ci.add_argument('value', help='IPv4 / IPv6 address')

    # ─── per-service subcommands (mostly unchanged) ───
    _build_service_parsers(sub)
    return p


def _build_service_parsers(sub):
    # vt
    vt = sub.add_parser('vt', help='VirusTotal',
        description='VirusTotal API v3 queries.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="EXAMPLES:\n  vt hash <sha256>\n  vt ip 8.8.8.8\n  vt domain example.com\n  vt url https://example.com\n  vt behavior <sha256>")
    vt.add_argument('action', choices=['hash', 'ip', 'domain', 'url', 'behavior'],
                    help='hash → file lookup; ip/domain/url → indicator lookup; behavior → sandbox summary')
    vt.add_argument('value', help='value matching action')

    # ha
    ha = sub.add_parser('ha', help='Hybrid Analysis',
        description='Hybrid Analysis (Falcon Sandbox) hash search.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="EXAMPLES:\n  ha hash 44d88612fea8a8f36de82e1278abb02f")
    ha.add_argument('action', choices=['hash'])
    ha.add_argument('value', help='hash')

    # triage
    tr = sub.add_parser('triage', help='tria.ge',
        description='tria.ge sandbox queries.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="EXAMPLES:\n  triage search sha256:<h>\n  triage search 'family:emotet'\n  triage summary 220315-qxzrfsadfl\n  triage dynamic 220315-qxzrfsadfl")
    tr.add_argument('action', choices=['search', 'summary', 'dynamic'])
    tr.add_argument('value', help='search query / sample-id')

    # bazaar
    bz = sub.add_parser('bazaar', help='MalwareBazaar',
        description='MalwareBazaar sample lookup by hash.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="EXAMPLES:\n  bazaar hash <sha256>")
    bz.add_argument('action', choices=['hash'])
    bz.add_argument('value', help='hash')

    # threatfox
    tf = sub.add_parser('threatfox', help='ThreatFox',
        description='ThreatFox IOC lookup.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="EXAMPLES:\n  threatfox ioc 1.2.3.4\n  threatfox ioc malicious.example.com\n  threatfox recent 3        # 3 days")
    tf.add_argument('action', choices=['ioc', 'recent'])
    tf.add_argument('value', nargs='?', default='3', help='IOC value | days for recent (default 3)')

    # otx
    otx = sub.add_parser('otx', help='AlienVault OTX',
        description='AlienVault Open Threat Exchange.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="EXAMPLES:\n  otx hash <sha256>\n  otx ip 8.8.8.8\n  otx domain example.com")
    otx.add_argument('action', choices=['hash', 'ip', 'domain'])
    otx.add_argument('value', help='hash / IP / domain')

    # urlhaus
    uh = sub.add_parser('urlhaus', help='URLHaus',
        description='abuse.ch URLHaus URL/payload lookup.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="EXAMPLES:\n  urlhaus url https://malicious.example/x.exe\n  urlhaus hash <sha256>\n  urlhaus tag Emotet\n  urlhaus recent-urls\n  urlhaus recent-payloads")
    uh.add_argument('action', choices=['url', 'hash', 'tag', 'recent-urls', 'recent-payloads'])
    uh.add_argument('value', nargs='?', help='URL / hash / tag (omit for recent-*)')

    # urlscanio
    us = sub.add_parser('urlscanio', help='URLScan.io',
        description='URLScan.io URL scan submit / result / search.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="EXAMPLES:\n  urlscanio submit https://example.com\n  urlscanio result <uuid>\n  urlscanio search 'task.tags:phishing'\n  urlscanio domain example.com\n  urlscanio ip 1.2.3.4")
    us.add_argument('action', choices=['submit', 'result', 'search', 'domain', 'ip'])
    us.add_argument('value', help='URL / UUID / query / domain / IP')

    # shodan
    sh = sub.add_parser('shodan', help='Shodan',
        description='Shodan host & query.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="EXAMPLES:\n  shodan ip 8.8.8.8\n  shodan search 'apache port:80'\n  shodan search 'product:nginx country:JP'")
    sh.add_argument('action', choices=['ip', 'search'])
    sh.add_argument('value', help='IP / Shodan query')

    # single-arg ip lookups
    for name, helptext in [
        ('abuseipdb', 'AbuseIPDB IP reputation'),
        ('greynoise', 'GreyNoise community IP classification'),
        ('ipinfo', 'IPInfo geolocation'),
        ('bgpview', 'BGPView ASN/prefix lookup'),
    ]:
        ap = sub.add_parser(name, help=helptext, description=helptext,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=f"EXAMPLES:\n  {name} ip 8.8.8.8")
        ap.add_argument('action', choices=['ip'])
        ap.add_argument('value', help='IP address')

    # whois
    wh = sub.add_parser('whois', help='Whois / RDAP',
        description='Domain whois (python-whois) or IP RDAP (ipwhois).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="EXAMPLES:\n  whois domain example.com\n  whois ip 8.8.8.8")
    wh.add_argument('action', choices=['domain', 'ip'])
    wh.add_argument('value', help='domain / IP')

    # nist
    nist = sub.add_parser('nist', help='NIST NVD',
        description='NIST National Vulnerability Database queries.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="EXAMPLES:\n  nist cve CVE-2024-3400\n  nist keyword 'remote code execution' --ncves 30 --years 2\n  nist severity CRITICAL --ncves 50\n  nist cwe CWE-79\n  nist cpe 'cpe:2.3:o:microsoft:windows_10'")
    nist.add_argument('action', choices=['cve', 'cpe', 'severity', 'keyword', 'cwe'],
                      help="cve=ID lookup; cpe=product; severity=CRITICAL/HIGH/MEDIUM; keyword=text; cwe=CWE-N")
    nist.add_argument('value', help='value matching action')
    nist.add_argument('--ncves', type=int, default=None, help='Limit results count')
    nist.add_argument('--years', type=int, default=None, help='Limit to last N years')

    # vulncheck
    vc = sub.add_parser('vulncheck', help='VulnCheck',
        description='VulnCheck KEV / MITRE / NVD2 indices.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="EXAMPLES:\n  vulncheck indexes\n  vulncheck kev 50\n  vulncheck kev-cve CVE-2024-3400\n  vulncheck mitre 100\n  vulncheck mitre-cve CVE-2024-3400\n  vulncheck nvd2-cve CVE-2024-3400\n  vulncheck backup")
    vc.add_argument('action', choices=['indexes', 'kev', 'kev-cve', 'mitre', 'mitre-cve',
                                       'nvd2', 'nvd2-cve', 'backup'])
    vc.add_argument('value', nargs='?', help='CVE for *-cve / count for kev|mitre|nvd2 (default 100)')

    # malpedia
    mp = sub.add_parser('malpedia', help='Malpedia',
        description='Malpedia families / actors / yara / sample download.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="EXAMPLES:\n  malpedia families\n  malpedia actors\n  malpedia actor apt41\n  malpedia family win.qakbot\n  malpedia yara win.qakbot      # downloads zip\n  malpedia sample <sha256>      # downloads zip (pwd: infected)")
    mp.add_argument('action', choices=['actors', 'families', 'payloads', 'actor', 'family',
                                        'yara', 'sample'])
    mp.add_argument('value', nargs='?', help='actor/family name | hash for sample')

    # malshare
    ms = sub.add_parser('malshare', help='Malshare',
        description='Malshare sample list / download.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="EXAMPLES:\n  malshare list PE32\n  malshare list ELF\n  malshare list all\n  malshare hash <sha256>")
    ms.add_argument('action', choices=['list', 'hash'])
    ms.add_argument('value', nargs='?', default='PE32', help='file type for list / hash for download')

    # ioc / yara / attack / report
    ioc = sub.add_parser('ioc', help='IOC extraction',
        description='Extract IOCs (hashes/IPs/URLs/domains/CVEs) from text/pdf/eml/url.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="EXAMPLES:\n  ioc extract report.txt\n  ioc extract report.pdf\n  ioc extract https://blog.example/post.html")
    ioc.add_argument('action', choices=['extract'])
    ioc.add_argument('value', help='file path or URL (http/https)')

    ya = sub.add_parser('yara', help='YARA scan',
        description='Compile YARA rules and scan a file or directory.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="EXAMPLES:\n  yara rules.yar samples/\n  yara malware.yar suspicious.exe")
    ya.add_argument('rules', help='YARA rules file (.yar/.yara)')
    ya.add_argument('target', help='file or directory to scan')

    at = sub.add_parser('attack', help='MITRE ATT&CK tag mapper',
        description='Match free-form tags to MITRE ATT&CK technique IDs.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="EXAMPLES:\n  attack T1059 'process injection'\n  attack persistence credential\n\nNote: first run downloads the ATT&CK matrix (~30MB, cached 7 days).")
    at.add_argument('tags', nargs='+', help='one or more tags / technique IDs')

    rp = sub.add_parser('report', help='Generate HTML/PDF report',
        description='Generate an HTML or PDF report. Reads from --from JSON file (output of --output-format json).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="EXAMPLES:\n  intel-cli.py --output-format json correlate-hash <h> > result.json\n  intel-cli.py report html out.html --from result.json\n\n  # one-shot:\n  intel-cli.py --report html --report-file out.html correlate-hash <h>")
    rp.add_argument('action', choices=['html', 'pdf'])
    rp.add_argument('value', help='output path')
    rp.add_argument('--from', dest='from_json', metavar='JSON',
                    help='Read records from JSON file')


# ─────────────────────────────────────────────────────────────────
# Main entry
# ─────────────────────────────────────────────────────────────────

_GLOBAL_FLAGS_VALUE = {
    '--output-format', '--proxy', '--cache-ttl', '--background',
    '--report', '--report-file',
}
_GLOBAL_FLAGS_BOOL = {'--no-cache', '--quiet', '--verbose'}


def _hoist_global_flags():
    """Move global flags to the front of sys.argv so they can be placed anywhere.

    argparse requires globals before the subcommand; this lets users write
    `intel-cli.py vt hash <h> --output-format json` and have it work.
    """
    if len(sys.argv) <= 1:
        return
    extracted, kept = [], [sys.argv[0]]
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in _GLOBAL_FLAGS_VALUE and i + 1 < len(sys.argv):
            extracted.extend([arg, sys.argv[i + 1]])
            i += 2
            continue
        if any(arg.startswith(f'{g}=') for g in _GLOBAL_FLAGS_VALUE):
            extracted.append(arg)
            i += 1
            continue
        if arg in _GLOBAL_FLAGS_BOOL:
            extracted.append(arg)
            i += 1
            continue
        kept.append(arg)
        i += 1
    sys.argv = [kept[0]] + extracted + kept[1:]


def _maybe_inject_auto():
    """Inject 'auto' before the first positional if it isn't a known subcommand.

    Walks past global flags (and their values) so that
    `intel-cli.py --output-format json <hash>` becomes
    `intel-cli.py --output-format json auto <hash>`.
    """
    if len(sys.argv) <= 1:
        return
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg.startswith('-'):
            # Value-taking flag: skip its value too (if not in --foo=bar form)
            if arg in _GLOBAL_FLAGS_VALUE and i + 1 < len(sys.argv):
                i += 2
                continue
            i += 1
            continue
        # First positional
        if arg not in KNOWN_CMDS:
            sys.argv.insert(i, 'auto')
        return


def main():
    _maybe_inject_auto()
    _hoist_global_flags()
    args = _build_parser().parse_args()
    cv.output_format = args.output_format
    cv.proxy = args.proxy
    cv.cache_enabled = not args.no_cache
    cv.cache_ttl = args.cache_ttl
    cv.bkg = args.background
    if args.quiet:
        cv.verbosity = -1
    elif args.verbose:
        cv.verbosity = 1

    rc = 0
    try:
        rc = _dispatch(args) or 0
    except KeyboardInterrupt:
        rc = 130
    except SystemExit as e:
        rc = e.code if isinstance(e.code, int) else 1
    except Exception as e:
        # final safety net — should never trigger if modules are well-behaved
        print(f"\n{mycolors.foreground.error(cv.bkg)}Unexpected error: {e}{mycolors.reset}", file=sys.stderr)
        rc = 4
    finally:
        if cv.output_format != 'text' and rc == 0:
            collector.finalize()
        elif cv.output_format == 'text':
            printr()
        if rc == 0 and args.report_format and args.report_file:
            from threat_intel.lib.report import ReportGenerator
            gen = ReportGenerator(collector.records, "Threat-Intel Report")
            if args.report_format == 'html':
                gen.to_html(args.report_file)
            else:
                gen.to_pdf(args.report_file)
    sys.exit(rc)


def _dispatch(args):
    cmd = args.command
    val = getattr(args, 'value', None)
    action = getattr(args, 'action', None)

    # Auto-detect & smart aliases
    if cmd == 'auto':
        return _cmd_auto(val)
    if cmd == 'status':
        return _cmd_status()
    if cmd == 'cache':
        return _cmd_cache(action)

    if cmd == 'hash' or cmd == 'correlate-hash':
        return _run_hash(val)
    if cmd == 'ip' or cmd == 'correlate-ip':
        return _run_ip(val)
    if cmd == 'cve':
        return _run_cve(val)
    if cmd == 'url':
        return _run_url(val)
    if cmd == 'domain':
        return _run_domain(val)
    if cmd == 'file':
        return _run_file(val)

    # Per-service
    if cmd == 'vt':
        return _vt(action, val)
    if cmd == 'ha':
        return _ha(action, val)
    if cmd == 'triage':
        return _triage(action, val)
    if cmd == 'bazaar':
        return _bazaar(action, val)
    if cmd == 'threatfox':
        return _threatfox(action, val)
    if cmd == 'otx':
        return _otx(action, val)
    if cmd == 'urlhaus':
        return _urlhaus(action, val)
    if cmd == 'urlscanio':
        return _urlscanio(action, val)
    if cmd == 'shodan':
        return _shodan(action, val)
    if cmd in ('abuseipdb', 'greynoise', 'ipinfo', 'bgpview'):
        return _ip_single(cmd, val)
    if cmd == 'whois':
        return _whois(action, val)
    if cmd == 'nist':
        return _nist(action, val, args)
    if cmd == 'vulncheck':
        return _vulncheck(action, val)
    if cmd == 'malpedia':
        return _malpedia(action, val)
    if cmd == 'malshare':
        return _malshare(action, val)
    if cmd == 'ioc':
        return _ioc(action, val)
    if cmd == 'yara':
        return _yara(args)
    if cmd == 'attack':
        return _attack(args)
    if cmd == 'report':
        return _report(action, val, args)
    return 0


# ─────────────────────────────────────────────────────────────────
# Auto / status / cache
# ─────────────────────────────────────────────────────────────────

def _cmd_auto(val):
    if not val:
        _exit_input_error("auto requires a value (hash/ip/url/cve/domain/file)")
    kind, normalized = auto_detect(val)
    from threat_intel.lib.display import info
    if kind == 'unknown':
        _exit_input_error(
            f"Could not detect type of '{val}'. "
            f"Use a specific subcommand: hash/ip/url/cve/domain/file/<service>"
        )
    info(f"Detected: {kind} → {normalized}")
    if kind == 'hash':
        _run_hash(normalized)
    elif kind == 'ip':
        _run_ip(normalized)
    elif kind == 'url':
        _run_url(normalized)
    elif kind == 'cve':
        _run_cve(normalized)
    elif kind == 'domain':
        _run_domain(normalized)
    elif kind == 'path':
        _run_file(normalized)
    return 0


def _cmd_status():
    from threat_intel.lib.config import all_services, get_key
    from threat_intel.lib.output import is_text_output
    services = list(all_services())
    rows = []
    for service, env in services:
        key = get_key(service)
        masked = (key[:6] + '…' + key[-4:]) if len(key) > 12 else ('●' * len(key) if key else '')
        rows.append((service, env, '✓' if key else '✗', masked))
        collector.add({'service': service, 'env_var': env, 'configured': bool(key)})

    if is_text_output():
        print()
        print("  THREAT-INTEL: API key status".center(70))
        print('  ' + '─' * 66)
        color_ok = mycolors.foreground.lightgreen
        color_no = mycolors.foreground.darkgrey
        for service, env, mark, masked in rows:
            color = color_ok if mark == '✓' else color_no
            print(f"  {color}{mark}{mycolors.reset} {service:<14} {env:<28} {masked}")
        print()
        configured = sum(1 for r in rows if r[2] == '✓')
        print(f"  {configured}/{len(rows)} services configured")
        print()
    return 0


def _cmd_cache(action):
    from threat_intel.lib.cache import ResultCache
    from threat_intel.lib.display import info
    cache = ResultCache()
    try:
        if action == 'stats':
            cur = cache.conn.execute('SELECT COUNT(*) FROM cache')
            count = cur.fetchone()[0]
            info(f"Cache: {count} entries")
            info(f"DB:    {cache.db_path}")
            info(f"TTL:   {cv.cache_ttl}s")
            collector.add({'cache_entries': count, 'db_path': cache.db_path, 'ttl': cv.cache_ttl})
        elif action == 'clear':
            cache.clear()
            info("Cache cleared")
        elif action == 'prune':
            cache.prune()
            info("Expired entries pruned")
    finally:
        cache.close()
    return 0


# ─────────────────────────────────────────────────────────────────
# Workflow runners (alias commands)
# ─────────────────────────────────────────────────────────────────

def _run_hash(val):
    h = _check(sanitize_hash, val, 'hash')
    from threat_intel.workflows import run_correlate_hash
    run_correlate_hash(h)
    return 0


def _run_ip(val):
    ip = _check(sanitize_ip, val, 'ip')
    from threat_intel.workflows import run_correlate_ip
    run_correlate_ip(ip)
    return 0


def _run_cve(val):
    cve = _check(sanitize_cve, val, 'cve')
    from threat_intel.workflows import run_cve
    run_cve(cve)
    return 0


def _run_url(val):
    url = _check(sanitize_url, val, 'url')
    from threat_intel.workflows import run_url
    run_url(url)
    return 0


def _run_domain(val):
    d = _check(sanitize_domain, val, 'domain')
    from threat_intel.workflows import run_domain
    run_domain(d)
    return 0


def _run_file(val):
    if not val.startswith(('http://', 'https://')):
        val = _check(sanitize_path, val, 'source')
    from threat_intel.workflows import run_file
    run_file(val)
    return 0


# ─────────────────────────────────────────────────────────────────
# Per-service handlers
# ─────────────────────────────────────────────────────────────────

def _vt(action, val):
    from threat_intel.modules._adapters import VirusTotalAdapter
    vt = VirusTotalAdapter()
    if action == 'hash':
        h = _check(sanitize_hash, val, 'hash')
        VirusTotalAdapter.display_hash(vt._raw_hash_info(h))
    elif action == 'behavior':
        h = _check(sanitize_hash, val, 'hash')
        from threat_intel.lib.display import section, error
        from threat_intel.lib.output import is_text_output
        data = vt._raw_behavior(h)
        section('VT BEHAVIOR')
        if not isinstance(data, dict) or 'error' in data:
            error(data.get('error', 'No data') if isinstance(data, dict) else 'No data')
            return 0
        d = data.get('data', {})
        if isinstance(d, dict):
            collector.add({
                'source': 'VT behavior',
                **{k: v for k, v in d.items() if isinstance(v, (str, int, float, list))}
            })
        if is_text_output():
            import json as _json
            print(_json.dumps(d, indent=2, default=str)[:4000])
    elif action == 'ip':
        ip = _check(sanitize_ip, val, 'ip')
        VirusTotalAdapter.display_ip(vt._raw_ip_info(ip))
    elif action == 'domain':
        d = _check(sanitize_domain, val, 'domain')
        VirusTotalAdapter.display_domain(vt._raw_domain_info(d))
    elif action == 'url':
        u = _check(sanitize_url, val, 'url')
        VirusTotalAdapter.display_url(vt._raw_url_info(u))
    return 0


def _ha(action, val):
    from threat_intel.modules.hybrid import HybridAnalysisExtractor
    h = _check(sanitize_hash, val, 'hash')
    HybridAnalysisExtractor().hashow(h)
    return 0


def _triage(action, val):
    from threat_intel.modules.triage import TriageExtractor
    t = TriageExtractor()
    if action == 'search':
        t.display_search(t.search(_check(sanitize_general, val, 'query')))
    elif action == 'summary':
        t.display_summary(t.summary(_check(sanitize_general, val, 'sample_id')))
    elif action == 'dynamic':
        from threat_intel.lib.display import section
        from threat_intel.lib.output import is_text_output
        sample_id = _check(sanitize_general, val, 'sample_id')
        data = t.dynamic(sample_id)
        section('TRIAGE DYNAMIC')
        if isinstance(data, dict) and 'error' not in data:
            collector.add({'source': 'Triage dynamic', 'sample_id': sample_id})
        if is_text_output():
            import json as _json
            print(_json.dumps(data, indent=2, default=str)[:4000])
    return 0


def _bazaar(action, val):
    from threat_intel.modules._adapters import BazaarAdapter
    h = _check(sanitize_hash, val, 'hash')
    BazaarAdapter.display(BazaarAdapter()._raw_hash_info(h))
    return 0


def _threatfox(action, val):
    from threat_intel.modules._adapters import ThreatFoxAdapter
    tf = ThreatFoxAdapter()
    if action == 'ioc':
        ThreatFoxAdapter.display(tf.search_ioc(_need_value(val, 'ioc')))
    else:
        ThreatFoxAdapter.display(tf.list_iocs(val))
    return 0


def _otx(action, val):
    from threat_intel.modules._adapters import OTXAdapter
    otx = OTXAdapter()
    if action == 'hash':
        OTXAdapter.display_general(otx._raw_hash_info(_check(sanitize_hash, val, 'hash')))
    elif action == 'ip':
        OTXAdapter.display_general(otx._raw_ip_info(_check(sanitize_ip, val, 'ip')))
    elif action == 'domain':
        OTXAdapter.display_general(otx._raw_domain_info(_check(sanitize_domain, val, 'domain')))
    return 0


def _urlhaus(action, val):
    from threat_intel.modules.urlhaus import URLHausExtractor
    uh = URLHausExtractor()
    if action == 'url':
        uh.display(uh.url_check(_check(sanitize_url, val, 'url')))
    elif action == 'hash':
        uh.display(uh.hash_search(_check(sanitize_hash, val, 'hash')))
    elif action == 'tag':
        uh.display(uh.tag_search(_check(sanitize_tag, val, 'tag')))
    elif action == 'recent-urls':
        uh.display(uh.recent_urls())
    elif action == 'recent-payloads':
        uh.display(uh.recent_payloads())
    return 0


def _urlscanio(action, val):
    from threat_intel.modules.urlscanio import URLScanIOExtractor
    us = URLScanIOExtractor()
    if action == 'submit':
        us.display(us.submit(_check(sanitize_url, val, 'url')))
    elif action == 'result':
        us.display(us.result(_check(sanitize_uuid, val, 'uuid')))
    elif action == 'search':
        us.display(us.search(_check(sanitize_general, val, 'query')))
    elif action == 'domain':
        us.display(us.search_domain(_check(sanitize_domain, val, 'domain')))
    elif action == 'ip':
        us.display(us.search_ip(_check(sanitize_ip, val, 'ip')))
    return 0


def _shodan(action, val):
    from threat_intel.modules.shodan_mod import ShodanExtractor
    sh = ShodanExtractor()
    if action == 'ip':
        sh.shodan_ip(_check(sanitize_ip, val, 'ip'))
    else:
        sh.shodan_search(_check(sanitize_general, val, 'query'))
    return 0


def _ip_single(cmd, val):
    ip = _check(sanitize_ip, val, 'ip')
    if cmd == 'abuseipdb':
        from threat_intel.modules.abuseipdb import AbuseIPDBExtractor
        AbuseIPDBExtractor().check_ip(ip)
    elif cmd == 'greynoise':
        from threat_intel.modules.greynoise import GreyNoiseExtractor
        GreyNoiseExtractor().quick_check(ip)
    elif cmd == 'ipinfo':
        from threat_intel.modules.ipinfo import IPInfoExtractor
        IPInfoExtractor().get_ip_details(ip)
    elif cmd == 'bgpview':
        from threat_intel.modules.bgpview import BGPViewExtractor
        BGPViewExtractor().get_ip_details(ip)
    return 0


def _whois(action, val):
    from threat_intel.modules.whois_mod import WhoisExtractor
    w = WhoisExtractor()
    if action == 'domain':
        w.domain_whois(_check(sanitize_domain, val, 'domain'))
    else:
        w.ip_whois(_check(sanitize_ip, val, 'ip'))
    return 0


def _nist(action, val, args):
    from threat_intel.modules.nist import NISTExtractor
    qmap = {'cpe': 1, 'cve': 2, 'severity': 3, 'keyword': 4, 'cwe': 5}
    qtype = qmap[action]
    if action == 'cve':
        v = _check(sanitize_cve, val, 'cve')
    else:
        v = _check(sanitize_general, val, action)
    n = NISTExtractor()
    n.display(n.query_cve(qtype, v, last_n_years=args.years), max_cves=args.ncves)
    return 0


def _vulncheck(action, val):
    from threat_intel.modules.vulncheck import VulnCheckExtractor
    v = VulnCheckExtractor()
    if action == 'indexes':
        v.list_indexes()
        return 0
    if action == 'kev':
        v.display(v.kev(int(val) if val and str(val).isdigit() else 100), 'KEV')
    elif action == 'kev-cve':
        v.display(v.cve_search(_check(sanitize_cve, val, 'cve')), 'KEV CVE')
    elif action == 'mitre':
        v.display(v.mitre_list(int(val) if val and str(val).isdigit() else 100), 'MITRE')
    elif action == 'mitre-cve':
        v.display(v.mitre_search(_check(sanitize_cve, val, 'cve')), 'MITRE CVE')
    elif action == 'nvd2':
        v.display(v.nist_list(int(val) if val and str(val).isdigit() else 100), 'NVD2')
    elif action == 'nvd2-cve':
        v.display(v.nist_search(_check(sanitize_cve, val, 'cve')), 'NVD2 CVE')
    elif action == 'backup':
        from threat_intel.lib.display import info
        info(str(v.backup_kev()))
    return 0


def _malpedia(action, val):
    from threat_intel.modules.malpedia import MalpediaExtractor
    m = MalpediaExtractor()
    if action == 'actors':
        m.display_list(m.actors(), 'MALPEDIA ACTORS')
    elif action == 'families':
        m.display_list(m.families(), 'MALPEDIA FAMILIES')
    elif action == 'payloads':
        m.display_list(m.payloads(), 'MALPEDIA PAYLOADS')
    elif action == 'actor':
        m.display_meta(m.get_actor(_check(sanitize_general, val, 'actor')), 'MALPEDIA ACTOR')
    elif action == 'family':
        m.display_meta(m.get_family(_check(sanitize_general, val, 'family')), 'MALPEDIA FAMILY')
    elif action == 'yara':
        m.get_yara(_check(sanitize_general, val, 'family'))
    elif action == 'sample':
        m.get_sample(_check(sanitize_hash, val, 'hash'))
    return 0


def _malshare(action, val):
    from threat_intel.modules.malshare import MalshareExtractor
    ms = MalshareExtractor()
    if action == 'list':
        ms.list_type(val or 'PE32')
    elif action == 'hash':
        ms.download(_check(sanitize_hash, val, 'hash'))
    return 0


def _ioc(action, val):
    from threat_intel.lib.ioc_extract import IOCExtractor
    if not val.startswith(('http://', 'https://')):
        val = _check(sanitize_path, val, 'source')
    IOCExtractor().extract_and_display(val)
    return 0


def _yara(args):
    from threat_intel.modules.yara_scan import YaraScanner
    rules = _check(sanitize_path, args.rules, 'rules')
    target = _check(sanitize_path, args.target, 'target')
    YaraScanner(rules).scan_and_display(target)
    return 0


def _attack(args):
    from threat_intel.lib.attack import AttackMapper
    m = AttackMapper()
    m.display(m.map_tags(args.tags))
    return 0


def _report(action, val, args):
    from threat_intel.lib.report import ReportGenerator
    if args.from_json:
        import json as _json
        try:
            with open(args.from_json, 'r', encoding='utf-8') as f:
                records = _json.load(f)
        except (OSError, _json.JSONDecodeError) as e:
            _exit_input_error(f"Cannot read --from {args.from_json}: {e}")
        if isinstance(records, dict):
            records = [records]
    else:
        records = collector.records
    gen = ReportGenerator(records)
    if action == 'html':
        gen.to_html(val)
    else:
        gen.to_pdf(val)
    return 0


if __name__ == '__main__':
    main()
