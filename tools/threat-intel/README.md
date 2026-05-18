# threat-intel

Smart unified OSINT / threat-intelligence CLI over 18 services. Auto-detects
input type — hash → correlation, IP → correlation, CVE → NIST+VulnCheck,
URL → URLScan+VT, domain → Whois+OTX+URLScan+VT, file → IOC extract.

Built on the malwoverview API surface
([alexandreborges/malwoverview](https://github.com/alexandreborges/malwoverview),
GPL-3.0), re-architected for cc-re-toolkit's Claude Code workflow.

## TL;DR

```bash
pip install -r tools/threat-intel/requirements.txt
python tools/threat-intel/intel-cli.py status               # see which keys are set
python tools/threat-intel/intel-cli.py 8.8.8.8              # auto-detect → IP correlation
python tools/threat-intel/intel-cli.py CVE-2024-3400        # auto-detect → NIST + VulnCheck
python tools/threat-intel/intel-cli.py <sha256>             # auto-detect → hash correlation
python tools/threat-intel/intel-cli.py example.com          # auto-detect → domain workflow
python tools/threat-intel/intel-cli.py /path/to/report.pdf  # auto-detect → IOC extract
```

That's it. The CLI figures out the right workflow.

## Architecture

```
tools/threat-intel/
├── intel-cli.py             # CLI entry (smart auto-detect + 30+ subcommands)
├── requirements.txt         # requests / urllib3 / dotenv (+ optional yara/PyPDF2/etc)
├── README.md
└── threat_intel/            # Importable Python package
    ├── auto.py              # Auto-detect input type (hash/ip/url/cve/domain/path)
    ├── workflows.py         # High-level workflows used by aliases
    ├── lib/                 # Shared infrastructure
    │   ├── session.py       # Retry/Retry-After/proxy
    │   ├── sanitize.py      # Input validation
    │   ├── cache.py         # SQLite TTL cache
    │   ├── output.py        # text/json/csv collector
    │   ├── display.py       # Generic dict→terminal renderer
    │   ├── colors.py        # ANSI colors (light/dark aware)
    │   ├── config.py        # API key loader (.env)
    │   ├── attack.py        # MITRE ATT&CK matrix
    │   ├── report.py        # HTML/PDF report
    │   └── ioc_extract.py   # txt/pdf/eml/url IOC extractor (SSRF defended)
    └── modules/             # 18 service clients — never raise; missing keys
        │                    # produce {'error': ...} dicts handled gracefully
        ├── _adapters.py     # VirusTotal / Bazaar / ThreatFox / OTX
        ├── nist.py          # NIST NVD CVE
        ├── vulncheck.py     # KEV / MITRE / NVD2
        ├── urlhaus.py / urlscanio.py
        ├── shodan_mod.py / abuseipdb.py / greynoise.py
        ├── ipinfo.py / bgpview.py / whois_mod.py
        ├── hybrid.py / triage.py / malshare.py / malpedia.py
        ├── multiplehash.py  # Cross-service hash correlation
        ├── multipleip.py    # Cross-service IP correlation
        └── yara_scan.py
```

## Smart auto-detect

The first positional argument's format determines what runs:

| Input format | Workflow |
|---|---|
| `[a-f0-9]{32,40,64}` (hex) | hash correlation (VT + Bazaar + OTX + URLHaus + HA + Triage) |
| valid IPv4 / IPv6 | IP correlation (BGPView + IPInfo + VT + OTX + Shodan + AbuseIPDB + GreyNoise) |
| `CVE-YYYY-NNNNN` | NIST NVD + VulnCheck (KEV / MITRE / NVD2) |
| `http(s)://...` | URLScan.io submit + VirusTotal URL lookup |
| valid domain | Whois + URLScan domain + VT domain + OTX domain |
| existing file path | IOC extract (txt/pdf/eml) |

Anything else → "Could not detect type" error with suggestion to use a specific subcommand.

## All subcommands

```
status                 Show which API keys are configured
cache {stats|clear|prune}

# Workflow aliases (skip auto-detect)
hash <h>               correlate-hash
ip <ip>                correlate-ip
cve <cve>              NIST + VulnCheck
url <url>              URLScan + VT
domain <d>             Whois + URLScan + VT + OTX
file <path>            IOC extract

# Per-service (when you need exactly one source)
vt {hash|ip|domain|url|behavior} <v>
ha hash <h>
triage {search|summary|dynamic} <v>
bazaar hash <h>
threatfox {ioc|recent} <v>
otx {hash|ip|domain} <v>
urlhaus {url|hash|tag|recent-urls|recent-payloads} [<v>]
urlscanio {submit|result|search|domain|ip} <v>
shodan {ip|search} <v>
abuseipdb ip <ip>
greynoise ip <ip>
ipinfo ip <ip>
bgpview ip <ip>
whois {domain|ip} <v>
nist {cve|cpe|severity|keyword|cwe} <v> [--ncves N] [--years N]
vulncheck {indexes|kev|kev-cve|mitre|mitre-cve|nvd2|nvd2-cve|backup} [<v>]
malpedia {actors|families|payloads|actor|family|yara|sample} [<v>]
malshare {list|hash} [<v>]

# Other
ioc extract <file|url>
yara <rules> <target>
attack <tag1> <tag2> ...
report html|pdf <out> [--from <result.json>]

# Global flags (position-independent)
--output-format text|json|csv  (default: text)
--proxy URL                    (HTTP/HTTPS/SOCKS5)
--no-cache / --cache-ttl SEC
--quiet / --verbose
--background 0|1               (0=light terminal, 1=dark default)
--report html|pdf --report-file PATH
```

Run `intel-cli.py <subcommand> --help` for examples on any subcommand.

## API keys

Configure in repository-root `.env` — see `.env.example` and
`.claude/skills/threat-intel/references/api-keys-guide.md`. Services without
a key are gracefully skipped; `status` shows the current configuration.

## Cache

Results are SQLite-cached at `~/.threat_intel_cache.db` (1h TTL by default).
Disable with `--no-cache`, change TTL with `--cache-ttl SECONDS`.
Cache key includes kwargs, so different `--years 2` vs `--years 5` are separate entries.

## Security notes

- **Never raises.** Missing API keys, network errors, malformed responses all
  produce `{'error': '...'}` dicts that display methods handle gracefully.
- All inputs validated via `lib/sanitize.py`
- All URLs URL-encoded (`urllib.parse.quote`) before insertion into request paths
- IOC extractor blocks SSRF — URLs resolving to private/loopback/reserved IPs are refused
- Downloads capped at 500 MB (Malshare/Malpedia) or 10 MB (IOC fetch)
- 429 Retry-After auto-honored, capped at 300s wait

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 2 | Input validation error (bad hash format, missing required value, etc) |
| 3 | (reserved) |
| 4 | Unexpected exception (should never happen — please report) |
| 130 | KeyboardInterrupt |

## What this tool is NOT

- Not a sandbox / not a static analyzer (use `ghidra-headless` / `malware-sandbox`)
- Not a browser (use `malware-fetch` for URL screenshots)
- Not an interactive REPL (Claude Code itself is the REPL)
- Does not embed an LLM (Claude Code reads `--output-format json` directly)

## Acknowledgements

API surface and patterns adapted from
[alexandreborges/malwoverview](https://github.com/alexandreborges/malwoverview)
(GPL-3.0-or-later).
