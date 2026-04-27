#!/usr/bin/env python3
"""loghunter: Log anomaly detection & threat hunting tool

Adapted from Ytools AI Engine concepts (anomaly detection, Multi-Armed Bandit, pattern mining).
Analyzes security logs (EDR, UTM, web server) for:
- Statistical anomalies (frequency spikes, unusual patterns)
- Known attack signatures (SQLi, XSS, LFI, RCE in access logs)
- Behavioral anomalies (unusual user agents, geographic outliers, time-based)
- IOC extraction from logs (IPs, domains, hashes, emails)

Usage:
    python loghunter.py scan access.log
    python loghunter.py scan access.log --format apache
    python loghunter.py scan firewall.log --format csv --json
    python loghunter.py ioc-extract access.log
    python loghunter.py stats access.log
    python loghunter.py top access.log --field ip --limit 20
    cat logs/*.log | python loghunter.py scan -
"""

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import add_output_args, emit_json
from math import sqrt
from urllib.parse import unquote

# ============================================================
# Log parsing patterns
# ============================================================

LOG_FORMATS = {
    "apache": re.compile(
        r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<size>\S+)'
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<useragent>[^"]*)")?'
    ),
    "nginx": re.compile(
        r'(?P<ip>\S+)\s+-\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<size>\S+)'
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<useragent>[^"]*)")?'
    ),
    "csv": None,  # Handled separately
    "json": None,  # Handled separately
}

# Attack signature patterns for log scanning
ATTACK_SIGNATURES = {
    "sqli": {
        "label": "SQL Injection",
        "severity": "critical",
        "patterns": [
            re.compile(r"(?:UNION\s+(?:ALL\s+)?SELECT|SELECT\s+.+\s+FROM)", re.I),
            re.compile(r"(?:OR|AND)\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+", re.I),
            re.compile(r"(?:DROP|ALTER|CREATE|INSERT|UPDATE|DELETE)\s+(?:TABLE|DATABASE|INTO)", re.I),
            re.compile(r"(?:SLEEP|BENCHMARK|WAITFOR\s+DELAY|pg_sleep)\s*\(", re.I),
            re.compile(r"['\"];\s*(?:DROP|SELECT|INSERT|UPDATE|DELETE|EXEC)", re.I),
            re.compile(r"(?:--|#|/\*)\s*$"),
            re.compile(r"(?:INFORMATION_SCHEMA|sys\.objects|sysobjects)", re.I),
            re.compile(r"(?:CHAR|CHR|CONCAT|SUBSTRING|ASCII)\s*\(", re.I),
        ],
    },
    "xss": {
        "label": "Cross-Site Scripting",
        "severity": "high",
        "patterns": [
            re.compile(r"<\s*script[^>]*>", re.I),
            re.compile(r"(?:javascript|vbscript|data)\s*:", re.I),
            re.compile(r"on(?:load|error|click|mouseover|focus|blur|submit)\s*=", re.I),
            re.compile(r"<\s*(?:img|svg|iframe|object|embed|video|audio)[^>]+(?:src|data)\s*=", re.I),
            re.compile(r"alert\s*\(|confirm\s*\(|prompt\s*\(", re.I),
            re.compile(r"document\.(?:cookie|domain|write|location)", re.I),
        ],
    },
    "lfi": {
        "label": "Local File Inclusion / Path Traversal",
        "severity": "critical",
        "patterns": [
            re.compile(r"\.\./|\.\.\\|%2e%2e[/%5c]", re.I),
            re.compile(r"(?:/etc/passwd|/etc/shadow|/proc/self|/windows/system32)", re.I),
            re.compile(r"(?:php://|file://|data://|expect://|input://|zip://)", re.I),
            re.compile(r"(?:\.htaccess|\.htpasswd|web\.config|wp-config\.php)", re.I),
            re.compile(r"(?:boot\.ini|win\.ini|hosts|\.env)", re.I),
        ],
    },
    "rce": {
        "label": "Remote Code Execution",
        "severity": "critical",
        "patterns": [
            re.compile(r"(?:;|\||`|&&)\s*(?:cat|ls|id|whoami|uname|pwd|dir|type)", re.I),
            re.compile(r"(?:wget|curl|fetch|nc|ncat|bash|sh|cmd|powershell)\s+", re.I),
            re.compile(r"\$\{(?:jndi|env|sys|java):", re.I),  # Log4Shell
            re.compile(r"(?:eval|exec|system|passthru|shell_exec|popen)\s*\(", re.I),
            re.compile(r"(?:base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(", re.I),
        ],
    },
    "ssrf": {
        "label": "Server-Side Request Forgery",
        "severity": "high",
        "patterns": [
            re.compile(r"(?:127\.0\.0\.1|0\.0\.0\.0|localhost|::1)", re.I),
            re.compile(r"(?:169\.254\.169\.254|metadata\.google)", re.I),  # Cloud metadata
            re.compile(r"(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.)", re.I),
            re.compile(r"(?:gopher|dict|ldap|tftp)://", re.I),
        ],
    },
    "scanner": {
        "label": "Scanner / Recon Activity",
        "severity": "medium",
        "patterns": [
            re.compile(r"(?:nikto|nmap|sqlmap|wpscan|dirbuster|gobuster|ffuf|nuclei|burp)", re.I),
            re.compile(r"(?:masscan|zmap|shodan|censys|zgrab)", re.I),
            re.compile(r"(?:robots\.txt|sitemap\.xml|\.well-known|\.git/HEAD|\.svn/entries)", re.I),
            re.compile(r"(?:wp-login|wp-admin|xmlrpc\.php|wp-json)", re.I),
            re.compile(r"(?:phpmyadmin|adminer|manager/html|axis2)", re.I),
        ],
    },
    "credential_stuffing": {
        "label": "Credential Stuffing / Brute Force",
        "severity": "high",
        "patterns": [
            re.compile(r"(?:POST)\s+.*/(?:login|signin|auth|session|token|oauth)", re.I),
        ],
    },
    "encoded_payload": {
        "label": "Encoded / Obfuscated Payload",
        "severity": "high",
        "patterns": [
            # Base64 encoded commands
            re.compile(r"(?:powershell|pwsh).*?-[Ee](?:nc|ncodedCommand)\s+[A-Za-z0-9+/=]{20,}", re.I),
            re.compile(r"echo\s+[A-Za-z0-9+/=]{30,}\s*\|\s*base64\s+-d", re.I),
            re.compile(r"base64\s+-d\s*<<<\s*[A-Za-z0-9+/=]{20,}", re.I),
            # Hex encoded payloads
            re.compile(r"(?:\\x[0-9a-f]{2}){8,}", re.I),
            re.compile(r"0x[0-9a-f]{16,}", re.I),
            # Unicode escaped
            re.compile(r"(?:%u[0-9a-f]{4}){4,}", re.I),
            # Double/triple URL encoding
            re.compile(r"(?:%25[0-9a-f]{2}){3,}", re.I),
            # Char/Chr function chains (SQLi bypass)
            re.compile(r"(?:CHR|CHAR)\s*\(\d+\)\s*(?:\+|,|\|\|)\s*(?:CHR|CHAR)\s*\(\d+\)", re.I),
            # Concat obfuscation
            re.compile(r"(?:CONCAT|CONCAT_WS)\s*\((?:\s*(?:CHR|CHAR)\s*\(\d+\)\s*,?\s*){3,}", re.I),
            # PowerShell obfuscation patterns
            re.compile(r"\$\{?[a-z]{1,3}\}?\s*=\s*\[(?:char|byte|int)\]\s*\d+", re.I),
            re.compile(r"(?:IEX|Invoke-Expression)\s*\(", re.I),
            re.compile(r"-join\s*\(\s*\(\s*\d+\s*,\s*\d+", re.I),
            # certutil / mshta / regsvr32 (LOLBins)
            re.compile(r"certutil\s.*?-(?:decode|urlcache)", re.I),
            re.compile(r"mshta\s+(?:http|javascript|vbscript)", re.I),
            re.compile(r"regsvr32\s+/s\s+/n\s+/u\s+/i:", re.I),
            re.compile(r"rundll32\.exe\s+javascript:", re.I),
            # MSF encoder signatures (Metasploit concept → detection)
            # shikata_ga_nai: polymorphic XOR encoder - NOP sled + decoder stub
            re.compile(r"(?:\\x[dD][89abAB][0-9a-fA-F]{2}){3}.*?(?:\\x[0-9a-fA-F]{2}){4,}", re.I),
            # MSF shellcode preamble patterns (common across encoders)
            re.compile(r"\\xfc\\xe8.*?\\x00\\x00\\x00", re.I),  # CLD + CALL $+5 (MSF stub)
            re.compile(r"\\xd9\\xee\\xd9\\x74\\x24\\xf4", re.I),  # shikata_ga_nai FPU stub
            re.compile(r"\\x60\\x89\\xe5\\x31", re.I),  # PUSHAD + MOV EBP,ESP + XOR (common stub)
            # msfvenom output patterns in URLs/params
            re.compile(r"(?:buf|shellcode|payload)\s*(?:\+|=)\s*[\"'](?:\\x[0-9a-f]{2}){8,}", re.I),
            # alpha_mixed / alpha_upper encoder (alphanumeric shellcode)
            re.compile(r"[A-Za-z0-9]{50,}(?:jA|PYIIIIIIIIIIIIIIII)", re.I),
            # cmd/unix/reverse encoded payloads via web params
            re.compile(r"(?:bash|sh)\s+-[ci]\s+[\"'](?:(?:\\x|%[0-9a-f]{2})[0-9a-f]+){5,}", re.I),
            # PowerShell Meterpreter download cradle patterns
            re.compile(r"(?:powershell|pwsh).*?(?:DownloadString|DownloadFile|WebClient).*?(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}", re.I),
            re.compile(r"(?:powershell|pwsh).*?-w\s+hidden.*?-(?:nop|noni|ep\s+bypass)", re.I),
        ],
    },
    "c2_communication": {
        "label": "C2 Communication Patterns",
        "severity": "critical",
        "patterns": [
            # PoshC2 PowerShell stager patterns
            re.compile(r"(?:powershell|pwsh).*?(?:Start-Sleep|sleep)\s*-[ms]\s*\d+.*?(?:Invoke-WebRequest|IWR|Invoke-RestMethod|IRM)", re.I),
            re.compile(r"(?:powershell|pwsh).*?\[System\.Net\.ServicePointManager\]::ServerCertificateValidationCallback", re.I),
            re.compile(r"(?:powershell|pwsh).*?New-Object\s+System\.Net\.WebClient.*?Proxy", re.I),
            # PowerShell download cradles (PoshC2/Empire/generic C2)
            re.compile(r"(?:IEX|Invoke-Expression)\s*\(\s*(?:New-Object\s+(?:Net\.WebClient|System\.Net\.WebClient))\s*\)\s*\.(?:Download(?:String|Data|File))", re.I),
            re.compile(r"(?:Invoke-WebRequest|IWR|wget|curl)\s.*?-(?:Uri|OutFile)\s", re.I),
            re.compile(r"\[System\.Reflection\.Assembly\]::Load(?:From|File|WithPartialName)\(", re.I),
            # .NET assembly loading (Covenant/C# agent patterns)
            re.compile(r"\[System\.Reflection\.Assembly\]::Load\(\s*\[Convert\]::FromBase64String", re.I),
            re.compile(r"Add-Type\s+-TypeDefinition.*?DllImport", re.I),
            # AMSI/ETW bypass attempts (Havoc/generic evasion)
            re.compile(r"(?:amsi|AmsiUtils|amsiInitFailed|AmsiScanBuffer)", re.I),
            re.compile(r"(?:Set-MpPreference|Add-MpPreference)\s+-(?:DisableRealtimeMonitoring|ExclusionPath)", re.I),
            re.compile(r"\[Ref\]\.Assembly\.GetType.*?amsi", re.I),
            # PSRemoting / WinRM lateral movement
            re.compile(r"(?:Enter-PSSession|Invoke-Command)\s+-(?:ComputerName|Session)", re.I),
            re.compile(r"New-PSSession\s+-(?:ComputerName|ConnectionUri)", re.I),
            re.compile(r"Enable-PSRemoting\s+-Force", re.I),
            # WMI/CIM lateral movement
            re.compile(r"(?:Invoke-WmiMethod|Invoke-CimMethod).*?(?:Create|Win32_Process)", re.I),
            re.compile(r"(?:wmic|WMIC).*?(?:process\s+call\s+create|/node:)", re.I),
            # HoaxShell / reverse shell indicators
            re.compile(r"(?:bash|sh)\s+-[ci]\s+[\"'](?:bash|sh)\s+-i\s+>(?:&\s*)?/dev/tcp/", re.I),
            re.compile(r"(?:python|python3)\s+-c\s+[\"']import\s+(?:socket|subprocess|os).*?connect", re.I),
            re.compile(r"(?:perl|ruby)\s+-e\s+.*?(?:socket|TCPSocket|IO\.popen)", re.I),
            # Cobalt Strike beacon behavior patterns in logs
            re.compile(r"(?:cookie|Cookie):\s*[A-Za-z0-9+/=]{50,}", re.I),  # Large base64 cookie (beacon data)
            re.compile(r"(?:GET|POST)\s+/(?:[a-zA-Z0-9]{4}){2,4}\s+", re.I),  # Short random path pattern
            # DNS C2 indicators
            re.compile(r"(?:nslookup|dig|host)\s+[a-zA-Z0-9]{20,}\.", re.I),  # Long subdomain query (DNS tunneling)
            # Telegram Bot API exfiltration (AgentTesla/Raccoon concept)
            re.compile(r"api\.telegram\.org/bot\d+:", re.I),
            re.compile(r"(?:GET|POST)\s+.*?api\.telegram\.org", re.I),
            re.compile(r"(?:GET|POST)\s+.*?(?:tttttt\.me|telete\.in)/", re.I),  # Telegram mirror for C2
            # Discord webhook exfiltration
            re.compile(r"discord(?:app)?\.com/api/webhooks/\d+/", re.I),
            # DDNS / tunnel C2 domains (AsyncRAT/Remcos/NjRAT/XWorm/DarkComet concept)
            re.compile(r"\.(?:duckdns\.org|no-ip\.(?:com|org|biz)|dynu\.(?:com|net)|hopto\.org|zapto\.org|sytes\.net|ddns\.net|portmap\.host|localto\.net|serveo\.net|ngrok\.io|ngrok-free\.app|trycloudflare\.com|loca\.lt|localhost\.run|bore\.digital|playit\.gg|servegame\.com|myftp\.(?:org|biz)|webhop\.me|gotdns\.ch|myvnc\.com|my-router\.de)", re.I),
            # Pastebin/paste-site C2 config retrieval
            re.compile(r"(?:GET|POST)\s+.*?(?:pastebin\.com/raw|paste\.ee/r|hastebin\.com/raw|ghostbin\.co/paste)", re.I),
            # Suspicious TLD patterns (Lumma/Raccoon stealer)
            re.compile(r"(?:GET|POST|CONNECT)\s+.*?\.(?:cyou|top|buzz|xyz|tk|ml|ga|cf|gq)/", re.I),
        ],
    },
}

# Suspicious user agents
SUSPICIOUS_UA = [
    (re.compile(r"^$"), "empty_ua", "Empty User-Agent"),
    (re.compile(r"^-$"), "dash_ua", "Dash User-Agent"),
    (re.compile(r"python-requests|urllib|aiohttp|httpx|go-http", re.I), "scripted", "Scripted client"),
    (re.compile(r"curl|wget|fetch|axios", re.I), "cli_tool", "CLI tool"),
    (re.compile(r"nikto|sqlmap|nmap|masscan|wpscan|dirbuster|gobuster|nuclei|burp", re.I),
     "scanner", "Known scanner"),
    (re.compile(r"bot|crawler|spider|scraper", re.I), "bot", "Bot/Crawler"),
]


# DB fingerprinting from error messages (from sqlmap concept)
DB_FINGERPRINTS = [
    # MySQL / MariaDB
    (re.compile(r"You have an error in your SQL syntax.*?MySQL", re.I), "MySQL"),
    (re.compile(r"Warning.*?mysql_", re.I), "MySQL"),
    (re.compile(r"MySqlException", re.I), "MySQL"),
    (re.compile(r"com\.mysql\.jdbc", re.I), "MySQL"),
    (re.compile(r"MariaDB", re.I), "MariaDB"),
    # PostgreSQL
    (re.compile(r"ERROR:\s+syntax error at or near", re.I), "PostgreSQL"),
    (re.compile(r"pg_query\(\).*?ERROR", re.I), "PostgreSQL"),
    (re.compile(r"PSQLException", re.I), "PostgreSQL"),
    (re.compile(r"org\.postgresql\.util", re.I), "PostgreSQL"),
    (re.compile(r"unterminated quoted string.*?PostgreSQL", re.I), "PostgreSQL"),
    # Microsoft SQL Server
    (re.compile(r"Microsoft OLE DB.*?SQL Server", re.I), "MSSQL"),
    (re.compile(r"Unclosed quotation mark.*?nvarchar", re.I), "MSSQL"),
    (re.compile(r"SqlException.*?System\.Data\.SqlClient", re.I), "MSSQL"),
    (re.compile(r"ODBC SQL Server Driver", re.I), "MSSQL"),
    (re.compile(r"com\.microsoft\.sqlserver\.jdbc", re.I), "MSSQL"),
    (re.compile(r"mssql_query\(\)", re.I), "MSSQL"),
    # Oracle
    (re.compile(r"ORA-\d{5}", re.I), "Oracle"),
    (re.compile(r"oracle\.jdbc\.driver", re.I), "Oracle"),
    (re.compile(r"quoted string not properly terminated.*?Oracle", re.I), "Oracle"),
    (re.compile(r"OracleException", re.I), "Oracle"),
    # SQLite
    (re.compile(r"SQLite.*?error", re.I), "SQLite"),
    (re.compile(r"sqlite3\.OperationalError", re.I), "SQLite"),
    (re.compile(r"SQLITE_ERROR", re.I), "SQLite"),
    (re.compile(r"unrecognized token.*?sqlite", re.I), "SQLite"),
    # MongoDB (NoSQL)
    (re.compile(r"MongoError", re.I), "MongoDB"),
    (re.compile(r"mongoose.*?Error", re.I), "MongoDB"),
    (re.compile(r"BSON.*?invalid", re.I), "MongoDB"),
    # Redis
    (re.compile(r"WRONGTYPE Operation", re.I), "Redis"),
    (re.compile(r"ERR unknown command", re.I), "Redis"),
    # Cassandra
    (re.compile(r"com\.datastax\.driver", re.I), "Cassandra"),
    (re.compile(r"SyntaxException.*?CQL", re.I), "Cassandra"),
]


def fingerprint_db(text):
    """Identify database type from error messages"""
    matches = {}
    for pattern, db_type in DB_FINGERPRINTS:
        if pattern.search(text):
            matches[db_type] = matches.get(db_type, 0) + 1
    return matches


def parse_log_line(line, fmt="auto"):
    """Parse a single log line"""
    line = line.strip()
    if not line:
        return None

    # JSON format
    if fmt == "json" or (fmt == "auto" and line.startswith("{")):
        try:
            data = json.loads(line)
            return {
                "ip": data.get("remote_addr", data.get("ip", data.get("src_ip", ""))),
                "timestamp": data.get("time_local", data.get("timestamp", data.get("@timestamp", ""))),
                "method": data.get("request_method", data.get("method", "")),
                "path": data.get("request_uri", data.get("path", data.get("url", ""))),
                "status": str(data.get("status", "")),
                "size": str(data.get("body_bytes_sent", data.get("size", "0"))),
                "referer": data.get("http_referer", data.get("referer", "")),
                "useragent": data.get("http_user_agent", data.get("useragent", data.get("user_agent", ""))),
                "raw": line,
            }
        except json.JSONDecodeError:
            pass

    # CSV format
    if fmt == "csv" or (fmt == "auto" and "," in line and not line.startswith('"')):
        parts = line.split(",")
        if len(parts) >= 4:
            return {
                "ip": parts[0].strip().strip('"'),
                "timestamp": parts[1].strip().strip('"') if len(parts) > 1 else "",
                "method": parts[2].strip().strip('"') if len(parts) > 2 else "",
                "path": parts[3].strip().strip('"') if len(parts) > 3 else "",
                "status": parts[4].strip().strip('"') if len(parts) > 4 else "",
                "size": parts[5].strip().strip('"') if len(parts) > 5 else "0",
                "referer": parts[6].strip().strip('"') if len(parts) > 6 else "",
                "useragent": parts[7].strip().strip('"') if len(parts) > 7 else "",
                "raw": line,
            }

    # Apache/Nginx format
    for fmt_name in ["apache", "nginx"]:
        pattern = LOG_FORMATS[fmt_name]
        m = pattern.match(line)
        if m:
            return {**m.groupdict(), "raw": line}

    # Fallback: extract what we can
    ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
    return {
        "ip": ip_match.group(1) if ip_match else "",
        "path": line,
        "raw": line,
        "method": "",
        "status": "",
        "timestamp": "",
        "useragent": "",
        "referer": "",
        "size": "0",
    }


def read_logs(source, fmt="auto"):
    """Read and parse log lines"""
    entries = []
    if source == "-":
        lines = sys.stdin.readlines()
    else:
        try:
            with open(source, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"[!] File not found: {source}", file=sys.stderr)
            sys.exit(1)

    for line in lines:
        parsed = parse_log_line(line, fmt)
        if parsed:
            entries.append(parsed)

    return entries


def scan_for_attacks(entries):
    """Scan log entries for attack signatures"""
    findings = []

    for entry in entries:
        path = unquote(entry.get("path", ""))
        raw = entry.get("raw", "")
        check_str = f"{path} {entry.get('referer', '')} {entry.get('useragent', '')}"

        entry_findings = []
        for sig_key, sig in ATTACK_SIGNATURES.items():
            for pattern in sig["patterns"]:
                if pattern.search(check_str):
                    entry_findings.append({
                        "type": sig_key,
                        "label": sig["label"],
                        "severity": sig["severity"],
                        "matched": pattern.pattern[:60],
                    })
                    break  # One match per signature type is enough

        # Check user agent
        ua = entry.get("useragent", "")
        for ua_pattern, ua_type, ua_label in SUSPICIOUS_UA:
            if ua_pattern.search(ua or ""):
                entry_findings.append({
                    "type": f"suspicious_ua:{ua_type}",
                    "label": ua_label,
                    "severity": "low" if ua_type == "bot" else "medium",
                    "matched": (ua or "")[:60],
                })
                break

        # DB fingerprinting from error responses in logs
        db_matches = fingerprint_db(raw)
        if db_matches:
            top_db = max(db_matches, key=db_matches.get)
            entry_findings.append({
                "type": f"db_fingerprint:{top_db}",
                "label": f"Database detected: {top_db}",
                "severity": "medium",
                "matched": f"{top_db} (confidence: {db_matches[top_db]})",
            })

        if entry_findings:
            findings.append({
                "ip": entry.get("ip", "?"),
                "method": entry.get("method", "?"),
                "path": path[:120],
                "status": entry.get("status", "?"),
                "timestamp": entry.get("timestamp", ""),
                "attacks": entry_findings,
                "max_severity": min(
                    (f["severity"] for f in entry_findings),
                    key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(s, 9)
                ),
            })

    return findings


def detect_anomalies(entries):
    """Detect statistical anomalies in log data"""
    anomalies = []

    # IP frequency analysis
    ip_counts = Counter(e.get("ip", "") for e in entries if e.get("ip"))
    if ip_counts:
        counts = list(ip_counts.values())
        mean = sum(counts) / len(counts)
        std = sqrt(sum((c - mean) ** 2 for c in counts) / len(counts)) if len(counts) > 1 else 0
        threshold = mean + 3 * std if std > 0 else mean * 5

        for ip, count in ip_counts.most_common():
            if count > threshold and count > 10:
                anomalies.append({
                    "type": "ip_frequency",
                    "severity": "high",
                    "detail": f"IP {ip} made {count} requests (mean={mean:.0f}, threshold={threshold:.0f})",
                    "ip": ip,
                    "count": count,
                })

    # Status code anomalies (high 4xx/5xx rate from single IP)
    ip_errors = defaultdict(lambda: {"total": 0, "errors": 0})
    for e in entries:
        ip = e.get("ip", "")
        status = e.get("status", "")
        if ip:
            ip_errors[ip]["total"] += 1
            if status.startswith("4") or status.startswith("5"):
                ip_errors[ip]["errors"] += 1

    for ip, data in ip_errors.items():
        if data["total"] >= 10:
            error_rate = data["errors"] / data["total"]
            if error_rate > 0.7:
                anomalies.append({
                    "type": "high_error_rate",
                    "severity": "medium",
                    "detail": f"IP {ip}: {error_rate:.0%} error rate ({data['errors']}/{data['total']})",
                    "ip": ip,
                    "error_rate": round(error_rate, 2),
                })

    # Path scanning detection (many unique paths from one IP)
    ip_paths = defaultdict(set)
    for e in entries:
        ip = e.get("ip", "")
        path = e.get("path", "")
        if ip and path:
            ip_paths[ip].add(path)

    for ip, paths in ip_paths.items():
        if len(paths) > 50:
            anomalies.append({
                "type": "path_scanning",
                "severity": "high",
                "detail": f"IP {ip}: {len(paths)} unique paths (directory brute-force?)",
                "ip": ip,
                "unique_paths": len(paths),
            })

    # Credential spraying detection (from crackmapexec concept)
    # Pattern: single IP sends many POST to login endpoints with high failure rate
    auth_paths = re.compile(r"/(?:login|signin|auth|session|oauth|token|api/auth|api/login)", re.I)
    ip_auth_attempts = defaultdict(lambda: {"total": 0, "failures": 0})
    for e in entries:
        ip = e.get("ip", "")
        method = e.get("method", "")
        path = e.get("path", "")
        status = e.get("status", "")
        if ip and method.upper() == "POST" and auth_paths.search(path):
            ip_auth_attempts[ip]["total"] += 1
            if status in ("401", "403", "429") or status.startswith("4"):
                ip_auth_attempts[ip]["failures"] += 1

    for ip, data in ip_auth_attempts.items():
        if data["total"] >= 5:
            fail_rate = data["failures"] / data["total"]
            if fail_rate >= 0.8:
                anomalies.append({
                    "type": "credential_spraying",
                    "severity": "critical",
                    "detail": f"IP {ip}: {data['total']} auth attempts, {fail_rate:.0%} failure rate (credential spraying?)",
                    "ip": ip,
                    "auth_attempts": data["total"],
                    "failure_rate": round(fail_rate, 2),
                })
            elif data["total"] >= 20:
                anomalies.append({
                    "type": "brute_force",
                    "severity": "high",
                    "detail": f"IP {ip}: {data['total']} auth attempts (brute force?)",
                    "ip": ip,
                    "auth_attempts": data["total"],
                })

    return anomalies


def extract_iocs_from_logs(entries):
    """Extract IOCs from log entries"""
    ips = Counter()
    domains = Counter()
    paths = Counter()
    user_agents = Counter()

    for e in entries:
        ip = e.get("ip", "")
        if ip and ip not in ("127.0.0.1", "::1", "-"):
            ips[ip] += 1

        referer = e.get("referer", "")
        if referer and referer not in ("-", ""):
            try:
                domain = re.search(r"https?://([^/]+)", referer)
                if domain:
                    domains[domain.group(1)] += 1
            except Exception:
                pass

        path = e.get("path", "")
        if path:
            paths[path] += 1

        ua = e.get("useragent", "")
        if ua and ua not in ("-", ""):
            user_agents[ua] += 1

    return {
        "ips": dict(ips.most_common(50)),
        "referer_domains": dict(domains.most_common(30)),
        "top_paths": dict(paths.most_common(30)),
        "user_agents": dict(user_agents.most_common(20)),
    }


# ============================================================
# Subcommands
# ============================================================

def cmd_scan(args):
    """Scan logs for attack signatures and anomalies"""
    entries = read_logs(args.source, args.format)
    if not entries:
        print("[!] No log entries parsed", file=sys.stderr)
        sys.exit(1)

    print(f"  Parsed {len(entries)} log entries", file=sys.stderr)

    findings = scan_for_attacks(entries)
    anomalies = detect_anomalies(entries)

    if args.json:
        emit_json({
            "total_entries": len(entries),
            "attack_findings": len(findings),
            "anomalies": len(anomalies),
            "findings": findings[:100],
            "anomaly_details": anomalies,
        }, args, tool="loghunter", command="scan")
    else:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings.sort(key=lambda f: severity_order.get(f["max_severity"], 9))

        print(f"\n{'='*60}")
        print(f"  Log Threat Scan Report")
        print(f"  Entries: {len(entries)} | Findings: {len(findings)} | Anomalies: {len(anomalies)}")
        print(f"{'='*60}")

        # Attack signature findings
        if findings:
            # Summary by type
            type_counts = Counter()
            for f in findings:
                for a in f["attacks"]:
                    type_counts[a["label"]] += 1

            print(f"\n  Attack Signatures Detected:")
            for label, count in type_counts.most_common():
                print(f"    {label:<35} {count}x")

            print(f"\n  Top Findings:")
            for f in findings[:20]:
                severity_tag = f"[{f['max_severity'].upper()}]"
                attacks_str = ", ".join(a["type"] for a in f["attacks"])
                print(f"  {severity_tag:<10} {f['ip']:<16} {f['method']:<5} {f['path'][:50]}")
                print(f"             Attacks: {attacks_str}")

        # Anomalies
        if anomalies:
            print(f"\n  Anomalies Detected:")
            for a in anomalies:
                print(f"  [{a['severity'].upper()}] {a['detail']}")

        print()


def cmd_ioc_extract(args):
    """Extract IOCs from log files"""
    entries = read_logs(args.source, args.format)
    iocs = extract_iocs_from_logs(entries)

    if args.json:
        emit_json(iocs, args, tool="loghunter", command="ioc-extract")
    else:
        print(f"\n  IOCs extracted from {len(entries)} entries:\n")
        print(f"  Top IPs ({len(iocs['ips'])}):")
        for ip, count in list(iocs["ips"].items())[:15]:
            print(f"    {ip:<20} {count}x")
        if iocs["referer_domains"]:
            print(f"\n  Referer Domains ({len(iocs['referer_domains'])}):")
            for domain, count in list(iocs["referer_domains"].items())[:10]:
                print(f"    {domain:<35} {count}x")
        print()


def cmd_stats(args):
    """Show log statistics"""
    entries = read_logs(args.source, args.format)

    status_counts = Counter(e.get("status", "?") for e in entries)
    method_counts = Counter(e.get("method", "?") for e in entries)
    ip_counts = Counter(e.get("ip", "?") for e in entries)

    if args.json:
        emit_json({
            "total": len(entries),
            "status_codes": dict(status_counts.most_common()),
            "methods": dict(method_counts.most_common()),
            "unique_ips": len(ip_counts),
            "top_ips": dict(ip_counts.most_common(20)),
        }, args, tool="loghunter", command="stats")
    else:
        print(f"\n  Log Statistics ({len(entries)} entries):\n")
        print(f"  Status codes:")
        for status, count in status_counts.most_common():
            print(f"    {status:<6} {count}")
        print(f"\n  Methods:")
        for method, count in method_counts.most_common():
            print(f"    {method:<8} {count}")
        print(f"\n  Unique IPs: {len(ip_counts)}")
        print(f"  Top IPs:")
        for ip, count in ip_counts.most_common(10):
            print(f"    {ip:<20} {count}")
        print()


def cmd_top(args):
    """Show top values for a field"""
    entries = read_logs(args.source, args.format)
    field = args.field
    counts = Counter(e.get(field, "?") for e in entries if e.get(field) not in ("", "-", None))

    if args.json:
        emit_json({"counts": dict(counts.most_common(args.limit))}, args, tool="loghunter", command="top")
    else:
        print(f"\n  Top {args.limit} by '{field}' ({len(entries)} entries):\n")
        for value, count in counts.most_common(args.limit):
            print(f"  {count:>6}  {value[:100]}")
        print()


# ============================================================
# Trend detection (from AI_GetTrends + AI_GetExclusions)
# ============================================================

def parse_timestamp_rough(ts_str):
    """Extract hour from various timestamp formats"""
    if not ts_str:
        return None, None
    # Apache/Nginx: 12/Apr/2026:10:05:00 +0900
    m = re.search(r'(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2})', ts_str)
    if m:
        hour = int(m.group(4))
        day = f"{m.group(3)}-{m.group(2)}-{m.group(1)}"
        return day, hour
    # ISO: 2026-04-12T10:05:00
    m = re.search(r'(\d{4}-\d{2}-\d{2})[T ](\d{2}):', ts_str)
    if m:
        return m.group(1), int(m.group(2))
    return None, None


def cmd_trends(args):
    """Detect temporal trends in log data"""
    entries = read_logs(args.source, args.format)
    if not entries:
        print("[!] No entries", file=sys.stderr)
        sys.exit(1)

    # Hourly distribution
    hourly = Counter()
    daily = Counter()
    ip_hourly = defaultdict(Counter)
    attack_hourly = defaultdict(Counter)

    findings = scan_for_attacks(entries)
    finding_by_ip = defaultdict(list)
    for f in findings:
        finding_by_ip[f["ip"]].append(f)

    for e in entries:
        day, hour = parse_timestamp_rough(e.get("timestamp", ""))
        if hour is not None:
            hourly[hour] += 1
        if day:
            daily[day] += 1
        ip = e.get("ip", "")
        if ip and hour is not None:
            ip_hourly[ip][hour] += 1

    for f in findings:
        _, hour = parse_timestamp_rough(f.get("timestamp", ""))
        if hour is not None:
            for a in f["attacks"]:
                attack_hourly[a["type"]][hour] += 1

    # Detect spikes (hours with > 2x average)
    spikes = []
    if hourly:
        avg = sum(hourly.values()) / max(len(hourly), 1)
        for hour, count in hourly.most_common():
            if count > avg * 2 and count > 5:
                spikes.append({"hour": hour, "count": count, "avg": round(avg, 1),
                               "ratio": round(count / avg, 1)})

    # Detect IP activity windows
    ip_windows = {}
    for ip, hours in ip_hourly.items():
        if sum(hours.values()) >= 5:
            active_hours = sorted(hours.keys())
            ip_windows[ip] = {
                "first_hour": active_hours[0],
                "last_hour": active_hours[-1],
                "active_hours": len(active_hours),
                "total_requests": sum(hours.values()),
                "peak_hour": hours.most_common(1)[0][0],
            }

    # Attack type trends
    attack_trends = {}
    for attack_type, hours in attack_hourly.items():
        total = sum(hours.values())
        if total >= 3:
            attack_trends[attack_type] = {
                "total": total,
                "peak_hour": hours.most_common(1)[0][0],
                "distribution": dict(sorted(hours.items())),
            }

    if args.json:
        emit_json({
            "entries": len(entries),
            "hourly_distribution": dict(sorted(hourly.items())),
            "daily_distribution": dict(sorted(daily.items())),
            "spikes": spikes,
            "ip_activity_windows": ip_windows,
            "attack_trends": attack_trends,
        }, args, tool="loghunter", command="trends")
    else:
        print(f"\n{'='*60}")
        print(f"  Trend Analysis ({len(entries)} entries)")
        print(f"{'='*60}")

        # Hourly heatmap
        if hourly:
            max_count = max(hourly.values()) if hourly else 1
            print(f"\n  Hourly Distribution:")
            for h in range(24):
                count = hourly.get(h, 0)
                bar_len = int(count / max_count * 30) if max_count > 0 else 0
                bar = "#" * bar_len
                spike_mark = " <<<SPIKE" if any(s["hour"] == h for s in spikes) else ""
                print(f"    {h:02d}:00  {count:>5}  {bar}{spike_mark}")

        # Spikes
        if spikes:
            print(f"\n  Activity Spikes ({len(spikes)}):")
            for s in spikes:
                print(f"    {s['hour']:02d}:00 - {s['count']} requests ({s['ratio']}x avg)")

        # IP activity windows
        if ip_windows:
            print(f"\n  IP Activity Windows:")
            sorted_ips = sorted(ip_windows.items(), key=lambda x: -x[1]["total_requests"])
            for ip, w in sorted_ips[:10]:
                has_attacks = ip in finding_by_ip
                tag = " [ATTACK]" if has_attacks else ""
                print(f"    {ip:<18} {w['first_hour']:02d}:00-{w['last_hour']:02d}:00  "
                      f"peak={w['peak_hour']:02d}:00  {w['total_requests']} reqs{tag}")

        # Attack trends
        if attack_trends:
            print(f"\n  Attack Type Trends:")
            for atype, data in sorted(attack_trends.items(), key=lambda x: -x[1]["total"]):
                print(f"    {atype:<25} {data['total']:>4}x  peak={data['peak_hour']:02d}:00")

        print()


def main():
    parser = argparse.ArgumentParser(
        prog="loghunter",
        description="Log anomaly detection & threat hunting",
    )
    sub = parser.add_subparsers(dest="command")

    # scan
    sc = sub.add_parser("scan", aliases=["s"], help="Scan for attacks & anomalies")
    sc.add_argument("source", help="Log file or - for stdin")
    sc.add_argument("--format", "-f", default="auto", choices=["auto", "apache", "nginx", "csv", "json"])
    add_output_args(sc, include=("json",))
    sc.set_defaults(func=cmd_scan)

    # ioc-extract
    ie = sub.add_parser("ioc-extract", aliases=["ioc"], help="Extract IOCs from logs")
    ie.add_argument("source", help="Log file or - for stdin")
    ie.add_argument("--format", "-f", default="auto")
    add_output_args(ie, include=("json",))
    ie.set_defaults(func=cmd_ioc_extract)

    # stats
    st = sub.add_parser("stats", aliases=["st"], help="Log statistics")
    st.add_argument("source", help="Log file or - for stdin")
    st.add_argument("--format", "-f", default="auto")
    add_output_args(st, include=("json",))
    st.set_defaults(func=cmd_stats)

    # top
    tp = sub.add_parser("top", aliases=["t"], help="Top N by field")
    tp.add_argument("source", help="Log file or - for stdin")
    tp.add_argument("--field", default="ip", help="Field to count (ip/path/status/method/useragent)")
    tp.add_argument("--limit", "-n", type=int, default=20)
    tp.add_argument("--format", "-f", default="auto")
    add_output_args(tp, include=("json",))
    tp.set_defaults(func=cmd_top)

    # trends
    tr = sub.add_parser("trends", aliases=["tr"], help="Detect temporal trends & activity patterns")
    tr.add_argument("source", help="Log file or - for stdin")
    tr.add_argument("--format", "-f", default="auto")
    add_output_args(tr, include=("json",))
    tr.set_defaults(func=cmd_trends)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
