"""Pre-submission guards. Pure functions, no network.

Every check returns human-readable reasons. A "block" reason stops that
IOC (or the whole manifest); a "warn" reason is shown in the plan for the
human reviewer but does not stop submission.
"""

import getpass
import ipaddress
import os
import re
from urllib.parse import urlsplit, parse_qsl, unquote

from .manifest import DATA_DIR

ALLOWLIST_FILE = DATA_DIR / 'submit_allowlist.txt'

EMAIL_RE = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}')
HOSTNAME_RE = re.compile(
    r'^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$')
SHA256_RE = re.compile(r'^[0-9a-f]{64}$')
HOST_PATH_RE = re.compile(r'[a-z]:[\\/]+users[\\/]|/home/[^/\s]+|/Users/[^/\s]+', re.I)
OPAQUE_TOKEN_RE = re.compile(r'^[A-Za-z0-9_\-=%.]{24,}$')

# Query keys that typically carry a victim identifier in phishing / lure URLs.
# Deliberately excludes generic "id" (payload ids are common in malware URLs).
SENSITIVE_QUERY_KEYS = {
    'email', 'e-mail', 'mail', 'emailaddress', 'user', 'username', 'uname', 'uid',
    'userid', 'user_id', 'login', 'account', 'acct', 'token', 'auth', 'session',
    'sessionid', 'sid', 'phone', 'tel', 'mobile', 'msisdn', 'victim', 'name',
}

TLP_OK = {'clear', 'white'}


def manifest_gate(m):
    """Manifest-wide blocks: TLP and provenance. Defaults deny."""
    reasons = []
    if m['tlp'] not in TLP_OK:
        reasons.append(f"tlp is {m['tlp'] or 'unset'!r}; only TLP:CLEAR may be submitted publicly")
    if m['source'] != 'osint':
        reasons.append(f"source is {m['source'] or 'unset'!r}; only self-collected OSINT ('osint') may be submitted")
    if m['reference']:
        u = urlsplit(m['reference'])
        if u.scheme != 'https' or not u.netloc:
            reasons.append("reference must be a public https:// URL")
    return reasons


def _load_allowlist():
    domains, ips = set(), set()
    try:
        for line in ALLOWLIST_FILE.read_text(encoding='utf-8').splitlines():
            s = line.split('#', 1)[0].strip().lower()
            if not s:
                continue
            try:
                ips.add(ipaddress.ip_address(s))
            except ValueError:
                domains.add(s.rstrip('.'))
    except OSError:
        pass
    return domains, ips


_ALLOW_DOMAINS, _ALLOW_IPS = _load_allowlist()


def allowlisted_domain(host):
    host = host.lower().rstrip('.')
    return any(host == d or host.endswith('.' + d) for d in _ALLOW_DOMAINS)


def _check_ip(s):
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None, f"not a valid IP address: {s!r}"
    if not ip.is_global:
        return ip, f"{ip} is not a globally routable address (private/reserved/sandbox/FakeNet range)"
    if ip in _ALLOW_IPS:
        return ip, f"{ip} is on the legitimate-infrastructure allowlist"
    return ip, None


def split_ip_port(value):
    m = re.match(r'^\[([0-9a-fA-F:]+)\]:(\d{1,5})$', value) or re.match(r'^([0-9.]+):(\d{1,5})$', value)
    if not m:
        return None, None
    return m.group(1), int(m.group(2))


def check_ioc(ioc):
    """Value-level checks. Returns (blocks, warns)."""
    blocks, warns = [], []
    t, v = ioc['type'], ioc['value']

    if t == 'ip':
        _, err = _check_ip(v)
        if err:
            blocks.append(err)

    elif t == 'ip:port':
        host, port = split_ip_port(v)
        if host is None:
            blocks.append(f"ip:port must look like 203.0.113.5:443 or [2001:db8::1]:443, got {v!r}")
        else:
            _, err = _check_ip(host)
            if err:
                blocks.append(err)
            if not 1 <= port <= 65535:
                blocks.append(f"port out of range: {port}")

    elif t == 'domain':
        if not HOSTNAME_RE.match(v):
            blocks.append(f"not a valid domain name: {v!r}")
        elif allowlisted_domain(v):
            blocks.append(f"{v} is legitimate infrastructure (allowlist) — submitting it would be a false positive")

    elif t == 'sha256':
        if not SHA256_RE.match(v):
            blocks.append("sha256 must be 64 lowercase hex characters")

    elif t == 'url':
        b, w = _check_url(v, ioc.get('allow_query', False))
        blocks += b
        warns += w

    return blocks, warns


def _check_url(v, allow_query):
    blocks, warns = [], []
    try:
        u = urlsplit(v)
    except ValueError:
        return [f"unparseable URL: {v!r}"], []
    if u.scheme not in ('http', 'https'):
        blocks.append(f"URL scheme must be http/https, got {u.scheme!r}")
    host = (u.hostname or '').lower()
    if not host:
        return blocks + ["URL has no host"], warns
    try:
        ipaddress.ip_address(host)
        _, err = _check_ip(host)
        if err:
            blocks.append(err)
    except ValueError:
        if not HOSTNAME_RE.match(host):
            blocks.append(f"URL host is not a valid domain: {host!r}")
        elif allowlisted_domain(host):
            warns.append(f"host {host} is legitimate infrastructure — make sure this exact URL (not the site) is malicious")
    if u.username or u.password:
        blocks.append("URL contains embedded credentials (user:pass@)")

    decoded = unquote(v)
    if EMAIL_RE.search(decoded):
        blocks.append("URL contains an e-mail address (likely a victim identifier) — remove it from the URL")

    if u.query and not allow_query:
        for key, val in parse_qsl(u.query, keep_blank_values=True):
            k = key.lower()
            if k in SENSITIVE_QUERY_KEYS and val:
                blocks.append(
                    f"query parameter {key!r} may carry a victim identifier — strip it, "
                    "or set allow_query: true on this IOC after manual review")
            elif OPAQUE_TOKEN_RE.match(val or ''):
                warns.append(f"query parameter {key!r} holds a long opaque value — confirm it is not a per-victim token")
    if u.fragment:
        warns.append("URL has a #fragment — fragments are not sent on the wire; consider dropping it")
    return blocks, warns


def _identity_needles():
    names = set()
    for n in (os.environ.get('USERNAME'), os.environ.get('USER'), os.environ.get('VM_GUEST_USER')):
        if n and len(n) >= 3:
            names.add(n.lower())
    try:
        n = getpass.getuser()
        if n and len(n) >= 3:
            names.add(n.lower())
    except Exception:
        pass
    return names


def check_public_text(label, text):
    """Blocks for free-text fields that will be published (comment, tags, filename, reference)."""
    if not text:
        return []
    s = str(text)
    reasons = []
    if HOST_PATH_RE.search(s):
        reasons.append(f"{label} contains a local filesystem path")
    if EMAIL_RE.search(s):
        reasons.append(f"{label} contains an e-mail address")
    low = s.lower()
    for n in _identity_needles():
        if n in low:
            reasons.append(f"{label} contains a local account name")
            break
    return reasons
