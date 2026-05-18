"""Auto-detect input type and route to the right correlation flow.

This is the heart of the user-friendly CLI: `intel-cli.py 8.8.8.8` just works.
"""

import os
import re
import ipaddress

_HEX_RE = re.compile(r'^[a-fA-F0-9]+$')
_CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$'
)


def detect(value):
    """Return (kind, normalized_value).

    kind ∈ {'hash', 'ip', 'url', 'cve', 'domain', 'path', 'unknown'}
    """
    if not value:
        return 'unknown', value
    s = value.strip()

    # hash (md5/sha1/sha256)
    if len(s) in (32, 40, 64) and _HEX_RE.match(s):
        return 'hash', s.lower()

    # IP
    try:
        ipaddress.ip_address(s)
        return 'ip', s
    except ValueError:
        pass

    # URL (incl. defanged)
    sl = s.lower()
    if sl.startswith(('http://', 'https://', 'hxxp://', 'hxxps://')):
        return 'url', s

    # CVE
    if _CVE_RE.match(s):
        return 'cve', s.upper()

    # Domain — TLD must contain at least one letter (rules out 999.999.999.999)
    if _DOMAIN_RE.match(s) and len(s) <= 253:
        tld = s.rsplit('.', 1)[-1]
        if any(c.isalpha() for c in tld):
            return 'domain', s.lower()

    # File path
    if os.path.exists(os.path.expanduser(s)):
        return 'path', os.path.abspath(os.path.expanduser(s))

    return 'unknown', s
