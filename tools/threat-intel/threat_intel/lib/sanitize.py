"""Input sanitization / validation helpers.

Each function returns ``(cleaned_value, error_message)``.
On success ``error_message`` is ``None``; on failure ``cleaned_value`` is
``None`` and ``error_message`` describes the problem.
"""

import os
import re
import ipaddress
from urllib.parse import urlparse

_HEX_RE = re.compile(r'^[a-fA-F0-9]+$')
_CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$'
)
_DANGEROUS_CHARS_RE = re.compile(r'[;&|`$<>"\'\\{}\n\r]')
_DANGEROUS_CHARS_GENERAL_RE = re.compile(r'[;&|`$<>"\'\\{}]')


def sanitize_hash(value):
    value = value.strip()
    if len(value) not in (32, 40, 64) or not _HEX_RE.match(value):
        return None, "Invalid hash. Expected MD5 (32), SHA1 (40), or SHA256 (64) hex characters."
    return value, None


def sanitize_hash_or_path(value):
    value = value.strip()
    if not value:
        return None, "Empty value."
    if len(value) in (32, 40, 64) and _HEX_RE.match(value):
        return value, None
    if _DANGEROUS_CHARS_GENERAL_RE.search(value):
        return None, "Input contains invalid characters."
    resolved = os.path.abspath(os.path.expanduser(value))
    if not os.path.exists(resolved):
        return None, f"Not a valid hash and file does not exist: {value}"
    return resolved, None


def sanitize_ip(value):
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        return value, None
    except ValueError:
        return None, f"Invalid IP address: {value}"


def sanitize_domain(value):
    value = value.strip().lower()
    if not _DOMAIN_RE.match(value) or len(value) > 253:
        return None, f"Invalid domain name: {value}"
    return value, None


def sanitize_url(value):
    value = value.strip()
    if not value.startswith(('http://', 'https://', 'hxxp://', 'hxxps://')):
        return None, "Invalid URL. Must start with http:// or https://"
    if len(value) > 2048:
        return None, "URL too long (max 2048 characters)."
    value = value.replace('hxxp://', 'http://').replace('hxxps://', 'https://').replace('[.]', '.')
    parsed = urlparse(value)
    if not parsed.hostname:
        return None, "URL has no hostname."
    return value, None


def sanitize_cve(value):
    value = value.strip().upper()
    if not _CVE_RE.match(value):
        return None, f"Invalid CVE ID format: {value}. Expected CVE-YYYY-NNNNN."
    return value, None


def sanitize_path(value):
    value = value.strip()
    if not value:
        return None, "Empty path."
    resolved = os.path.abspath(os.path.expanduser(value))
    if not os.path.exists(resolved):
        return None, f"Path does not exist: {resolved}"
    return resolved, None


def sanitize_tag(value):
    value = value.strip()
    if not value or len(value) > 200:
        return None, "Invalid tag (empty or too long)."
    if _DANGEROUS_CHARS_RE.search(value):
        return None, "Tag contains invalid characters."
    return value, None


def sanitize_general(value):
    value = value.strip()
    if not value or len(value) > 500:
        return None, "Query empty or too long (max 500 characters)."
    if _DANGEROUS_CHARS_GENERAL_RE.search(value):
        return None, "Query contains invalid characters."
    return value, None


def sanitize_uuid(value):
    value = value.strip()
    if not re.match(r'^[a-fA-F0-9\-]{36}$', value):
        return None, f"Invalid UUID format: {value}"
    return value, None


def sanitize_export_path(value):
    value = value.strip()
    if not value:
        return None, "Empty path."
    resolved = os.path.normcase(os.path.abspath(os.path.expanduser(value)))
    cwd = os.path.normcase(os.path.abspath(os.getcwd()))
    if not (resolved.startswith(cwd + os.sep) or resolved == cwd):
        return None, f"Export path must be within current directory ({cwd})."
    return resolved, None
