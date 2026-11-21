"""IOC manifest loader (schema v1).

A manifest lives next to its report (reports/campaigns/<name>.iocs.yaml) and
is the single source of truth for what may be shared publicly. Reports stay
human-readable markdown; we never scrape IOCs out of them.

    schema: 1
    title: Short campaign name
    report: reports/campaigns/20260907_xxx.md   # informational, repo-relative
    tlp: clear            # only "clear" is submittable
    source: osint         # only "osint" (self-collected) is submittable
    reference: https://...  # optional PUBLIC write-up URL, sent to services
    defaults:
      malware: win.lumma  # Malpedia name (ThreatFox requires one)
      confidence: 75
      tags: [Lumma]
      first_seen: 2026-11-20
    iocs:
      - {type: ip:port, value: "203.0.113.5:443", role: c2}
      - {type: url, value: "hxxps://bad[.]example/a.exe", role: payload_delivery,
         verified_online_at: "2026-11-21T10:00:00+09:00"}
      - {type: sha256, value: "<64 hex>", role: sample,
         file: tools/malware-fetch/Quarantine/<dir>/a.exe.enc.gz, filename: a.exe}
"""

import datetime as _dt
import hashlib
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
DATA_DIR = Path(__file__).resolve().parents[2] / 'data'

VALID_TYPES = ('url', 'domain', 'ip', 'ip:port', 'sha256')
VALID_ROLES = ('c2', 'payload_delivery', 'phishing_landing', 'sample')
VALID_DELIVERY = ('email_attachment', 'email_link', 'web_download',
                  'web_drive-by', 'multiple', 'other')
IOC_KEYS = {
    'type', 'value', 'role', 'malware', 'confidence', 'tags', 'comment',
    'first_seen', 'verified_online_at', 'abuseipdb_categories', 'only', 'skip',
    'allow_query', 'file', 'filename', 'delivery_method',
}
TOP_KEYS = {'schema', 'title', 'report', 'tlp', 'source', 'reference', 'defaults', 'iocs'}


class ManifestError(ValueError):
    pass


def refang(value):
    """Undo common defanging: hxxp, [.], (.), [:], [dot]."""
    s = str(value).strip()
    s = re.sub(r'^hxxp', 'http', s, flags=re.I)
    s = re.sub(r'^fxp', 'ftp', s, flags=re.I)
    for a, b in (('[.]', '.'), ('(.)', '.'), ('{.}', '.'), ('[dot]', '.'),
                 ('(dot)', '.'), ('[:]', ':'), ('[://]', '://')):
        s = s.replace(a, b)
    return s


def _parse_date(v, label):
    if v in (None, ''):
        return None
    if isinstance(v, _dt.datetime):
        return v if v.tzinfo else v.replace(tzinfo=_dt.timezone.utc)
    if isinstance(v, _dt.date):
        return _dt.datetime(v.year, v.month, v.day, tzinfo=_dt.timezone.utc)
    try:
        d = _dt.datetime.fromisoformat(str(v).replace('Z', '+00:00'))
    except ValueError as e:
        raise ManifestError(f"{label}: not an ISO date/datetime: {v!r}") from e
    return d if d.tzinfo else d.replace(tzinfo=_dt.timezone.utc)


def _as_list(v):
    if v in (None, ''):
        return []
    if isinstance(v, (list, tuple)):
        return [str(x).strip() for x in v if str(x).strip()]
    return [s.strip() for s in str(v).split(',') if s.strip()]


def _read(path):
    text = path.read_text(encoding='utf-8')
    if path.suffix.lower() in ('.yaml', '.yml'):
        try:
            import yaml
        except ImportError as e:
            raise ManifestError("PyYAML not installed (pip install PyYAML) — or use a .json manifest") from e
        return yaml.safe_load(text), text
    return json.loads(text), text


def load(path):
    """Load + normalize a manifest. Returns dict with 'iocs' fully resolved."""
    path = Path(path).resolve()
    if not path.is_file():
        raise ManifestError(f"manifest not found: {path}")
    doc, raw = _read(path)
    if not isinstance(doc, dict):
        raise ManifestError("manifest root must be a mapping")
    unknown = set(doc) - TOP_KEYS
    if unknown:
        raise ManifestError(f"unknown top-level keys: {sorted(unknown)}")
    if doc.get('schema') != 1:
        raise ManifestError("schema: 1 is required")

    defaults = doc.get('defaults') or {}
    if not isinstance(defaults, dict):
        raise ManifestError("defaults must be a mapping")
    bad = set(defaults) - IOC_KEYS
    if bad:
        raise ManifestError(f"unknown keys in defaults: {sorted(bad)}")

    iocs_in = doc.get('iocs')
    if not isinstance(iocs_in, list) or not iocs_in:
        raise ManifestError("iocs must be a non-empty list")

    iocs = []
    for i, raw_ioc in enumerate(iocs_in, 1):
        label = f"iocs[{i}]"
        if not isinstance(raw_ioc, dict):
            raise ManifestError(f"{label}: must be a mapping")
        bad = set(raw_ioc) - IOC_KEYS
        if bad:
            raise ManifestError(f"{label}: unknown keys {sorted(bad)}")
        merged = {**defaults, **raw_ioc}
        t = str(merged.get('type', '')).strip().lower()
        role = str(merged.get('role', '')).strip().lower()
        if t not in VALID_TYPES:
            raise ManifestError(f"{label}: type must be one of {VALID_TYPES}")
        if role not in VALID_ROLES:
            raise ManifestError(f"{label}: role must be one of {VALID_ROLES}")
        if not merged.get('value'):
            raise ManifestError(f"{label}: value is required")
        try:
            conf = int(merged.get('confidence', 75))
        except (TypeError, ValueError) as e:
            raise ManifestError(f"{label}: confidence must be an integer") from e
        if not 0 <= conf <= 100:
            raise ManifestError(f"{label}: confidence must be 0-100")
        dm = merged.get('delivery_method') or 'web_download'
        if dm not in VALID_DELIVERY:
            raise ManifestError(f"{label}: delivery_method must be one of {VALID_DELIVERY}")
        value = refang(merged['value'])
        if t == 'sha256':
            value = value.lower()
        if t == 'domain':
            value = value.lower().rstrip('.')
        iocs.append({
            'n': i,
            'type': t,
            'role': role,
            'value': value,
            'malware': (str(merged['malware']).strip() if merged.get('malware') else None),
            'confidence': conf,
            'tags': _as_list(merged.get('tags')),
            'comment': (str(merged['comment']).strip() if merged.get('comment') else None),
            'first_seen': _parse_date(merged.get('first_seen'), f"{label}.first_seen"),
            'verified_online_at': _parse_date(merged.get('verified_online_at'),
                                              f"{label}.verified_online_at"),
            'abuseipdb_categories': _as_list(merged.get('abuseipdb_categories')),
            'only': [s.lower() for s in _as_list(merged.get('only'))],
            'skip': [s.lower() for s in _as_list(merged.get('skip'))],
            'allow_query': bool(merged.get('allow_query', False)),
            'file': (str(merged['file']).strip() if merged.get('file') else None),
            'filename': (str(merged['filename']).strip() if merged.get('filename') else None),
            'delivery_method': dm,
        })

    try:
        rel = path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        rel = path.name  # never leak absolute host paths into plans/ledger
    return {
        'path': rel,
        'abs_path': path,
        'sha256': hashlib.sha256(raw.encode('utf-8')).hexdigest(),
        'title': str(doc.get('title') or path.stem),
        'report': doc.get('report'),
        'tlp': str(doc.get('tlp') or '').strip().lower(),
        'source': str(doc.get('source') or '').strip().lower(),
        'reference': (str(doc['reference']).strip() if doc.get('reference') else None),
        'iocs': iocs,
    }
