"""Map manifest IOCs to per-service submission actions. Pure (filesystem reads only).

Routing (only what each platform's acceptance policy allows):

  type      role               -> services
  ip:port   c2                 -> threatfox(botnet_cc), abuseipdb
  ip        c2                 -> abuseipdb            (ThreatFox needs ip:port)
  domain    c2                 -> threatfox(botnet_cc)
  url       c2                 -> threatfox(botnet_cc)
  url       payload_delivery   -> urlhaus, threatfox(payload_delivery)
  domain    payload_delivery   -> threatfox(payload_delivery)
  ip:port   payload_delivery   -> threatfox(payload_delivery), abuseipdb
  ip        payload_delivery   -> abuseipdb
  sha256    sample             -> bazaar, virustotal, triage (uploads, in container),
                                  threatfox(payload)
  ip/ip:port phishing_landing  -> abuseipdb (category 7)
  url/domain phishing_landing  -> NONE (URLhaus/ThreatFox reject phishing) -> manual
"""

import datetime as _dt
import re
from pathlib import Path

from . import guards
from .manifest import REPO_ROOT

SERVICES = ('threatfox', 'urlhaus', 'abuseipdb', 'bazaar', 'virustotal', 'triage')
UPLOAD_SERVICES = ('bazaar', 'virustotal', 'triage')

MALPEDIA_RE = re.compile(r'^[a-z0-9]+\.[a-z0-9_]+$')
URLHAUS_TAG_RE = re.compile(r'[^A-Za-z0-9.\- ]')

ABUSEIPDB_DEFAULT_CATS = {
    'c2': ['15', '20'],             # Hacking, Exploited Host
    'payload_delivery': ['20'],     # Exploited Host (hosting malicious content)
    'phishing_landing': ['7'],      # Phishing
}
ROLE_LABEL = {
    'c2': 'Malware C2 server',
    'payload_delivery': 'Malware distribution host',
    'phishing_landing': 'Phishing site host',
    'sample': 'Malware sample',
}

MB_MAX_AGE = _dt.timedelta(days=10)       # MalwareBazaar: no samples older than 10 days
URLHAUS_MAX_VERIFY_AGE = _dt.timedelta(hours=48)  # URLhaus: online, serving payload


def _now():
    return _dt.datetime.now(_dt.timezone.utc)


def _family_tag(malware):
    if not malware or '.' not in malware:
        return None
    return malware.split('.', 1)[1]


def _with_family(tags, malware):
    fam = _family_tag(malware)
    out = list(tags)
    if fam and fam != 'unknown' and fam.lower() not in {t.lower() for t in out}:
        out.append(fam)
    return out


def _routes(ioc):
    t, role = ioc['type'], ioc['role']
    r = []
    if role == 'c2':
        if t in ('ip:port', 'domain', 'url'):
            r.append(('threatfox', {'threat_type': 'botnet_cc', 'ioc_type': t}))
        if t in ('ip', 'ip:port'):
            r.append(('abuseipdb', {}))
    elif role == 'payload_delivery':
        if t == 'url':
            r.append(('urlhaus', {}))
        if t in ('url', 'domain', 'ip:port'):
            r.append(('threatfox', {'threat_type': 'payload_delivery', 'ioc_type': t}))
        if t in ('ip', 'ip:port'):
            r.append(('abuseipdb', {}))
    elif role == 'sample':
        if t == 'sha256':
            for s in UPLOAD_SERVICES:
                r.append((s, {}))
            r.append(('threatfox', {'threat_type': 'payload', 'ioc_type': 'sha256_hash'}))
    elif role == 'phishing_landing':
        if t in ('ip', 'ip:port'):
            r.append(('abuseipdb', {}))
    return r


def _resolve_sample_file(ioc):
    """Validate the encrypted sample path. Returns (repo_relative_path, error)."""
    f = ioc.get('file')
    if not f:
        return None, "no encrypted sample file (file: <path>.enc.gz) in manifest"
    p = Path(f)
    if not p.is_absolute():
        p = REPO_ROOT / p
    p = p.resolve()
    try:
        rel = p.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return None, "sample file must live inside the repository (Quarantine dirs)"
    if not p.name.endswith('.enc.gz'):
        return None, "sample file must be an encrypted quarantine blob (*.enc.gz); plaintext is never handled on the host"
    if not p.is_file():
        return None, f"sample file not found: {rel}"
    with open(p, 'rb') as fh:
        if fh.read(2) != b'\x1f\x8b':
            return None, "sample file is not gzip — not a quarantine .enc.gz blob"
    return rel, None


def _abuseipdb_comment(ioc, reference):
    parts = [ROLE_LABEL[ioc['role']]]
    if ioc['malware']:
        parts[0] += f" ({ioc['malware']})"
    parts.append(f"IOC {ioc['value']}")
    if ioc['first_seen']:
        parts.append(f"observed {ioc['first_seen'].date().isoformat()}")
    s = ', '.join(parts) + '.'
    if ioc['comment']:
        s += f" {ioc['comment']}"
    if reference:
        s += f" Ref: {reference}"
    return s[:1024]


def build_actions(manifest, only=None, skip=None):
    """Return (actions, manifest_blocks). Each action is a dict; see module doc."""
    only = {s.lower() for s in (only or [])}
    skip = {s.lower() for s in (skip or [])}
    unknown = (only | skip) - set(SERVICES)
    if unknown:
        raise ValueError(f"unknown service(s): {sorted(unknown)}; valid: {SERVICES}")

    manifest_blocks = guards.manifest_gate(manifest)
    ref = manifest['reference']
    ref_blocks = guards.check_public_text('reference', ref)

    actions, seen = [], set()
    now = _now()
    for ioc in manifest['iocs']:
        value_blocks, value_warns = guards.check_ioc(ioc)
        text_blocks = list(ref_blocks)
        text_blocks += guards.check_public_text('comment', ioc['comment'])
        for tg in ioc['tags']:
            text_blocks += guards.check_public_text(f"tag {tg!r}", tg)
        text_blocks += guards.check_public_text('filename', ioc['filename'])

        routes = _routes(ioc)
        if not routes:
            actions.append({
                'service': 'manual', 'kind': 'none', 'ioc_n': ioc['n'], 'type': ioc['type'],
                'role': ioc['role'], 'ioc': ioc['value'], 'status': 'manual',
                'reasons': ["no API platform accepts this (phishing URL/domain: URLhaus & ThreatFox reject phishing) "
                            "— report via browser forms (Google Safe Browsing, Netcraft, etc.)"
                            if ioc['role'] == 'phishing_landing' else
                            f"no route for type={ioc['type']} role={ioc['role']}"],
                'warnings': [], 'request': None,
            })
            continue

        for service, params in routes:
            if only and service not in only:
                continue
            if service in skip or (ioc['only'] and service not in ioc['only']) or service in ioc['skip']:
                continue
            dedup_value = ioc['value']
            if service == 'abuseipdb' and ioc['type'] == 'ip:port':
                dedup_value = guards.split_ip_port(ioc['value'])[0] or ioc['value']
            key = (service, dedup_value)
            if key in seen:
                continue
            seen.add(key)

            blocks = list(manifest_blocks) + value_blocks + text_blocks
            warns = list(value_warns)
            req = None
            kind = 'upload' if service in UPLOAD_SERVICES else 'ioc'

            if service == 'threatfox':
                if not ioc['malware']:
                    blocks.append("ThreatFox requires malware: <Malpedia name> (e.g. win.lumma)")
                elif not MALPEDIA_RE.match(ioc['malware']):
                    blocks.append(f"malware {ioc['malware']!r} is not a Malpedia name (e.g. win.lumma, apk.hydra)")
                req = {
                    'query': 'submit_ioc',
                    'threat_type': params['threat_type'],
                    'ioc_type': params['ioc_type'],
                    'malware': ioc['malware'],
                    'confidence_level': ioc['confidence'],
                    'anonymous': 0,
                    'tags': ioc['tags'],
                    'iocs': [ioc['value']],
                }
                if ref:
                    req['reference'] = ref
                if ioc['comment']:
                    req['comment'] = ioc['comment']

            elif service == 'urlhaus':
                v_at = ioc['verified_online_at']
                if not v_at:
                    blocks.append("URLhaus accepts only URLs currently serving a payload — set verified_online_at "
                                  "(checked via malware-fetch, never from the host)")
                elif now - v_at > URLHAUS_MAX_VERIFY_AGE:
                    blocks.append(f"verified_online_at is older than {int(URLHAUS_MAX_VERIFY_AGE.total_seconds() // 3600)}h "
                                  "— re-verify the URL is still serving a payload")
                tags = [URLHAUS_TAG_RE.sub('', t) for t in _with_family(ioc['tags'], ioc['malware'])]
                req = {
                    'anonymous': '0',
                    'submission': [{'url': ioc['value'], 'threat': 'malware_download',
                                    'tags': [t for t in tags if t]}],
                }

            elif service == 'abuseipdb':
                ip = ioc['value']
                if ioc['type'] == 'ip:port':
                    ip, _ = guards.split_ip_port(ioc['value'])
                cats = ioc['abuseipdb_categories'] or ABUSEIPDB_DEFAULT_CATS[ioc['role']]
                if not all(c.isdigit() and 1 <= int(c) <= 23 for c in cats):
                    blocks.append(f"invalid AbuseIPDB categories: {cats} (1-23)")
                req ={'ip': ip, 'categories': ','.join(cats),
                       'comment': _abuseipdb_comment(ioc, ref)}

            else:  # bazaar / virustotal / triage uploads
                rel, err = _resolve_sample_file(ioc)
                if err:
                    blocks.append(err)
                filename = ioc['filename'] or (Path(rel).name[:-len('.enc.gz')] if rel else None)
                if service == 'bazaar':
                    fs = ioc['first_seen']
                    if fs is None:
                        warns.append("first_seen unknown — MalwareBazaar asks for samples no older than 10 days")
                    elif now - fs > MB_MAX_AGE:
                        blocks.append(f"first_seen {fs.date()} is older than 10 days — MalwareBazaar policy says do not upload")
                    json_data = {
                        'anonymous': 0,
                        'delivery_method': ioc['delivery_method'],
                        'tags': _with_family(ioc['tags'], ioc['malware']),
                    }
                    if ref:
                        json_data['references'] = {'links': [ref]}
                    if ioc['comment']:
                        json_data['context'] = {'comment': ioc['comment']}
                    req = {'json_data': json_data}
                elif service == 'virustotal':
                    req = {}
                else:
                    req = {'_json': {'kind': 'file', 'interactive': False}}
                req['file'] = {'path': rel, 'filename': filename, 'sha256': ioc['value']}

            actions.append({
                'service': service, 'kind': kind, 'ioc_n': ioc['n'], 'type': ioc['type'],
                'role': ioc['role'], 'ioc': ioc['value'],
                'status': 'blocked' if blocks else 'ready',
                'reasons': blocks, 'warnings': warns, 'request': req,
            })

    for i, a in enumerate(actions, 1):
        a['n'] = i
    return actions, manifest_blocks
