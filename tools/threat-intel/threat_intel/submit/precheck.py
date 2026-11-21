"""Dedup / sanity pre-checks (read-only lookups) run at plan time.

Marks actions 'skip' when the IOC is already known on the target platform
or already submitted by us (ledger), and 'blocked' when the API key is
missing or AbuseIPDB says the IP is whitelisted / a CDN.
Cache is bypassed so a stale "not found" never causes a duplicate submit.
"""

from ..lib import configvars as cv
from ..lib.config import get_key, env_var_for
from . import ledger

LINKS = {
    'threatfox': 'https://threatfox.abuse.ch/ioc/{id}/',
    'urlhaus': 'https://urlhaus.abuse.ch/url/{id}/',
    'bazaar': 'https://bazaar.abuse.ch/sample/{sha256}/',
    'virustotal': 'https://www.virustotal.com/gui/file/{sha256}',
    'triage': 'https://tria.ge/{id}',
    'abuseipdb': 'https://www.abuseipdb.com/check/{ip}',
}


def ledger_key(action):
    if action['service'] == 'abuseipdb' and action.get('request'):
        return action['request']['ip']
    return action['ioc']


def _threatfox(a):
    from ..modules._adapters import ThreatFoxAdapter
    d = ThreatFoxAdapter().search_ioc(a['ioc'])
    if 'error' in d:
        return None, d['error']
    if d.get('query_status') == 'ok' and isinstance(d.get('data'), list) and d['data']:
        return LINKS['threatfox'].format(id=d['data'][0].get('id')), None
    if d.get('query_status') in ('no_result', 'no_results'):
        return False, None
    return None, f"unexpected query_status {d.get('query_status')!r}"


def _urlhaus(a):
    from ..modules.urlhaus import URLHausExtractor
    d = URLHausExtractor().url_check(a['ioc'])
    if 'error' in d:
        return None, d['error']
    if d.get('query_status') == 'ok':
        return d.get('urlhaus_reference') or LINKS['urlhaus'].format(id=d.get('id')), None
    if d.get('query_status') == 'no_results':
        return False, None
    return None, f"unexpected query_status {d.get('query_status')!r}"


def _bazaar(a):
    from ..modules._adapters import BazaarAdapter
    d = BazaarAdapter()._raw_hash_info(a['ioc'])
    if 'error' in d:
        return (False, None) if d['error'] in ('hash_not_found', 'no_results') else (None, d['error'])
    return LINKS['bazaar'].format(sha256=a['ioc']), None


def _virustotal(a):
    from ..modules._adapters import VirusTotalAdapter
    d = VirusTotalAdapter()._raw_hash_info(a['ioc'])
    if 'error' in d:
        return (False, None) if d['error'] == 'not found' else (None, d['error'])
    return LINKS['virustotal'].format(sha256=a['ioc']), None


def _triage(a):
    from ..modules.triage import TriageExtractor
    d = TriageExtractor().search(f"sha256:{a['ioc']}")
    if 'error' in d:
        return None, d['error']
    items = d.get('data') or []
    if items:
        return LINKS['triage'].format(id=items[0].get('id')), None
    return False, None


def _abuseipdb(a):
    """Not a dedup check (multiple reporters are expected) — a false-positive guard."""
    from ..modules.abuseipdb import AbuseIPDBExtractor
    d = AbuseIPDBExtractor()._raw_ip_info(a['request']['ip'])
    if 'error' in d:
        return None, d['error']
    rep = d.get('data') or {}
    if rep.get('isWhitelisted'):
        a['status'] = 'blocked'
        a['reasons'].append("AbuseIPDB lists this IP as whitelisted (legitimate infrastructure)")
    usage = (rep.get('usageType') or '')
    if 'Content Delivery Network' in usage:
        a['status'] = 'blocked'
        a['reasons'].append(f"usage type is {usage!r} — reporting a shared CDN IP hurts innocent tenants")
    if rep.get('totalReports'):
        a['warnings'].append(f"already reported {rep.get('totalReports')}x (score {rep.get('abuseConfidenceScore')}) — "
                             "adding a report is still fine")
    return False, None


CHECKS = {
    'threatfox': _threatfox, 'urlhaus': _urlhaus, 'bazaar': _bazaar,
    'virustotal': _virustotal, 'triage': _triage, 'abuseipdb': _abuseipdb,
}


def run(actions):
    prev_cache = cv.cache_enabled
    cv.cache_enabled = False
    try:
        for a in actions:
            if a['status'] != 'ready':
                continue
            svc = a['service']
            prev = ledger.submitted_ok(svc, ledger_key(a))
            if prev:
                a['status'] = 'skip'
                a['reasons'].append(f"already submitted by you on {prev['ts'][:10]} (plan {prev.get('plan_id')})")
                continue
            if not get_key(svc):
                a['status'] = 'blocked'
                a['reasons'].append(f"{env_var_for(svc)} not set in .env")
                continue
            try:
                known, err = CHECKS[svc](a)
            except Exception as e:  # never let a lookup crash planning
                known, err = None, str(e)
            if err:
                a['warnings'].append(f"pre-check failed ({err}) — duplicate status unknown")
            elif known:
                a['status'] = 'skip'
                a['reasons'].append(f"already known on {svc}: {known}")
    finally:
        cv.cache_enabled = prev_cache
    return actions
