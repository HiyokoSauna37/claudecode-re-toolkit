"""Self-contained adapters for VirusTotal / Bazaar / ThreatFox / OTX.

These services already exist in tools/malware-fetch (Go binary), but the
correlation framework needs Python `_raw_*` methods. These adapters speak
the APIs directly so threat-intel works standalone.

All adapters return dicts; never raise. Missing API keys produce
{'error': '...'} dicts the display methods handle gracefully.
"""

import json
import base64
from urllib.parse import quote

from ..lib.session import create_session
from ..lib.cache import cached
from ..lib.config import get_key, missing_key_error
from ..lib.display import error, info, section, field
from ..lib.output import collector


def _safe_call(fn):
    """Catch any exception from an HTTP call and convert to error dict."""
    try:
        return fn()
    except Exception as e:
        return {'error': str(e)}


class VirusTotalAdapter:
    base = 'https://www.virustotal.com/api/v3'
    SERVICE = 'virustotal'

    def __init__(self, api_key=None):
        self.api_key = api_key if api_key is not None else get_key(self.SERVICE)

    def _key_or_error(self):
        if not self.api_key:
            return missing_key_error(self.SERVICE)
        return None

    def _session(self):
        return create_session({'x-apikey': self.api_key, 'Accept': 'application/json'})

    @cached("vt_hash")
    def _raw_hash_info(self, hash_value):
        err = self._key_or_error()
        if err:
            return err

        def _do():
            r = self._session().get(f"{self.base}/files/{quote(hash_value, safe='')}", timeout=60)
            if r.status_code == 404:
                return {'error': 'not found'}
            if r.status_code != 200:
                return {'error': f'HTTP {r.status_code}'}
            return r.json()
        return _safe_call(_do)

    @cached("vt_ip")
    def _raw_ip_info(self, ip):
        err = self._key_or_error()
        if err:
            return err

        def _do():
            r = self._session().get(f"{self.base}/ip_addresses/{quote(ip, safe='')}", timeout=60)
            if r.status_code != 200:
                return {'error': f'HTTP {r.status_code}'}
            return r.json()
        return _safe_call(_do)

    @cached("vt_domain")
    def _raw_domain_info(self, domain):
        err = self._key_or_error()
        if err:
            return err

        def _do():
            r = self._session().get(f"{self.base}/domains/{quote(domain, safe='')}", timeout=60)
            if r.status_code != 200:
                return {'error': f'HTTP {r.status_code}'}
            return r.json()
        return _safe_call(_do)

    @cached("vt_url")
    def _raw_url_info(self, url):
        err = self._key_or_error()
        if err:
            return err
        urlid = base64.urlsafe_b64encode(url.encode()).decode().strip('=')

        def _do():
            r = self._session().get(f"{self.base}/urls/{urlid}", timeout=60)
            if r.status_code != 200:
                return {'error': f'HTTP {r.status_code}'}
            return r.json()
        return _safe_call(_do)

    @cached("vt_behavior")
    def _raw_behavior(self, hash_value):
        err = self._key_or_error()
        if err:
            return err

        def _do():
            r = self._session().get(
                f"{self.base}/files/{quote(hash_value, safe='')}/behaviour_summary", timeout=60,
            )
            if r.status_code != 200:
                return {'error': f'HTTP {r.status_code}'}
            return r.json()
        return _safe_call(_do)

    @staticmethod
    def display_hash(data, label="VIRUSTOTAL"):
        section(label)
        if not data or (isinstance(data, dict) and 'error' in data):
            error(data.get('error', 'No data') if isinstance(data, dict) else 'No data')
            return
        attrs = data.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        cls = attrs.get('popular_threat_classification', {}) or {}
        rec = {
            'Meaningful Name': attrs.get('meaningful_name'),
            'Type': attrs.get('type_description'),
            'Size': attrs.get('size'),
            'Times Submitted': attrs.get('times_submitted'),
            'Malicious': stats.get('malicious'),
            'Undetected': stats.get('undetected'),
            'Suspicious': stats.get('suspicious'),
            'SHA256': attrs.get('sha256'),
            'MD5': attrs.get('md5'),
            'SHA1': attrs.get('sha1'),
            'Threat Label': cls.get('suggested_threat_label'),
        }
        for k, v in rec.items():
            field(k, v, error=(k in ('Malicious', 'Suspicious', 'Threat Label')))
        collector.add({'source': 'VirusTotal', **rec})

    @staticmethod
    def display_ip(data, label="VIRUSTOTAL IP"):
        section(label)
        if not data or (isinstance(data, dict) and 'error' in data):
            error(data.get('error', 'No data') if isinstance(data, dict) else 'No data')
            return
        attrs = data.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        rec = {
            'IP': data.get('data', {}).get('id'),
            'Reputation': attrs.get('reputation'),
            'RIR': attrs.get('regional_internet_registry'),
            'ASN': attrs.get('asn'),
            'AS Owner': attrs.get('as_owner'),
            'Country': attrs.get('country'),
            'Network': attrs.get('network'),
            'Malicious': stats.get('malicious'),
            'Suspicious': stats.get('suspicious'),
        }
        for k, v in rec.items():
            field(k, v, error=(k in ('Malicious', 'Suspicious')))
        collector.add({'source': 'VirusTotal', **rec})

    @staticmethod
    def display_domain(data, label="VIRUSTOTAL DOMAIN"):
        section(label)
        if not data or (isinstance(data, dict) and 'error' in data):
            error(data.get('error', 'No data') if isinstance(data, dict) else 'No data')
            return
        d = data.get('data', {})
        attrs = d.get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        rec = {
            'Domain': d.get('id'),
            'Reputation': attrs.get('reputation'),
            'Categories': str(attrs.get('categories', {})) if attrs.get('categories') else None,
            'Registrar': attrs.get('registrar'),
            'Malicious': stats.get('malicious'),
            'Suspicious': stats.get('suspicious'),
        }
        for k, v in rec.items():
            field(k, v, error=(k in ('Malicious', 'Suspicious')))
        collector.add({'source': 'VirusTotal', **rec})

    @staticmethod
    def display_url(data, label="VIRUSTOTAL URL"):
        section(label)
        if not data or (isinstance(data, dict) and 'error' in data):
            error(data.get('error', 'No data') if isinstance(data, dict) else 'No data')
            return
        attrs = data.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        rec = {
            'URL': attrs.get('url'),
            'Title': attrs.get('title'),
            'Reputation': attrs.get('reputation'),
            'Malicious': stats.get('malicious'),
            'Suspicious': stats.get('suspicious'),
        }
        for k, v in rec.items():
            field(k, v, error=(k in ('Malicious', 'Suspicious')))
        collector.add({'source': 'VirusTotal', **rec})


class BazaarAdapter:
    base = 'https://mb-api.abuse.ch/api/v1/'
    SERVICE = 'bazaar'

    def __init__(self, api_key=None):
        self.api_key = api_key if api_key is not None else get_key(self.SERVICE)

    def _session(self):
        headers = {'Accept': 'application/json'}
        if self.api_key:
            headers['Auth-Key'] = self.api_key
        return create_session(headers)

    @cached("bazaar_hash")
    def _raw_hash_info(self, hash_value):
        def _do():
            r = self._session().post(
                self.base, data={'query': 'get_info', 'hash': hash_value}, timeout=60,
            )
            if r.status_code != 200:
                return {'error': f'HTTP {r.status_code}'}
            data = r.json()
            return data if data.get('query_status') == 'ok' else {'error': data.get('query_status', 'unknown')}
        return _safe_call(_do)

    @staticmethod
    def display(data, label="MALWARE BAZAAR"):
        section(label)
        if not data or (isinstance(data, dict) and 'error' in data):
            err = data.get('error', 'No data') if isinstance(data, dict) else 'No data'
            if err in ('hash_not_found', 'no_results'):
                info("no record")
            else:
                error(err)
            return
        items = data.get('data', [])
        if not items:
            info("No samples found")
            return
        d = items[0]
        rec = {
            'SHA256': d.get('sha256_hash'),
            'MD5': d.get('md5_hash'),
            'File Type': d.get('file_type'),
            'File Name': d.get('file_name'),
            'File Size': d.get('file_size'),
            'First Seen': d.get('first_seen'),
            'Reporter': d.get('reporter'),
            'Signature': d.get('signature'),
            'Tags': ', '.join(d.get('tags') or []),
        }
        for k, v in rec.items():
            field(k, v, error=(k == 'Signature'))
        collector.add({'source': 'MalwareBazaar', **rec})


class ThreatFoxAdapter:
    base = 'https://threatfox-api.abuse.ch/api/v1/'
    SERVICE = 'threatfox'

    def __init__(self, api_key=None):
        self.api_key = api_key if api_key is not None else get_key(self.SERVICE)

    def _session(self):
        headers = {'Accept': 'application/json'}
        if self.api_key:
            headers['Auth-Key'] = self.api_key
        return create_session(headers)

    def search_ioc(self, ioc):
        def _do():
            r = self._session().post(
                self.base, data=json.dumps({'query': 'search_ioc', 'search_term': ioc}),
                timeout=60,
            )
            if r.status_code != 200:
                return {'error': f'HTTP {r.status_code}'}
            return r.json()
        return _safe_call(_do)

    def list_iocs(self, days=3):
        try:
            days = int(days)
        except (ValueError, TypeError):
            days = 3

        def _do():
            r = self._session().post(
                self.base, data=json.dumps({'query': 'get_iocs', 'days': days}),
                timeout=60,
            )
            if r.status_code != 200:
                return {'error': f'HTTP {r.status_code}'}
            return r.json()
        return _safe_call(_do)

    @staticmethod
    def display(data, label="THREATFOX"):
        section(label)
        if not data or (isinstance(data, dict) and 'error' in data):
            err = data.get('error', 'No data') if isinstance(data, dict) else 'No data'
            if err in ('no_result', 'no_results'):
                info("no record")
            else:
                error(err)
            return
        for d in data.get('data', [])[:30]:
            rec = {
                'IOC': d.get('ioc'),
                'Type': d.get('ioc_type'),
                'Threat Type': d.get('threat_type'),
                'Malware': d.get('malware_printable'),
                'Confidence': d.get('confidence_level'),
                'First Seen': d.get('first_seen'),
                'Tags': ', '.join(d.get('tags') or []),
            }
            for k, v in rec.items():
                field(k, v, error=(k == 'Malware'))
            print()
            collector.add({'source': 'ThreatFox', **rec})


class OTXAdapter:
    base = 'https://otx.alienvault.com/api/v1'
    SERVICE = 'alienvault'

    def __init__(self, api_key=None):
        self.api_key = api_key if api_key is not None else get_key(self.SERVICE)

    def _key_or_error(self):
        if not self.api_key:
            return missing_key_error(self.SERVICE)
        return None

    def _session(self):
        return create_session({
            'X-OTX-API-KEY': self.api_key,
            'Content-Type': 'application/json',
        })

    @cached("otx_hash")
    def _raw_hash_info(self, hash_value):
        err = self._key_or_error()
        if err:
            return err

        def _do():
            r = self._session().get(
                f"{self.base}/indicators/file/{quote(hash_value, safe='')}", timeout=30,
            )
            if r.status_code != 200:
                return {'error': f'HTTP {r.status_code}'}
            data = r.json()
            return data if data.get('indicator') else {'error': 'not found'}
        return _safe_call(_do)

    @cached("otx_ip")
    def _raw_ip_info(self, ip):
        err = self._key_or_error()
        if err:
            return err
        try:
            import ipaddress as _ip
            family = 'IPv6' if _ip.ip_address(ip).version == 6 else 'IPv4'
        except (ValueError, TypeError):
            family = 'IPv4'

        def _do():
            r = self._session().get(
                f"{self.base}/indicators/{family}/{quote(ip, safe='')}/general", timeout=30,
            )
            if r.status_code != 200:
                return {'error': f'HTTP {r.status_code}'}
            return r.json()
        return _safe_call(_do)

    @cached("otx_domain")
    def _raw_domain_info(self, domain):
        err = self._key_or_error()
        if err:
            return err

        def _do():
            r = self._session().get(
                f"{self.base}/indicators/domain/{quote(domain, safe='')}/general", timeout=30,
            )
            if r.status_code != 200:
                return {'error': f'HTTP {r.status_code}'}
            return r.json()
        return _safe_call(_do)

    @staticmethod
    def display_general(data, label="OTX"):
        section(label)
        if not data or (isinstance(data, dict) and 'error' in data):
            err = data.get('error', 'No data') if isinstance(data, dict) else 'No data'
            if err == 'not found':
                info("no record")
            else:
                error(err)
            return
        pulse_info = data.get('pulse_info', {}) or {}
        pulses = pulse_info.get('pulses', []) or []
        tags, families, attack_ids, countries = set(), set(), set(), set()
        for p in pulses[:20]:
            tags.update(p.get('tags') or [])
            families.update(f.get('display_name', '') for f in (p.get('malware_families') or []))
            attack_ids.update(a.get('display_name', '') for a in (p.get('attack_ids') or []))
            countries.update(p.get('targeted_countries') or [])
        rec = {
            'Indicator': data.get('indicator'),
            'Pulse Count': pulse_info.get('count', 0),
            'Tags': ', '.join(sorted(tags - {''})[:20]),
            'Malware Families': ', '.join(sorted(families - {''})),
            'ATT&CK IDs': ', '.join(sorted(attack_ids - {''})),
            'Targeted Countries': ', '.join(sorted(countries - {''})),
        }
        for k, v in rec.items():
            field(k, v, error=(k in ('Malware Families', 'ATT&CK IDs', 'Pulse Count') and v))
        collector.add({'source': 'AlienVault OTX', **rec})
