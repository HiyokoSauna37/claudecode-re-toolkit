"""Shodan client. Never raises."""

from urllib.parse import quote

from ..lib.session import create_session
from ..lib.cache import cached
from ..lib.config import get_key, missing_key_error
from ..lib.display import error, section, field
from ..lib.output import collector


class ShodanExtractor:
    base = 'https://api.shodan.io'
    SERVICE = 'shodan'

    def __init__(self, api_key=None):
        self.api_key = api_key if api_key is not None else get_key(self.SERVICE)

    def _key_or_error(self):
        if not self.api_key:
            return missing_key_error(self.SERVICE)
        return None

    @staticmethod
    def _check(r):
        codes = {401: 'Unauthorized', 403: 'Forbidden — plan may not include this',
                 404: 'No information', 429: 'Rate limited'}
        if r.status_code in codes:
            return {'error': codes[r.status_code]}
        if r.status_code != 200:
            return {'error': f'HTTP {r.status_code}'}
        return None

    @cached("shodan_ip")
    def _raw_ip_info(self, ip):
        err = self._key_or_error()
        if err:
            return err
        try:
            r = create_session({'Accept': 'application/json'}).get(
                f"{self.base}/shodan/host/{quote(ip, safe='')}",
                params={'key': self.api_key}, timeout=30,
            )
            e = self._check(r)
            if e:
                return e
            return r.json()
        except Exception as e:
            return {'error': str(e)}

    def get_ip_details(self, ip):
        return self.shodan_ip(ip)

    def shodan_ip(self, ip):
        data = self._raw_ip_info(ip)
        section("SHODAN IP REPORT")
        if not isinstance(data, dict) or 'error' in data:
            error(data.get('error', 'No data') if isinstance(data, dict) else 'No data')
            return
        rec = {
            'IP': data.get('ip_str'),
            'Organization': data.get('org'),
            'ISP': data.get('isp'),
            'OS': data.get('os'),
            'Ports': ', '.join(str(p) for p in data.get('ports', [])),
            'Vulns': ', '.join(data.get('vulns') or []),
            'Hostnames': ', '.join(data.get('hostnames') or []),
            'City': data.get('city'),
            'Country': data.get('country_name'),
            'Last Update': data.get('last_update'),
        }
        for k, v in rec.items():
            field(k, v, error=(k == 'Vulns' and v))
        collector.add(rec)

    def shodan_search(self, query):
        section("SHODAN SEARCH")
        err = self._key_or_error()
        if err:
            error(err['error'])
            return
        try:
            r = create_session({'Accept': 'application/json'}).get(
                f"{self.base}/shodan/host/search",
                params={'key': self.api_key, 'query': query}, timeout=30,
            )
            e = self._check(r)
            if e:
                error(e['error'])
                return
            data = r.json()
        except Exception as e:
            error(str(e))
            return
        for m in data.get('matches', []):
            snippet = str(m.get('data', ''))[:80].replace('\n', ' ').replace('\r', '')
            rec = {
                'IP': m.get('ip_str'),
                'Port': m.get('port'),
                'Org': m.get('org'),
                'Snippet': snippet,
            }
            for k, v in rec.items():
                field(k, v)
            print()
            collector.add(rec)
