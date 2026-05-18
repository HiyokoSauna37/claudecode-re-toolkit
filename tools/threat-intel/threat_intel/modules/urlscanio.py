"""URLScan.io client.

Endpoints: /scan (POST), /result/<uuid>, /search.
Never raises. Missing key produces error dict.
"""

from urllib.parse import quote

from ..lib.session import create_session
from ..lib.cache import cached
from ..lib.config import get_key, missing_key_error
from ..lib.display import error, info, section, field
from ..lib.output import collector

MAX_SEARCH_RESULTS = 30


class URLScanIOExtractor:
    base = 'https://urlscan.io/api/v1'
    SERVICE = 'urlscanio'

    def __init__(self, api_key=None):
        self.api_key = api_key if api_key is not None else get_key(self.SERVICE)

    def _key_or_error(self):
        if not self.api_key:
            return missing_key_error(self.SERVICE)
        return None

    def _session(self):
        return create_session({'API-Key': self.api_key, 'Accept': 'application/json'})

    @staticmethod
    def _check(r):
        codes = {401: 'Unauthorized', 403: 'Forbidden', 404: 'Not found',
                 429: 'Rate limited'}
        if r.status_code in codes:
            return {'error': codes[r.status_code]}
        if r.status_code != 200:
            return {'error': f'HTTP {r.status_code}'}
        return None

    def submit(self, url):
        err = self._key_or_error()
        if err:
            return err
        try:
            session = self._session()
            session.headers['Content-Type'] = 'application/json'
            r = session.post(
                f"{self.base}/scan/",
                json={'url': url, 'visibility': 'public'},
                timeout=30,
            )
            err = self._check(r)
            if err:
                return err
            return r.json()
        except Exception as e:
            return {'error': str(e)}

    @cached("us_result")
    def _raw_result(self, uuid):
        err = self._key_or_error()
        if err:
            return err
        try:
            r = self._session().get(f"{self.base}/result/{quote(uuid, safe='')}/", timeout=30)
            e = self._check(r)
            if e:
                return e
            return r.json()
        except Exception as e:
            return {'error': str(e)}

    def result(self, uuid):
        return self._raw_result(uuid)

    def search(self, query):
        err = self._key_or_error()
        if err:
            return err
        try:
            r = self._session().get(f"{self.base}/search/", params={'q': query}, timeout=30)
            e = self._check(r)
            if e:
                return e
            return r.json()
        except Exception as e:
            return {'error': str(e)}

    def search_domain(self, domain):
        return self.search(f"domain:{domain}")

    def search_ip(self, ip):
        return self.search(f"page.ip:{ip}")

    def display(self, data, label="URLSCAN.IO"):
        section(label)
        if not isinstance(data, dict):
            error("No data")
            return
        if 'error' in data:
            error(data['error'])
            return

        if 'results' in data:
            for result in data['results'][:MAX_SEARCH_RESULTS]:
                t = result.get('task', {})
                p = result.get('page', {})
                v = result.get('verdicts', {}).get('overall', {})
                rec = {
                    'uuid': result.get('_id'),
                    'domain': p.get('domain'),
                    'ip': p.get('ip'),
                    'country': p.get('country'),
                    'asn': p.get('asn'),
                    'score': v.get('score', 0),
                    'malicious': v.get('malicious', False),
                    'time': t.get('time'),
                }
                for k, val in rec.items():
                    field(k, val, error=(k == 'malicious' and val))
                print()
                collector.add(rec)
            total = data.get('total', len(data['results']))
            info(f"Showing {min(MAX_SEARCH_RESULTS, len(data['results']))} of {total} total results.")
            return

        if 'uuid' in data and 'task' not in data:
            rec = {
                'uuid': data.get('uuid'),
                'submitted_url': data.get('url'),
                'result_page': data.get('result'),
                'visibility': data.get('visibility'),
            }
            for k, v in rec.items():
                field(k, v)
            collector.add(rec)
            return

        task = data.get('task', {})
        page = data.get('page', {})
        v = data.get('verdicts', {}).get('overall', {})
        rec = {
            'url': task.get('url'),
            'domain': task.get('domain'),
            'ip': page.get('ip'),
            'country': page.get('country'),
            'asn': page.get('asn'),
            'asn_name': page.get('asnname'),
            'server': page.get('server'),
            'status': page.get('status'),
            'malicious': v.get('malicious', False),
            'score': v.get('score', 0),
            'categories': ', '.join(v.get('categories') or []),
            'tags': ', '.join(v.get('tags') or []),
            'scan_time': task.get('time'),
        }
        for k, val in rec.items():
            field(k, val, error=(k in ('malicious', 'score') and val))
        collector.add(rec)
