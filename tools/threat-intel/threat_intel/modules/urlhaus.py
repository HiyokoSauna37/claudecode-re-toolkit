"""URLHaus (abuse.ch) client.

Endpoints: /url, /payload, /tag, /signature, /urls/recent, /payloads/recent.
Auth-Key required from late 2025.
"""

from urllib.parse import quote

from ..lib.session import create_session
from ..lib.cache import cached
from ..lib.config import get_key
from ..lib.display import error, info, section, field
from ..lib.output import collector


class URLHausExtractor:
    base = 'https://urlhaus-api.abuse.ch/v1'

    def __init__(self, api_key=None):
        self.api_key = api_key or get_key('urlhaus')
        headers = {'Accept': 'application/json'}
        if self.api_key:
            headers['Auth-Key'] = self.api_key
        self.session = create_session(headers)

    def _post(self, path, data, timeout=60):
        try:
            r = self.session.post(f"{self.base}/{path}/", data=data, timeout=timeout)
            if r.status_code == 200:
                return r.json()
            return {'error': f"HTTP {r.status_code}"}
        except Exception as e:
            return {'error': str(e)}

    def _get(self, path, timeout=60):
        try:
            r = self.session.get(f"{self.base}/{path}/", timeout=timeout)
            if r.status_code == 200:
                return r.json()
            return {'error': f"HTTP {r.status_code}"}
        except Exception as e:
            return {'error': str(e)}

    @cached("urlhaus_url")
    def url_check(self, url):
        return self._post('url', {'url': url})

    @cached("urlhaus_hash")
    def _raw_hash_info(self, hash_value):
        param = 'md5_hash' if len(hash_value) == 32 else 'sha256_hash'
        data = self._post('payload', {param: hash_value})
        if isinstance(data, dict) and data.get('query_status') == 'ok':
            return data
        if isinstance(data, dict) and 'error' in data:
            return data
        return {'error': (data.get('query_status') or 'no record') if isinstance(data, dict) else 'no record'}

    def hash_search(self, hash_value):
        return self._raw_hash_info(hash_value)

    @cached("urlhaus_tag")
    def tag_search(self, tag):
        return self._post('tag', {'tag': tag})

    @cached("urlhaus_signature")
    def signature_search(self, sig):
        return self._post('signature', {'signature': sig})

    def recent_urls(self):
        return self._get('urls/recent')

    def recent_payloads(self):
        return self._get('payloads/recent')

    def display(self, data, label="URLHAUS"):
        section(label)
        if not isinstance(data, dict):
            error("No data")
            return
        if 'error' in data:
            err = data['error']
            if err in ('no_results', 'no record', 'no_result', 'hash_not_found'):
                info("no record")
            else:
                error(err)
            return
        if data.get('query_status') and data['query_status'] != 'ok':
            info(f"Status: {data['query_status']}")
            return
        # /url single result has 'url' key at top level, list responses use 'urls' key.
        if 'url' in data and 'urls' not in data:
            urls = [data]
        else:
            urls = data.get('urls', [])
        payloads = data.get('payloads', [])
        if isinstance(urls, list) and urls:
            for u in urls[:30]:
                fields = {
                    'URL': u.get('url'),
                    'Status': u.get('url_status'),
                    'Threat': u.get('threat'),
                    'Tags': ', '.join(u.get('tags') or []),
                    'Date Added': u.get('date_added'),
                    'Reporter': u.get('reporter'),
                }
                for k, v in fields.items():
                    field(k, v, error=(k == 'Threat'))
                print()
                collector.add(fields)
        elif payloads:
            for p in payloads[:30]:
                fields = {
                    'SHA256': p.get('sha256_hash'),
                    'MD5': p.get('md5_hash'),
                    'File Type': p.get('file_type'),
                    'Signature': p.get('signature'),
                    'First Seen': p.get('firstseen'),
                }
                for k, v in fields.items():
                    field(k, v, error=(k == 'Signature'))
                print()
                collector.add(fields)
        else:
            for k, v in data.items():
                if isinstance(v, (str, int, float)):
                    field(k, v)
            collector.add(data)
