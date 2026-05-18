"""VulnCheck client (Community / Free tier).

Endpoints used:
  /v3/index/vulncheck-kev      KEV catalog
  /v3/index/mitre-cvelist-v5   MITRE CVE list
  /v3/index/nist-nvd2          NIST NVD v2
  /v3/backup/vulncheck-kev     KEV backup link
  /v3/index                    list available indexes

Never raises. Missing key produces error dict.
"""

from ..lib.session import create_session
from ..lib.cache import cached
from ..lib.config import get_key, missing_key_error
from ..lib.display import error, info, section
from ..lib.output import collector


class VulnCheckExtractor:
    base_url = 'https://api.vulncheck.com/v3'
    SERVICE = 'vulncheck'

    def __init__(self, api_key=None):
        self.api_key = api_key if api_key is not None else get_key(self.SERVICE)

    def _key_or_error(self):
        if not self.api_key:
            return missing_key_error(self.SERVICE)
        return None

    def _session(self):
        return create_session({
            'Accept': 'application/json',
            'Authorization': f'Bearer {self.api_key}',
        })

    def _get(self, path, params=None, timeout=60):
        err = self._key_or_error()
        if err:
            return err
        try:
            r = self._session().get(f"{self.base_url}{path}", params=params or {}, timeout=timeout)
            if r.status_code == 401:
                return {'error': 'Unauthorized — check VULNCHECK_API_KEY.'}
            if r.status_code == 402:
                return {'error': 'Subscription required for this endpoint.'}
            if r.status_code == 429:
                return {'error': 'Rate limit exceeded.'}
            if r.status_code != 200:
                return {'error': f'HTTP {r.status_code}'}
            return r.json()
        except Exception as e:
            return {'error': str(e)}

    def list_indexes(self):
        section("VULNCHECK — AVAILABLE INDEXES")
        data = self._get('/index')
        if isinstance(data, dict) and 'error' in data:
            error(data['error'])
            return
        for idx in data.get('data', []):
            info(f"{idx.get('name', 'N/A')} → {idx.get('href', 'N/A')}")
            collector.add({'index_name': idx.get('name'), 'href': idx.get('href')})

    @cached("vc_kev")
    def kev(self, limit=100):
        return self._get('/index/vulncheck-kev', params={'limit': limit})

    def cve_search(self, cve):
        return self._get('/index/vulncheck-kev', params={'cve': cve})

    def backup_kev(self):
        return self._get('/backup/vulncheck-kev')

    @cached("vc_mitre")
    def mitre_list(self, limit=100):
        return self._get('/index/mitre-cvelist-v5', params={'limit': limit})

    def mitre_search(self, cve):
        return self._get('/index/mitre-cvelist-v5', params={'cve': cve})

    @cached("vc_nist")
    def nist_list(self, limit=100):
        return self._get('/index/nist-nvd2', params={'limit': limit})

    def nist_search(self, cve):
        return self._get('/index/nist-nvd2', params={'cve': cve})

    def display(self, data, label="VULNCHECK"):
        section(label)
        if not isinstance(data, dict) or 'error' in data:
            err = data.get('error', 'No data') if isinstance(data, dict) else 'No data'
            error(err)
            return
        items = data.get('data', [])
        if not items:
            info("No results.")
            return
        for item in items[:50]:
            cid = item.get('cve') or item.get('cveID') or item.get('id') or 'N/A'
            vendor = item.get('vendorProject', '')
            product = item.get('product', '')
            name = item.get('vulnerabilityName', '')
            date_added = item.get('dateAdded', '')
            info(f"\n{cid} — {vendor} {product}")
            if name:
                print(f"  {name}")
            if date_added:
                print(f"  Added: {date_added}")
            collector.add({
                'cve': cid, 'vendor': vendor, 'product': product,
                'name': name, 'date_added': date_added,
            })
