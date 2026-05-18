"""tria.ge v0 client. Never raises."""

from urllib.parse import quote

from ..lib.session import create_session
from ..lib.cache import cached
from ..lib.config import get_key, missing_key_error
from ..lib.display import error, info, section, field
from ..lib.output import collector


class TriageExtractor:
    base = 'https://api.tria.ge/v0'
    SERVICE = 'triage'

    def __init__(self, api_key=None):
        self.api_key = api_key if api_key is not None else get_key(self.SERVICE)

    def _key_or_error(self):
        if not self.api_key:
            return missing_key_error(self.SERVICE)
        return None

    def _session(self):
        return create_session({
            'Authorization': f'Bearer {self.api_key}',
            'Accept': 'application/json',
        })

    @cached("triage_search")
    def search(self, query):
        err = self._key_or_error()
        if err:
            return err
        try:
            r = self._session().get(
                f"{self.base}/search",
                params={'query': query}, timeout=60,
            )
            return r.json() if r.status_code == 200 else {'error': f"HTTP {r.status_code}"}
        except Exception as e:
            return {'error': str(e)}

    @cached("triage_overview")
    def _raw_hash_info(self, hash_value):
        data = self.search(f"sha256:{hash_value}")
        if not data or (isinstance(data, dict) and 'error' in data):
            return {'error': data.get('error', 'no data') if isinstance(data, dict) else 'no data'}
        items = data.get('data', [])
        if not items:
            return {'error': 'not found'}
        sample_id = items[0].get('id')
        if not sample_id:
            return {'error': 'no sample id'}
        return self.summary(sample_id)

    @cached("triage_summary")
    def summary(self, sample_id):
        err = self._key_or_error()
        if err:
            return err
        try:
            r = self._session().get(
                f"{self.base}/samples/{quote(sample_id, safe='')}/overview.json",
                timeout=60,
            )
            return r.json() if r.status_code == 200 else {'error': f"HTTP {r.status_code}"}
        except Exception as e:
            return {'error': str(e)}

    def dynamic(self, sample_id):
        err = self._key_or_error()
        if err:
            return err
        try:
            r = self._session().get(
                f"{self.base}/samples/{quote(sample_id, safe='')}/triage_report.json",
                timeout=60,
            )
            return r.json() if r.status_code == 200 else {'error': f"HTTP {r.status_code}"}
        except Exception as e:
            return {'error': str(e)}

    def display_search(self, data):
        section("TRIAGE SEARCH")
        if not data or (isinstance(data, dict) and 'error' in data):
            err = data.get('error', 'No data') if isinstance(data, dict) else 'No data'
            error(err)
            return
        for item in data.get('data', [])[:30]:
            rec = {
                'ID': item.get('id'),
                'Status': item.get('status'),
                'Kind': item.get('kind'),
                'Filename': item.get('filename'),
                'Submitted': item.get('submitted'),
            }
            for k, v in rec.items():
                field(k, v)
            print()
            collector.add(rec)

    def display_summary(self, data):
        section("TRIAGE SUMMARY")
        if not data or (isinstance(data, dict) and 'error' in data):
            err = data.get('error', 'No data') if isinstance(data, dict) else 'No data'
            if err == 'not found':
                info("no record")
            else:
                error(err)
            return
        sample = data.get('sample', {})
        targets = data.get('targets', []) or []
        sigs = []
        for t in targets:
            for s in (t.get('signatures') or []):
                if s.get('name'):
                    sigs.append(s['name'])
        rec = {
            'Sample ID': sample.get('id'),
            'Target': sample.get('target'),
            'Size': sample.get('size'),
            'MD5': sample.get('md5'),
            'SHA256': sample.get('sha256'),
            'Score': sample.get('score'),
            'Status': sample.get('status'),
            'Signatures': ', '.join(sorted(set(sigs))[:15]),
        }
        for k, v in rec.items():
            field(k, v, error=(k in ('Score', 'Signatures')))
        collector.add(rec)
