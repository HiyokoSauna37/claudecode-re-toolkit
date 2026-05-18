"""Hybrid Analysis (Falcon Sandbox) v2 client. Never raises."""

from ..lib.session import create_session
from ..lib.cache import cached
from ..lib.config import get_key, missing_key_error
from ..lib.display import error, info, section, field
from ..lib.output import collector


class HybridAnalysisExtractor:
    base = 'https://www.hybrid-analysis.com/api/v2'
    SERVICE = 'hybrid'

    def __init__(self, api_key=None):
        self.api_key = api_key if api_key is not None else get_key(self.SERVICE)

    def _key_or_error(self):
        if not self.api_key:
            return missing_key_error(self.SERVICE)
        return None

    def _session(self):
        return create_session({
            'api-key': self.api_key,
            'user-agent': 'Falcon Sandbox',
            'accept': 'application/json',
        })

    @cached("ha_hash")
    def _raw_hash_info(self, hash_value):
        err = self._key_or_error()
        if err:
            return err
        try:
            r = self._session().post(
                f"{self.base}/search/hash",
                data={'hash': hash_value}, timeout=60,
            )
            if r.status_code != 200:
                return {'error': f'HTTP {r.status_code}'}
            data = r.json()
            if not data:
                return {'error': 'not found'}
            return data
        except Exception as e:
            return {'error': str(e)}

    def hashow(self, hash_value, env_idx=1):
        data = self._raw_hash_info(hash_value)
        section(f"HYBRID ANALYSIS REPORT (env={env_idx})")
        if not data or (isinstance(data, dict) and 'error' in data):
            err = data.get('error', 'No data') if isinstance(data, dict) else 'No data'
            if err == 'not found':
                info("no record")
            else:
                error(err)
            return
        sample = data[0] if isinstance(data, list) else data
        rec = {
            'SHA256': sample.get('sha256'),
            'MD5': sample.get('md5'),
            'SHA1': sample.get('sha1'),
            'Type': sample.get('type_short') or sample.get('type'),
            'Size': sample.get('size'),
            'Verdict': sample.get('verdict'),
            'VX Family': sample.get('vx_family'),
            'Threat Score': sample.get('threat_score'),
            'AV Detect': sample.get('av_detect'),
            'Environment': sample.get('environment_description'),
        }
        for k, v in rec.items():
            field(k, v, error=(k in ('Verdict', 'VX Family', 'Threat Score')))
        collector.add(rec)
