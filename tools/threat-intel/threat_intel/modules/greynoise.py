"""GreyNoise community v3 client. Never raises."""

from urllib.parse import quote

from ..lib.session import create_session
from ..lib.cache import cached
from ..lib.config import get_key, missing_key_error
from ..lib.display import error, section, field
from ..lib.output import collector


class GreyNoiseExtractor:
    base = 'https://api.greynoise.io/v3/community'
    SERVICE = 'greynoise'

    def __init__(self, api_key=None):
        self.api_key = api_key if api_key is not None else get_key(self.SERVICE)

    def _key_or_error(self):
        if not self.api_key:
            return missing_key_error(self.SERVICE)
        return None

    @cached("greynoise_ip")
    def _raw_ip_info(self, ip):
        err = self._key_or_error()
        if err:
            return err
        try:
            r = create_session({
                'key': self.api_key, 'Accept': 'application/json',
            }).get(f"{self.base}/{quote(ip, safe='')}", timeout=30)
            if r.status_code != 200:
                return {'error': f"HTTP {r.status_code}"}
            return r.json()
        except Exception as e:
            return {'error': str(e)}

    def get_ip_details(self, ip):
        return self.quick_check(ip)

    def quick_check(self, ip):
        data = self._raw_ip_info(ip)
        section("GREYNOISE COMMUNITY")
        if not isinstance(data, dict) or 'error' in data:
            error(data.get('error', 'No data') if isinstance(data, dict) else 'No data')
            return
        classification = data.get('classification', 'unknown')
        rec = {
            'IP': data.get('ip'),
            'Noise': data.get('noise'),
            'RIOT': data.get('riot'),
            'Classification': classification,
            'Name': data.get('name'),
            'Last Seen': data.get('last_seen'),
            'Message': data.get('message'),
        }
        for k, v in rec.items():
            field(k, v, error=(k == 'Classification' and classification == 'malicious'))
        collector.add(rec)
