"""IPInfo client (works keyless with reduced rate)."""

import ipaddress

from ..lib.session import create_session
from ..lib.cache import cached
from ..lib.config import get_key
from ..lib.display import error, section, field
from ..lib.output import collector


class IPInfoExtractor:
    base = 'https://ipinfo.io'

    def __init__(self, api_key=None):
        self.api_key = api_key if api_key is not None else get_key('ipinfo')

    @cached("ipinfo_ip")
    def _raw_ip_info(self, ip):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {'error': 'Invalid IP'}
        headers = {'Accept': 'application/json'}
        if self.api_key:
            headers['Authorization'] = f'Bearer {self.api_key}'
        try:
            r = create_session(headers).get(f"{self.base}/{ip}", timeout=30)
            return r.json()
        except Exception as e:
            return {'error': str(e)}

    def get_ip_details(self, ip):
        data = self._raw_ip_info(ip)
        section("IPINFO REPORT")
        if 'error' in data:
            error(str(data['error']))
            return
        rec = {k: data.get(k) for k in
               ('ip', 'hostname', 'org', 'country', 'region', 'city', 'loc', 'postal', 'timezone')}
        for k, v in rec.items():
            field(k, v)
        collector.add(rec)
