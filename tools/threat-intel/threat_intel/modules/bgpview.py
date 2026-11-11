"""BGPView client (no auth)."""

import ipaddress

from ..lib.session import create_session
from ..lib.cache import cached
from ..lib.display import error, section, field
from ..lib.output import collector


class BGPViewExtractor:
    base = 'https://api.bgpview.io/ip/'

    @cached("bgpview_ip")
    def _raw_ip_info(self, ip):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {}
        try:
            r = create_session().get(f"{self.base}{ip}", timeout=30)
            data = r.json()
            return data.get('data', {}) if data.get('status') == 'ok' else {}
        except Exception as e:
            return {'error': str(e)}

    def get_ip_details(self, ip):
        data = self._raw_ip_info(ip)
        section("BGPVIEW REPORT")
        if isinstance(data, dict) and 'error' in data:
            # Reporting a transport failure as "No information available" made an
            # unreachable endpoint look identical to a genuine zero-hit lookup, so
            # callers could not tell "this IP is unknown" from "this service is down".
            error(f"BGPView unreachable: {data['error']}")
            return
        if not data:
            error("No information available")
            return
        prefixes = data.get('prefixes') or [{}]
        first = prefixes[0]
        asn = first.get('asn') or {}
        rec = {
            'IP': data.get('ip'),
            'PTR': data.get('ptr_record'),
            'Prefix': first.get('prefix'),
            'ASN': asn.get('asn'),
            'AS Name': asn.get('name'),
            'AS Description': asn.get('description'),
            'Country': asn.get('country_code'),
        }
        for k, v in rec.items():
            field(k, v)
        collector.add(rec)
