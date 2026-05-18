"""Whois (python-whois) + RDAP (ipwhois) client."""

from ..lib.display import error, section, field
from ..lib.output import collector


class WhoisExtractor:
    def domain_whois(self, domain):
        try:
            import whois
        except ImportError:
            error("python-whois required: pip install python-whois")
            return
        section("WHOIS DOMAIN")
        try:
            w = whois.whois(domain)
        except Exception as e:
            error(str(e))
            return
        rec = {
            'Domain Name': w.domain_name,
            'Registrar': w.registrar,
            'Creation Date': w.creation_date,
            'Expiration Date': w.expiration_date,
            'Updated Date': w.updated_date,
            'Name Servers': w.name_servers,
            'Status': w.status,
            'Emails': w.emails,
            'Organization': w.org,
            'Country': w.country,
        }
        for k, v in rec.items():
            field(k, v, error=(k in ('Expiration Date', 'Status')))
        collector.add({k: str(v) if not isinstance(v, list) else v for k, v in rec.items()})

    def ip_whois(self, ip):
        try:
            from ipwhois import IPWhois
        except ImportError:
            error("ipwhois required: pip install ipwhois")
            return
        section("WHOIS IP (RDAP)")
        try:
            result = IPWhois(ip).lookup_rdap()
        except Exception as e:
            error(str(e))
            return
        net = result.get('network') or {}
        entities = result.get('entities') or []
        rec = {
            'ASN': result.get('asn'),
            'ASN Description': result.get('asn_description'),
            'ASN Country': result.get('asn_country_code'),
            'Network Name': net.get('name'),
            'Network CIDR': net.get('cidr'),
            'Entities': ', '.join(entities) if entities else None,
        }
        for k, v in rec.items():
            field(k, v, error=(k == 'ASN'))
        collector.add(rec)
