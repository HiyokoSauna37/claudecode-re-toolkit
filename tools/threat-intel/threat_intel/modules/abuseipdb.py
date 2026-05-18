"""AbuseIPDB v2 client. Never raises."""

from ..lib.session import create_session
from ..lib.cache import cached
from ..lib.config import get_key, missing_key_error
from ..lib.display import error, section, field
from ..lib.output import collector


class AbuseIPDBExtractor:
    base = 'https://api.abuseipdb.com/api/v2'
    SERVICE = 'abuseipdb'

    def __init__(self, api_key=None):
        self.api_key = api_key if api_key is not None else get_key(self.SERVICE)

    def _key_or_error(self):
        if not self.api_key:
            return missing_key_error(self.SERVICE)
        return None

    @cached("abuseipdb_ip")
    def _raw_ip_info(self, ip):
        err = self._key_or_error()
        if err:
            return err
        try:
            r = create_session({
                'Key': self.api_key, 'Accept': 'application/json',
            }).get(
                f"{self.base}/check",
                params={'ipAddress': ip, 'maxAgeInDays': '90', 'verbose': ''},
                timeout=30,
            )
            if r.status_code != 200:
                return {'error': f"HTTP {r.status_code}"}
            return r.json()
        except Exception as e:
            return {'error': str(e)}

    def get_ip_details(self, ip):
        return self.check_ip(ip)

    def check_ip(self, ip):
        data = self._raw_ip_info(ip)
        section("ABUSEIPDB REPORT")
        if not isinstance(data, dict) or 'error' in data:
            error(data.get('error', 'No data') if isinstance(data, dict) else 'No data')
            return
        report = data.get('data', {})
        score = report.get('abuseConfidenceScore', 0)
        rec = {
            'IP': report.get('ipAddress'),
            'Abuse Score': score,
            'ISP': report.get('isp'),
            'Usage Type': report.get('usageType'),
            'Country': report.get('countryCode'),
            'Domain': report.get('domain'),
            'Total Reports': report.get('totalReports'),
            'Distinct Users': report.get('numDistinctUsers'),
            'Last Reported': report.get('lastReportedAt'),
        }
        for k, v in rec.items():
            try:
                err = (k == 'Abuse Score' and int(score) >= 50) or (
                    k == 'Total Reports' and int(report.get('totalReports') or 0) > 0
                )
            except (TypeError, ValueError):
                err = False
            field(k, v, error=err)
        collector.add(rec)
