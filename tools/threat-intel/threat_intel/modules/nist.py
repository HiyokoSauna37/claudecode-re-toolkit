"""NIST NVD CVE database client.

5 query types: CPE/keyword, CVE-ID, CVSS severity, keyword, CWE.
Smart positioning (start near end of total) surfaces recent CVEs first.
"""

import textwrap
from datetime import datetime

from ..lib.session import create_session
from ..lib.cache import cached
from ..lib.display import error, warn, info, section
from ..lib.output import collector
from ..lib.config import get_key


class NISTExtractor:
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

    def __init__(self):
        self.session = create_session({'User-Agent': 'cc-re-toolkit/threat-intel'})
        api_key = get_key('nist')
        if api_key:
            self.session.headers['apiKey'] = api_key

    @cached("nist_cve")
    def query_cve(self, query_type, query_value, results_per_page=100, start_index=0, last_n_years=None):
        if not query_value and query_type != 0:
            error("No query value provided.")
            return None
        results_per_page = max(1, min(results_per_page, 2000))
        params = {'resultsPerPage': results_per_page, 'startIndex': start_index}

        if query_type == 1:
            if query_value.lower().startswith('cpe:'):
                params['cpeName'] = query_value
            else:
                params['keywordSearch'] = query_value
        elif query_type == 2:
            params['cveId'] = query_value
        elif query_type == 3:
            params['cvssV3Severity'] = query_value
        elif query_type == 4:
            params['keywordSearch'] = query_value
        elif query_type == 5:
            params['cweId'] = query_value
        else:
            error(f"Unknown query type '{query_type}'.")
            return None

        try:
            r = self.session.get(self.base_url, params=params, timeout=60)
            r.raise_for_status()
            data = r.json()
            total = data.get('totalResults', 0)
            if start_index == 0 and total > 0 and query_type in (1, 3, 4, 5):
                params['startIndex'] = max(0, int(total * 0.99))
                params['resultsPerPage'] = 2000
                r = self.session.get(self.base_url, params=params, timeout=60)
                r.raise_for_status()
                data = r.json()
            if last_n_years and query_type in (1, 3, 4, 5):
                data = self._filter_by_year(data, last_n_years)
            elif query_type in (1, 3, 4, 5):
                data = self._filter_by_year(data, 2)
                data = self._sort_by_year(data)
            return data
        except Exception as e:
            error(f"NIST query failed: {e}")
            return None

    @staticmethod
    def _cve_year(vuln):
        cid = vuln.get('cve', {}).get('id', '')
        try:
            return int(cid.split('-')[1])
        except (IndexError, ValueError):
            return 0

    def _filter_by_year(self, data, n):
        if not data or 'vulnerabilities' not in data:
            return data
        cutoff = datetime.now().year - n
        data['vulnerabilities'] = [
            v for v in data['vulnerabilities'] if self._cve_year(v) >= cutoff
        ]
        return data

    def _sort_by_year(self, data):
        if not data or 'vulnerabilities' not in data:
            return data
        data['vulnerabilities'].sort(key=self._cve_year, reverse=True)
        return data

    def display(self, data, max_cves=None):
        if not data or 'vulnerabilities' not in data:
            warn("No results found.")
            return
        vulns = sorted(data['vulnerabilities'], key=self._cve_year, reverse=True)
        if max_cves:
            vulns = vulns[:max_cves]
        for idx, v in enumerate(vulns, 1):
            cve = v.get('cve', {})
            cid = cve.get('id', 'N/A')
            published = cve.get('published', 'N/A')
            status = cve.get('vulnStatus', 'N/A')
            descs = cve.get('descriptions', [])
            description = next((d['value'] for d in descs if d.get('lang') == 'en'), 'N/A')
            metrics = cve.get('metrics', {})
            cvss3 = (metrics.get('cvssMetricV31') or metrics.get('cvssMetricV3') or [{}])[0]
            cvss3_score = cvss3.get('cvssData', {}).get('baseScore', 'N/A')
            cvss3_sev = cvss3.get('baseSeverity', 'N/A')

            info(f"\n[{idx}] {cid}  ({status})")
            print(f"    Published: {published}")
            print(f"    CVSS v3:   {cvss3_score} ({cvss3_sev})")
            wrapped = textwrap.fill(description, width=80, initial_indent='    ', subsequent_indent='    ')
            print(wrapped)

            collector.add({
                'cve_id': cid,
                'published': published,
                'status': status,
                'cvss_v3_score': cvss3_score,
                'cvss_v3_severity': cvss3_sev,
                'description': description[:500],
            })
