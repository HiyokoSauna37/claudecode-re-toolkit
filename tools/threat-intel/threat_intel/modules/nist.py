"""NIST NVD CVE database client.

5 query types: CPE/keyword, CVE-ID, CVSS severity, keyword, CWE.
Smart positioning (start near end of total) surfaces recent CVEs first.
"""

import textwrap
from datetime import datetime

from ..lib.session import create_session
from ..lib.cache import cached
from ..lib.display import error, warn, info, section
from ..lib.output import collector, is_text_output
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

    @staticmethod
    def _pick_cvss3(metrics):
        """Pick NVD's own CVSS v3 entry, not whichever one happens to be first.

        NVD returns one entry per scoring organisation. For CVE-2020-1472 the CNA
        (secure@microsoft.com) scores 5.5 MEDIUM and NVD scores 10.0 CRITICAL, and the
        CNA's entry comes first -- so taking [0] reported Zerologon as a medium. Both
        entries are marked type "Secondary" there, so the source is what disambiguates;
        type is only a fallback for records where NVD does label a primary.
        """
        entries = metrics.get('cvssMetricV31') or metrics.get('cvssMetricV3') or []
        if not entries:
            return {}
        for e in entries:
            if e.get('source') == 'nvd@nist.gov':
                return e
        for e in entries:
            if e.get('type') == 'Primary':
                return e
        return entries[0]

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
            cvss3 = self._pick_cvss3(metrics)
            cvss3_data = cvss3.get('cvssData', {})
            cvss3_score = cvss3_data.get('baseScore', 'N/A')
            # NVD API v2 nests baseSeverity inside cvssData. Reading it off the metric
            # itself made every CVE report severity "N/A" even at CVSS 10.0.
            cvss3_sev = cvss3_data.get('baseSeverity', cvss3.get('baseSeverity', 'N/A'))

            # NVD v2 ships the CISA KEV decision inline (cisaExploitAdd et al). The
            # module used to drop it, which left KEV answerable only through VulnCheck --
            # so without a VulnCheck key every CVE came back "exploitation unknown" even
            # though the very response already in hand said otherwise.
            kev_added = cve.get('cisaExploitAdd')
            kev_due = cve.get('cisaActionDue')
            kev_name = cve.get('cisaVulnerabilityName')

            info(f"\n[{idx}] {cid}  ({status})")
            # Bare print() bypasses the text/JSON guard that every other display helper
            # honours, so `--output-format json` used to emit these lines onto stdout
            # ahead of the JSON array and left the output unparseable by jq.
            if is_text_output():
                print(f"    Published: {published}")
                print(f"    CVSS v3:   {cvss3_score} ({cvss3_sev})")
                if kev_added:
                    print(f"    CISA KEV:  LISTED  (added {kev_added}, action due {kev_due})")
                else:
                    print("    CISA KEV:  not listed (per NVD)")
                wrapped = textwrap.fill(description, width=80, initial_indent='    ', subsequent_indent='    ')
                print(wrapped)

            collector.add({
                'cve_id': cid,
                'published': published,
                'status': status,
                'cvss_v3_score': cvss3_score,
                'cvss_v3_severity': cvss3_sev,
                'kev_listed': bool(kev_added),
                'kev_added': kev_added,
                'kev_action_due': kev_due,
                'kev_name': kev_name,
                # Full text on purpose: the terminal already prints the whole
                # description, so truncating only the machine-readable copy handed
                # downstream consumers a silently clipped field (it cut mid-word at
                # 500 chars) while a human reading the same run saw everything.
                'description': description,
            })
