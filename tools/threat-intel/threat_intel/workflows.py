"""High-level workflow helpers used by the CLI.

Each ``run_*`` builds the appropriate set of extractors and runs the
corresponding correlation, gracefully skipping services without API keys.
"""

from .lib.config import get_key
from .lib.display import section, info


def run_correlate_hash(hash_value):
    """Cross-service hash correlation. Each service is included only if its
    API key is set (or is keyless). Keeps the report uncluttered for users
    who haven't configured every paid key.
    """
    from .modules._adapters import VirusTotalAdapter, BazaarAdapter, OTXAdapter
    from .modules.urlhaus import URLHausExtractor
    from .modules.multiplehash import MultipleHashExtractor

    extractors = {
        'MalwareBazaar': BazaarAdapter(),  # keyless OK
        'URLHaus': URLHausExtractor(),     # keyless OK
    }
    if get_key('virustotal'):
        extractors['VirusTotal'] = VirusTotalAdapter()
    if get_key('alienvault'):
        extractors['AlienVault OTX'] = OTXAdapter()
    if get_key('hybrid'):
        from .modules.hybrid import HybridAnalysisExtractor
        extractors['Hybrid Analysis'] = HybridAnalysisExtractor()
    if get_key('triage'):
        from .modules.triage import TriageExtractor
        extractors['Triage'] = TriageExtractor()
    MultipleHashExtractor(extractors).correlate(hash_value)


def run_correlate_ip(ip):
    """BGPView + IPInfo (always) + VT/OTX/Shodan/AbuseIPDB/GreyNoise (if keys)."""
    from .modules._adapters import VirusTotalAdapter, OTXAdapter
    from .modules.shodan_mod import ShodanExtractor
    from .modules.abuseipdb import AbuseIPDBExtractor
    from .modules.greynoise import GreyNoiseExtractor
    from .modules.ipinfo import IPInfoExtractor
    from .modules.bgpview import BGPViewExtractor
    from .modules.multipleip import MultipleIPExtractor

    extractors = {
        'BGPView': BGPViewExtractor(),
        'IPInfo': IPInfoExtractor(),
    }
    if get_key('virustotal'):
        extractors['VirusTotal'] = VirusTotalAdapter()
    if get_key('alienvault'):
        extractors['AlienVault OTX'] = OTXAdapter()
    if get_key('shodan'):
        extractors['Shodan'] = ShodanExtractor()
    if get_key('abuseipdb'):
        extractors['AbuseIPDB'] = AbuseIPDBExtractor()
    if get_key('greynoise'):
        extractors['GreyNoise'] = GreyNoiseExtractor()
    MultipleIPExtractor(extractors).correlate(ip)


def run_cve(cve):
    """NIST NVD + VulnCheck KEV/MITRE/NVD2 search."""
    from .modules.nist import NISTExtractor
    from .modules.vulncheck import VulnCheckExtractor

    section(f"CVE WORKFLOW: {cve}", width=100)
    nist = NISTExtractor()
    nist.display(nist.query_cve(2, cve))

    vc = VulnCheckExtractor()
    if not vc.api_key:
        info("\nVulnCheck skipped (no VULNCHECK_API_KEY)")
    else:
        vc.display(vc.cve_search(cve), label="VULNCHECK KEV")
        vc.display(vc.mitre_search(cve), label="VULNCHECK MITRE")
        vc.display(vc.nist_search(cve), label="VULNCHECK NVD2")


def run_url(url):
    """URLScan submit + VT URL lookup (if keys)."""
    from .modules._adapters import VirusTotalAdapter
    from .modules.urlscanio import URLScanIOExtractor

    section(f"URL WORKFLOW: {url}", width=100)
    if get_key('urlscanio'):
        us = URLScanIOExtractor()
        us.display(us.submit(url), label="URLSCAN.IO SUBMIT")
    else:
        info("URLScan.io skipped (no URLSCANIO_API_KEY)")
    if get_key('virustotal'):
        vt = VirusTotalAdapter()
        VirusTotalAdapter.display_url(vt._raw_url_info(url))
    else:
        info("VirusTotal skipped (no VIRUSTOTAL_API_KEY)")


def run_domain(domain):
    """Whois + URLScan domain search + VT domain + OTX domain (if keys)."""
    from .modules._adapters import VirusTotalAdapter, OTXAdapter
    from .modules.whois_mod import WhoisExtractor
    from .modules.urlscanio import URLScanIOExtractor

    section(f"DOMAIN WORKFLOW: {domain}", width=100)
    WhoisExtractor().domain_whois(domain)
    if get_key('urlscanio'):
        us = URLScanIOExtractor()
        us.display(us.search_domain(domain), label="URLSCAN.IO DOMAIN")
    if get_key('virustotal'):
        vt = VirusTotalAdapter()
        VirusTotalAdapter.display_domain(vt._raw_domain_info(domain))
    if get_key('alienvault'):
        otx = OTXAdapter()
        OTXAdapter.display_general(otx._raw_domain_info(domain), label="OTX DOMAIN")


def run_file(path):
    """Extract IOCs from a file."""
    from .lib.ioc_extract import IOCExtractor
    IOCExtractor().extract_and_display(path)
