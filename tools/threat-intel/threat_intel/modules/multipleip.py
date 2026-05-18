"""Cross-service IP correlation.

Calls _raw_ip_info() (or get_ip_details()) on each registered extractor and
renders a stacked report.
"""

from ..lib.display import error, info, section


class MultipleIPExtractor:
    def __init__(self, extractors):
        self.extractors = extractors

    def correlate(self, ip):
        section("CONSOLIDATED IP CORRELATION REPORT")
        info(f"IP: {ip}")
        for name, ext in self.extractors.items():
            try:
                if hasattr(ext, 'get_ip_details'):
                    ext.get_ip_details(ip)
                elif hasattr(ext, '_raw_ip_info'):
                    data = ext._raw_ip_info(ip)
                    self._render(name, ext, data)
                else:
                    info(f"\n{name}: no IP method")
            except Exception as e:
                error(f"\n{name}: {e}")
        section("END OF CORRELATION")

    def _render(self, name, ext, data):
        from ._adapters import VirusTotalAdapter, OTXAdapter
        if not data or (isinstance(data, dict) and 'error' in data):
            info(f"\n{name}: {data.get('error', 'no data') if data else 'no data'}")
            return
        if isinstance(ext, VirusTotalAdapter):
            VirusTotalAdapter.display_ip(data, label=name)
        elif isinstance(ext, OTXAdapter):
            OTXAdapter.display_general(data, label=name)
        else:
            section(name)
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, (str, int, float)):
                        info(f"  {k}: {v}")
