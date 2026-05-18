"""Cross-service hash correlation.

Calls _raw_hash_info() on each registered extractor and renders a stacked
report. Extractors must implement _raw_hash_info(hash) -> dict | None.

Modules return error dicts {'error': '...'} for missing keys / API errors;
display methods handle them. Empty results render as "no record".
"""

from ..lib.display import error, info, section, field
from ..lib.output import collector


class MultipleHashExtractor:
    def __init__(self, extractors):
        self.extractors = extractors

    def correlate(self, hash_value):
        section("CONSOLIDATED HASH CORRELATION REPORT", width=100)
        info(f"Hash: {hash_value}")
        for name, ext in self.extractors.items():
            try:
                data = ext._raw_hash_info(hash_value)
                if not data:
                    info(f"\n{name}: no record")
                    continue
                self._render(name, ext, data)
            except Exception as e:
                error(f"\n{name}: {e}")
        section("END OF CORRELATION", width=100)

    def _render(self, name, ext, data):
        from ._adapters import VirusTotalAdapter, BazaarAdapter, OTXAdapter
        from .triage import TriageExtractor
        from .hybrid import HybridAnalysisExtractor
        from .urlhaus import URLHausExtractor

        if isinstance(ext, VirusTotalAdapter):
            VirusTotalAdapter.display_hash(data, label=name)
        elif isinstance(ext, BazaarAdapter):
            BazaarAdapter.display(data, label=name)
        elif isinstance(ext, OTXAdapter):
            OTXAdapter.display_general(data, label=name)
        elif isinstance(ext, TriageExtractor):
            ext.display_summary(data)
        elif isinstance(ext, HybridAnalysisExtractor):
            self._render_ha(name, data)
        elif isinstance(ext, URLHausExtractor):
            ext.display(data, label=name)
        else:
            section(name)
            for k, v in (data.items() if isinstance(data, dict) else []):
                if isinstance(v, (str, int, float)):
                    info(f"  {k}: {v}")
            collector.add({'source': name, **(data if isinstance(data, dict) else {})})

    def _render_ha(self, name, data):
        """Render Hybrid Analysis result inline (avoids a second fetch).

        HA's _raw_hash_info returns either a list of samples (success) or
        an error dict. Rendering inline lets correlation reuse the cached
        data without re-issuing the request.
        """
        section(name)
        if isinstance(data, dict) and 'error' in data:
            err = data['error']
            if err == 'not found':
                info("no record")
            else:
                error(err)
            return
        if isinstance(data, list) and data:
            sample = data[0]
        elif isinstance(data, dict):
            sample = data
        else:
            error("unexpected response")
            return
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
        collector.add({'source': name, **rec})
