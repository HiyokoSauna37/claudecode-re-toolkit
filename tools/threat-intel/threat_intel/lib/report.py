"""HTML / PDF report generator.

PDF uses weasyprint (optional dep). HTML is dark-themed self-contained.
"""

import os
import json
import tempfile
from datetime import datetime

from .display import info


class ReportGenerator:
    def __init__(self, data, title="Threat-Intel Report"):
        self.data = data
        self.title = title

    def to_html(self, output_path):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cards = ''
        for i, record in enumerate(self.data, 1):
            rows = ''
            for k, v in record.items():
                k_e = str(k).replace('&', '&amp;').replace('<', '&lt;')
                if isinstance(v, (dict, list)):
                    v_e = json.dumps(v, indent=2, default=str).replace('&', '&amp;').replace('<', '&lt;')
                    v_e = f'<pre>{v_e}</pre>'
                else:
                    v_e = str(v).replace('&', '&amp;').replace('<', '&lt;')
                rows += f'<tr><td class="key">{k_e}</td><td class="value">{v_e}</td></tr>\n'
            cards += f'<div class="card"><h3>Record {i}</h3><table>{rows}</table></div>\n'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{self.title}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: #1a1a2e; color: #e0e0e0; font-family: 'Courier New', monospace; padding: 20px; }}
h1 {{ color: #00d4ff; text-align: center; margin-bottom: 5px; font-size: 1.8em; }}
.timestamp {{ text-align: center; color: #888; margin-bottom: 30px; }}
.card {{ background: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 15px; margin-bottom: 20px; }}
.card h3 {{ color: #e94560; margin-bottom: 10px; border-bottom: 1px solid #0f3460; padding-bottom: 5px; }}
table {{ width: 100%; border-collapse: collapse; }}
tr:nth-child(even) {{ background: #1a1a3e; }}
td {{ padding: 6px 10px; vertical-align: top; border-bottom: 1px solid #0f3460; }}
td.key {{ color: #00d4ff; width: 200px; font-weight: bold; }}
td.value {{ color: #e0e0e0; word-break: break-all; }}
td.value pre {{ margin: 0; white-space: pre-wrap; font-family: inherit; }}
</style>
</head>
<body>
<h1>{self.title}</h1>
<div class="timestamp">Generated: {timestamp}</div>
{cards}
</body>
</html>"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        info(f"Report saved to: {output_path}")

    def to_pdf(self, output_path):
        try:
            import weasyprint
        except ImportError:
            info("Install weasyprint for PDF support: pip install weasyprint")
            return
        fd, html_path = tempfile.mkstemp(suffix='.html', prefix='threat_intel_')
        try:
            os.close(fd)
            self.to_html(html_path)
            weasyprint.HTML(filename=html_path).write_pdf(output_path)
        finally:
            try:
                os.remove(html_path)
            except OSError:
                pass
        info(f"PDF report saved to: {output_path}")
