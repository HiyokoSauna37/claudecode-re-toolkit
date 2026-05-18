"""MITRE ATT&CK Enterprise matrix loader + tag mapper.

Caches the upstream JSON at ~/.threat_intel_attack.json for 7 days.
"""

import json
import os
import time
from pathlib import Path

from .session import create_session
from .display import error, info, table

ATTACK_URL = (
    'https://raw.githubusercontent.com/mitre/cti/master/'
    'enterprise-attack/enterprise-attack.json'
)
CACHE_FILE = os.path.join(str(Path.home()), '.threat_intel_attack.json')
CACHE_MAX_AGE = 7 * 24 * 3600


class AttackMapper:
    def __init__(self):
        self.techniques = {}
        if os.path.exists(CACHE_FILE):
            age = time.time() - os.path.getmtime(CACHE_FILE)
            if age < CACHE_MAX_AGE:
                try:
                    with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                        self._load_techniques(json.load(f))
                    return
                except (json.JSONDecodeError, OSError):
                    pass
        try:
            session = create_session()
            resp = session.get(ATTACK_URL, timeout=120)
            resp.raise_for_status()
            data = resp.json()
            with open(CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f)
            self._load_techniques(data)
        except Exception as e:
            error(f"Error downloading ATT&CK matrix: {e}")

    def _load_techniques(self, data):
        for obj in data.get('objects', []):
            if obj.get('type') != 'attack-pattern':
                continue
            ext_refs = obj.get('external_references', [])
            if not ext_refs:
                continue
            tid = ext_refs[0].get('external_id', '')
            url = ext_refs[0].get('url', '')
            phases = [p.get('phase_name', '') for p in obj.get('kill_chain_phases', [])]
            self.techniques[tid] = {
                'name': obj.get('name', ''),
                'description': obj.get('description', ''),
                'kill_chain_phases': phases,
                'url': url,
            }

    def map_tags(self, tags):
        matched = []
        for tag in tags:
            tag_lower = tag.lower()
            for tid, info_d in self.techniques.items():
                if tag_lower in tid.lower() or tag_lower in info_d['name'].lower():
                    matched.append({'id': tid, **info_d})
        return matched

    def display(self, techniques):
        if not techniques:
            info("No ATT&CK techniques matched.")
            return
        rows = [
            {
                'ID': t['id'],
                'Name': t['name'],
                'Tactics': ', '.join(t.get('kill_chain_phases', [])),
            }
            for t in techniques
        ]
        table(rows, ['ID', 'Name', 'Tactics'], [12, 40, 30])
