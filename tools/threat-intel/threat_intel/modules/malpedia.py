"""Malpedia client.

URL-encodes user input before insertion (CVE-style fix).
Never raises. Missing key produces error dict.
"""

import os
from urllib.parse import quote

from ..lib.session import create_session
from ..lib.cache import cached
from ..lib.config import get_key, missing_key_error
from ..lib.display import error, info, section, field
from ..lib.output import collector
from ..lib import configvars as cv


class MalpediaExtractor:
    base = 'https://malpedia.caad.fkie.fraunhofer.de/api'
    SERVICE = 'malpedia'

    def __init__(self, api_key=None):
        self.api_key = api_key if api_key is not None else get_key(self.SERVICE)

    def _key_or_error(self):
        if not self.api_key:
            return missing_key_error(self.SERVICE)
        return None

    def _session(self):
        return create_session({
            'Authorization': f'apitoken {self.api_key}',
            'Content-Type': 'application/json',
        })

    def _get(self, path, timeout=60):
        err = self._key_or_error()
        if err:
            return err
        try:
            r = self._session().get(f"{self.base}/{path}", timeout=timeout)
            if r.status_code != 200:
                return {'error': f"HTTP {r.status_code}"}
            return r.json()
        except Exception as e:
            return {'error': str(e)}

    @cached("malpedia_actors")
    def actors(self):
        return self._get('list/actors')

    @cached("malpedia_families")
    def families(self):
        return self._get('list/families')

    @cached("malpedia_payloads")
    def payloads(self):
        return self._get('list/samples')

    def get_actor(self, name):
        return self._get(f'get/actor/{quote(name, safe="")}')

    def get_family(self, name):
        return self._get(f'get/family/{quote(name, safe="")}')

    def get_yara(self, name):
        err = self._key_or_error()
        if err:
            error(err['error'])
            return
        try:
            r = self._session().get(
                f"{self.base}/get/yara/{quote(name, safe='')}/zip",
                stream=True, timeout=120,
            )
            if r.status_code != 200:
                error(f"HTTP {r.status_code}")
                return
            out_path = os.path.join(cv.output_dir, f"{name}_yara.zip")
            with open(out_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            info(f"YARA rules saved to {out_path}")
        except Exception as e:
            error(str(e))

    def get_sample(self, hash_value):
        err = self._key_or_error()
        if err:
            error(err['error'])
            return
        try:
            r = self._session().get(
                f"{self.base}/get/sample/{quote(hash_value, safe='')}/zip",
                stream=True, timeout=120,
            )
            if r.status_code != 200:
                error(f"HTTP {r.status_code}")
                return
            out_path = os.path.join(cv.output_dir, f"{hash_value}.zip")
            with open(out_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            info(f"Sample saved to {out_path} (password: infected)")
        except Exception as e:
            error(str(e))

    def display_list(self, data, label):
        section(label)
        if not data or (isinstance(data, dict) and 'error' in data):
            err = data.get('error', 'No data') if isinstance(data, dict) else 'No data'
            error(err)
            return
        if isinstance(data, dict):
            for k in sorted(data.keys()):
                info(k)
                collector.add({'name': k})
        elif isinstance(data, list):
            for k in sorted(data):
                info(str(k))
                collector.add({'name': k})

    def display_meta(self, data, label):
        section(label)
        if not data or (isinstance(data, dict) and 'error' in data):
            err = data.get('error', 'No data') if isinstance(data, dict) else 'No data'
            error(err)
            return
        for k, v in data.items():
            if isinstance(v, (str, int, float)):
                field(k, v)
        collector.add(data)
