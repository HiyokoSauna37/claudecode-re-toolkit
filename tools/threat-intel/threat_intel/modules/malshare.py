"""Malshare v1 client. Never raises."""

import os

from ..lib.session import create_session
from ..lib.config import get_key, missing_key_error
from ..lib.display import error, info, section, field
from ..lib.output import collector
from ..lib import configvars as cv


class MalshareExtractor:
    base = 'https://malshare.com/api.php'
    SERVICE = 'malshare'

    def __init__(self, api_key=None):
        self.api_key = api_key if api_key is not None else get_key(self.SERVICE)

    def _key_or_error(self):
        if not self.api_key:
            return missing_key_error(self.SERVICE)
        return None

    def _url(self, action, **extra):
        params = '&'.join(f"{k}={v}" for k, v in extra.items())
        sep = '&' if params else ''
        return f"{self.base}?api_key={self.api_key}&action={action}{sep}{params}"

    def list_type(self, file_type='PE32'):
        section(f"MALSHARE LIST ({file_type})")
        err = self._key_or_error()
        if err:
            error(err['error'])
            return
        action = 'getlist' if file_type.lower() == 'all' else 'type'
        url = self._url(action) if action == 'getlist' else self._url(action, type=file_type)
        try:
            r = create_session({'Accept': 'application/json'}).get(url, timeout=60)
            data = r.json()
        except Exception as e:
            error(str(e))
            return
        if not isinstance(data, list):
            error("unexpected response")
            return
        for item in data[:200]:
            field('SHA256', item.get('sha256'))
            field('MD5', item.get('md5'))
            collector.add({'sha256': item.get('sha256'), 'md5': item.get('md5'), 'type': file_type})
            print()

    def download(self, hash_value):
        err = self._key_or_error()
        if err:
            error(err['error'])
            return
        url = self._url('getfile', hash=hash_value)
        try:
            r = create_session().get(url, allow_redirects=False, stream=True, timeout=60)
        except Exception as e:
            error(str(e))
            return
        max_size = 500 * 1024 * 1024
        content = bytearray()
        for chunk in r.iter_content(chunk_size=8192):
            if not chunk:
                continue
            content += chunk
            if len(content) > max_size:
                error("File >500MB. Aborting.")
                return
        if b'Sample not found by hash' in content:
            error("Sample not found.")
            return
        out_path = os.path.join(cv.output_dir, os.path.basename(hash_value))
        try:
            with open(out_path, 'wb') as f:
                f.write(content)
            info(f"Downloaded to {out_path}")
        except OSError as e:
            error(f"Cannot write {out_path}: {e}")
