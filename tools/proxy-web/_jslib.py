"""
_jslib.py - Shared utilities for proxy-web JS analyzers

Used by: js_deobfuscate.py, clearfake_decode.py
"""

import base64
import gzip
import hashlib
import os
import re
import sys
import urllib.request
from pathlib import Path

UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    _CRYPTO_BACKEND = 'cryptography'
except ImportError:
    try:
        from Crypto.Cipher import AES  # type: ignore
        _CRYPTO_BACKEND = 'pycryptodome'
    except ImportError:
        _CRYPTO_BACKEND = None


def _load_dotenv_once():
    """Auto-load .env from project root (same discovery as proxy-web.exe)."""
    if os.environ.get('_JSLIB_ENV_LOADED'):
        return
    here = Path(__file__).resolve()
    # Walk up: Tools/proxy-web/_jslib.py → project root
    for parent in (here.parents[2], here.parents[1], Path.cwd()):
        env = parent / '.env'
        if env.exists():
            for line in env.read_text(encoding='utf-8', errors='ignore').splitlines():
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, _, v = line.partition('=')
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k and not os.environ.get(k):
                    os.environ[k] = v
            break
    os.environ['_JSLIB_ENV_LOADED'] = '1'


_load_dotenv_once()


def fetch_url(url: str, timeout: int = 15) -> str:
    """HTTP GET → UTF-8 text (errors='replace'). Raises on network error."""
    req = urllib.request.Request(url, headers={'User-Agent': UA, 'Accept': '*/*'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode('utf-8', errors='replace')


def decrypt_quarantine(path: str, password: str | None = None) -> str:
    """Decrypt an AES-256-CBC+gzip quarantine file produced by proxy-web.

    Format: gzip( IV[16] + AES-256-CBC(PKCS7(plaintext)) )
    Key:    SHA256(password)
    """
    if password is None:
        password = os.environ.get('QUARANTINE_PASSWORD', '')
    if not password:
        raise RuntimeError('QUARANTINE_PASSWORD not set')
    if _CRYPTO_BACKEND is None:
        raise RuntimeError("Install 'cryptography' or 'pycryptodome' to decrypt .enc.gz files")

    data = gzip.decompress(Path(path).read_bytes())
    iv, ciphertext = data[:16], data[16:]
    key = hashlib.sha256(password.encode()).digest()

    if _CRYPTO_BACKEND == 'cryptography':
        dec = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
        plaintext = dec.update(ciphertext) + dec.finalize()
    else:  # pycryptodome
        plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)

    pad_len = plaintext[-1]
    return plaintext[:-pad_len].decode('utf-8', errors='replace')


def unwrap_html_pre(js: str) -> str:
    """Strip <pre> wrapper from proxy-web page.html output and unescape entities."""
    m = re.search(r'<pre[^>]*>(.*)</pre>', js, re.DOTALL)
    if not m:
        return js
    content = m.group(1)
    return (content.replace('&amp;', '&').replace('&lt;', '<')
            .replace('&gt;', '>').replace('&#39;', "'").replace('&quot;', '"'))


def load_js_source(filepath: str | None, url: str | None = None) -> tuple[str, str]:
    """Load JS from file path, URL, or stdin. Returns (content, source_name).
    - url: fetched over HTTP (no disk write)
    - filepath '-' or None: stdin
    - filepath ending .enc.gz: auto-decrypted via QUARANTINE_PASSWORD
    - other: read as UTF-8 text file
    """
    if url:
        return fetch_url(url), url

    if filepath == '-' or filepath is None:
        return sys.stdin.read(), '<stdin>'

    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    if path.suffix == '.gz' and '.enc' in path.name:
        return decrypt_quarantine(str(path)), path.name

    return path.read_text(encoding='utf-8', errors='replace'), path.name


def decode_xor_base64(js: str) -> tuple[str | None, int | None]:
    """Decode XOR+Base64 obfuscation (ClearFake/BW-style loaders).

    Pattern:
        var _0xKEY  = NUMBER;
        var _0xDATA = 'BASE64_STRING';
        → base64decode(DATA) XOR KEY → plaintext JS

    Returns (decoded_str, xor_key) or (None, None) if pattern not found.
    """
    key_m = re.search(r'var\s+_0x\w+\s*=\s*(\d+)\s*;', js)
    str_m = re.search(r"var\s+_0x\w+\s*=\s*'([A-Za-z0-9+/=]{200,})'", js)
    if not (key_m and str_m):
        return None, None
    key = int(key_m.group(1))
    try:
        raw = base64.b64decode(str_m.group(1) + '==')
        return bytes(b ^ key for b in raw).decode('utf-8', errors='replace'), key
    except Exception:
        return None, None


# ClearFake signature strings — used for both config extraction and identification
_CF_CONTRACT_ADDRESS_RE = re.compile(r'CONTRACT_ADDRESS\s*:\s*[\'"]?(0x[a-fA-F0-9]{40})[\'"]?')
_CF_FUNCTION_SELECTOR_RE = re.compile(r'FUNCTION_SELECTOR\s*:\s*[\'"]([a-fA-F0-9]{8})[\'"]')
_CF_API_KEY_RE = re.compile(r'API_Q2_KEY_HEX\s*=\s*[\'"]([a-fA-F0-9]{64})[\'"]')
_CF_STORAGE_KEY_RE = re.compile(r"LOCAL_STORAGE_KEY\s*=\s*'([^']+)'")
_CF_MODE_MAP_RE = re.compile(r'MODE_FILE_MAP\s*=\s*\{([^}]+)\}', re.DOTALL)
_CF_MODE_ENTRY_RE = re.compile(r"(\w+)\s*:\s*'([^']+)'")
_CF_RPC_RE = re.compile(
    r'https://[a-zA-Z0-9\-._]+(?:polygon|matic|ankr|rpc|1rpc|blastapi|nodies|drpc|tenderly|tatum)[a-zA-Z0-9\-._/]*'
)
_CF_INIT_MARKERS = ('__BW_SCRIPT_INITIALIZED__', '__BW_MODE_RUN__', 'CONTRACT_CONFIG')


def extract_clearfake_config(js: str) -> dict:
    """Extract ClearFake blockchain C2 configuration.
    Returns dict with:
      is_clearfake, contract_address, function_selector, api_key_hex,
      storage_key, mode_map, rpc_hosts
    """
    cfg: dict = {
        'is_clearfake': False,
        'contract_address': None,
        'function_selector': None,
        'api_key_hex': None,
        'storage_key': None,
        'mode_map': {},
        'rpc_hosts': [],
    }

    if m := _CF_CONTRACT_ADDRESS_RE.search(js):
        cfg['contract_address'] = m.group(1)
        cfg['is_clearfake'] = True
    if m := _CF_FUNCTION_SELECTOR_RE.search(js):
        cfg['function_selector'] = m.group(1)
    if m := _CF_API_KEY_RE.search(js):
        cfg['api_key_hex'] = m.group(1)
    if m := _CF_STORAGE_KEY_RE.search(js):
        cfg['storage_key'] = m.group(1)
    if m := _CF_MODE_MAP_RE.search(js):
        cfg['mode_map'] = dict(_CF_MODE_ENTRY_RE.findall(m.group(1)))

    cfg['rpc_hosts'] = sorted(set(_CF_RPC_RE.findall(js)))

    if any(marker in js for marker in _CF_INIT_MARKERS):
        cfg['is_clearfake'] = True

    return cfg
