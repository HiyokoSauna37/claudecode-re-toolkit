#!/usr/bin/env python3
"""Sample uploader — runs ONLY inside the ti-sample-uploader container.

Input  : job JSON on stdin, encrypted blob mounted read-only at /in/sample.enc.gz
Output : one JSON line on stdout: {"results": {service: {...}}} or {"error": "..."}

The quarantine blob (gzip(iv || AES-256-CBC(PKCS7(plaintext))), key = SHA256(password))
is decrypted in memory, its SHA-256 is checked against the job, and the bytes
are streamed to each service. Nothing is written to disk; the container is
--read-only and removed afterwards. Stdlib + cryptography only.

Endpoints (verified against vendor docs, 2026-11):
  MalwareBazaar : POST https://mb-api.abuse.ch/api/v1/    Auth-Key header, multipart json_data + file
  VirusTotal    : POST https://www.virustotal.com/api/v3/files  x-apikey (>32MB: GET /files/upload_url first)
  Triage        : POST https://tria.ge/api/v0/samples     Bearer token, multipart _json + file
"""

import gzip
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
import uuid

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SAMPLE = '/in/sample.enc.gz'
VT_DIRECT_MAX = 32 * 1024 * 1024
VT_MAX = 650 * 1024 * 1024
UA = 'cc-re-toolkit-threat-intel/1.0'


def emit(obj, code=0):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + '\n')
    sys.stdout.flush()
    sys.exit(code)


def decrypt(path, password):
    with open(path, 'rb') as f:
        blob = gzip.decompress(f.read())
    iv, ct = blob[:16], blob[16:]
    key = hashlib.sha256(password.encode()).digest()
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpad = padding.PKCS7(128).unpadder()
    return unpad.update(padded) + unpad.finalize()


def safe_filename(name):
    name = re.sub(r'[\r\n"\\/]', '_', name or 'sample.bin').strip() or 'sample.bin'
    return name[:200]


def multipart(fields):
    """fields: list of (name, filename_or_None, content_type_or_None, bytes)."""
    boundary = uuid.uuid4().hex
    out = []
    for name, filename, ctype, data in fields:
        out.append(f'--{boundary}\r\n'.encode())
        disp = f'Content-Disposition: form-data; name="{name}"'
        if filename is not None:
            disp += f'; filename="{safe_filename(filename)}"'
        out.append((disp + '\r\n').encode())
        if ctype:
            out.append(f'Content-Type: {ctype}\r\n'.encode())
        out.append(b'\r\n')
        out.append(data)
        out.append(b'\r\n')
    out.append(f'--{boundary}--\r\n'.encode())
    return b''.join(out), f'multipart/form-data; boundary={boundary}'


def http(method, url, headers, body=None, timeout=600):
    """Single attempt, no retry. Returns (status, text)."""
    req = urllib.request.Request(url, data=body, method=method, headers={'User-Agent': UA, **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')


def result(ok, status=None, response='', link=None, error=None, duplicate=False):
    return {'ok': ok, 'http_status': status, 'response': (response or '')[:800],
            'link': link, 'error': error, 'duplicate': duplicate, 'uncertain': False}


def up_bazaar(data, filename, sha256, req):
    body, ctype = multipart([
        ('json_data', None, 'application/json', json.dumps(req['json_data']).encode()),
        ('file', filename, 'application/octet-stream', data),
    ])
    st, text = http('POST', 'https://mb-api.abuse.ch/api/v1/',
                    {'Auth-Key': os.environ['ABUSECH_AUTH_KEY'], 'Content-Type': ctype}, body)
    try:
        qs = json.loads(text).get('query_status')
    except ValueError:
        qs = None
    link = f'https://bazaar.abuse.ch/sample/{sha256}/'
    if qs == 'inserted':
        return result(True, st, text, link)
    if qs == 'file_already_known':
        return result(True, st, text, link, duplicate=True)
    return result(False, st, text, None, error=qs or f'HTTP {st}')


def up_virustotal(data, filename, sha256, req):
    if len(data) > VT_MAX:
        return result(False, error='file larger than 650MB (VirusTotal limit)')
    key = os.environ['VIRUSTOTAL_API_KEY']
    url = 'https://www.virustotal.com/api/v3/files'
    if len(data) > VT_DIRECT_MAX:
        st, text = http('GET', 'https://www.virustotal.com/api/v3/files/upload_url',
                        {'x-apikey': key, 'Accept': 'application/json'}, timeout=60)
        if st != 200:
            return result(False, st, text, error='could not get upload_url')
        url = json.loads(text)['data']
    body, ctype = multipart([('file', filename, 'application/octet-stream', data)])
    st, text = http('POST', url, {'x-apikey': key, 'Accept': 'application/json', 'Content-Type': ctype}, body)
    ok = st == 200
    return result(ok, st, text, f'https://www.virustotal.com/gui/file/{sha256}' if ok else None,
                  error=None if ok else f'HTTP {st}')


def up_triage(data, filename, sha256, req):
    body, ctype = multipart([
        ('_json', None, 'application/json', json.dumps(req.get('_json') or {'kind': 'file'}).encode()),
        ('file', filename, 'application/octet-stream', data),
    ])
    st, text = http('POST', 'https://tria.ge/api/v0/samples',
                    {'Authorization': f"Bearer {os.environ['TRIAGE_API_KEY']}", 'Content-Type': ctype}, body)
    sid = None
    try:
        sid = json.loads(text).get('id')
    except ValueError:
        pass
    ok = st == 200 and bool(sid)
    return result(ok, st, text, f'https://tria.ge/{sid}' if sid else None, error=None if ok else f'HTTP {st}')


UPLOADERS = {'bazaar': up_bazaar, 'virustotal': up_virustotal, 'triage': up_triage}


def main():
    if not os.path.exists('/.dockerenv'):
        emit({'error': 'refusing to run outside a container (no /.dockerenv) — never decrypt samples on the host'}, 2)
    try:
        job = json.loads(sys.stdin.read())
    except ValueError as e:
        emit({'error': f'bad job JSON: {e}'}, 2)
    password = os.environ.get('QUARANTINE_PASSWORD')
    if not password:
        emit({'error': 'QUARANTINE_PASSWORD not provided'}, 2)
    try:
        data = decrypt(SAMPLE, password)
    except Exception as e:
        emit({'error': f'decrypt failed: {type(e).__name__}: {e}'}, 3)
    actual = hashlib.sha256(data).hexdigest()
    if actual != job['sha256']:
        emit({'error': f'sha256 mismatch: manifest {job["sha256"]} != decrypted {actual} — wrong file, nothing uploaded'}, 3)

    filename = job.get('filename') or f'{actual}.bin'
    results = {}
    for svc, req in job['services'].items():
        fn = UPLOADERS.get(svc)
        if not fn:
            results[svc] = result(False, error=f'unknown service {svc}')
            continue
        try:
            results[svc] = fn(data, filename, actual, req)
        except Exception as e:
            results[svc] = result(False, error=f'{type(e).__name__}: {e}')
            results[svc]['uncertain'] = True
    del data
    emit({'results': results})


if __name__ == '__main__':
    main()
