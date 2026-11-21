"""Host-side driver for sample uploads. The host only ever touches the
encrypted .enc.gz; decryption + upload happen in the ti-sample-uploader
container (tools/threat-intel/uploader/)."""

import json
import os
import subprocess
from pathlib import Path

from ..lib.config import _load_env, env_var_for
from .manifest import REPO_ROOT

IMAGE = 'ti-sample-uploader:latest'
UPLOADER_DIR = Path(__file__).resolve().parents[2] / 'uploader'


def ensure_image():
    r = subprocess.run(['docker', 'image', 'inspect', IMAGE], capture_output=True, text=True)
    if r.returncode == 0:
        return None
    b = subprocess.run(['docker', 'build', '-t', IMAGE, str(UPLOADER_DIR)], capture_output=True, text=True)
    if b.returncode != 0:
        return f"docker build failed: {(b.stderr or b.stdout)[-600:]}"
    return None


def upload(file_rel, sha256, filename, service_requests):
    """service_requests: {service: request_without_file}. Returns {service: result}."""
    def fail(msg):
        return {s: {'ok': False, 'error': msg, 'uncertain': False, 'http_status': None,
                    'response': '', 'link': None} for s in service_requests}

    _load_env()
    needed = ['QUARANTINE_PASSWORD'] + [env_var_for(s) for s in service_requests]
    missing = [n for n in needed if not os.environ.get(n)]
    if missing:
        return fail(f"missing env: {', '.join(missing)}")
    err = ensure_image()
    if err:
        return fail(err)

    src = (REPO_ROOT / file_rel).resolve()
    cmd = [
        'docker', 'run', '--rm', '-i',
        '--read-only', '--tmpfs', '/tmp:rw,size=16m',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
        '--pids-limit', '64', '--memory', '2g',
        '-v', f"{src}:/in/sample.enc.gz:ro",
    ]
    for n in dict.fromkeys(needed):     # pass by name: values come from this process env, not argv
        cmd += ['-e', n]
    cmd.append(IMAGE)
    job = {'sha256': sha256, 'filename': filename, 'services': service_requests}
    try:
        p = subprocess.run(cmd, input=json.dumps(job), capture_output=True, text=True, timeout=1800)
    except subprocess.TimeoutExpired:
        r = fail("container timed out — uploads MAY have happened; check the platforms")
        for v in r.values():
            v['uncertain'] = True
        return r
    lines = [ln for ln in (p.stdout or '').splitlines() if ln.strip()]
    try:
        out = json.loads(lines[-1]) if lines else {}
    except ValueError:
        out = {}
    if 'results' in out:
        return out['results']
    return fail(out.get('error') or f"container exit {p.returncode}: {(p.stderr or '')[-400:]}")
