"""Plan / approval / ledger storage under tools/threat-intel/data/submit/ (gitignored).

- plans/<plan_id>.json      : immutable plan; plan_id = first 12 hex of its content digest
- approvals/<plan_id>.json  : written ONLY by `submit approve` (human); binds the digest
- ledger.jsonl              : one line per executed action (idempotency + audit trail)
"""

import datetime as _dt
import hashlib
import json
import os
import re

from .manifest import DATA_DIR

SUBMIT_DIR = DATA_DIR / 'submit'
PLANS_DIR = SUBMIT_DIR / 'plans'
APPROVALS_DIR = SUBMIT_DIR / 'approvals'
LEDGER_FILE = SUBMIT_DIR / 'ledger.jsonl'

PLAN_ID_RE = re.compile(r'^[0-9a-f]{12}$')
PLAN_TTL = _dt.timedelta(hours=24)


def _now_iso():
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec='seconds')


def _digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False).encode('utf-8')).hexdigest()


def _check_id(plan_id):
    if not PLAN_ID_RE.match(plan_id or ''):
        raise ValueError(f"invalid plan id {plan_id!r} (12 hex chars)")


PLAN_KEYS = ('plan_version', 'manifest', 'manifest_sha256', 'title', 'tlp', 'source',
             'reference', 'created_at', 'actions')


def save_plan(manifest, actions):
    body = {
        'plan_version': 1,
        'manifest': manifest['path'],
        'manifest_sha256': manifest['sha256'],
        'title': manifest['title'],
        'tlp': manifest['tlp'],
        'source': manifest['source'],
        'reference': manifest['reference'],
        'created_at': _now_iso(),   # part of the digest: every planning run gets a fresh id
        'actions': actions,
    }
    digest = _digest(body)
    plan_id = digest[:12]
    plan = {**body, 'plan_id': plan_id, 'plan_sha256': digest}
    PLANS_DIR.mkdir(parents=True, exist_ok=True)
    (PLANS_DIR / f"{plan_id}.json").write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding='utf-8')
    return plan


def load_plan(plan_id):
    _check_id(plan_id)
    p = PLANS_DIR / f"{plan_id}.json"
    if not p.is_file():
        raise FileNotFoundError(f"plan {plan_id} not found — run `submit plan <manifest>` first")
    plan = json.loads(p.read_text(encoding='utf-8'))
    try:
        body = {k: plan[k] for k in PLAN_KEYS}
    except KeyError as e:
        raise ValueError(f"plan {plan_id} is from an older format — re-run `submit plan`") from e
    if _digest(body) != plan.get('plan_sha256') or not plan['plan_sha256'].startswith(plan_id):
        raise ValueError(f"plan {plan_id} was modified after creation — re-run `submit plan`")
    return plan


def plan_age(plan):
    created = _dt.datetime.fromisoformat(plan['created_at'])
    return _dt.datetime.now(_dt.timezone.utc) - created


def write_approval(plan):
    APPROVALS_DIR.mkdir(parents=True, exist_ok=True)
    rec = {'plan_id': plan['plan_id'], 'plan_sha256': plan['plan_sha256'], 'approved_at': _now_iso()}
    (APPROVALS_DIR / f"{plan['plan_id']}.json").write_text(json.dumps(rec, indent=2), encoding='utf-8')
    return rec


def load_approval(plan_id):
    _check_id(plan_id)
    p = APPROVALS_DIR / f"{plan_id}.json"
    if not p.is_file():
        return None
    return json.loads(p.read_text(encoding='utf-8'))


def append(entry):
    """Append one event. Events:
       attempt : written BEFORE sending (so a killed run still leaves a trace)
       result  : outcome of an attempt (ok / failed / uncertain)
       resolve : human/Claude verdict after checking the platform for an
                 unresolved or uncertain attempt (only affects dedup, never sends)
    """
    SUBMIT_DIR.mkdir(parents=True, exist_ok=True)
    entry = {'ts': _now_iso(), **entry}
    with open(LEDGER_FILE, 'a', encoding='utf-8') as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + '\n')
        fh.flush()
        os.fsync(fh.fileno())


def entries():
    if not LEDGER_FILE.is_file():
        return []
    out = []
    for line in LEDGER_FILE.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def attempts():
    """attempt_id -> {'attempt': entry, 'final': last result/resolve entry or None}."""
    out = {}
    for e in entries():
        aid = e.get('attempt_id')
        if not aid:
            continue
        if e.get('event') == 'attempt':
            out[aid] = {'attempt': e, 'final': None}
        elif e.get('event') in ('result', 'resolve') and aid in out:
            out[aid]['final'] = e
    return out


def state_of(rec):
    """ok | failed | uncertain | unresolved"""
    f = rec['final']
    if f is None:
        return 'unresolved'
    if f.get('ok'):
        return 'ok'
    return 'uncertain' if f.get('uncertain') else 'failed'


def lookup(service, ioc):
    """(state, attempt_entry, final_entry) of the most relevant attempt for (service, ioc):
    an 'ok' wins; otherwise any unresolved/uncertain one (must be checked by hand); else None."""
    best = None
    for rec in attempts().values():
        a = rec['attempt']
        if a.get('service') != service or a.get('ioc') != ioc:
            continue
        st = state_of(rec)
        if st == 'ok':
            return st, a, rec['final']
        if st in ('unresolved', 'uncertain'):
            best = (st, a, rec['final'])
    return best


def get_attempt(attempt_id):
    return attempts().get(attempt_id)


def executed(plan_id):
    return any(e.get('plan_id') == plan_id and e.get('event') == 'attempt' for e in entries())
