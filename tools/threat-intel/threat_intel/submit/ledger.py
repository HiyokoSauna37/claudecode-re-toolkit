"""Plan / approval / ledger storage under tools/threat-intel/data/submit/ (gitignored).

- plans/<plan_id>.json      : immutable plan; plan_id = first 12 hex of its content digest
- approvals/<plan_id>.json  : written ONLY by `submit approve` (human); binds the digest
- ledger.jsonl              : one line per executed action (idempotency + audit trail)
"""

import datetime as _dt
import hashlib
import json
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


def save_plan(manifest, actions):
    body = {
        'plan_version': 1,
        'manifest': manifest['path'],
        'manifest_sha256': manifest['sha256'],
        'title': manifest['title'],
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
    body = {k: plan[k] for k in ('plan_version', 'manifest', 'manifest_sha256', 'title', 'created_at', 'actions')}
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
    SUBMIT_DIR.mkdir(parents=True, exist_ok=True)
    entry = {'ts': _now_iso(), **entry}
    with open(LEDGER_FILE, 'a', encoding='utf-8') as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + '\n')


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


def submitted_ok(service, ioc):
    for e in reversed(entries()):
        if e.get('service') == service and e.get('ioc') == ioc and e.get('ok'):
            return e
    return None


def executed(plan_id):
    return any(e.get('plan_id') == plan_id for e in entries())
