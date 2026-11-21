"""`intel-cli.py submit {plan|show|approve|run|ledger}`.

approve is HUMAN-ONLY: a PreToolUse hook (.claude/hooks/guard_submit_approve.py)
blocks Claude from running it or writing approval files. The human runs it
with `! python tools/threat-intel/intel-cli.py submit approve <plan_id>`.
"""

import json
import sys

from ..lib.config import _load_env
from . import ledger, precheck, router
from .manifest import ManifestError, load as load_manifest

CLI = 'python tools/threat-intel/intel-cli.py'
STATUS_LABEL = {'ready': 'READY', 'skip': 'SKIP', 'blocked': 'BLOCKED', 'manual': 'MANUAL'}


def _out(s=''):
    print(s)


def _short(s, n):
    s = str(s)
    return s if len(s) <= n else s[:n - 3] + '...'


def _render(plan, payloads=True):
    acts = plan['actions']
    _out(f"IOC SUBMISSION PLAN {plan['plan_id']}  ({plan['title']})")
    _out(f"manifest: {plan['manifest']}  created: {plan['created_at']}")
    _out(f"provenance claim: tlp={plan['tlp'] or '-'}  source={plan['source'] or '-'}  "
         f"(approve only if these samples/IOCs really are your own OSINT collection)")
    if plan.get('reference'):
        _out(f"public reference sent with submissions: {plan['reference']}")
    _out('-' * 100)
    _out(f"{'#':>3}  {'service':<11}{'ioc':<52}{'status':<9}")
    for a in acts:
        _out(f"{a['n']:>3}  {a['service']:<11}{_short(a['ioc'], 50):<52}{STATUS_LABEL[a['status']]:<9}")
        for r in a['reasons']:
            _out(f"       - {r}")
        for w in a['warnings']:
            _out(f"       ! {w}")
    counts = {k: sum(1 for a in acts if a['status'] == k) for k in STATUS_LABEL}
    _out('-' * 100)
    _out('  '.join(f"{STATUS_LABEL[k]}={v}" for k, v in counts.items()))
    ready = [a for a in acts if a['status'] == 'ready']
    if payloads and ready:
        _out()
        _out("Exact payloads that `submit run` will send (API keys added at send time, not stored):")
        for a in ready:
            _out(f"  [{a['n']}] {a['service']}: {json.dumps(a['request'], ensure_ascii=False)}")
    return ready


def cmd_plan(manifest_path, only=None, skip=None):
    _load_env()
    try:
        m = load_manifest(manifest_path)
        actions, mblocks = router.build_actions(m, only=only, skip=skip)
    except (ManifestError, ValueError) as e:
        print(f"Manifest error: {e}", file=sys.stderr)
        return 2
    if not mblocks:
        precheck.run(actions)
    plan = ledger.save_plan(m, actions)
    ready = _render(plan)
    _out()
    if ready:
        _out("No report or sample was published. Duplicate checks may have queried external services.")
        _out("Submissions are PUBLIC and PERMANENT.")
        _out("To approve, the HUMAN runs (Claude is blocked from this step):")
        _out(f"  ! {CLI} submit approve {plan['plan_id']}")
        _out(f"Then: {CLI} submit run {plan['plan_id']}")
    else:
        _out("No submittable actions.")
    return 0


def cmd_show(plan_id):
    try:
        _render(ledger.load_plan(plan_id))
    except (ValueError, FileNotFoundError) as e:
        print(str(e), file=sys.stderr)
        return 2
    return 0


def cmd_approve(plan_id):
    try:
        plan = ledger.load_plan(plan_id)
    except (ValueError, FileNotFoundError) as e:
        print(str(e), file=sys.stderr)
        return 2
    if ledger.plan_age(plan) > ledger.PLAN_TTL:
        print("Plan is older than 24h — re-run `submit plan` so pre-checks are fresh.", file=sys.stderr)
        return 2
    ready = _render(plan, payloads=True)
    if not ready:
        print("Plan has no READY actions; nothing to approve.", file=sys.stderr)
        return 2
    rec = ledger.write_approval(plan)
    _out()
    _out(f"APPROVED {len(ready)} action(s) of plan {plan_id} at {rec['approved_at']}.")
    _out(f"Run: {CLI} submit run {plan_id}")
    return 0


def _attempt_id(plan_id, a):
    return f"{plan_id}-{a['n']}"


def _record_attempt(plan_id, a):
    """Written BEFORE sending: if the process dies mid-request, the attempt stays
    'unresolved' and later plans block that IOC until a human checks the platform."""
    ledger.append({
        'event': 'attempt', 'attempt_id': _attempt_id(plan_id, a), 'plan_id': plan_id,
        'service': a['service'], 'ioc': precheck.ledger_key(a), 'type': a['type'], 'role': a['role'],
    })


def _record_result(plan_id, a, res):
    ledger.append({
        'event': 'result', 'attempt_id': _attempt_id(plan_id, a), 'plan_id': plan_id,
        'service': a['service'], 'ioc': precheck.ledger_key(a), 'ok': res.get('ok'),
        'duplicate': res.get('duplicate', False), 'uncertain': res.get('uncertain', False),
        'http_status': res.get('http_status'), 'link': res.get('link'),
        'error': res.get('error'), 'response': res.get('response'),
    })


def cmd_run(plan_id):
    from . import clients, samples
    _load_env()
    try:
        plan = ledger.load_plan(plan_id)
    except (ValueError, FileNotFoundError) as e:
        print(str(e), file=sys.stderr)
        return 2
    appr = ledger.load_approval(plan_id)
    if not appr:
        print(f"Plan {plan_id} is not approved. The human must run:\n  ! {CLI} submit approve {plan_id}",
              file=sys.stderr)
        return 3
    if appr.get('plan_sha256') != plan['plan_sha256']:
        print("Approval does not match this plan's digest — refusing.", file=sys.stderr)
        return 3
    if ledger.plan_age(plan) > ledger.PLAN_TTL:
        print("Plan is older than 24h — re-plan and re-approve.", file=sys.stderr)
        return 3
    if ledger.executed(plan_id):
        print(f"Plan {plan_id} was already executed (see `submit ledger`). Re-plan to submit again.",
              file=sys.stderr)
        return 3

    ready = [a for a in plan['actions'] if a['status'] == 'ready']
    results = []

    for a in (x for x in ready if x['kind'] == 'ioc'):
        _record_attempt(plan_id, a)
        res = clients.SUBMITTERS[a['service']](a['request'])
        _record_result(plan_id, a, res)
        results.append((a, res))

    groups = {}
    for a in (x for x in ready if x['kind'] == 'upload'):
        f = a['request']['file']
        groups.setdefault((f['path'], f['sha256'], f['filename']), []).append(a)
    for (path, sha, fname), acts in groups.items():
        reqs = {a['service']: {k: v for k, v in a['request'].items() if k != 'file'} for a in acts}
        for a in acts:
            _record_attempt(plan_id, a)
        out = samples.upload(path, sha, fname, reqs)
        for a in acts:
            res = out.get(a['service']) or {'ok': False, 'uncertain': True, 'error': 'no result from container'}
            _record_result(plan_id, a, res)
            results.append((a, res))

    _out(f"SUBMISSION RESULTS — plan {plan_id}")
    _out('-' * 100)
    bad = 0
    for a, res in results:
        if res.get('ok'):
            tag = 'DUPLICATE' if res.get('duplicate') else 'OK'
        else:
            tag = 'UNCERTAIN' if res.get('uncertain') else 'FAILED'
            bad += 1
        _out(f"{a['n']:>3}  {a['service']:<11}{_short(a['ioc'], 50):<52}{tag}")
        if res.get('link'):
            _out(f"       {res['link']}")
        if not res.get('ok'):
            _out(f"       attempt {_attempt_id(plan_id, a)} error: {res.get('error') or ''} "
                 f"{_short(res.get('response') or '', 300)}")
    _out('-' * 100)
    _out(f"done: {len(results) - bad} ok, {bad} failed/uncertain. Ledger: tools/threat-intel/data/submit/ledger.jsonl")
    return 0 if bad == 0 else 1


def cmd_ledger(last=20):
    recs = list(ledger.attempts().items())[-last:]
    if not recs:
        _out("ledger is empty")
        return 0
    for aid, rec in recs:
        a, f = rec['attempt'], rec['final'] or {}
        state = ledger.state_of(rec).upper()
        if f.get('event') == 'resolve':
            state += '(resolved)'
        _out(f"{a['ts'][:19]}  {aid:<16}{a.get('service'):<11}{_short(a.get('ioc'), 46):<48}{state:<18}{f.get('link') or ''}")
    return 0


def cmd_resolve(attempt_id, verdict):
    """Record the outcome of an UNRESOLVED/UNCERTAIN attempt after checking the platform.
    Only affects dedup; never sends anything (a re-submit still needs plan + human approval)."""
    if verdict not in ('ok', 'failed'):
        print("usage: submit resolve <attempt_id> ok|failed", file=sys.stderr)
        return 2
    rec = ledger.get_attempt(attempt_id)
    if not rec:
        print(f"unknown attempt {attempt_id!r} (see `submit ledger`)", file=sys.stderr)
        return 2
    st = ledger.state_of(rec)
    if st in ('ok', 'failed'):
        print(f"attempt {attempt_id} is already {st.upper()}; nothing to resolve", file=sys.stderr)
        return 2
    a = rec['attempt']
    ledger.append({'event': 'resolve', 'attempt_id': attempt_id, 'plan_id': a.get('plan_id'),
                   'service': a.get('service'), 'ioc': a.get('ioc'), 'ok': verdict == 'ok',
                   'uncertain': False})
    _out(f"attempt {attempt_id} ({a.get('service')} {a.get('ioc')}) marked {verdict.upper()}")
    return 0


def dispatch(action, value, only=None, skip=None, last=20, extra=None):
    try:
        sys.stdout.reconfigure(errors='replace')
    except Exception:
        pass
    if action == 'plan':
        return cmd_plan(value, only=only, skip=skip)
    if action == 'show':
        return cmd_show(value)
    if action == 'approve':
        return cmd_approve(value)
    if action == 'run':
        return cmd_run(value)
    if action == 'ledger':
        return cmd_ledger(last)
    if action == 'resolve':
        return cmd_resolve(value, extra)
    print(f"unknown submit action {action!r}", file=sys.stderr)
    return 2
