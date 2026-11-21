"""Post-approval path with every network/docker call stubbed.

Covers: run refuses without approval, attempt-before-send ledger ordering,
ok / failed / uncertain / duplicate outcomes, refusal to re-run, resolve,
precheck blocking on unresolved attempts, and the exact multipart bodies the
in-container uploader would send (no network, nothing decrypted).
"""

import email
import email.policy
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from threat_intel.submit import cli, clients, ledger, precheck, samples  # noqa: E402

SHA = 'a' * 64


@pytest.fixture
def store(tmp_path, monkeypatch):
    # never reach the real ThreatFox `types` endpoint from tests
    monkeypatch.setattr(precheck, 'threatfox_type_pairs', lambda: {('botnet_cc', 'ip:port')})
    sub = tmp_path / 'submit'
    monkeypatch.setattr(ledger, 'SUBMIT_DIR', sub)
    monkeypatch.setattr(ledger, 'PLANS_DIR', sub / 'plans')
    monkeypatch.setattr(ledger, 'APPROVALS_DIR', sub / 'approvals')
    monkeypatch.setattr(ledger, 'LEDGER_FILE', sub / 'ledger.jsonl')
    return sub


def _manifest():
    return {'path': 't.iocs.yaml', 'sha256': '0' * 64, 'title': 't', 'tlp': 'clear',
            'source': 'osint', 'reference': None}


def _actions():
    def act(n, service, kind, ioc, req, typ='ip:port', role='c2'):
        return {'n': n, 'service': service, 'kind': kind, 'ioc_n': n, 'type': typ, 'role': role,
                'ioc': ioc, 'status': 'ready', 'reasons': [], 'warnings': [], 'request': req}
    f = {'path': 'tools/x/a.exe.enc.gz', 'filename': 'a.exe', 'sha256': SHA}
    return [
        act(1, 'threatfox', 'ioc', '1.2.3.4:443', {'query': 'submit_ioc', 'threat_type': 'botnet_cc',
                                                  'ioc_type': 'ip:port', 'iocs': ['1.2.3.4:443']}),
        act(2, 'abuseipdb', 'ioc', '1.2.3.4:443', {'ip': '1.2.3.4', 'categories': '15', 'comment': 'c'}),
        act(3, 'bazaar', 'upload', SHA, {'json_data': {'anonymous': 0}, 'file': f}, 'sha256', 'sample'),
        act(4, 'virustotal', 'upload', SHA, {'file': f}, 'sha256', 'sample'),
        {**act(5, 'urlhaus', 'ioc', 'http://x.example/p', {}), 'status': 'blocked'},
    ]


def _stub_send(monkeypatch, seen_attempts):
    def make(name, result):
        def fn(req):
            # attempt line must already be on disk when the request goes out
            seen_attempts.append(any(e.get('event') == 'attempt' and e['service'] == name
                                     for e in ledger.entries()))
            return result
        return fn
    monkeypatch.setitem(clients.SUBMITTERS, 'threatfox', make('threatfox', {'ok': True, 'link': 'L1'}))
    monkeypatch.setitem(clients.SUBMITTERS, 'abuseipdb',
                        make('abuseipdb', {'ok': False, 'uncertain': True, 'error': 'timeout'}))

    def fake_upload(path, sha, fname, reqs):
        assert set(reqs) == {'bazaar', 'virustotal'} and all('file' not in r for r in reqs.values())
        seen_attempts.append(sum(1 for e in ledger.entries() if e.get('event') == 'attempt') == 4)
        return {'bazaar': {'ok': True, 'duplicate': True, 'link': 'L3'},
                'virustotal': {'ok': False, 'error': 'HTTP 400'}}
    monkeypatch.setattr(samples, 'upload', fake_upload)


def test_run_refuses_without_approval(store, monkeypatch):
    plan = ledger.save_plan(_manifest(), _actions())
    called = []
    monkeypatch.setitem(clients.SUBMITTERS, 'threatfox', lambda r: called.append(r))
    assert cli.cmd_run(plan['plan_id']) == 3
    assert not called and ledger.entries() == []


def test_run_full_cycle(store, monkeypatch):
    plan = ledger.save_plan(_manifest(), _actions())
    ledger.write_approval(plan)
    seen = []
    _stub_send(monkeypatch, seen)

    assert cli.cmd_run(plan['plan_id']) == 1          # 1 failed + 1 uncertain
    assert seen and all(seen)                          # attempts were written before every send
    states = {rec['attempt']['service']: ledger.state_of(rec) for rec in ledger.attempts().values()}
    assert states == {'threatfox': 'ok', 'abuseipdb': 'uncertain', 'bazaar': 'ok', 'virustotal': 'failed'}
    assert 'urlhaus' not in states                     # blocked actions never sent

    # cannot replay the same approved plan
    assert cli.cmd_run(plan['plan_id']) == 3

    # dedup on the next plan: ok -> skip, uncertain -> blocked until resolved, failed -> retryable
    nxt = _actions()
    monkeypatch.setattr(precheck, 'get_key', lambda s: 'k')
    monkeypatch.setattr(precheck, 'CHECKS', {s: (lambda a: (False, None)) for s in precheck.CHECKS})
    precheck.run(nxt)
    st = {a['service']: a['status'] for a in nxt}
    assert st['threatfox'] == 'skip' and st['bazaar'] == 'skip'
    assert st['abuseipdb'] == 'blocked' and 'resolve' in nxt[1]['reasons'][-1]
    assert st['virustotal'] == 'ready'

    # human checked AbuseIPDB: the report is not there -> failed -> becomes retryable
    aid = f"{plan['plan_id']}-2"
    assert cli.cmd_resolve(aid, 'failed') == 0
    assert cli.cmd_resolve(aid, 'failed') == 2         # already resolved
    nxt = _actions()
    precheck.run(nxt)
    assert {a['service']: a['status'] for a in nxt}['abuseipdb'] == 'ready'


def test_unresolved_attempt_blocks(store, monkeypatch):
    """Simulate a process killed between attempt and result."""
    ledger.append({'event': 'attempt', 'attempt_id': 'deadbeef0000-1', 'plan_id': 'deadbeef0000',
                   'service': 'threatfox', 'ioc': '1.2.3.4:443'})
    assert ledger.executed('deadbeef0000')
    acts = _actions()
    monkeypatch.setattr(precheck, 'get_key', lambda s: 'k')
    monkeypatch.setattr(precheck, 'CHECKS', {s: (lambda a: (False, None)) for s in precheck.CHECKS})
    precheck.run(acts)
    assert acts[0]['status'] == 'blocked' and 'UNRESOLVED' in acts[0]['reasons'][-1]


def test_tampered_plan_rejected(store):
    plan = ledger.save_plan(_manifest(), _actions())
    p = ledger.PLANS_DIR / f"{plan['plan_id']}.json"
    d = json.loads(p.read_text(encoding='utf-8'))
    d['actions'][0]['request']['iocs'] = ['6.6.6.6:443']
    p.write_text(json.dumps(d), encoding='utf-8')
    with pytest.raises(ValueError):
        ledger.load_plan(plan['plan_id'])


# ── in-container uploader: request shapes (imported, never run as main) ──

def _load_uploader():
    spec = importlib.util.spec_from_file_location('upload_sample', ROOT / 'uploader' / 'upload_sample.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _parts(headers, body):
    msg = email.message_from_bytes(
        f"Content-Type: {headers['Content-Type']}\r\n\r\n".encode() + body, policy=email.policy.default)
    return {p.get_param('name', header='content-disposition'): p for p in msg.iter_parts()}


def test_uploader_bazaar_and_triage_multipart(monkeypatch):
    up = _load_uploader()
    calls = []

    def fake_http(method, url, headers, body=None, timeout=600):
        calls.append((method, url, headers, body))
        if 'mb-api' in url:
            return 200, '{"query_status": "inserted"}'
        return 200, '{"id": "261121-abc"}'
    monkeypatch.setattr(up, 'http', fake_http)
    monkeypatch.setenv('ABUSECH_AUTH_KEY', 'k1')
    monkeypatch.setenv('TRIAGE_API_KEY', 'k2')

    r = up.up_bazaar(b'MZ\x90\x00', 'a "x".exe', SHA, {'json_data': {'anonymous': 0, 'tags': ['t']}})
    assert r['ok'] and r['link'].endswith(f'/sample/{SHA}/')
    _, url, h, body = calls[-1]
    assert url == 'https://mb-api.abuse.ch/api/v1/' and h['Auth-Key'] == 'k1'
    parts = _parts(h, body)
    assert json.loads(parts['json_data'].get_content()) == {'anonymous': 0, 'tags': ['t']}
    assert parts['file'].get_filename() == 'a _x_.exe'          # quotes neutralised
    assert parts['file'].get_content() == b'MZ\x90\x00'

    r = up.up_triage(b'MZ', 'a.exe', SHA, {'_json': {'kind': 'file', 'interactive': False}})
    assert r['ok'] and r['link'] == 'https://tria.ge/261121-abc'
    _, url, h, body = calls[-1]
    assert url == 'https://tria.ge/api/v0/samples' and h['Authorization'] == 'Bearer k2'
    parts = _parts(h, body)
    assert json.loads(parts['_json'].get_content())['kind'] == 'file'


def test_uploader_bazaar_known_and_error(monkeypatch):
    up = _load_uploader()
    monkeypatch.setenv('ABUSECH_AUTH_KEY', 'k')
    monkeypatch.setattr(up, 'http', lambda *a, **k: (200, '{"query_status": "file_already_known"}'))
    r = up.up_bazaar(b'x', 'a', SHA, {'json_data': {}})
    assert r['ok'] and r['duplicate']
    monkeypatch.setattr(up, 'http', lambda *a, **k: (200, '{"query_status": "user_blacklisted"}'))
    r = up.up_bazaar(b'x', 'a', SHA, {'json_data': {}})
    assert not r['ok'] and r['error'] == 'user_blacklisted'


def test_uploader_virustotal_large_uses_upload_url(monkeypatch):
    up = _load_uploader()
    calls = []

    def fake_http(method, url, headers, body=None, timeout=600):
        calls.append((method, url))
        if url.endswith('/files/upload_url'):
            return 200, '{"data": "https://upload.example/abc"}'
        return 200, '{"data": {"id": "x"}}'
    monkeypatch.setattr(up, 'http', fake_http)
    monkeypatch.setattr(up, 'VT_DIRECT_MAX', 4)
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'k')
    assert up.up_virustotal(b'small', 'a', SHA, {})['ok']
    assert calls == [('GET', 'https://www.virustotal.com/api/v3/files/upload_url'),
                     ('POST', 'https://upload.example/abc')]
    calls.clear()
    monkeypatch.setattr(up, 'VT_DIRECT_MAX', 1024)
    up.up_virustotal(b'small', 'a', SHA, {})
    assert calls == [('POST', 'https://www.virustotal.com/api/v3/files')]


def test_urlhaus_success_requires_lookup_visibility(monkeypatch):
    class R:
        status_code = 200
        text = 'some undocumented body'
    monkeypatch.setattr(clients, '_post', lambda url, **kw: R())
    monkeypatch.setattr(clients, 'get_key', lambda s: 'k')
    req = {'anonymous': '0', 'submission': [{'url': 'http://x.example/p', 'threat': 'malware_download', 'tags': []}]}
    monkeypatch.setattr(clients, '_urlhaus_visible', lambda u: False)
    r = clients.urlhaus(req)
    assert not r['ok'] and r['uncertain']
    monkeypatch.setattr(clients, '_urlhaus_visible', lambda u: True)
    assert clients.urlhaus(req)['ok']


def test_threatfox_type_pair_not_listed_blocks(store, monkeypatch):
    monkeypatch.setattr(precheck, 'threatfox_type_pairs', lambda: {('botnet_cc', 'domain')})
    monkeypatch.setattr(precheck, 'get_key', lambda s: 'k')
    monkeypatch.setattr(precheck, 'CHECKS', {s: (lambda a: (False, None)) for s in precheck.CHECKS})
    acts = _actions()
    precheck.run(acts)
    assert acts[0]['status'] == 'blocked' and "types" in acts[0]['reasons'][-1]
    monkeypatch.setattr(precheck, 'threatfox_type_pairs', lambda: None)   # cannot verify -> warn only
    acts = _actions()
    precheck.run(acts)
    assert acts[0]['status'] == 'ready' and acts[0]['warnings']
