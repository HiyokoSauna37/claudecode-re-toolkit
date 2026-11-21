"""Offline tests for the submission guards / router (no network, no docker).

    python -m pytest tools/threat-intel/tests -q
"""

import datetime as dt
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from threat_intel.submit import guards, router  # noqa: E402
from threat_intel.submit.manifest import refang  # noqa: E402

NOW = dt.datetime.now(dt.timezone.utc)


def ioc(**kw):
    base = dict(n=1, type='ip:port', role='c2', value='1.2.3.4:443', malware='win.lumma',
                confidence=80, tags=[], comment=None, first_seen=NOW, verified_online_at=NOW,
                abuseipdb_categories=[], only=[], skip=[], allow_query=False, file=None,
                filename=None, delivery_method='web_download')
    base.update(kw)
    return base


def manifest(*iocs, **kw):
    m = dict(path='t.iocs.yaml', sha256='0' * 64, title='t', report=None, tlp='clear',
             source='osint', reference=None, iocs=list(iocs))
    m.update(kw)
    return m


def by_service(actions):
    return {a['service']: a for a in actions}


def test_refang():
    assert refang('hxxps://evil[.]example(.)com[:]8080/a') == 'https://evil.example.com:8080/a'


def test_non_global_ips_blocked():
    for v in ('10.0.0.5', '192.168.1.1', '127.0.0.1', '203.0.113.9', '198.18.0.1', '100.64.1.1', '169.254.1.1'):
        blocks, _ = guards.check_ioc(ioc(type='ip', value=v))
        assert blocks, v


def test_allowlist_domain_blocked_but_url_only_warned():
    b, _ = guards.check_ioc(ioc(type='domain', value='api.ipify.org'))
    assert b
    b, w = guards.check_ioc(ioc(type='url', value='https://raw.githubusercontent.com/x/y/main/p.exe',
                                role='payload_delivery'))
    assert not b and w


def test_victim_identifiers_in_url_blocked():
    for u in ('https://bad.example/l?email=a%40b.co', 'https://bad.example/l?token=abc',
              'https://bad.example/a@b.co/x'):
        b, _ = guards.check_ioc(ioc(type='url', value=u, role='payload_delivery'))
        assert b, u
    b, _ = guards.check_ioc(ioc(type='url', value='https://bad.example/l?token=abc',
                                role='payload_delivery', allow_query=True))
    assert not b


def test_public_text_rejects_paths_and_emails():
    assert guards.check_public_text('comment', r'dropped to C:\Users\bob\AppData')
    assert guards.check_public_text('comment', 'contact me at someone@example.com')
    assert not guards.check_public_text('comment', 'Lumma C2 behind Cloudflare')


def test_tlp_and_source_default_deny():
    acts, mb = router.build_actions(manifest(ioc(), tlp='amber'))
    assert mb and all(a['status'] == 'blocked' for a in acts)
    acts, mb = router.build_actions(manifest(ioc(), source=''))
    assert mb and all(a['status'] == 'blocked' for a in acts)


def test_c2_routing_and_abuseipdb_dedup():
    acts, _ = router.build_actions(manifest(ioc(), ioc(n=2, type='ip', value='1.2.3.4')))
    svcs = [a['service'] for a in acts]
    assert svcs.count('abuseipdb') == 1 and 'threatfox' in svcs
    tf = by_service(acts)['threatfox']['request']
    assert tf['threat_type'] == 'botnet_cc' and tf['ioc_type'] == 'ip:port' and tf['anonymous'] == 0
    ab = by_service(acts)['abuseipdb']['request']
    assert ab['ip'] == '1.2.3.4' and ab['categories'] == '15,20'


def test_phishing_landing_goes_manual_not_urlhaus():
    acts, _ = router.build_actions(manifest(ioc(type='url', value='https://phish.example/login',
                                                role='phishing_landing')))
    assert [a['service'] for a in acts] == ['manual']


def test_urlhaus_requires_recent_verification():
    stale = NOW - dt.timedelta(days=3)
    acts, _ = router.build_actions(manifest(ioc(type='url', value='http://bad.example/p.exe',
                                                role='payload_delivery', verified_online_at=stale)))
    assert by_service(acts)['urlhaus']['status'] == 'blocked'
    acts, _ = router.build_actions(manifest(ioc(type='url', value='http://bad.example/p.exe',
                                                role='payload_delivery')))
    uh = by_service(acts)['urlhaus']
    assert uh['status'] == 'ready' and uh['request']['anonymous'] == '0'
    assert uh['request']['submission'][0]['threat'] == 'malware_download'


def test_sample_requires_encrypted_file_and_mb_age():
    old = NOW - dt.timedelta(days=30)
    acts, _ = router.build_actions(manifest(ioc(type='sha256', value='a' * 64, role='sample', first_seen=old)))
    s = by_service(acts)
    assert all(s[x]['status'] == 'blocked' for x in ('bazaar', 'virustotal', 'triage'))
    assert any('10 days' in r for r in s['bazaar']['reasons'])
    assert any('.enc.gz' in r for r in s['virustotal']['reasons'])


def test_bad_malpedia_name_blocks_threatfox():
    acts, _ = router.build_actions(manifest(ioc(malware='Lumma')))
    assert by_service(acts)['threatfox']['status'] == 'blocked'
