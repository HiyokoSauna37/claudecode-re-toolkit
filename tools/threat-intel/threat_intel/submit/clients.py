"""Host-side IOC submitters (ThreatFox / URLhaus / AbuseIPDB).

Deliberately NOT using lib.session.create_session: that session retries POST
on 5xx, which turns one public submission into several. Here every request
is sent exactly once; a timeout is recorded as "uncertain" so the human can
check the platform before re-running.
"""

import json
from urllib.parse import quote

import requests

from ..lib import configvars as cv
from ..lib.config import get_key

TIMEOUT = 60


def _post(url, **kw):
    proxies = {'http': cv.proxy, 'https': cv.proxy} if cv.proxy else None
    return requests.post(url, timeout=TIMEOUT, proxies=proxies, **kw)


def _result(ok, status=None, response=None, link=None, uncertain=False, error=None):
    if isinstance(response, (dict, list)):
        response = json.dumps(response, ensure_ascii=False)
    return {
        'ok': bool(ok), 'http_status': status,
        'response': (response or '')[:800], 'link': link,
        'uncertain': uncertain, 'error': error,
    }


def _guard(fn):
    def wrapper(req):
        try:
            return fn(req)
        except requests.Timeout:
            return _result(False, uncertain=True,
                           error="timeout after sending — the submission MAY have been accepted; check the platform")
        except requests.RequestException as e:
            return _result(False, error=f"{type(e).__name__}: {e}")
    return wrapper


@_guard
def threatfox(req):
    r = _post('https://threatfox-api.abuse.ch/api/v1/',
              headers={'Auth-Key': get_key('threatfox'), 'Content-Type': 'application/json'},
              data=json.dumps(req))
    try:
        d = r.json()
    except ValueError:
        d = r.text
    ok = r.status_code == 200 and isinstance(d, dict) and d.get('query_status') == 'ok'
    link = 'https://threatfox.abuse.ch/browse.php?search=ioc%3A' + quote(req['iocs'][0], safe='')
    return _result(ok, r.status_code, d, link)


@_guard
def urlhaus(req):
    # Per abuse.ch's reference client (abusech/URLhaus submit_url.py): Auth-Key header + JSON body.
    r = _post('https://urlhaus.abuse.ch/api/',
              headers={'Auth-Key': get_key('urlhaus'), 'Content-Type': 'application/json'},
              json=req)
    text = r.text or ''
    low = text.lower()
    ok = r.status_code == 200 and not any(w in low for w in ('error', 'invalid', 'denied', 'not allowed'))
    url = req['submission'][0]['url']
    link = 'https://urlhaus.abuse.ch/browse.php?search=' + quote(url, safe='')
    return _result(ok, r.status_code, text, link)


@_guard
def abuseipdb(req):
    r = _post('https://api.abuseipdb.com/api/v2/report',
              headers={'Key': get_key('abuseipdb'), 'Accept': 'application/json'},
              data=req)
    try:
        d = r.json()
    except ValueError:
        d = r.text
    ok = r.status_code == 200 and isinstance(d, dict) and 'data' in d
    return _result(ok, r.status_code, d, f"https://www.abuseipdb.com/check/{req['ip']}")


SUBMITTERS = {'threatfox': threatfox, 'urlhaus': urlhaus, 'abuseipdb': abuseipdb}
