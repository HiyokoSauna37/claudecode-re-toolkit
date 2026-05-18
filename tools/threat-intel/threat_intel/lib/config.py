"""API key loader.

Reads from process env first; falls back to .env in repo root.
The repo root is detected by walking up from this file until .env is found.
"""

import os
from pathlib import Path

SERVICE_KEYS = {
    'virustotal': 'VIRUSTOTAL_API_KEY',
    'bazaar': 'ABUSECH_AUTH_KEY',
    'threatfox': 'ABUSECH_AUTH_KEY',
    'urlhaus': 'ABUSECH_AUTH_KEY',
    'hybrid': 'HYBRID_ANALYSIS_API_KEY',
    'triage': 'TRIAGE_API_KEY',
    'alienvault': 'ALIENVAULT_API_KEY',
    'malshare': 'MALSHARE_API_KEY',
    'malpedia': 'MALPEDIA_API_KEY',
    'urlscanio': 'URLSCANIO_API_KEY',
    'shodan': 'SHODAN_API_KEY',
    'abuseipdb': 'ABUSEIPDB_API_KEY',
    'greynoise': 'GREYNOISE_API_KEY',
    'ipinfo': 'IPINFO_API_KEY',
    'vulncheck': 'VULNCHECK_API_KEY',
    'nist': 'NIST_API_KEY',
}

_loaded = False


def _load_env():
    global _loaded
    if _loaded:
        return
    _loaded = True
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    here = Path(__file__).resolve()
    for parent in here.parents:
        env_path = parent / '.env'
        if env_path.is_file():
            load_dotenv(env_path)
            return


def get_key(service):
    _load_env()
    env_var = SERVICE_KEYS.get(service.lower())
    if not env_var:
        return ''
    return os.environ.get(env_var, '').strip()


def env_var_for(service):
    """Return the env-var name for a service, or '<unknown>' if not registered."""
    return SERVICE_KEYS.get(service.lower(), '<unknown>')


def missing_key_error(service):
    """Build a uniform error dict for modules to return when key missing."""
    return {'error': f"{service} API key not set. Configure {env_var_for(service)} in .env"}


def all_services():
    """Yield (service_name, env_var) for every registered service. Stable order."""
    for service, var in SERVICE_KEYS.items():
        yield service, var
