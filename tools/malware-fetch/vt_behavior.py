#!/usr/bin/env python3
"""VirusTotal behavior summary by SHA-256 hash.

Retrieves dynamic analysis behavior: DNS, HTTP, processes, files, registry.
"""
import argparse
import json
import os
import sys


def _vt_get(endpoint, api_key, timeout=30):
    try:
        import requests
    except ImportError:
        print("Error: requests not installed. Run: pip install requests", file=sys.stderr)
        sys.exit(1)
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/{endpoint}",
            headers={"x-apikey": api_key},
            timeout=timeout,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.Timeout:
        print("Error: VT API timeout", file=sys.stderr)
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        print(f"Error: VT API HTTP {e.response.status_code}", file=sys.stderr)
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="vt_behavior.py",
        description="VirusTotal behavior summary by SHA-256",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python vt_behavior.py abc123...
  python vt_behavior.py abc123... --json
  python vt_behavior.py abc123... -j --limit 10
""",
    )
    parser.add_argument("sha256", help="SHA-256 hash")
    parser.add_argument("--json", "-j", action="store_true", dest="json_output",
                        help="Output as JSON")
    parser.add_argument("--limit", "-n", type=int, default=20, metavar="N",
                        help="Max items per section (default: 20)")
    args = parser.parse_args()

    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        print("Error: VIRUSTOTAL_API_KEY not set in .env or environment", file=sys.stderr)
        sys.exit(1)

    resp_data = _vt_get(f"files/{args.sha256}/behaviour_summary", api_key)
    if "error" in resp_data:
        print(f"Error: {resp_data['error'].get('message', resp_data['error'])}", file=sys.stderr)
        sys.exit(1)

    data = resp_data.get("data", {})
    lim = args.limit

    dns = [{"hostname": x.get("hostname", "?"), "resolved_ips": x.get("resolved_ips", [])}
           for x in data.get("dns_lookups", [])[:lim]]
    http = [{"method": x.get("request_method", "?"), "url": x.get("url", "?"),
             "status": x.get("response_status_code", "?")}
            for x in data.get("http_conversations", [])[:lim]]
    ip = [{"dst": x.get("destination_ip", "?"), "port": x.get("destination_port", "?"),
           "proto": x.get("transport_layer_protocol", "?")}
          for x in data.get("ip_traffic", [])[:lim]]

    out = {
        "sha256": args.sha256,
        "dns_lookups": dns,
        "http_conversations": http,
        "ip_traffic": ip,
        "processes_created": data.get("processes_created", [])[:lim],
        "command_executions": data.get("command_executions", [])[:lim],
        "files_opened": data.get("files_opened", [])[:lim],
        "files_written": data.get("files_written", [])[:lim],
        "files_deleted": data.get("files_deleted", [])[:lim],
        "files_dropped": data.get("files_dropped", [])[:lim],
        "registry_keys_set": data.get("registry_keys_set", [])[:lim],
        "registry_keys_opened": data.get("registry_keys_opened", [])[:lim],
        "registry_keys_deleted": data.get("registry_keys_deleted", [])[:lim],
        "mutexes_created": data.get("mutexes_created", [])[:lim],
        "modules_loaded": data.get("modules_loaded", [])[:lim],
        "services_started": data.get("services_started", [])[:lim],
        "services_created": data.get("services_created", [])[:lim],
    }

    if args.json_output:
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0

    def _sec(title, items, fmt=None):
        if not items:
            return
        print(f"\n=== {title} ===")
        for item in items:
            if fmt:
                print(f"  {fmt(item)}")
            elif isinstance(item, dict):
                print(f"  {item}")
            else:
                print(f"  {item}")

    def _reg_fmt(x):
        return f"{x.get('key','?')} = {x.get('value','?')}" if isinstance(x, dict) else str(x)

    _sec("DNS Lookups", dns, lambda x: f"{x['hostname']} -> {x['resolved_ips']}")
    _sec("HTTP Conversations", http, lambda x: f"{x['method']} {x['url']} [{x['status']}]")
    _sec("IP Traffic", ip, lambda x: f"{x['dst']}:{x['port']} ({x['proto']})")
    _sec("Processes Created", out["processes_created"])
    _sec("Commands Executed", out["command_executions"])
    _sec("Files Opened", out["files_opened"])
    _sec("Files Written", out["files_written"])
    _sec("Files Deleted", out["files_deleted"])
    _sec("Files Dropped", out["files_dropped"])
    _sec("Registry Keys Set", out["registry_keys_set"], _reg_fmt)
    _sec("Registry Keys Opened", out["registry_keys_opened"], _reg_fmt)
    _sec("Registry Keys Deleted", out["registry_keys_deleted"], _reg_fmt)
    _sec("Mutexes Created", out["mutexes_created"])
    _sec("Modules Loaded", out["modules_loaded"])
    _sec("Services Started", out["services_started"])
    _sec("Services Created", out["services_created"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
