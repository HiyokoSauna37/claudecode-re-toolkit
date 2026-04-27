#!/usr/bin/env python3
"""VirusTotal detailed file lookup by SHA-256 hash.

Retrieves comprehensive file metadata: detection stats, type, names, tags,
threat classification, and family information.
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
        prog="vt_lookup.py",
        description="VirusTotal detailed file lookup by SHA-256",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python vt_lookup.py abc123...
  python vt_lookup.py abc123... --json
  python vt_lookup.py abc123... -j
""",
    )
    parser.add_argument("sha256", help="SHA-256 hash")
    parser.add_argument("--json", "-j", action="store_true", dest="json_output",
                        help="Output as JSON")
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

    data = _vt_get(f"files/{args.sha256}", api_key)
    if "error" in data:
        print(f"Error: {data['error'].get('message', data['error'])}", file=sys.stderr)
        sys.exit(1)

    a = data.get("data", {}).get("attributes", {})
    s = a.get("last_analysis_stats", {})
    pop = a.get("popular_threat_classification") or {}
    families = pop.get("popular_threat_name", [])

    out = {
        "sha256": args.sha256,
        "detection": f"{s.get('malicious',0) + s.get('suspicious',0)}/{sum(s.values())}",
        "stats": s,
        "type": a.get("type_description", "?"),
        "size_bytes": a.get("size", "?"),
        "tags": a.get("tags", []),
        "names": a.get("names", [])[:10],
        "classification": pop.get("suggested_threat_label", "?"),
        "families": [(f["value"], f["count"]) for f in families[:5]],
    }

    if args.json_output:
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0

    print(f"Detection:      {out['detection']}")
    print(f"Type:           {out['type']}")
    print(f"Size:           {out['size_bytes']} bytes")
    if out["tags"]:
        print(f"Tags:           {out['tags']}")
    if out["names"]:
        print(f"Names:          {out['names']}")
    print(f"Classification: {out['classification']}")
    if out["families"]:
        print(f"Families:       {out['families']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
