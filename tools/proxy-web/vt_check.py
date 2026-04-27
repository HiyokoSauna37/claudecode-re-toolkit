#!/usr/bin/env python3
"""VirusTotal file check by SHA-256 hash.

Queries VT API for detection rate, file type, threat classification,
and top malicious engine detections.
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
        prog="vt_check.py",
        description="VirusTotal detection check by SHA-256",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python vt_check.py abc123...
  python vt_check.py abc123... --json
  python vt_check.py abc123... -j --limit 5
""",
    )
    parser.add_argument("sha256", help="SHA-256 hash to check")
    parser.add_argument("--json", "-j", action="store_true", dest="json_output",
                        help="Output as JSON")
    parser.add_argument("--limit", "-n", type=int, default=15, metavar="N",
                        help="Max engine detections to show (default: 15)")
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

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    results = attrs.get("last_analysis_results", {})
    detections = sorted(
        [{"engine": k, "result": v["result"]}
         for k, v in results.items()
         if v.get("category") == "malicious" and v.get("result")],
        key=lambda x: x["engine"],
    )

    out = {
        "sha256": args.sha256,
        "detection": f"{stats.get('malicious', 0)}/{sum(stats.values())}",
        "stats": stats,
        "type": attrs.get("type_description", "N/A"),
        "name": attrs.get("meaningful_name", "N/A"),
        "tags": attrs.get("tags", []),
        "threat_label": (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label", "N/A"),
        "top_detections": detections[:args.limit],
    }

    if args.json_output:
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0

    print(f"Detection: {out['detection']}")
    print(f"Type:      {out['type']}")
    print(f"Name:      {out['name']}")
    if out["tags"]:
        print(f"Tags:      {out['tags']}")
    if out["threat_label"] != "N/A":
        print(f"Threat:    {out['threat_label']}")
    if out["top_detections"]:
        print(f"\nTop detections ({len(out['top_detections'])} / {len(detections)} total):")
        for d in out["top_detections"]:
            print(f"  {d['engine']}: {d['result']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
