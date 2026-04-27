#!/usr/bin/env python3
"""c2cluster: C2 infrastructure cluster profiling

Given a seed (IP:port, ThreatFox tag, or IP list file), discover related C2 nodes,
probe each in parallel, and produce a consolidated fingerprint-grouped report.

Reproduces the manual workflow: ThreatFox tag search -> unique IPs -> parallel HTTP probe
-> banner/title extraction -> fingerprint grouping -> cluster summary.

Usage:
    # From ThreatFox tag (most common)
    python c2cluster.py profile --tag BotManager
    python c2cluster.py profile --tag AS216071 --limit 200

    # From seed IP:port (auto-resolves ThreatFox tags, then pivots)
    python c2cluster.py profile --seed 84.247.150.177:8000

    # From IP list file (one IP or IP:port per line)
    python c2cluster.py profile --ips-file ips.txt

    # Just list unique IPs (for piping into other tools)
    python c2cluster.py profile --tag BotManager --ips-only

Output (default):
    * Probe status per IP (OPEN/FILTERED/CLOSED/HTTP code)
    * Cluster summary grouped by (server-header + title) fingerprint
    * Panel candidates with URL + size for follow-up proxy-web fetch

JSON output (--json) includes full probe records for downstream tooling.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import add_output_args, emit_json

SCRIPT_DIR = Path(__file__).resolve().parent
PROXY_WEB = SCRIPT_DIR.parent / "proxy-web.exe"

# Common C2 ports to try when only an IP (no port) is supplied.
DEFAULT_PORTS = [8080, 443, 80, 8443, 8000, 8888, 5000, 3000, 4443, 4444]

# Kept narrow on purpose — a full scan belongs in proxy-web c2-profile.
PROBE_TIMEOUT_SEC = 6
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) c2cluster/1.0"


# ============================================================
# Input collection
# ============================================================

def ips_from_tag(tag: str, limit: int) -> list[str]:
    """Call threatfeed.py tag --ips to get unique IPs. Fails gracefully if missing."""
    bb_tf = SCRIPT_DIR / "threatfeed.py"
    if not bb_tf.exists():
        print(f"[!] threatfeed.py not found at {bb_tf}", file=sys.stderr)
        return []
    try:
        result = subprocess.run(
            ["python3", str(bb_tf), "tag", tag, "--limit", str(limit), "--ips"],
            capture_output=True, text=True, timeout=90,
        )
        if result.returncode != 0:
            print(f"[!] threatfeed tag {tag} failed: {result.stderr[:200]}", file=sys.stderr)
            return []
        ips = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return [ip for ip in ips if _looks_like_ip(ip)]
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[!] threatfeed call failed: {e}", file=sys.stderr)
        return []


def iocs_from_tag(tag: str, limit: int) -> list[dict]:
    """Call threatfeed.py tag --json to get full IOC records (for port info)."""
    bb_tf = SCRIPT_DIR / "threatfeed.py"
    if not bb_tf.exists():
        return []
    try:
        result = subprocess.run(
            ["python3", str(bb_tf), "tag", tag, "--limit", str(limit), "--json"],
            capture_output=True, text=True, timeout=90,
        )
        if result.returncode != 0:
            return []
        data = json.loads(result.stdout)
        return data.get("results", [])
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        return []


def tags_from_seed(seed: str) -> list[str]:
    """Run proxy-web threatfox ioc <seed> and extract tags from the response."""
    if not PROXY_WEB.exists():
        return []
    try:
        result = subprocess.run(
            [str(PROXY_WEB), "threatfox", "ioc", seed],
            capture_output=True, text=True, timeout=30,
        )
        tags: set[str] = set()
        for line in result.stdout.splitlines():
            m = re.match(r"\s*Tags:\s*\[(.+)\]", line)
            if m:
                for tok in m.group(1).split():
                    tok = tok.strip().strip(",")
                    if tok and tok.lower() not in {"unknown", "malware"}:
                        tags.add(tok)
        return sorted(tags)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def _looks_like_ip(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def parse_ip_port(entry: str) -> tuple[str, int | None]:
    """Parse 'ip:port' or 'ip' into (ip, port_or_none)."""
    if ":" in entry and "://" not in entry:
        host, _, port = entry.partition(":")
        try:
            return host, int(port)
        except ValueError:
            return host, None
    if "://" in entry:
        host = entry.split("://", 1)[1].split("/", 1)[0]
        if ":" in host:
            h, _, p = host.partition(":")
            try:
                return h, int(p)
            except ValueError:
                return h, None
        return host, None
    return entry, None


# ============================================================
# Probe
# ============================================================

def tcp_probe(ip: str, port: int, timeout: float = PROBE_TIMEOUT_SEC) -> str:
    """Classify a TCP port as OPEN / CLOSED / FILTERED.

    OPEN     = 3-way handshake succeeded
    CLOSED   = RST received (refused, service not running)
    FILTERED = timeout (firewall silently dropping packets)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return "OPEN"
    except socket.timeout:
        return "FILTERED"
    except ConnectionRefusedError:
        return "CLOSED"
    except OSError:
        return "FILTERED"
    finally:
        s.close()


def http_probe(ip: str, port: int, timeout: float = PROBE_TIMEOUT_SEC) -> dict:
    """Perform a single HTTP GET to the root path, extract banner + title + size."""
    scheme = "https" if port in (443, 8443, 4443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(4096)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            title = _extract_title(body)
            return {
                "url": url,
                "http_status": resp.status,
                "server": headers.get("server", ""),
                "content_type": headers.get("content-type", ""),
                "title": title,
                "location": headers.get("location", ""),
                "size": len(body),
            }
    except urllib.error.HTTPError as e:
        # HTTP error code — server is up, just returning non-2xx
        try:
            body = e.read(4096)
        except Exception:
            body = b""
        headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        return {
            "url": url,
            "http_status": e.code,
            "server": headers.get("server", ""),
            "content_type": headers.get("content-type", ""),
            "title": _extract_title(body),
            "location": headers.get("location", ""),
            "size": len(body) if body else 0,
        }
    except Exception as e:
        return {"url": url, "http_status": 0, "error": str(e)[:120]}


_title_re = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _extract_title(body: bytes) -> str:
    if not body:
        return ""
    m = _title_re.search(body)
    if not m:
        return ""
    try:
        return m.group(1).decode("utf-8", errors="replace").strip()[:200]
    except Exception:
        return ""


def probe_node(entry: str) -> dict:
    """Probe a single IP[:port] entry."""
    ip, port = parse_ip_port(entry)
    result: dict[str, Any] = {"ip": ip, "input": entry}

    if port is not None:
        tcp = tcp_probe(ip, port)
        result["port"] = port
        result["tcp"] = tcp
        if tcp == "OPEN":
            result.update(http_probe(ip, port))
        return result

    # No port specified: try DEFAULT_PORTS until one opens
    for p in DEFAULT_PORTS:
        tcp = tcp_probe(ip, p, timeout=3)
        if tcp == "OPEN":
            result["port"] = p
            result["tcp"] = tcp
            result.update(http_probe(ip, p))
            return result
    # None open
    result["port"] = None
    result["tcp"] = "ALL_CLOSED_OR_FILTERED"
    return result


# ============================================================
# Fingerprint grouping
# ============================================================

def fingerprint(node: dict) -> str:
    """Compact fingerprint for grouping nodes that share the same software."""
    if node.get("tcp") != "OPEN":
        return f"[{node.get('tcp', 'NO_PROBE')}]"
    server = (node.get("server") or "-").strip()
    title = (node.get("title") or "").strip() or "-"
    status = node.get("http_status", "-")
    return f"{status} | {server} | {title}"


def group_by_fingerprint(nodes: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for n in nodes:
        groups[fingerprint(n)].append(n)
    return dict(groups)


# ============================================================
# Subcommands
# ============================================================

def cmd_profile(args):
    # 1. Gather input IPs/entries
    entries: list[str] = []
    ioc_records: list[dict] = []

    if args.tag:
        ioc_records = iocs_from_tag(args.tag, args.limit)
        for r in ioc_records:
            ioc = r.get("ioc", "").strip()
            if ioc and not ioc.startswith("http"):
                entries.append(ioc)
        print(f"  [tag={args.tag}] resolved {len(entries)} IOCs (limit={args.limit})", file=sys.stderr)
    elif args.seed:
        entries.append(args.seed)
        tags = tags_from_seed(args.seed)
        if tags:
            print(f"  [seed={args.seed}] tags: {', '.join(tags)}", file=sys.stderr)
            for t in tags:
                if t.lower() in {"panel", "botnet", "c2"}:
                    # Too broad — pivoting these drowns us in noise
                    continue
                records = iocs_from_tag(t, args.limit)
                added = 0
                for r in records:
                    ioc = r.get("ioc", "").strip()
                    if ioc and not ioc.startswith("http"):
                        entries.append(ioc)
                        added += 1
                print(f"    pivot tag '{t}': +{added} IOCs", file=sys.stderr)
    elif args.ips_file:
        with open(args.ips_file, "r", encoding="utf-8") as f:
            entries = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not entries:
        print("[!] No entries to probe. Provide --tag / --seed / --ips-file.", file=sys.stderr)
        sys.exit(1)

    # Deduplicate (preserve first-seen port info)
    seen: set[str] = set()
    unique: list[str] = []
    for e in entries:
        if e not in seen:
            seen.add(e)
            unique.append(e)
    print(f"  [dedupe] {len(unique)} unique entries to probe", file=sys.stderr)

    if args.ips_only:
        for e in unique:
            print(e)
        return

    # 2. Parallel probe
    print(f"  [probe] parallel (threads={args.threads})...", file=sys.stderr)
    start = time.time()
    nodes: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        for node in ex.map(probe_node, unique):
            nodes.append(node)
            _short_print_progress(node)
    elapsed = time.time() - start
    print(f"  [probe] done in {elapsed:.1f}s", file=sys.stderr)

    # 3. Group by fingerprint
    groups = group_by_fingerprint(nodes)

    # 4. Output
    if args.json:
        emit_json(
            {
                "source": {"tag": args.tag, "seed": args.seed, "ips_file": args.ips_file},
                "total_nodes": len(nodes),
                "groups": {fp: [n for n in ns] for fp, ns in groups.items()},
                "nodes": nodes,
                "iocs": ioc_records,
            },
            args, tool="c2cluster", command="profile",
        )
        return

    _print_text_report(nodes, groups, args)


def _short_print_progress(node: dict):
    ip = node.get("ip", "?")
    port_val = node.get("port")
    port = "-" if port_val is None else str(port_val)
    tcp = node.get("tcp") or "-"
    status = node.get("http_status", "")
    server = (node.get("server") or "")[:30]
    title = (node.get("title") or "")[:40]
    line = f"    {ip}:{port:<6} {tcp:<10} {status} {server} {title}"
    print(line, file=sys.stderr)


def _print_text_report(nodes: list[dict], groups: dict[str, list[dict]], args) -> None:
    print(f"\n{'='*60}")
    print(f"  C2 Cluster Profile")
    print(f"{'='*60}")
    print(f"  Total nodes: {len(nodes)}")
    print(f"  Fingerprint groups: {len(groups)}")

    # Group table: biggest group first
    for fp, members in sorted(groups.items(), key=lambda x: -len(x[1])):
        print(f"\n  [{len(members):>3}] {fp}")
        for n in members[:10]:
            ip = n.get("ip", "?")
            port_val = n.get("port")
            port = "-" if port_val is None else str(port_val)
            url = n.get("url", "")
            tcp = n.get("tcp") or "-"
            print(f"        {ip}:{port:<6} {tcp:<10} {url}")
        if len(members) > 10:
            print(f"        ... +{len(members)-10} more")

    # Panel candidates (OPEN + HTML title present)
    panels = [
        n for n in nodes
        if n.get("tcp") == "OPEN" and (n.get("title") or "login" in (n.get("location") or "").lower())
    ]
    if panels:
        print(f"\n  Panel candidates ({len(panels)}):")
        for n in panels[:20]:
            ip = n.get("ip", "?")
            port = n.get("port", "-")
            print(f"    * {ip}:{port}  {n.get('server', ''):<30}  \"{n.get('title', '')}\"")
            loc = n.get("location", "")
            if loc:
                print(f"      -> Location: {loc}")
    print()


def cmd_fp_hunt(args):
    """Hunt for an existing fingerprint across a list of candidate IPs."""
    with open(args.ips_file, "r", encoding="utf-8") as f:
        entries = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    matcher_title = args.title.lower() if args.title else ""
    matcher_server = args.server.lower() if args.server else ""

    print(f"  [hunt] {len(entries)} entries / title~={matcher_title!r} server~={matcher_server!r}", file=sys.stderr)
    hits: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        for node in ex.map(probe_node, entries):
            title = (node.get("title") or "").lower()
            server = (node.get("server") or "").lower()
            if matcher_title and matcher_title not in title:
                continue
            if matcher_server and matcher_server not in server:
                continue
            hits.append(node)
            print(f"    HIT {node.get('ip')}:{node.get('port')}  \"{node.get('title', '')}\"", file=sys.stderr)

    if args.json:
        emit_json(
            {"total_candidates": len(entries), "hits": hits,
             "matchers": {"title": args.title, "server": args.server}},
            args, tool="c2cluster", command="fp-hunt",
        )
    else:
        print(f"\n  {len(hits)} hits / {len(entries)} candidates")
        for h in hits:
            print(f"    {h.get('ip')}:{h.get('port')}  \"{h.get('title', '')}\"  ({h.get('server', '')})")


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        prog="c2cluster",
        description="C2 infrastructure cluster profiling (tag/seed -> parallel probe -> fingerprint grouping)",
    )
    sub = parser.add_subparsers(dest="command")

    # profile (main)
    p = sub.add_parser("profile", help="Profile a C2 cluster from tag/seed/file")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--tag", help="ThreatFox tag (e.g. BotManager, AS216071)")
    src.add_argument("--seed", help="Seed IP[:port] — auto-resolves tags then pivots")
    src.add_argument("--ips-file", help="File with one IP or IP:port per line")
    p.add_argument("--limit", type=int, default=200, help="Max IOCs per tag (default 200)")
    p.add_argument("--threads", type=int, default=20, help="Parallel probe threads (default 20)")
    p.add_argument("--ips-only", action="store_true", help="Print unique IPs only, skip probe")
    add_output_args(p, include=("json", "output"))
    p.set_defaults(func=cmd_profile)

    # fp-hunt (fingerprint-based hunt across an existing IP list)
    h = sub.add_parser("fp-hunt", help="Hunt candidates by fingerprint (title/server match)")
    h.add_argument("ips_file", help="File with one IP or IP:port per line")
    h.add_argument("--title", help="Substring match against <title> (case-insensitive)")
    h.add_argument("--server", help="Substring match against Server header")
    h.add_argument("--threads", type=int, default=20)
    add_output_args(h, include=("json", "output"))
    h.set_defaults(func=cmd_fp_hunt)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()
