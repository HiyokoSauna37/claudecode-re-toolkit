#!/usr/bin/env python3
"""iocminer: IOC pattern analysis & threat campaign clustering

Adapted from Ytools AI Engine concepts (clustering, NER, pattern mining, co-occurrence).
Analyzes IOC lists to discover:
- Related infrastructure (same ASN, subnet, registrar patterns)
- Campaign clusters (IOCs that appear together)
- Pattern extraction (common URL paths, domain naming conventions)
- Timeline analysis (first/last seen, activity windows)

Usage:
    python iocminer.py cluster ips.txt
    python iocminer.py cluster iocs.txt --type mixed
    python iocminer.py patterns urls.txt
    python iocminer.py cooccurrence iocs.txt
    python iocminer.py timeline iocs.txt
    python iocminer.py enrich ips.txt --json
    echo "1.2.3.4" | python iocminer.py enrich -
"""

import argparse
import ipaddress
import json
import os
import re
import sys
from collections import Counter, defaultdict
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import add_output_args, emit_json

# ============================================================
# IOC type detection
# ============================================================

IOC_PATTERNS = {
    "ipv4": re.compile(r"^(\d{1,3}\.){3}\d{1,3}$"),
    "ipv4_port": re.compile(r"^(\d{1,3}\.){3}\d{1,3}:\d+$"),
    "ipv6": re.compile(r"^([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}$"),
    "domain": re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$"),
    "url": re.compile(r"^https?://"),
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "email": re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"),
}

DEFANG_RULES = [
    (re.compile(r"hxxps?", re.I), lambda m: m.group().replace("xx", "tt")),
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[at\]", re.I), "@"),
    (re.compile(r"\[dot\]", re.I), "."),
]


def refang(text):
    """Convert defanged IOC to fanged"""
    for pattern, repl in DEFANG_RULES:
        if callable(repl):
            text = pattern.sub(repl, text)
        else:
            text = pattern.sub(repl, text)
    return text


def detect_ioc_type(value):
    """Detect the type of an IOC"""
    value = value.strip()
    for ioc_type, pattern in IOC_PATTERNS.items():
        if pattern.match(value):
            return ioc_type
    return "unknown"


def parse_ioc(line):
    """Parse a single IOC line"""
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("//"):
        return None

    # Handle CSV/TSV (take first column or column with IOC)
    for sep in ["\t", ",", "|", ";"]:
        if sep in line:
            parts = [p.strip().strip('"') for p in line.split(sep)]
            for p in parts:
                refanged = refang(p)
                if detect_ioc_type(refanged) != "unknown":
                    line = refanged
                    break
            break
    else:
        line = refang(line)

    ioc_type = detect_ioc_type(line)
    if ioc_type == "unknown":
        return None

    result = {"value": line, "type": ioc_type}

    # Extract additional info based on type
    if ioc_type == "ipv4_port":
        ip, port = line.rsplit(":", 1)
        result["ip"] = ip
        result["port"] = int(port)
    elif ioc_type == "url":
        parsed = urlparse(line)
        result["domain"] = parsed.netloc
        result["path"] = parsed.path
        result["scheme"] = parsed.scheme
    elif ioc_type == "domain":
        parts = line.split(".")
        result["tld"] = parts[-1]
        result["sld"] = ".".join(parts[-2:])

    return result


def read_iocs(source):
    """Read IOCs from file, stdin, or single value"""
    iocs = []
    if source == "-":
        lines = sys.stdin.read().splitlines()
    elif any(c in source for c in [".", ":", "/"]) and detect_ioc_type(refang(source)) != "unknown":
        lines = [source]
    else:
        try:
            with open(source, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"[!] File not found: {source}", file=sys.stderr)
            sys.exit(1)

    for line in lines:
        parsed = parse_ioc(line)
        if parsed:
            iocs.append(parsed)

    return iocs


# ============================================================
# Analysis functions
# ============================================================

def cluster_by_subnet(iocs, prefix_len=24):
    """Cluster IPs by subnet (default /24)"""
    clusters = defaultdict(list)
    for ioc in iocs:
        if ioc["type"] in ("ipv4", "ipv4_port"):
            ip = ioc.get("ip", ioc["value"])
            try:
                net = ipaddress.ip_network(f"{ip}/{prefix_len}", strict=False)
                clusters[str(net)].append(ioc)
            except ValueError:
                pass
    return dict(sorted(clusters.items(), key=lambda x: len(x[1]), reverse=True))


def cluster_by_asn_range(iocs):
    """Cluster IPs by /16 range (rough ASN approximation)"""
    clusters = defaultdict(list)
    for ioc in iocs:
        if ioc["type"] in ("ipv4", "ipv4_port"):
            ip = ioc.get("ip", ioc["value"])
            parts = ip.split(".")
            prefix = f"{parts[0]}.{parts[1]}.0.0/16"
            clusters[prefix].append(ioc)
    return dict(sorted(clusters.items(), key=lambda x: len(x[1]), reverse=True))


def _resolve_asn_cymru(ip):
    """Resolve IP to ASN using Team Cymru DNS (amass concept).

    Query: <reversed-IP>.origin.asn.cymru.com TXT
    Returns: (asn, prefix, org_name) or None
    """
    import socket
    parts = ip.split(".")
    reversed_ip = ".".join(reversed(parts))
    try:
        # Step 1: Get ASN + prefix
        answers = socket.getaddrinfo(
            f"{reversed_ip}.origin.asn.cymru.com", None, socket.AF_INET,
            socket.SOCK_DGRAM, 0, 0
        )
        # Fallback: use subprocess for TXT record (socket can't do TXT)
        import subprocess
        result = subprocess.run(
            ["nslookup", "-type=TXT", f"{reversed_ip}.origin.asn.cymru.com"],
            capture_output=True, text=True, timeout=5
        )
        # Parse TXT record: "ASN | prefix | CC | registry | allocated"
        for line in result.stdout.split("\n"):
            if "|" in line:
                txt = line.strip().strip('"').strip()
                fields = [f.strip() for f in txt.split("|")]
                if len(fields) >= 3:
                    asn = fields[0].strip('"').strip()
                    prefix = fields[1]
                    # Step 2: Get org name
                    try:
                        result2 = subprocess.run(
                            ["nslookup", "-type=TXT", f"AS{asn}.asn.cymru.com"],
                            capture_output=True, text=True, timeout=5
                        )
                        for line2 in result2.stdout.split("\n"):
                            if "|" in line2:
                                fields2 = [f.strip().strip('"') for f in line2.split("|")]
                                org = fields2[-1].strip() if len(fields2) >= 5 else "?"
                                return (f"AS{asn}", prefix, org)
                    except Exception:
                        pass
                    return (f"AS{asn}", prefix, "?")
    except Exception:
        pass
    return None


def cluster_by_asn(iocs, max_lookups=50):
    """Cluster IPs by ASN using Team Cymru DNS (amass concept).

    Groups IOCs by their actual ASN and organization, identifying
    shared attacker infrastructure across different IP ranges.
    """
    asn_cache = {}  # ip -> (asn, prefix, org)
    clusters = defaultdict(lambda: {"org": "?", "prefix": set(), "iocs": []})

    ip_iocs = [ioc for ioc in iocs if ioc["type"] in ("ipv4", "ipv4_port")]

    for ioc in ip_iocs[:max_lookups]:
        ip = ioc.get("ip", ioc["value"])
        if ip not in asn_cache:
            info = _resolve_asn_cymru(ip)
            asn_cache[ip] = info

        info = asn_cache.get(ip)
        if info:
            asn, prefix, org = info
            clusters[asn]["org"] = org
            clusters[asn]["prefix"].add(prefix)
            clusters[asn]["iocs"].append(ioc)
        else:
            clusters["UNKNOWN"]["iocs"].append(ioc)

    # Convert sets to lists for JSON serialization
    result = {}
    for asn, data in sorted(clusters.items(), key=lambda x: len(x[1]["iocs"]), reverse=True):
        result[asn] = {
            "org": data["org"],
            "prefixes": sorted(data["prefix"]),
            "count": len(data["iocs"]),
            "iocs": data["iocs"],
        }
    return result


def cluster_by_domain_pattern(iocs):
    """Cluster domains by naming patterns"""
    clusters = defaultdict(list)
    for ioc in iocs:
        if ioc["type"] == "domain":
            sld = ioc.get("sld", ioc["value"])
            clusters[sld].append(ioc)
        elif ioc["type"] == "url":
            domain = ioc.get("domain", "")
            parts = domain.split(".")
            if len(parts) >= 2:
                sld = ".".join(parts[-2:])
                clusters[sld].append(ioc)
    return dict(sorted(clusters.items(), key=lambda x: len(x[1]), reverse=True))


def cluster_by_tld(iocs):
    """Cluster domains by TLD"""
    clusters = defaultdict(list)
    for ioc in iocs:
        if ioc["type"] == "domain":
            clusters[ioc.get("tld", "?")].append(ioc)
    return dict(sorted(clusters.items(), key=lambda x: len(x[1]), reverse=True))


def cluster_by_port(iocs):
    """Cluster by port number"""
    clusters = defaultdict(list)
    for ioc in iocs:
        if ioc["type"] == "ipv4_port":
            clusters[ioc["port"]].append(ioc)
        elif ioc["type"] == "url":
            parsed = urlparse(ioc["value"])
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            clusters[port].append(ioc)
    return dict(sorted(clusters.items(), key=lambda x: len(x[1]), reverse=True))


def extract_url_patterns(iocs):
    """Extract common URL path patterns"""
    paths = []
    for ioc in iocs:
        if ioc["type"] == "url":
            path = ioc.get("path", "/")
            paths.append(path)

    if not paths:
        return {}

    # Common path segments
    segments = Counter()
    for path in paths:
        for seg in path.strip("/").split("/"):
            if seg and not re.match(r"^[0-9a-f]{8,}$", seg):  # Skip hashes/IDs
                segments[seg] += 1

    # Common path prefixes
    prefixes = Counter()
    for path in paths:
        parts = path.strip("/").split("/")
        for i in range(1, min(len(parts) + 1, 4)):
            prefix = "/" + "/".join(parts[:i])
            prefixes[prefix] += 1

    # File extensions
    extensions = Counter()
    for path in paths:
        if "." in path.split("/")[-1]:
            ext = "." + path.split(".")[-1].split("?")[0]
            extensions[ext] += 1

    return {
        "common_segments": dict(segments.most_common(20)),
        "common_prefixes": dict(prefixes.most_common(15)),
        "file_extensions": dict(extensions.most_common(10)),
        "total_urls": len(paths),
    }


def find_cooccurrence(iocs):
    """Find IOCs that commonly appear together (same subnet/domain family)"""
    # Group by subnet
    subnet_groups = cluster_by_subnet(iocs)
    # Group by domain
    domain_groups = cluster_by_domain_pattern(iocs)

    cooccurrence = []

    for group_key, members in {**subnet_groups, **domain_groups}.items():
        if len(members) >= 2:
            cooccurrence.append({
                "group": group_key,
                "count": len(members),
                "iocs": [m["value"] for m in members],
                "types": list(set(m["type"] for m in members)),
            })

    cooccurrence.sort(key=lambda x: x["count"], reverse=True)
    return cooccurrence


def extract_naming_patterns(iocs):
    """Extract domain naming convention patterns"""
    patterns = {
        "dga_like": [],      # Random-looking domains
        "brand_impersonation": [],  # Known brand names in domain
        "numbered": [],      # Domains with sequential numbers
        "short": [],         # Very short domains (< 5 chars)
        "hyphenated": [],    # Multiple hyphens
    }

    known_brands = ["google", "microsoft", "apple", "amazon", "facebook", "paypal",
                     "netflix", "linkedin", "twitter", "instagram", "dropbox", "adobe",
                     "outlook", "office", "onedrive", "icloud", "chase", "wellsfargo"]

    for ioc in iocs:
        if ioc["type"] != "domain":
            continue
        name = ioc["value"].split(".")[0]

        # DGA-like: high entropy, consonant clusters
        vowels = sum(1 for c in name if c in "aeiou")
        if len(name) > 8 and vowels < len(name) * 0.25:
            patterns["dga_like"].append(ioc["value"])

        # Brand impersonation
        for brand in known_brands:
            if brand in name.lower() and name.lower() != brand:
                patterns["brand_impersonation"].append(ioc["value"])
                break

        # Numbered
        if re.search(r"\d{2,}", name):
            patterns["numbered"].append(ioc["value"])

        # Short
        if len(name) <= 4:
            patterns["short"].append(ioc["value"])

        # Hyphenated
        if name.count("-") >= 2:
            patterns["hyphenated"].append(ioc["value"])

    return {k: v for k, v in patterns.items() if v}


def compute_hash_similarity(iocs):
    """Group hashes by type and find patterns"""
    hash_groups = defaultdict(list)
    for ioc in iocs:
        if ioc["type"] in ("md5", "sha1", "sha256"):
            hash_groups[ioc["type"]].append(ioc["value"])

    stats = {}
    for htype, hashes in hash_groups.items():
        # Check for common prefixes (potential same malware family)
        prefix_groups = defaultdict(list)
        for h in hashes:
            prefix_groups[h[:4]].append(h)

        common_prefixes = {k: v for k, v in prefix_groups.items() if len(v) > 1}
        stats[htype] = {
            "count": len(hashes),
            "common_prefixes": common_prefixes if common_prefixes else None,
        }

    return stats


# ============================================================
# Subcommands
# ============================================================

def cmd_cluster(args):
    """Cluster IOCs by infrastructure patterns"""
    iocs = read_iocs(args.source)
    if not iocs:
        print("[!] No IOCs found", file=sys.stderr)
        sys.exit(1)

    type_counts = Counter(i["type"] for i in iocs)

    results = {
        "total": len(iocs),
        "types": dict(type_counts),
        "clusters": {},
    }

    # IP clustering
    ip_iocs = [i for i in iocs if i["type"] in ("ipv4", "ipv4_port")]
    if ip_iocs:
        results["clusters"]["subnet_24"] = cluster_by_subnet(ip_iocs, 24)
        results["clusters"]["range_16"] = cluster_by_asn_range(ip_iocs)
        results["clusters"]["port"] = cluster_by_port(ip_iocs)
        # ASN lookup clustering (amass concept)
        if getattr(args, "asn", False):
            print("  Resolving ASNs via Team Cymru DNS...", file=sys.stderr)
            asn_result = cluster_by_asn(ip_iocs, max_lookups=getattr(args, "max_asn", 50))
            results["clusters"]["asn"] = asn_result

    # Domain clustering
    domain_iocs = [i for i in iocs if i["type"] in ("domain", "url")]
    if domain_iocs:
        results["clusters"]["domain_family"] = cluster_by_domain_pattern(domain_iocs)
        results["clusters"]["tld"] = cluster_by_tld([i for i in iocs if i["type"] == "domain"])

    # Hash clustering
    hash_iocs = [i for i in iocs if i["type"] in ("md5", "sha1", "sha256")]
    if hash_iocs:
        results["clusters"]["hashes"] = compute_hash_similarity(iocs)

    if args.json:
        # Serialize IOC objects
        def serialize(obj):
            if isinstance(obj, list) and obj and isinstance(obj[0], dict) and "value" in obj[0]:
                return [x["value"] for x in obj]
            if isinstance(obj, set):
                return sorted(obj)
            return str(obj)
        emit_json(results, args, tool="iocminer", command="cluster", default=serialize)
    else:
        print(f"\n{'='*55}")
        print(f"  IOC Cluster Analysis")
        print(f"  Total IOCs: {len(iocs)}")
        print(f"  Types: {', '.join(f'{k}({v})' for k, v in type_counts.most_common())}")
        print(f"{'='*55}")

        for cluster_type, clusters in results["clusters"].items():
            if not clusters:
                continue
            print(f"\n  --- {cluster_type} ---")

            # Special display for ASN clusters
            if cluster_type == "asn":
                for asn, data in clusters.items():
                    org = data.get("org", "?")
                    prefixes = ", ".join(data.get("prefixes", []))
                    count = data.get("count", 0)
                    print(f"  {asn} [{org}] ({count} IOCs)")
                    if prefixes:
                        print(f"    Prefixes: {prefixes}")
                    iocs_list = data.get("iocs", [])
                    for ioc in iocs_list[:5]:
                        val = ioc["value"] if isinstance(ioc, dict) else str(ioc)
                        print(f"    {val}")
                    if len(iocs_list) > 5:
                        print(f"    ... +{len(iocs_list)-5} more")
                continue

            items = clusters.items() if isinstance(clusters, dict) else []
            for key, members in list(items)[:15]:
                if isinstance(members, list):
                    values = [m["value"] if isinstance(m, dict) else str(m) for m in members]
                    if len(values) > 1:
                        print(f"  {key} ({len(values)} IOCs)")
                        for v in values[:5]:
                            print(f"    {v}")
                        if len(values) > 5:
                            print(f"    ... +{len(values)-5} more")
                elif isinstance(members, dict):
                    print(f"  {key}: {json.dumps(members, indent=4)}")
        print()


def cmd_patterns(args):
    """Extract common patterns from IOCs"""
    iocs = read_iocs(args.source)
    if not iocs:
        print("[!] No IOCs found", file=sys.stderr)
        sys.exit(1)

    results = {}

    # URL patterns
    url_iocs = [i for i in iocs if i["type"] == "url"]
    if url_iocs:
        results["url_patterns"] = extract_url_patterns(url_iocs)

    # Domain naming patterns
    domain_iocs = [i for i in iocs if i["type"] == "domain"]
    if domain_iocs:
        results["naming_patterns"] = extract_naming_patterns(domain_iocs)

    if args.json:
        emit_json(results, args, tool="iocminer", command="patterns")
    else:
        print(f"\n{'='*55}")
        print(f"  IOC Pattern Analysis ({len(iocs)} IOCs)")
        print(f"{'='*55}")

        if "url_patterns" in results:
            up = results["url_patterns"]
            print(f"\n  URL Patterns ({up.get('total_urls', 0)} URLs):")
            if up.get("common_segments"):
                print(f"    Common path segments:")
                for seg, cnt in list(up["common_segments"].items())[:10]:
                    print(f"      /{seg}  ({cnt}x)")
            if up.get("file_extensions"):
                print(f"    File extensions:")
                for ext, cnt in up["file_extensions"].items():
                    print(f"      {ext}  ({cnt}x)")

        if "naming_patterns" in results:
            np = results["naming_patterns"]
            print(f"\n  Domain Naming Patterns:")
            for pattern_type, domains in np.items():
                label = pattern_type.replace("_", " ").title()
                print(f"    {label} ({len(domains)}):")
                for d in domains[:5]:
                    print(f"      {d}")
        print()


def cmd_cooccurrence(args):
    """Find IOCs that appear in the same infrastructure"""
    iocs = read_iocs(args.source)
    if not iocs:
        print("[!] No IOCs found", file=sys.stderr)
        sys.exit(1)

    groups = find_cooccurrence(iocs)

    if args.json:
        emit_json(groups, args, tool="iocminer", command="cooccurrence")
    else:
        print(f"\n{'='*55}")
        print(f"  Co-occurrence Analysis ({len(iocs)} IOCs)")
        print(f"{'='*55}")

        if not groups:
            print("\n  No co-occurrence groups found.")
        else:
            for g in groups[:20]:
                print(f"\n  Group: {g['group']} ({g['count']} IOCs)")
                for ioc in g["iocs"][:8]:
                    print(f"    {ioc}")
                if len(g["iocs"]) > 8:
                    print(f"    ... +{len(g['iocs'])-8} more")
        print()


def cmd_enrich(args):
    """Parse and classify IOCs with metadata"""
    iocs = read_iocs(args.source)
    if not iocs:
        print("[!] No IOCs found", file=sys.stderr)
        sys.exit(1)

    if args.json:
        emit_json({"iocs": iocs, "count": len(iocs)}, args, tool="iocminer", command="enrich")
    else:
        print(f"\n  Parsed {len(iocs)} IOCs:\n")
        print(f"  {'IOC':<50} {'Type':<12} Extra")
        print(f"  {'─'*50} {'─'*12} {'─'*30}")
        for ioc in iocs:
            extra_parts = []
            for k in ["port", "domain", "path", "tld", "scheme"]:
                if k in ioc:
                    extra_parts.append(f"{k}={ioc[k]}")
            extra = ", ".join(extra_parts) if extra_parts else ""
            print(f"  {ioc['value']:<50} {ioc['type']:<12} {extra}")
        print()


# ============================================================
# Association Rule Mining (from AI_MinePatterns)
# ============================================================

def mine_association_rules(iocs, min_support=2):
    """Mine frequent patterns and association rules from IOC properties"""
    # Extract features per IOC
    transactions = []
    for ioc in iocs:
        features = set()
        features.add(f"type:{ioc['type']}")

        if ioc["type"] in ("ipv4", "ipv4_port"):
            val = ioc.get("ip", ioc["value"])
            ip = val.rsplit(":", 1)[0] if ":" in val and "." in val else val
            octets = ip.split(".")
            if len(octets) < 2:
                continue  # skip non-IPv4 (e.g. IPv6)
            features.add(f"oct1:{octets[0]}")
            features.add(f"oct12:{octets[0]}.{octets[1]}")
            if ioc["type"] == "ipv4_port":
                port = ioc.get("port", 0)
                features.add(f"port:{port}")
                if port in (80, 8080, 8000, 8888):
                    features.add("service:http")
                elif port in (443, 8443):
                    features.add("service:https")
                elif port in (21,):
                    features.add("service:ftp")
                elif port in (22,):
                    features.add("service:ssh")
                elif port in (25, 465, 587):
                    features.add("service:smtp")
                elif port in (53,):
                    features.add("service:dns")

        elif ioc["type"] == "domain":
            features.add(f"tld:{ioc.get('tld', '?')}")
            name = ioc["value"].split(".")[0]
            features.add(f"namelen:{len(name)//5*5}-{len(name)//5*5+4}")
            if "-" in name:
                features.add("has:hyphen")
            if any(c.isdigit() for c in name):
                features.add("has:digits")

        elif ioc["type"] == "url":
            parsed = urlparse(ioc["value"])
            features.add(f"scheme:{parsed.scheme}")
            path = parsed.path
            if "." in path.split("/")[-1]:
                ext = path.split(".")[-1].lower()
                features.add(f"ext:{ext}")
            segments = [s for s in path.strip("/").split("/") if s]
            if segments:
                features.add(f"depth:{len(segments)}")
                features.add(f"firstseg:{segments[0]}")

        transactions.append(features)

    # Count individual features
    feature_counts = Counter()
    for t in transactions:
        for f in t:
            feature_counts[f] += 1

    # Count pairs (2-itemsets)
    pair_counts = Counter()
    for t in transactions:
        items = sorted(t)
        for i in range(len(items)):
            for j in range(i + 1, len(items)):
                pair_counts[(items[i], items[j])] += 1

    # Generate rules: {A} → {B} with support and confidence
    rules = []
    for (a, b), count in pair_counts.items():
        if count >= min_support:
            conf_a_to_b = count / feature_counts[a] if feature_counts[a] > 0 else 0
            conf_b_to_a = count / feature_counts[b] if feature_counts[b] > 0 else 0

            if conf_a_to_b >= 0.5:
                rules.append({
                    "rule": f"{a} → {b}",
                    "support": count,
                    "confidence": round(conf_a_to_b, 2),
                    "antecedent": a,
                    "consequent": b,
                })
            if conf_b_to_a >= 0.5:
                rules.append({
                    "rule": f"{b} → {a}",
                    "support": count,
                    "confidence": round(conf_b_to_a, 2),
                    "antecedent": b,
                    "consequent": a,
                })

    rules.sort(key=lambda r: (-r["confidence"], -r["support"]))

    # Frequent itemsets summary
    frequent = {k: v for k, v in feature_counts.most_common() if v >= min_support}

    return rules, frequent


def cmd_mine(args):
    """Mine association rules from IOC data"""
    iocs = read_iocs(args.source)
    if not iocs:
        print("[!] No IOCs found", file=sys.stderr)
        sys.exit(1)

    rules, frequent = mine_association_rules(iocs, min_support=args.min_support)

    if args.json:
        emit_json({
            "total_iocs": len(iocs),
            "frequent_features": frequent,
            "rules": rules[:50],
        }, args, tool="iocminer", command="mine")
    else:
        print(f"\n{'='*60}")
        print(f"  Association Rule Mining ({len(iocs)} IOCs)")
        print(f"{'='*60}")

        print(f"\n  Frequent Features (support >= {args.min_support}):")
        for feature, count in list(frequent.items())[:20]:
            bar = "#" * min(count, 30)
            print(f"    {feature:<30} {count:>3}  {bar}")

        if rules:
            print(f"\n  Association Rules ({len(rules)} found):")
            print(f"  {'Rule':<45} {'Conf':<8} {'Sup':<5}")
            print(f"  {'─'*45} {'─'*8} {'─'*5}")
            for r in rules[:25]:
                print(f"  {r['rule']:<45} {r['confidence']:<8.0%} {r['support']:<5}")

            # Highlight strongest campaign indicators
            strong = [r for r in rules if r["confidence"] >= 0.8 and r["support"] >= 3]
            if strong:
                print(f"\n  Strong Campaign Indicators:")
                for r in strong[:10]:
                    print(f"    {r['rule']}  (conf={r['confidence']:.0%}, sup={r['support']})")
        print()


def main():
    parser = argparse.ArgumentParser(
        prog="iocminer",
        description="IOC pattern analysis & threat campaign clustering",
    )
    sub = parser.add_subparsers(dest="command")

    # cluster
    cl = sub.add_parser("cluster", aliases=["c"], help="Cluster IOCs by infrastructure")
    cl.add_argument("source", help="File with IOCs, single IOC, or - for stdin")
    cl.add_argument("--asn", action="store_true", help="Enable ASN lookup clustering via Team Cymru DNS (amass concept)")
    cl.add_argument("--max-asn", type=int, default=50, help="Max IPs for ASN lookup (default: 50)")
    add_output_args(cl, include=("json",))
    cl.set_defaults(func=cmd_cluster)

    # patterns
    pt = sub.add_parser("patterns", aliases=["p"], help="Extract common patterns")
    pt.add_argument("source", help="File with IOCs or - for stdin")
    add_output_args(pt, include=("json",))
    pt.set_defaults(func=cmd_patterns)

    # cooccurrence
    co = sub.add_parser("cooccurrence", aliases=["co"], help="Find co-occurring IOCs")
    co.add_argument("source", help="File with IOCs or - for stdin")
    add_output_args(co, include=("json",))
    co.set_defaults(func=cmd_cooccurrence)

    # enrich
    en = sub.add_parser("enrich", aliases=["e"], help="Parse & classify IOCs")
    en.add_argument("source", help="File with IOCs, single IOC, or - for stdin")
    add_output_args(en, include=("json",))
    en.set_defaults(func=cmd_enrich)

    # mine
    mn = sub.add_parser("mine", aliases=["m"], help="Mine association rules from IOCs")
    mn.add_argument("source", help="File with IOCs or - for stdin")
    mn.add_argument("--min-support", type=int, default=2, help="Min support for rules")
    add_output_args(mn, include=("json",))
    mn.set_defaults(func=cmd_mine)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
