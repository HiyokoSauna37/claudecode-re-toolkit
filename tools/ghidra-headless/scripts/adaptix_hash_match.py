#!/usr/bin/env python3
"""
Match API hash constants observed in decompiled AdaptixC2 agent against
ApiDefines.h hash table. Outputs a CSV of (hash -> API name).
"""
import argparse
import re
import sys


def parse_defs(path: str) -> dict:
    table = {}
    pat = re.compile(r"#define\s+(HASH_(?:LIB|FUNC)_\w+)\s+(0x[0-9a-fA-F]+)")
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            m = pat.search(line)
            if m:
                table[int(m.group(2), 16) & 0xFFFFFFFF] = m.group(1)
    return table


def collect_hashes(decomp_path: str) -> list:
    hashes = []
    seen_set = set()
    api_call_pat = re.compile(r"FUN_1400111a1\([^,]+,\s*(-?0x[0-9a-fA-F]+)\s*\)")
    mod_call_pat = re.compile(r"FUN_1400110fa\(\s*(-?0x[0-9a-fA-F]+)\s*\)")
    with open(decomp_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            for pat, kind in ((api_call_pat, "FUNC"), (mod_call_pat, "LIB")):
                for m in pat.findall(line):
                    val = int(m, 16) & 0xFFFFFFFF
                    if (val, kind) not in seen_set:
                        seen_set.add((val, kind))
                        hashes.append((val, kind))
    return hashes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("decomp", help="decompiled.c path")
    ap.add_argument("defs", help="ApiDefines.h path")
    args = ap.parse_args()

    table = parse_defs(args.defs)
    sys.stderr.write(f"[+] loaded {len(table)} hash defines\n")

    observed = collect_hashes(args.decomp)
    sys.stderr.write(f"[+] observed {len(observed)} unique hashes in decompiled.c\n")

    matched = 0
    unmatched = 0
    print("hash,kind,api_name")
    for h, kind in sorted(observed):
        name = table.get(h, "<UNKNOWN>")
        if name == "<UNKNOWN>":
            unmatched += 1
        else:
            matched += 1
        print(f"0x{h:08x},{kind},{name}")
    sys.stderr.write(f"[+] matched={matched} unmatched={unmatched}\n")


if __name__ == "__main__":
    main()
